# Track E — Build-in-VM (Dockerfile → sandbox) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let izba build OCI images from a Dockerfile entirely inside a throwaway builder microVM (no host builder) and run the result as a sandbox, plus ingest pre-built OCI-archive images directly.

**Architecture:** Reuse the existing image pipeline's `flatten → erofs → publish` tail for a new `oci-archive:` ingest path; add a local tag store so built images get names; orchestrate a disposable builder sandbox booted from a sha-pinned BuildKit image (lazy-pulled, cached) that runs `buildkitd`+`buildctl` over the existing `workspace` virtiofs share, writes `type=oci` output to a new read-write `izba-buildout` share the host then ingests; gate the builder VM's egress with a dedicated build-network policy distinct from the sandbox run policy.

**Tech Stack:** Rust (izba-core/izba-cli), Cloud Hypervisor/OpenVMM microVMs, crun OCI runtime in-guest, BuildKit (`moby/buildkit`, sha-pinned), regorus egress policy, virtiofs shares, GitHub Actions e2e (KVM + WHP).

## Global Constraints

- **Builder = BuildKit, run as root inside the disposable builder VM** with the overlayfs snapshotter (`--oci-worker-snapshotter=overlayfs`); the VM is the trust boundary. izba orchestrates BuildKit; it does NOT reimplement it.
- **Builder image delivery: lazy-pull on first build, cached locally.** A sha-pinned `moby/buildkit` reference + digest live as constants in izba-core; NOT shipped in the installer; pulled on first `izba build` into the normal image store and reused.
- **Build runs `linux/amd64`** (same as all izba pulls) regardless of host OS — this is what makes build-in-VM cross-platform-free.
- **Build-time egress uses a SEPARATE dedicated build-network policy**, enforced through the same izbad vsock-1027 plane (allow-list + audit) — NOT AllowAll, and distinct from the sandbox's run-time egress policy. It allow-lists what a build legitimately needs (the builder-image pull host + base-image registries + declared mirrors) and denies the rest.
- **oci-archive ingest reuses the EXISTING `flatten_layers` + erofs + publish tail** (factor the shared tail into a helper; do not duplicate it). Once ingested, `build_vm_disks` keys the rootfs off `image_digest` with zero further change.
- **New ref schemes are orthogonal to `izba run --image <registry-ref>`:** `oci-archive:/path`, a local tag (`myimg`), `izba build -t myimg`, and `izba run --build ./Dockerfile`.
- TDD throughout; conventional commits (`feat(core): …`); all six workspace gates + the app gate (since `izba-core`/`izba-proto` public types may change) must be green before completion (see CLAUDE.md "Build & test").
- New vendored/pinned references must be sha256-pinned (follow the `hack/build-*.sh` + immutable-digest pattern).
- Never silently downgrade security; fail closed + loud on policy/confinement gaps (see the "loud on security degradation" rule).

---

### Task 1: Factor the publish tail into a shared `publish_image` helper

**Files:**
- Modify: `crates/izba-core/src/image/mod.rs` (extract from `ensure_image`, L29–61)
- Test: existing `crates/izba-core/src/image/mod.rs` tests + `crates/izba-core/tests/integration.rs` cover behavior; add a focused unit test.

**Interfaces:**
- Consumes: `ImageStore::publish` (store.rs), `flatten::flatten_layers`, `erofs::build_erofs`.
- Produces:
  ```rust
  /// Shared tail: flatten the ordered layer readers into one tar, build the
  /// erofs, and publish under `digest` along with `config_json` + `image_ref`.
  /// Returns the canonical digest (echoes `digest`). Idempotent: if the store
  /// already has `digest` cached, it is a no-op returning `digest`.
  pub(crate) fn publish_image(
      paths: &Paths,
      digest: &str,
      image_ref: &str,
      config_json: &[u8],
      layers: Vec<Box<dyn std::io::Read>>,
  ) -> anyhow::Result<String>
  ```

- [ ] **Step 1: Write the failing test** — assert `ensure_image` and `publish_image` agree on store layout for a synthetic single-layer image (build a tiny gzip tar layer + minimal config in a temp `Paths`, call `publish_image`, assert `ImageStore::is_cached(digest)` is true and `rootfs.erofs`/`config.json`/`ref.txt` exist).

```rust
#[test]
fn publish_image_writes_full_store_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::for_test(tmp.path());
    let layer = single_file_gzip_tar_layer("hello", b"hi"); // helper builds a 1-file gz tar
    let digest = "sha256:".to_string() + &"a".repeat(64);
    let out = publish_image(&paths, &digest, "oci-archive:/x", b"{}", vec![Box::new(layer)]).unwrap();
    assert_eq!(out, digest);
    let store = ImageStore::new(&paths);
    assert!(store.is_cached(&digest));
    assert!(store.config_path(&digest).exists());
    assert!(store.ref_path(&digest).exists());
}
```

- [ ] **Step 2: Run it to verify it fails** — `cargo test -p izba-core publish_image_writes_full_store_entry` → FAIL (`publish_image` not found).
- [ ] **Step 3: Extract the helper** — move the `flatten_layers → build_erofs → publish` + config/ref persistence tail out of `ensure_image` into `publish_image`; have `ensure_image` call it after `resolve`+`fetch_layers`. Early-return `digest` if `store.is_cached(digest)`.
- [ ] **Step 4: Run tests** — `cargo test -p izba-core image::` → PASS; existing integration image tests still green.
- [ ] **Step 5: Commit** — `refactor(image): extract publish_image tail shared by ensure_image and ingest`.

---

### Task 2: `oci-archive` ingest

**Files:**
- Create: `crates/izba-core/src/image/ingest.rs`
- Modify: `crates/izba-core/src/image/mod.rs` (add `mod ingest;` + re-export)
- Test: in `ingest.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `publish_image` (Task 1).
- Produces:
  ```rust
  /// Ingest an OCI-layout archive tarball (the `type=oci` export format:
  /// `oci-layout` + `index.json` + `blobs/sha256/<hex>`). Reads index → the
  /// single image manifest → its config + ordered layer blobs, VERIFIES each
  /// blob's sha256 against the manifest, then feeds the layer readers into
  /// `publish_image`. The published digest is the manifest's config digest
  /// (the image ID), matching registry-pull semantics. Returns that digest.
  pub fn ingest_oci_archive(paths: &Paths, archive_path: &Path) -> anyhow::Result<String>
  ```

Implementation notes (OCI image-layout spec): the tar contains `index.json` (a manifest list); pick the single `application/vnd.oci.image.manifest.v1+json` entry (error if 0 or >1 unless a platform selector matches `linux/amd64`); read that manifest blob; its `.config.digest` is the image ID and `.layers[]` are the ordered layer blobs (gzip or zstd or plain — `flatten_layers` already sniffs gzip; add zstd sniff only if needed, else error clearly on unsupported media types). Blobs live at `blobs/sha256/<hex>` inside the tar. Stream blobs to temp files, verify sha256, rewind, box as `Read`.

- [ ] **Step 1: Write the failing test** — build a minimal OCI-archive tar fixture in-test (one layer, one config, `index.json`), call `ingest_oci_archive`, assert returned digest == config digest and `ImageStore::is_cached` true.

```rust
#[test]
fn ingest_oci_archive_publishes_image() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::for_test(tmp.path());
    let archive = build_oci_archive_fixture(tmp.path(), /*file*/ "/etc/x", b"y");
    let digest = ingest_oci_archive(&paths, &archive).unwrap();
    assert!(digest.starts_with("sha256:"));
    assert!(ImageStore::new(&paths).is_cached(&digest));
}

#[test]
fn ingest_rejects_blob_digest_mismatch() {
    // corrupt one byte of a layer blob in the fixture → ingest must error.
}
```

- [ ] **Step 2: Run to verify fail** — `cargo test -p izba-core ingest_` → FAIL.
- [ ] **Step 3: Implement `ingest.rs`** — parse layout, verify digests, call `publish_image`.
- [ ] **Step 4: Run tests** — both ingest tests PASS.
- [ ] **Step 5: Commit** — `feat(image): ingest OCI-archive tarballs into the image store`.

---

### Task 3: Route `oci-archive:` refs through ingest

**Files:**
- Modify: `crates/izba-core/src/image/mod.rs` (`ensure_image` dispatch, L29)
- Modify: `crates/izba-core/src/image/mod.rs` — add a small ref-scheme classifier
- Test: `ingest.rs` / `mod.rs` unit + `crates/izba-core/tests/integration.rs`

**Interfaces:**
- Produces: `ensure_image(paths, "oci-archive:/abs/path.tar")` → `ingest_oci_archive(paths, "/abs/path.tar")`. Everything else falls through to the existing registry path unchanged.

- [ ] **Step 1: Failing test** — `ensure_image(&paths, &format!("oci-archive:{}", archive.display()))` returns the same digest as a direct `ingest_oci_archive` call.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** — at the top of `ensure_image`, `if let Some(p) = image_ref.strip_prefix("oci-archive:") { return ingest_oci_archive(paths, Path::new(p)); }`.
- [ ] **Step 4: Run → pass**; existing registry resolution tests unchanged.
- [ ] **Step 5: Commit** — `feat(image): route oci-archive: refs to the ingest path`.

---

### Task 4: Local image tag store

**Files:**
- Create: `crates/izba-core/src/image/tags.rs`
- Modify: `crates/izba-core/src/image/mod.rs` (`mod tags;`, dispatch in `ensure_image`)
- Test: `tags.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces:
  ```rust
  /// Local tag → digest map persisted at `<data>/images/tags.json`
  /// (a flat `BTreeMap<String, String>`; tag → "sha256:…"). Concurrency-safe
  /// via atomic tempfile+rename on write.
  pub fn set_tag(paths: &Paths, tag: &str, digest: &str) -> anyhow::Result<()>;
  pub fn resolve_tag(paths: &Paths, tag: &str) -> anyhow::Result<Option<String>>;
  /// Validate a user-supplied tag: `[a-z0-9][a-z0-9._-]*`, max 128, no `:`/`/`
  /// that would collide with registry refs or schemes. Errors otherwise.
  pub fn validate_tag(tag: &str) -> anyhow::Result<()>;
  ```
- Dispatch rule in `ensure_image` (precedence): `oci-archive:` prefix → ingest; else if `resolve_tag` returns `Some(digest)` AND `ImageStore::is_cached(digest)` → return that digest; else → existing registry resolve. (A local tag shadows a registry ref only when it exists locally and is cached — keeps `ubuntu:24.04` resolving to the registry.)

- [ ] **Step 1: Failing tests** — `set_tag` then `resolve_tag` round-trips; `resolve_tag` of an unknown tag is `None`; `validate_tag` rejects `"a:b"`, `"a/b"`, `""`, accepts `"myimg"`.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement `tags.rs`** + wire dispatch (guard so a tag only shadows when cached).
- [ ] **Step 4: Run → pass.**
- [ ] **Step 5: Commit** — `feat(image): local image tag store (tag → digest)`.

---

### Task 5: Builder-image constants + lazy-pull-and-cache

**Files:**
- Create: `crates/izba-core/src/build/mod.rs` (new `build` module; add `pub mod build;` to `crates/izba-core/src/lib.rs`)
- Create: `crates/izba-core/src/build/builder_image.rs`
- Test: `builder_image.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces:
  ```rust
  /// Sha-pinned BuildKit builder image. The ref is registry-resolvable; the
  /// digest pins the exact content. (Pin to a current moby/buildkit release
  /// digest — verify with `crane digest moby/buildkit:vX.Y.Z` at pin time and
  /// record the version in a comment.)
  pub const BUILDER_IMAGE_REF: &str = "moby/buildkit@sha256:<PINNED>";
  pub const BUILDER_IMAGE_DIGEST: &str = "sha256:<PINNED>";

  /// Ensure the builder image is in the local store, lazy-pulling on first use.
  /// Returns its digest. The pull needs egress+DNS and runs under the
  /// build-network policy (Task 6) when invoked from the build flow.
  pub fn ensure_builder_image(paths: &Paths) -> anyhow::Result<String>;
  ```
- `ensure_builder_image` = `image::ensure_image(paths, BUILDER_IMAGE_REF)` then assert the returned digest matches `BUILDER_IMAGE_DIGEST` (fail loud on drift).

- [ ] **Step 1: Failing test** — `BUILDER_IMAGE_REF` contains `@sha256:` and `BUILDER_IMAGE_DIGEST` is a 71-char `sha256:` string; a unit test that `ensure_builder_image` returns early with the cached digest when the store is pre-seeded with `BUILDER_IMAGE_DIGEST` (no network).

```rust
#[test]
fn ensure_builder_image_uses_cache_without_network() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::for_test(tmp.path());
    seed_store_entry(&paths, BUILDER_IMAGE_DIGEST); // write dummy rootfs.erofs/config/ref
    assert_eq!(ensure_builder_image(&paths).unwrap(), BUILDER_IMAGE_DIGEST);
}
```

(NOTE to implementer: pin a real, current `moby/buildkit` digest — do not leave the placeholder. Record the exact `vX.Y.Z` in a code comment. The live pull is exercised by the e2e task, not this unit test.)

- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement constants + `ensure_builder_image`** with the cache-hit short-circuit via `ImageStore::is_cached`.
- [ ] **Step 4: Run → pass.**
- [ ] **Step 5: Commit** — `feat(build): sha-pinned BuildKit builder image + lazy-pull`.

---

### Task 6: Dedicated build-network egress policy

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/config.rs` (add a builder-policy constructor)
- Test: `config.rs` + `policy.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces:
  ```rust
  impl EgressPolicyConfig {
      /// The build-network policy: enforce=true, allow-list the builder-image
      /// registry host(s) + the caller-declared base-image registries/mirrors.
      /// Distinct from a sandbox run policy. `extra_hosts` are user-declared
      /// `--build-allow` entries (registries/mirrors a Dockerfile's FROM needs).
      pub fn build_network(extra_hosts: &[String]) -> Self;
  }
  ```
- Default allow-list MUST include the BuildKit image registry host (`registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` / the Docker Hub blob CDN) so the lazy-pull and a `FROM` from Docker Hub succeed; everything else denied. `extra_hosts` extend it for other registries/mirrors.

- [ ] **Step 1: Failing tests** — `build_network(&[])` produces a policy where `enforces()` is true, `check` ALLOWs an `auth.docker.io:443` flow and DENYs `evil.example.com:443`; `build_network(&["mirror.example.com".into()])` ALLOWs `mirror.example.com:443`.

```rust
#[test]
fn build_policy_allows_dockerhub_denies_others() {
    let p = EgressPolicyConfig::build_network(&[]).into_policy("builder").unwrap();
    assert!(p.enforces());
    assert!(matches!(p.check(&flow("auth.docker.io", 443)), Verdict::Allow { .. }));
    assert!(matches!(p.check(&flow("evil.example.com", 443)), Verdict::Deny { .. }));
}
```

- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement `build_network`** building an `EgressPolicyConfig { enforce: true, allow: [docker-hub hosts + extra_hosts as AllowEntry::Host], git: vec![] }`.
- [ ] **Step 4: Run → pass.**
- [ ] **Step 5: Commit** — `feat(egress): dedicated build-network policy for the builder VM`.

---

### Task 7: `izba-buildout` read-write share + builder-VM disk/share wiring

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (add the `izba-buildout` share next to `izba-oci`, ~L615–642; conditional on a build flag)
- Modify: the VMM driver share list if a new tag needs registering (`crates/izba-core/src/vmm/` — mirror how `izba-oci` is threaded)
- Test: `sandbox.rs` (`#[cfg(test)]`) for the share-spec construction; real boot covered by Task 10.

**Interfaces:**
- Produces: when a sandbox is started in "builder" mode, an extra read-write virtiofs share `izba-buildout` mapped host `<sandbox>/<name>/buildout/` ↔ guest `/out`. Mirror the `izba-oci`/`izba-ssh` optional-share pattern exactly (host dir created 0700; share added to the `Vec<FsShare>` only when present). The host reads `<sandbox>/<name>/buildout/img.tar` after the build.
- A `StartOpts`/`CreateOpts` field (e.g. `builder: bool` or `buildout: bool`) carried from the build command down to `start`. If `start`'s signature is fixed, thread it via the sandbox `config`/`state.json` (follow how `policy`/`workspace` are carried).

- [ ] **Step 1: Failing test** — constructing the share list for a builder sandbox includes an `FsShare { tag: "izba-buildout", .. }` with the right host path and `read_only: false`; a non-builder sandbox does not.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** — add the share + host-dir creation guarded by the builder flag.
- [ ] **Step 4: Run → pass**; `cargo test -p izba-core sandbox::` green.
- [ ] **Step 5: Commit** — `feat(core): add izba-buildout virtiofs share for builder VMs`.

---

### Task 8: `izba build` orchestration (core + CLI)

**Files:**
- Create: `crates/izba-core/src/build/run.rs` (orchestration)
- Modify: `crates/izba-core/src/build/mod.rs` (re-export)
- Create: `crates/izba-cli/src/commands/build.rs`
- Modify: `crates/izba-cli/src/main.rs` (add `Build { … }` to `Cmd`), `crates/izba-cli/src/commands/mod.rs` (`pub mod build;`)
- Test: `run.rs` unit tests for the generated build script + arg assembly; full flow in Task 10.

**Interfaces:**
- Produces:
  ```rust
  pub struct BuildOpts {
      pub dockerfile: PathBuf,   // -f, default "<ctx>/Dockerfile"
      pub tag: Option<String>,   // -t, validated via image::tags::validate_tag
      pub context: PathBuf,      // ./ctx (becomes the workspace share)
      pub build_allow: Vec<String>, // --build-allow registries/mirrors
      pub cpus: u32, pub mem: u32,
  }
  /// Boot a throwaway builder sandbox from the BuildKit image, run the build,
  /// ingest the OCI output, optionally tag it, tear the sandbox down, and
  /// return the built image digest.
  pub fn build_image(paths: &Paths, driver: &dyn VmmDriver, art: &Artifacts, opts: &BuildOpts) -> anyhow::Result<String>;
  ```

**Orchestration steps inside `build_image`:**
1. `ensure_builder_image(paths)` → builder digest.
2. Create an ephemeral sandbox (unique generated name `izba-build-<rand>`): image = builder digest; workspace = `opts.context`; volumes = one persistent named volume `izba-buildcache` → `/var/lib/buildkit` (size e.g. 16 GiB, reused across builds for incremental cache); builder share `izba-buildout` on; egress policy = `EgressPolicyConfig::build_network(&opts.build_allow)` (write it to the sandbox `policy.yaml` path the daemon loads, OR pass it through the build-network channel).
3. `sandbox::start(...)`.
4. Run the build command in the container to completion (reuse the exec/`crun exec` path used by `izba exec`, capturing exit code). The command is the generated script below, passed as `sh -c "<script>"`.
5. On exit 0, host reads `<sandbox>/<name>/buildout/img.tar` → `image::ingest_oci_archive` → digest; if `opts.tag`, `image::tags::set_tag(paths, tag, digest)`.
6. Always tear down: `sandbox::stop` + remove the ephemeral sandbox dir (keep the persistent `izba-buildcache` volume).
7. Return the digest (propagate buildctl's non-zero exit as a build error with the captured console/stderr tail).

**Generated build script** (`run.rs`, as a `const` template; `{filename}` = Dockerfile name relative to context):
```sh
set -e
buildkitd --oci-worker-snapshotter=overlayfs --root /var/lib/buildkit >/var/log/buildkitd.log 2>&1 &
for i in $(seq 1 60); do buildctl debug workers >/dev/null 2>&1 && break; sleep 1; done
buildctl build \
  --frontend dockerfile.v0 \
  --local context=/workspace \
  --local dockerfile=/workspace \
  --opt filename={filename} \
  --output type=oci,dest=/out/img.tar
```

- [ ] **Step 1: Failing test** — `build_script("Dockerfile.dev")` contains `--opt filename=Dockerfile.dev` and the `type=oci,dest=/out/img.tar` output and the overlayfs snapshotter flag; arg assembly maps `BuildOpts` → builder sandbox `CreateOpts` correctly (image=builder digest, workspace=context, buildcache volume present, buildout on).
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** core `build_image` + the CLI `build` command (clap: `izba build [-f FILE] [-t TAG] [--build-allow HOST]... [--cpus N] [--mem MB] CONTEXT`). The CLI calls core and prints the resulting digest/tag.
- [ ] **Step 4: Run → pass** (unit level); `cargo test -p izba-core build:: -p izba-cli` green.
- [ ] **Step 5: Commit** — `feat(build): izba build — Dockerfile → image via throwaway builder VM`.

---

### Task 9: `izba run --build ./Dockerfile` one-shot

**Files:**
- Modify: `crates/izba-cli/src/main.rs` (`Run` gets `--build <DOCKERFILE-or-CONTEXT>` / a `build: Option<PathBuf>` field)
- Modify: `crates/izba-cli/src/commands/run.rs`
- Test: `run.rs` unit test for the build-then-run dispatch.

**Interfaces:**
- Consumes: `build::build_image` (Task 8), the existing `run` path.
- Produces: `izba run --build ./Dockerfile [--build-allow HOST]... [run flags]` → builds (context = the Dockerfile's parent dir, or the path if it's a dir), then runs a sandbox from the resulting digest, reusing `--name`/`-p`/`--volume`/etc. `--build` and `--image` are mutually exclusive (clap conflict).

- [ ] **Step 1: Failing test** — given `--build ./ctx/Dockerfile`, the resolved context is `./ctx` and the run uses the built digest; `--build` + `--image` together is a clap error.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** the dispatch in `run`: if `opts.build.is_some()`, call `build_image` (no tag), then set the run image to the returned digest.
- [ ] **Step 4: Run → pass.**
- [ ] **Step 5: Commit** — `feat(cli): izba run --build one-shot (build then run)`.

---

### Task 10: End-to-end build-in-VM on both platforms (KVM + WHP)

**Files:**
- Create: `crates/izba-core/tests/build_e2e.rs` (KVM-gated, `IZBA_INTEGRATION=1`) — boots a real builder VM and builds a tiny Dockerfile.
- Create fixture: `crates/izba-core/tests/fixtures/build/Dockerfile` (`FROM alpine:3.20` + `RUN echo izba-build-ok > /izba-build-marker`).
- Modify: `.github/workflows/e2e.yml` — add the build_e2e suite to the `linux-kvm` leg; add a builder validation step to the `windows-whp` leg.
- Modify: `hack/spike/validate-izba-windows.ps1` — add a build-in-VM scenario (run `izba build` then assert the marker file via `izba run … cat`).

**Interfaces:**
- Consumes everything above. The test must exercise: lazy-pull of the builder image (under the build-network policy), the buildkit run inside the VM, OCI output ingest, tagging, and running the built image to read the marker.

**Test (KVM leg):**
```rust
#[test]
fn build_in_vm_dockerfile_to_running_sandbox() {
    if std::env::var("IZBA_INTEGRATION").is_err() { return; } // self-skip
    // izba build -t izba-e2e-built tests/fixtures/build
    // assert digest returned; tags::resolve_tag == digest
    // izba run --image izba-e2e-built -- cat /izba-build-marker  → "izba-build-ok"
}
```

- [ ] **Step 1: Write the fixture Dockerfile + the KVM-gated test** (self-skips without `IZBA_INTEGRATION`).
- [ ] **Step 2: Run locally with KVM** (sandbox disabled): `IZBA_INTEGRATION=1 cargo test -p izba-core --test build_e2e -- --test-threads=1`. Iterate until the marker reads back. Capture `logs/console.log` + `buildkitd.log` on failure.
- [ ] **Step 3: Wire `e2e.yml`** — add the build_e2e cargo test to `linux-kvm`; add the `izba build`+verify scenario to `validate-izba-windows.ps1` invoked by `windows-whp`. Ensure the builder image pull is allowed in CI (build-network policy hosts) and DNS works (landed).
- [ ] **Step 4: Commit** — `test(e2e): build-in-VM Dockerfile→run on KVM + WHP`.

---

## Self-Review notes

- **Spec coverage (§8 + §9):** oci-archive ingest (T2–T3), `--image oci-archive:` (T3), local tags + `izba build -t` + `izba run --image myimg` (T4, T8), `izba run --build` (T9), builder image lazy-pull sha-pinned (T5), build-network policy (T6), buildcache volume `/var/lib/buildkit` + `/out` share (T7–T8), BuildKit-as-builder + overlayfs snapshotter run-as-root (T8 script), cross-platform e2e (T10). Prereq #1 (sized `/var/lib/buildkit`) → T7/T8 buildcache volume. Prereq #2 (DNS) already landed. Prereq #4 (build-time egress policy) → T6.
- **Open implementer decisions flagged in briefs:** the real `moby/buildkit` pin digest (T5); whether `/out` is best as a share vs. volume (plan picks share — host reads directly, no host-side ext4 mount); exact Docker Hub blob-CDN host set for the build policy allow-list (T6 — verify against an actual pull).
- **Ordering:** T1→T2→T3 (ingest), T4 (tags), T5 (builder image), T6 (policy), T7 (share), T8 (build orchestration, depends T5/T6/T7), T9 (one-shot, depends T8), T10 (e2e, depends all).
