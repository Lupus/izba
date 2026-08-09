# VNC Display (KasmVNC) Implementation Plan — PR1 backend

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `izba create --vnc` (or `izba vnc on` + restart) gives a sandbox a browser-viewable KasmVNC desktop, auto-started in the workload container from an izba-shipped read-only erofs bundle, reachable via an auto-published loopback relay with per-start credentials — covered by KVM e2e.

**Architecture:** self-contained patchelf'd KasmVNC erofs appended as the disk after user volumes (`izba.vnc=1` cmdline); init mounts it outside the overlay, the OCI spec binds it into the container, init auto-starts `Xkasmvnc`+`openbox` (dockerd precedent); daemon auto-publishes an ephemeral TcpDial relay to guest `127.0.0.1:6901` and surfaces a credentialed URL via Inspect. Spec: `docs/superpowers/specs/2026-08-09-vnc-display-design.md`.

**Tech Stack:** Rust (izba workspace), oci-spec 0.9 builders, KasmVNC 1.5.0 upstream deb, patchelf, mkfs.erofs, GitHub Actions.

## Global Constraints

- All six workspace gates green before every commit: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`. Run `[ -f .cargo-env ] && source .cargo-env` first.
- TDD: write the failing test, see it fail, implement, see it pass, commit. Conventional commits.
- izba-init must NOT depend on izba-core; shared paths are duplicated constants pinned by one-line drift tests on each side (model: `the_shared_directory_path_matches_the_one_izba_init_writes_to`).
- Unit tests never bind listeners; guest-only/spawn-glue fns get `#[mutants::skip] // reason: …`.
- Every rule gets a test AND its call site gets one (USB campaign defect class).
- Fixed strings from the spec: bundle mount `/opt/izba-vnc`; init-root mount `/run/izba/vnc`; secrets `/run/izba/vnc-secrets`; share tag `izba-vnc`; guest websocket port `6901`; artifact file `kasmvnc.erofs`; env override `IZBA_KASMVNC_EROFS`; cmdline `izba.vnc=1`; basic-auth user `izba`; `DAEMON_PROTO_VERSION` 5→6.

---

### Task 1: `hack/build-kasmvnc-erofs.sh` — promote the spike bundle to an erofs artifact

**Files:**
- Create: `hack/build-kasmvnc-erofs.sh` (start from `hack/spike/build-kasmvnc-bundle.sh`)
- Modify: `hack/spike/build-kasmvnc-bundle.sh` (top comment: superseded pointer)

**Interfaces:**
- Produces: `dist/kasmvnc.erofs` (also honors `KASMVNC_OUT` env for output path). Bundle tree exactly as the spike (bin/, lib/ incl. `ld-linux-x86-64.so.2`, share/{kasmvnc,xkb,fonts,themes}, etc/{fonts,openbox}) patchelf'd to `/opt/izba-vnc/...`.

- [ ] **Step 1: Write the script** — copy the spike script, then: (a) rename output dir staging to a `WORK` tempdir; (b) after the patchelf pass add a self-containment assertion loop:

```bash
for f in "$B"/bin/*; do
  file "$f" | grep -q "ELF 64-bit" || continue
  patchelf --print-interpreter "$f" 2>/dev/null | grep -q "^/opt/izba-vnc/lib/ld-linux-x86-64.so.2$" || {
    echo "error: $f does not use the bundle loader" >&2; exit 1; }
  patchelf --print-rpath "$f" | grep -q "^/opt/izba-vnc/lib$" || {
    echo "error: $f rpath escapes the bundle" >&2; exit 1; }
done
```

(c) build the erofs on the host side of the docker run: `mkfs.erofs -zlz4hc "$OUT_FILE" "$STAGE_DIR"` where `OUT_FILE="${KASMVNC_OUT:-$HERE/../dist/kasmvnc.erofs}"`; require `mkfs.erofs` present (`command -v mkfs.erofs || { echo "install erofs-utils (>=1.8) or run hack/build-mkfs-erofs-windows.sh --linux-only" >&2; exit 1; }`); (d) print size + sha256 like `build-sshd.sh` does.

- [ ] **Step 2: Run it and verify** — `bash hack/build-kasmvnc-erofs.sh` (unsandboxed; needs docker + network). Expected: `dist/kasmvnc.erofs` exists, ~40 MB, script exits 0. Then sanity: `docker run --rm -v "$PWD/dist/kasmvnc.erofs:/kv.erofs:ro" debian:bookworm-slim bash -c 'apt-get update -qq >/dev/null && apt-get install -y -qq erofs-utils >/dev/null && fsck.erofs /kv.erofs'` exits 0.

- [ ] **Step 3: Commit**

```bash
git add hack/build-kasmvnc-erofs.sh hack/spike/build-kasmvnc-bundle.sh
git commit -m "feat(hack): build-kasmvnc-erofs.sh — sha-pinned self-contained KasmVNC erofs artifact"
```

---

### Task 2: artifacts — `kasmvnc.erofs` discovery, fail-closed

**Files:**
- Modify: `crates/izba-core/src/artifacts.rs` (locate at :60, locate_from at :71, tests mod at :135)
- Modify: `crates/izba-core/src/sandbox.rs:75` (`Artifacts` struct)
- Modify: `crates/izba-core/src/daemon/server.rs:84` (`ArtifactsFn`), `:552` (variant choice site) and every `(d.deps.artifacts)(…)` call site
- Modify: `packaging/build-deb.sh` (install line + env contract comment)

**Interfaces:**
- Produces: `Artifacts { …, pub kasmvnc_erofs: Option<PathBuf> }`; `pub fn locate(paths: &Paths, variant: KernelVariant, vnc: bool) -> anyhow::Result<Artifacts>` — `kasmvnc_erofs` is `Some` iff `vnc` was requested (found), and locate BAILS when `vnc` is requested and the file is missing. `ArtifactsFn = Box<dyn Fn(&Paths, KernelVariant, bool) -> anyhow::Result<Artifacts> + Send + Sync>`.
- Resolution for the bundle mirrors kernels: `$IZBA_KASMVNC_EROFS` (standalone override, no pairing rule) → `<exe-dir>/../artifacts/kasmvnc.erofs` → `<data>/artifacts/kasmvnc.erofs`.

- [ ] **Step 1: Write the failing tests** in `artifacts.rs` tests mod (reuse `touch`):

```rust
#[test]
fn a_vnc_sandbox_without_the_bundle_fails_with_a_fixable_error() {
    let dir = tempfile::tempdir().unwrap();
    touch(dir.path(), "vmlinux");
    touch(dir.path(), "initramfs.cpio.gz");
    let err = locate_from(None, None, dir.path(), None, KernelVariant::Base, true)
        .unwrap_err()
        .to_string();
    assert!(err.contains("kasmvnc.erofs"), "names the artifact: {err}");
    assert!(err.contains("hack/build-kasmvnc-erofs.sh"), "names the remedy: {err}");
    assert!(err.contains("izba vnc off"), "names the way out: {err}");
}

#[test]
fn the_vnc_bundle_is_found_next_to_the_kernel() {
    let dir = tempfile::tempdir().unwrap();
    touch(dir.path(), "vmlinux");
    touch(dir.path(), "initramfs.cpio.gz");
    touch(dir.path(), "kasmvnc.erofs");
    let art = locate_from(None, None, dir.path(), None, KernelVariant::Base, true).unwrap();
    assert_eq!(art.kasmvnc_erofs, Some(dir.path().join("kasmvnc.erofs")));
}

#[test]
fn a_non_vnc_sandbox_never_looks_for_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    touch(dir.path(), "vmlinux");
    touch(dir.path(), "initramfs.cpio.gz");
    let art = locate_from(None, None, dir.path(), None, KernelVariant::Base, false).unwrap();
    assert_eq!(art.kasmvnc_erofs, None);
}

#[test]
fn the_vnc_bundle_env_override_wins() {
    let dir = tempfile::tempdir().unwrap();
    touch(dir.path(), "vmlinux");
    touch(dir.path(), "initramfs.cpio.gz");
    let alt = tempfile::tempdir().unwrap();
    touch(alt.path(), "kasmvnc.erofs");
    let art = locate_from_with_vnc_env(
        None, None, Some(alt.path().join("kasmvnc.erofs")),
        dir.path(), None, KernelVariant::Base, true).unwrap();
    assert_eq!(art.kasmvnc_erofs, Some(alt.path().join("kasmvnc.erofs")));
}
```

(`locate_from` grows the `vnc: bool` param; add a `locate_from_with_vnc_env` inner fn taking the env value explicitly so tests stay env-free, same style as the existing kernel env plumbing.) Also extend `every_kernel_variant_is_installed_by_the_debian_package` with a sibling assertion that `usr/lib/izba/artifacts/kasmvnc.erofs` appears in `packaging/build-deb.sh`.

- [ ] **Step 2: Run to verify failure** — `cargo test -p izba-core artifacts` → compile errors (missing param/field) count as failing.

- [ ] **Step 3: Implement** — add the field + param threading; bail message:

```rust
anyhow::bail!(
    "VNC is enabled for this sandbox but kasmvnc.erofs was not found in {} \
     (or next to the izba binary) — reinstall izba, run hack/build-kasmvnc-erofs.sh, \
     set IZBA_KASMVNC_EROFS, or disable VNC with `izba vnc off <name>`",
    dir.display()
);
```

In `build-deb.sh` add next to the kernel installs: `install -D -m 0644 "$IZBA_KASMVNC_EROFS" "$STAGE/usr/lib/izba/artifacts/kasmvnc.erofs"` (document the new required env at the top with the others). Update `daemon/server.rs` `ArtifactsFn` signature, `DaemonDeps::production()`, and the `:552` call to pass `false` for now (Task 7 wires the real flag) — every existing test fake gets the extra `_` param.

- [ ] **Step 4: Run** — `cargo test -p izba-core` all green.

- [ ] **Step 5: Commit** — `git commit -m "feat(core): locate kasmvnc.erofs fail-closed for VNC sandboxes"`

---

### Task 3: `SandboxConfig.vnc` + `izba create --vnc`

**Files:**
- Modify: `crates/izba-core/src/state.rs:21` (`SandboxConfig`), `crates/izba-core/src/sandbox.rs:~50` (`CreateOpts`) + `create()` body writing config
- Modify: `crates/izba-core/src/daemon/proto.rs` (`DaemonCreate` — add `#[serde(default)] pub vnc: bool`)
- Modify: `crates/izba-cli/src/main.rs` (create args at :66 area, `build_create_request`)

**Interfaces:**
- Produces: `SandboxConfig { …, #[serde(default)] pub vnc: bool }`; `CreateOpts { …, pub vnc: bool }`; `DaemonCreate { …, #[serde(default)] pub vnc: bool }`; CLI `izba create --vnc`. Additive serde(default) on an existing struct — no proto bump (the bump comes with `VncSet` in Task 8).

- [ ] **Step 1: Failing tests** — in `sandbox.rs` tests near `opts()` helper (:2116): create with `vnc: true`, reload `SandboxConfig` from disk, assert `cfg.vnc`; plus the default-false round-trip. In `main.rs` tests near `parse_create_docker_flags` (:869): `parse_create_vnc_flag` asserting `--vnc` sets the field and its absence leaves `false` (plain bool `#[arg(long)] vnc: bool` — no `--no-vnc`, nothing auto-enables VNC).

- [ ] **Step 2: Run to fail** — `cargo test -p izba-core create && cargo test -p izba-cli parse_create` → compile fail.

- [ ] **Step 3: Implement** — field threading `CreateOpts → SandboxConfig` (serialize in `create()`), `DaemonCreate.vnc → CreateOpts.vnc` in the daemon create handler, clap arg + `build_create_request`.

- [ ] **Step 4: Run** — `cargo test -p izba-core && cargo test -p izba-cli` green.

- [ ] **Step 5: Commit** — `git commit -m "feat(core,cli): SandboxConfig.vnc + izba create --vnc"`

---

### Task 4: disks + cmdline + volume cap

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` — `build_vm_disks` (:212), `build_cmdline` (:242), call sites :920/:937/:1259, tests :2078/:2106/:2196/:3749/:3778
- Modify: `crates/izba-core/src/volume.rs:16` (`MAX_VOLUMES` doc + `validate_volumes` gains vnc-aware form)

**Interfaces:**
- Produces: `fn build_vm_disks(paths, name, image_digest, volumes, vnc_erofs: Option<&Path>) -> Vec<BlockDisk>` — appends `BlockDisk { path: vnc_erofs, readonly: true }` after the volume loop. `fn build_cmdline(name, volumes, builder, usb, docker, vnc: bool) -> String` — appends ` izba.vnc=1` last. `pub fn validate_volumes(volumes: &[VolumeSpec], vnc: bool)` — effective cap `MAX_VOLUMES - (vnc as usize)` with error text mentioning VNC when it bites.

- [ ] **Step 1: Failing tests** (`sandbox.rs` tests):

```rust
#[test]
fn vnc_erofs_appends_after_all_volumes_readonly() {
    // two volumes + vnc: [vda erofs ro, vdb rw, vdc vol, vdd vol, vde kasmvnc ro]
    let disks = build_vm_disks(&paths, "s", "sha256:d", &vols, Some(Path::new("/a/kasmvnc.erofs")));
    assert_eq!(disks.len(), 5);
    assert!(disks[4].readonly);
    assert!(disks[4].path.ends_with("kasmvnc.erofs"));
}

#[test]
fn no_vnc_disk_for_a_plain_sandbox() { /* same call with None => len 4, unchanged order */ }

#[test]
fn cmdline_declares_vnc_only_when_enabled() {
    assert!(build_cmdline("s", &[], false, false, false, true).ends_with(" izba.vnc=1"));
    assert!(!build_cmdline("s", &[], false, false, false, false).contains("izba.vnc"));
}
```

Volume-cap test in `volume.rs`: 24 volumes with `vnc=false` OK; 24 with `vnc=true` errors and the message contains `"VNC"`; 23 with `vnc=true` OK.

- [ ] **Step 2: Run to fail** — `cargo test -p izba-core sandbox:: volume::` → compile fail (arity). Fix EVERY existing call site/test by passing `None`/`false` (≈8 sites; `start_builds_correct_spec` stays asserting `disks.len()==2` — it is now the absence guard).

- [ ] **Step 3: Implement** — thread `config.vnc` at :920 (`build_cmdline(…, config.vnc)`) and :937/:1259 (`build_vm_disks(…, art.kasmvnc_erofs.as_deref())`); `validate_volumes` call sites pass `cfg.vnc`.

- [ ] **Step 4: Run** — `cargo test -p izba-core` green.

- [ ] **Step 5: Commit** — `git commit -m "feat(core): append kasmvnc.erofs after volumes + izba.vnc cmdline + vnc-aware volume cap"`

---

### Task 5: OCI spec — bundle/xkbcomp/secrets binds + /dev/shm resize

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` — `SpecParams` (:619), `generate_spec` (:713, author after the `params.usb` block at :870), constants near :694, tests near :1470
- Modify: `crates/izba-core/src/sandbox.rs:889` (`write_oci_bundle` passes `vnc`)

**Interfaces:**
- Produces constants: `pub const VNC_BUNDLE_SHARED_DIR: &str = "/run/izba/vnc"; pub const VNC_BUNDLE_CONTAINER_DIR: &str = "/opt/izba-vnc"; pub const VNC_SECRETS_SHARED_DIR: &str = "/run/izba/vnc-secrets"; pub const VNC_SECRETS_CONTAINER_DIR: &str = "/run/izba/vnc-secrets"; pub const DEV_SHM_VNC_SIZE: &str = "size=524288k";`
- `SpecParams { …, pub vnc: bool }`; when set, `generate_spec` calls `add_vnc_mounts(&mut spec)?` and `resize_dev_shm(&mut spec)?`.

- [ ] **Step 1: Failing tests** (mirror the USB quartet, using `..base_params(&img)`):

```rust
#[test]
fn a_vnc_sandbox_gets_bundle_xkbcomp_and_secrets_bound_in() {
    let img = image_config(r#"{}"#);
    let spec = generate_spec(&SpecParams { vnc: true, ..base_params(&img) }).unwrap();
    let m = |dest: &str| spec.mounts().as_ref().unwrap().iter()
        .find(|m| m.destination().to_str() == Some(dest)).cloned();
    let bundle = m("/opt/izba-vnc").expect("bundle bind");
    assert_eq!(bundle.source().as_ref().unwrap().to_str(), Some("/run/izba/vnc"));
    assert!(bundle.options().as_ref().unwrap().contains(&"ro".to_string()));
    let xkb = m("/usr/bin/xkbcomp").expect("xkbcomp file bind (server path is hardcoded)");
    assert_eq!(xkb.source().as_ref().unwrap().to_str(), Some("/run/izba/vnc/bin/xkbcomp"));
    let sec = m("/run/izba/vnc-secrets").expect("secrets bind");
    assert!(sec.options().as_ref().unwrap().contains(&"ro".to_string()));
    let shm = m("/dev/shm").unwrap();
    let opts = shm.options().as_ref().unwrap();
    assert!(opts.contains(&"size=524288k".to_string()));
    assert!(!opts.iter().any(|o| o == "size=65536k"), "old size replaced, not duplicated");
}

#[test]
fn a_sandbox_without_vnc_has_stock_shm_and_no_vnc_mounts() { /* default shm size present or absent-as-default; no /opt/izba-vnc, no /usr/bin/xkbcomp mount */ }

#[test]
fn vnc_does_not_disturb_the_rest_of_the_spec() { /* differential guard copied from usb_does_not_disturb_the_rest_of_the_spec: with/without vnc → same namespaces, same /sys typ, same readonly_paths */ }
```

- [ ] **Step 2: Run to fail** — `cargo test -p izba-core runtime_config` → compile fail on `SpecParams.vnc`.

- [ ] **Step 3: Implement** — `add_vnc_mounts` pushes the three binds via `MountBuilder` (bundle: `rbind,ro,nosuid`; xkbcomp: `bind,ro,nosuid`; secrets: `rbind,ro,nosuid,noexec`); `resize_dev_shm` finds the `/dev/shm` mount and rewrites `options`, dropping any `size=…` entry and pushing `DEV_SHM_VNC_SIZE` (in-place mutation pattern of `rebind_sys_mount`). Author both behind `if params.vnc { … }` immediately after the USB block. Thread `vnc: config.vnc` through `write_oci_bundle` → `SpecParams` (update `base_params` with `vnc: false`).

- [ ] **Step 4: Run** — green.

- [ ] **Step 5: Commit** — `git commit -m "feat(core): OCI spec authors VNC bundle/xkbcomp/secrets binds + 512M /dev/shm"`

---

### Task 6: credentials — host-side generation + `izba-vnc` share

**Files:**
- Create: `crates/izba-core/src/vnc.rs` (new module; register in `lib.rs`)
- Modify: `crates/izba-core/src/paths.rs` (add `vnc_share_dir(name) -> PathBuf` = `<sandbox>/vnc`, next to `ssh_share_dir` :111)
- Modify: `crates/izba-core/src/sandbox.rs` — share attach in `extra_shares` (:900-908 conditional-share site), call `vnc::write_vnc_material` from `start_with_timeouts` when `config.vnc`
- Modify: `crates/izba-core/Cargo.toml` — add `sha-crypt` (or `bcrypt`) + `rand` if absent

**Interfaces:**
- Produces: `pub fn write_vnc_material(paths: &Paths, name: &str) -> anyhow::Result<PathBuf>` — generates a fresh 24-char alphanumeric password each call (per-start rotation), writes host-only plaintext `<sandbox>/vnc/password` (0600) and the guest-facing hash file `<sandbox>/vnc/kasmpasswd` (0644 in-share; single line `izba:<hash>:ow`), returns the share dir. `pub fn read_password(paths, name) -> anyhow::Result<String>`. Share tag `"izba-vnc"`.
- **Hash-format ground truth (resolve FIRST, in Step 1):** run upstream `kasmvncpasswd` once in the builder container and inspect: `docker run --rm -v <deb-cache>:/c debian:bookworm-slim bash -c 'apt-get update -qq >/dev/null; apt-get install -y -qq /c/kasmvncserver_bookworm_1.5.0_amd64.deb >/dev/null; printf "secret123\nsecret123\n" | kasmvncpasswd -u izba -ow /tmp/kp; cat /tmp/kp'`. Expected shape `izba:$5$…` or `$6$…` (sha-crypt) → implement with the matching crate and pin the captured line as a golden verify-vector test (verify our hash function output against the crate's own `verify`, and assert the FORMAT prefix matches the captured one). If the format turns out non-crypt(3) (custom), STOP and switch to the documented fallback: share carries plaintext `kasmvnc-password` 0600 and Task 10's init runs bundled `kasmvncpasswd` at boot — record the choice in the spec §6 and adjust Task 10 accordingly. Do not implement both.

- [ ] **Step 1: Capture the format** (command above), paste the observed line into the test as the golden prefix.

- [ ] **Step 2: Failing tests** in `vnc.rs`:

```rust
#[test]
fn write_vnc_material_creates_password_and_hash() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::for_data_dir(dir.path().into());
    std::fs::create_dir_all(paths.sandbox_dir("s")).unwrap();
    let share = write_vnc_material(&paths, "s").unwrap();
    let pw = read_password(&paths, "s").unwrap();
    assert_eq!(pw.len(), 24);
    let kp = std::fs::read_to_string(share.join("kasmpasswd")).unwrap();
    assert!(kp.starts_with("izba:$"), "user + crypt hash: {kp}");
    assert!(kp.trim_end().ends_with(":ow"), "owner perms: {kp}");
    assert!(verify_password(&pw, &kp), "hash round-trips");
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(paths.sandbox_dir("s").join("vnc/password")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn each_start_rotates_the_password() {
    /* call write_vnc_material twice; read_password differs */
}
```

Also in `sandbox.rs`: `start_includes_vnc_share` (mirror `start_includes_ssh_share` :3626) asserting a `FsShare { tag: "izba-vnc", .. }` is present for a vnc sandbox and ABSENT otherwise (extend `start_builds_correct_spec`'s share assertions).

- [ ] **Step 3: Run to fail**, **Step 4: implement** (`verify_password` is a thin wrapper over the crate's verify, used by the test only — mark `#[cfg(test)]` if unused in prod), **Step 5: run green**.

- [ ] **Step 6: Commit** — `git commit -m "feat(core): per-start VNC credentials via izba-vnc share"`

---

### Task 7: RunState recording + start re-verify

**Files:**
- Modify: `crates/izba-core/src/state.rs:122` (`RunState` — add `#[serde(default)] pub vnc: bool` beside `usb_kernel` :154)
- Modify: `crates/izba-core/src/sandbox.rs` — `record_run_state` (:1045, new param), re-verify block (:817-838), literal constructions at `liveness.rs:119`, `testutil.rs:92/:113`, `sandbox.rs:1809/:3298/:3328`, `izba-ttytest/src/scripted_guest.rs:123`
- Modify: `crates/izba-core/src/daemon/server.rs:552` — variant choice site now computes `let vnc = config.vnc;` and calls `(d.deps.artifacts)(&d.paths, variant, vnc)?`

**Interfaces:**
- Produces: `RunState.vnc: bool` — "the sandbox BOOTED with the VNC disk+cmdline" (the only truth for restart_required). `record_run_state(…, vnc: bool)`. Re-verify in `start_with_timeouts`: `let wants_vnc = config.vnc; let has_vnc = art.kasmvnc_erofs.is_some(); if wants_vnc != has_vnc { bail!("sandbox {name}: its VNC setting changed while it was starting; start it again") }` (exact mirror of the USB window guard).

- [ ] **Step 1: Failing tests** — mirror `sandbox.rs:2365/:2370`: `assert!(!started_run_state(&paths, "plain").vnc);` and `assert!(started_run_state(&paths, "withvnc").vnc);` (create the vnc sandbox via `CreateOpts { vnc: true, .. }` and a fake artifacts fn returning `kasmvnc_erofs: Some(touched file)`); plus a re-verify test flipping `config.json` between locate and start (model: the existing USB toctou test near :817's coverage).

- [ ] **Step 2: fail → Step 3: implement → Step 4: green** (`cargo test -p izba-core -p izba-ttytest`).

- [ ] **Step 5: Commit** — `git commit -m "feat(core): record booted vnc in RunState + start-window re-verify"`

---

### Task 8: daemon proto v6 — `VncSet`, Inspect surface

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs` — `DAEMON_PROTO_VERSION` :35 (5→6 + history line "v6 added DaemonRequest::VncSet"), `DaemonRequest` (add `VncSet { name: String, enabled: bool }` after `UsbDetach`), `SandboxDetail` (add `#[serde(default)] pub vnc: bool, #[serde(default)] pub vnc_running: bool, #[serde(default)] pub vnc_url: Option<String>, #[serde(default)] pub vnc_restart_required: bool` — each with the standard additive comment), `request_roundtrip` array
- Modify: `crates/izba-core/src/daemon/server.rs` — dispatch match (new arm near the Usb arms :423), new `fn handle_vnc_set`, `handle_inspect` (:665), new `fn needs_vnc_restart`
- Modify: `app/src-tauri/src/views.rs:439/:463/:987` — `SandboxDetailView` gains the four fields (mechanical; app gate)

**Interfaces:**
- Produces: `handle_vnc_set(d, name, enabled)`: `sandbox_must_exist`; load config; if `cfg.vnc == enabled` → `Ok(DaemonResponse::Ok)` (idempotent); else mutate `config.json` (same read-modify-write helper style as `persist_port_rule` :1012). NO artifact check here — enabling records intent; the artifact gate fires at start (fail-closed) and `restart_required` tells the user. `fn needs_vnc_restart(enabled: bool, running: bool, booted_vnc: bool) -> bool { running && enabled != booted_vnc }` — NOTE: unlike USB this is bidirectional (turning VNC OFF also needs a restart to drop the desktop).
- `handle_inspect` additions: `vnc: cfg.vnc`; `vnc_restart_required: needs_vnc_restart(cfg.vnc, running, run_state_vnc)`; `vnc_running` + `vnc_url` from Task 9's relay registry (until Task 9 lands, wire them as `false`/`None` with a `// Task 9` note is FORBIDDEN — instead Task 9 is a dependency: implement inspect fields in Task 9. In THIS task only `vnc` + `vnc_restart_required`).

- [ ] **Step 1: Failing tests** — proto: extend `request_roundtrip` with `DaemonRequest::VncSet { name: "s".into(), enabled: true }`; assert `DAEMON_PROTO_VERSION == 6` in the existing version test if one pins it. Server (use the existing in-memory client/server test harness around :2249):

```rust
#[test]
fn vnc_set_persists_and_restart_required_is_bidirectional() {
    // create sandbox (fake driver), vnc off, "boot" it (booted vnc=false)
    // VncSet on  -> Inspect: vnc=true,  vnc_restart_required=true
    // VncSet on again -> Ok (idempotent), config unchanged
    // stop; Inspect: vnc_restart_required=false (not running)
}
#[test]
fn needs_vnc_restart_truth_table() {
    assert!(!needs_vnc_restart(false, false, false));
    assert!(!needs_vnc_restart(true,  false, false)); // stopped: next start picks it up
    assert!( needs_vnc_restart(true,  true,  false)); // enable while running
    assert!( needs_vnc_restart(false, true,  true));  // disable while running
    assert!(!needs_vnc_restart(true,  true,  true));
}
```

- [ ] **Step 2: fail → Step 3: implement → Step 4: workspace green + app gate** (`cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`).

- [ ] **Step 5: Commit** — `git commit -m "feat(daemon): VncSet RPC (proto v6) + vnc/restart-required on Inspect"`

---

### Task 9: ephemeral VNC relay + URL surfacing

**Files:**
- Modify: `crates/izba-core/src/daemon/relays.rs` — `RelayManager::publish_bound` (new), `RelaySlot` (store rewritten rule)
- Modify: `crates/izba-core/src/daemon/server.rs` — `Daemon` struct (:127, add `pub vnc_relays: RelayManager`), `handle_start` (:534, after the ports loop), `handle_stop`/`handle_rm` (teardown), `handle_inspect` (vnc_running/vnc_url)

**Interfaces:**
- Produces: `pub fn publish_bound(&self, paths: &Paths, name: &str, rule: PortRule) -> anyhow::Result<u16>` — like `publish` but accepts `host_port: 0`, reads the actually-bound port from the listener (`TcpListener::local_addr()` inside `spawn_slot`, returned through a channel or by binding before thread spawn), stores the REWRITTEN rule (real port) so `active()` reports it, and returns it.
- **Separate manager = the persistence firewall:** the VNC relay lives in `d.vnc_relays`, NEVER in `d.relays`, so `relays::save_rules(paths, name, &d.relays.active(name))` (called by port publish/unpublish handlers) can never leak it into `ports.json`. Guard test required.
- `handle_start`: after the config-ports loop — `if config.vnc { let port = d.vnc_relays.publish_bound(&d.paths, &name, PortRule { bind: Ipv4Addr::LOCALHOST, host_port: 0, guest_port: 6901 })?; progress(format!("vnc: http://127.0.0.1:{port}/")); }` (relay teardown on the existing error path + in stop/rm alongside `d.relays.stop_all`).
- `handle_inspect`: `vnc_running` = vnc relay exists AND a fresh guest dial succeeds (reuse the container-probe budget pattern; only when status running and cfg.vnc); `vnc_url` = `Some(format!("http://izba:{pw}@127.0.0.1:{port}/"))` with `pw = vnc::read_password(...)` when the relay is up.

- [ ] **Step 1: Failing tests** — `relays.rs`: `publish_bound_reports_the_ephemeral_port` (bind port 0 → returned port != 0, `active()` shows same port; runtime-skip on `PermissionDenied` per the listener-test convention `full_connect_via_listener`); server tests: `vnc_relay_never_persists_into_ports_json` (start vnc sandbox with fake connector, then `PortPublish` an unrelated rule, read `ports.json`, assert no `guest_port: 6901` entry) and `stop_tears_down_the_vnc_relay`.

- [ ] **Step 2: fail → Step 3: implement → Step 4: green.**

- [ ] **Step 5: Commit** — `git commit -m "feat(daemon): ephemeral loopback VNC relay + credentialed URL on Inspect"`

---

### Task 10: init — mount, secrets, auto-start, DISPLAY

**Files:**
- Create: `crates/izba-init/src/vnc.rs` (register in `lib.rs`)
- Modify: `crates/izba-init/src/main.rs` (parse `izba.vnc` at the `izba.usb` line :217 style; mount + materialize + start sites), `src/mounts.rs` (vnc mount op + share entry in `rootfs_mount_plan`), `src/exec.rs` (:87/:102/:275), `src/ssh.rs` (:36)

**Interfaces:**
- `mounts.rs`: `pub const VNC_TAG: &str = "izba-vnc";` add to `rootfs_mount_plan()` a virtiofs entry `MountOp::new(VNC_TAG, "/rootfs/izba-vnc", "virtiofs", &["ro"], "").optional()` (after the ssh entry; check `pause_before` applicability for OpenVMM). New `pub fn vnc_mount_op(volume_count: usize) -> MountOp` = `MountOp::new(&volume_device(volume_count), "/run/izba/vnc", "erofs", &["ro"], "")`.
- `vnc.rs`:

```rust
pub const BUNDLE_DIR: &str = "/run/izba/vnc";        // drift-tested vs izba-core
pub const SECRETS_DIR: &str = "/run/izba/vnc-secrets";
pub const VNC_LOG: &str = "/var/log/izba-vnc.log";
pub const DISPLAY: &str = ":1";
/// Copy kasmpasswd out of the share (0644 → SECRETS_DIR 0644, dir 0755);
/// Ok(false) when the share/file is absent. Mirror of ssh::materialize.
pub fn materialize(share_dir: &Path, secrets_dir: &Path) -> std::io::Result<bool>;
/// The two crun-exec argvs (pure, host-testable):
/// 1. sh -c "mkdir -p /var/log; exec /opt/izba-vnc/bin/Xkasmvnc :1 -geometry 1280x800 -depth 24
///    -interface 127.0.0.1 -websocketPort 6901 -publicIP 127.0.0.1
///    -KasmPasswordFile /run/izba/vnc-secrets/kasmpasswd
///    -httpd /opt/izba-vnc/share/kasmvnc/www -fp /opt/izba-vnc/share/fonts/X11/misc
///    -xkbdir /opt/izba-vnc/share/xkb -ac -noreset >>/var/log/izba-vnc.log 2>&1"
///    via crun_exec_argv(mgr, false, "/", &VNC_ENV, Some("0:0"), …)
/// 2. same shape for: exec /opt/izba-vnc/bin/openbox   (DISPLAY=:1 in env)
pub fn desktop_exec_argvs(cgroup_manager: crate::oci::CgroupManager) -> Vec<Vec<String>>;
#[mutants::skip] // reason: guest-only spawn glue, covered by KVM e2e
pub fn start_desktop();
```

`VNC_ENV`: `HOME=/tmp`, `FONTCONFIG_PATH=/opt/izba-vnc/etc/fonts`, `XDG_CONFIG_DIRS=/opt/izba-vnc/etc`, `XDG_DATA_DIRS=/opt/izba-vnc/share`, plus `DISPLAY=:1` for openbox. Run as `--user 0:0` (dockerd precedent — container root maps to an unprivileged guest uid; sidesteps password-file/X-socket ownership).
- `main.rs` wiring: parse `let vnc_enabled = params.get("izba.vnc").map(|v| v == "1").unwrap_or(false);`; in the mount phase, when enabled: apply `vnc_mount_op(vols.len())`, then `std::os::unix::fs::symlink("/run/izba/vnc", "/opt/izba-vnc")` (best-effort, for init-context debugging); after `launch_container()` returns and OUTSIDE the `if docker` block: `if vnc_enabled { vnc::materialize(Path::new("/rootfs/izba-vnc"), Path::new(vnc::SECRETS_DIR)).ok(); vnc::start_desktop(); }`.
- DISPLAY injection: `ExecEngine::new(root: Option<PathBuf>, vnc: bool)` (+ `new_direct`); `build_env_overlay` adds `("DISPLAY", ":1")` when `self.vnc` and the request doesn't already set it (same `has` guard as TERM). `ssh_session_crun_argv(…, vnc: bool)` same. Callers in `main.rs` pass `vnc_enabled`.

- [ ] **Step 1: Failing tests** — `vnc.rs`: `materialize` happy/absent/permissions tests (copy ssh's); `desktop_exec_argvs_runs_server_then_wm_as_root_with_honest_logging` asserting `--user 0:0`, `-publicIP 127.0.0.1`, `-interface 127.0.0.1`, `-KasmPasswordFile /run/izba/vnc-secrets/kasmpasswd`, log redirection, and openbox argv carrying `DISPLAY=:1`. `mounts.rs`: `vnc_mount_op_targets_the_disk_after_volumes` (`volume_count=2` → `/dev/vde`... careful: `volume_device(2)` = `/dev/vde`? `b'c'+2` = `e` — yes) + plan test that `rootfs_mount_plan` contains the optional RO `izba-vnc` virtiofs. `exec.rs`: `display_env_injected_only_for_vnc_and_not_overridden`. `ssh.rs`: same for `ssh_session_crun_argv`. Drift tests both sides: izba-core asserts `VNC_BUNDLE_SHARED_DIR == "/run/izba/vnc"` etc.; izba-init asserts its constants equal the same strings.

- [ ] **Step 2: fail → Step 3: implement → Step 4: green** incl. musl build gate.

- [ ] **Step 5: Commit** — `git commit -m "feat(init): mount kasmvnc erofs, materialize creds, auto-start desktop, DISPLAY injection"`

---

### Task 11: CLI — `izba vnc` group + status line

**Files:**
- Create: `crates/izba-cli/src/commands/vnc.rs`
- Modify: `crates/izba-cli/src/main.rs` (subcommand + dispatch, model `Usb` :277/:485), `crates/izba-cli/src/commands/status.rs` (:46 `render`)

**Interfaces:**
- `pub enum VncCmd { On { name: String }, Off { name: String }, Url { name: String }, Open { name: String } }`; `pub fn run(paths: &Paths, cmd: &VncCmd) -> anyhow::Result<i32>` — On/Off → `DaemonRequest::VncSet`, then Inspect; if `vnc_restart_required` print `vnc: restart required — stop and start '{name}' to apply` (match the USB `render_status` tone). Url → Inspect, print `vnc_url` or a two-case error (`vnc not enabled — run 'izba vnc on {name}'` / `sandbox not running — 'izba start {name}'`). Open → same URL then platform-open (`xdg-open`/`cmd /C start`), `#[mutants::skip] // reason: spawns a browser`.
- `status.rs` `render`: after the docker `mode:` block, when `det.vnc`: `vnc:         enabled (running|dead|restart required)` using the 13-column alignment; include URL line `vnc url:     …` when `Some`.

- [ ] **Step 1: Failing tests** — pure `render_*` helpers: `render` with a vnc detail asserts exact `"vnc:         enabled"` prefix + restart-required wording; `vnc.rs` url-formatting/error-selection helper unit tests (pure fn `fn url_or_reason(det: &SandboxDetail) -> Result<String, String>` so the RPC-driving `run` stays `#[mutants::skip]` per CLI precedent).

- [ ] **Step 2: fail → Step 3: implement → Step 4: green.**

- [ ] **Step 5: Commit** — `git commit -m "feat(cli): izba vnc on/off/url/open + status surface"`

---

### Task 12: KVM e2e

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs`

**Interfaces:**
- Consumes: everything above; the bundle must be discoverable via the PRODUCTION path — the test does NOT set `IZBA_KASMVNC_EROFS`. Preflight helper:

```rust
fn vnc_bundle_available() -> bool {
    // same discovery the daemon uses: exe-relative artifacts dir
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_izba"));
    exe.parent().and_then(|d| d.parent())
        .map(|d| d.join("artifacts/kasmvnc.erofs").exists())
        .unwrap_or(false)
}
```

(CI stages the file at `target/artifacts/kasmvnc.erofs` — `CARGO_BIN_EXE_izba` is `target/debug/deps/../izba` → exe-dir `target/debug`, `../artifacts` = `target/artifacts`. Verify the exact exe-dir in-step and adjust the relative hop; the loud skip prints the expected path.)
- Extend `http_get` family with:

```rust
fn http_get_status(port: u16, path: &str, basic_auth: Option<(&str, &str)>) -> anyhow::Result<(u16, String)> {
    // TcpStream::connect, write "GET {path} HTTP/1.0\r\n" + optional
    // "Authorization: Basic {base64(user:pass)}\r\n" + "\r\n"; parse status line; return (code, body)
}
```

(base64 by hand — 20 lines, no new dev-dep; or reuse a base64 already in the tree if one exists.)

- [ ] **Step 1: Write the test** (fails/skips until CI staging lands in Task 13 — locally run `hack/build-kasmvnc-erofs.sh KASMVNC_OUT=target/artifacts/kasmvnc.erofs` first):

```rust
#[test]
fn vnc_desktop_e2e() {
    if !want() { return; }
    if !vnc_bundle_available() {
        eprintln!("SKIP vnc_desktop_e2e: kasmvnc.erofs not staged at <target>/artifacts — run hack/build-kasmvnc-erofs.sh");
        return;
    }
    // 1. create --vnc + start (alpine IMAGE), SandboxGuard
    // 2. `izba vnc url` → parse http://izba:PW@127.0.0.1:PORT/
    // 3. poll http_get_status(PORT, "/", None) until (401, _) — auth required
    // 4. http_get_status(PORT, "/", Some(("izba", PW))) → (200, body) && body.to_lowercase().contains("kasm")
    // 5. `izba vnc off` → status contains "restart required"
    // 6. plain sandbox (no --vnc): `izba vnc url` exits non-zero mentioning "vnc on"
    // 7. rm; missing-artifact refusal is covered at unit level (locate) — not re-proven here
}
```

Poll with the 120 s deadline pattern; on failure append the sandbox's `logs/console.log` tail like `docker_diag` does.

- [ ] **Step 2: Run locally** (unsandboxed, KVM): build the bundle, stage it, `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e vnc_desktop_e2e -- --test-threads=1 --nocapture`. Expected: PASS. Iterate here — this is the step that shakes out real-VM surprises (fontconfig, timing, crun exec env).

- [ ] **Step 3: Commit** — `git commit -m "test(cli): VNC desktop KVM e2e — credentialed web client through the relay"`

---

### Task 13: CI + packaging wiring

**Files:**
- Modify: `.github/workflows/e2e.yml` (new artifact job + staging + Windows staging), `.github/workflows/_artifacts.yml` (same job + roll-up needs), `.github/workflows/release.yml` (download + `IZBA_KASMVNC_EROFS` for deb; Windows stage list), `hack/devbuild.sh` (artifact download list)
- Modify: `docs/testing.md` (local bundle build note)

**Interfaces:**
- New job (both e2e.yml and _artifacts.yml — they are duplicated by design):

```yaml
  kasmvnc-erofs:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@<same pin as siblings>
      - uses: actions/cache@<same pin>
        id: kasmvnc-cache
        with:
          path: dist/kasmvnc.erofs
          key: kasmvnc-erofs-${{ hashFiles('hack/build-kasmvnc-erofs.sh') }}
      - if: steps.kasmvnc-cache.outputs.cache-hit != 'true'
        run: |
          hack/build-mkfs-erofs-windows.sh --linux-only
          hack/build-kasmvnc-erofs.sh
      - uses: actions/upload-artifact@<same pin>
        with: { name: kasmvnc-erofs, path: dist/kasmvnc.erofs, if-no-files-found: error }
```

- `linux-kvm` job: add `kasmvnc-erofs` to `needs`, download it, and stage: `mkdir -p target/artifacts && cp <dl>/kasmvnc.erofs target/artifacts/` + an explicit `test -f target/artifacts/kasmvnc.erofs` step (so a broken artifact job fails loudly instead of skipping the e2e). NO env override.
- `windows-whp`: add to `needs` + stage into the exe-relative `stage/artifacts/` next to vmlinux (production discovery on Windows too).
- `release.yml`: download into `dl/art/`, export `IZBA_KASMVNC_EROFS=dl/art/kasmvnc.erofs` for the deb step; append to the Windows `stage/artifacts` copy list.
- `_artifacts.yml`: add `kasmvnc-erofs` to the roll-up `needs` list (:284).

- [ ] **Step 1: Make the edits.** No unit test exists for YAML; the packaging cross-check test from Task 2 guards `build-deb.sh`. Add one more cross-check in `artifacts.rs` tests: read `.github/workflows/e2e.yml` and assert it contains `kasmvnc-erofs` (same file-reading pattern as `every_kernel_variant_is_installed_by_the_debian_package`).
- [ ] **Step 2: Verify** — `cargo test -p izba-core artifacts` green; `actionlint` if available; push branch and confirm the new job appears and caches (checked during CI iteration).
- [ ] **Step 3: Commit** — `git commit -m "ci: build, cache and stage kasmvnc.erofs across e2e/artifacts/release/devbuild"`

---

### Task 14: Windows WHP validation

**Files:**
- Modify: `hack/spike/validate-izba-windows.ps1`

**Interfaces:**
- Consumes: staged `kasmvnc.erofs` next to the exe (Task 13). Adds a section after the existing lifecycle checks: create `--vnc` sandbox, start, `izba vnc url` → parse URL, `Invoke-WebRequest` without creds expecting 401 (`-SkipHttpErrorCheck`), with `-Headers @{Authorization=("Basic "+[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("izba:$pw")))}` expecting 200 + `kasm` in content, then `izba rm --force`. Guard the whole section on the artifact's presence with a loud `Write-Warning "SKIP vnc: kasmvnc.erofs not staged"` so local runs without the artifact stay usable.

- [ ] **Step 1: Write the section.** **Step 2: Run** via `powershell.exe -NoProfile` against a devbuild (unsandboxed; needs the artifact staged). Expected PASS. **Step 3: Commit** — `git commit -m "test(windows): WHP validation covers the VNC relay end-to-end"`

---

### Task 15: docs + contracts

**Files:**
- Modify: `CLAUDE.md` (Load-bearing contracts: disk order sentence gains the vnc-after-volumes rule + `izba.vnc=1` in the cmdline chain; DAEMON_PROTO_VERSION note 5→6), `README.md` (command surface: one `izba vnc` paragraph + `--vnc`), `docs/testing.md` (bundle prerequisite for the vnc e2e)

- [ ] **Step 1: Make the edits** (keep the existing terse contract style — amend the existing bullets, don't add new sections).
- [ ] **Step 2: `cargo test --workspace` still green** (docs-only, but the CLAUDE.md compliance of wording matters for future agents).
- [ ] **Step 3: Commit** — `git commit -m "docs: VNC contracts (disk order, cmdline, proto v6) + command surface"`

---

## Final gate (before PR)

- [ ] All six workspace gates + app gate green locally.
- [ ] `hack/build-kasmvnc-erofs.sh` + staged bundle + `IZBA_INTEGRATION=1` daemon_e2e (full suite, `--test-threads=1`) green locally on KVM, including `vnc_desktop_e2e`.
- [ ] `cargo mutants` gate expectations: new pure fns have tests; spawn-glue carries `#[mutants::skip] // reason: …`.
- [ ] Push, open PR (ready, never draft), dispatch `bash hack/devbuild.sh`, iterate CI to CLEAN (Actions + Sonar + Greptile 5/5 per greploop).
