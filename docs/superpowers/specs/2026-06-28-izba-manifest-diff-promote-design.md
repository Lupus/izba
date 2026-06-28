# izba.yml manifest + `diff` / `promote` / `export` workflow — design

Status: **draft for review** · Date: 2026-06-28

## 1. Summary

Introduce a Kubernetes-style project manifest (`izba.yml`) that declares a
sandbox's desired configuration (image or build recipe, resources, volumes,
ports, egress policy), plus a reconciliation workflow between that repo-tracked
manifest and izba's existing host-only **managed truth**
(`~/.local/share/izba/sandboxes/<name>/`):

- `izba diff` — show structural drift between manifest and managed truth.
- `izba promote` — apply manifest → managed truth, **human-gated** across a
  trust boundary (the manifest is agent-writable; the managed truth is not).
- `izba export` — write managed truth → `izba.yml` ("sync the truth back to the
  repo").

The central idea: `izba.yml` lives in the project workspace, which is mounted
into the guest at `/workspace`, so **the agent running inside the sandbox can
edit it**. The manifest can therefore only ever *propose* configuration; a
host-side, human-gated `promote` is the only thing that *enacts* it. This is the
pull-request model applied to a sandbox's own jail, and it is the same host-pin
pattern already used for live egress policy (finding F-30) and for the ssh
material isolated at init-root `/run/izba/ssh` outside the `/rootfs` overlay.

## 2. Motivation, goals, non-goals

**Today**, all sandbox configuration is per-invocation CLI flags
(`crates/izba-cli/src/main.rs`). There is no project file; nothing is version
controllable; recreating a sandbox means remembering the exact flags. The
managed truth (`config.json` immutable + `policy.yaml` editable) is the only
durable record and it is not human-authored.

**Goals**

- A declarative, version-controllable project file (`izba.yml`).
- `izba create` honors the manifest; the Tauri app can create from it.
- A safe, reviewable path to change a running sandbox's configuration —
  including its own firewall — that an untrusted in-guest agent cannot subvert.
- A way to capture host-side / app-driven changes back into the repo.

**Non-goals (this iteration)**

- Multiple sandboxes per manifest. The schema is `kind`-extensible (§12) but we
  ship `kind: Sandbox` only.
- New build options not present in build-in-VM today (`--build-arg`,
  `--secret`, `--no-cache`, `--target`).
- A new daemon RPC for diff/promote/export. These are computed host-side from
  files the daemon already exposes (§11).

## 3. Trust model (the spine)

Two stores, deliberately asymmetric in trust:

| Store | Location | Writable by | Trust |
|---|---|---|---|
| **Repo manifest** `izba.yml` (+ referenced `Dockerfile`) | project root → mounted at guest `/workspace` | the human **and the in-guest agent** | **untrusted** — desired state / proposal |
| **Managed truth** | `~/.local/share/izba/sandboxes/<name>/` (`config.json` + `policy.yaml`), host-only, outside the `/rootfs` overlay | host only | **authoritative** |

Two flows, matching the two write paths:

- **Agent / CLI (untrusted):** edit `izba.yml` → `izba diff` → `izba promote`
  (gated) → managed truth.
- **App (trusted human at the keyboard):** edit firewall / resources in the UI →
  applied **live** to managed truth → "Save to repo" / `izba export` →
  `izba.yml` (a git diff then appears for the human to commit).

The asymmetry is intentional: the human driving the app *is* the reviewer, so
app edits need no `promote` gate; the in-guest agent is untrusted, so its edits
must pass one.

## 4. Manifest schema (Kubernetes-style)

```yaml
apiVersion: izba.dev/v1alpha1
kind: Sandbox
metadata:
  name: myapp                 # optional; defaults to workspace basename
  labels:
    project: acme
spec:
  # --- image OR build (mutually exclusive) ---
  image: ubuntu:24.04         # an OCI ref
  # build:                    # a build recipe (requires build-in-VM)
  #   context: .              # build context dir (default ".")
  #   dockerfile: Dockerfile  # relative to context (default "<context>/Dockerfile")
  #   tag: myapp:dev          # optional; otherwise an internal cache tag is used
  #   allow:                  # extra egress hosts permitted DURING the build
  #     - get.example.com     #   (Docker Hub hosts are always allowed)
  #   resources:              # builder VM sizing (maps to build --cpus/--mem)
  #     cpus: 2
  #     memory: 4Gi
  resources:
    cpus: 2
    memory: 4Gi               # k8s quantity (Mi/Gi) -> internal mem_mb
  rootDisk:
    size: 8Gi                 # writable overlay (scratch) over the RO image -> rw.img
  volumes:
    - name: data              # named => persistent (survives rm); omit name => ephemeral
      mountPath: /data        # k8s volumeMount vocabulary
      size: 8Gi
  ports:
    - guest: 80               # ~ containerPort, but honest "guest" vocabulary
      host: 8080              # ~ hostPort
      bind: 127.0.0.1         # ~ hostIP; optional, defaults to 127.0.0.1
  egress:                     # persists to the managed policy.yaml
    enforce: true
    allow:
      - host: github.com      # bare host => ports [80, 443]
      - host: api.example.com
        ports: [443]
        access: read          # read | read-write
    git:
      - repo: github.com/me/*
        access: read-write
```

Design notes:

- **`apiVersion` + `kind`** make the document self-describing. The parser
  dispatches on them; an unknown/newer `kind` or `apiVersion` **fails loudly**
  ("this izba.yml needs a newer izba") rather than silently mis-parsing.
  `v1alpha1` honestly signals the schema may still move. The group domain
  `izba.dev` is a placeholder (bikeshed: `izba.sh`, `izba.oxnull.net`, …).
- **No size primitives.** `memory` and every `size` are k8s quantity strings
  (`512Mi`, `4Gi`, `8Gi`), parsed to internal `mem_mb` / bytes. This kills the
  `rw_size_gb` smell.
- **No CLI grammar in the manifest.** Volumes and ports are structured objects
  (`mountPath`, `guest`/`host`/`bind`), never the colon-delimited
  `data:/data:8` / `127.0.0.1:8080:80` strings. The colon grammar remains only
  on the CLI flags themselves.
- **`image` xor `build`.** Exactly one must be present, mirroring the existing
  `--image` xor `--build` rule. `build:` requires the build-in-VM feature.
- **No secrets in the manifest, ever.** CA keys, ssh host keys, etc. stay
  host-only and are never rendered into `izba.yml`.

### Build recipe surface (mirrors build-in-VM as landed)

`build:` mirrors the real `izba build` surface and **nothing more**:
`context` (positional CONTEXT), `dockerfile` (`-f`), `tag` (`-t`), `allow`
(`--build-allow`, extra egress hosts during the build on top of the always-on
Docker Hub allow-list), and `resources` (builder VM `--cpus`/`--mem`).
Deliberately absent because build-in-VM does not have them yet: `build-arg`,
`secret`, `no-cache`, `target`. They are out of scope until the feature adds
them; the schema can grow then.

## 5. On-disk layout (host-only additions)

Inside the existing managed sandbox dir `~/.local/share/izba/sandboxes/<name>/`,
add two host-only artifacts (outside `/rootfs`, never exposed to the guest):

- **`manifest.base.yaml`** — the canonical manifest as of the last
  reconciliation (`create` / `promote` / `export`). This is the shared base for
  3-way comparison (§6). Stored in normalized canonical form.
- **`manifest.review`** — the review token: a hash over the exact bytes the last
  `izba diff` showed the human (§7). Contains the manifest hash **and** the
  hash of any referenced `Dockerfile` (§9).

Both are host-written, host-read, never inside the workspace/overlay, so the
in-guest agent can neither read nor forge them.

The existing ground truth is unchanged: `config.json` (image digest + ref,
cpus, mem, ports, volumes), `policy.yaml` (egress). The managed *effective
state* used in diffs is **rendered from these into manifest shape** by a single
normalization function (so the comparison is apples-to-apples).

## 6. Three-way reconciliation

A structural, field-by-field 3-way compare on a normalized in-memory struct
(never textual — YAML formatting and comments never read as drift):

- **base** = `manifest.base.yaml` (last reconciled, host-only)
- **repo** = current `izba.yml`
- **managed** = current effective managed state (rendered from `config.json` +
  `policy.yaml`)

| repo vs base | managed vs base | State | Suggested action |
|---|---|---|---|
| changed | same | repo ahead | `izba promote` |
| same | changed | managed ahead (app/CLI edits) | `izba export` |
| changed | changed | **diverged** | `izba diff` shows both sides; human resolves |
| same | same | in sync | nothing |

`izba diff` renders all three columns when relevant and labels the state. It
groups changes by field class (live / restart / image — §8) so the human sees
the blast radius, and it flags **security-relevant deltas** distinctly (§10).

## 7. The review gate

`izba diff` writes `manifest.review` = hash of the exact `izba.yml` (and
referenced `Dockerfile`) it just showed. `izba promote` requires
`hash(repo now) == manifest.review`:

- **No token** → the manifest was never reviewed → **fail without `--force`**
  ("run `izba diff` first").
- **Token mismatch** → `izba.yml` (or the Dockerfile) changed *after* you ran
  `diff` → **fail** ("manifest changed since review — re-run `izba diff`"). This
  is the TOCTOU guard: it stops an agent from sneaking edits in between the
  human's review and the promote.

`--force` is the single escape hatch for **both** cases, always with a loud
warning. In the stale case the warning is explicit: "you are promoting
**unreviewed** changes." The token is host-only, so a guest agent cannot fabricate
a reviewed state.

## 8. `promote` field semantics — restart, never destructive recreate

Verified against `crates/izba-core/src/sandbox.rs`: `start_with_timeouts`
re-reads `config.json` from disk on every start (`sandbox.rs:592`) and passes
`cpus`/`mem_mb` straight into the VMM launch spec (`:656-657`), with disks
rebuilt from `config.image_digest` (`:658`). So **no config change ever requires
a destructive `rm`+recreate** — worst case is a restart, and the rw scratch +
named volumes persist across it.

`promote` writes the managed truth, then applies by field class:

- **Live** — `egress` (hot-reload via the existing `ReloadPolicy` path),
  `ports` (publish/unpublish), `volumes` (attach/detach). Applied immediately,
  no interruption.
- **Restart** — `resources.cpus`, `resources.memory`, `image`/`build`.
  `config.json` is updated immediately; the values take effect on the next
  start. `izba status` shows a `pending restart: cpus 2→4` delta.
  `izba promote --restart` performs the stop→start now (scratch + named volumes
  persist).
- **Image** — additionally governed by `--reset-scratch` (default **yes**),
  consulted **only when `image`/`build` actually changes**:
  - `--reset-scratch=y` (default): a clean rw.img overlay is created on the new
    image's erofs base. Correct overlay semantics. Discards un-volumed writes to
    the root filesystem (expected when the base image changes).
  - `--reset-scratch=n`: keep the existing overlay on the new base, behind an
    **expert-only warning**: packages installed (`apt-get install`) against the
    old base may now have missing libs / wrong ABI and can render the guest
    unbootable — proceed only if you understand the overlay semantics.

## 9. Build recipes in diff / promote

The managed truth stores a **resolved image digest**; the manifest may carry a
**build recipe**. Bridging them:

- **Review/diff scope includes referenced files.** Because the `Dockerfile` is
  itself agent-writable in `/workspace` and determines what gets baked into the
  image, `izba diff` hashes and (on change) displays the **`Dockerfile` content**
  alongside the manifest, and `manifest.review` covers both. A human reviewing a
  promote sees Dockerfile changes, not just `izba.yml` changes.
- **Drift detection for `build:`.** A build change is detected when the recipe
  (`context`/`dockerfile`/`tag`/`allow`/builder `resources`) **or the
  Dockerfile content** differs from `manifest.base`. (Full build-context content
  is not hashed — too large; the Dockerfile + allow-list are the
  security-relevant inputs, and a rebuild always re-reads the live context.)
- **Promoting a `build:` change** triggers a rebuild (the throwaway buildkit
  builder VM) → new digest → an `image` restart-class change (so the
  `--reset-scratch=y` default applies). The rebuild reuses the persistent
  `izba-buildcache` volume.
- **`image:` (plain ref).** Drift is the ref string changing; optionally
  re-resolved to a digest at promote time.

## 10. Security considerations

Grounded in `docs/security/` (threat model: guest-is-hostile microVM) and the
"never silently downgrade security; fail closed; loud + opt-in" rule.

- **The manifest is untrusted input.** It is parsed defensively (validated
  names, quantities, paths; `dockerfile` must resolve inside `context` —
  mirroring the existing `dockerfile_rel` check). It can only *propose*; only a
  host-side human `promote` enacts.
- **Review state is unforgeable.** `manifest.base.yaml` and `manifest.review`
  live host-only, outside the overlay; the guest agent cannot read or write
  them.
- **Security-weakening deltas are flagged loudly.** `diff` and `promote` mark
  any change that *loosens* the jail with a `⚠ weakens egress` marker: adding
  `allow` entries, `enforce: true → false`, `access: read → read-write`,
  widening `git` scope, or adding `build.allow` hosts. A human skimming a
  promote cannot miss a loosened firewall.
- **`--force` is loud.** It bypasses the review gate but always prints a warning
  naming exactly what is being applied unreviewed.
- **No secrets cross into the repo.** `export` renders only declarative config;
  host-only key material is never written to `izba.yml`.
- **`export` exposes truth to an agent-readable file** — acceptable: it only
  reflects the already-enacted managed state; it grants no new capability.

## 11. Daemon proto impact

The diff/promote/export computations are **host-side**, over files the daemon
already serves:

- `diff` / `export` read the managed truth via the existing `Inspect`
  (`SandboxDetail`) plus `policy.yaml` on disk; no new RPC.
- `promote` of live fields reuses `ReloadPolicy`, `PortPublish/Unpublish`,
  `VolumeAttach/Detach`. `promote --restart` reuses `Stop` + `Start`.
- `create` honoring the manifest reuses `Create` (with the build-in-VM
  `DaemonCreate { builder: bool }` path when `build:` is present).

⇒ **No `DAEMON_PROTO_VERSION` bump** for the manifest workflow itself. (If a
future iteration moves reconciliation server-side, that is a separate, gated
change.) The app-facing Tauri commands gain thin wrappers
(`diff`/`promote`/`export`) over the same host-side logic.

## 12. Out of scope / future

- **Multiple sandboxes per project.** `kind` is the extension axis (pod →
  statefulset analogy): a future `kind: Project` document owns a set of
  sandboxes, either via embedded `Sandbox` templates or **multi-document YAML**
  (`---`-separated `kind: Sandbox` docs in one `izba.yml`, the canonical k8s
  pattern). No migration of the `kind: Sandbox` schema is required.
- **Server-side reconciliation** (a `DaemonRequest::Promote`) if/when the app or
  remote control needs it.
- **Richer build options** (`build-arg`, `secret`, `no-cache`, `target`) once
  build-in-VM grows them.

## 13. Tauri app surface

- **Create dialog:** a "Create from manifest" path that loads `izba.yml` from
  the chosen workspace and prefills the form (`CreateOpts` in
  `app/src-tauri/src/views.rs`); seeds `manifest.base.yaml`.
- **Live editors:** firewall and resource editors write the managed truth
  directly (live for egress/ports/volumes; `pending restart` badge for
  cpus/mem/image), reflecting the trusted-human write path.
- **Drift badge:** surfaced when managed ≠ repo, with the 3-way state label.
- **Review & promote panel:** when repo is ahead (or diverged), render the same
  structural diff with the `⚠ weakens egress` flags; a "Promote" action mirrors
  the CLI gate.
- **"Save to repo" button:** `export` — writes managed truth into `izba.yml`;
  the human then sees and commits the git diff.

## 14. Testing strategy (TDD)

Unit (host-testable, no VM):

- **Manifest parse/validate:** apiVersion/kind dispatch; unknown kind/version
  fails loud; `image` xor `build`; quantity parsing (`4Gi`/`512Mi` → bytes);
  `dockerfile` inside `context`; defensive rejection of bad names/paths.
- **Normalization round-trip:** manifest → internal → rendered managed →
  manifest is stable (no spurious drift); `export` round-trips.
- **3-way reconciliation:** each cell of the §6 table (repo-ahead,
  managed-ahead, diverged, in-sync).
- **Review gate:** no-token fail; token-match pass; stale-token fail; `--force`
  bypass + warning text; Dockerfile-change invalidates the token.
- **Field classification:** live vs restart vs image; `--reset-scratch` default
  and `=n` warning; flag only consulted on image change.
- **Security flagging:** every weakening delta produces `⚠`.
- **Build diff:** recipe change and Dockerfile-content change both detected;
  promote of a build change is image-restart-class.

App (`app/src-tauri`): view tests for create-from-manifest, drift badge state,
and the promote panel — and run the App CI gate locally (it is outside the
workspace gates).

## 15. Decisions log

1. **Schema scope:** single sandbox now (`kind: Sandbox`), `kind`-extensible to
   `Project` later — no schema migration.
2. **Write paths asymmetric:** app writes managed directly; agent/CLI must
   `promote`.
3. **No destructive recreate:** config changes are live or restart-class;
   verified `config.json` is re-read each start.
4. **Image-change overlay:** single `--reset-scratch` flag, default **yes**;
   `=n` is expert-only and loud.
5. **Command names:** `diff` / `promote` / `export` (`promote` carries the
   trust-boundary-elevation meaning that `apply` would not).
6. **`--force`** overrides both never-reviewed and stale-review, always loud.
7. **k8s-style schema:** `apiVersion`/`kind`/`metadata`/`spec`, quantity
   strings, structured volumes/ports — no CLI grammar, no size primitives.
8. **Build recipe** mirrors build-in-VM exactly; Dockerfile content is part of
   the review/diff scope.
9. **No proto bump:** diff/promote/export are host-side over existing RPCs.
