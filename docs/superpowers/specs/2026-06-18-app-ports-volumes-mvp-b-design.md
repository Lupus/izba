# MVP-B — Ports & Volumes in the Tauri app (design)

Date: 2026-06-18
Status: approved-for-planning
Base: `main` after PR #50 (`ce83b0d`, "Tauri app UX") merged.
Branch: `worktree-mvp-b-app-ports-volumes`.

## Goal

Wire the two remaining sandbox-resource stories — **port publishing** and
**persistent / ephemeral volume management** — into the desktop app, both at
**create time** (wizard) and for **existing sandboxes** (management views). The
CLI / daemon / driver datapath largely ships already; MVP-B is mostly app
wiring, plus a small, additive backend slice to fill the gaps the app needs
(volume enumeration, guarded delete, live-port persistence, editable volumes).

This is the app-side counterpart to MVP-A (the M2.1 firewall **policy** UI:
`PolicyEditor` / `NetlogView` / `FirewallStatus`). MVP-B shares only two files
with MVP-A — `NewSandbox.tsx` (the create wizard) and `Detail.tsx` (the tabbed
detail panel) — and touches no policy *logic*. PR #50 already landed the
validated port-row pattern in the wizard; MVP-B reuses it for the new volume
rows.

## What already ships (verified)

| Capability | CLI | Daemon proto | App |
| --- | --- | --- | --- |
| Port publish at **create** | `-p [BIND:]HOST:GUEST` | `DaemonCreate.ports` | ✅ wizard |
| Port publish **live** | `port publish` | `PortPublish` | ❌ |
| Port unpublish **live** | `port unpublish` | `PortUnpublish` | ❌ |
| Port list **live** | `port ls` | `PortList` → `Ports` | ❌ |
| Volume declare at **create** | `--volume [NAME:]PATH:SIZE` | `DaemonCreate.volumes` | ❌ (hardcoded `vec![]`) |
| Volume **prune unreferenced** | `volume prune` | `VolumePrune` → `Pruned` | ❌ |
| Volume **list** | ❌ | ❌ | ❌ |
| Volume **delete (one)** | ❌ | ❌ | ❌ |
| Volume **attach/detach (existing sandbox)** | ❌ | ❌ | ❌ |

Key facts the design leans on:

- `PortRule { bind: Ipv4Addr, host_port: u16, guest_port: u16 }`
  (`state.rs:39`), identity = `(bind, host_port)`.
- Live `PortPublish`/`PortUnpublish` are **not** persisted to `config.json` —
  they live only in the relay manager + a transient `run/ports.json`, so they
  vanish on sandbox restart. On `Start`, only `config.ports` is re-applied
  (`server.rs:330`).
- `VolumeSpec { name: Option<String>, guest_path: PathBuf, size_bytes: u64 }`
  (`volume.rs:21`). `name.is_some()` ⇒ persistent
  (`<data>/volumes/<name>.img`, survives `rm`); `None` ⇒ ephemeral
  (`<sandbox>/volumes/<index>.img`, reaped at `rm`).
- **Ephemeral image hazard:** `image_path` keys an ephemeral image by its
  *positional index* in the full `config.volumes` list (`volume.rs:39`,
  `sandbox.rs:178/245`). Removing any volume before an ephemeral one shifts its
  index, mis-mapping or wiping it on next boot. This is the disk-order contract
  (risk register #5) and forces the stable-id change below.
- `SandboxDetail` (the `Inspect` reply) carries persisted `ports` but **not**
  `volumes` (`proto.rs:122`).
- `prune_volumes` already builds the "referenced by some `config.json`" set
  (`sandbox.rs:838`); `VolumeList`/`VolumeRemove`/the detach guard reuse it.

## Out of scope

- Attaching/detaching volumes **live** (applied to a running VM without
  restart) — not a datapath capability; MVP-B applies volume edits on next
  restart.
- Cross-sandbox single-writer enforcement for a shared persistent volume —
  unchanged from today (convention, surfaced as a UI caveat, not a new guard).
- Driver changes (disks/relays already order-driven on both CH and OpenVMM).
- Policy/firewall UI (MVP-A, already merged).

## Decisions (from brainstorming)

1. **Volume listing** → add a minimal `VolumeList` daemon op + `izba volume ls`,
   so the app and CLI share a real listing.
2. **Information architecture** → per-sandbox **Ports** and **Volumes** tabs in
   `Detail`, plus a top-level **Storage** entry in the left Rail for
   cross-sandbox persistent-volume management.
3. **Live-port persistence** → add `--persist` to `izba port publish` (also
   writes `config.ports`); the Ports tab badges live-only forwards "active
   until restart" with a **Make persistent** button; every forward gets an
   **Open in browser** icon. `PortUnpublish` also drops the rule from
   `config.ports` so a removed forward stays removed across restart.
4. **Volume delete** → guarded `VolumeRemove` + `izba volume rm NAME` (fails
   closed if any sandbox references it).
5. **Editable volumes** → the per-sandbox Volumes tab can add/remove volumes;
   edits are written to `config.volumes` and **applied on next restart**
   (a "changes apply on next restart" banner + a **Restart now** button), never
   live. Backed by `VolumeAttach`/`VolumeDetach`.
6. **Ephemeral identity** → ephemeral images get a stable backing id so
   detach/reorder can't mis-map them (see below).

## Backend slice (Rust)

All proto changes are **additive** (`#[serde(default)]` fields, new enum
variants). `DAEMON_PROTO_VERSION` stays `1` — same convention used when
`DaemonCreate.volumes` was added.

### Stable ephemeral identity

Add to `VolumeSpec`:

```rust
pub struct VolumeSpec {
    pub name: Option<String>,
    pub guest_path: PathBuf,
    pub size_bytes: u64,
    /// Stable backing id for an ephemeral image (`<sandbox>/volumes/<id>.img`),
    /// assigned once at provision time and never recomputed from list position.
    /// `None` for persistent volumes (those are name-keyed) and for a freshly
    /// parsed spec (the backend assigns it at create/attach).
    #[serde(default)]
    pub eph_id: Option<u64>,
}
```

- `image_path(persistent)` unchanged (`<data>/volumes/<name>.img`).
- `image_path(ephemeral)` uses `eph_id` (`<sandbox>/volumes/<id>.img`), not the
  list index.
- **`create`:** assign ephemeral ids `0, 1, 2, …` in declaration order (one
  time). A fresh single-ephemeral create still gets `0.img` — existing tests
  (`create_provisions_volume_images`, `disks_append_volumes_after_rw`) stay
  green.
- **`attach`:** assign `eph_id = (max existing eph_id) + 1`. Append-only ⇒ no
  existing id moves.
- **`detach`:** remove the entry from `config.volumes`; **no file I/O** (so it
  is safe in any sandbox state and on Windows where a running VM holds the image
  open). Surviving ephemeral ids are unchanged → no mis-map. An orphaned
  ephemeral image (rare) is reclaimed at sandbox `rm`.
- Migration: M3 volumes are unreleased, so there are no on-disk
  `config.volumes` with the old scheme to migrate.

This is a **host-only** change: the disk *order* (vdc/vdd…), the `izba.volumes`
cmdline (ordered guest paths), and the guest mount plan are all untouched, so it
is not a guest-facing contract change. It is still validated by the KVM volume
integration test.

### Proto additions (`daemon/proto.rs`)

```rust
// requests
PortPublish { name, rule, #[serde(default)] persist: bool },   // persist added
VolumeList,
VolumeRemove { name: String },
VolumeAttach { name: String, spec: VolumeSpec },
VolumeDetach { name: String, guest_path: PathBuf },

// SandboxDetail gains:
#[serde(default)] pub volumes: Vec<VolumeSpec>,

// responses
Volumes { volumes: Vec<VolumeInfo> },
// VolumeRemove reuses the existing `Pruned { removed, reclaimed_bytes }`.

pub struct VolumeInfo {
    pub name: String,
    pub size_bytes: u64,     // apparent/declared (image file length)
    pub actual_bytes: u64,   // on-disk allocation, best-effort
    pub referenced_by: Vec<String>,
}
```

### Core / daemon (`sandbox.rs`, `daemon/server.rs`)

- `sandbox::list_volumes(&paths) -> Vec<VolumeInfo>` — scan `volumes_dir()` for
  `*.img`, derive name/sizes, fill `referenced_by` from the config scan.
- `sandbox::remove_volume(&paths, name)` — error if referenced; else delete the
  image; return reclaimed bytes.
- `sandbox::attach_volume(&paths, name, spec)` — load `config`, build the new
  volume list, `validate_volumes`, assign `eph_id` if ephemeral, provision the
  image (idempotent `create_volume_image` — an existing persistent image is
  reused, never reformatted), save `config`.
- `sandbox::detach_volume(&paths, name, guest_path)` — load `config`, drop the
  matching entry, save. No image I/O.
- `Inspect` populates `SandboxDetail.volumes` from `config.volumes`.
- `PortPublish` with `persist`: after the relay is up, dedup-insert `rule` into
  `config.ports` by `(bind, host_port)` and save. Made **idempotent** — if an
  identical rule is already an active relay, skip the rebind but still persist;
  this is what the app's "Make persistent" button calls (re-issuing the live
  rule with `persist: true`). A conflicting rule on a bound `(bind, host_port)`
  still errors.
- `PortUnpublish`: after stopping the relay, also drop the matching
  `(bind, host_port)` from `config.ports` (if present) and save.

### CLI (`izba-cli`) — parity with the new ops

- `izba port publish NAME RULE [--persist]`.
- `izba volume ls` — table (name, size, used, in-use-by).
- `izba volume rm NAME` — guarded; `--force` only bypasses the *confirmation*,
  never the in-use guard.
- `izba volume attach NAME [VNAME:]GUEST_PATH:SIZE` and
  `izba volume detach NAME GUEST_PATH` — keep CLI/app consistent (both note the
  restart-to-apply semantics).

## Tauri layer (`app/src-tauri`)

- `DaemonApi` + Tauri commands + `FakeDaemon` gain: `inspect`, `port_list`,
  `port_publish(name, rule, persist)`, `port_unpublish(name, bind, host_port)`,
  `volume_list`, `volume_remove(name)`, `volume_prune`,
  `volume_attach(name, spec)`, `volume_detach(name, guest_path)`.
- `CreateOpts` gains `volumes: Vec<String>` (parsed via
  `volume::parse_volume_flag`, mirroring how `ports` is parsed); drop the
  hardcoded `volumes: Vec::new()`.
- `FakeDaemon` grows in-memory per-sandbox ports + volumes + a global volume
  store so the whole frontend runs in `vitest` without a daemon.
- Add `tauri-plugin-opener` (+ `@tauri-apps/plugin-opener`) for Open-in-browser.

## Frontend (`app/src`)

### Types (`lib/types.ts`)

`PortRule`, `VolumeSpec` (with optional `eph_id`), `VolumeInfo`,
`SandboxDetail` (with `ports` + `volumes`); `CreateOpts` gains `volumes:
string[]`.

### Create wizard (`NewSandbox.tsx`)

A **Volumes** section mirroring PR #50's validated port-row component: rows of
`[ Name (optional) · Guest path · Size ]`. Inline validation reusing the core
grammar rules — name `^[a-z0-9][a-z0-9_-]*$`, guest path absolute & comma-free,
size `^\d+[gmGM]$`. An empty name renders an "ephemeral" tag; a named row is
"persistent". Invalid non-blank rows block **Create**; blank rows are ignored
(same contract as the port rows). Emits `volumes: string[]` as
`[name:]path:size`.

### Detail → **Ports** tab (`PortsTab.tsx`, new)

- Merge `Inspect.ports` (persisted) with `PortList` (live relays): a rule in
  both is **persisted**; live-only gets an **"active until restart"** badge and
  a **Make persistent** button (`portPublish(rule, persist=true)`).
- Each forward shows `bind:host → guest` and an **Open in browser** icon
  (`http://127.0.0.1:<host_port>`, via the opener plugin) — VS Code
  forwarded-ports style.
- Add-forward form (enabled only when the sandbox is running) and a remove (×)
  per row (`portUnpublish`).

### Detail → **Volumes** tab (`VolumesTab.tsx`, new)

- Editable list seeded from `SandboxDetail.volumes`: name (or "ephemeral" tag),
  guest path, size. Add rows (same validated row component as the wizard) and
  remove rows.
- Edits are **staged**: a "These changes apply on next restart" banner appears
  while the tab is dirty; **Save** persists via `volumeAttach`/`volumeDetach`;
  **Restart now** chains stop→start (offered when the sandbox is running). A
  persistent-volume row carries a one-line single-writer caveat.

### **Storage** view (`StorageView.tsx`, new top-level Rail entry)

- Table from `volumeList()`: name, declared size, used, in-use chips
  (`referenced_by`).
- **Delete** per row — disabled with a tooltip ("in use by <sandbox>") when
  referenced; otherwise `volumeRemove` behind a confirm dialog.
- **Prune unused** — `volumePrune` behind a confirm; reports reclaimed bytes.
- `Rail.tsx` + `App.tsx` gain a Storage destination alongside the sandbox list.

## Testing

- **Rust unit:** proto round-trip for the new variants/fields; `eph_id`
  assignment (create order, attach `max+1`, detach stability); `image_path`
  ephemeral keyed by `eph_id`; `list_volumes` + `referenced_by`;
  `remove_volume` guard; `attach_volume`/`detach_volume` config edits;
  `PortPublish{persist}` config-write + idempotency; `PortUnpublish` config
  drop. Host-side only (`Paths::with_root` temp dirs, `UnixStream::pair` —
  never bind listeners).
- **CLI:** arg-parse tests for `volume ls/rm/attach/detach`,
  `port publish --persist`.
- **Frontend (`vitest` + `FakeDaemon`):** wizard volume validation;
  Ports-tab persisted-vs-live + Make-persistent + Open-in-browser invocation;
  Volumes-tab staged-edit/banner/Restart-now; Storage list / delete-guard /
  prune.
- **Integration (gated):** the existing KVM volume integration test must stay
  green under the `eph_id` keying change (boot with an ephemeral volume, write,
  restart, data survives; detach safety).
- **Gates:** the six workspace gates, the two Windows cross-compile gates, and
  the **App CI** gate (`cd app && npm ci && npm run build && cargo clippy
  --all-targets -- -D warnings && cargo test`) — required because this touches
  `izba-core` / `izba-proto` public types.

## Verification & deliverable

After all CI is green, produce a real devbuild (`bash hack/devbuild.sh`,
unsandboxed) and copy `dist/local/<UTC-ts>-<sha>/` into the **main** checkout's
`dist/local/`. Report that exact path plus ready-to-paste install commands.

End-to-end flows to verify:

1. **Ports** — create a sandbox with a published port via the wizard; in the
   Ports tab add a live forward, watch its "active until restart" badge, click
   **Make persistent**, restart, confirm it survives; **Open in browser**
   reaches the guest service.
2. **Volumes** — create a sandbox with one persistent + one ephemeral volume;
   in the Volumes tab attach another persistent volume, **Restart now**, confirm
   it mounts; detach one, confirm the others still mount with intact data
   (ephemeral identity holds); in **Storage**, observe in-use chips, try to
   delete an in-use volume (blocked), delete an unreferenced one, and **Prune
   unused**.

## Risks

- **Disk-order contract (#5):** mitigated by the host-only `eph_id` change (no
  guest-facing/order change) + KVM volume integration coverage before merge.
- **Open file on Windows:** detach does no image I/O; attach writes a new file —
  neither touches an in-use image.
- **Shared app surface with MVP-A:** confined to `NewSandbox.tsx` /
  `Detail.tsx`; built on PR #50's merged port-row pattern; no policy-logic
  overlap.
