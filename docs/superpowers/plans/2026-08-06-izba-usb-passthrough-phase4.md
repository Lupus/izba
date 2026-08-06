# USB passthrough phase 4 — the desktop app surface

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the Tauri GUI the USB passthrough surface the design spec §6.3
promises — a device panel with grant/revoke/attach/detach behind the same
consent gate as the CLI, a copy-the-command affordance for devices that still
need `usbipd bind`, and an honest restart-class warning — backed by two new
pieces of daemon-side truth (is the running kernel USB-capable, and what is
attached right now).

**Architecture:** Phases 1–3 built the control plane, the datapath, and the CLI.
Everything the GUI needs already exists as `Usb*` daemon RPCs, so phase 4 is
mostly plumbing: `DaemonApi` methods → `views` structs → `*_core` command
functions → Tauri commands + bridge dispatch → `ipc.ts` → two React components.
Two facts the spec's GUI copy requires are not yet computable by *any* client,
so they are added at the daemon first and surfaced in the CLI before the GUI:
**restart-required** (the running VM booted `vmlinux`, not `vmlinux-usb`, so an
attach cannot work until it restarts) and **attached-to** (which sandbox is
currently holding a device). Both are additive `#[serde(default)]` fields, so
`DAEMON_PROTO_VERSION` stays at 4.

**Tech Stack:** Rust (izba-core, izba-cli, `app/src-tauri` — Tauri 2), React 18
+ TypeScript + Tailwind/shadcn (`app/src`), vitest + @testing-library/react.

## Global Constraints

Every task's requirements implicitly include this section.

- **Disabled USB adds zero attack surface** (spec §2.2). Nothing in this plan may
  bind a listener, spawn a thread, or dial an upstream when USB is unconfigured.
  Only `UsbUpstreamShow` is answerable with the feature off — every other `Usb*`
  RPC refuses via `usb_settings_or_refuse` with a message containing
  `not configured`. **The GUI must gate on `usbUpstreamShow` and never call a
  refusing RPC to discover the feature is off.**
- **No `DAEMON_PROTO_VERSION` bump.** Every wire addition in this plan is a new
  field on an existing struct carrying `#[serde(default)]`, exactly like
  `SandboxDetail::user_fallback`. If a change cannot be made that way, stop and
  escalate rather than bumping.
- **izba never runs `usbipd bind`.** The GUI shows the command and offers to copy
  it. No elevation, no wrapping, no "do it for me" button (spec §2.5, §6.1).
- **Consent parity with the CLI.** The GUI grant dialog states the same four
  consequences as `consent_banner` (`crates/izba-cli/src/commands/usb.rs:144`)
  and requires the device id to be typed back before the grant button enables.
- **`app/src-tauri` is OUT of the root workspace.** The six workspace gates do
  not compile it. Run the app gate explicitly:
  `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`
- **Tauri camelCases command args.** A Rust command arg `host_port` arrives from
  the frontend as `hostPort`, and `lib.rs::dispatch` (the headless dogfood
  bridge) must accept the **camelCase** key. See the NOTE at `lib.rs:490`.
- **Tests never bind sockets.** Sandboxes deny `bind` with EPERM. Use
  `UdsStream::pair()` fakes (never `std::os::unix::net::UnixStream::pair`, which
  breaks the windows-gnu cross-check) or runtime-skip on `PermissionDenied`.
- **A self-skipping test is a test that cannot fail.** If a test can pass because
  the thing under test never ran, it is not a test. Assert the precondition.
- Conventional commits (`feat(app): ...`), TDD, frequent commits.
- Six workspace gates + the app gate must be green before every commit:
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --check`, `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`,
  `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`,
  `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.

## Out of scope

- A GUI dogfood journey for the USB panel (the `llm-dogfooding` harness needs a
  fake usbipd reachable from the sidecar; file a follow-up issue instead).
- The `GET_DESCRIPTOR` serial probe (spec §9, v1.1).
- Any change to the datapath, the broker's protocol handling, or the kernel
  variants. Phase 3 shipped those and they are CLEAN.

## File Structure

| File | Responsibility |
| --- | --- |
| `crates/izba-core/src/state.rs` (M) | `RunState.usb_kernel` — which kernel this run actually booted |
| `crates/izba-core/src/sandbox.rs` (M) | record `usb_kernel` at launch |
| `crates/izba-core/src/usb/broker/attachments.rs` (C) | the live attachment registry: insert on splice, remove on end, query by device |
| `crates/izba-core/src/usb/broker/mod.rs` (M) | own one `Attachments`, guard the splice with it |
| `crates/izba-core/src/usb/broker/session.rs` (M) | `Attached` carries the resolved `DeviceId` |
| `crates/izba-core/src/usb/mod.rs` (M) | `list_devices` annotates rows with `attached_to` |
| `crates/izba-core/src/daemon/proto.rs` (M) | `UsbDeviceInfo.attached_to`, `UsbStatus.{attached,restart_required}` |
| `crates/izba-core/src/daemon/server.rs` (M) | compute both new facts |
| `crates/izba-cli/src/commands/usb.rs` (M) | print them (`status`, `allow`, `list`) |
| `app/src-tauri/src/daemon.rs` (M) | 8 `DaemonApi` methods + `RealDaemon` impls |
| `app/src-tauri/src/views.rs` (M) | `UsbUpstreamView`, `UsbDeviceView`, `UsbStatusView` |
| `app/src-tauri/src/fake.rs` (M) | `FakeDaemon` USB state + impls |
| `app/src-tauri/src/commands.rs` (M) | `usb_*_core` functions + their unit tests |
| `app/src-tauri/src/lib.rs` (M) | `#[tauri::command]` wrappers, handler registration, `dispatch` arms |
| `app/src/lib/types.ts` (M) | `UsbUpstream`, `UsbDevice`, `UsbGrant`, `UsbStatus` |
| `app/src/lib/ipc.ts` (M) | `api.usb*` wrappers |
| `app/src/components/UsbConsentDialog.tsx` (C) | the shared consent gate (clauses + type-back) |
| `app/src/components/UsbView.tsx` (C) | global Devices view: upstream config + inventory + bind commands |
| `app/src/components/UsbTab.tsx` (C) | per-sandbox tab: grants, allow, revoke, attach/detach, restart badge |
| `app/src/components/{Rail,Detail}.tsx`, `app/src/App.tsx` (M) | wire both surfaces in |
| `app/src/test/usb{ConsentDialog,View,Tab}.test.tsx` (C) | component tests |
| `README.md`, `CLAUDE.md`, spec §6.3 (M) | document the delivered surface |

(C) = create, (M) = modify.

---

### Task 1: Record which kernel a run actually booted

The GUI must say "restart to apply" only when it is true. Today no client can
know: `config.usb` says a grant exists, but the *running* VM booted whichever
kernel was chosen at `start`. A sandbox granted its first device while running
is still on `vmlinux`, which has no USB stack at all — an attach against it
fails in the guest, and the honest answer is "restart first".

**Files:**
- Modify: `crates/izba-core/src/state.rs` (`RunState`)
- Modify: `crates/izba-core/src/sandbox.rs:1004` (`RunState` construction), `:2076` (test fixture)
- Test: `crates/izba-core/src/state.rs` (round-trip), `crates/izba-core/src/sandbox.rs` (recorded at launch)

**Interfaces:**
- Produces: `RunState { usb_kernel: bool, .. }` — `true` iff this run booted
  `KernelVariant::Usb`. Task 4 reads it.

- [ ] **Step 1: Write the failing test**

In `crates/izba-core/src/state.rs` tests:

```rust
#[test]
fn a_state_json_written_before_usb_reads_as_a_non_usb_kernel() {
    // The safe direction: an old record must not claim USB support the run
    // does not have, because that claim suppresses the "restart" warning.
    let legacy = r#"{"vmm_pid":{"pid":1,"starttime":2},"sidecar_pids":[],"started_unix_ms":0}"#;
    let s: RunState = serde_json::from_str(legacy).unwrap();
    assert!(!s.usb_kernel);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p izba-core a_state_json_written_before_usb -- --nocapture`
Expected: FAIL — `no field 'usb_kernel'`.

- [ ] **Step 3: Add the field**

In `crates/izba-core/src/state.rs`, inside `RunState`, after `user_fallback`:

```rust
    /// Whether this run booted the USB kernel variant (`vmlinux-usb`).
    ///
    /// The grant record answers "may this sandbox have a device"; only this
    /// answers "can the kernel it is running accept one". They diverge exactly
    /// when a grant is added to a running sandbox, which is the case the UI has
    /// to warn about. `serde(default)` → a pre-USB `state.json` reads as
    /// `false`, which is both true of it and the safe direction.
    #[serde(default)]
    pub usb_kernel: bool,
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p izba-core a_state_json_written_before_usb`
Expected: PASS. Other `RunState` literals now fail to compile — fix them in the
next step.

- [ ] **Step 5: Record it at launch**

In `crates/izba-core/src/sandbox.rs`, the `RunState` literal at ~`:1004` gains
the field. The function that builds it must receive the variant; it is already
in scope as the `Artifacts.variant` used to pick the kernel — thread it through
as a `bool` parameter named `usb_kernel` rather than the enum, so the state
module keeps no dependency on `artifacts`:

```rust
        user_fallback,
        usb_kernel,
```

and at the call site pass `artifacts.variant == crate::artifacts::KernelVariant::Usb`.
Fix the test fixture at `:2076` and any other `RunState` literal by adding
`usb_kernel: false`.

- [ ] **Step 6: Write the launch-records-it test**

In `crates/izba-core/src/sandbox.rs` tests, extend the existing start-path test
that asserts on `state.json` (search for `STATE_FILE` in the test module) — or
add:

```rust
#[test]
fn the_recorded_run_says_which_kernel_it_booted() {
    // A bool that is always false is indistinguishable from an unrecorded one,
    // so assert BOTH directions against the same writer.
    for (variant, expected) in [
        (crate::artifacts::KernelVariant::Base, false),
        (crate::artifacts::KernelVariant::Usb, true),
    ] {
        assert_eq!(variant == crate::artifacts::KernelVariant::Usb, expected);
    }
}
```

Replace that placeholder assertion with a real call to the state-writing helper
once you have read its signature; the test must exercise the writer, not restate
the expression. If the writer is not callable without a live VM, assert instead
on the one call site by making the helper take `usb_kernel: bool` and unit-test
the helper directly with both values, asserting the round-tripped `RunState`.

- [ ] **Step 7: Run the gates and commit**

```bash
cargo test -p izba-core && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/state.rs crates/izba-core/src/sandbox.rs
git commit -m "feat(core): record which kernel variant a run booted"
```

---

### Task 2: Track live attachments in the broker

The spec's GUI copy needs "attached elsewhere". Attachment state lives in the
guest, but izbad does not have to ask the guest for it — **izbad is the
attachment**: every live device is a splice this daemon is running. Registering
around the splice is both cheaper and more trustworthy than a guest RPC (A1: the
guest is hostile, and this is exactly the kind of fact it would lie about).

**Files:**
- Create: `crates/izba-core/src/usb/broker/attachments.rs`
- Modify: `crates/izba-core/src/usb/broker/mod.rs`, `crates/izba-core/src/usb/broker/session.rs`
- Test: in `attachments.rs`

**Interfaces:**
- Consumes: `session::Attached` (phase 3).
- Produces:
  - `session::Attached { device: DeviceId, devid: u32, speed: u32, busid: String }`
  - `Attachments::{new, guard, held_by, map}`; `UsbBroker::attached_map() -> HashMap<DeviceId, String>`
    and `UsbBroker::attached_to(&self, sandbox: &str) -> Vec<DeviceId>`. Task 4 reads both.

- [ ] **Step 1: Write the failing test**

Create `crates/izba-core/src/usb/broker/attachments.rs` with tests only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn dev(s: &str) -> crate::usb::DeviceId {
        s.parse().unwrap()
    }

    #[test]
    fn a_device_is_held_only_while_its_guard_lives() {
        let a = Attachments::new();
        assert!(a.map().is_empty());
        {
            let _g = a.guard("web", dev("0403:6001"));
            assert_eq!(a.map().get(&dev("0403:6001")).map(String::as_str), Some("web"));
            assert_eq!(a.held_by("web"), vec![dev("0403:6001")]);
        }
        // The splice ended: the device is back on the host, and saying
        // otherwise would tell a user to detach something already detached.
        assert!(a.map().is_empty());
        assert!(a.held_by("web").is_empty());
    }

    #[test]
    fn a_panicking_splice_still_releases_the_device() {
        let a = Attachments::new();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = a.guard("web", dev("0403:6001"));
            panic!("splice blew up");
        }));
        assert!(res.is_err());
        assert!(a.map().is_empty(), "a leaked entry is a permanently stuck device");
    }

    #[test]
    fn one_sandbox_can_hold_several_devices_and_they_are_listed_sorted() {
        let a = Attachments::new();
        let _g1 = a.guard("web", dev("0403:6001"));
        let _g2 = a.guard("web", dev("10c4:ea60"));
        assert_eq!(a.held_by("web"), vec![dev("0403:6001"), dev("10c4:ea60")]);
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p izba-core attachments`
Expected: FAIL — module not declared / `Attachments` not found.

- [ ] **Step 3: Implement**

Above those tests in the same file:

```rust
//! Which device each sandbox is holding right now.
//!
//! The entry exists for exactly as long as the splice does: `guard` inserts and
//! its `Drop` removes, so a handler that returns, errors, or panics cannot leave
//! a device looking attached when it is back on the host.

use crate::usb::DeviceId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct Attachments {
    inner: Arc<Mutex<HashMap<DeviceId, String>>>,
}

impl Attachments {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `device` as held by `sandbox` until the returned guard drops.
    pub fn guard(&self, sandbox: &str, device: DeviceId) -> AttachmentGuard {
        self.inner
            .lock()
            .unwrap()
            .insert(device, sandbox.to_string());
        AttachmentGuard {
            inner: Arc::clone(&self.inner),
            device,
        }
    }

    /// Device → holding sandbox, for the whole daemon.
    pub fn map(&self) -> HashMap<DeviceId, String> {
        self.inner.lock().unwrap().clone()
    }

    /// What one sandbox is holding, in a stable order (a listing that reorders
    /// between polls reads as churn).
    pub fn held_by(&self, sandbox: &str) -> Vec<DeviceId> {
        let mut v: Vec<DeviceId> = self
            .inner
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| s.as_str() == sandbox)
            .map(|(d, _)| *d)
            .collect();
        v.sort();
        v
    }
}

pub struct AttachmentGuard {
    inner: Arc<Mutex<HashMap<DeviceId, String>>>,
    device: DeviceId,
}

impl Drop for AttachmentGuard {
    fn drop(&mut self) {
        // `lock()` can only fail if a holder panicked mid-mutation; removing is
        // still the right end state, so recover rather than double-panic.
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.remove(&self.device);
    }
}
```

`DeviceId` (`crates/izba-core/src/usb/ids.rs:12`) already derives
`Copy, Eq, Hash, PartialOrd, Ord` — `sort()` and the `HashMap` key both work as
written, no derive change needed.

- [ ] **Step 4: Declare the module and run the tests**

In `crates/izba-core/src/usb/broker/mod.rs`, near the existing `mod session;`:

```rust
mod attachments;
pub use attachments::Attachments;
```

Run: `cargo test -p izba-core attachments`
Expected: PASS (3 tests).

- [ ] **Step 5: Carry the DeviceId out of the handshake**

In `crates/izba-core/src/usb/broker/session.rs`, add the field to `Attached`:

```rust
pub struct Attached {
    /// The `vid:pid` the guest asked for, already checked against the grant.
    pub device: crate::usb::DeviceId,
    pub devid: u32,
    pub speed: u32,
    pub busid: String,
}
```

`import()` already has the resolved id in scope (it verifies against the grant);
set `device: grant.device`. Fix the existing `Attached` literals in tests.

- [ ] **Step 6: Guard the splice**

In `mod.rs`, add `attachments: Attachments` to `UsbBroker`, construct it in
`UsbBroker::new`/`Default`, and expose:

```rust
    /// Device → holding sandbox for every live attachment.
    pub fn attached_map(&self) -> std::collections::HashMap<crate::usb::DeviceId, String> {
        self.attachments.map()
    }

    /// What `name` is holding right now.
    pub fn attached_to(&self, name: &str) -> Vec<crate::usb::DeviceId> {
        self.attachments.held_by(name)
    }
```

`handle_conn` needs the registry, so give it one more parameter
(`attachments: &Attachments`) — the accept loop already clones per-connection
state, so clone an `Arc` of it the same way (make `Attachments` hold its `Arc`
internally, as above, and derive `Clone`). Then:

```rust
    let _held = attachments.guard(sandbox, _attached.device);
    let _ = conn.set_io_timeout(None);
    splice(conn, upstream);
```

Rename `_attached` to `attached` now that it is read.

- [ ] **Step 7: Run the full core suite and commit**

```bash
cargo test -p izba-core && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/usb/broker/attachments.rs crates/izba-core/src/usb/broker/mod.rs crates/izba-core/src/usb/broker/session.rs crates/izba-core/src/usb/ids.rs
git commit -m "feat(usb): track live attachments for the lifetime of each splice"
```

---

### Task 3: Surface both facts on the wire

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs` (`UsbDeviceInfo`, `DaemonResponse::UsbStatus`)
- Modify: `crates/izba-core/src/usb/mod.rs` (`list_devices`)
- Modify: `crates/izba-core/src/daemon/server.rs` (`handle_usb_list_devices`, `handle_usb_status`)
- Test: `crates/izba-core/src/usb/mod.rs`, `crates/izba-core/src/daemon/proto.rs`

**Interfaces:**
- Consumes: `UsbBroker::{attached_map, attached_to}` (Task 2), `RunState.usb_kernel` (Task 1).
- Produces:
  - `UsbDeviceInfo { .., attached_to: Option<String> }`
  - `DaemonResponse::UsbStatus { grants, attached: Vec<String>, restart_required: bool }`
  - `usb::list_devices(paths, shared, known, attached: &HashMap<DeviceId, String>)`

- [ ] **Step 1: Write the failing tests**

In `crates/izba-core/src/daemon/proto.rs` tests, extend the back-compat test
that already round-trips `UsbDeviceInfo` / `UsbStatus`:

```rust
#[test]
fn a_pre_phase4_usb_frame_still_deserializes() {
    // Old daemon, new client: the two new facts must read as "nothing attached,
    // no restart needed" rather than failing the frame.
    let d: UsbDeviceInfo = serde_json::from_str(
        r#"{"busid":"3-2","device":"0403:6001","description":"FT232","shared":true}"#,
    )
    .unwrap();
    assert_eq!(d.attached_to, None);

    let r: DaemonResponse =
        serde_json::from_str(r#"{"type":"usb_status","grants":[]}"#).unwrap();
    match r {
        DaemonResponse::UsbStatus { attached, restart_required, .. } => {
            assert!(attached.is_empty());
            assert!(!restart_required);
        }
        other => panic!("expected usb_status, got {other:?}"),
    }
}
```

In `crates/izba-core/src/usb/mod.rs` tests:

```rust
#[test]
fn a_listed_device_says_which_sandbox_is_holding_it() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(tmp.path().to_path_buf());
    let shared = vec![inventory::UpstreamDevice {
        busid: "3-2".into(),
        id: "0403:6001".parse().unwrap(),
        description: "FT232".into(),
    }];
    let mut attached = HashMap::new();
    attached.insert("0403:6001".parse().unwrap(), "web".to_string());

    let rows = list_devices(&paths, &shared, None, &attached);
    assert_eq!(rows[0].attached_to.as_deref(), Some("web"));

    // And the empty map is not vacuously equal to the populated one.
    let rows = list_devices(&paths, &shared, None, &HashMap::new());
    assert_eq!(rows[0].attached_to, None);
}
```

Match the existing tests' `Paths` construction and `UpstreamDevice` field names —
read them first; do not guess.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p izba-core usb -- --nocapture`
Expected: FAIL — unknown fields / wrong arity.

- [ ] **Step 3: Add the wire fields**

`proto.rs`, on `UsbDeviceInfo`:

```rust
    /// The sandbox currently holding this device, when one is. Host-observed:
    /// izbad is running the splice, so it never has to ask the guest.
    #[serde(default)]
    pub attached_to: Option<String>,
```

and on `DaemonResponse::UsbStatus`:

```rust
    UsbStatus {
        grants: Vec<UsbGrantInfo>,
        /// `vid:pid` of every device this sandbox is holding right now.
        #[serde(default)]
        attached: Vec<String>,
        /// The sandbox is running a kernel with no USB stack while holding at
        /// least one grant: attaching cannot work until it restarts.
        #[serde(default)]
        restart_required: bool,
    },
```

Update the round-trip fixtures already present in that test module.

- [ ] **Step 4: Thread it through `list_devices`**

`usb/mod.rs`: add the `attached: &HashMap<DeviceId, String>` parameter and set
`attached_to: attached.get(&d.id).cloned()` on the shared rows and
`attached.get(&k.id).cloned()` on the unshared ones (an unshared device cannot be
attached, but computing it the same way keeps the two arms honest if that ever
changes). Update the doc comment to mention the new annotation.

- [ ] **Step 5: Compute both in the server**

`server.rs`, `handle_usb_list_devices`: pass `&d.usb.attached_map()`.

`handle_usb_status`: after loading `cfg`, add

```rust
    let attached: Vec<String> = d
        .usb
        .attached_to(&name)
        .into_iter()
        .map(|x| x.to_string())
        .collect();
    // Restart-class truth: a grant the running kernel cannot honour. Only a
    // LIVE run can need a restart — a stopped sandbox will boot the right
    // kernel by itself, and saying "restart" there would be noise. Liveness and
    // the run record are read exactly as `handle_inspect` reads them
    // (server.rs:611) so the two answers can never disagree.
    let running = d
        .registry
        .liveness(&name)
        .unwrap_or(Liveness::Stopped)
        != Liveness::Stopped;
    let usb_kernel = load_json::<crate::state::RunState>(
        &d.paths.sandbox_dir(&name).join(crate::state::STATE_FILE),
    )?
    .map(|r| r.usb_kernel)
    .unwrap_or(false);
    let restart_required = !cfg.usb.devices.is_empty() && running && !usb_kernel;
```

- [ ] **Step 6: Test the server-side computation**

In `server.rs`'s test module, next to the existing USB tests:

```rust
#[test]
fn a_stopped_sandbox_never_asks_for_a_restart() {
    // The grant applies on its next start; a restart prompt would be a lie.
    let (d, _tmp) = daemon_with_usb_configured();
    create_sandbox_with_grant(&d, "web");
    match handle_usb_status(&d, "web".into()).unwrap() {
        DaemonResponse::UsbStatus { restart_required, .. } => assert!(!restart_required),
        other => panic!("expected usb_status, got {other:?}"),
    }
}
```

Reuse whatever fixtures the phase-3 USB server tests already have (grep
`fn handle_usb_status` in the test module) rather than inventing helpers. Add a
second test that fabricates a `state.json` with `usb_kernel: false` and a live
pid identity to assert the `true` branch, if the existing fixtures make a
"running" sandbox reachable; if they do not, assert the `true` branch by
extracting the condition into a pure helper
`fn needs_usb_restart(grants: bool, running: bool, usb_kernel: bool) -> bool`
and testing all eight combinations. **Do not leave the `true` branch untested** —
that branch is the entire point of the field.

- [ ] **Step 7: Run the gates and commit**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
git add crates/izba-core/src/daemon/proto.rs crates/izba-core/src/daemon/server.rs crates/izba-core/src/usb/mod.rs
git commit -m "feat(daemon): report live attachments and the restart-class grant gap"
```

---

### Task 4: Make the CLI say both things

The cheap surface goes first: if the CLI cannot explain the new facts in one
line each, the GUI will not do better with a badge.

**Files:**
- Modify: `crates/izba-cli/src/commands/usb.rs`
- Test: same file

**Interfaces:**
- Consumes: `DaemonResponse::UsbStatus { attached, restart_required }` (Task 3).
- Produces: `render_status(grants, attached, restart_required, name) -> String`,
  `restart_note(name) -> String` (used by both `status` and `allow`).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn status_marks_an_attached_grant_and_warns_about_the_stale_kernel() {
    let out = render_status(
        &[UsbGrantInfo {
            device: "0403:6001".into(),
            busid_pin: None,
            description: "FT232".into(),
            granted_at_unix_ms: 0,
        }],
        &["0403:6001".to_string()],
        true,
        "web",
    );
    assert!(out.contains("attached"), "an attached device must read as attached:\n{out}");
    assert!(out.contains("izba restart web"), "the warning must carry the fix:\n{out}");
}

#[test]
fn status_of_a_ready_sandbox_says_nothing_about_restarting() {
    let out = render_status(&[], &[], false, "web");
    assert!(!out.contains("restart"), "silence is the honest answer here:\n{out}");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p izba-cli status_marks_an_attached_grant`
Expected: FAIL — `render_status` not found.

- [ ] **Step 3: Implement**

```rust
/// The one-line fix for a grant the running kernel cannot honour.
pub(crate) fn restart_note(name: &str) -> String {
    format!(
        "⚠  '{name}' is running a kernel without USB support — \
         run `izba restart {name}` before attaching."
    )
}

/// Render `izba usb status` for one sandbox.
pub(crate) fn render_status(
    grants: &[UsbGrantInfo],
    attached: &[String],
    restart_required: bool,
    name: &str,
) -> String {
    let mut out = String::new();
    if grants.is_empty() {
        out.push_str("no devices granted\n");
    }
    for g in grants {
        let state = if attached.iter().any(|a| a == &g.device) {
            " (attached)"
        } else {
            ""
        };
        let pin = g
            .busid_pin
            .as_deref()
            .map(|b| format!(" pinned to {b}"))
            .unwrap_or_default();
        out.push_str(&format!("{}{}{}\n", g.device, pin, state));
    }
    if restart_required {
        out.push_str(&restart_note(name));
        out.push('\n');
    }
    out
}
```

Wire it into the existing `status` verb, replacing its current per-grant
`println!` loop with `print!("{}", render_status(...))`. Keep whatever
description column the current output has — read it and preserve it.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p izba-cli usb`
Expected: PASS.

- [ ] **Step 5: Say it at `allow` time too**

After a successful `UsbAllow`, ask the daemon for the sandbox's status and print
the note if it applies — the daemon's answer, never a client-side inference:

```rust
    println!("granted {device} to '{name}'");
    // The grant is durable either way; this is only about what happens next.
    if let Ok(DaemonResponse::UsbStatus { restart_required: true, .. }) = client.request(
        &DaemonRequest::UsbStatus { name: name.to_string() },
        &mut |_| {},
    ) {
        eprintln!("{}", restart_note(name));
    }
```

- [ ] **Step 6: Show holders in `izba usb list`**

The list verb already renders `granted_to`; add the holder when present. Find its
row formatter and append `" — attached to <sandbox>"` when
`d.attached_to` is `Some`. Add a test asserting a device attached to `web`
renders `web` in its row and that an unattached row does not contain "attached".

- [ ] **Step 7: Run the gates and commit**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-cli/src/commands/usb.rs
git commit -m "feat(cli): report attachment state and the restart-class grant gap"
```

---

### Task 5: `DaemonApi` methods and view structs

**Files:**
- Modify: `app/src-tauri/src/daemon.rs`, `app/src-tauri/src/views.rs`, `app/src-tauri/src/fake.rs`
- Test: `app/src-tauri/src/views.rs`

**Interfaces:**
- Consumes: `DaemonRequest::Usb*`, `DaemonResponse::Usb*` (Tasks 3).
- Produces (trait methods on `DaemonApi`, all `&mut self`):
  - `usb_upstream_show(&mut self) -> anyhow::Result<Option<UsbUpstreamInfo>>`
  - `usb_upstream_set(&mut self, host: &str, port: u16, allow_remote: bool) -> anyhow::Result<()>`
  - `usb_list_devices(&mut self) -> anyhow::Result<Vec<UsbDeviceInfo>>`
  - `usb_allow(&mut self, name: &str, device: &str, busid_pin: Option<String>) -> anyhow::Result<()>`
  - `usb_revoke(&mut self, name: &str, device: &str) -> anyhow::Result<()>`
  - `usb_status(&mut self, name: &str) -> anyhow::Result<(Vec<UsbGrantInfo>, Vec<String>, bool)>`
  - `usb_attach(&mut self, name: &str, device: &str) -> anyhow::Result<()>`
  - `usb_detach(&mut self, name: &str, device: &str) -> anyhow::Result<()>`
- Produces (views): `UsbUpstreamView`, `UsbDeviceView`, `UsbGrantView`, `UsbStatusView`.

- [ ] **Step 1: Write the failing view test**

In `app/src-tauri/src/views.rs` tests:

```rust
#[test]
fn a_usb_status_view_serializes_the_shape_the_ui_reads() {
    let v = UsbStatusView::new(
        vec![izba_core::daemon::proto::UsbGrantInfo {
            device: "0403:6001".into(),
            busid_pin: None,
            description: "FT232".into(),
            granted_at_unix_ms: 7,
        }],
        vec!["0403:6001".to_string()],
        true,
    );
    let j = serde_json::to_value(&v).unwrap();
    assert_eq!(j["grants"][0]["device"], "0403:6001");
    assert_eq!(j["grants"][0]["attached"], serde_json::json!(true));
    assert_eq!(j["restart_required"], serde_json::json!(true));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd app/src-tauri && cargo test a_usb_status_view`
Expected: FAIL — `UsbStatusView` not found.

- [ ] **Step 3: Add the views**

In `views.rs`:

```rust
/// The configured upstream as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbUpstreamView {
    pub host: String,
    pub port: u16,
    pub resolved: Option<String>,
    pub trust: String,
    pub warning: Option<String>,
}

impl From<izba_core::daemon::proto::UsbUpstreamInfo> for UsbUpstreamView { /* field-for-field */ }

/// One row of the device inventory.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbDeviceView {
    pub busid: String,
    pub device: String,
    pub description: String,
    pub shared: bool,
    pub granted_to: Vec<String>,
    pub bind_command: Option<String>,
    pub attached_to: Option<String>,
}

impl From<izba_core::daemon::proto::UsbDeviceInfo> for UsbDeviceView { /* field-for-field */ }

/// One grant, with its live attachment state folded in — the UI renders a row
/// per grant and would otherwise have to join two arrays by string.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbGrantView {
    pub device: String,
    pub busid_pin: Option<String>,
    pub description: String,
    pub granted_at_unix_ms: u64,
    pub attached: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsbStatusView {
    pub grants: Vec<UsbGrantView>,
    pub restart_required: bool,
}

impl UsbStatusView {
    pub fn new(
        grants: Vec<izba_core::daemon::proto::UsbGrantInfo>,
        attached: Vec<String>,
        restart_required: bool,
    ) -> Self {
        Self {
            grants: grants
                .into_iter()
                .map(|g| UsbGrantView {
                    attached: attached.contains(&g.device),
                    device: g.device,
                    busid_pin: g.busid_pin,
                    description: g.description,
                    granted_at_unix_ms: g.granted_at_unix_ms,
                })
                .collect(),
            restart_required,
        }
    }
}
```

- [ ] **Step 4: Run the test**

Run: `cd app/src-tauri && cargo test a_usb_status_view`
Expected: PASS.

- [ ] **Step 5: Add the trait methods and `RealDaemon` impls**

In `daemon.rs`, add the eight signatures to `trait DaemonApi`, then implement
them on `RealDaemon` following the existing `with_client` pattern. Two worked
examples; the rest are the same shape with their own request/response arms:

```rust
    fn usb_upstream_show(&mut self) -> anyhow::Result<Option<UsbUpstreamInfo>> {
        self.with_client(|c| {
            match c.request(&DaemonRequest::UsbUpstreamShow, &mut |_| {})? {
                DaemonResponse::UsbUpstream { upstream } => Ok(upstream),
                other => Err(unexpected(other)),
            }
        })
    }

    fn usb_attach(&mut self, name: &str, device: &str) -> anyhow::Result<()> {
        let (name, device) = (name.to_string(), device.to_string());
        self.with_client(move |c| {
            // Attach/detach are forwarded to the guest, so the daemon answers
            // with the guest's reply in an envelope — `expect_ok` is wrong here
            // exactly as it was in the CLI (crates/izba-cli/src/commands/usb.rs).
            match c.request(&DaemonRequest::UsbAttach { name, device }, &mut |_| {})? {
                DaemonResponse::Ok => Ok(()),
                // The inner Response is nested under `payload` (proto.rs:337) to
                // dodge a serde tag collision — both types discriminate on "type".
                DaemonResponse::Guest { payload } => match payload {
                    izba_proto::Response::UsbAttached { .. } | izba_proto::Response::Ok => Ok(()),
                    izba_proto::Response::Error { message, .. } => Err(anyhow::anyhow!(message)),
                    other => Err(anyhow::anyhow!("unexpected guest reply: {other:?}")),
                },
                other => Err(unexpected(other)),
            }
        })
    }
```

This mirrors `interpret_attach_reply` in `crates/izba-cli/src/commands/usb.rs`,
which is already correct and tested — read it and match its arms exactly, since a
regression here reports a successful attach as a failure (the phase-3 bug). If an
`unexpected(other)` helper does not exist in `daemon.rs`, use the file's existing
error idiom instead of adding one.

- [ ] **Step 6: Add `FakeDaemon` state and impls**

In `fake.rs`, add fields:

```rust
    /// Configured upstream echoed by `usb_upstream_show`; `None` ⇒ USB is off,
    /// which is the state every other USB RPC refuses in.
    pub usb_upstream: Option<izba_core::daemon::proto::UsbUpstreamInfo>,
    pub usb_devices: Vec<izba_core::daemon::proto::UsbDeviceInfo>,
    pub usb_grants: Vec<izba_core::daemon::proto::UsbGrantInfo>,
    pub usb_attached: Vec<String>,
    pub usb_restart_required: bool,
```

Default them in `FakeDaemon::default()` (`None` / empty / false), and implement
the eight methods to record into `self.calls` (`format!("usb_allow {name} {device}")`
etc.) and mutate `usb_grants` / `usb_attached` so a test can assert the effect,
honouring `fail_action` like the neighbouring impls do.

- [ ] **Step 7: Run the app backend gate and commit**

```bash
cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
git add app/src-tauri/src/daemon.rs app/src-tauri/src/views.rs app/src-tauri/src/fake.rs
git commit -m "feat(app): add the USB daemon API surface and its view types"
```

---

### Task 6: `*_core` command functions, Tauri commands, bridge dispatch

**Files:**
- Modify: `app/src-tauri/src/commands.rs`, `app/src-tauri/src/lib.rs`
- Test: `app/src-tauri/src/commands.rs`, `app/src-tauri/src/lib.rs` (dispatch)

**Interfaces:**
- Consumes: the `DaemonApi` USB methods (Task 5).
- Produces: `usb_upstream_show_core`, `usb_upstream_set_core`,
  `usb_list_devices_core`, `usb_allow_core`, `usb_revoke_core`,
  `usb_status_core`, `usb_attach_core`, `usb_detach_core` — each
  `(d: &mut dyn DaemonApi, ..) -> Result<T, String>`; Tauri command names
  `usb_upstream_show`, `usb_upstream_set`, `usb_list_devices`, `usb_allow`,
  `usb_revoke`, `usb_status`, `usb_attach`, `usb_detach`.

- [ ] **Step 1: Write the failing tests**

In `commands.rs` tests:

```rust
#[test]
fn usb_status_core_folds_attachment_state_into_each_grant() {
    let mut d = FakeDaemon::default();
    d.usb_grants = vec![grant("0403:6001"), grant("10c4:ea60")];
    d.usb_attached = vec!["10c4:ea60".into()];
    let v = usb_status_core(&mut d, "web").unwrap();
    assert_eq!(v.grants[0].attached, false);
    assert_eq!(v.grants[1].attached, true);
}

#[test]
fn usb_upstream_show_core_reports_the_feature_being_off_as_none_not_an_error() {
    // The UI decides what to render from this; an Err would make "off" look
    // like "broken".
    let mut d = FakeDaemon::default();
    assert!(usb_upstream_show_core(&mut d).unwrap().is_none());
}

#[test]
fn usb_allow_core_passes_the_device_through_unchanged() {
    let mut d = FakeDaemon::default();
    usb_allow_core(&mut d, "web", "0403:6001", None).unwrap();
    assert!(d.calls.iter().any(|c| c == "usb_allow web 0403:6001"));
}
```

Add a small `fn grant(device: &str) -> UsbGrantInfo` helper in the test module.

- [ ] **Step 2: Run to verify they fail**

Run: `cd app/src-tauri && cargo test usb_`
Expected: FAIL — functions not found.

- [ ] **Step 3: Implement the core functions**

```rust
pub fn usb_upstream_show_core(d: &mut dyn DaemonApi) -> Result<Option<UsbUpstreamView>, String> {
    d.usb_upstream_show()
        .map(|u| u.map(UsbUpstreamView::from))
        .map_err(|e| e.to_string())
}

pub fn usb_upstream_set_core(
    d: &mut dyn DaemonApi,
    host: &str,
    port: u16,
    allow_remote: bool,
) -> Result<(), String> {
    d.usb_upstream_set(host, port, allow_remote)
        .map_err(|e| e.to_string())
}

pub fn usb_list_devices_core(d: &mut dyn DaemonApi) -> Result<Vec<UsbDeviceView>, String> {
    d.usb_list_devices()
        .map(|v| v.into_iter().map(UsbDeviceView::from).collect())
        .map_err(|e| e.to_string())
}

pub fn usb_status_core(d: &mut dyn DaemonApi, name: &str) -> Result<UsbStatusView, String> {
    let (grants, attached, restart_required) = d.usb_status(name).map_err(|e| e.to_string())?;
    Ok(UsbStatusView::new(grants, attached, restart_required))
}

pub fn usb_allow_core(
    d: &mut dyn DaemonApi,
    name: &str,
    device: &str,
    busid_pin: Option<String>,
) -> Result<(), String> {
    d.usb_allow(name, device, busid_pin)
        .map_err(|e| e.to_string())
}

pub fn usb_revoke_core(d: &mut dyn DaemonApi, name: &str, device: &str) -> Result<(), String> {
    d.usb_revoke(name, device).map_err(|e| e.to_string())
}

pub fn usb_attach_core(d: &mut dyn DaemonApi, name: &str, device: &str) -> Result<(), String> {
    d.usb_attach(name, device).map_err(|e| e.to_string())
}

pub fn usb_detach_core(d: &mut dyn DaemonApi, name: &str, device: &str) -> Result<(), String> {
    d.usb_detach(name, device).map_err(|e| e.to_string())
}
```

- [ ] **Step 4: Run the tests**

Run: `cd app/src-tauri && cargo test usb_`
Expected: PASS.

- [ ] **Step 5: Add the Tauri commands**

In `lib.rs`, following the `run_action` pattern (these all talk to the daemon and
`usb_list_devices` dials the upstream, so none may hold the polling lock):

```rust
#[tauri::command]
async fn usb_upstream_show(state: State<'_, AppState>) -> Result<Option<views::UsbUpstreamView>, String> {
    run_action(&state, commands::usb_upstream_show_core).await
}

#[tauri::command]
async fn usb_upstream_set(
    state: State<'_, AppState>,
    host: String,
    port: u16,
    allow_remote: bool,
) -> Result<(), String> {
    run_action(&state, move |d| commands::usb_upstream_set_core(d, &host, port, allow_remote)).await
}

#[tauri::command]
async fn usb_list_devices(state: State<'_, AppState>) -> Result<Vec<views::UsbDeviceView>, String> {
    run_action(&state, commands::usb_list_devices_core).await
}

#[tauri::command]
async fn usb_status(state: State<'_, AppState>, name: String) -> Result<views::UsbStatusView, String> {
    run_action(&state, move |d| commands::usb_status_core(d, &name)).await
}

#[tauri::command]
async fn usb_allow(
    state: State<'_, AppState>,
    name: String,
    device: String,
    busid_pin: Option<String>,
) -> Result<(), String> {
    run_action(&state, move |d| commands::usb_allow_core(d, &name, &device, busid_pin)).await
}

#[tauri::command]
async fn usb_revoke(state: State<'_, AppState>, name: String, device: String) -> Result<(), String> {
    run_action(&state, move |d| commands::usb_revoke_core(d, &name, &device)).await
}

#[tauri::command]
async fn usb_attach(state: State<'_, AppState>, name: String, device: String) -> Result<(), String> {
    run_action(&state, move |d| commands::usb_attach_core(d, &name, &device)).await
}

#[tauri::command]
async fn usb_detach(state: State<'_, AppState>, name: String, device: String) -> Result<(), String> {
    run_action(&state, move |d| commands::usb_detach_core(d, &name, &device)).await
}
```

If `run_action` will not accept a bare function item for the two no-arg cases,
wrap them in closures (`move |d| commands::usb_list_devices_core(d)`).

Register all eight in `tauri::generate_handler![...]`, after `manifest_promote`.

- [ ] **Step 6: Add the bridge arms + their test**

In `dispatch`, note the camelCase rule — the frontend sends `allowRemote` and
`busidPin`:

```rust
        "usb_upstream_show" => to_json(commands::usb_upstream_show_core(d)?),
        "usb_upstream_set" => {
            let allow_remote = args
                .get("allowRemote")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            to_json(commands::usb_upstream_set_core(
                d,
                &arg_str(&args, "host")?,
                arg_u16(&args, "port")?,
                allow_remote,
            )?)
        }
        "usb_list_devices" => to_json(commands::usb_list_devices_core(d)?),
        "usb_status" => to_json(commands::usb_status_core(d, &arg_str(&args, "name")?)?),
        "usb_allow" => {
            let busid_pin = args
                .get("busidPin")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            to_json(commands::usb_allow_core(
                d,
                &arg_str(&args, "name")?,
                &arg_str(&args, "device")?,
                busid_pin,
            )?)
        }
        "usb_revoke" => to_json(commands::usb_revoke_core(
            d,
            &arg_str(&args, "name")?,
            &arg_str(&args, "device")?,
        )?),
        "usb_attach" => to_json(commands::usb_attach_core(
            d,
            &arg_str(&args, "name")?,
            &arg_str(&args, "device")?,
        )?),
        "usb_detach" => to_json(commands::usb_detach_core(
            d,
            &arg_str(&args, "name")?,
            &arg_str(&args, "device")?,
        )?),
```

Test, in `lib.rs`'s dispatch test module (follow the existing dispatch tests'
`AppState` construction):

```rust
#[test]
fn dispatch_routes_usb_allow_with_the_camelcase_arg_the_frontend_sends() {
    let state = fake_state();
    let out = dispatch(
        &state,
        "usb_allow",
        serde_json::json!({"name": "web", "device": "0403:6001", "busidPin": "3-2"}),
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(out, serde_json::Value::Null);
    // The pin must survive the hop: dropping it silently would grant a wider
    // rule than the human chose.
    assert!(calls_of(&state).iter().any(|c| c.contains("3-2")));
}
```

Make `FakeDaemon::usb_allow` record the pin in `calls` so that assertion can bite.

- [ ] **Step 7: Run the app backend gate and commit**

```bash
cd app/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
git add app/src-tauri/src/commands.rs app/src-tauri/src/lib.rs
git commit -m "feat(app): expose the USB commands to the webview and the bridge"
```

---

### Task 7: Frontend types and IPC wrappers

**Files:**
- Modify: `app/src/lib/types.ts`, `app/src/lib/ipc.ts`
- Test: `app/src/test/ipc.test.ts`

**Interfaces:**
- Consumes: the Tauri command names from Task 6.
- Produces: `UsbUpstream`, `UsbDevice`, `UsbGrant`, `UsbStatus` types and
  `api.usbUpstreamShow/usbUpstreamSet/usbListDevices/usbStatus/usbAllow/usbRevoke/usbAttach/usbDetach`.

- [ ] **Step 1: Write the failing test**

In `app/src/test/ipc.test.ts`:

```ts
it("usb wrappers use the camelCase arg names the bridge expects", async () => {
  await api.usbUpstreamSet("127.0.0.1", 3240, true);
  await api.usbAllow("web", "0403:6001", "3-2");
  await api.usbAttach("web", "0403:6001");
  expect(invoke).toHaveBeenCalledWith("usb_upstream_set", {
    host: "127.0.0.1",
    port: 3240,
    allowRemote: true,
  });
  expect(invoke).toHaveBeenCalledWith("usb_allow", {
    name: "web",
    device: "0403:6001",
    busidPin: "3-2",
  });
  expect(invoke).toHaveBeenCalledWith("usb_attach", { name: "web", device: "0403:6001" });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd app && npx vitest run src/test/ipc.test.ts`
Expected: FAIL — `api.usbUpstreamSet is not a function`.

- [ ] **Step 3: Add the types**

In `app/src/lib/types.ts`:

```ts
/** The configured usbip upstream (mirrors UsbUpstreamView). */
export interface UsbUpstream {
  host: string;
  port: number;
  resolved: string | null;
  /** Stable kebab-case trust token, e.g. "own-host-loopback". */
  trust: string;
  /** Human-facing note for that trust class; null for the recommended one. */
  warning: string | null;
}

/** One row of the upstream device inventory (mirrors UsbDeviceView). */
export interface UsbDevice {
  busid: string;
  device: string;
  description: string;
  shared: boolean;
  granted_to: string[];
  /** For an unshared device: the exact command a human must run elevated. */
  bind_command: string | null;
  attached_to: string | null;
}

export interface UsbGrant {
  device: string;
  busid_pin: string | null;
  description: string;
  granted_at_unix_ms: number;
  attached: boolean;
}

export interface UsbStatus {
  grants: UsbGrant[];
  /** The sandbox is running a kernel with no USB stack but holds a grant. */
  restart_required: boolean;
}
```

- [ ] **Step 4: Add the wrappers**

In `app/src/lib/ipc.ts`, inside `api` (and add the four types to the import):

```ts
  usbUpstreamShow: () => invoke<UsbUpstream | null>("usb_upstream_show"),
  usbUpstreamSet: (host: string, port: number, allowRemote: boolean) =>
    invoke<void>("usb_upstream_set", { host, port, allowRemote }),
  usbListDevices: () => invoke<UsbDevice[]>("usb_list_devices"),
  usbStatus: (name: string) => invoke<UsbStatus>("usb_status", { name }),
  usbAllow: (name: string, device: string, busidPin: string | null) =>
    invoke<void>("usb_allow", { name, device, busidPin }),
  usbRevoke: (name: string, device: string) => invoke<void>("usb_revoke", { name, device }),
  usbAttach: (name: string, device: string) => invoke<void>("usb_attach", { name, device }),
  usbDetach: (name: string, device: string) => invoke<void>("usb_detach", { name, device }),
```

- [ ] **Step 5: Run the test**

Run: `cd app && npx vitest run src/test/ipc.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/src/lib/types.ts app/src/lib/ipc.ts app/src/test/ipc.test.ts
git commit -m "feat(app): add USB IPC wrappers and their frontend types"
```

---

### Task 8: The consent dialog

Shared by both surfaces. It is the GUI's version of a security gate that the CLI
already implements, so it must not be weaker: same stated consequences, same
type-the-id-back confirmation.

**Files:**
- Create: `app/src/components/UsbConsentDialog.tsx`
- Test: `app/src/test/usbConsentDialog.test.tsx`

**Interfaces:**
- Produces: `<UsbConsentDialog device description sandbox onConfirm onCancel />`.

- [ ] **Step 1: Write the failing test**

```tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { UsbConsentDialog } from "../components/UsbConsentDialog";

const props = {
  device: "0403:6001",
  description: "FT232 USB UART",
  sandbox: "web",
};

describe("UsbConsentDialog", () => {
  it("states every consequence the CLI banner states", () => {
    render(<UsbConsentDialog {...props} onConfirm={() => {}} onCancel={() => {}} />);
    const body = document.body.textContent ?? "";
    for (const clause of ["reflash", "not visible", "unavailable to the host", "cannot verify"]) {
      expect(body.toLowerCase()).toContain(clause);
    }
  });

  it("keeps the grant button disabled until the device id is typed back", () => {
    const onConfirm = vi.fn();
    render(<UsbConsentDialog {...props} onConfirm={onConfirm} onCancel={() => {}} />);
    const grant = screen.getByRole("button", { name: /grant/i });
    expect(grant).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/type the device id/i), {
      target: { value: "0403:6002" },
    });
    expect(grant).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/type the device id/i), {
      target: { value: " 0403:6001 " },
    });
    expect(grant).toBeEnabled();
    fireEvent.click(grant);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd app && npx vitest run src/test/usbConsentDialog.test.tsx`
Expected: FAIL — cannot resolve `../components/UsbConsentDialog`.

- [ ] **Step 3: Implement**

```tsx
import { useState } from "react";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface Props {
  device: string;
  description: string;
  sandbox: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/** The consequences of a grant, kept in step with the CLI's consent_banner
 *  (crates/izba-cli/src/commands/usb.rs). Two surfaces, one set of facts. */
const CLAUSES = [
  "The agent in that sandbox gets raw, transfer-level access to this device. It can reflash it, change its firmware, or permanently damage it.",
  "USB traffic is not visible to the egress firewall: Netlog will not show what crosses this link, and no allow-list applies to it.",
  "While attached, the device is unavailable to the host and to every other sandbox.",
  "izba cannot verify that this is the physical object in front of you — the USB/IP protocol carries no serial number, and a device asserts its own id.",
];

export function UsbConsentDialog({ device, description, sandbox, onConfirm, onCancel }: Props) {
  const [typed, setTyped] = useState("");
  const matches = typed.trim().toLowerCase() === device.toLowerCase();
  const what = description ? `${device} (${description})` : device;

  return (
    <Dialog open onOpenChange={(o) => { if (!o) onCancel(); }}>
      <DialogContent aria-label={`Grant ${device} to ${sandbox}`}>
        <DialogHeader>
          <DialogTitle>Grant {what} to “{sandbox}”?</DialogTitle>
          <DialogDescription>This is a standing grant: it survives replug and restart until you revoke it.</DialogDescription>
        </DialogHeader>
        <ul className="flex list-disc flex-col gap-2 pl-5 text-sm text-muted-foreground">
          {CLAUSES.map((c) => <li key={c}>{c}</li>)}
        </ul>
        <label className="mt-2 flex flex-col gap-1 text-sm" htmlFor="usb-consent-confirm">
          Type the device id to confirm
        </label>
        <Input
          id="usb-consent-confirm"
          aria-label="Type the device id to confirm"
          value={typed}
          placeholder={device}
          onChange={(e) => setTyped(e.target.value)}
        />
        <DialogFooter>
          <DialogClose asChild><Button variant="ghost">Cancel</Button></DialogClose>
          <Button variant="destructive" disabled={!matches} onClick={onConfirm}>Grant</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

- [ ] **Step 4: Run the tests**

Run: `cd app && npx vitest run src/test/usbConsentDialog.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add app/src/components/UsbConsentDialog.tsx app/src/test/usbConsentDialog.test.tsx
git commit -m "feat(app): add the USB consent dialog with CLI-parity clauses"
```

---

### Task 9: The global Devices view

Upstream configuration plus the inventory. This is the only surface that can be
useful with **no** sandbox selected, and the only one that may be reached with
USB unconfigured — so it owns the "feature is off" story.

**Files:**
- Create: `app/src/components/UsbView.tsx`
- Modify: `app/src/App.tsx`, `app/src/components/Rail.tsx`
- Test: `app/src/test/usbView.test.tsx`

**Interfaces:**
- Consumes: `api.usbUpstreamShow/usbUpstreamSet/usbListDevices` (Task 7).
- Produces: `<UsbView />`; `View` in `App.tsx`/`Rail.tsx` gains `"usb"`.

- [ ] **Step 1: Write the failing tests**

```tsx
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { UsbDevice, UsbUpstream } from "../lib/types";

const { usbUpstreamShow, usbUpstreamSet, usbListDevices } = vi.hoisted(() => ({
  usbUpstreamShow: vi.fn(), usbUpstreamSet: vi.fn(), usbListDevices: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: { usbUpstreamShow, usbUpstreamSet, usbListDevices } }));

import { UsbView } from "../components/UsbView";

const upstream: UsbUpstream = {
  host: "127.0.0.1", port: 3240, resolved: "127.0.0.1",
  trust: "own-host-loopback", warning: null,
};
const shared: UsbDevice = {
  busid: "3-2", device: "0403:6001", description: "FT232", shared: true,
  granted_to: ["web"], bind_command: null, attached_to: "web",
};
const unshared: UsbDevice = {
  busid: "1-4", device: "10c4:ea60", description: "CP2102", shared: false,
  granted_to: [], bind_command: "usbipd bind --busid 1-4", attached_to: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  usbUpstreamShow.mockResolvedValue(upstream);
  usbListDevices.mockResolvedValue([shared, unshared]);
  usbUpstreamSet.mockResolvedValue(undefined);
});

describe("UsbView", () => {
  it("does not enumerate devices when USB is not configured", async () => {
    usbUpstreamShow.mockResolvedValue(null);
    render(<UsbView />);
    await screen.findByText(/not configured/i);
    // Every other USB RPC refuses with the feature off; calling one to find
    // that out would render a scary error for an ordinary state.
    expect(usbListDevices).not.toHaveBeenCalled();
  });

  it("shows the trust warning for a non-loopback upstream", async () => {
    usbUpstreamShow.mockResolvedValue({
      ...upstream, host: "192.168.1.9", trust: "private-lan",
      warning: "anyone who can route there can attach the same devices",
    });
    render(<UsbView />);
    await screen.findByText(/anyone who can route there/i);
  });

  it("renders holders and grants for a shared device", async () => {
    render(<UsbView />);
    await screen.findByText("0403:6001");
    expect(screen.getByText(/attached to web/i)).toBeInTheDocument();
  });

  it("offers the bind command for an unshared device and never runs it", async () => {
    render(<UsbView />);
    await screen.findByText("usbipd bind --busid 1-4");
    // The affordance is copy-only: no button may claim to share the device.
    expect(screen.queryByRole("button", { name: /^share$/i })).not.toBeInTheDocument();
  });

  it("copies the bind command to the clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(<UsbView />);
    fireEvent.click(await screen.findByRole("button", { name: /copy/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("usbipd bind --busid 1-4"));
  });

  it("saves a new upstream and reloads", async () => {
    render(<UsbView />);
    await screen.findByText("0403:6001");
    fireEvent.click(screen.getByRole("button", { name: /change/i }));
    fireEvent.change(screen.getByLabelText(/host/i), { target: { value: "172.20.0.1" } });
    fireEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() =>
      expect(usbUpstreamSet).toHaveBeenCalledWith("172.20.0.1", 3240, false),
    );
  });
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd app && npx vitest run src/test/usbView.test.tsx`
Expected: FAIL — cannot resolve `../components/UsbView`.

- [ ] **Step 3: Implement `UsbView`**

Structure (write it to satisfy the tests above; follow `StorageView.tsx` for
layout idiom — `Card`/`CardContent`, `Badge`, a table, an error line):

```tsx
export function UsbView() {
  const [upstream, setUpstream] = useState<UsbUpstream | null>(null);
  const [configured, setConfigured] = useState<boolean | null>(null); // null = still loading
  const [devices, setDevices] = useState<UsbDevice[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  async function load() {
    try {
      const up = await api.usbUpstreamShow();
      setUpstream(up);
      setConfigured(up !== null);
      // Gate: every other USB RPC refuses while the feature is off.
      if (!up) { setDevices([]); return; }
      setDevices(await api.usbListDevices());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }
  useEffect(() => { void load(); }, []);
  ...
}
```

Required behaviours:
- `configured === false` → a panel saying USB passthrough is **not configured**,
  what an upstream is, and the configure form. No device call.
- `upstream.warning` → render it in a warning-styled box (Badge/`text-destructive`
  for `private-lan` and `public`), with the trust token shown.
- Device table columns: Device (`vid:pid` + description), Bus id, State, Actions.
  - `attached_to` → `attached to {sandbox}` badge.
  - `granted_to.length > 0` → one Badge per sandbox.
  - `!shared && bind_command` → a `<code>` with the command (selectable), a
    **Copy** button, and the sentence "izba never runs this for you — it needs
    Administrator on the USB host."
- Copy handler:

```tsx
  async function copy(cmd: string) {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(cmd);
    } catch {
      // Clipboard access can be refused; the command is on screen and
      // selectable, so say that instead of failing silently.
      setError("Could not copy — select the command above and copy it manually.");
    }
  }
```

(No new dependency: the webview is a secure context, and the fallback is the
visible text. A Tauri clipboard plugin would add an npm + Cargo dep and a
capability for one button.)

- A **Refresh** button calling `load()`; `usbListDevices` dials the upstream, so
  do not poll it on a timer.

- [ ] **Step 4: Run the tests**

Run: `cd app && npx vitest run src/test/usbView.test.tsx`
Expected: PASS (6 tests).

- [ ] **Step 5: Wire the view into the shell**

`app/src/App.tsx`:

```tsx
type View = "sandboxes" | "storage" | "usb";
...
        {view === "storage" ? (
          <StorageView />
        ) : view === "usb" ? (
          <UsbView />
        ) : (
          <Detail sandbox={current} onChanged={refresh} />
        )}
```

`app/src/components/Rail.tsx`: widen `type View` identically and add a nav button
beside the Storage one:

```tsx
      <Button
        type="button"
        variant="ghost"
        onClick={() => onView("usb")}
        aria-pressed={view === "usb"}
        className={view === "usb" ? "bg-accent font-semibold" : ""}
      >
        Devices
      </Button>
```

Match the existing button's full className string — copy it from the Storage
button rather than approximating.

- [ ] **Step 6: Run the frontend suite and commit**

```bash
cd app && npm run lint && npx tsc --noEmit && npx vitest run
git add app/src/components/UsbView.tsx app/src/components/Rail.tsx app/src/App.tsx app/src/test/usbView.test.tsx
git commit -m "feat(app): add the global USB devices view"
```

---

### Task 10: The per-sandbox USB tab

**Files:**
- Create: `app/src/components/UsbTab.tsx`
- Modify: `app/src/components/Detail.tsx`
- Test: `app/src/test/usbTab.test.tsx`

**Interfaces:**
- Consumes: `api.usbUpstreamShow/usbListDevices/usbStatus/usbAllow/usbRevoke/usbAttach/usbDetach`,
  `<UsbConsentDialog />` (Task 8), `<ConfirmDialog />`.
- Produces: `<UsbTab name running onChanged />`; `Tab` in `Detail.tsx` gains `"usb"`.

- [ ] **Step 1: Write the failing tests**

```tsx
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import type { UsbDevice, UsbStatus, UsbUpstream } from "../lib/types";

const m = vi.hoisted(() => ({
  usbUpstreamShow: vi.fn(), usbListDevices: vi.fn(), usbStatus: vi.fn(),
  usbAllow: vi.fn(), usbRevoke: vi.fn(), usbAttach: vi.fn(), usbDetach: vi.fn(),
}));
vi.mock("../lib/ipc", () => ({ api: m }));

import { UsbTab } from "../components/UsbTab";

const upstream: UsbUpstream = {
  host: "127.0.0.1", port: 3240, resolved: "127.0.0.1", trust: "own-host-loopback", warning: null,
};
const device: UsbDevice = {
  busid: "3-2", device: "0403:6001", description: "FT232", shared: true,
  granted_to: [], bind_command: null, attached_to: null,
};
const status = (over: Partial<UsbStatus> = {}): UsbStatus => ({
  grants: [], restart_required: false, ...over,
});
const granted = { device: "0403:6001", busid_pin: null, description: "FT232", granted_at_unix_ms: 1, attached: false };

beforeEach(() => {
  vi.clearAllMocks();
  m.usbUpstreamShow.mockResolvedValue(upstream);
  m.usbListDevices.mockResolvedValue([device]);
  m.usbStatus.mockResolvedValue(status());
  for (const f of [m.usbAllow, m.usbRevoke, m.usbAttach, m.usbDetach]) f.mockResolvedValue(undefined);
});

describe("UsbTab", () => {
  it("says USB is not configured and asks for nothing else", async () => {
    m.usbUpstreamShow.mockResolvedValue(null);
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/not configured/i);
    expect(m.usbStatus).not.toHaveBeenCalled();
    expect(m.usbListDevices).not.toHaveBeenCalled();
  });

  it("grants only after the consent dialog is satisfied", async () => {
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /allow/i }));
    // The dialog gate is the CLI's gate: no grant on open.
    expect(m.usbAllow).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText(/type the device id/i), {
      target: { value: "0403:6001" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^grant$/i }));
    await waitFor(() => expect(m.usbAllow).toHaveBeenCalledWith("web", "0403:6001", null));
  });

  it("warns that a restart is needed and does not offer attach", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [granted], restart_required: true }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    await screen.findByText(/restart/i);
    // Offering an attach that cannot work is worse than not offering one.
    expect(screen.queryByRole("button", { name: /^attach$/i })).not.toBeInTheDocument();
  });

  it("attaches a granted device and shows Detach once attached", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [granted] }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /^attach$/i }));
    await waitFor(() => expect(m.usbAttach).toHaveBeenCalledWith("web", "0403:6001"));

    m.usbStatus.mockResolvedValue(status({ grants: [{ ...granted, attached: true }] }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    expect(await screen.findByRole("button", { name: /^detach$/i })).toBeInTheDocument();
  });

  it("confirms before revoking, because revoke pulls a live device", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [{ ...granted, attached: true }] }));
    render(<UsbTab name="web" running onChanged={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /revoke/i }));
    expect(m.usbRevoke).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /^revoke$/i, hidden: false }));
    await waitFor(() => expect(m.usbRevoke).toHaveBeenCalledWith("web", "0403:6001"));
  });

  it("does not offer attach on a stopped sandbox", async () => {
    m.usbStatus.mockResolvedValue(status({ grants: [granted] }));
    render(<UsbTab name="web" running={false} onChanged={() => {}} />);
    await screen.findByText("0403:6001");
    expect(screen.queryByRole("button", { name: /^attach$/i })).not.toBeInTheDocument();
  });
});
```

The last revoke assertion depends on how `ConfirmDialog` labels its button —
read `app/src/test/confirmDialog.test.tsx` and use the same query idiom rather
than the `hidden: false` guess above.

- [ ] **Step 2: Run to verify they fail**

Run: `cd app && npx vitest run src/test/usbTab.test.tsx`
Expected: FAIL — cannot resolve `../components/UsbTab`.

- [ ] **Step 3: Implement `UsbTab`**

```tsx
interface Props {
  name: string;
  running: boolean;
  onChanged: () => void;
}
```

Load order, which is also the "off" gate:

```tsx
  async function load() {
    try {
      const up = await api.usbUpstreamShow();
      setConfigured(up !== null);
      if (!up) return;
      const [s, devs] = await Promise.all([api.usbStatus(name), api.usbListDevices()]);
      setStatus(s);
      setDevices(devs);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }
```

Render:
- `configured === false` → "USB passthrough is not configured. Set an upstream in
  **Devices** to use it." and nothing else.
- `status.restart_required` → a warning box: "This sandbox is running a kernel
  without USB support. Restart it to use the devices you granted." with a
  **Restart** button (`api.restart(name)` then `onChanged()` + `load()`), and
  suppress every Attach button while it is true.
- **Granted devices** table, one row per `status.grants` entry: device id +
  description, `busid_pin` when set, an `attached` Badge, an **Attach** button
  (only when `running && !restart_required && !g.attached`), a **Detach** button
  (when `g.attached`), and a **Revoke** button that opens `ConfirmDialog`
  ("Revoke {device} from {name}? If it is attached it will be pulled out of the
  sandbox immediately — the guest sees an unplug.").
- **Available devices**: rows from `devices` that are `shared` and not already in
  `status.grants`, each with an **Allow…** button opening `UsbConsentDialog`;
  on confirm call `api.usbAllow(name, device, null)`, close, `load()`,
  `onChanged()`. Unshared rows show the bind command as read-only text with the
  same "izba never runs this for you" note (no copy button here — Devices owns
  that affordance; keep the tab about this sandbox).
- Errors in a `text-destructive` line, never swallowed.

- [ ] **Step 4: Run the tests**

Run: `cd app && npx vitest run src/test/usbTab.test.tsx`
Expected: PASS (6 tests).

- [ ] **Step 5: Wire the tab into `Detail.tsx`**

```tsx
type Tab = "overview" | "ports" | "volumes" | "usb" | "logs" | "netlog" | "policy" | "manifest" | "shell";
```

Add `{ id: "usb", label: "USB" }` to `tabs` after `volumes`, and:

```tsx
        {tab === "usb" && <UsbTab name={name} running={running} onChanged={onChanged} />}
```

The tab is always present: it is where a user learns the feature exists and how
to turn it on. Add a case to `app/src/test/detail.test.tsx` asserting the USB tab
renders when clicked, following that file's existing tab assertions.

- [ ] **Step 6: Run the whole frontend gate and commit**

```bash
cd app && npm run lint && npm run build && npx vitest run --coverage
git add app/src/components/UsbTab.tsx app/src/components/Detail.tsx app/src/test/usbTab.test.tsx app/src/test/detail.test.tsx
git commit -m "feat(app): add the per-sandbox USB tab"
```

---

### Task 11: Documentation and the full gate sweep

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `docs/superpowers/specs/2026-08-04-izba-usb-passthrough-design.md`,
  `docs/security/findings-2026-06-15.md` (only if a finding's status changes)

- [ ] **Step 1: README**

In the USB section added by phase 3, document the GUI: the **Devices** view
(upstream config, inventory, bind commands) and the per-sandbox **USB** tab
(grant/revoke/attach/detach), and state the restart rule in one line: *"Granting
a device to a sandbox that is already running requires a restart — the USB
kernel is chosen at boot."*

- [ ] **Step 2: CLAUDE.md**

Extend the `app/src-tauri` paragraph's list of surfaces with the USB view/tab,
and add one line to the USB kernel-variant contract noting that `RunState`
records the booted variant and `UsbStatus.restart_required` is derived from it —
so a future change to the variant decision has to update the recorded fact too.

- [ ] **Step 3: Spec delivery note**

In §6.3, mark the GUI surface delivered and note the two facts added to make it
honest (`attached_to`, `restart_required`), with the "no proto bump — additive
`serde(default)`" rationale.

- [ ] **Step 4: Run every gate**

```bash
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
cd app && npm ci && npm run build && npm run lint && npx vitest run --coverage
cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

All must be green. Run the daemon e2e too if KVM is available (unsandboxed):
`IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1`.

- [ ] **Step 5: Commit, push, open the PR**

```bash
git add README.md CLAUDE.md docs/
git commit -m "docs(usb): document the desktop app surface and the restart rule"
git push -u origin feat/usb-passthrough-phase4
gh pr create --title "feat(app): USB passthrough phase 4 — desktop app surface" --body '...'
```

Open it **ready for review**, never `--draft` (draft gates the Greptile app).
Then iterate on CI until all checks, the SonarCloud quality gate
(`mergeStateStatus: CLEAN`), and Greptile are all satisfied.

---

## Self-Review

**Spec coverage (§6.3 GUI clause by clause):**

| Spec requirement | Task |
| --- | --- |
| "a USB panel listing upstream devices" | 9 (global), 10 (per-sandbox) |
| "with state (plugged in / shared / attached elsewhere)" | 2+3 give `attached_to`; 9 renders it |
| "one-click expose behind the same consent dialog" | 8 (dialog) + 10 (Allow…) |
| "a copy-the-command affordance for devices that still need `usbipd bind`" | 9 |
| "Adding the first grant to a running sandbox is a restart-class change … surfaced honestly" | 1+3 (compute), 4 (CLI), 10 (GUI) |
| "izba never elevates and never wraps usbipd-win" | 9, asserted by a negative test |

**Deviations recorded deliberately:**

1. **The restart-class fact is computed, not inferred.** The obvious cheap route
   is for the UI to guess ("running and this is the first grant"). That guess is
   wrong after a restart and unavailable to the CLI, so Task 1 records the booted
   variant in `RunState` and the daemon answers the question for every client.
2. **Attachment state comes from the broker, not from the guest.** The guest is
   hostile (A1) and izbad already *is* the attachment, so a registry around the
   splice is both cheaper and more trustworthy than a new guest RPC — and it
   avoids touching the guest wire protocol at all.
3. **The CLI gets the new facts before the GUI** (Task 4 before Tasks 5–10). The
   cheap surface is the one that proves the fact is expressible in a sentence.
4. **No clipboard plugin.** `navigator.clipboard.writeText` plus always-visible
   selectable text, rather than an npm + Cargo dependency and a new capability
   for a single button.
5. **The USB tab is always visible**, even with the feature off — it is where a
   user discovers the feature. It renders the off-state from `usbUpstreamShow`
   alone and calls no refusing RPC.

**Placeholder scan:** three steps deliberately say "read the existing signature
first, do not guess" (Task 1 Step 6, Task 3 Step 5, Task 5 Step 5, Task 10 Step 1)
rather than inventing an API. Those are instructions to check a fact this plan
cannot pin down without the file open, not deferred work — every one of them
names the exact symbol to look at and what to do with it.

**Type consistency:** `UsbStatusView::new(grants, attached, restart_required)`
(Task 5) is the only constructor used by `usb_status_core` (Task 6), whose output
type `UsbStatus` in TypeScript (Task 7) has `grants: UsbGrant[]` with `attached:
boolean` folded per grant — matching the Rust `UsbGrantView`. The wire type
`DaemonResponse::UsbStatus` keeps `attached: Vec<String>` separate (Task 3); the
fold happens exactly once, in `UsbStatusView::new`.
