# USB Passthrough Follow-ups (#187 #188 #189 #190 #195) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make USB passthrough actually usable from an installed build: ship the
USB kernel in the packages, make the `usbipd bind` affordance work on Windows and
on custom-kernel WSL, and give every device surface a human-readable name.

**Architecture:** Five defects with two roots. (1) The packaging pipeline never
learned about the second kernel `vmlinux-usb` that phase 3 introduced — fixed by
adding a `kernel-usb` job to the shared `_artifacts.yml` and threading the
artifact through both installers, pinned by a Rust test that couples
`KernelVariant` to the packaging manifest. (2) `usbipd_state::probe()` gates on
"am I under WSL?" when the question is "can I run `usbipd.exe` here?" — fixed by
a new capability predicate, which unblocks joining usbipd's product names onto
the device list and populating the grant record's description at allow time.

**Tech Stack:** Rust (izba-core, izba-cli), Tauri 2 backend (`app/src-tauri`),
Vitest/React frontend, GitHub Actions YAML, bash packaging scripts, Inno Setup.

## Global Constraints

- **Six workspace gates must be green before any commit:** `cargo test
  --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo
  fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl
  --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p
  izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu
  --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- **`app/src-tauri` is OUTSIDE the workspace.** Any task touching `izba-core`
  public types must additionally run: `cd app && npm ci && npm run build && (cd
  src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings &&
  cargo test)`.
- **`DAEMON_PROTO_VERSION` stays at 4.** Every change here is either host-local
  or an additive `#[serde(default)]` field on an existing shape. If a task seems
  to need a bump, stop and escalate.
- **Tests never bind unix/vsock/TCP listeners** — sandboxes deny `bind` with
  EPERM. Use pure functions and injected inputs.
- **`#[mutants::skip]` belongs only on the impure shim** (the function that reads
  `/proc` or spawns a process), never on the pure predicate it delegates to.
- Conventional commits (`fix(core): …`), TDD — test first, watch it fail, then
  implement.
- Never push to `main`; never open or convert a PR to draft.
- Branch: `feat/usb-passthrough-phase4`, on top of PR #186's existing 10 commits.

## Design Decisions (locked — do not re-litigate)

- **D-A (#189):** `vmlinux-usb` ships in **every** install, not behind an opt-in
  fetch. It adds ~40 MiB uncompressed (~10–12 MiB after xz/lzma2). The
  alternative requires artifact-hosting infrastructure that does not exist, and
  the status quo is a hard stop telling a packaged user to build a kernel.
- **D-B (#187):** WSL detection ORs the osrelease string match with
  process-independent filesystem markers `/run/WSL` and
  `/proc/sys/fs/binfmt_misc/WSLInterop`. **Not** `WSL_INTEROP`/`WSL_DISTRO_NAME`
  — izbad is a daemon and may not inherit a login shell's environment.
- **D-C (#188):** a new predicate `can_probe_usbipd()` = `cfg!(windows) ||
  running_under_wsl()` gates the probe. `trust::classify`'s use of
  `running_under_wsl()` is unchanged — there, WSL-ness genuinely is the question.
- **D-D (#190):** the description join key is **(busid, id) both equal**, with a
  fallback to id alone **only when exactly one usbipd row carries that id**.
  Never join on busid alone: a busid is host-local, so against a remote upstream
  a bare busid match would paste a local device's name (e.g. `USB Serial Device
  (COM8)`) onto someone else's hardware.
- **D-E (#195):** the grant description is sourced host-side from
  `usbipd_state::probe()` **only** — no `inventory::fetch` dial in the allow
  path. Rationale: `UpstreamDevice.description` is a sysfs path, not a product
  name, so the dial would cost up to 5 s to obtain something not worth showing;
  and a grant is a standing config edit that must keep working with the upstream
  unreachable. Absent a name, the description stays empty and every surface
  already degrades cleanly.

---

## File Structure

**Modified — Rust core**
- `crates/izba-core/src/usb/trust.rs` — add `wsl_from_signals`, rewire
  `running_under_wsl`; add `usbipd_is_local` + `can_probe_usbipd`.
- `crates/izba-core/src/usb/usbipd_state.rs` — swap the probe gate; add
  `describe` (the D-D join helper).
- `crates/izba-core/src/usb/mod.rs` — `list_devices` enriches shared rows.
- `crates/izba-core/src/daemon/server.rs` — `handle_usb_allow` populates the
  grant description.
- `crates/izba-core/src/artifacts.rs` — `KernelVariant::ALL` + the packaging
  regression test.

**Modified — CLI**
- `crates/izba-cli/src/commands/usb.rs` — `allow()` looks up the description
  before printing the consent banner.

**Modified — app**
- `app/src-tauri/src/fake.rs` — `FakeDaemon::usb_allow` mirrors the daemon.

**Modified — packaging/CI**
- `.github/workflows/_artifacts.yml` — new `kernel-usb` job; `manifest.needs`.
- `.github/workflows/devbuild.yml` — download `vmlinux-usb` into `dl/art` and
  `stage/artifacts`; pass `IZBA_VMLINUX_USB`.
- `.github/workflows/release.yml` — same, plus the `.deb` smoke assertion.
- `packaging/build-deb.sh` — new required `IZBA_VMLINUX_USB` input.
- `packaging/windows/izba.iss` — header comment only (`[Files]` already globs).
- `hack/stage-izba-windows.sh` — stage the USB kernel too (best-effort).

---

### Task 1: WSL detection that survives a custom kernel (#187)

**Files:**
- Modify: `crates/izba-core/src/usb/trust.rs:116-119` (`wsl_from_osrelease`) and
  `:135-140` (`running_under_wsl`)
- Test: same file, `mod tests`

**Interfaces:**
- Consumes: nothing.
- Produces: `pub fn wsl_from_signals(release: &str, run_wsl_marker: bool,
  binfmt_marker: bool) -> bool`. `wsl_from_osrelease(&str) -> bool` stays
  public and unchanged (still used by the existing test and by
  `wsl_from_signals`). `running_under_wsl() -> bool` keeps its signature.

- [ ] **Step 1: Write the failing tests**

Append inside `mod tests` in `crates/izba-core/src/usb/trust.rs`:

```rust
    #[test]
    fn a_custom_wsl_kernel_is_still_wsl_when_the_interop_markers_are_present() {
        // The reported case: a self-built WSL2 kernel whose release string
        // carries neither "microsoft" nor "wsl", on a machine where interop
        // plainly works.
        assert!(wsl_from_signals("6.6.87.2-cilium-6.6.87.2+", true, false));
        assert!(wsl_from_signals("6.6.87.2-cilium-6.6.87.2+", false, true));
        assert!(wsl_from_signals("6.6.87.2-cilium-6.6.87.2+", true, true));
    }

    #[test]
    fn a_stock_wsl_kernel_is_wsl_even_with_no_markers_readable() {
        // The markers are a widening, never a narrowing: a release string that
        // already says microsoft must not start depending on /run/WSL being
        // readable by whatever user izbad runs as.
        assert!(wsl_from_signals("5.15.167.4-microsoft-standard-WSL2", false, false));
    }

    #[test]
    fn a_plain_linux_host_is_not_wsl() {
        assert!(!wsl_from_signals("6.8.0-45-generic", false, false));
        assert!(!wsl_from_signals("", false, false));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib usb::trust -- --nocapture`
Expected: FAIL — `cannot find function 'wsl_from_signals' in this scope`.

- [ ] **Step 3: Implement**

In `crates/izba-core/src/usb/trust.rs`, immediately after `wsl_from_osrelease`
(which stays exactly as it is), add:

```rust
/// Decide WSL-ness from every signal available to a *daemon*.
///
/// The kernel release string alone is not enough: a custom WSL2 kernel carries
/// neither "microsoft" nor "wsl" (izba issue #187), and concluding "not WSL"
/// there silently kills the `usbipd bind` affordance. The filesystem markers are
/// process-independent on purpose — `WSL_INTEROP` and `WSL_DISTRO_NAME` are
/// login-shell environment, which izbad may never have inherited.
///
/// Widening only: any single positive signal is enough, so a machine that was
/// already detected keeps being detected.
pub fn wsl_from_signals(release: &str, run_wsl_marker: bool, binfmt_marker: bool) -> bool {
    wsl_from_osrelease(release) || run_wsl_marker || binfmt_marker
}
```

Then replace the body of `running_under_wsl` (keeping its `#[mutants::skip]` and
its doc comment, extending the comment as shown):

```rust
/// Whether izbad is running inside WSL. Impure shim over [`wsl_from_signals`];
/// every signal it reads is a file, so the decision itself stays testable.
#[mutants::skip]
pub fn running_under_wsl() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    wsl_from_signals(
        &release,
        std::path::Path::new("/run/WSL").exists(),
        std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists(),
    )
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib usb::trust`
Expected: PASS, including the pre-existing
`wsl_is_detected_from_the_kernel_release_string`.

- [ ] **Step 5: Gates + commit**

```bash
cargo fmt && cargo clippy -p izba-core --all-targets -- -D warnings
git add crates/izba-core/src/usb/trust.rs
git commit -m "fix(core): detect WSL from interop markers, not just the release string

A self-built WSL2 kernel reports a release with neither \"microsoft\" nor
\"wsl\" in it, so izba concluded it was not under WSL on a machine that
plainly was — silently killing the usbipd-bind affordance and downgrading
gateway trust to a spurious LAN warning. OR the string match with the
process-independent markers /run/WSL and WSLInterop; env vars are not an
option because izbad is a daemon and may not inherit a login shell.

Closes #187"
```

---

### Task 2: Gate the probe on capability, not environment (#188)

**Files:**
- Modify: `crates/izba-core/src/usb/trust.rs` (add the predicate),
  `crates/izba-core/src/usb/usbipd_state.rs:113-121` (the gate)
- Test: `crates/izba-core/src/usb/trust.rs` `mod tests`

**Interfaces:**
- Consumes: `wsl_from_signals` / `running_under_wsl` from Task 1.
- Produces: `pub fn usbipd_is_local(is_windows: bool, under_wsl: bool) -> bool`
  and `pub fn can_probe_usbipd() -> bool` in `usb::trust`.

- [ ] **Step 1: Write the failing tests**

Append inside `mod tests` in `crates/izba-core/src/usb/trust.rs`:

```rust
    #[test]
    fn usbipd_is_reachable_natively_on_windows() {
        // izbad on Windows runs *beside* usbipd-win — no interop hop at all.
        // This is the platform usbipd-win actually targets, and it was the one
        // where the probe never ran (#188).
        assert!(usbipd_is_local(true, false));
    }

    #[test]
    fn usbipd_is_reachable_across_the_wsl_interop_boundary() {
        assert!(usbipd_is_local(false, true));
    }

    #[test]
    fn a_plain_linux_host_has_no_local_usbipd_to_ask() {
        // Its upstream is another machine; spawning usbipd.exe there would only
        // burn the probe timeout.
        assert!(!usbipd_is_local(false, false));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core --lib usb::trust`
Expected: FAIL — `cannot find function 'usbipd_is_local' in this scope`.

- [ ] **Step 3: Implement the predicate**

Append to `crates/izba-core/src/usb/trust.rs`, after `wsl_from_signals`:

```rust
/// Whether a local `usbipd.exe` is reachable from this process.
///
/// Deliberately NOT "am I under WSL?" — that question and this one coincide only
/// on stock WSL. On Windows izbad runs natively beside usbipd-win and can invoke
/// it directly (#188); under WSL it reaches it over interop (#187); on a plain
/// Linux host there is nothing to ask, and probing would only burn the timeout.
pub fn usbipd_is_local(is_windows: bool, under_wsl: bool) -> bool {
    is_windows || under_wsl
}

/// Impure shim over [`usbipd_is_local`].
#[mutants::skip]
pub fn can_probe_usbipd() -> bool {
    usbipd_is_local(cfg!(windows), running_under_wsl())
}
```

- [ ] **Step 4: Swap the gate**

In `crates/izba-core/src/usb/usbipd_state.rs`, replace lines 119–121:

```rust
    if !super::trust::running_under_wsl() {
        return None;
    }
```

with:

```rust
    if !super::trust::can_probe_usbipd() {
        return None;
    }
```

Also update the doc comment on `PROBE_TIMEOUT_SECS` (line 19–21) to stop
asserting an interop hop is always involved:

```rust
/// How long izba waits for `usbipd.exe state`. Sized for the WSL interop hop,
/// which is the slow case; a native Windows spawn returns far inside it. Past
/// this the listing proceeds without enrichment.
pub const PROBE_TIMEOUT_SECS: u64 = 5;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p izba-core --lib usb::`
Expected: PASS.

- [ ] **Step 6: Cross gates + commit**

```bash
cargo fmt && cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
git add crates/izba-core/src/usb/trust.rs crates/izba-core/src/usb/usbipd_state.rs
git commit -m "fix(core): probe usbipd wherever it is reachable, including Windows

The probe gate asked \"am I under WSL?\" when the question it needed to
answer was \"can I run usbipd.exe here?\". Those coincide on stock WSL and
nowhere else, so on Windows — the platform usbipd-win actually runs on —
izba never enumerated unshared devices and never printed the
'usbipd bind --busid <id>' command spec §6.1 promises. An empty list is
indistinguishable from no hardware, so the feature failed silently.

Closes #188"
```

---

### Task 3: Join usbipd's product name onto shared rows (#190)

**Files:**
- Modify: `crates/izba-core/src/usb/usbipd_state.rs` (add `describe`),
  `crates/izba-core/src/usb/mod.rs:196-207` (`list_devices` shared arm)
- Test: both files, `mod tests`

**Interfaces:**
- Consumes: `UsbipdDevice { busid, id, description, bound, attached }` from
  `usb::usbipd_state`; `DeviceId` (`usb::ids`, `Copy`, `PartialEq`).
- Produces: `pub fn describe<'a>(known: &'a [UsbipdDevice], busid: &str, id:
  DeviceId) -> Option<&'a str>` in `usb::usbipd_state`.

- [ ] **Step 1: Write the failing join tests**

Append inside `mod tests` in `crates/izba-core/src/usb/usbipd_state.rs`:

```rust
    fn known(busid: &str, vid: u16, pid: u16, desc: &str) -> UsbipdDevice {
        UsbipdDevice {
            busid: busid.to_string(),
            id: DeviceId { vid, pid },
            description: desc.to_string(),
            bound: true,
            attached: false,
        }
    }

    #[test]
    fn a_row_matching_on_both_busid_and_id_gets_the_product_name() {
        let table = [known("12-4", 0x303a, 0x1001, "USB JTAG/serial debug unit")];
        assert_eq!(
            describe(&table, "12-4", DeviceId { vid: 0x303a, pid: 0x1001 }),
            Some("USB JTAG/serial debug unit")
        );
    }

    #[test]
    fn a_busid_match_with_a_different_device_never_lends_its_name() {
        // A busid is host-local. Against a remote upstream the same string can
        // name entirely different hardware, and pasting a local product name
        // (worse: one carrying a local COM port) onto it would be a lie.
        let table = [known("12-4", 0x303a, 0x1001, "USB JTAG/serial debug unit")];
        assert_eq!(
            describe(&table, "12-4", DeviceId { vid: 0x0403, pid: 0x6001 }),
            None
        );
    }

    #[test]
    fn a_unique_id_still_matches_when_the_busids_differ() {
        // usbipd's busid and the upstream's exported busid need not be spelled
        // the same. One unambiguous device of that model is still safe to name.
        let table = [known("3-2", 0x303a, 0x1001, "USB JTAG/serial debug unit")];
        assert_eq!(
            describe(&table, "12-4", DeviceId { vid: 0x303a, pid: 0x1001 }),
            Some("USB JTAG/serial debug unit")
        );
    }

    #[test]
    fn two_identical_models_are_ambiguous_and_neither_name_is_borrowed() {
        let table = [
            known("3-2", 0x303a, 0x1001, "board on the left"),
            known("3-3", 0x303a, 0x1001, "board on the right"),
        ];
        // Neither busid matches, and the id alone cannot pick between them.
        assert_eq!(
            describe(&table, "12-4", DeviceId { vid: 0x303a, pid: 0x1001 }),
            None
        );
        // …but an exact busid match still resolves it.
        assert_eq!(
            describe(&table, "3-3", DeviceId { vid: 0x303a, pid: 0x1001 }),
            Some("board on the right")
        );
    }

    #[test]
    fn an_empty_usbipd_description_is_not_worth_borrowing() {
        let table = [known("12-4", 0x303a, 0x1001, "")];
        assert_eq!(
            describe(&table, "12-4", DeviceId { vid: 0x303a, pid: 0x1001 }),
            None
        );
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p izba-core --lib usb::usbipd_state`
Expected: FAIL — `cannot find function 'describe' in this scope`.

- [ ] **Step 3: Implement `describe`**

In `crates/izba-core/src/usb/usbipd_state.rs`, after `bind_command`:

```rust
/// The human-readable product name usbipd knows for a device, if it can be
/// matched without guessing.
///
/// The USB/IP wire format carries no product string — `OP_REP_DEVLIST` gives a
/// sysfs path and nothing friendlier — so the only source of "USB JTAG/serial
/// debug unit" is usbipd's own state table, and getting it onto a shared row is
/// a join rather than a new field (#190).
///
/// Match rule, in order:
/// 1. busid AND id both equal — unambiguous.
/// 2. id equal and exactly one row carries it — the busid spellings need not
///    agree between usbipd and the upstream's export, and one device of that
///    model cannot be confused with another.
///
/// Never busid alone: a busid is host-local, so against a remote upstream that
/// would paste this machine's device name onto someone else's hardware.
pub fn describe<'a>(known: &'a [UsbipdDevice], busid: &str, id: DeviceId) -> Option<&'a str> {
    let non_empty = |d: &'a UsbipdDevice| Some(d.description.as_str()).filter(|s| !s.is_empty());
    if let Some(d) = known.iter().find(|d| d.busid == busid && d.id == id) {
        return non_empty(d);
    }
    let mut by_id = known.iter().filter(|d| d.id == id);
    let only = by_id.next()?;
    if by_id.next().is_some() {
        return None;
    }
    non_empty(only)
}
```

- [ ] **Step 4: Write the failing `list_devices` test**

Append inside `mod tests` in `crates/izba-core/src/usb/mod.rs` (reuse the
existing `paths_with_sandboxes` and `upstream_device` helpers; construct
`UsbipdDevice` inline since `usbipd_state`'s test helper is private to that
module):

```rust
    #[test]
    fn a_shared_row_borrows_the_product_name_usbipd_knows_for_it() {
        let (_tmp, paths) = paths_with_sandboxes(&[]);
        let shared = [upstream_device("12-4", 0x303a, 0x1001)];
        let known = vec![usbipd_state::UsbipdDevice {
            busid: "12-4".to_string(),
            id: DeviceId { vid: 0x303a, pid: 0x1001 },
            description: "USB JTAG/serial debug unit".to_string(),
            bound: true,
            attached: false,
        }];
        let out = list_devices(&paths, &shared, Some(known), &HashMap::new());
        assert_eq!(out.len(), 1, "a bound device must not be listed twice");
        assert_eq!(out[0].description, "USB JTAG/serial debug unit");
    }

    #[test]
    fn a_shared_row_keeps_its_sysfs_path_when_usbipd_offers_no_better_name() {
        let (_tmp, paths) = paths_with_sandboxes(&[]);
        let shared = [upstream_device("12-4", 0x303a, 0x1001)];
        let out = list_devices(&paths, &shared, None, &HashMap::new());
        assert!(
            out[0].description.starts_with("/sys/devices"),
            "expected the unenriched fallback, got {:?}",
            out[0].description
        );
    }
```

Check `upstream_device`'s existing signature at `crates/izba-core/src/usb/mod.rs`
first; if it does not already take busid/vid/pid, call it as it is defined and
adjust the literals above to match what it produces.

- [ ] **Step 5: Run to verify the first test fails**

Run: `cargo test -p izba-core --lib usb::tests`
Expected: FAIL on `a_shared_row_borrows_the_product_name_usbipd_knows_for_it` —
description is the sysfs path, not the product name.

- [ ] **Step 6: Enrich the shared arm**

In `crates/izba-core/src/usb/mod.rs`, `list_devices` currently binds `known` and
consumes it only in the unshared loop. Materialise it once before the shared map
so both arms can read it:

```rust
    let grants = grants_by_device(paths);
    let known = known.unwrap_or_default();
    let mut out: Vec<UsbDeviceInfo> = shared
        .iter()
        .map(|d| UsbDeviceInfo {
            busid: d.busid.clone(),
            device: d.id.to_string(),
            // The wire format carries only a sysfs path; usbipd knows the
            // product name. Prefer the name, keep the path as the fallback.
            description: usbipd_state::describe(&known, &d.busid, d.id)
                .unwrap_or(&d.description)
                .to_string(),
            shared: true,
            granted_to: grants.get(&d.id).cloned().unwrap_or_default(),
            attached_to: attached.get(&d.id).cloned(),
            bind_command: None,
        })
        .collect();
    // Only the UNBOUND rows are additive: a bound device is already in `shared`,
    // and listing it twice would read as two pieces of hardware.
    for k in known.into_iter().filter(|k| !k.bound) {
```

(the rest of the unshared loop is unchanged).

- [ ] **Step 7: Run to verify all pass**

Run: `cargo test -p izba-core --lib usb::`
Expected: PASS, including the six pre-existing `list_devices` tests.

- [ ] **Step 8: Gates + commit**

```bash
cargo fmt && cargo clippy --workspace --all-targets -- -D warnings
git add crates/izba-core/src/usb/usbipd_state.rs crates/izba-core/src/usb/mod.rs
git commit -m "feat(core): name shared devices by their product string, not a sysfs path

OP_REP_DEVLIST carries no product name, so a shared row could only be
described by the sysfs path the wire format does carry. usbipd's own state
table has the friendly name, so this is a join, not a new source. The join
requires busid+id, or a unique id: a busid is host-local, and matching on it
alone would paste this machine's device name onto a remote upstream's
hardware.

Closes #190"
```

---

### Task 4: Populate the grant description at allow time (#195, host side)

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs:881-907` (`handle_usb_allow`)
- Modify: `app/src-tauri/src/fake.rs:429-450` (`FakeDaemon::usb_allow`)
- Test: `crates/izba-core/src/daemon/server.rs` `mod tests`

**Interfaces:**
- Consumes: `usbipd_state::describe` from Task 3; the existing `grant_on_disk`
  test helper at `crates/izba-core/src/daemon/server.rs:1585`.
- Produces: a non-empty `UsbGrant.description` on the production allow path.
  No wire change — `UsbAllow` gains no field (D-E: the description is derived
  host-side, keeping the grant record host-only managed truth per D1).

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/izba-core/src/daemon/server.rs`. Model it on the
existing USB handler tests in that module (find one that builds a `Daemon` with
a configured upstream — e.g. near `usb_requests_refuse_when_no_upstream_is_configured`
at line 1445 — and reuse its fixture verbatim). The assertion:

```rust
    #[test]
    fn a_grant_records_the_product_name_izba_already_knows() {
        // The grant record is what every later surface reads — `izba usb status`,
        // the app's granted list, and the CLI consent banner. Storing an empty
        // description there makes all three name a physical device by four hex
        // digits, which is exactly where "is this the board on my desk?" needs
        // answering.
        let known = vec![crate::usb::usbipd_state::UsbipdDevice {
            busid: "12-4".to_string(),
            id: crate::usb::DeviceId { vid: 0x303a, pid: 0x1001 },
            description: "USB JTAG/serial debug unit".to_string(),
            bound: true,
            attached: false,
        }];
        assert_eq!(
            grant_description(Some(&known), crate::usb::DeviceId { vid: 0x303a, pid: 0x1001 }, None),
            "USB JTAG/serial debug unit"
        );
    }

    #[test]
    fn a_grant_with_no_name_available_records_an_empty_one_rather_than_failing() {
        // A grant is a standing config edit; it must keep working with no local
        // usbipd and no reachable upstream. Every surface already renders an
        // empty description cleanly (the consent banner drops the parentheses).
        assert_eq!(
            grant_description(None, crate::usb::DeviceId { vid: 0x303a, pid: 0x1001 }, None),
            ""
        );
    }

    #[test]
    fn a_pinned_grant_takes_the_name_of_the_device_it_pinned() {
        let known = vec![
            crate::usb::usbipd_state::UsbipdDevice {
                busid: "3-2".to_string(),
                id: crate::usb::DeviceId { vid: 0x303a, pid: 0x1001 },
                description: "board on the left".to_string(),
                bound: true,
                attached: false,
            },
            crate::usb::usbipd_state::UsbipdDevice {
                busid: "3-3".to_string(),
                id: crate::usb::DeviceId { vid: 0x303a, pid: 0x1001 },
                description: "board on the right".to_string(),
                bound: true,
                attached: false,
            },
        ];
        assert_eq!(
            grant_description(
                Some(&known),
                crate::usb::DeviceId { vid: 0x303a, pid: 0x1001 },
                Some("3-3"),
            ),
            "board on the right"
        );
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p izba-core --lib daemon::server`
Expected: FAIL — `cannot find function 'grant_description' in this scope`.

- [ ] **Step 3: Implement the pure helper**

In `crates/izba-core/src/daemon/server.rs`, immediately above `handle_usb_allow`:

```rust
/// The description to store on a new grant. Pure so the match rule is testable
/// without a live usbipd.
///
/// Best-effort by design (D-E): a grant is a standing config edit and must not
/// fail because the name is unavailable. When there is no pin, an unpinned grant
/// matches any busid, so the id-alone rule in `usbipd_state::describe` is the
/// right one; a pinned grant names the exact device it pinned.
fn grant_description(
    known: Option<&[crate::usb::usbipd_state::UsbipdDevice]>,
    id: crate::usb::DeviceId,
    busid_pin: Option<&str>,
) -> String {
    known
        .and_then(|k| crate::usb::usbipd_state::describe(k, busid_pin.unwrap_or(""), id))
        .unwrap_or_default()
        .to_string()
}
```

Note the `unwrap_or("")` — an empty busid can never equal a real one
(`valid_busid` rejects empty), so an unpinned grant falls straight through to the
unique-id rule.

- [ ] **Step 4: Wire it into the handler**

In `handle_usb_allow`, replace `description: String::new(),` (line 896) so the
handler reads:

```rust
    usb_settings_or_refuse(d)?;
    let id: crate::usb::DeviceId = device.parse()?;
    sandbox_must_exist(&d.paths, &name)?;
    // Derived host-side, never accepted from the client: the grant record is
    // host-only managed truth (D1), and this is the value every later surface
    // shows the human.
    let description = grant_description(
        crate::usb::usbipd_state::probe().as_deref(),
        id,
        busid_pin.as_deref(),
    );
    sandbox::edit_usb_grants(&d.paths, &name, |usb| {
        crate::usb::grants::grant(
            usb,
            crate::usb::UsbGrant {
                device: id,
                busid_pin: busid_pin.clone(),
                description: description.clone(),
                granted_at_unix_ms: crate::usb::now_unix_ms(),
            },
        )
    })?;
```

(`busid_pin` is moved into the closure today; cloning it keeps the pin available
for `grant_description` above. If clippy objects to the clone, restructure by
computing the description before the closure and moving `busid_pin` in as
before — the pin is only read, so `busid_pin.as_deref()` before the closure is
sufficient and no clone is needed.)

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p izba-core --lib daemon::server`
Expected: PASS.

- [ ] **Step 6: Mirror it in the app's fake daemon**

`app/src-tauri/src/fake.rs:429-450` reproduces the daemon's bug, so app tests
cannot see the fix. `FakeDaemon` already holds a device list; look up the
description from it. Replace line 446 (`description: String::new(),`) with a
lookup over the fake's own device inventory, matching on `device`:

```rust
            description: self
                .usb_devices
                .iter()
                .find(|d| d.device == device)
                .map(|d| d.description.clone())
                .unwrap_or_default(),
```

Adjust the field name (`self.usb_devices`) to whatever the struct actually calls
its device list — read the surrounding `FakeDaemon` definition first.

- [ ] **Step 7: App gate**

```bash
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cd "$(git rev-parse --show-toplevel)"
cargo fmt && cargo clippy --workspace --all-targets -- -D warnings
git add crates/izba-core/src/daemon/server.rs app/src-tauri/src/fake.rs
git commit -m "fix(core): record what a granted device actually is

UsbGrant.description was plumbed end to end — persisted, returned, rendered
by izba usb status, by the app's granted rows and by UsbStatusView — but the
only code that ever created a grant wrote an empty string, so every one of
those surfaces rendered blank. Derive it host-side from usbipd's table at
allow time, best-effort: no dial, no new wire field, and a grant still
succeeds with nothing reachable.

Refs #195"
```

---

### Task 5: Name the device in the CLI consent banner (#195, CLI side)

**Files:**
- Modify: `crates/izba-cli/src/commands/usb.rs:302-356` (`allow`)
- Test: same file, `mod tests`

**Interfaces:**
- Consumes: `DaemonRequest::UsbListDevices` / `DaemonResponse::UsbDevices`
  (`UsbDeviceInfo { device, description, .. }`), `consent_banner(sandbox, device,
  description)`.
- Produces: `fn description_of(devices: &[UsbDeviceInfo], device: &str) -> &str`
  in the same module.

- [ ] **Step 1: Write the failing test**

Append inside `mod tests` in `crates/izba-cli/src/commands/usb.rs` (reuse the
existing `dev` helper at line 695):

```rust
    #[test]
    fn the_banner_names_the_device_when_the_listing_knows_it() {
        // The consent banner is the loudest, most safety-relevant surface in the
        // feature — it asks a human to type an id back to confirm they are
        // handing raw transfer-level access to a physical object. Identifying
        // that object by four hex digits is exactly where it must not stop.
        let devices = [dev("12-4", "303a:1001", "USB JTAG/serial debug unit")];
        assert_eq!(
            description_of(&devices, "303a:1001"),
            "USB JTAG/serial debug unit"
        );
    }

    #[test]
    fn an_unknown_device_yields_no_description_rather_than_a_wrong_one() {
        let devices = [dev("12-4", "303a:1001", "USB JTAG/serial debug unit")];
        assert_eq!(description_of(&devices, "0403:6001"), "");
        assert_eq!(description_of(&[], "303a:1001"), "");
    }
```

Check `dev`'s existing parameter order at line 695 and match it; adjust the
literals if it takes different fields.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p izba-cli --lib commands::usb`
Expected: FAIL — `cannot find function 'description_of' in this scope`.

- [ ] **Step 3: Implement the lookup**

In `crates/izba-cli/src/commands/usb.rs`, above `allow`:

```rust
/// The description the daemon's listing carries for `device`, or "" if it has
/// none. Pure so the banner's naming is testable without a daemon.
fn description_of<'a>(devices: &'a [UsbDeviceInfo], device: &str) -> &'a str {
    devices
        .iter()
        .find(|d| d.device == device)
        .map(|d| d.description.as_str())
        .unwrap_or_default()
}
```

- [ ] **Step 4: Use it in `allow`**

`allow` currently connects to the daemon only after confirmation. Connect first,
look the description up best-effort, then prompt. Replace the body from the
`confirmed` binding through the `DaemonClient::connect` line with:

```rust
    let mut client = DaemonClient::connect(paths)?;

    // Best-effort: a listing needs a configured, reachable upstream, and a grant
    // is a standing config edit that must not depend on either. No name is a
    // quieter banner, not a failed grant.
    let described = match client.request(&DaemonRequest::UsbListDevices, &mut |_| {}) {
        Ok(DaemonResponse::UsbDevices { devices }) => description_of(&devices, &device).to_string(),
        _ => String::new(),
    };

    // One decision, one branch: either the flag already confirmed it, or the
    // human types the id back after reading the banner.
    let confirmed = match resolve_confirmation(&device, confirm, std::io::stdin().is_terminal())? {
        true => true,
        false => {
            eprint!("{}", consent_banner(name, &device, &described));
            eprint!("\nType the device id to confirm: ");
            std::io::stderr().flush()?;
            prompt_confirms(&device)?
        }
    };
    if !confirmed {
        eprintln!("aborted");
        return Ok(1);
    }

    super::expect_ok(client.request(
```

(The `DaemonClient::connect` line that used to sit here is now above; delete the
duplicate.)

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p izba-cli`
Expected: PASS, including the pre-existing
`the_banner_omits_an_empty_description_rather_than_printing_empty_parens`.

- [ ] **Step 6: Gates + commit**

```bash
cargo fmt && cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
git add crates/izba-cli/src/commands/usb.rs
git commit -m "fix(cli): name the device in the consent banner

consent_banner formats \"{device} ({description})\" and drops the parens on
an empty description — which, since allow() passed a literal \"\", was
always. The one surface asking a human to confirm they are handing raw
transfer-level access to a physical device identified it by four hex digits.
Look the name up from the daemon's own listing, best-effort so a grant still
works with no reachable upstream.

Closes #195"
```

---

### Task 6: Build the USB kernel in the shared artifacts workflow (#189, build half)

**Files:**
- Modify: `.github/workflows/_artifacts.yml` (new job after `kernel` at line 34;
  `manifest.needs` at line 234)

**Interfaces:**
- Consumes: `hack/build-kernel.sh` (`VERSION` arg 1, `OUTPUT` arg 2, env
  `IZBA_KERNEL_EXTRA_CONFIG`), `hack/kernel-usb.config`.
- Produces: a workflow artifact named `vmlinux-usb` containing `dist/vmlinux-usb`,
  downloadable by `devbuild.yml` and `release.yml` in Task 7.

- [ ] **Step 1: Add the job**

Insert into `.github/workflows/_artifacts.yml` directly after the `kernel` job
(which ends at line 34), copied from the proven `e2e.yml:44-72`:

```yaml
  kernel-usb:
    name: vmlinux-usb (USB passthrough variant)
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@9f698171ed81b15d1823a05fc7211befd50c8ae0 # v6.0.3
      - name: Restore built vmlinux-usb
        id: vmlinux_usb
        uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5
        with:
          path: dist/vmlinux-usb
          # Hashes BOTH fragments: the variant is the base config plus the USB
          # overlay, so a change to either must rebuild it.
          key: vmlinux-usb-${{ hashFiles('hack/kernel.config', 'hack/kernel-usb.config', 'hack/build-kernel.sh') }}
      - name: Install kernel build deps
        if: steps.vmlinux_usb.outputs.cache-hit != 'true'
        run: |
          sudo apt-get update
          sudo apt-get install -y --no-install-recommends build-essential flex bison bc libelf-dev
      - name: Build USB kernel
        if: steps.vmlinux_usb.outputs.cache-hit != 'true'
        env:
          IZBA_KERNEL_EXTRA_CONFIG: hack/kernel-usb.config
        run: hack/build-kernel.sh 6.12.30 dist/vmlinux-usb
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: vmlinux-usb
          path: dist/vmlinux-usb
          if-no-files-found: error
```

The cache key matches `e2e.yml`'s exactly, so the two workflows share cache
entries and the second one to run is a hit rather than a 90-minute rebuild.

- [ ] **Step 2: Cover it in the checksum manifest**

At `.github/workflows/_artifacts.yml:234`, add `kernel-usb` to `manifest.needs`:

```yaml
    needs: [kernel, kernel-usb, initramfs, mke2fs, nft, crun, sshd, erofs-parity, izba-windows]
```

Then find the `manifest` job's download steps (lines 236–255) and add a
`vmlinux-usb` download alongside the existing `vmlinux` one, using the same
`path:` those steps use, so `SHA256SUMS` covers it.

- [ ] **Step 3: Validate the YAML**

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/_artifacts.yml')); print('ok')"
```
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/_artifacts.yml
git commit -m "ci: build vmlinux-usb in the shared artifacts workflow

Phase 3 wired the USB kernel into the test path (e2e.yml) and never into the
shipping one, so no installer could ever contain it. Same build, same cache
key as e2e.yml so the two share cache entries rather than each spending 90
minutes.

Refs #189"
```

---

### Task 7: Package the USB kernel, and pin it so it cannot regress (#189, ship half)

**Files:**
- Modify: `packaging/build-deb.sh:3-22` (env contract) and `:27-39` (payload)
- Modify: `.github/workflows/devbuild.yml:119-142` (deb) and `:164-171` (windows)
- Modify: `.github/workflows/release.yml:143-166` (deb), `:188-195` (windows),
  `:291-298` (smoke assertion)
- Modify: `packaging/windows/izba.iss:4-11` (header comment)
- Modify: `hack/stage-izba-windows.sh:21,30`
- Modify + Test: `crates/izba-core/src/artifacts.rs`

**Interfaces:**
- Consumes: the `vmlinux-usb` workflow artifact from Task 6;
  `KernelVariant::image()` (`crates/izba-core/src/artifacts.rs:28-33`).
- Produces: `KernelVariant::ALL: [KernelVariant; 2]`; `vmlinux-usb` at
  `/usr/lib/izba/artifacts/vmlinux-usb` and `{app}\artifacts\vmlinux-usb`.

- [ ] **Step 1: Write the failing regression test**

This is the test the issue asks for: the thing that actually broke was a Rust
enum growing a variant without the packaging manifest learning about it. Append
to `mod tests` in `crates/izba-core/src/artifacts.rs`:

```rust
    #[test]
    fn every_kernel_variant_is_installed_by_the_debian_package() {
        // The defect this pins (#189): KernelVariant::Usb was added, artifacts
        // resolution learned to demand `vmlinux-usb`, and the packaging manifest
        // was never told — so a sandbox with grants hit a hard stop telling a
        // packaged user to go build a kernel. A test over the *enum* catches the
        // next variant too, which a hardcoded filename list would not.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let script = std::fs::read_to_string(root.join("packaging/build-deb.sh"))
            .expect("packaging/build-deb.sh must be readable from the crate");
        for v in KernelVariant::ALL {
            let dest = format!("usr/lib/izba/artifacts/{}", v.image());
            assert!(
                script.contains(&dest),
                "packaging/build-deb.sh installs no {dest}: a sandbox needing the \
                 {:?} kernel cannot start from an installed build",
                v
            );
        }
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p izba-core --lib artifacts`
Expected: FAIL — first on `no associated item named 'ALL'`, then (once `ALL`
exists) on the missing `usr/lib/izba/artifacts/vmlinux-usb`.

- [ ] **Step 3: Add `KernelVariant::ALL`**

In `crates/izba-core/src/artifacts.rs`, inside `impl KernelVariant`, above
`image()`:

```rust
    /// Every variant, so a consumer that must handle all of them (packaging
    /// checks, docs) cannot silently miss one added later.
    pub const ALL: [KernelVariant; 2] = [KernelVariant::Base, KernelVariant::Usb];
```

`image()` is currently `pub(crate)`; the test lives in the same crate, so no
visibility change is needed.

- [ ] **Step 4: Install it from the .deb builder**

In `packaging/build-deb.sh`, add to the required-env doc block (after the
`IZBA_VMLINUX` line at 7):

```bash
#   IZBA_VMLINUX_USB  USB-capable kernel image (vmlinux-usb)
```

Extend the required-vars check at line 14:

```bash
: "${IZBA_VMLINUX:?}" "${IZBA_VMLINUX_USB:?}" "${IZBA_INITRAMFS:?}" "${VERSION:?}"
```

and the existence loop at line 20:

```bash
for f in "$IZBA_BIN" "$IZBA_CH" "$IZBA_VIRTIOFSD" "$IZBA_VMLINUX" "$IZBA_VMLINUX_USB" "$IZBA_INITRAMFS"; do
```

Required, not optional, on purpose: a build that forgets the USB kernel must
fail loudly rather than ship a package whose USB feature hard-stops. Then the
payload — update the layout comment at line 12 and add the install after line 35:

```bash
#   /usr/lib/izba/artifacts/{vmlinux,vmlinux-usb,initramfs.cpio.gz}
```
```bash
install -D -m 0644 "$IZBA_VMLINUX_USB" "$STAGE/usr/lib/izba/artifacts/vmlinux-usb"
```

- [ ] **Step 5: Run to verify the test passes**

Run: `cargo test -p izba-core --lib artifacts`
Expected: PASS.

- [ ] **Step 6: Feed it from both workflows**

`.github/workflows/devbuild.yml`, in `package-deb`, after the `vmlinux` download
(lines 119–122) add the same step with `name: vmlinux-usb`, same `path: dl/art`;
and add to that job's `env:` block:

```yaml
            IZBA_VMLINUX_USB: ${{ github.workspace }}/dl/art/vmlinux-usb
```

In `package-windows`, after the `vmlinux` download (lines 164–167) add the same
step with `name: vmlinux-usb`, same `path: stage/artifacts`. No `.iss` change is
needed — `izba.iss:45` already globs `{#StageDir}\artifacts\*`.

Apply the identical two edits to `.github/workflows/release.yml`: deb downloads
at 143–146 and its `env:` block at 156–166; windows download at 188–191.

- [ ] **Step 7: Assert it in the release smoke job**

`.github/workflows/release.yml:291-298`, add to the payload list:

```yaml
              usr/lib/izba/artifacts/vmlinux-usb \
```

- [ ] **Step 8: Update the two remaining stale references**

`packaging/windows/izba.iss`, header comment line 10:

```
;   <StageDir>\artifacts\vmlinux
;   <StageDir>\artifacts\vmlinux-usb
```

`hack/stage-izba-windows.sh` — line 7's layout comment, the preflight loop at
line 21, and a copy after line 30. The USB kernel is a dev-loop convenience here,
so keep it non-fatal: leave line 21's loop as it is and add

```bash
[[ -f dist/vmlinux-usb ]] && cp dist/vmlinux-usb "$WIN_LOCALAPPDATA/izba/artifacts/vmlinux-usb"
```

after line 30, so staging still works for someone who has not built the variant.

- [ ] **Step 9: Validate + full gates**

```bash
bash -n packaging/build-deb.sh hack/stage-izba-windows.sh
for f in .github/workflows/devbuild.yml .github/workflows/release.yml; do
  python3 -c "import yaml,sys; yaml.safe_load(open('$f')); print('ok $f')"
done
cargo fmt && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings
```
Expected: all `ok` / PASS.

- [ ] **Step 10: Commit**

```bash
git add packaging/build-deb.sh packaging/windows/izba.iss hack/stage-izba-windows.sh \
        .github/workflows/devbuild.yml .github/workflows/release.yml \
        crates/izba-core/src/artifacts.rs
git commit -m "fix(packaging): ship the USB kernel, and pin it so it cannot regress

Every installer shipped the base kernel alone, so granting a device and
starting the sandbox hit a hard stop telling a packaged user to go build a
kernel. Ship vmlinux-usb in the .deb and the Windows installer (+~40 MiB
uncompressed; the alternative, an opt-in fetch, needs artifact hosting that
does not exist).

IZBA_VMLINUX_USB is required rather than optional so a build that forgets it
fails loudly instead of shipping a broken feature, and a test over
KernelVariant::ALL asserts the Debian payload covers every variant — the
next one added is caught the same way this one was missed.

Closes #189"
```

---

### Task 8: Make the grant-description *wiring* testable (#195, gap found in review)

Tasks 4 and 3 test `grant_description` and `describe` as pure functions, but
nothing asserts that `handle_usb_allow` and `handle_usb_list_devices` actually
call them — the two handlers reach `usbipd_state::probe()` directly, which spawns
a process and so cannot run in a unit test. That is precisely the gap issue #195
names ("a test that grants through `handle_usb_allow` and asserts a non-empty
description would pin it") and the same class of miss that let the original
defect survive a mutation-clean gate: **coverage of a predicate is not coverage
of its call site.**

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` — `DaemonDeps` (line 89),
  `DaemonDeps::production` (line 100), `test_deps` (line 1292),
  `handle_usb_list_devices` (line 875), `handle_usb_allow`
- Test: same file, `mod tests`

**Interfaces:**
- Consumes: `usbipd_state::{probe, UsbipdDevice}`; the existing `test_deps()`
  fixture and whatever helper builds a `Daemon` around it.
- Produces: `pub type UsbipdProbeFn = Box<dyn Fn() -> Option<Vec<UsbipdDevice>> +
  Send + Sync>` and a `pub usbipd_probe: UsbipdProbeFn` field on `DaemonDeps`,
  following the established `artifacts: ArtifactsFn` / `resolve_image:
  ResolveImageFn` seam pattern exactly.

- [ ] **Step 1: Write the failing wiring test**

Add to `mod tests` in `crates/izba-core/src/daemon/server.rs`. Build a `Daemon`
whose `deps.usbipd_probe` returns a fixed table, drive the **real**
`handle_usb_allow`, then read the grant back off disk:

```rust
    #[test]
    fn granting_through_the_rpc_stores_the_name_usbipd_reported() {
        // The pure `grant_description` tests above prove the match rule. This one
        // proves the handler actually calls it — the defect in #195 was a live
        // wire that went nowhere, and a predicate test could never have seen it.
        let (_tmp, paths) = /* the module's existing paths+sandbox fixture */;
        let mut deps = test_deps();
        deps.usbipd_probe = Box::new(|| {
            Some(vec![crate::usb::usbipd_state::UsbipdDevice {
                busid: "12-4".to_string(),
                id: crate::usb::DeviceId { vid: 0x303a, pid: 0x1001 },
                description: "USB JTAG/serial debug unit".to_string(),
                bound: true,
                attached: false,
            }])
        });
        let d = /* build the Arc<Daemon> the other USB handler tests build */;

        handle_usb_allow(&d, "web".to_string(), "303a:1001".to_string(), None)
            .expect("grant should succeed");

        let cfg = /* read the sandbox config back off disk, as grant_on_disk's
                     readers do */;
        assert_eq!(
            cfg.usb.devices[0].description, "USB JTAG/serial debug unit",
            "the handler must record the name, not an empty string"
        );
    }
```

Fill the three `/* … */` slots from the neighbouring USB handler tests in that
module — reuse their fixtures verbatim rather than inventing new ones. The
sandbox must exist and an upstream must be configured, or `handle_usb_allow`
bails before reaching the description (see `usb_settings_or_refuse`).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p izba-core --lib daemon::server::tests::granting_through_the_rpc`
Expected: FAIL — `no field 'usbipd_probe' on type 'DaemonDeps'`.

- [ ] **Step 3: Add the seam**

Beside the existing `ArtifactsFn` / `ResolveImageFn` type aliases, add:

```rust
/// Injectable usbipd probe. Production spawns `usbipd.exe`; tests hand over a
/// fixed table, which is the only way the handlers' *use* of it is observable.
pub type UsbipdProbeFn = Box<dyn Fn() -> Option<Vec<crate::usb::usbipd_state::UsbipdDevice>> + Send + Sync>;
```

Add `pub usbipd_probe: UsbipdProbeFn,` to `DaemonDeps`; in `production()` set
`usbipd_probe: Box::new(crate::usb::usbipd_state::probe),`; in `test_deps()` set
`usbipd_probe: Box::new(|| None),` — the honest default for a host with no local
usbipd, and it keeps every existing test's behaviour unchanged.

- [ ] **Step 4: Route both call sites through it**

In `handle_usb_allow`, replace `crate::usb::usbipd_state::probe().as_deref()`
with `(d.deps.usbipd_probe)().as_deref()`.

In `handle_usb_list_devices`, replace `crate::usb::usbipd_state::probe()` with
`(d.deps.usbipd_probe)()`.

- [ ] **Step 5: Add the listing wiring test too**

Same seam, same reason — `list_devices`' enrichment is only reachable in
production through this handler:

```rust
    #[test]
    fn the_listing_names_devices_from_the_probe_the_daemon_was_given() {
        // Pins handle_usb_list_devices → list_devices → describe. Without the
        // seam this path could only be exercised by a machine that happens to
        // have usbipd installed, i.e. never in CI.
    }
```

Write it only if the module already has a fixture that lets
`handle_usb_list_devices` reach `inventory::fetch` without a real socket (it
dials the upstream, so it may not be reachable in a unit test). **If it is not
reachable without binding a socket, skip this step and say so in your report** —
the constraint that tests never bind wins over the extra coverage.

- [ ] **Step 6: Run the gates and commit**

```bash
cargo test --workspace && cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
git add crates/izba-core/src/daemon/server.rs
git commit -m "test(core): pin the grant description to the handler, not just the rule

Tasks 4's tests prove the match rule; nothing proved handle_usb_allow calls
it, and an untested call site is exactly how #195 survived a mutation-clean
gate in the first place. Inject the usbipd probe through DaemonDeps like the
artifacts and image seams, so a grant made through the real RPC can be read
back off disk and asserted.

Refs #195"
```

---

## Self-Review

**1. Spec coverage.** Issue → task: #187 → Task 1. #188 → Task 2. #190 → Task 3.
#195 → Tasks 4 (grant record) + 5 (consent banner). #189 → Tasks 6 (build) + 7
(ship + regression test). Deliberately out of scope, with reasons: #191 (USB e2e
covers only Linux/KVM with a fake usbipd — a genuine gap, but it is a new test
matrix, not a defect in this PR's code); #192/#193/#194 (not USB — they surfaced
during USB testing but live in the app's lifecycle and Overview surfaces); #196
(needs crun-namespace work across four lifecycle states, and the reporter
explicitly said dropping it is acceptable if it gets messy).

**2. Placeholder scan.** Three steps say "check the existing helper's signature
first and adjust" — Task 3 Step 4 (`upstream_device`), Task 4 Step 6
(`FakeDaemon`'s device-list field), Task 5 Step 1 (`dev`). These are real
lookups against named symbols at named lines, not deferred decisions; the
behaviour asserted is fully specified either way.

**3. Type consistency.** `describe<'a>(&'a [UsbipdDevice], &str, DeviceId) ->
Option<&'a str>` is defined in Task 3 and consumed by Tasks 3 and 4.
`grant_description(Option<&[UsbipdDevice]>, DeviceId, Option<&str>) -> String`
is defined and consumed in Task 4 — note `probe()` returns
`Option<Vec<UsbipdDevice>>`, so the call site uses `.as_deref()`.
`description_of<'a>(&'a [UsbDeviceInfo], &str) -> &'a str` is Task 5 only.
`KernelVariant::ALL` is defined in Task 7 Step 3 and consumed by its own test.

**4. Ordering.** 1 → 2 (Task 2's predicate calls Task 1's), 3 → 4 (Task 4 calls
`describe`), 6 → 7 (Task 7 downloads Task 6's artifact). Task 5 depends on
nothing structural. Tasks 6–7 are independent of 1–5 and may run in parallel.
