# Persistent-Volume Durability on `rm --force` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix issue #78 — `izba rm --force` on a running sandbox with named persistent volumes silently loses unsynced guest writes; make the force path best-effort durable (guest sync before kill) and warn loudly about the residual risk.

**Architecture:** Root cause: graceful stop sends `Request::Shutdown` over vsock 1025 and the guest's PID 1 runs `nix::unistd::sync()` before `reboot(RB_POWER_OFF)` (`crates/izba-init/src/main.rs:266`); the force-rm path calls `stop_locked(…, Duration::ZERO, graceful=false)`, which skips the Shutdown RPC entirely and SIGKILLs the VMM — dirty ext4 page-cache buffers for the volume disks are dropped with the VM. The fix is host-side and platform-independent (the same `stop_locked` path serves Cloud Hypervisor and OpenVMM; neither driver's `kill()` is on this path — `procmgr::kill_pid` on `state.vmm_pid` is): (a) when the sandbox's config declares ≥1 named persistent volume, `remove(force)` attempts the existing graceful Shutdown with a short bounded grace before escalation; (b) `izba rm --force` prints a ⚠️ stderr warning (via the existing `Inspect` RPC — `SandboxDetail` already carries `status` + `volumes`) because the sync is best-effort: a hung guest is still killed when the grace expires. Sandboxes without persistent volumes keep today's instant kill (rw.img and ephemeral volumes die with the sandbox anyway — nothing durable to lose).

**Tech Stack:** Rust; existing test seams `fake_connector`/`count_shutdowns` (`crates/izba-core/src/testutil.rs`), env-gated KVM integration suite (`crates/izba-core/tests/integration.rs`).

## Global Constraints

- NO `DAEMON_PROTO_VERSION` bump and NO new `izba_proto::Request` / daemon wire variants — the fix reuses `Request::Shutdown` and `DaemonRequest::Inspect` exactly as they exist today.
- The guest RPC in the force path must remain best-effort: a hung, wedged, or unreachable guest MUST still be killed and removed within the bounded grace — `rm --force` may never hang or fail because of the durability attempt.
- Unit tests never bind unix/vsock listeners (sandbox EPERM) — use the existing `fake_connector`/`hanging_connector` socketpair fakes only.
- CLI warning style: `eprintln!("⚠️  WARNING: …")` exactly like `crates/izba-cli/src/commands/start.rs:40-47`; warnings go to stderr, never stdout.
- Gates before every commit: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check` (the cross/musl gates run at branch level; no public izba-core/izba-proto types change in this plan, so the app gate is not triggered).
- Conventional commits (`fix(core): …`, `fix(cli): …`, `test(core): …`).
- Root cause must be documented in a code comment at the fix site (issue #78 acceptance criterion).

---

### Task 1: Durable force-remove in izba-core

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (const near `CONTROL_RPC_TIMEOUT` ~line 30; helper near `has_persistent_volumes` call site; `remove()` ~line 1195; tests module after `rm_force_kills_then_deletes` ~line 2425)

**Interfaces:**
- Consumes: `stop_locked(paths, name, connector, timeout, graceful)` (unchanged), `load_json::<SandboxConfig>`, `VolumeSpec::is_persistent()`, test seams `fake_connector`/`count_shutdowns`/`spawn_sleep`/`write_state`/`wait_dead`/`opts`.
- Produces: `remove()` behavior change only — signature unchanged; private `fn has_persistent_volumes(paths: &Paths, name: &str) -> bool`; private `const FORCE_RM_SYNC_GRACE: Duration`.

- [ ] **Step 1: Write the failing tests**

Append to the tests module in `crates/izba-core/src/sandbox.rs`, right after `rm_force_kills_then_deletes` (~line 2425). Model: the existing `stop_graceful` / `rm_force_kills_then_deletes` tests visible just above.

```rust
    /// Returns `opts(ws)` extended with one named persistent volume, the
    /// shape a `--volume data:/data:64M` create would persist.
    fn opts_with_persistent_volume(workspace: &Path) -> CreateOpts {
        let mut o = opts(workspace);
        o.volumes.push(crate::volume::VolumeSpec {
            name: Some("data".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        });
        o
    }

    #[test]
    fn rm_force_syncs_guest_when_persistent_volume_attached() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts_with_persistent_volume(&ws)).unwrap();

        // Real short-lived child stands in for the VMM; the fake guest kills
        // it on Shutdown, so the force path observes a graceful death well
        // inside FORCE_RM_SYNC_GRACE.
        let sleep_id = spawn_sleep(dir.path());
        write_state(&paths, "web", sleep_id.clone());

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log.clone(), Some(sleep_id.clone()));
        remove(&paths, "web", &conn, true).unwrap();

        assert_eq!(
            count_shutdowns(&log),
            1,
            "force-rm with a persistent volume must attempt the guest sync"
        );
        assert!(!paths.sandbox_dir("web").exists(), "dir must be gone");
        assert!(wait_dead(&sleep_id), "vmm stand-in must be dead");
        assert!(
            paths.volume_image("data").exists(),
            "persistent volume image must survive rm"
        );
    }

    #[test]
    fn rm_force_stays_abrupt_without_persistent_volumes() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let sleep_id = spawn_sleep(dir.path());
        write_state(&paths, "web", sleep_id.clone());

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log.clone(), None);
        remove(&paths, "web", &conn, true).unwrap();

        assert_eq!(
            count_shutdowns(&log),
            0,
            "nothing durable is attached — keep the instant-kill semantics"
        );
        assert!(!paths.sandbox_dir("web").exists(), "dir must be gone");
        assert!(wait_dead(&sleep_id), "force remove must kill the vmm");
    }

    #[test]
    fn rm_force_escalates_when_guest_ignores_shutdown() {
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts_with_persistent_volume(&ws)).unwrap();

        let sleep_id = spawn_sleep(dir.path());
        write_state(&paths, "web", sleep_id.clone());

        // Guest acks Shutdown but never powers off → after FORCE_RM_SYNC_GRACE
        // the removal must escalate to SIGKILL and still succeed. (This test
        // deliberately waits out the full grace — ~5s wall clock.)
        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log.clone(), None);
        remove(&paths, "web", &conn, true).unwrap();

        assert_eq!(count_shutdowns(&log), 1, "sync must have been attempted");
        assert!(!paths.sandbox_dir("web").exists(), "dir must be gone");
        assert!(wait_dead(&sleep_id), "escalation must kill the vmm");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core rm_force -- --nocapture`
Expected: `rm_force_syncs_guest_when_persistent_volume_attached` FAILS (count_shutdowns is 0, not 1) and `rm_force_escalates_when_guest_ignores_shutdown` FAILS (count 0, not 1); `rm_force_stays_abrupt_without_persistent_volumes` and the pre-existing `rm_force_kills_then_deletes` PASS.

- [ ] **Step 3: Implement the fix**

In `crates/izba-core/src/sandbox.rs`, next to `CONTROL_RPC_TIMEOUT` (~line 30) add:

```rust
/// Grace granted to a *forced* removal of a running sandbox that has named
/// persistent volumes attached (#78). Root cause of the data loss this
/// prevents: a bare SIGKILL of the VMM drops dirty ext4 buffers still in the
/// guest page cache, silently losing recent writes to the volume image; the
/// graceful path is durable only because init syncs before power-off
/// (`izba-init/src/main.rs`, `Request::Shutdown` → `sync()` → RB_POWER_OFF).
/// So the force path sends the same Shutdown and waits this long before
/// escalating. Best-effort by design: a hung guest is still killed when the
/// grace expires (the CLI warns about that residual risk).
const FORCE_RM_SYNC_GRACE: Duration = Duration::from_secs(5);
```

Above `remove()` (~line 1195) add:

```rust
/// Whether the sandbox's config declares at least one named persistent
/// volume. Unreadable or missing config reads as "no" — force-remove of a
/// corrupt sandbox must not be blocked by a durability nicety.
fn has_persistent_volumes(paths: &Paths, name: &str) -> bool {
    load_json::<SandboxConfig>(&paths.sandbox_dir(name).join(CONFIG_FILE))
        .ok()
        .flatten()
        .is_some_and(|c| c.volumes.iter().any(|v| v.is_persistent()))
}
```

In `remove()`, replace the force arm (currently `_ => stop_locked(paths, name, connector, Duration::ZERO, false)?,` at ~line 1212) with:

```rust
            _ => {
                // #78: killing a live guest outright loses page-cache writes
                // not yet flushed to the volume images. With persistent
                // volumes attached, try the graceful Shutdown (guest syncs
                // before power-off) under a short grace before escalating.
                let (grace, graceful) = if has_persistent_volumes(paths, name) {
                    (FORCE_RM_SYNC_GRACE, true)
                } else {
                    (Duration::ZERO, false)
                };
                stop_locked(paths, name, connector, grace, graceful)?
            }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-core rm_force`
Expected: all 4 `rm_force*` tests PASS (the escalation one takes ~5s).

- [ ] **Step 5: Run the module + gates**

Run: `cargo test -p izba-core sandbox && cargo clippy -p izba-core --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS, no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/sandbox.rs
git commit -m "fix(core): sync guest before killing a force-removed sandbox with persistent volumes

rm --force used stop_locked(graceful=false), skipping the Shutdown RPC that
makes graceful stop durable (init syncs the page cache before power-off), so
dirty ext4 buffers on named persistent volumes were silently dropped. With
persistent volumes attached, the force path now attempts the same Shutdown
under a bounded FORCE_RM_SYNC_GRACE before SIGKILL escalation; sandboxes
without persistent volumes keep the instant kill. Closes the core half of #78."
```

---

### Task 2: Loud CLI warning on `rm --force` of a running volume-holder

**Files:**
- Modify: `crates/izba-cli/src/commands/rm.rs`
- Modify: `crates/izba-cli/src/main.rs:239-247` (clap `--force` help text)

**Interfaces:**
- Consumes: `DaemonRequest::Inspect { name }` → `DaemonResponse::Inspect(SandboxDetail)` (fields `status: String`, `volumes: Vec<VolumeSpec>`); `VolumeSpec::is_persistent()`.
- Produces: private `fn force_rm_warning(detail: &SandboxDetail) -> Option<String>` in `rm.rs` (unit-tested pure helper); no signature changes to `run()`.

- [ ] **Step 1: Write the failing tests**

Append a tests module to `crates/izba-cli/src/commands/rm.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::daemon::proto::SandboxDetail;
    use izba_core::volume::VolumeSpec;

    fn detail(status: &str, volumes: Vec<VolumeSpec>) -> SandboxDetail {
        SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:22.04".into(),
            image_digest: "sha256:abc".into(),
            cpus: 2,
            mem_mb: 1024,
            workspace: "/ws".into(),
            status: status.into(),
            ports: Vec::new(),
            volumes,
            confinement: None,
            container: None,
        }
    }

    fn pvol(name: &str) -> VolumeSpec {
        VolumeSpec {
            name: Some(name.into()),
            guest_path: format!("/{name}").into(),
            size_bytes: 64 << 20,
            eph_id: None,
        }
    }

    fn evol() -> VolumeSpec {
        VolumeSpec {
            name: None,
            guest_path: "/eph".into(),
            size_bytes: 64 << 20,
            eph_id: Some(1),
        }
    }

    #[test]
    fn warns_when_running_with_persistent_volumes() {
        let w = force_rm_warning(&detail("running", vec![evol(), pvol("data")]))
            .expect("must warn");
        assert!(w.contains("⚠️"), "loud-warning marker missing: {w}");
        assert!(w.contains("'data'"), "must name the volume: {w}");
        assert!(
            w.contains("izba stop"),
            "must point at the durable alternative: {w}"
        );
    }

    #[test]
    fn warns_for_degraded_sandboxes_too() {
        // Anything not fully stopped still holds a live-ish VMM whose guest
        // cache may be dirty — same risk, same warning.
        assert!(force_rm_warning(&detail("degraded (vmm dead)", vec![pvol("data")])).is_some());
    }

    #[test]
    fn silent_when_stopped() {
        assert!(force_rm_warning(&detail("stopped", vec![pvol("data")])).is_none());
    }

    #[test]
    fn silent_without_persistent_volumes() {
        assert!(force_rm_warning(&detail("running", vec![evol()])).is_none());
        assert!(force_rm_warning(&detail("running", Vec::new())).is_none());
    }

    #[test]
    fn names_every_persistent_volume() {
        let w = force_rm_warning(&detail("running", vec![pvol("data"), pvol("cache")]))
            .expect("must warn");
        assert!(w.contains("'data'") && w.contains("'cache'"), "got: {w}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-cli rm::tests`
Expected: FAIL to compile — `force_rm_warning` not defined.

- [ ] **Step 3: Implement the helper + wiring**

In `crates/izba-cli/src/commands/rm.rs`, add above `run()` (new imports: `use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxDetail};`):

```rust
/// The #78 residual-risk warning: force-removing a not-stopped sandbox that
/// holds named persistent volumes triggers only a *best-effort* guest sync —
/// a hung guest is still killed, losing unsynced writes. Say so loudly.
fn force_rm_warning(detail: &SandboxDetail) -> Option<String> {
    if detail.status == "stopped" {
        return None;
    }
    let names: Vec<String> = detail
        .volumes
        .iter()
        .filter(|v| v.is_persistent())
        .filter_map(|v| v.name.as_ref())
        .map(|n| format!("'{n}'"))
        .collect();
    if names.is_empty() {
        return None;
    }
    Some(format!(
        "⚠️  WARNING: removing '{}' while it is running — a best-effort guest sync \
         of persistent volume(s) {} is attempted before the VM is killed, but writes \
         from the last moments may be lost if the guest is unresponsive. Prefer \
         `izba stop {}` first for guaranteed durability.",
        detail.name,
        names.join(", "),
        detail.name
    ))
}
```

In `run()`, after `let mut client = DaemonClient::connect(paths)?;` and before the `Rm` request, insert:

```rust
    // Best-effort pre-flight: warn about the force-removal durability gap.
    // Any Inspect failure (unknown sandbox, stale daemon) is ignored — the
    // authoritative outcome comes from the Rm RPC below.
    if force {
        if let Ok(DaemonResponse::Inspect(detail)) =
            client.request(&DaemonRequest::Inspect { name: name.to_string() }, &mut |_| {})
        {
            if let Some(warning) = force_rm_warning(&detail) {
                eprintln!("{warning}");
            }
        }
    }
```

In `crates/izba-cli/src/main.rs` update the `--force` help (keep it one line):

```rust
        /// Stop and remove even if running (best-effort guest sync for
        /// persistent volumes; unsynced writes may be lost)
        #[arg(long)]
        force: bool,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p izba-cli rm::tests`
Expected: 5 tests PASS.

- [ ] **Step 5: Gates**

Run: `cargo test -p izba-cli && cargo clippy -p izba-cli --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-cli/src/commands/rm.rs crates/izba-cli/src/main.rs
git commit -m "fix(cli): warn that rm --force of a running volume-holder is only best-effort durable

The core fix syncs the guest before the kill, but a hung guest is still
killed when the grace expires. Inspect the target before a forced Rm and
print the ⚠️ residual-risk warning (naming each persistent volume and the
durable stop-first alternative) so the loss window is never silent. CLI
half of #78."
```

---

### Task 3: KVM integration regression test (real-VM durability proof)

**Files:**
- Modify: `crates/izba-core/tests/integration.rs` (new test after `volumes_persist_reattach_and_prune`, ~line 1060)

**Interfaces:**
- Consumes: existing harness helpers used by `volumes_persist_reattach_and_prune` (visible at integration.rs:951-1044): `want()`, `TestBox::new()`, `tb.workspace`, `create_sandbox_with_volumes`, `start_sandbox`, `exec_ok`, `boot_diag`, `sandbox::default_connector`, `sandbox::remove`, `tb.paths.volume_image`.
- Produces: nothing consumed later.

- [ ] **Step 1: Write the test**

The write deliberately has **no `sync`** (contrast integration.rs:985) and the sandbox is **still running** at remove time (contrast integration.rs:1002-1004 which stops first) — this is exactly the #78 reproduction, now expected to pass.

```rust
#[test]
fn volume_survives_force_rm_of_running_sandbox() {
    // #78 regression: rm --force of a RUNNING sandbox must not lose unsynced
    // persistent-volume writes. The force path now sends the guest Shutdown
    // (init syncs the page cache before power-off) under a bounded grace.
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("fvol");
    create_sandbox_with_volumes(
        &env,
        &mut tb,
        "fvol",
        &ws,
        vec![izba_core::volume::VolumeSpec {
            name: Some("fdata".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        }],
    );
    if let Err(e) = start_sandbox(&env, &tb, "fvol") {
        panic!(
            "boot of 'fvol' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "fvol")
        );
    }

    // Write WITHOUT an explicit sync: the sentinel sits in the guest page
    // cache, exactly the state the old abrupt kill lost.
    exec_ok(&tb.paths, "fvol", &["sh", "-c", "echo forced > /data/s"]);

    // Force-remove while still running.
    let connector = sandbox::default_connector();
    sandbox::remove(&tb.paths, "fvol", &connector, true).expect("force rm running fvol");
    tb.names.retain(|n| n != "fvol");
    assert!(
        tb.paths.volume_image("fdata").exists(),
        "persistent volume must survive force rm"
    );

    // Re-attach in a fresh sandbox: the unsynced write must have survived.
    let ws2 = tb.workspace("fvol2");
    create_sandbox_with_volumes(
        &env,
        &mut tb,
        "fvol2",
        &ws2,
        vec![izba_core::volume::VolumeSpec {
            name: Some("fdata".into()),
            guest_path: "/data".into(),
            size_bytes: 64 << 20,
            eph_id: None,
        }],
    );
    if let Err(e) = start_sandbox(&env, &tb, "fvol2") {
        panic!(
            "boot of 'fvol2' failed: {e:#}\nconsole tail:\n{}",
            boot_diag(&tb.paths, "fvol2")
        );
    }
    assert_eq!(
        exec_ok(&tb.paths, "fvol2", &["cat", "/data/s"]),
        "forced\n",
        "write made just before rm --force of the running sandbox must survive"
    );
}
```

- [ ] **Step 2: Verify it compiles and self-skips without KVM env**

Run: `cargo test -p izba-core --test integration volume_survives_force_rm -- --test-threads=1`
Expected: PASS (self-skips via `want()` returning None when `IZBA_INTEGRATION` unset).

- [ ] **Step 3: Run for real under KVM (unsandboxed Bash, this host has working /dev/kvm)**

Run:
```bash
IZBA_INTEGRATION=1 \
IZBA_KERNEL=$HOME/.local/share/izba/artifacts/vmlinux \
IZBA_INITRAMFS=$HOME/.local/share/izba/artifacts/initramfs.cpio.gz \
IZBA_TEST_CACHE=$HOME/.cache/izba-itest \
cargo test -p izba-core --test integration volume_survives_force_rm -- --test-threads=1 --nocapture
```
Expected: PASS. Also re-run `volumes_persist_reattach_and_prune` the same way — must still PASS (no-regression acceptance criterion).

- [ ] **Step 4: Gates**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): real-VM regression for #78 — unsynced volume write survives rm --force

Writes a sentinel with no explicit sync, force-removes the sandbox while it
is still running, re-attaches the volume in a fresh sandbox, and asserts the
write survived. Complements volumes_persist_reattach_and_prune, which stops
gracefully first and so never exercised the abrupt path."
```

---

## Windows / OpenVMM coverage note (for the PR body, no task)

The fix lives entirely in the shared host path (`sandbox::remove` → `stop_locked`); neither VMM driver's `kill()` is involved (teardown is `procmgr::kill_pid` on `state.vmm_pid` on both platforms). The Task 1 unit tests run natively on Windows in CI's `cargo test (windows)` shards (the fake connector is a `UdsStream::pair`, portable), so the WHP teardown path is covered by the same tests. Additionally dispatch `e2e.yml` on the branch for the full real-VM legs.
