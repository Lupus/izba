# Fix #134: supervisor tick must not tear down a booting sandbox's egress plane

## Context

Issue #134 (sibling of the PR #133 registry clobber, found in the same
root-cause analysis): `handle_start` binds the vsock-1027 egress listener
BEFORE launching the VM (`d.egress.ensure_listening`, server.rs) so the guest
can dial izbad during boot, but `state.json` is only written AFTER the boot
health check passes — so for the entire boot window (seconds; up to
IZBA_BOOT_TIMEOUT_SECS) the disk scan honestly reports the sandbox `Stopped`.
`supervisor::tick`'s side-effect loop then runs `relays.stop_all(name)` +
`egress.stop(paths, name)` off that stale-but-honest snapshot, killing the
listener the booting guest needs. It heals ≤1 tick after boot (the tick's
else-branch re-ensures), but guest DNS/TCP egress dials fail meanwhile.
The PR #133 registry generation guard cannot cover this: the side effects run
off the scan `infos` before `replace_all`, and the boot spans multiple ticks
so a single mutation stamp can't shield it.

## Global constraints

- In-memory only; NO wire/proto changes, no `DAEMON_PROTO_VERSION` bump.
- Unit tests never bind listeners unconditionally — any test that must bind
  (unix or TCP) runtime-skips on `PermissionDenied` (see
  `full_connect_via_listener` in `crates/izba-core/src/vsock.rs`).
- All six workspace gates green; conventional commits; TDD (failing test
  first).
- The fix must close the WHOLE boot window, not one tick — so it must be an
  explicit starts-in-flight set consulted by the tick, not a generation stamp.

## Task 1: starts-in-flight guard

**Files:** `crates/izba-core/src/daemon/supervisor.rs` (new type + tick
param + tests), `crates/izba-core/src/daemon/server.rs` (Daemon field +
handle_start guard + supervisor-thread call site).

**Design:**

- New type in `supervisor.rs`:
  ```rust
  /// Sandbox names with a `Start` in flight. `handle_start` holds a guard for
  /// the whole listener-bind → boot → relay-republish window; the supervisor
  /// tick leaves those sandboxes' relays/egress alone even though the disk
  /// scan honestly reports them Stopped until state.json lands post-boot.
  #[derive(Default)]
  pub struct StartsInFlight(Mutex<HashSet<String>>);
  impl StartsInFlight {
      pub fn new() -> Self;
      /// Marks `name` in flight; the returned guard un-marks on drop.
      pub fn begin(&self, name: &str) -> StartGuard<'_>;
      pub fn contains(&self, name: &str) -> bool;
  }
  pub struct StartGuard<'a> { ... }  // Drop removes the name
  ```
- `tick(...)` gains a `starting: &StartsInFlight` parameter. In the
  side-effect loop, the `Liveness::Stopped` arm becomes: skip
  `relays.stop_all` + `egress.stop` when `starting.contains(&info.name)`
  (with a comment tying it to the boot window / #134). The else-branch and
  `replace_all` are unchanged.
- `Daemon` (server.rs) gains `starting: StartsInFlight`; the supervisor
  thread's `tick(...)` call passes `&d.starting`; `handle_start` takes
  `let _start_guard = d.starting.begin(&name);` immediately before
  `d.egress.ensure_listening(...)` so the guard covers bind → boot →
  relay republish → registry set (it drops when the handler returns, on both
  success and error paths — the error path's own `egress.stop` runs while
  the guard is still held, which is fine: the guard only gates the TICK's
  stops, not the handler's own).
- Update the module doc header ("stop relays of stopped sandboxes") to
  mention the in-flight exemption.

**Tests (failing first, in supervisor.rs `mod tests`):**

1. `tick_spares_egress_and_relays_of_starting_sandbox` — create sandbox
   `boot` with NO state.json (disk says Stopped); `egress.ensure_listening`
   + `relays.publish` a rule (BOTH runtime-skip the test on
   `PermissionDenied`, following the vsock.rs pattern); mark
   `let _g = starting.begin("boot")`; run `tick`; assert
   `egress.listening("boot")` still true AND `relays.active("boot")` still
   non-empty.
2. `tick_stops_egress_and_relays_of_genuinely_stopped_sandbox` — same setup
   WITHOUT the guard (or after dropping it); run `tick`; assert
   `egress.listening("boot")` false and `relays.active("boot")` empty.
   (Negative control; kills the condition-negation mutant.)
3. `start_guard_unmarks_on_drop` — pure StartsInFlight unit test: contains
   true inside `begin` scope, false after drop; two concurrent guards on
   different names don't interfere.
4. Existing `tick_reflects_disk_state` updated for the new signature (pass an
   empty `StartsInFlight`).

**Verify:** `cargo test -p izba-core daemon::supervisor` then full crate +
clippy + fmt.

## Final

- Six gates; real-VM sanity: `IZBA_INTEGRATION=1 cargo test -p izba-cli
  --test daemon_e2e -- --test-threads=1` on local KVM.
- Push, draft PR "Closes #134", greploop, Sonar, e2e dispatch on the branch.
