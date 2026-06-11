# izba `exec -it` TTY Test Harness — Design

**Status:** approved (2026-06-11)
**Author:** brainstormed with Claude; approved by Konstantin Olkhovskiy

## 1. Problem

izba's interactive terminal path (`izba exec -it`) has a manual operator
checklist that must be re-run by hand on every change, on both Linux and
Windows. The checklist (verbatim from
`docs/superpowers/plans/2026-06-10-izba-windows-port-p2.md:336-341`):

- lands in a guest `/bin/sh -l` prompt (PTY allocated, raw mode on)
- arrow keys / line editing work (VT input)
- `vi /workspace/x` renders fullscreen and resizes when the window resizes
- Ctrl-C interrupts a `sleep 100` in the guest without killing izba.exe
- exiting the shell restores the console (no garbled mode)

Nothing automated covers this today. The existing integration tests
(`tty_resize`, `exit_codes` in `crates/izba-core/tests/integration.rs`) drive
exec at the **library level** — they construct `Request` frames and talk to a
real guest over vsock, but they never launch the compiled `izba` binary through
a real terminal. The **host terminal layer** — `RawGuard`, `console_out`/
`console_err`, the resize watcher, the pump threads in
`crates/izba-cli/src/terminal.rs` + `crates/izba-cli/src/commands/exec.rs` — has
**zero automated coverage**. That layer is exactly where the recent
Windows-console vim-hang bug (commit `21fbd31`) lived.

**Goal:** replace the manual checklist with declarative `cargo test` cases that
drive the real `izba` binary through a real pseudo-terminal (Unix PTY on Linux,
ConPTY on Windows), send keystrokes/resizes, and assert on the rendered screen —
so an agent or CI gets pass/fail per checklist item instead of a human clicking.

## 2. Non-goals

- Not an interactive agent-driving JSON service (no `ht`-style live protocol).
  Chosen interface is deterministic `cargo test` cases. A future JSON driver can
  reuse the harness core, but it is out of scope here.
- Not a replacement for the existing library-level integration tests; this is
  additive coverage of the compiled binary's terminal behavior.
- Not a new VMM or guest. The scripted guest (below) replays bytes; it is not a
  real OCI workload.

## 3. Tooling decision

Cross-platform foundation, both confirmed ConPTY-capable / OS-agnostic:

- **`portable-pty`** (wezterm crate, ~0.9): one API over Unix PTY and Windows
  **ConPTY** (`CreatePseudoConsole`/`ResizePseudoConsole`). `native_pty_system()`
  → `openpty(PtySize)` → `PtyPair { master, slave }`; `slave.spawn_command(
  CommandBuilder)` → `Box<dyn Child>`; `master.try_clone_reader()`,
  `master.take_writer()`, `master.resize(PtySize)`.
- **`vt100`** (~0.16): parses the master byte-stream into a screen-cell grid.
  `Parser::new(rows, cols, scrollback)` + `parser.process(&bytes)`;
  `screen.contents()` (whole-grid text), `screen.cell(row, col)`,
  `screen.cursor_position()`, `screen.contents_diff(prev)` (quiescence /
  change detection).

Both are added as **dev-dependencies only** — no shipping crate gains a runtime
dependency.

Rejected for the core: `ht`, `agent-tui` (Unix-only, no ConPTY); `rexpect`,
`pexpect`, `tmux` (Unix-only or line-oriented); `expectrl` (cross-platform but
line/regex-oriented, no screen grid). They remain useful design references.

### 3.1 The load-bearing Windows rule

ConPTY renders asynchronously and runs its own reflow. Therefore:

- **Always assert on the parsed `vt100` grid, never on raw master bytes.**
- **Poll-until-quiescent** before snapshotting: read until `contents_diff`
  reports no change for a short idle window (the `wait_stable` gate), rather than
  asserting on a single read. This is the #1 source of cross-platform flake.
- **Debounce resizes** and re-probe the size after resizing.
- Windows runs require build ≥ 10.0.17763 (1809). Prefer text-presence / cell
  assertions over exact full-screen byte-snapshot equality across OSes.

## 4. Architecture

The harness drives the **real compiled `izba` binary** through a real
PTY/ConPTY. What the binary connects to on the guest side is swappable — that
swap is the two tiers.

```
        ┌──────────────────── the thing under test ────────────────────┐
        │  real `izba` binary  (env!("CARGO_BIN_EXE_izba"))            │
        │   └─ host terminal layer: RawGuard · console_out ·          │
        │      resize-watcher · pump threads                          │
        └───────────▲──────────────────────────────────┬─────────────┘
   PTY/ConPTY master│ keystrokes, resize                │ vsock handshake +
   (harness owns)   │ screen bytes                      │ framed RPC over UDS
                    │                                   ▼
        ┌───────────┴───────────┐        ┌──────────── guest backend ───────────┐
        │ TerminalSession       │        │ Tier 1: scripted guest (no VM)        │
        │ portable-pty + vt100  │        │ Tier 2: real sandbox (KVM / OpenVMM)  │
        └───────────────────────┘        └───────────────────────────────────────┘
```

### 4.1 New crate: `crates/izba-ttytest/`

A dev/test-support library crate. Depends on `izba-proto` (wire types) and, for
the scripted guest's socket/handshake, mirrors the `UnixListener`/`uds_windows`
usage already in `izba-core`. It does **not** depend on `izba-core` to avoid a
cycle; the small amount of path/state-file knowledge it needs is duplicated
deliberately and documented at the site (it is test code shadowing a couple of
on-disk contracts).

The crate exposes three modules:

**`harness.rs` — `TerminalSession`** (cross-platform core, ~200 LOC)
- Opens a PTY/ConPTY via `portable-pty`, spawns a configured `izba` command on
  the slave, owns the master reader+writer and a background thread that feeds
  master bytes into a `vt100::Parser` behind a `Mutex`.
- Public API:
  - `TerminalSession::spawn(cmd: CommandBuilder, size: PtySize) -> Result<Self>`
  - `send_keys(&self, s: &str)` / `send_bytes(&self, b: &[u8])`
  - `resize(&self, cols: u16, rows: u16)`
  - `wait_for_text(&self, needle: &str, timeout: Duration) -> Result<()>`
  - `wait_stable(&self, idle: Duration, timeout: Duration)` — the ConPTY
    quiescence gate (no `contents_diff` change for `idle`)
  - `screen_contains(&self, needle: &str) -> bool`
  - `cell(&self, row: u16, col: u16) -> Option<String>`
  - `wait_exit(&self, timeout: Duration) -> Result<ExitOutcome>` where
    `ExitOutcome { code: Option<i32> }`
  - `is_child_alive(&self) -> bool` (for the "izba survived Ctrl-C" assertion)

**`scripted_guest.rs` — the no-VM fake guest** (cross-platform)
- `ScriptedGuest::start(script: GuestScript) -> Result<RunningGuest>`:
  1. Fabricates a temp data root and a sandbox dir under it with a `state.json`
     whose recorded PID + start-identity belongs to a genuinely-live helper
     process the guest spawns and owns, so the real binary's liveness check
     (`pid + /proc/<pid>/stat` starttime on Linux, the Windows equivalent)
     passes. `RunningGuest` exposes the data-root path so the test can point
     `izba` at it (via `HOME`/data-dir env — see §4.4).
  2. Binds the hybrid-vsock socket at `run/<name>/vsock.sock`
     (`UnixListener` / `uds_windows::UnixListener`).
  3. Answers the Cloud-Hypervisor hybrid handshake: read `CONNECT <port>\n`,
     reply `OK <something>\n` (matching what `vsock::hybrid_handshake` expects:
     a line starting `OK `). Reads the response byte-by-byte contract is the
     host's concern; the guest just writes the line.
  4. Over the **control** port (1025): serves length-prefixed JSON frames —
     `Health`→`Health(HealthInfo)`, `Exec(ExecRequest)`→`ExecStarted{exec_id}`
     (or `Error{CommandNotFound,..}` when the script says so), `Wait{exec_id}`→
     `Wait{status}` (the script's terminal `ExitStatus`), `Kill`→`Ok`
     (recorded), `Resize{cols,rows}`→`Ok` (recorded; may trigger an
     `OnResizeEmit` step), `Shutdown`→`Ok`.
  5. Over the **stream** port (1026): reads one `StreamAttach` frame, then runs
     the script's stream steps as raw bytes.
- `GuestScript` is a small ordered list of steps:
  - `EmitBytes(Vec<u8>)` — push bytes toward the host (guest→host)
  - `ExpectInput { bytes: Vec<u8>, timeout }` — assert the host sent these
    (host→guest); recorded for the test to query
  - `OnResizeEmit(Box<dyn Fn(u16,u16)->Vec<u8>>)` — when a Resize RPC lands,
    emit a frame computed from the new size
  - `EndWith(ExitStatus)` — close the stream (EOF) and make `Wait` return this
- `RunningGuest` query surface for assertions:
  - `received_input() -> Vec<u8>` (everything the host sent on the stream)
  - `last_resize() -> Option<(u16,u16)>`
  - `kills() -> Vec<i32>` (signals delivered via `Kill` RPC)

**`scenarios.rs` — shared checklist scenarios**
- One function per checklist item returning the pieces both tiers need: the
  `izba` argv to run, the `GuestScript` (Tier 1 only), and a closure of
  assertions against a `TerminalSession` (+ `RunningGuest` for Tier 1). This
  keeps the assertion logic written once and reused across tiers.

### 4.2 Tier 1 — scripted-guest CI tier

Test file: `crates/izba-cli/tests/tty_scripted.rs`.

- Gated only on "can this environment allocate a PTY/ConPTY". If `openpty`
  fails with `PermissionDenied`/equivalent, the test **self-skips** (matching the
  existing `full_connect_via_listener` runtime-skip pattern). Otherwise it runs
  in a normal `cargo test` — no KVM, no artifacts, no VM.
- For each scenario: start the `ScriptedGuest`, build a `CommandBuilder` for
  `izba exec -it <name> -- <argv>` pointed at the guest's data root, spawn it
  under `TerminalSession`, drive keystrokes/resizes, `wait_stable`, assert on the
  grid + the guest's recorded input.
- This tier is what regression-guards the **Windows console byte path** with no
  spike host: the vim scenario emits a redraw containing the lone `0xbd` probe
  byte and asserts the post-probe line is visible — the exact failure that
  wedged before `21fbd31`.

### 4.3 Tier 2 — real-sandbox end-to-end tier

Test file: `crates/izba-cli/tests/tty_e2e.rs`.

- Env-gated like the existing suite: `IZBA_INTEGRATION=1` + KVM + artifacts on
  Linux; on Windows a parallel gate keyed off OpenVMM availability + artifacts.
  Self-skips otherwise.
- Boots a real sandbox (reusing the existing integration boot/teardown helpers —
  factored so this crate can call them, or duplicated minimally if factoring is
  too invasive), then for each scenario spawns the real `izba exec -it` under
  `TerminalSession` against the live guest and asserts.
- This is the only tier where **real** semantics occur: Ctrl-C → guest PTY
  generates SIGINT → `killpg`; real vim reflow on resize; real console-mode
  restore. On Windows it is a single command the operator runs on the spike host,
  in the same place `validate-izba-windows.ps1` already runs — replacing the
  manual click-through.

### 4.4 Pointing the real binary at the scripted guest

`izba` resolves its data dir from the standard location
(`~/.local/share/izba`). The harness sets the child's environment (`HOME`, and
`XDG_DATA_HOME` where honored) so `Paths` resolves to the scripted guest's temp
data root. If a more direct override is needed, a single test-only env var read
in `izba-core::paths` is acceptable (documented as test-only); the plan checks
the existing `Paths` constructor first and prefers env redirection without code
change.

## 5. Checklist → assertion mapping

| Checklist item | Tier 1 (scripted) | Tier 2 (real VM) |
| --- | --- | --- |
| Lands in prompt / raw mode on | guest emits prompt bytes; assert grid shows prompt; `RawGuard` runs for real | real `sh -l`; assert prompt |
| Arrow keys / VT input | host sends `ESC[A`/etc.; assert `received_input()` contains them | guest echoes; assert grid |
| vim renders + resize | guest replays vim redraw **with `0xbd`**; assert post-probe line visible; `resize()` → `OnResizeEmit`; assert resized frame + `last_resize()` | real vim; assert status line present and reflows on resize |
| Ctrl-C doesn't kill izba | host sends `0x03`; guest ends exec; assert `is_child_alive()` stayed true until normal exit and exit path taken | real PTY → SIGINT → killpg; assert `sleep` died and izba lived |
| Console restored on exit | after child exit, assert PTY-slave/console mode is back to cooked where queryable (best-effort) | same |
| Exit-code mapping | guest `Wait` returns `Code(n)`/`Signal(s)`/`CommandNotFound`; assert izba exit `n` / `128+s` / `127` | real commands; same |

Tier-1 Ctrl-C and console-restore are **simulations** (a scripted guest cannot
raise a real SIGINT); their full-fidelity coverage is Tier 2. This split is
documented at the assertion sites so Tier 1 is never mistaken for complete
coverage.

## 6. Error handling

- Every wait API takes a timeout and returns a descriptive error on expiry
  (including a dump of current `screen.contents()` to make CI failures
  diagnosable).
- `wait_stable` is mandatory before any screen assertion that follows input, to
  absorb ConPTY async-render lag.
- The scripted guest runs on its own threads; a panic there is surfaced to the
  test via a captured `Result`/channel rather than silently hanging the test (a
  watchdog-style stall guard, mirroring `ttystorm.rs`'s 15s watchdog, fails the
  test loudly instead of hanging CI).

## 7. Testing strategy for the harness itself

- The `TerminalSession` core is exercised by a trivial cross-platform smoke test
  that spawns a tiny known program (e.g. a Rust helper bin or `printf`/`cmd /c
  echo`) and asserts the grid — proving the PTY/ConPTY + vt100 path before any
  izba-specific scenario.
- The `ScriptedGuest` is unit-tested against a hand-written client that performs
  the hybrid handshake and one `Health` round-trip, proving the fake speaks the
  protocol before the real binary is pointed at it.
- Build gates: all six CLAUDE.md gates must stay green. The new crate is added to
  the workspace; `portable-pty`/`vt100` are dev-deps so the musl-static and
  windows-gnu cross gates are unaffected for shipping crates. The new test files
  self-skip when no PTY/no integration env, so `cargo test --workspace` stays
  green in the sandbox.

## 8. File structure

```
crates/izba-ttytest/
  Cargo.toml            # dev-support crate; deps: izba-proto, portable-pty,
                        #   vt100, anyhow, serde_json, tempfile, (uds_windows on win)
  src/lib.rs            # re-exports harness, scripted_guest, scenarios
  src/harness.rs        # TerminalSession (portable-pty + vt100)
  src/scripted_guest.rs # ScriptedGuest, GuestScript, RunningGuest
  src/scenarios.rs      # one fn per checklist item

crates/izba-cli/tests/
  tty_scripted.rs       # Tier 1: real izba binary vs scripted guest (CI, both OS)
  tty_e2e.rs            # Tier 2: real izba binary vs real sandbox (env-gated)
```

## 9. Risks

1. **ConPTY async render** — mitigated by the mandatory `wait_stable` grid-based
   gate; no raw-byte assertions. Residual unknown: the exact idle window on the
   target Windows build; the plan includes a one-scenario calibration before the
   full set.
2. **Liveness fakery** (Tier 1) — fabricating a `state.json` the real binary
   accepts is the fiddliest part; contained in `scripted_guest.rs` and unit-
   tested before use.
3. **Pointing the binary at the fake data root** — prefer env redirection; fall
   back to a documented test-only env var only if `Paths` cannot be redirected
   otherwise.
4. **Helper-process lifetime** — the live PID backing `state.json` must outlive
   the test and be reaped on teardown; `RunningGuest`'s `Drop` kills it.
```
