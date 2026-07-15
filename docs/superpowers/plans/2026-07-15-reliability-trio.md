# Reliability Trio (#67, #110, #114) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three reliability/honesty gaps in one PR: the intermittent libocispec codegen race in `hack/build-crun.sh` (#110), the invisible symbolic-USER→root fallback (#114), and the daemon status lies around idempotent `izba run` + one-tick reconciler transients (#67).

**Architecture:** #110 is a script-only serialization of libocispec's codegen before crun's parallel build. #114 mirrors the existing confinement-status precedent end to end: persist a `UserFallback` into `RunState` (state.json), expose it as an additive `#[serde(default)]` field on `SandboxDetail` (no proto bump), render one line in `izba status`. #67 gets two targeted fixes: the daemon's already-running `Start` path heals the registry and stops tearing down the live sandbox's egress listener (typed `AlreadyRunning` error), and the reconciler confirms violations across a settle re-sample so one-tick cache transients are no longer reported.

**Tech Stack:** Rust workspace (izba-core, izba-cli), shell (hack/build-crun.sh), automake/libocispec internals (informational only — we don't patch crun).

## Global Constraints

- All six workspace gates green before EVERY commit (run from the worktree, with `export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH="$CARGO_HOME/bin:$PATH"`):
  1. `cargo test --workspace`
  2. `cargo clippy --workspace --all-targets -- -D warnings`
  3. `cargo fmt --check`
  4. `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`
  5. `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`
  6. `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`
- Task 3 changes `SandboxDetail` (public izba-core type embedded by the Tauri app): the separate app gate MUST also run in that task: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- **No `DAEMON_PROTO_VERSION` bump.** Only additive `#[serde(default)]` fields on existing frames; no new `DaemonRequest`/`DaemonResponse` variants; no wire-framing changes. (Repo convention: additive serde-default fields are wire-compatible — see `proto.rs` comments on `builder`/`confinement`.)
- crun stays pinned at 1.28 / sha `eb8fe73ffe44d868b14bb94fa6c295bd57e8bf023de43b61579da826c07cc406`; `-j"$(nproc)"` parallelism is preserved for the crun compile itself.
- The start-time warning `eprintln!` in `write_oci_bundle` (sandbox.rs) is preserved — same text, now sourced from `UserFallback::reason` (single source of truth).
- Images with a numeric USER or no USER: NO new field in state.json, NO new `izba status` line, NO warning (existing behavior).
- Unit tests never bind unix/vsock listeners unconditionally — a test that needs `ensure_listening` must runtime-skip on `PermissionDenied` exactly like the existing egress-touching tests in `daemon/server.rs` / `daemon/egress/mod.rs`.
- CLI functions that drive a live daemon get `#[mutants::skip] // reason: ...` (repo precedent: run.rs, rm.rs, volume.rs); all decision logic lives in unit-tested core/helper functions.
- Conventional commits, one commit per task, staged file-by-file (never `git add -A`).

## File Structure

| File | Task | Responsibility |
| --- | --- | --- |
| `hack/build-crun.sh` | 1 | serialize libocispec codegen before parallel crun build |
| `crates/izba-core/src/state.rs` | 2 | `UserFallback` type + `RunState.user_fallback` field |
| `crates/izba-core/src/image/runtime_config.rs` | 2 | `resolve_process_user` returns structured fallback |
| `crates/izba-core/src/sandbox.rs` | 2, 4 | thread fallback → `record_run_state` (T2); typed `AlreadyRunning` (T4) |
| `crates/izba-core/src/testutil.rs` | 2 | `write_state*` literals gain the new field |
| `crates/izba-core/src/daemon/proto.rs` | 3 | `SandboxDetail.user_fallback` (serde-default) |
| `crates/izba-core/src/daemon/server.rs` | 3, 4 | Inspect populates fallback (T3); already-running heal (T4) |
| `crates/izba-cli/src/commands/status.rs` | 3 | render the fallback line |
| `app/src-tauri/src/{fake.rs,views.rs}` | 3 | `SandboxDetail` literals gain the field |
| `crates/izba-core/src/reconcile.rs` | 5 | `reconcile_settled` two-sample confirmation |
| `crates/izba-cli/src/commands/reconcile.rs` | 5 | CLI uses `reconcile_settled` with tick-derived settle |
| `crates/izba-cli/tests/daemon_e2e.rs` | 5 | KVM-gated run→reconcile regression test |

---

### Task 1: #110 — serialize libocispec codegen in `hack/build-crun.sh`

**Files:**
- Modify: `hack/build-crun.sh` (insert one `make` invocation + comment between the `git-version.h` line and the `make crun` line)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: nothing other tasks rely on. Script CLI/outputs unchanged (`dist/crun`), so all callers (`.github/workflows/e2e.yml` job `crun`, `.github/workflows/_artifacts.yml` job `crun`, `.github/workflows/dogfood.yml` job `crun`) need no changes.

**Background (verified against the actual crun-1.28 release tarball, sha matches the script's pin):**
- crun's top-level `Makefile.am` line 352: `BUILT_SOURCES = .version git-version.h` — libocispec's generated sources are NOT in the top-level BUILT_SOURCES.
- Automake force-builds `BUILT_SOURCES` only for the default `all`/`check` targets. The script invokes `make crun` (explicit target) — so no BUILT_SOURCES ordering at all; the script already works around this for `git-version.h` (its existing serial-first line).
- crun's `.o` files include libocispec headers via `-I libocispec/src`; the only ordering to libocispec is the link-time rule `libocispec/libocispec.la: $(MAKE) -C libocispec libocispec.la` (top-level Makefile.am:77). Under `-j`, top-level compiles race the sub-make's `generate.py` (libocispec/Makefile.am:62-75, stamp rules `src/runtime_spec_stamp` etc.) → torn header → `unterminated #ifndef` at `runtime_spec_schema_config_windows.h:2` (CI run 28289347552; again on run 29369354376).
- Inside libocispec's own make graph the ordering is sound: every generated `.c`/`.h` depends on its family stamp (`Makefile.am:78-148`), `BUILT_SOURCES = $(HEADER_FILES) $(SOURCE_FILES)` are all in `libocispec_la_SOURCES`, and the non-generated sources (`json_common.c`, `read-file.c`) include no generated headers (verified). So `make -j -C libocispec libocispec.la` is itself parallel-safe, and completing it first materializes EVERY generated header/source before any crun compile starts.

- [ ] **Step 1: Read the current script**

Read `hack/build-crun.sh` fully. Locate the block (near lines 67-75):

```sh
./configure --enable-static --disable-systemd
# ... existing comment about BUILT_SOURCES / git-version.h ...
make -j"$(nproc)" git-version.h
make -j"$(nproc)" crun LDFLAGS="-all-static"
```

- [ ] **Step 2: Insert the serialization (the fix)**

Between the `git-version.h` line and the `make ... crun` line, insert:

```sh
    # Same BUILT_SOURCES hole, bigger member (issue #110): libocispec's
    # generated headers/sources hang off stamp rules inside the SUB-make,
    # so the top-level "make crun" -j build can compile crun .o files that
    # #include e.g. runtime_spec_schema_config_windows.h while the
    # sub-make's generate.py is still writing it (intermittent
    # "unterminated #ifndef"). Build libocispec.la to completion first:
    # its own stamp dependencies order codegen internally (parallel-safe),
    # and afterwards every generated header exists before any crun compile.
    make -j"$(nproc)" -C libocispec libocispec.la
```

Match the surrounding indentation exactly (the block lives inside the `docker run ... sh -euc '...'` heredoc/quoted script — keep quoting style intact).

- [ ] **Step 3: Syntax-check**

Run: `bash -n hack/build-crun.sh`
Expected: exit 0, no output.

- [ ] **Step 4: Verify determinism (3 consecutive full builds)**

Run (needs docker; run with the Bash sandbox disabled):

```sh
for i in 1 2 3; do rm -f dist/crun && bash hack/build-crun.sh || exit 1; file dist/crun | grep -q "statically linked" || exit 1; echo "RUN $i OK"; done
```

Expected: three `RUN N OK` lines, no `unterminated #ifndef` anywhere in the output. (Each run is a few minutes; total well under the CI job's 30-min budget.) If docker is unavailable, report BLOCKED — do not skip this verification silently.

- [ ] **Step 5: Commit**

```bash
git add hack/build-crun.sh
git commit -m "fix(hack): serialize libocispec codegen before crun's parallel build

The top-level 'make crun' is an explicit target, so automake's
BUILT_SOURCES ordering never applies and crun .o compiles race
libocispec's generate.py over the generated headers (intermittent
'unterminated #ifndef'). Pre-build libocispec.la — internally ordered
by its stamp rules — before the parallel crun build.

Fixes #110"
```

---

### Task 2: #114 (persist side) — record the symbolic-USER→root fallback in `state.json`

**Files:**
- Modify: `crates/izba-core/src/state.rs` (new `UserFallback` type + `RunState` field + tests)
- Modify: `crates/izba-core/src/image/runtime_config.rs` (`resolve_process_user` returns `Option<UserFallback>`; update its unit tests)
- Modify: `crates/izba-core/src/sandbox.rs` (thread the fallback `write_oci_bundle` → `start_with_timeouts` → `record_run_state`; update `RunState` test literals at ~1666, ~1680, ~2909, ~2937)
- Modify: `crates/izba-core/src/testutil.rs` (`write_state`, `write_state_with_run_dir`, `write_state_with_sidecars` literals)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces (Task 3 relies on these exact names):
  - `izba_core::state::UserFallback { pub declared: String, pub reason: String }` with `pub fn new(declared: &str) -> Self`.
  - `RunState.user_fallback: Option<UserFallback>` (serde-default), written by `record_run_state`.

- [ ] **Step 1: Write failing tests in `state.rs`**

Next to the existing `run_state_without_confinement_defaults_none` / `run_state_roundtrips_confinement` tests, add (adapting `sample_run_state()`):

```rust
#[test]
fn run_state_without_user_fallback_defaults_none() {
    // A pre-#114 state.json (no user_fallback key) must deserialize.
    let mut v = serde_json::to_value(sample_run_state()).unwrap();
    v.as_object_mut().unwrap().remove("user_fallback");
    let parsed: RunState = serde_json::from_value(v).unwrap();
    assert!(parsed.user_fallback.is_none());
}

#[test]
fn run_state_roundtrips_user_fallback() {
    let mut rs = sample_run_state();
    rs.user_fallback = Some(UserFallback::new("node"));
    let parsed: RunState =
        serde_json::from_str(&serde_json::to_string(&rs).unwrap()).unwrap();
    let fb = parsed.user_fallback.expect("fallback survives roundtrip");
    assert_eq!(fb.declared, "node");
    assert!(fb.reason.contains("USER 'node'"), "got: {}", fb.reason);
    assert!(fb.reason.contains("root"), "got: {}", fb.reason);
}
```

(Follow the exact mechanics of the existing back-compat tests in that file — if they build the JSON by hand instead of remove(), mirror that.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core state:: -- user_fallback`
Expected: FAIL to compile (`UserFallback` not defined).

- [ ] **Step 3: Implement the type + field in `state.rs`**

```rust
/// A symbolic image USER that could not be resolved host-side, forcing the
/// workload to run as root (#114). Persisted per-run so `izba status` can
/// re-surface the degradation durably — the start-time stderr warning is
/// one-shot and easy to miss (loud-on-degradation rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserFallback {
    /// The image's original (unresolved) symbolic USER string.
    pub declared: String,
    /// Human-readable reason; also the body of the start-time warning.
    pub reason: String,
}

impl UserFallback {
    pub fn new(declared: &str) -> Self {
        Self {
            reason: format!(
                "image USER '{declared}' could not be resolved against the image's /etc/passwd — running the workload as root (uid 0)"
            ),
            declared: declared.to_string(),
        }
    }
}
```

(The `reason` string must be byte-identical to the message currently built in `runtime_config.rs` ~352-356 — copy it from there, then delete it there in Step 5.)

Add to `RunState` (after `confinement`, mirroring its style):

```rust
    /// Present when the image declared a symbolic USER that could not be
    /// resolved host-side and the workload fell back to root (#114).
    /// `serde(default)`: absent in pre-#114 state.json → None.
    #[serde(default)]
    pub user_fallback: Option<UserFallback>,
```

Fix every `RunState { ... }` literal the compiler now rejects: `sample_run_state` in state.rs, `testutil.rs` (`write_state*`), sandbox.rs test literals — add `user_fallback: None`.

- [ ] **Step 4: Run the state tests**

Run: `cargo test -p izba-core state::`
Expected: PASS (both new tests green).

- [ ] **Step 5: Change `resolve_process_user` (tests first)**

In `runtime_config.rs`, the signature changes from returning `((u32, u32), Option<String>)` to `((u32, u32), Option<UserFallback>)`. First update the existing test `resolve_process_user_unresolvable_is_loud_root` (~line 1067) to the new shape:

```rust
let ((uid, gid), fb) = resolve_process_user(Some("ghost"), &db);
assert_eq!((uid, gid), (0, 0));
let fb = fb.expect("unresolvable symbolic USER produces a fallback");
assert_eq!(fb.declared, "ghost");
assert!(fb.reason.contains("USER 'ghost'"), "got: {}", fb.reason);
```

And the silent cases (`_none_is_silent_root`, `_empty_is_silent_root`, `_numeric_is_silent`, `_symbolic_resolves_from_db`, `_partly_symbolic_resolves_group`) assert `fb.is_none()` / unchanged uid-gid expectations. Run `cargo test -p izba-core runtime_config` — expect compile FAIL, then implement: the fallback arm becomes

```rust
((0, 0), Some(crate::state::UserFallback::new(u)))
```

(delete the local `format!` message — `UserFallback::new` is now the single source). Re-run: PASS.

- [ ] **Step 6: Thread it through `sandbox.rs`**

- `write_oci_bundle` (~line 608): return type `anyhow::Result<()>` → `anyhow::Result<Option<UserFallback>>`. The warning block becomes:

```rust
let ((uid, gid), user_fallback) = crate::image::runtime_config::resolve_process_user(
    image_config.and_then(|c| c.user.as_deref()),
    user_db,
);
if let Some(fb) = &user_fallback {
    eprintln!("warning: sandbox '{name}': {}", fb.reason);
}
```

and the function ends with `Ok(user_fallback)`.
- In `start_with_timeouts` (~line 797) capture it: `let user_fallback = write_oci_bundle(...)?;`
- `record_run_state` (~line 943): add parameter `user_fallback: Option<UserFallback>`, set it in the `RunState { ... }` literal it builds; update its call site (~line 870, inside the booted closure — move/clone as needed).

- [ ] **Step 7: Unit-test the bundle-level behavior**

`write_oci_bundle` is callable from sandbox.rs unit tests. Find how existing tests build its inputs (image config + `UserDb`); if no direct `write_oci_bundle` test exists, add the assertion at the `resolve_process_user`/`record_run_state` seams instead: a test that `record_run_state` writes `user_fallback` into state.json and one that it writes `None` when absent. Minimum bar: the round-trip from "fallback produced" to "state.json contains it" is covered by tests at some seam in this task (not deferred to e2e).

- [ ] **Step 8: Full gates + commit**

Run all six gates (Global Constraints). Expected: green.

```bash
git add crates/izba-core/src/state.rs crates/izba-core/src/image/runtime_config.rs crates/izba-core/src/sandbox.rs crates/izba-core/src/testutil.rs
git commit -m "feat(core): persist the symbolic-USER→root fallback in state.json

An unresolvable symbolic image USER falls back to root with only a
one-shot stderr warning at start. Record the fallback (original USER +
reason) in RunState (serde-default, back-compat) so it can be surfaced
durably. Part of #114."
```

---

### Task 3: #114 (surface side) — expose the fallback via Inspect and `izba status`

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs` (`SandboxDetail` + its test literals ~406, ~523)
- Modify: `crates/izba-core/src/daemon/server.rs` (`handle_inspect` ~549-587; inspect test asserts)
- Modify: `crates/izba-cli/src/commands/status.rs` (render + `detail*` test helpers + new render tests)
- Modify: `app/src-tauri/src/fake.rs` (~292), `app/src-tauri/src/views.rs` (~606) — add the field to `SandboxDetail` literals (GUI surfacing itself is out of scope per #114)

**Interfaces:**
- Consumes: `RunState.user_fallback: Option<UserFallback>` (Task 2).
- Produces: `SandboxDetail.user_fallback: Option<String>` (the declared USER string; `#[serde(default)]`; None → no output).

- [ ] **Step 1: Failing render tests in `status.rs`**

Extend the `detail(...)` helper(s) with `user_fallback: None`, then add tests modeled on the confinement render tests:

```rust
#[test]
fn renders_user_fallback_prominently() {
    let mut det = detail("web", "running");
    det.user_fallback = Some("node".into());
    let out = render(&det, ...);           // match the existing tests' render call shape
    assert!(out.contains("root"), "got: {out}");
    assert!(out.contains("'node'"), "got: {out}");
}

#[test]
fn no_user_line_without_fallback() {
    let det = detail("web", "running");
    let out = render(&det, ...);
    assert!(!out.contains("USER"), "got: {out}");
}
```

Run: `cargo test -p izba-cli status` — expect compile FAIL (no field).

- [ ] **Step 2: Add the proto field**

In `SandboxDetail` (proto.rs ~175, right after `confinement`):

```rust
    /// Present when the image's symbolic USER could not be resolved and the
    /// workload runs as root (#114): the original declared USER string.
    /// Additive + serde(default) → no DAEMON_PROTO_VERSION bump; None →
    /// the CLI prints nothing.
    #[serde(default)]
    pub user_fallback: Option<String>,
```

Fix all `SandboxDetail { ... }` literals in proto.rs/server.rs/status.rs tests (`user_fallback: None`).

- [ ] **Step 3: Populate it in `handle_inspect`**

In server.rs where the `RunState` is already loaded for `confinement` (~559-571), also extract:

```rust
let user_fallback = run_state
    .as_ref()
    .and_then(|s| s.user_fallback.as_ref())
    .map(|f| f.declared.clone());
```

(adapt to the actual binding — if the current code consumes the state with `.and_then(|s| s.confinement)`, restructure minimally so both fields read from one load) and set it in the returned `SandboxDetail`.

Add a server test next to the existing inspect test: seed state.json via the Task 2 testutil path with `user_fallback: Some(UserFallback::new("node"))` (extend a `write_state*` helper call or write the RunState directly in the test), dispatch `Inspect`, assert `det.user_fallback == Some("node".into())`; and assert the existing default test still sees `None`.

- [ ] **Step 4: Render in `status.rs`**

After the `confinement:` line in `render`, matching its exact label/indent style:

```rust
if let Some(declared) = det.user_fallback.as_deref() {
    // Loud-on-degradation: the workload is running as root because the
    // image's symbolic USER could not be resolved host-side (#114).
    out.push_str(&format!(
        "user:        root — image USER '{declared}' could not be resolved (symbolic-USER fallback)\n"
    ));
}
```

(Adapt label padding to the file's actual column alignment.)

- [ ] **Step 5: Run CLI + core tests**

Run: `cargo test -p izba-cli status && cargo test -p izba-core daemon::`
Expected: PASS.

- [ ] **Step 6: Fix the app crates + run the app gate**

Add `user_fallback: None` to the `SandboxDetail` literals in `app/src-tauri/src/fake.rs` (~292) and `app/src-tauri/src/views.rs` (~606). Do NOT extend `SandboxDetailView` (GUI surfacing is #114's explicit follow-up, not this task).

Run: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`
Expected: all green.

- [ ] **Step 7: Full gates + commit**

Run all six workspace gates. Expected: green.

```bash
git add crates/izba-core/src/daemon/proto.rs crates/izba-core/src/daemon/server.rs crates/izba-cli/src/commands/status.rs app/src-tauri/src/fake.rs app/src-tauri/src/views.rs
git commit -m "feat(cli): surface the symbolic-USER→root fallback in izba status

Inspect now carries the persisted fallback (additive serde-default
field on SandboxDetail — no proto bump) and status prints a loud
user-runs-as-root line naming the unresolved USER. Closes #114."
```

---

### Task 4: #67 (start side) — idempotent `Start` heals the registry and keeps egress alive

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (typed `AlreadyRunning` error at the ~754 bail; `liveness_of` → `pub(crate)`)
- Modify: `crates/izba-core/src/daemon/server.rs` (`handle_start` error path ~486-500 + new tests)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `izba_core::sandbox::AlreadyRunning { pub name: String }` (std Error; Display = `"sandbox '{name}' is already running"` — byte-identical to today's message, which `run.rs:173` string-matches).

**Why (both facets verified in code):** `sandbox::start` bails "already running" (sandbox.rs:753-754) → `handle_start` hits its generic error path, which (a) never reaches `registry.set(Running)` at server.rs:512, so a stale `Stopped` cache entry is never healed by a redundant `izba run` (the CLI swallows the error as idempotent success, run.rs:172-173); and (b) runs `d.egress.stop(&name, ...)` at server.rs:498 — but `ensure_listening` at :484 was a no-op for the already-live slot (egress/mod.rs:163-166), so this tears down the RUNNING sandbox's egress listener (guest DNS/TCP dials fail until the supervisor tick rebinds, ~2s).

- [ ] **Step 1: Typed error in `sandbox.rs` (test first)**

Add a unit test near the existing already-running test (~2383):

```rust
#[test]
fn start_already_running_is_typed() {
    // reuse the exact setup of the existing test at ~2383 that produces
    // the "already running" error, then:
    assert!(
        err.downcast_ref::<AlreadyRunning>().is_some(),
        "start's already-running bail must be downcastable, got: {err:#}"
    );
    assert_eq!(err.to_string(), "sandbox 'web' is already running");
}
```

(Adapt the sandbox name to whatever that existing test uses.) Run `cargo test -p izba-core sandbox:: -- already_running` — expect FAIL (type missing).

Implement:

```rust
/// Typed marker for `start`'s idempotent refusal so the daemon can tell
/// "the sandbox is alive" apart from a genuine boot failure (#67). The CLI
/// string-matches the Display text (run.rs) — keep it stable.
#[derive(Debug)]
pub struct AlreadyRunning {
    pub name: String,
}

impl std::fmt::Display for AlreadyRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sandbox '{}' is already running", self.name)
    }
}

impl std::error::Error for AlreadyRunning {}
```

and replace the bail at ~754:

```rust
return Err(AlreadyRunning { name: name.to_string() }.into());
```

Change `fn liveness_of` (~539) to `pub(crate) fn liveness_of`. Run the sandbox tests: PASS (including the pre-existing `contains("already running")` asserts — text unchanged).

- [ ] **Step 2: Failing daemon test for the heal + egress preservation**

In server.rs tests, following the existing patterns (`stop_removes_legacy_egress_listener_of_adopted_sandbox` for egress + testutil `spawn_sleep`/`write_state` for a live pid; runtime-skip on `PermissionDenied` from `ensure_listening` like its sibling tests):

```rust
/// #67: a redundant Start on an already-running sandbox must (a) heal a
/// stale registry entry to the actual liveness and (b) NOT tear down the
/// live sandbox's egress listener.
#[test]
fn start_already_running_heals_registry_and_keeps_egress() {
    // setup: sandbox dir + config.json + state.json with a live pid
    // (spawn_sleep) and run_dir; d.egress.ensure_listening(...) bound
    // (runtime-skip on PermissionDenied); registry seeded STALE:
    // d.registry.set(&name, &image_ref, Liveness::Stopped);
    // act: dispatch DaemonRequest::Start { name, .. }
    // assert:
    //   - response is DaemonResponse::Error with "already running"
    //   - d.egress.listening(&name) is still true
    //   - d.registry.liveness(&name) == Some(Liveness::Running)
}
```

Fill in with the concrete helpers the neighboring tests use. Run: FAIL (egress torn down / registry still Stopped).

- [ ] **Step 3: Implement in `handle_start`**

Replace the error arm (server.rs ~492-500):

```rust
    if let Err(e) = sandbox::start(
        &d.paths,
        &name,
        d.deps.driver.as_ref(),
        &art,
        allow_unconfined,
    ) {
        if e.downcast_ref::<sandbox::AlreadyRunning>().is_some() {
            // The sandbox is alive: the listener bound by its original
            // start is still serving (ensure_listening above was a no-op)
            // — leave it. And heal a stale registry entry so a redundant
            // `izba run` self-corrects List/Inspect instead of returning
            // success while the daemon keeps reporting "stopped" (#67).
            if let Ok(live) = sandbox::liveness_of(&d.paths, &name, d.connector()) {
                d.registry.set(&name, &config.image_ref, live);
            }
            return Err(e);
        }
        // Boot never happened — tear the listener back down, in the SAME
        // dir the bind above used. Not `live_run_dir`: a stale pre-upgrade
        // state.json (crashed old run, `run_dir: None`, dead pid) would
        // make it resolve to the legacy dir and miss the listener just
        // bound in `paths.run_dir`.
        d.egress.stop(&name, &d.paths.run_dir(&name));
        return Err(e);
    }
```

(Keep the existing comment on the genuine-failure branch verbatim; check `liveness_of`'s exact connector parameter type against `supervisor::tick`'s usage of `d.connector()`.)

- [ ] **Step 4: Run the tests**

Run: `cargo test -p izba-core daemon::server`
Expected: new test PASS; all existing start/stop/rm tests PASS.

- [ ] **Step 5: Full gates + commit**

```bash
git add crates/izba-core/src/sandbox.rs crates/izba-core/src/daemon/server.rs
git commit -m "fix(daemon): idempotent Start heals the registry and spares live egress

A redundant Start on a running sandbox took the generic boot-failure
path: it tore down the live egress listener (ensure_listening had
no-op'd) and returned before registry.set(Running), so a stale
'stopped' cache entry was never corrected even though the CLI treats
already-running as success. Type the refusal (AlreadyRunning), keep
the listener, and re-assess liveness into the registry. Part of #67."
```

---

### Task 5: #67 (checker side) — reconciler confirms violations across a settle re-sample

**Files:**
- Modify: `crates/izba-core/src/reconcile.rs` (`reconcile_settled` + tests, incl. the missing daemon-stopped-but-pid-alive direction)
- Modify: `crates/izba-cli/src/commands/reconcile.rs` (use it; `#[mutants::skip]` on the daemon-glue `run`)
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (KVM-gated run→reconcile regression)

**Interfaces:**
- Consumes: nothing from other tasks (composes with Task 4 at runtime only).
- Produces: `izba_core::reconcile::reconcile_settled(paths, &mut dyn FnMut() -> anyhow::Result<Option<Vec<SandboxSummary>>>, &dyn Probes, settle: Duration) -> anyhow::Result<ReconcileReport>`.

**Why:** the daemon's List status is a cache refreshed by a ~2s supervisor tick (supervisor.rs:148-157); a single-sample disagreement during a transition is expected of that design, and the #133 guard deliberately lets the tick own steady state. The reconciler (a read-only checker) must therefore only report disagreements that PERSIST past a tick — exactly the remedy #67's own analysis proposes. Fixes the dogfood flake class regardless of which transient produced it.

- [ ] **Step 1: Failing core tests**

In reconcile.rs tests, using the existing `FakeProbes`/temp-dir helpers:

```rust
#[test]
fn daemon_stopped_but_pid_alive_is_disk_live_mismatch() {
    // inverse direction of the existing daemon_running_but_vmm_pid_dead
    // test: state.json with a pid FakeProbes reports alive, daemon view
    // status "stopped" → exactly one DiskLiveMismatch violation.
}

#[test]
fn settled_drops_a_transient_mismatch() {
    // fetch closure returns view[status="stopped"] on call 1 and
    // view[status="running"] on call 2 (RefCell counter); pid alive.
    // reconcile_settled(..., Duration::ZERO) → zero violations.
}

#[test]
fn settled_reports_a_persistent_mismatch_once() {
    // same view ("stopped") on both calls → exactly one DiskLiveMismatch.
}

#[test]
fn settled_fetches_once_when_first_pass_is_clean() {
    // consistent view; counter asserts the closure ran exactly once.
}
```

Run: `cargo test -p izba-core reconcile` — expect compile FAIL (`reconcile_settled` missing). (If the first test reveals the direction is already covered, keep it anyway only if it pins something new; otherwise drop it and say so in the report.)

- [ ] **Step 2: Implement `reconcile_settled`**

```rust
/// Two-sample reconcile (#67): the daemon's status is a cache refreshed by
/// the supervisor tick, so a single-sample alive⇄stopped disagreement during
/// a start/stop transition is expected, not a violation. Sample once; if
/// violations are found, wait `settle` (callers pass one tick + margin),
/// re-fetch a FRESH daemon view, re-run, and keep only violations present in
/// BOTH passes (matched by kind + sandbox). Returns the second pass's report
/// (fresher snapshots), filtered.
pub fn reconcile_settled(
    paths: &Paths,
    fetch_daemon_view: &mut dyn FnMut() -> anyhow::Result<Option<Vec<SandboxSummary>>>,
    probes: &dyn Probes,
    settle: std::time::Duration,
) -> anyhow::Result<ReconcileReport> {
    let first_view = fetch_daemon_view()?;
    let first = reconcile(paths, first_view.as_deref(), probes)?;
    if first.violations.is_empty() {
        return Ok(first);
    }
    std::thread::sleep(settle);
    let second_view = fetch_daemon_view()?;
    let mut second = reconcile(paths, second_view.as_deref(), probes)?;
    second.violations.retain(|v| {
        first
            .violations
            .iter()
            .any(|f| f.kind == v.kind && f.sandbox == v.sandbox)
    });
    Ok(second)
}
```

Run: `cargo test -p izba-core reconcile` — PASS.

- [ ] **Step 3: Wire the CLI**

Rewrite `crates/izba-cli/src/commands/reconcile.rs`'s `run` to reuse one optional client across both fetches:

```rust
#[mutants::skip] // reason: drives a live daemon (List over the socket) and real sleeps; the settle/intersection decision logic is unit-tested in izba_core::reconcile.
pub fn run(paths: &Paths, json: bool) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect_existing(paths)?;
    let mut fetch = || -> anyhow::Result<Option<Vec<SandboxSummary>>> {
        match client.as_mut() {
            // Best-effort daemon view; None if the daemon is not running.
            None => Ok(None),
            Some(c) => match c.request(&DaemonRequest::List, &mut |_| {})? {
                DaemonResponse::List { sandboxes } => Ok(Some(sandboxes)),
                DaemonResponse::Error { message } => anyhow::bail!("daemon list failed: {message}"),
                other => anyhow::bail!("unexpected daemon response: {other:?}"),
            },
        }
    };
    // One supervisor tick + margin: long enough for the daemon's cached
    // status to self-correct after a transition (#67).
    let settle = izba_core::daemon::supervisor::tick_interval() + std::time::Duration::from_millis(500);
    let report = reconcile_settled(paths, &mut fetch, &PidProbes, settle)?;
    // ... unchanged json / plain printing ...
    Ok(0)
}
```

(Import `SandboxSummary` + `reconcile_settled`; keep `PidProbes` as-is; keep the output code byte-identical.)

- [ ] **Step 4: Run CLI tests + clippy**

Run: `cargo test -p izba-cli && cargo clippy -p izba-cli --all-targets -- -D warnings`
Expected: PASS (closure borrow of `client` is the usual FnMut pattern; fix signature nits per clippy).

- [ ] **Step 5: KVM-gated e2e regression**

In `crates/izba-cli/tests/daemon_e2e.rs`, next to the existing run-then-ls test (~904), add a test following that file's helper conventions (env-gated, `--test-threads=1` suite):

```rust
/// #67 regression: right after `izba run`, the reconciler must see a
/// consistent daemon-vs-disk view (the settle re-sample absorbs the
/// supervisor tick's cache lag; the Start heal covers the idempotent path).
#[test]
fn reconcile_is_clean_right_after_run() {
    // guard: if !integration_enabled() { return; } (per file convention)
    // izba run <name>  (exit 0)
    // izba __reconcile --json  → parse stdout as JSON
    // assert violations array is empty, printing the full report on failure
}
```

This runs under `IZBA_INTEGRATION=1` locally and in CI e2e — do not attempt it in the unit gates.

- [ ] **Step 6: Full gates + commit**

```bash
git add crates/izba-core/src/reconcile.rs crates/izba-cli/src/commands/reconcile.rs crates/izba-cli/tests/daemon_e2e.rs
git commit -m "fix(cli): reconcile confirms violations across a settle re-sample

The daemon's List status is a tick-refreshed cache, so a single-sample
alive⇄stopped disagreement during a transition is expected. Re-sample
after one tick + margin and report only persistent violations; add the
missing daemon-stopped-but-pid-alive direction test and a KVM e2e
run→reconcile regression. Closes #67. Closes #110 is in an earlier
commit of this branch."
```

(Note: strike the last sentence if the commit-message linter objects — issue closing is handled by the PR body.)

---

## Self-Review Notes

- Spec coverage: #110 AC (deterministic repeated `-j` builds, parallelism preserved, callers unchanged, same artifact) → Task 1 steps 2-4. #114 AC (persist original name + reason; status shows it; numeric/none unchanged; eprintln preserved; tests) → Tasks 2-3. #67 (repro path, cache-lag class fixed at both the producer and the checker, missing test direction, e2e regression) → Tasks 4-5.
- Type consistency: `UserFallback{declared,reason}` produced in Task 2 and consumed by name in Task 3; `AlreadyRunning{name}` produced and consumed inside Task 4; `reconcile_settled` signature matches its CLI call in Task 5.
- Deliberate exclusions: no supervisor-tick debounce for a transient `/proc` misread (speculative trigger, poor injectability — the checker-side settle neutralizes its observable symptom, and the tick self-heals); no GUI surfacing of the fallback (#114 explicitly defers it); no change to `run.rs`'s message string-match (no error codes on the wire; Display kept stable instead).
