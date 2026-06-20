# LLM dogfooding agent — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the increment-1 (Linux-only) PoC of the spec-anchored LLM dogfooding pipeline: a Rust snapshot-consistency reconciler, a cheap-model journey-execution runner with a deterministic oracle layer, a `workflow_dispatch` CI fan-out, and a local Claude Code harness for the strong phases.

**Architecture:** Three phases over two file contracts. Phase 1 (intent extraction) & Phase 3 (skeptic+synthesis) run locally in Claude Code; Phase 2 (the cheap-model journey loop) fans out across KVM CI workers. Handoff is `journeys.json` (in) and per-shard trajectory bundles (out). The one Rust artifact is `izba __reconcile --json`, a single-shot consistency checker reused by the runner and by e2e tests; sequence invariants are derived by the runner diffing reconciler snapshots across actions.

**Tech Stack:** Rust (izba-core + izba-cli, existing toolchain), Python 3 stdlib for the CI runner (urllib for OpenRouter HTTP — no new pip deps), GitHub Actions (`workflow_dispatch`, KVM matrix), a Claude Code skill for the local phases.

## Global Constraints

- **All six workspace gates must stay green** (copied from CLAUDE.md): `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`.
- **The reconciler must compile for `x86_64-pc-windows-gnu`** (it lives in izba-core/izba-cli, both cross-gated). Use `crate::procmgr::pid_alive` (already cross-platform) for liveness; do NOT add Linux-only `/proc` parsing in the reconciler — reuse procmgr.
- **TDD:** tests first; reviews expect it. Use `UnixStream::pair()` / `FakeProbes` fakes — unit tests never bind listeners (some sandboxes deny `bind` with EPERM).
- **Conventional commits** (`feat(core): ...`). Frequent commits, one per task.
- **No new runtime deps in izba-core/izba-cli** beyond what's already vendored; serde/serde_json/anyhow are available.
- **Reconciler runs read-only** — it never mutates daemon or disk state.
- **CI runner: report-only.** Never fails the job on findings; only infra errors fail it. Hard caps mandatory (max-turns, budget USD, step-cap, per-action timeout, loop-dedup).
- Sandbox-local toolchain: `[ -f .cargo-env ] && source .cargo-env` before cargo (worktrees may lack it; fall back to system toolchain).

---

## Phase A — The reconciler (Rust, CI-green-critical)

New library module `crates/izba-core/src/reconcile.rs` (pure logic + types) and a thin CLI command `crates/izba-cli/src/commands/reconcile.rs` (daemon List + disk scan + print). The pure `reconcile()` takes the daemon view + a `Probes` impl as parameters so it is fully unit-testable with `FakeProbes` and temp dirs.

### Task A1: Reconcile types + `list == reality` check

**Files:**
- Create: `crates/izba-core/src/reconcile.rs`
- Modify: `crates/izba-core/src/lib.rs` (add `pub mod reconcile;`)
- Test: inline `#[cfg(test)]` module in `reconcile.rs`

**Interfaces:**
- Consumes: `crate::paths::Paths`, `crate::daemon::proto::SandboxSummary { name, image_ref, status }`, `crate::liveness::{assess, Liveness, Probes}`, `crate::state::{RunState, PidIdentity, load_json, STATE_FILE, CONFIG_FILE, PORTS_FILE}`.
- Produces:
  ```rust
  pub enum ViolationKind { ListMismatch, DiskLiveMismatch, OrphanRelay, OrphanVolume }
  pub struct Violation { pub kind: ViolationKind, pub sandbox: Option<String>, pub detail: String }
  pub struct SandboxSnapshot { pub name: String, pub status_daemon: Option<String>, pub status_disk: String, pub vmm: Option<PidIdentity> }
  pub struct ReconcileReport { pub violations: Vec<Violation>, pub sandboxes: Vec<SandboxSnapshot> }
  pub fn reconcile(paths: &Paths, daemon_view: Option<&[SandboxSummary]>, probes: &dyn Probes) -> anyhow::Result<ReconcileReport>
  ```

- [ ] **Step 1: Write the failing test** (add to a new `#[cfg(test)] mod tests` in `reconcile.rs`)

```rust
use super::*;
use crate::testutil::{test_paths, live_identity, dead_identity, write_state};
use crate::daemon::proto::SandboxSummary;
use crate::liveness::Probes;
use crate::state::PidIdentity;

struct FakeProbes { alive: Vec<PidIdentity>, control: bool }
impl Probes for FakeProbes {
    fn pid_alive(&self, id: &PidIdentity) -> bool { self.alive.contains(id) }
    fn control_answers(&self) -> bool { self.control }
}
fn summary(name: &str, status: &str) -> SandboxSummary {
    SandboxSummary { name: name.into(), image_ref: "alpine:3.20".into(), status: status.into() }
}

#[test]
fn daemon_lists_sandbox_with_no_dir_is_list_mismatch() {
    let (_tmp, paths) = test_paths();
    // daemon claims "ghost" exists; nothing on disk
    let view = vec![summary("ghost", "running")];
    let probes = FakeProbes { alive: vec![], control: true };
    let report = reconcile(&paths, Some(&view), &probes).unwrap();
    assert!(report.violations.iter().any(|v|
        v.kind == ViolationKind::ListMismatch && v.sandbox.as_deref() == Some("ghost")));
}

#[test]
fn disk_dir_not_in_daemon_list_is_list_mismatch() {
    let (_tmp, paths) = test_paths();
    std::fs::create_dir_all(paths.sandbox_dir("orphan")).unwrap();
    let view: Vec<SandboxSummary> = vec![]; // daemon lists nothing
    let probes = FakeProbes { alive: vec![], control: true };
    let report = reconcile(&paths, Some(&view), &probes).unwrap();
    assert!(report.violations.iter().any(|v|
        v.kind == ViolationKind::ListMismatch && v.sandbox.as_deref() == Some("orphan")));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-core reconcile:: 2>&1 | tail -20`
Expected: FAIL — `reconcile` / types not found.

- [ ] **Step 3: Write minimal implementation** (top of `reconcile.rs`)

```rust
use crate::daemon::proto::SandboxSummary;
use crate::liveness::{assess, Probes};
use crate::paths::Paths;
use crate::state::{load_json, PidIdentity, RunState, STATE_FILE};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind { ListMismatch, DiskLiveMismatch, OrphanRelay, OrphanVolume }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation { pub kind: ViolationKind, pub sandbox: Option<String>, pub detail: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSnapshot {
    pub name: String,
    pub status_daemon: Option<String>,
    pub status_disk: String,
    pub vmm: Option<PidIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileReport { pub violations: Vec<Violation>, pub sandboxes: Vec<SandboxSnapshot> }

/// Names of sandbox dirs on disk (sorted).
fn disk_names(paths: &Paths) -> anyhow::Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let dir = paths.sandboxes_dir();
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() { out.insert(name.to_string()); }
            }
        }
    }
    Ok(out)
}

pub fn reconcile(
    paths: &Paths,
    daemon_view: Option<&[SandboxSummary]>,
    probes: &dyn Probes,
) -> anyhow::Result<ReconcileReport> {
    let mut violations = Vec::new();
    let disk = disk_names(paths)?;
    let daemon: BTreeSet<String> = daemon_view
        .map(|v| v.iter().map(|s| s.name.clone()).collect())
        .unwrap_or_default();

    for name in daemon.difference(&disk) {
        violations.push(Violation {
            kind: ViolationKind::ListMismatch,
            sandbox: Some(name.clone()),
            detail: "daemon lists a sandbox with no on-disk directory".into(),
        });
    }
    for name in disk.difference(&daemon) {
        violations.push(Violation {
            kind: ViolationKind::ListMismatch,
            sandbox: Some(name.clone()),
            detail: "on-disk sandbox directory not reported by daemon list".into(),
        });
    }

    // sandboxes snapshot filled in A2; empty for now keeps the type stable.
    let sandboxes = Vec::new();
    let _ = (assess, load_json::<RunState>, STATE_FILE); // referenced in A2
    Ok(ReconcileReport { violations, sandboxes })
}
```

Add `pub mod reconcile;` to `crates/izba-core/src/lib.rs` (alongside the other `pub mod` lines).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-core reconcile:: 2>&1 | tail -20`
Expected: PASS (2 tests). Fix the `let _ = ...` line if it causes a clippy/type issue — it is a placeholder to keep imports live until A2; replace with real use there.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/reconcile.rs crates/izba-core/src/lib.rs
git commit -m "feat(core): reconcile — list==reality snapshot check + types"
```

### Task A2: `disk == live` check + per-sandbox snapshot

**Files:**
- Modify: `crates/izba-core/src/reconcile.rs`
- Test: inline tests

**Interfaces:**
- Consumes: `crate::liveness::assess(Option<&RunState>, &dyn Probes) -> Liveness`, `Liveness::describe()`.
- Produces: `reconcile()` now fills `report.sandboxes` and emits `DiskLiveMismatch` when the daemon believes a sandbox is alive but the independent pid assessment says Stopped (or vice versa). Lenient: only the Stopped⇄alive disagreement is flagged (control-plane-hang divergence is intentionally NOT flagged — that is the harness latency oracle's job).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn daemon_running_but_vmm_pid_dead_is_disk_live_mismatch() {
    let (_tmp, paths) = test_paths();
    std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
    write_state(&paths, "box", dead_identity());      // state.json references a dead pid
    let view = vec![summary("box", "running")];        // daemon thinks it's running
    let probes = FakeProbes { alive: vec![], control: true };
    let report = reconcile(&paths, Some(&view), &probes).unwrap();
    assert!(report.violations.iter().any(|v|
        v.kind == ViolationKind::DiskLiveMismatch && v.sandbox.as_deref() == Some("box")));
    let snap = report.sandboxes.iter().find(|s| s.name == "box").unwrap();
    assert_eq!(snap.status_daemon.as_deref(), Some("running"));
    assert_eq!(snap.status_disk, "stopped");
}

#[test]
fn daemon_running_and_vmm_alive_is_clean() {
    let (_tmp, paths) = test_paths();
    std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
    let vmm = live_identity();
    write_state(&paths, "box", vmm.clone());
    let view = vec![summary("box", "running")];
    let probes = FakeProbes { alive: vec![vmm], control: true };
    let report = reconcile(&paths, Some(&view), &probes).unwrap();
    assert!(report.violations.is_empty(), "unexpected: {:?}", report.violations);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-core reconcile:: 2>&1 | tail -20`
Expected: FAIL — `sandboxes` empty / no `DiskLiveMismatch`.

- [ ] **Step 3: Write minimal implementation** (replace the snapshot section of `reconcile()`)

```rust
    let mut sandboxes = Vec::new();
    for name in &disk {
        let state: Option<RunState> =
            load_json(&paths.sandbox_dir(name).join(STATE_FILE))?;
        let disk_status = assess(state.as_ref(), probes);
        let status_disk = disk_status.describe();
        let status_daemon = daemon_view
            .and_then(|v| v.iter().find(|s| &s.name == name))
            .map(|s| s.status.clone());

        // Lenient: flag only the unambiguous alive⇄stopped disagreement.
        if let Some(d) = &status_daemon {
            let daemon_thinks_alive = d != "stopped";
            let disk_thinks_alive = !matches!(disk_status, crate::liveness::Liveness::Stopped);
            if daemon_thinks_alive != disk_thinks_alive {
                violations.push(Violation {
                    kind: ViolationKind::DiskLiveMismatch,
                    sandbox: Some(name.clone()),
                    detail: format!("daemon status {d:?} but disk/pid assessment is {status_disk:?}"),
                });
            }
        }
        sandboxes.push(SandboxSnapshot {
            name: name.clone(),
            status_daemon,
            status_disk,
            vmm: state.as_ref().map(|r| r.vmm_pid.clone()),
        });
    }
```

Remove the A1 placeholder `let _ = (...)` and the `let sandboxes = Vec::new();` stub.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-core reconcile:: 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/reconcile.rs
git commit -m "feat(core): reconcile — disk==live mismatch + per-sandbox snapshot"
```

### Task A3: orphan-relay + orphan-volume checks

**Files:**
- Modify: `crates/izba-core/src/reconcile.rs`
- Test: inline tests

**Interfaces:**
- Consumes: `crate::state::{PortRecord, PORTS_FILE}`, `crate::volume::unreferenced_volumes`, `crate::state::{SandboxConfig, CONFIG_FILE}`, `crate::paths::Paths::{volumes_dir, volume_image}`.
- Produces: `reconcile()` emits `OrphanRelay` (a `ports.json` relay pid that is dead while its sandbox is alive, or alive while its sandbox is Stopped) and `OrphanVolume` (a `<data>/volumes/*.img` not referenced by any sandbox config — emitted as a low-signal finding, since persistent volumes intentionally survive `rm`; detail must say "informational: persistent volumes survive rm").

- [ ] **Step 1: Write the failing test**

```rust
use crate::state::{PortRecord, PortRule, PORTS_FILE, save_json};
use std::net::Ipv4Addr;

#[test]
fn relay_dead_while_sandbox_running_is_orphan_relay() {
    let (_tmp, paths) = test_paths();
    std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
    let vmm = live_identity();
    write_state(&paths, "box", vmm.clone());
    let rec = PortRecord {
        rule: PortRule { bind: Ipv4Addr::LOCALHOST, host_port: 8080, guest_port: 80 },
        relay: dead_identity(),
    };
    save_json(&paths.sandbox_dir("box").join(PORTS_FILE), &vec![rec]).unwrap();
    let view = vec![summary("box", "running")];
    let probes = FakeProbes { alive: vec![vmm], control: true };
    let report = reconcile(&paths, Some(&view), &probes).unwrap();
    assert!(report.violations.iter().any(|v|
        v.kind == ViolationKind::OrphanRelay && v.sandbox.as_deref() == Some("box")));
}

#[test]
fn unreferenced_named_volume_is_informational_orphan_volume() {
    let (_tmp, paths) = test_paths();
    std::fs::create_dir_all(paths.volumes_dir()).unwrap();
    std::fs::write(paths.volume_image("leftover"), b"x").unwrap();
    let view: Vec<SandboxSummary> = vec![];
    let probes = FakeProbes { alive: vec![], control: true };
    let report = reconcile(&paths, Some(&view), &probes).unwrap();
    let v = report.violations.iter().find(|v| v.kind == ViolationKind::OrphanVolume).unwrap();
    assert!(v.detail.contains("informational"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-core reconcile:: 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Write minimal implementation** (append two passes inside `reconcile()` before `Ok(...)`)

```rust
    use crate::state::{PortRecord, SandboxConfig, CONFIG_FILE, PORTS_FILE};
    use std::collections::HashSet;

    // Orphan relays: relay liveness must track sandbox liveness.
    for name in &disk {
        let ports: Option<Vec<PortRecord>> =
            load_json(&paths.sandbox_dir(name).join(PORTS_FILE))?;
        let Some(ports) = ports else { continue };
        let sandbox_alive = sandboxes.iter().any(|s| &s.name == name && s.status_disk != "stopped");
        for rec in ports {
            let relay_alive = probes.pid_alive(&rec.relay);
            if sandbox_alive && !relay_alive {
                violations.push(Violation {
                    kind: ViolationKind::OrphanRelay,
                    sandbox: Some(name.clone()),
                    detail: format!("relay for host_port {} dead while sandbox is alive", rec.rule.host_port),
                });
            }
            if !sandbox_alive && relay_alive {
                violations.push(Violation {
                    kind: ViolationKind::OrphanRelay,
                    sandbox: Some(name.clone()),
                    detail: format!("relay for host_port {} alive while sandbox is stopped", rec.rule.host_port),
                });
            }
        }
    }

    // Orphan (unreferenced) named volume images — informational only.
    let mut referenced: HashSet<String> = HashSet::new();
    for name in &disk {
        if let Some(cfg) = load_json::<SandboxConfig>(&paths.sandbox_dir(name).join(CONFIG_FILE))? {
            for vol in cfg.volumes {
                if let Some(n) = vol.name { referenced.insert(n); }
            }
        }
    }
    let vdir = paths.volumes_dir();
    if vdir.is_dir() {
        for entry in std::fs::read_dir(&vdir)? {
            let entry = entry?;
            let fname = entry.file_name();
            let Some(stem) = fname.to_str().and_then(|s| s.strip_suffix(".img")) else { continue };
            if !referenced.contains(stem) {
                violations.push(Violation {
                    kind: ViolationKind::OrphanVolume,
                    sandbox: None,
                    detail: format!("informational: named volume '{stem}' is unreferenced (persistent volumes survive rm)"),
                });
            }
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p izba-core reconcile:: 2>&1 | tail -20`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/reconcile.rs
git commit -m "feat(core): reconcile — orphan-relay + informational orphan-volume checks"
```

### Task A4: CLI hidden subcommand `izba __reconcile --json`

**Files:**
- Create: `crates/izba-cli/src/commands/reconcile.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs` (add `pub mod reconcile;`)
- Modify: `crates/izba-cli/src/main.rs` (add hidden `Reconcile { json: bool }` variant + dispatch arm)

**Interfaces:**
- Consumes: `izba_core::daemon::client::DaemonClient`, `izba_core::daemon::proto::{DaemonRequest, DaemonResponse}`, `izba_core::reconcile::reconcile`, `izba_core::procmgr`, `izba_core::liveness::Probes`, `izba_core::paths::Paths`.
- Produces: command `__reconcile` printing `ReconcileReport` as JSON to stdout, exit 0 (report-only). The harness parses stdout JSON.

- [ ] **Step 1: Write the command** (`crates/izba-cli/src/commands/reconcile.rs`)

```rust
use izba_core::daemon::client::DaemonClient;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::liveness::Probes;
use izba_core::paths::Paths;
use izba_core::reconcile::reconcile;
use izba_core::state::PidIdentity;

/// Reconciler probes: pid liveness from procmgr; control assumed answering
/// (the reconciler flags only the unambiguous alive⇄stopped disagreement —
/// control-plane responsiveness is the runner's latency oracle, not ours).
struct PidProbes;
impl Probes for PidProbes {
    fn pid_alive(&self, id: &PidIdentity) -> bool { izba_core::procmgr::pid_alive(id) }
    fn control_answers(&self) -> bool { true }
}

pub fn run(paths: &Paths, json: bool) -> anyhow::Result<i32> {
    // Best-effort daemon view; None if the daemon is not running.
    let daemon_view = match DaemonClient::connect_existing(paths)? {
        Some(mut client) => match client.request(&DaemonRequest::List, &mut |_| {})? {
            DaemonResponse::List { sandboxes } => Some(sandboxes),
            DaemonResponse::Error { message } => anyhow::bail!("daemon list failed: {message}"),
            other => anyhow::bail!("unexpected daemon response: {other:?}"),
        },
        None => None,
    };
    let report = reconcile(paths, daemon_view.as_deref(), &PidProbes)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for v in &report.violations {
            println!("{:?} {:?}: {}", v.kind, v.sandbox, v.detail);
        }
    }
    Ok(0)
}
```

- [ ] **Step 2: Wire the subcommand** — add to the `Cmd` enum in `crates/izba-cli/src/main.rs`:

```rust
    /// Internal: print state-consistency report (used by the dogfooding harness).
    #[command(hide = true, name = "__reconcile")]
    Reconcile {
        #[arg(long)]
        json: bool,
    },
```

…and the dispatch arm in `fn dispatch(...)`:

```rust
        Cmd::Reconcile { json } => commands::reconcile::run(paths, json),
```

…and `pub mod reconcile;` in `crates/izba-cli/src/commands/mod.rs`.

- [ ] **Step 3: Build + smoke-run**

Run: `[ -f .cargo-env ] && source .cargo-env; cargo run -p izba-cli -- __reconcile --json`
Expected: prints `{ "violations": [], "sandboxes": [...] }` (a clean report against whatever is on the dev machine; non-empty `sandboxes` only if you have sandboxes). Exit 0. (If no daemon and no sandboxes: `{"violations":[],"sandboxes":[]}`.)

- [ ] **Step 4: Add a CLI smoke test** (`crates/izba-cli/tests/`, follow the existing test style; gate on nothing — it uses an empty `IZBA_DATA_DIR`)

```rust
// tests/reconcile_smoke.rs
use std::process::Command;
#[test]
fn reconcile_json_on_empty_data_dir_is_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(["__reconcile", "--json"])
        .env("IZBA_DATA_DIR", tmp.path())
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["violations"].as_array().unwrap().len(), 0);
}
```

Note: `connect_existing` must NOT auto-start a daemon (it returns `Ok(None)` when absent), so this test stays hermetic. Verify that is the case before relying on it; if `connect_existing` ever auto-starts, set a temp `IZBA_DATA_DIR` (done) so no real daemon is touched.

- [ ] **Step 5: Run the smoke test**

Run: `cargo test -p izba-cli --test reconcile_smoke 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/izba-cli/src/commands/reconcile.rs crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/main.rs crates/izba-cli/tests/reconcile_smoke.rs
git commit -m "feat(cli): add hidden __reconcile --json snapshot-consistency command"
```

### Task A5: run all six workspace gates green

- [ ] **Step 1: Run the gates** (unsandboxed if needed; cross gates require the windows-gnu target + mingw)

```bash
[ -f .cargo-env ] && source .cargo-env
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace 2>&1 | tail -30
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

- [ ] **Step 2: Fix any clippy/fmt issues inline; re-run until all six are green.** Common fixes: `#[derive(...)]` ordering, `BTreeSet`/`HashSet` import paths, remove the A1 placeholder if it lingers. Expected: all six green.

- [ ] **Step 3: Commit any fixups**

```bash
git add -p
git commit -m "chore(core): satisfy clippy/fmt for reconcile module"
```

---

## Phase B — File contracts + the Phase-2 runner (Python)

A self-contained runner under `hack/dogfood/`. Python 3 stdlib only (urllib for OpenRouter). It must be testable in CI **without** an API key or KVM via a `--fake-model` mode, so its oracle/cap logic is covered by plain `python -m pytest`-free unit tests (use `unittest`, stdlib).

### Task B1: file-contract schemas + fixtures

**Files:**
- Create: `hack/dogfood/schema/journeys.schema.json`
- Create: `hack/dogfood/schema/trajectory.schema.json`
- Create: `hack/dogfood/fixtures/journeys.example.json`
- Create: `hack/dogfood/README.md` (the contracts + the dispatch-branch procedure)

**Interfaces:**
- Produces: the two JSON contracts (`journeys.json` in, trajectory bundle out) that Phases 1/2/3 share.

- [ ] **Step 1: Write `journeys.schema.json`** — an object `{ "feature": str, "journeys": [Journey] }` where `Journey = { journey_id: str, rationale: str, source: { kind: "spec"|"pr"|"greptile"|"help", ref: str }, steps: [ { intent: str, expect: str } ] }`. Mark all listed fields required.

- [ ] **Step 2: Write `trajectory.schema.json`** — a bundle `{ shard: int, feature: str, results: [JourneyResult] }` where `JourneyResult = { journey_id: str, actions: [ { intent, command, exit_code, stdout_tail, stderr_tail, latency_ms, reconcile: {violations:[...]} } ], candidates: [ { kind: "functional"|"latency"|"implicit"|"reconcile_seq", detail, violated_expectation, source, trajectory_ref } ] }`.

- [ ] **Step 3: Write `fixtures/journeys.example.json`** — a 2-journey example matching the schema (reuse the `publish-port-and-reach-it` example from the spec + a simple `create-run-rm-leaves-no-trace`).

- [ ] **Step 4: Write `hack/dogfood/README.md`** — document the two contracts, the local→CI→local flow, and the exact dispatch-branch commands (branch from main, add `journeys.json`, push `dogfood-run/<feature>`, `gh workflow run dogfood.yml --ref ...`, never open a PR).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/schema hack/dogfood/fixtures hack/dogfood/README.md
git commit -m "feat(dogfood): journeys + trajectory file contracts and fixtures"
```

### Task B2: the oracle harness (deterministic, no model)

**Files:**
- Create: `hack/dogfood/oracles.py`
- Test: `hack/dogfood/test_oracles.py` (stdlib `unittest`)

**Interfaces:**
- Produces:
  - `run_action(izba_bin, argv, data_dir, timeout_s) -> Action` — runs one `izba` command, captures `exit_code, stdout_tail, stderr_tail, latency_ms`, then calls `izba __reconcile --json` and attaches `reconcile`.
  - `implicit_oracle(action) -> list[Candidate]` — scrape stderr/stdout tail for `panic`/`assertion failed`/`ERROR`/`thread '...' panicked`; decode exit codes (127, 128+n) into candidates.
  - `latency_oracle(action, budget_ms) -> list[Candidate]` — flag actions over the human-normal budget for their class.
  - `reconcile_seq_oracle(prev_snapshot, cur_snapshot) -> list[Candidate]` — the *sequence* invariants the Rust reconciler can't see in one shot: monotonic (a sandbox's vmm starttime must change if pid is reused; proto never decreases), legal-transition (no `removed→running` without a create), idempotency hints (same op twice changed state).
  - `Candidate`, `Action` dataclasses matching `trajectory.schema.json`.

- [ ] **Step 1: Write failing tests** in `test_oracles.py`

```python
import unittest
from oracles import implicit_oracle, latency_oracle, Action

def act(**kw):
    base = dict(intent="x", command="izba ls", exit_code=0, stdout_tail="",
                stderr_tail="", latency_ms=10, reconcile={"violations": []})
    base.update(kw); return Action(**base)

class OracleTests(unittest.TestCase):
    def test_panic_in_stderr_is_candidate(self):
        c = implicit_oracle(act(stderr_tail="thread 'main' panicked at foo.rs:1"))
        self.assertTrue(any(x.kind == "implicit" for x in c))
    def test_clean_action_no_candidate(self):
        self.assertEqual(implicit_oracle(act()), [])
    def test_latency_over_budget_is_candidate(self):
        c = latency_oracle(act(latency_ms=99999), budget_ms=1000)
        self.assertTrue(any(x.kind == "latency" for x in c))

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify fail**

Run: `cd hack/dogfood && python3 -m unittest test_oracles -v 2>&1 | tail -20`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `oracles.py`** — dataclasses + the four functions above. `run_action` uses `subprocess.run` with `timeout=timeout_s`, measures wall time with `time.monotonic()`, truncates tails to last 4 KB, and shells `izba __reconcile --json` parsing stdout. The scrape patterns: regex `r"panic|assertion failed|^ERROR|^FATAL|thread '.*' panicked|AddressSanitizer"`. Exit-code decode: `127 → CommandNotFound`, `>128 → Signal(code-128)`.

- [ ] **Step 4: Run to verify pass**

Run: `cd hack/dogfood && python3 -m unittest test_oracles -v 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/oracles.py hack/dogfood/test_oracles.py
git commit -m "feat(dogfood): deterministic oracle harness + unit tests"
```

### Task B3: the Actor loop + caps + runner entrypoint

**Files:**
- Create: `hack/dogfood/model.py` (OpenRouter client + a `FakeModel` for tests)
- Create: `hack/dogfood/run_journeys.py` (entrypoint: load journeys shard, loop, write trajectory bundle)
- Test: `hack/dogfood/test_runner.py`

**Interfaces:**
- Consumes: `oracles.run_action/implicit_oracle/latency_oracle/reconcile_seq_oracle`.
- Produces:
  - `model.Model` protocol: `next_command(journey, step, observations) -> {"command": str} | {"done": true}`; `OpenRouterModel(api_key, model_id)` and `FakeModel(script)`.
  - `run_journeys.main(argv)` — args: `--journeys PATH --shard N --shards M --izba-bin PATH --data-dir DIR --out PATH --max-turns --max-usd --step-cap --action-timeout-s [--fake-model SCRIPT]`. Selects this shard's journeys (`i % M == N`), runs each with the Actor loop under all caps, writes the trajectory bundle.

- [ ] **Step 1: Write failing test** (`test_runner.py`) — drive `run_journeys.main` with `--fake-model` whose scripted commands include a deliberately failing one (`izba bogus-subcommand`), against a temp `IZBA_DATA_DIR`, assert the output bundle has a candidate and that the step-cap halts a runaway scripted loop.

- [ ] **Step 2: Run to verify fail.** `cd hack/dogfood && python3 -m unittest test_runner -v` → FAIL.

- [ ] **Step 3: Implement `model.py` + `run_journeys.py`.** Caps: stop a journey at `step_cap` actions; track cumulative est. USD from OpenRouter usage and abort the run at `max_usd`; `max_turns` per journey; per-action `subprocess` timeout; loop-dedup via a `set()` of `(journey_id, command)` hashes — a repeat short-circuits to "done". On any infra error, log and continue (report-only). Write the bundle per `trajectory.schema.json`.

- [ ] **Step 4: Run to verify pass.** Expected PASS.

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/model.py hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "feat(dogfood): actor loop, OpenRouter/fake model, caps, sharded runner"
```

---

## Phase C — the CI fan-out workflow

### Task C1: `dogfood.yml`

**Files:**
- Create: `.github/workflows/dogfood.yml`

**Interfaces:**
- Consumes: `hack/dogfood/run_journeys.py`, the dev build (reuse the e2e/devbuild install path), `journeys.json` on the dispatched ref, secret `OPENROUTER_API_KEY`.

- [ ] **Step 1: Write the workflow** — `on: workflow_dispatch` with inputs `shards` (default `"3"`), `model` (default a cheap OpenRouter id), `max_usd` (default `"2"`). `concurrency: { group: dogfood-${{ github.ref }}, cancel-in-progress: true }`. A `strategy.matrix.shard: [0,1,2]` (generated to match `shards`) of KVM jobs that: check out the dispatched ref (so `journeys.json` is present), build/install izba (mirror `e2e.yml`'s KVM setup), run `python3 hack/dogfood/run_journeys.py --journeys journeys.json --shard ${{ matrix.shard }} --shards ${{ inputs.shards }} --izba-bin <path> --out traj-${{ matrix.shard }}.json --max-usd ${{ inputs.max_usd }} --action-timeout-s 120 --step-cap 25` with `OPENROUTER_API_KEY` from secrets, then `actions/upload-artifact` the `traj-*.json`. `timeout-minutes: 60`. The job must **not** fail on findings — only on infra errors.

- [ ] **Step 2: Validate the workflow YAML.**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/dogfood.yml'))" && echo OK`
(If `actionlint` is available, run it too.)
Expected: `OK`.

- [ ] **Step 3: Optional hardening** — add `branches-ignore: ['dogfood-run/**']` to the `pull_request:` triggers of `ci.yml`, `app.yml`, `coverage.yml`, so an accidental PR off a dispatch branch fires no gates. (Push triggers are already `main`-only — verified — so no change needed there.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/dogfood.yml .github/workflows/ci.yml .github/workflows/app.yml .github/workflows/coverage.yml
git commit -m "ci(dogfood): workflow_dispatch KVM fan-out runner + dispatch-branch guard"
```

---

## Phase D — local Phase 1 & 3 harness (Claude Code)

### Task D1: the dogfooding skill

**Files:**
- Create: `.claude/skills/dogfood/SKILL.md` (or the repo's skill location) documenting the local procedure.

**Interfaces:**
- Produces: a repeatable Claude Code procedure: **Phase 1** — read the feature spec + PR description + Greptile review (via the Greptile MCP) + `izba --help`, emit `journeys.json` per the schema; create `dogfood-run/<feature>` off main, add `journeys.json`, push (no PR), `gh workflow run dogfood.yml --ref ...`, watch the run, download trajectory artifacts. **Phase 3** — load the bundles, run the adversarial skeptic (refute each candidate as intended / self-inflicted), synthesize survivors into `report.md` with bug + violated expectation + source + trajectory; dedup.

- [ ] **Step 1: Write `SKILL.md`** with the two phases as explicit checklists, the journey/ trajectory schema references, the skeptic prompt template (classify real/intended/self-inflicted, with the infinite-`bash`-loop example), and the exact `git`/`gh` commands.

- [ ] **Step 2: Commit**

```bash
git add .claude/skills/dogfood/SKILL.md
git commit -m "feat(dogfood): local Claude Code skill for intent extraction + skeptic"
```

---

## Self-review

- **Spec coverage:** Phase 1 → D1; Phase 2 → B2/B3 + C1; Phase 3 → D1; reconciler → A1–A4; file contracts → B1; handoff/branch → B1 README + C1; non-goals (no kill-9/fuzz/min/GUI/cross-platform) respected — none added. Cross-platform/scheduled/GUI explicitly deferred per spec.
- **Placeholder scan:** all code steps contain real code; the only intentional stub (A1 `let _ = ...`) is removed in A2 with an explicit note.
- **Type consistency:** `ViolationKind`/`Violation`/`SandboxSnapshot`/`ReconcileReport` defined in A1, extended (not renamed) in A2/A3; CLI consumes them unchanged in A4. `Probes`/`PidIdentity`/`SandboxSummary` match the verified codebase signatures. Python `Action`/`Candidate` defined in B2, consumed unchanged in B3.
- **Gate risk:** the reconciler uses only `procmgr::pid_alive` (cross-platform) — no Linux-only `/proc` in core — so the windows-gnu cross gates stay green (A5 verifies).
