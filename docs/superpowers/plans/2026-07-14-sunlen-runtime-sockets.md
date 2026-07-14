# SUN_LEN-proof runtime socket paths (#71, #85) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A sandbox's AF_UNIX runtime sockets never exceed the 108-byte `SUN_LEN` limit for any valid (≤64-char) sandbox name, deep data dirs get a big headroom raise, and a pathologically deep `IZBA_DATA_DIR` fails **early at `create`** with an actionable message instead of a late opaque kernel error at `start`.

**Architecture:** Relocate the per-sandbox runtime (socket) dir from `<root>/sandboxes/<name>/run/` to `<root>/run/<hex8(sha256(name))>/` by changing `Paths::run_dir` itself — every socket path in the codebase (both VMM drivers, egress listener, stream connectors, port relays, the Landlock rule) derives from it on the fly, so the one accessor change propagates everywhere. Upgrade compatibility (the disk-state invariant: upgrading the daemon never harms running sandboxes) is preserved by recording the run dir in `state.json`'s `RunState` (`#[serde(default)]` — absent ⇒ pre-upgrade legacy `<sandbox>/run`) and resolving **live-management** paths through that record. A new create/start-time budget check turns residual over-length roots into an early, actionable error.

**Why this fixes both bugs:**
- **#85**: the sandbox name no longer appears in any socket path (only its 8-hex hash), so every ≤64-char valid name starts successfully — acceptance option (b) "shorten/hash the per-sandbox run-dir socket path".
- **#71**: the fixed overhead drops from `/sandboxes/` + name (≤64) + `/run/` + basename to `/run/` + 8 + `/` + basename, raising the data-dir ceiling from ~28 bytes (worst-case name) to **72 bytes**; roots deeper than that are rejected at `create` (and `start`) with guidance — issue #71's "at minimum" mitigation, on top of the raised ceiling.

**Tech Stack:** Rust workspace (izba-core, izba-cli, izba-ttytest), sha2 (already an izba-core dep), serde disk-state back-compat pattern (mirrors `RunState.confinement`).

## Global Constraints

- All six workspace gates green before every commit: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`. In this worktree first run: `export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo PATH="$CARGO_HOME/bin:$PATH"` (worktrees lack `.cargo-env`).
- **No `DAEMON_PROTO_VERSION` bump** — this change is disk-state only (`RunState` gains a `#[serde(default)]` field); no wire frame changes.
- **Disk-state invariant**: a pre-upgrade `state.json` (no `run_dir` field) must deserialize (`None`) and resolve to the legacy `<sandbox>/run` dir for all live-management paths (egress adoption/rebind, stop, connectors, relays). Start-context paths always use the NEW scheme.
- Unit tests never bind unix/vsock listeners without the house runtime-skip pattern (`PermissionDenied` ⇒ `eprintln!("SKIP …")` + return), and never bind at all when a `UdsStream::pair()` fake suffices.
- Fail loud, never silently degrade (project principle): the budget check is a hard error naming the limit; the hash-collision guard is a hard error naming both sandboxes.
- New socket-path budget: run dir = `<root>/run/<8 hex>`; longest socket basename = `fs-izba-buildout.sock` (21 bytes); budget check enforces `len(<root>) ≤ 72` bytes so the worst socket path stays ≤ 107 bytes (108 incl. NUL).
- Conventional commits; stage exact files (never `git add -A`).
- `RunState` is a public izba-core type embedded by the Tauri app — the controller runs the app gate before the PR (task for the controller, not a subagent).

---

### Task 1: `Paths::run_dir` → hashed runtime dir + `legacy_run_dir`

**Files:**
- Modify: `crates/izba-core/src/paths.rs`
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (convention test only)
- Modify: `crates/izba-ttytest/src/scripted_guest.rs` (sandbox-dir creation no longer implied)
- Tests: in-file `#[cfg(test)]` blocks of the above

**Interfaces:**
- Produces: `Paths::run_dir(&self, name: &str) -> PathBuf` returning `<root>/run/<hex8>` where `hex8` = first 8 lowercase-hex chars of `sha256(name)`; `Paths::legacy_run_dir(&self, name: &str) -> PathBuf` returning `<root>/sandboxes/<name>/run` (the pre-change layout). Later tasks rely on both signatures exactly.

- [ ] **Step 1: Write the failing tests** in `crates/izba-core/src/paths.rs` `mod tests` (replace the `run_dir` assertion inside `layout_composes` with the first block, add the rest as new tests):

```rust
    #[test]
    fn run_dir_is_short_and_name_hashed() {
        let p = Paths::with_root("/data/izba".into());
        let d = p.run_dir("web");
        // `<root>/run/<8 hex>` — the name itself must NOT appear (SUN_LEN, #85).
        assert!(d.starts_with("/data/izba/run"), "{d:?}");
        let leaf = d.file_name().unwrap().to_str().unwrap();
        assert_eq!(leaf.len(), 8, "{leaf}");
        assert!(leaf.chars().all(|c| c.is_ascii_hexdigit()), "{leaf}");
        // Deterministic and per-name unique.
        assert_eq!(d, p.run_dir("web"));
        assert_ne!(d, p.run_dir("web2"));
    }

    #[test]
    fn run_dir_length_is_name_independent() {
        // The #85 guarantee: a max-length (64-char) valid name yields exactly
        // the same socket-path length as a 1-char name.
        let p = Paths::with_root("/data/izba".into());
        let long = "a".repeat(64);
        assert_eq!(
            p.run_dir(&long).as_os_str().len(),
            p.run_dir("b").as_os_str().len()
        );
    }

    #[test]
    fn legacy_run_dir_is_the_pre_hash_layout() {
        let p = Paths::with_root("/data/izba".into());
        assert_eq!(
            p.legacy_run_dir("web"),
            PathBuf::from("/data/izba/sandboxes/web/run")
        );
    }
```

In `layout_composes`, replace the `run_dir("web")` equality assertion with:

```rust
        assert!(p.run_dir("web").starts_with("/data/izba/run"));
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core paths:: -- --nocapture`
Expected: FAIL — `run_dir_is_short_and_name_hashed` (still `sandboxes/web/run`), `legacy_run_dir…` (method missing).

- [ ] **Step 3: Implement** in `crates/izba-core/src/paths.rs` — replace the existing `run_dir` and add the helper + `legacy_run_dir`:

```rust
    /// Per-sandbox runtime (socket) dir: `<root>/run/<hex8(sha256(name))>`.
    ///
    /// Deliberately short and name-length-independent: every AF_UNIX socket a
    /// sandbox needs (hybrid-vsock, egress `_1027`, virtiofsd, CH API) lives
    /// here, and `sun_path` caps the whole path at 108 bytes. Hashing the
    /// name keeps a 64-char valid name from overflowing the cap (#85) and
    /// maximizes the data-dir depth budget (#71). The dir for an
    /// already-running sandbox is recorded in its `state.json` (`RunState::
    /// run_dir`); this accessor is the *start-context* chooser.
    pub fn run_dir(&self, name: &str) -> PathBuf {
        self.root.join("run").join(short_name_hash(name))
    }

    /// The pre-hash runtime-dir layout (`<root>/sandboxes/<name>/run`), kept
    /// only to manage sandboxes started by an older izba: a `state.json`
    /// without `run_dir` resolves here. Never used for new starts.
    pub fn legacy_run_dir(&self, name: &str) -> PathBuf {
        self.sandbox_dir(name).join("run")
    }
```

and at module scope (below the `Paths` impl):

```rust
/// First 8 hex chars of `sha256(name)` — the runtime-dir leaf component.
fn short_name_hash(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(name.as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}
```

- [ ] **Step 4: Fix the two derivation-dependent test/support sites** (they assumed `run_dir` lives under the sandbox dir):

`crates/izba-core/src/daemon/egress/mod.rs`, test `listener_path_follows_vmm_convention` — assert against the accessor instead of a literal `sandboxes/web/run` path:

```rust
    #[test]
    fn listener_path_follows_vmm_convention() {
        let paths = Paths::with_root(PathBuf::from("/data"));
        assert_eq!(
            listener_path(&paths, "web"),
            paths.run_dir("web").join("vsock.sock_1027")
        );
    }
```

`crates/izba-ttytest/src/scripted_guest.rs` (~line 84): `create_dir_all(&run)` no longer implicitly creates the sandbox dir. Add an explicit creation and fix the stale comment:

```rust
        let run = paths.run_dir(&name);
        // run_dir is now `<root>/run/<hash>` — create the sandbox dir (which
        // holds config/state) separately.
        std::fs::create_dir_all(paths.sandbox_dir(&name)).context("create sandbox dir")?;
        std::fs::create_dir_all(&run).context("create run dir")?;
```

(Adapt to the file's actual surrounding code; keep its error-handling style.)

- [ ] **Step 5: Run the whole workspace** — this is the semantic-switch task; most other tests derive from `Paths` and must keep passing unchanged.

Run: `cargo test --workspace`
Expected: PASS. If a test fails because it hardcodes `sandboxes/<name>/run`, update it to derive from `paths.run_dir(...)` — do NOT weaken what it asserts. (Known candidates: `crates/izba-core/src/sandbox.rs` tests around lines 1758/1858/2127/2156, `crates/izba-core/src/vmm/{cloud_hypervisor,openvmm}.rs` argv tests — these already use `paths.run_dir`/`spec.run_dir` and should auto-follow; `crates/izba-cli/tests/*` grep for `run/vsock`.)

- [ ] **Step 6: Gates + commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/paths.rs crates/izba-core/src/daemon/egress/mod.rs crates/izba-ttytest/src/scripted_guest.rs
git commit -m "feat(core): hash the per-sandbox runtime socket dir to <root>/run/<hex8> (#71, #85)"
```

(Include any additional test files updated in Step 5 in the same commit, staged individually.)

---

### Task 2: Socket-path budget check — early, actionable error

**Files:**
- Modify: `crates/izba-core/src/paths.rs` (budget helper + constant)
- Modify: `crates/izba-core/src/sandbox.rs` (`create` + `start_with_timeouts` call it)
- Modify: `crates/izba-cli/src/commands/create.rs`, `crates/izba-cli/src/commands/run.rs` (pre-RPC check, mirrors the #139 `read_policy` placement)
- Create: `crates/izba-cli/tests/create_sunlen_failures.rs` (binary-level, mirrors `create_policy_failures.rs`)

**Interfaces:**
- Consumes: `Paths::run_dir` from Task 1.
- Produces: `pub fn ensure_socket_budget(paths: &Paths, name: &str) -> anyhow::Result<()>` in `crates/izba-core/src/paths.rs`, re-exported or reachable as `izba_core::paths::ensure_socket_budget`; `pub const LONGEST_RUNTIME_SOCKET: &str = "fs-izba-buildout.sock";` in the same module. Later tasks and the CLI call these exactly.

- [ ] **Step 1: Write the failing unit tests** in `crates/izba-core/src/paths.rs` `mod tests`:

```rust
    #[test]
    fn socket_budget_accepts_normal_roots() {
        let p = Paths::with_root("/home/user/.local/share/izba".into());
        ensure_socket_budget(&p, &"a".repeat(64)).unwrap();
    }

    #[test]
    fn socket_budget_rejects_deep_roots_with_actionable_error() {
        // 100-byte root ⇒ worst socket path is well over 107 bytes.
        let deep = format!("/{}", "d".repeat(99));
        let p = Paths::with_root(deep.into());
        let err = format!("{:#}", ensure_socket_budget(&p, "web").unwrap_err());
        // Actionable: names the env var, the byte budget, and the limit —
        // never the raw kernel "SUN_LEN" string alone.
        assert!(err.contains("IZBA_DATA_DIR"), "{err}");
        assert!(err.contains("108"), "{err}");
        assert!(err.contains("72"), "{err}");
    }

    #[test]
    fn socket_budget_boundary_is_exact() {
        // Boundary: worst path = root + "/run/" + 8 + "/" + 21. 107-35 = 72.
        let ok = Paths::with_root(format!("/{}", "r".repeat(71)).into()); // 72 bytes
        ensure_socket_budget(&ok, "web").unwrap();
        let over = Paths::with_root(format!("/{}", "r".repeat(72)).into()); // 73 bytes
        assert!(ensure_socket_budget(&over, "web").is_err());
    }
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p izba-core paths::` — FAIL: `ensure_socket_budget` not found.

- [ ] **Step 3: Implement** in `crates/izba-core/src/paths.rs`:

```rust
/// The longest socket basename any sandbox runtime dir can hold — the
/// virtiofsd socket of the `izba-buildout` share (builder VMs). Grep-anchor:
/// if a longer-named share tag is ever added, update this constant or the
/// budget check silently under-estimates.
pub const LONGEST_RUNTIME_SOCKET: &str = "fs-izba-buildout.sock";

/// AF_UNIX `sun_path` holds at most 108 bytes including the NUL terminator.
const SUN_PATH_MAX: usize = 107;

/// Reject a data root too deep for the VM runtime sockets — early and
/// actionably, instead of the raw "path must be shorter than SUN_LEN" that
/// a bind would produce at start time (#71). The hashed run dir makes the
/// result name-independent, but the check takes `name` so the reported path
/// is the sandbox's real one.
pub fn ensure_socket_budget(paths: &Paths, name: &str) -> anyhow::Result<()> {
    use anyhow::bail;
    let worst = paths.run_dir(name).join(LONGEST_RUNTIME_SOCKET);
    let len = worst.as_os_str().len();
    if len > SUN_PATH_MAX {
        let overhead = len - paths.root().as_os_str().len();
        bail!(
            "data dir too deep for VM runtime sockets: {} would be {len} bytes, \
             but unix socket paths are capped at 108 bytes — \
             use an IZBA_DATA_DIR of at most {} bytes",
            worst.display(),
            SUN_PATH_MAX - overhead,
        );
    }
    Ok(())
}
```

(The `72` the tests assert comes out of `SUN_PATH_MAX - overhead` with the Task-1 layout; do not hardcode 72 in the message.)

- [ ] **Step 4: Run** — `cargo test -p izba-core paths::` — PASS.

- [ ] **Step 5: Wire into core create/start (failing test first).** In `crates/izba-core/src/sandbox.rs` tests (near the existing create tests):

```rust
    #[test]
    fn create_rejects_a_data_root_too_deep_for_sockets() {
        let tmp = tempfile::tempdir().unwrap();
        let deep = tmp.path().join("d".repeat(100));
        let paths = Paths::with_root(deep);
        let err = format!(
            "{:#}",
            create(&paths, "web", &test_create_opts()).unwrap_err()
        );
        assert!(err.contains("IZBA_DATA_DIR"), "{err}");
        // No stub sandbox dir may be left behind (mirrors #139).
        assert!(!paths.sandbox_dir("web").exists());
    }
```

(Use the file's existing create-opts helper — grep for how `create` is called in neighboring tests and reuse that helper; if none exists, build the minimal `CreateOpts` the way the closest test does.)

Then wire: in `create()` right after `validate_name(name)?;` and in `start_with_timeouts()` right after its `validate_name(name)?;`:

```rust
    crate::paths::ensure_socket_budget(paths, name)?;
```

Run: `cargo test -p izba-core sandbox::` — PASS.

- [ ] **Step 6: CLI pre-RPC check + binary-level test.** In `crates/izba-cli/src/commands/create.rs` and `run.rs`, immediately before the daemon connect/Create RPC (the same spot the #139 fix put `read_policy` — grep `read_policy(` in both files and add adjacent):

```rust
    izba_core::paths::ensure_socket_budget(&paths, &name)?;
```

Create `crates/izba-cli/tests/create_sunlen_failures.rs` mirroring `create_policy_failures.rs`'s harness (same `env!("CARGO_BIN_EXE_izba")` + tempdir `IZBA_DATA_DIR` + `IZBA_DAEMON_IDLE_SECS` pattern — copy its scaffolding):

```rust
//! Binary-level: a too-deep IZBA_DATA_DIR fails `create` EARLY (before any
//! daemon RPC), with an actionable message and no stub sandbox dir (#71).

use std::process::Command;

#[test]
fn create_on_deep_data_dir_fails_early_and_leaves_no_stub() {
    let tmp = tempfile::tempdir().unwrap();
    let deep = tmp.path().join("d".repeat(100));
    let out = Command::new(env!("CARGO_BIN_EXE_izba"))
        .args(["create", "web", "--image", "docker.io/library/alpine:3.20"])
        .env("IZBA_DATA_DIR", &deep)
        .env("IZBA_DAEMON_IDLE_SECS", "2")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("IZBA_DATA_DIR"), "stderr: {stderr}");
    assert!(stderr.contains("108"), "stderr: {stderr}");
    assert!(!stderr.contains("SUN_LEN"), "raw kernel error leaked: {stderr}");
    assert!(!deep.join("sandboxes").join("web").exists());
}
```

(Match the real `create` argv of the existing test file — if `--image` differs there, copy its form. If the deep data dir makes the daemon socket path itself exceed SUN_LEN, the pre-RPC check MUST fire before any connect attempt for this test to pass — that ordering is the point.)

Run: `cargo test -p izba-cli --test create_sunlen_failures` — PASS.

- [ ] **Step 7: Gates + commit**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/paths.rs crates/izba-core/src/sandbox.rs crates/izba-cli/src/commands/create.rs crates/izba-cli/src/commands/run.rs crates/izba-cli/tests/create_sunlen_failures.rs
git commit -m "feat(core,cli): reject too-deep data dirs for runtime sockets early with an actionable error (#71)"
```

---

### Task 3: Record `run_dir` in `RunState`; live-path resolver; connectors + relays use it

**Files:**
- Modify: `crates/izba-core/src/state.rs` (`RunState` field)
- Modify: `crates/izba-core/src/sandbox.rs` (`record_run_state`, `live_run_dir`, both connectors)
- Modify: `crates/izba-core/src/daemon/relays.rs` (`spawn_slot`)
- Tests: in-file

**Interfaces:**
- Consumes: `Paths::{run_dir, legacy_run_dir}` (Task 1).
- Produces: `RunState.run_dir: Option<PathBuf>` (serde default); `pub fn live_run_dir(paths: &Paths, name: &str) -> PathBuf` in `crates/izba-core/src/sandbox.rs`. Resolution rule (later tasks rely on it verbatim): *state.json has a `RunState` ⇒ its `run_dir`, or `legacy_run_dir` when the field is absent (pre-upgrade start); no `RunState` at all ⇒ `paths.run_dir(name)` (nothing is running — the next start's dir).*

- [ ] **Step 1: Failing tests.** In `crates/izba-core/src/state.rs` tests:

```rust
    #[test]
    fn run_state_without_run_dir_deserializes_to_none() {
        // A state.json written before the field existed (disk back-compat).
        let json = r#"{
            "vmm_pid": {"pid": 1, "starttime": 2},
            "sidecar_pids": [],
            "started_unix_ms": 3
        }"#;
        let s: RunState = serde_json::from_str(json).unwrap();
        assert_eq!(s.run_dir, None);
    }
```

(Match the real `PidIdentity` JSON shape — copy it from an existing state.rs test or from `PidIdentity`'s definition; adjust field names accordingly.)

In `crates/izba-core/src/sandbox.rs` tests:

```rust
    #[test]
    fn live_run_dir_resolution_precedence() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();

        // 1. No state.json ⇒ the next start's dir (new scheme).
        assert_eq!(live_run_dir(&paths, "web"), paths.run_dir("web"));

        // 2. RunState without run_dir (pre-upgrade start) ⇒ legacy dir.
        let legacy = RunState {
            vmm_pid: PidIdentity { pid: 1, starttime: 2 },
            sidecar_pids: vec![],
            started_unix_ms: 0,
            confinement: None,
            run_dir: None,
        };
        save_json(&paths.sandbox_dir("web").join(STATE_FILE), &legacy).unwrap();
        assert_eq!(live_run_dir(&paths, "web"), paths.legacy_run_dir("web"));

        // 3. RunState with a recorded dir ⇒ exactly that dir.
        let recorded = RunState {
            run_dir: Some(paths.run_dir("web")),
            ..legacy
        };
        save_json(&paths.sandbox_dir("web").join(STATE_FILE), &recorded).unwrap();
        assert_eq!(live_run_dir(&paths, "web"), paths.run_dir("web"));
    }
```

(Match `PidIdentity`'s actual construction — copy from a neighboring test. If `RunState` doesn't `derive(Clone)`, build the third value without `..` struct-update.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p izba-core state:: sandbox::live_run_dir` — FAIL (missing field/function).

- [ ] **Step 3: Implement.**

`crates/izba-core/src/state.rs` — add to `RunState` (below `confinement`):

```rust
    /// The runtime (socket) dir this run's VMM was launched with. `Option` +
    /// `serde(default)` so a `state.json` written before this field still
    /// deserializes — `None` ⇒ the pre-hash legacy `<sandbox>/run` layout,
    /// which is exactly where such a run's sockets live. Live-management
    /// paths (egress rebind/stop, connectors, relays) resolve through
    /// [`crate::sandbox::live_run_dir`], never `Paths::run_dir` directly.
    #[serde(default)]
    pub run_dir: Option<std::path::PathBuf>,
```

`crates/izba-core/src/sandbox.rs` — in `record_run_state`, add to the `RunState` literal:

```rust
        run_dir: Some(paths.run_dir(name)),
```

and add the resolver (near the connectors at the top of the file):

```rust
/// The runtime (socket) dir of the sandbox's CURRENT run: the dir recorded in
/// its `state.json` (a pre-upgrade record without the field means the legacy
/// `<sandbox>/run` layout), or — when nothing is recorded, i.e. nothing is
/// running — the dir the next start will use. Every live-management path
/// (connectors, port relays, egress rebind/stop) must resolve through this,
/// or a daemon upgraded mid-run would look for sockets where the running VMM
/// never put them.
pub fn live_run_dir(paths: &Paths, name: &str) -> PathBuf {
    let state: Option<RunState> = load_json(&paths.sandbox_dir(name).join(STATE_FILE))
        .ok()
        .flatten();
    match state {
        Some(s) => s.run_dir.unwrap_or_else(|| paths.legacy_run_dir(name)),
        None => paths.run_dir(name),
    }
}
```

Switch the two connectors to it (`default_connector` line ~79, `default_stream_connector` line ~94):

```rust
        let sock = live_run_dir(paths, name).join("vsock.sock");
```

`crates/izba-core/src/daemon/relays.rs` `spawn_slot` (~line 178):

```rust
    let vsock = crate::sandbox::live_run_dir(paths, name).join("vsock.sock");
```

- [ ] **Step 4: Run** — `cargo test -p izba-core` — PASS (existing connector/relay tests use fakes or derive paths; fix any that assert the old literal by deriving from `live_run_dir`).

- [ ] **Step 5: Gates + commit**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/state.rs crates/izba-core/src/sandbox.rs crates/izba-core/src/daemon/relays.rs
git commit -m "feat(core): record the runtime dir in state.json and resolve live socket paths through it"
```

---

### Task 4: Egress takes an explicit run dir; server/supervisor pass the right context

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (`listener_path`, `ensure_listening`, `stop`)
- Modify: `crates/izba-core/src/daemon/server.rs` (start-context vs adoption-context call sites + tests)
- Modify: `crates/izba-core/src/daemon/supervisor.rs` (respawn call site + tests)
- Tests: in-file

**Interfaces:**
- Consumes: `live_run_dir` (Task 3), `Paths::run_dir` (Task 1).
- Produces: `pub fn listener_path(run_dir: &Path) -> PathBuf`; `EgressManager::ensure_listening(&self, paths: &Paths, name: &str, run_dir: &Path) -> anyhow::Result<()>`; `EgressManager::stop(&self, name: &str, run_dir: &Path)`. (`paths` stays on `ensure_listening` — `resolve_policy` reads `policy.yaml` from the sandbox dir.)

**Context-passing rule (the heart of this task):** the **Start RPC** binds the listener for the run that is about to launch ⇒ `paths.run_dir(name)` (must match the `VmSpec.run_dir` `sandbox::start` builds — a stale `state.json` from a crashed pre-upgrade run must NOT drag the new bind to the legacy dir). **Adoption at daemon startup and the supervisor's rebind tick** serve already-running VMs ⇒ `live_run_dir(paths, name)`. **Stop** tears down the current run ⇒ `live_run_dir`.

- [ ] **Step 1: Failing tests.** In `crates/izba-core/src/daemon/egress/mod.rs` tests, extend/replace the convention test and add a legacy-dir bind test (house runtime-skip pattern):

```rust
    #[test]
    fn listener_path_follows_vmm_convention() {
        assert_eq!(
            listener_path(Path::new("/data/run/aabbccdd")),
            PathBuf::from("/data/run/aabbccdd/vsock.sock_1027")
        );
    }

    #[test]
    fn ensure_listening_binds_in_the_dir_it_is_given() {
        // Adoption hands a LEGACY dir for pre-upgrade sandboxes; the bind must
        // land exactly there, not in the new hashed dir.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let legacy = paths.legacy_run_dir("web");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        let mgr = test_manager(); // reuse the file's existing constructor helper
        match mgr.ensure_listening(&paths, "web", &legacy) {
            Ok(()) => {}
            Err(e) if is_bind_denied(&e) => {
                eprintln!("SKIP ensure_listening_binds_in_the_dir_it_is_given: bind denied");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(listener_path(&legacy).exists());
        assert!(!listener_path(&paths.run_dir("web")).exists());
        mgr.stop("web", &legacy);
    }
```

(Reuse the file's existing test-manager constructor and its `PermissionDenied` detection helper — grep the existing `ensure_listening_accepts_and_routes` test and mirror its scaffolding exactly; if there's no named helper, inline the same match arms it uses.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p izba-core egress` — FAIL (signature mismatch).

- [ ] **Step 3: Implement the signature changes** in `crates/izba-core/src/daemon/egress/mod.rs`:

```rust
/// Host-side unix path the VMM bridges guest-initiated vsock connections
/// to (Firecracker convention, shared by CH and OpenVMM):
/// `<run dir>/vsock.sock_<port>`. The caller supplies the run dir — the
/// start path passes the new run's dir, adoption/stop pass the LIVE dir
/// recorded in state.json (see `sandbox::live_run_dir`).
pub fn listener_path(run_dir: &Path) -> PathBuf {
    run_dir.join(format!("vsock.sock_{EGRESS_PORT}"))
}
```

In `ensure_listening(&self, paths: &Paths, name: &str, run_dir: &Path)`: replace `let path = listener_path(paths, name);` with `let path = listener_path(run_dir);`, replace the chmod block's `paths.run_dir(name)` with `run_dir`, and create the dir first (the hashed dir may not exist yet on the adoption path):

```rust
        crate::paths::create_dir_700(run_dir, paths.root())
            .with_context(|| format!("creating run dir {}", run_dir.display()))?;
```

(That call replaces the bare chmod: `create_dir_700` already hardens to 0700; keep the existing `#[cfg(unix)]` chmod as well only if the dir may pre-exist with looser perms — it may (created by Task 5's `create`), so KEEP the existing chmod block after the create, switched to `run_dir`.)

In `stop`: signature `pub fn stop(&self, name: &str, run_dir: &Path)`, and `remove_file(listener_path(run_dir))`.

- [ ] **Step 4: Update all callers.**

`crates/izba-core/src/daemon/server.rs`:
- Start handler (~line 478): `d.egress.ensure_listening(&d.paths, &name, &d.paths.run_dir(&name))?;`
- Adoption (~line 775): `let run_dir = crate::sandbox::live_run_dir(&d.paths, &info.name); if let Err(e) = d.egress.ensure_listening(&d.paths, &info.name, &run_dir) { … }`
- Every `d.egress.stop(&d.paths, &name)` call site (grep `egress.stop`): `d.egress.stop(&name, &crate::sandbox::live_run_dir(&d.paths, &name));`
- Tests (~lines 1261/1269): `egress::listener_path(&d.paths.run_dir("web"))` (or the live dir, matching what the test starts).

`crates/izba-core/src/daemon/supervisor.rs` (~line 138):

```rust
            let run_dir = crate::sandbox::live_run_dir(paths, &info.name);
            let _ = egress.ensure_listening(paths, &info.name, &run_dir);
```

and the test at ~line 254 passes `&paths.run_dir("boot")` explicitly.

- [ ] **Step 5: Run** — `cargo test -p izba-core` — PASS.

- [ ] **Step 6: Gates + commit**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/daemon/egress/mod.rs crates/izba-core/src/daemon/server.rs crates/izba-core/src/daemon/supervisor.rs
git commit -m "feat(daemon): egress binds in an explicitly-passed run dir (start=new scheme, adoption/stop=recorded)"
```

---

### Task 5: Lifecycle — create/clear/rm cover the hashed dir; collision guard

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs` (`create`, `clear_run_dir_files`, `cleanup_runtime`, `remove`, `start_with_timeouts`)
- Tests: in-file

**Interfaces:**
- Consumes: everything above.
- Produces: runtime-dir owner marker file name `pub(crate) const RUN_DIR_OWNER: &str = "owner";` — the file inside `<root>/run/<hash>/` holding the owning sandbox's name.

**Semantics:**
1. `create` keeps creating the run dir (now hashed) via `create_dir_700`, then claims it: if `<run>/owner` exists with a DIFFERENT name ⇒ hard error naming both sandboxes (8-hex collision guard — astronomically rare, must be loud, never silent); else write `name` to it.
2. `start_with_timeouts` re-verifies the claim the same way just before building the spec (covers pre-marker dirs: claim-if-absent).
3. `clear_run_dir_files` + `cleanup_runtime` clear socket files in BOTH `paths.run_dir(name)` and `paths.legacy_run_dir(name)` (covers pre-upgrade runs; both are cheap best-effort dir walks) and MUST NOT delete the `owner` marker.
4. `remove` deletes the hashed runtime dir (`remove_dir_all`, NotFound-tolerant) after the tombstone removal — the legacy dir dies with the sandbox dir as before.

- [ ] **Step 1: Failing tests** in `crates/izba-core/src/sandbox.rs` tests:

```rust
    #[test]
    fn create_claims_the_runtime_dir_and_detects_collisions() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        create(&paths, "web", &test_create_opts()).unwrap();
        let owner = paths.run_dir("web").join(RUN_DIR_OWNER);
        assert_eq!(std::fs::read_to_string(&owner).unwrap(), "web");

        // Simulate an 8-hex hash collision: another name's marker in OUR dir.
        std::fs::write(&owner, "impostor").unwrap();
        std::fs::remove_dir_all(paths.sandbox_dir("web")).unwrap();
        let err = format!("{:#}", create(&paths, "web", &test_create_opts()).unwrap_err());
        assert!(err.contains("impostor"), "{err}");
        assert!(err.contains("web"), "{err}");
    }

    #[test]
    fn rm_removes_the_hashed_runtime_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        create(&paths, "web", &test_create_opts()).unwrap();
        assert!(paths.run_dir("web").is_dir());
        let conn = never_connects(); // reuse the file's existing fake connector
        remove(&paths, "web", &conn, false).unwrap();
        assert!(!paths.run_dir("web").exists());
        assert!(!paths.sandbox_dir("web").exists());
    }

    #[test]
    fn cleanup_clears_sockets_in_both_layouts_but_keeps_the_owner_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        create(&paths, "web", &test_create_opts()).unwrap();
        std::fs::create_dir_all(paths.legacy_run_dir("web")).unwrap();
        std::fs::write(paths.run_dir("web").join("vsock.sock"), b"").unwrap();
        std::fs::write(paths.legacy_run_dir("web").join("vsock.sock"), b"").unwrap();
        clear_run_dir_files(&paths, "web");
        assert!(!paths.run_dir("web").join("vsock.sock").exists());
        assert!(!paths.legacy_run_dir("web").join("vsock.sock").exists());
        assert!(paths.run_dir("web").join(RUN_DIR_OWNER).exists());
    }
```

(For `test_create_opts()` / `never_connects()`: reuse the file's existing helpers — grep neighboring create/rm tests (`rm_force_kills_then_deletes` at ~2263) and use exactly their scaffolding names; the snippets above name them generically.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p izba-core sandbox::` — FAIL.

- [ ] **Step 3: Implement.**

Marker + claim helper (near `create`):

```rust
/// Name-claim marker inside a hashed runtime dir: detects an 8-hex hash
/// collision between two sandbox names. Rare enough to never engineer
/// around, common enough across a fleet to refuse LOUDLY instead of letting
/// two sandboxes share sockets.
pub(crate) const RUN_DIR_OWNER: &str = "owner";

/// Create (0700) and claim the hashed runtime dir for `name`. Errors if the
/// dir is already claimed by a different sandbox name.
fn claim_run_dir(paths: &Paths, name: &str) -> anyhow::Result<()> {
    let run = paths.run_dir(name);
    crate::paths::create_dir_700(&run, paths.root())?;
    let marker = run.join(RUN_DIR_OWNER);
    match fs::read_to_string(&marker) {
        Ok(owner) if owner != name => bail!(
            "runtime dir {} is already claimed by sandbox '{owner}' — its name \
             hashes to the same short id as '{name}'; rename one of them",
            run.display()
        ),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::write(&marker, name).with_context(|| format!("writing {}", marker.display()))
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", marker.display())),
    }
}
```

In `create()`'s `populate` closure, replace `crate::paths::create_dir_700(&paths.run_dir(name), paths.root())?;` with `claim_run_dir(paths, name)?;`. In `start_with_timeouts`, after the budget check, add `claim_run_dir(paths, name)?;`.

`clear_run_dir_files` — clear both layouts, keep the marker:

```rust
/// Best-effort removal of socket/pid files in the runtime dir — BOTH the
/// hashed dir and the legacy `<sandbox>/run` (a pre-upgrade run's sockets
/// live there). The `owner` claim marker is preserved.
fn clear_run_dir_files(paths: &Paths, name: &str) {
    for run in [paths.run_dir(name), paths.legacy_run_dir(name)] {
        let Ok(entries) = fs::read_dir(&run) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_name().to_str() == Some(RUN_DIR_OWNER) {
                continue;
            }
            if entry.file_type().map(|t| !t.is_dir()).unwrap_or(false) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}
```

`cleanup_runtime` — same both-layouts loop (keep its error propagation and dir-entry recursion, add the marker skip):

```rust
    for run in [paths.run_dir(name), paths.legacy_run_dir(name)] {
        if !run.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&run)? {
            let entry = entry?;
            if entry.file_name().to_str() == Some(RUN_DIR_OWNER) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
    }
```

`remove()` — after the tombstone `remove_dir_all` block, before the lock-file removal:

```rust
    // The hashed runtime dir lives outside the sandbox dir — remove it too.
    // (NotFound-tolerant: pre-upgrade sandboxes never had one.)
    if let Err(e) = fs::remove_dir_all(paths.run_dir(name)) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "warning: removing runtime dir {} failed: {e}",
                paths.run_dir(name).display()
            );
        }
    }
```

- [ ] **Step 4: Run** — `cargo test -p izba-core sandbox::` — PASS. Then the full crate: `cargo test -p izba-core` — PASS.

- [ ] **Step 5: Gates + commit**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): runtime-dir lifecycle — claim marker, dual-layout cleanup, rm sweep (#71, #85)"
```

---

### Task 6: Windows account grants + Windows validation script

**Files:**
- Modify: `crates/izba-core/src/jail_account/orchestrate.rs` (`compute_grants` + its tests)
- Modify: `hack/spike/validate-izba-windows.ps1` (~line 164)

**Interfaces:**
- Consumes: `Paths::run_dir` (Task 1).
- Produces: nothing new — `compute_grants` return value gains one entry.

**Why:** the locked-down `izba-sb-<name>` Windows account gets Modify on `[workspace, sandbox_dir]` — the hashed runtime dir now lives OUTSIDE `sandbox_dir`, so without a grant the confined OpenVMM cannot bind `vsock.sock` (fail-closed boot failure).

- [ ] **Step 1: Failing test** in `crates/izba-core/src/jail_account/orchestrate.rs` tests (mirror the existing `compute_grants` test's config scaffolding):

```rust
    #[test]
    fn grants_include_the_hashed_runtime_dir() {
        let paths = Paths::with_root(PathBuf::from("/data"));
        let config = test_config(); // the file's existing helper/pattern
        let grants = compute_grants(&config, &paths, "web");
        assert!(grants.contains(&paths.run_dir("web")), "{grants:?}");
        assert!(grants.contains(&paths.sandbox_dir("web")), "{grants:?}");
    }
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p izba-core orchestrate` (adjust the filter to the module's test path) — FAIL.

- [ ] **Step 3: Implement** — in `compute_grants`, change the seed vec and its doc comment:

```rust
    // The hashed runtime dir holds the AF_UNIX sockets the VMM must bind and
    // lives OUTSIDE sandbox_dir (SUN_LEN, #71/#85) — grant it explicitly.
    let mut grants = vec![
        config.workspace.clone(),
        paths.sandbox_dir(name),
        paths.run_dir(name),
    ];
```

(Also update the function's `/// Returns [workspace, sandbox_dir]…` doc line to include the runtime dir.)

- [ ] **Step 4: Update the Windows validation script.** In `hack/spike/validate-izba-windows.ps1` (~line 164), the egress-listener probe hardcodes the legacy path. Replace with the hashed layout (8 hex of SHA-256 over the UTF-8 name):

```powershell
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("egress-a")) |
        ForEach-Object { $_.ToString("x2") }) -join ""
    $runDir = "$env:LOCALAPPDATA\izba\run\$($hash.Substring(0, 8))"
    $egListener = "$runDir\vsock.sock_1027"
```

(Keep the surrounding probe logic and the line-140 comment accurate — update the comment's `run\vsock.sock_1027` wording to the new location.)

- [ ] **Step 5: Gates (including the Windows cross-gates this task exists for) + commit**

```bash
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
git add crates/izba-core/src/jail_account/orchestrate.rs hack/spike/validate-izba-windows.ps1
git commit -m "fix(windows): grant the hashed runtime dir to the sandbox account; update WHP validation probe"
```

---

### Task 7: Documentation + stray-reference sweep

**Files:**
- Modify: `CLAUDE.md` (Load-bearing contracts: "Disk-state invariant" + "vsock ports" bullets)
- Modify: `hack/dogfood/run_journeys.py` (~line 224 comment: the budget rationale cites the old path)
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (module doc `<vsock.sock>_<port>` wording already updated in Task 4 — verify)
- Sweep: `git grep -n "sandboxes/.*run/vsock\|run/vsock.sock" -- ':!docs/superpowers/plans' ':!docs/superpowers/specs'` and fix any remaining live references (historical specs/plans stay untouched).

- [ ] **Step 1: CLAUDE.md.** In the **vsock ports** bullet, update the hybrid-vsock sentence to name the new location and the recorded fallback:

```
  Host reaches them via Cloud Hypervisor hybrid-vsock: `CONNECT <port>\n` on
  the sandbox's runtime socket `<data>/run/<hex8(name)>/vsock.sock` (recorded
  in `state.json` `run_dir`; a pre-upgrade record without the field means the
  legacy `sandboxes/<name>/run/vsock.sock`), …
```

In the **Disk-state invariant** bullet, after the "sandbox = its dir …" sentence, add:

```
  Runtime sockets live OUTSIDE the sandbox dir in a short hashed dir
  (`<data>/run/<hex8(sha256(name))>/`, SUN_LEN budget — #71/#85), claimed by
  an `owner` marker, recorded per-run in `state.json`, and removed by `rm`.
  A data root deeper than the socket budget (~72 bytes) is rejected at
  `create`/`start` with an actionable error, never a raw SUN_LEN bind error.
```

(Integrate with the existing sentence flow — keep the bullet readable, don't just splice.)

- [ ] **Step 2: run_journeys.py comment** (~line 224): the docstring explains the SUN_LEN budget citing `<dir>/sandboxes/<name>/run/vsock.sock_1027`; update the cited path to `<dir>/run/<hex8>/vsock.sock_1027` and note the product now enforces its own budget at create time (the harness cap remains a belt-and-suspenders shortener). Do not change the harness behavior — `hack/dogfood` tests (`python3 -m pytest hack/dogfood/ -q` if available locally; CI runs them) must stay green.

- [ ] **Step 3: Sweep** with the grep above; fix stragglers (README mentions, doc comments). Historical documents under `docs/superpowers/{plans,specs}` are immutable records — leave them.

- [ ] **Step 4: Gates + commit**

```bash
cargo test --workspace && cargo fmt --check
git add CLAUDE.md hack/dogfood/run_journeys.py <any swept files>
git commit -m "docs: runtime-socket relocation — contracts, dogfood budget rationale, stray refs"
```

---

## Post-task verification (controller, not subagents)

1. Final whole-branch review (superpowers final code-reviewer, most capable model).
2. App gate (RunState is a public core type): `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
3. Real-VM suites locally (sandbox disabled): `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1` and `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1` — this change moves the boot datapath's socket layout; static gates alone are not enough.
4. Push, PR (closes #71, #85), CI green, greploop to 5/5 + 0 unresolved, Sonar QG.
