# Detailed Version Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or
> superpowers:subagent-driven-development to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Embed rich build metadata (git describe/sha/commit-date, build date,
rustc, target, profile) at compile time and surface it across the CLI, daemon,
desktop app, and guest init — with the CLI↔daemon compatibility check gating on
a stable wire protocol version rather than the display string.

**Architecture:** A `build_info` module in `izba-core` backed by a
`vergen-gitcl` `build.rs` is the single source of truth for CLI + daemon (same
binary) and the linked core version in the app. The daemon hello frame carries a
`proto: u32` (compat gate) plus a structured `BuildInfoOwned` (display). The app
gets its own vergen `build.rs` and a `version_info` Tauri command; init gets a
tiny vergen `build.rs` and logs its build to console at boot.

**Tech Stack:** Rust, vergen-gitcl, clap, serde, Tauri 2, React/TypeScript.

**Toolchain note (worktree):** `.cargo-env` uses `$PWD`; from a worktree export
the absolute root paths instead:
```bash
export RUSTUP_HOME=/home/kolkhovskiy/git/izba/.toolchain/rustup
export CARGO_HOME=/home/kolkhovskiy/git/izba/.toolchain/cargo
export PATH=/home/kolkhovskiy/git/izba/.toolchain/cargo/bin:$PATH
```

---

### Task 1: `build_info` module + vergen build.rs in izba-core

**Files:**
- Create: `crates/izba-core/build.rs`
- Create: `crates/izba-core/src/build_info.rs`
- Modify: `crates/izba-core/Cargo.toml` (add `[build-dependencies] vergen-gitcl`)
- Modify: `crates/izba-core/src/lib.rs` (add `pub mod build_info;`)

- [ ] **Step 1: Add vergen build-dependency**

In `crates/izba-core/Cargo.toml`, add:
```toml
[build-dependencies]
vergen-gitcl = { version = "1", features = ["build", "cargo", "rustc"] }
```

- [ ] **Step 2: Write build.rs**

`crates/izba-core/build.rs`:
```rust
use vergen_gitcl::{BuildBuilder, CargoBuilder, Emitter, GitclBuilder, RustcBuilder};

fn main() {
    // Best-effort: a missing `.git` (release tarball) must not fail the build —
    // vergen still emits the non-git fields; git fields become absent and the
    // module's option_env! falls back to "unknown".
    let mut emitter = Emitter::default();
    let _ = emitter.add_instructions(&BuildBuilder::all_build().unwrap());
    let _ = emitter.add_instructions(&CargoBuilder::all_cargo().unwrap());
    let _ = emitter.add_instructions(&RustcBuilder::all_rustc().unwrap());
    if let Ok(gitcl) = GitclBuilder::default()
        .describe(true, true, None) // tags, dirty, no match pattern
        .sha(false)
        .commit_date(true)
        .build()
    {
        let _ = emitter.add_instructions(&gitcl);
    }
    emitter.emit().unwrap();
}
```

- [ ] **Step 3: Write the build_info module with injected-field tests first**

`crates/izba-core/src/build_info.rs`:
```rust
//! Compile-time build metadata, the single source of truth shared by the CLI,
//! the daemon (same binary), and — via the linked library — the desktop app.
//! Git/build fields resolve through `option_env!` so a build without `.git`
//! (release tarball) degrades to "unknown" instead of failing to compile.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug)]
pub struct BuildInfo {
    pub pkg_version: &'static str,
    pub git_describe: &'static str,
    pub git_sha: &'static str,
    pub commit_date: &'static str,
    pub build_timestamp: &'static str,
    pub rustc: &'static str,
    pub target: &'static str,
    pub profile: &'static str,
}

const fn or_unknown(v: Option<&'static str>) -> &'static str {
    match v {
        Some(s) => s,
        None => "unknown",
    }
}

impl BuildInfo {
    pub const fn current() -> Self {
        BuildInfo {
            pkg_version: env!("CARGO_PKG_VERSION"),
            git_describe: or_unknown(option_env!("VERGEN_GIT_DESCRIBE")),
            git_sha: or_unknown(option_env!("VERGEN_GIT_SHA")),
            commit_date: or_unknown(option_env!("VERGEN_GIT_COMMIT_DATE")),
            build_timestamp: or_unknown(option_env!("VERGEN_BUILD_TIMESTAMP")),
            rustc: or_unknown(option_env!("VERGEN_RUSTC_SEMVER")),
            target: or_unknown(option_env!("VERGEN_CARGO_TARGET_TRIPLE")),
            profile: or_unknown(option_env!("VERGEN_CARGO_OPT_LEVEL")),
        }
    }

    /// First 9 chars of the sha, or "unknown".
    pub fn sha_short(&self) -> &str {
        if self.git_sha == "unknown" {
            "unknown"
        } else {
            &self.git_sha[..self.git_sha.len().min(9)]
        }
    }

    /// One-liner for `--version`: `0.1.0 (9f0d480)`.
    pub fn short(&self) -> String {
        format!("{} ({})", self.pkg_version, self.sha_short())
    }

    /// Multi-line block for `izba version`.
    pub fn long(&self) -> String {
        format!(
            "izba {}\n git:     {}\n commit:  {} {}\n built:   {}\n rustc:   {}   target: {}\n profile: {}",
            self.pkg_version,
            self.git_describe,
            self.sha_short(),
            self.commit_date,
            self.build_timestamp,
            self.rustc,
            self.target,
            self.profile,
        )
    }

    pub fn to_owned(&self) -> BuildInfoOwned {
        BuildInfoOwned {
            pkg_version: self.pkg_version.into(),
            git_describe: self.git_describe.into(),
            git_sha: self.git_sha.into(),
            commit_date: self.commit_date.into(),
            build_timestamp: self.build_timestamp.into(),
            rustc: self.rustc.into(),
            target: self.target.into(),
            profile: self.profile.into(),
        }
    }
}

/// Wire/serde form sent over the daemon protocol and returned to the app UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfoOwned {
    pub pkg_version: String,
    pub git_describe: String,
    pub git_sha: String,
    pub commit_date: String,
    pub build_timestamp: String,
    pub rustc: String,
    pub target: String,
    pub profile: String,
}

impl BuildInfoOwned {
    pub fn current() -> Self {
        BuildInfo::current().to_owned()
    }
    pub fn sha_short(&self) -> &str {
        if self.git_sha == "unknown" {
            "unknown"
        } else {
            &self.git_sha[..self.git_sha.len().min(9)]
        }
    }
    pub fn short(&self) -> String {
        format!("{} ({})", self.pkg_version, self.sha_short())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BuildInfo {
        BuildInfo {
            pkg_version: "0.1.0",
            git_describe: "v0.1.0-rc1-3-g9f0d480",
            git_sha: "9f0d480abcdef",
            commit_date: "2026-06-14",
            build_timestamp: "2026-06-14T10:00:00Z",
            rustc: "1.96.0",
            target: "x86_64-unknown-linux-gnu",
            profile: "3",
        }
    }

    #[test]
    fn short_is_semver_and_short_sha() {
        assert_eq!(sample().short(), "0.1.0 (9f0d480)");
    }

    #[test]
    fn sha_short_handles_unknown() {
        let mut b = sample();
        b.git_sha = "unknown";
        assert_eq!(b.sha_short(), "unknown");
    }

    #[test]
    fn long_contains_all_fields() {
        let s = sample().long();
        for needle in ["0.1.0", "v0.1.0-rc1-3-g9f0d480", "2026-06-14", "1.96.0", "x86_64-unknown-linux-gnu"] {
            assert!(s.contains(needle), "long() missing {needle}: {s}");
        }
    }

    #[test]
    fn owned_roundtrips_through_serde() {
        let owned = sample().to_owned();
        let json = serde_json::to_string(&owned).unwrap();
        let back: BuildInfoOwned = serde_json::from_str(&json).unwrap();
        assert_eq!(owned, back);
    }

    #[test]
    fn current_builds_and_short_is_nonempty() {
        // Smoke: the real env-backed constructor compiles and produces something.
        assert!(!BuildInfo::current().short().is_empty());
    }
}
```

Add to `crates/izba-core/src/lib.rs` (with the other `pub mod` lines):
```rust
pub mod build_info;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-core build_info`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/build.rs crates/izba-core/src/build_info.rs crates/izba-core/src/lib.rs crates/izba-core/Cargo.toml
git commit -m "feat(core): build_info module with vergen-gitcl build metadata"
```

---

### Task 2: Proto version constant + enriched hello/status frames

**Files:**
- Modify: `crates/izba-core/src/daemon/proto.rs` (add const, extend `DaemonHello`, `HelloOk`, `DaemonStatus`)

- [ ] **Step 1: Write the round-trip test (extend existing `tests` in proto.rs)**

Add to the `tests` mod in `crates/izba-core/src/daemon/proto.rs`:
```rust
#[test]
fn hello_ok_carries_proto_and_build() {
    let resp = DaemonResponse::HelloOk {
        version: "0.1.0 (9f0d480)".into(),
        proto: DAEMON_PROTO_VERSION,
        build: crate::build_info::BuildInfoOwned::current(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let back: DaemonResponse = serde_json::from_str(&json).unwrap();
    matches!(back, DaemonResponse::HelloOk { proto, .. } if proto == DAEMON_PROTO_VERSION);
}

#[test]
fn old_hello_without_proto_defaults_to_zero() {
    // An old daemon's frame had only {"type":"hello_ok","version":"x"}.
    let json = r#"{"type":"hello_ok","version":"old"}"#;
    let back: DaemonResponse = serde_json::from_str(json).unwrap();
    match back {
        DaemonResponse::HelloOk { proto, version, .. } => {
            assert_eq!(proto, 0);
            assert_eq!(version, "old");
        }
        other => panic!("expected HelloOk, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core hello`
Expected: FAIL to compile (`DAEMON_PROTO_VERSION`, `proto`, `build` unknown).

- [ ] **Step 3: Add the const and extend the frames**

In `crates/izba-core/src/daemon/proto.rs`:
```rust
use crate::build_info::BuildInfoOwned;

/// Wire-protocol version exchanged in the hello frame. The CLI↔daemon
/// **compatibility** gate compares this (NOT the display version string).
/// Bump only on a wire-breaking change to any daemon frame.
pub const DAEMON_PROTO_VERSION: u32 = 1;
```

Extend `DaemonHello`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonHello {
    /// Display string (BuildInfo::short()); kept for logs/back-compat.
    pub version: String,
    /// Compatibility gate. Absent (old client) → 0 via serde default.
    #[serde(default)]
    pub proto: u32,
}
```

Extend `HelloOk` (in `DaemonResponse`):
```rust
    HelloOk {
        version: String,
        #[serde(default)]
        proto: u32,
        #[serde(default)]
        build: BuildInfoOwned,
    },
```

Extend `DaemonStatus`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    #[serde(default)]
    pub proto: u32,
    #[serde(default)]
    pub build: BuildInfoOwned,
    pub pid: u32,
    pub uptime_ms: u64,
    pub socket: String,
    pub sandboxes: Vec<SandboxSummary>,
}
```

Add a `Default` impl for `BuildInfoOwned` (needed by `#[serde(default)]`) in
`build_info.rs`:
```rust
impl Default for BuildInfoOwned {
    fn default() -> Self {
        BuildInfo {
            pkg_version: "unknown",
            git_describe: "unknown",
            git_sha: "unknown",
            commit_date: "unknown",
            build_timestamp: "unknown",
            rustc: "unknown",
            target: "unknown",
            profile: "unknown",
        }
        .to_owned()
    }
}
```

Update the existing proto.rs `tests` that construct `HelloOk { version }` /
`DaemonStatus { .. }` to include the new fields (use
`..Default::default()`-style explicit fields or set `proto: 0, build:
Default::default()`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-core -- proto`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/proto.rs crates/izba-core/src/build_info.rs
git commit -m "feat(proto): add DAEMON_PROTO_VERSION + build info to hello/status frames"
```

---

### Task 3: Client compat gate on proto; expose server build

**Files:**
- Modify: `crates/izba-core/src/daemon/client.rs` (struct fields, handshake, `connect_with`)
- Modify: `crates/izba-core/src/daemon/transport.rs` (keep `daemon_version`, used for display hello)

- [ ] **Step 1: Write the test — equal proto + differing build does NOT restart**

In `crates/izba-core/src/daemon/client.rs` tests (or server.rs handshake tests
where the spawner seam lives), add a test asserting that when the server's proto
equals the client's `DAEMON_PROTO_VERSION` but the display version differs, the
client returns Ok without invoking the spawner/restart. Mirror the existing
`connect_with` test harness (injected spawner + `my_version`). Add a parallel
test that a proto mismatch still triggers exactly one restart then bail.

(Concretely: extend the existing version-mismatch test so the handshake now
turns on `proto`. The injected fake server must answer `HelloOk { proto, build,
version }`.)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core -- client`
Expected: FAIL (fields/logic missing).

- [ ] **Step 3: Implement**

`DaemonClient` struct — add fields:
```rust
pub struct DaemonClient {
    conn: UdsStream,
    pub server_version: String,
    pub server_proto: u32,
    pub server_build: crate::build_info::BuildInfoOwned,
}
```

In `handshake`, parse the new `HelloOk` fields and store them; send
`DaemonHello { version: BuildInfo::current().short(), proto: DAEMON_PROTO_VERSION }`
(replace the `my_version`-string hello — keep `my_version` param for the display
string but always send the local proto).

In `connect_with`, change the compatibility predicate from
`client.server_version == my_version` to
`client.server_proto == DAEMON_PROTO_VERSION`. Update the bail/eprintln messages
to cite proto + both build short strings, e.g.:
```rust
if client.server_proto == DAEMON_PROTO_VERSION {
    return Ok(client);
}
// ... on mismatch:
eprintln!(
    "izba: daemon proto {} != CLI {} (daemon {}); restarting daemon",
    client.server_proto, DAEMON_PROTO_VERSION, client.server_build.short()
);
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p izba-core -- daemon`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/client.rs crates/izba-core/src/daemon/transport.rs
git commit -m "feat(daemon): gate CLI/daemon compatibility on proto version, expose server build"
```

---

### Task 4: Server populates build/proto in hello + status

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` (HelloOk + Status construction, `DaemonDeps`)

- [ ] **Step 1: Adjust failing server tests**

The existing server tests construct `HelloOk { version }` and a `DaemonStatus`.
Update them to expect `proto: DAEMON_PROTO_VERSION` and a `build`. Add a test
that `Status` reply carries `proto == DAEMON_PROTO_VERSION`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-core -- server`
Expected: FAIL.

- [ ] **Step 3: Implement**

Where the server writes `HelloOk` (server.rs ~200, ~411), set:
```rust
&DaemonResponse::HelloOk {
    version: d.deps.version.clone(),
    proto: crate::daemon::proto::DAEMON_PROTO_VERSION,
    build: crate::build_info::BuildInfoOwned::current(),
}
```
Where it builds `DaemonStatus`, add `proto: DAEMON_PROTO_VERSION` and
`build: BuildInfoOwned::current()`. Leave `DaemonDeps.version` as-is (still the
display string from `transport::daemon_version()`), now also set to
`BuildInfo::current().short()` in `production()` for a richer default.

- [ ] **Step 4: Run tests + full core suite**

Run: `cargo test -p izba-core`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-core/src/daemon/server.rs
git commit -m "feat(daemon): server reports proto + build in hello and status"
```

---

### Task 5: CLI `--version` short + `izba version` subcommand

**Files:**
- Modify: `crates/izba-cli/src/main.rs` (clap version override, new `Version` subcommand)
- Create: `crates/izba-cli/src/commands/version.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs` (register)
- Modify: `crates/izba-cli/src/commands/daemon.rs` (status rendering shows build + mismatch)

- [ ] **Step 1: Write the JSON-shape test**

`crates/izba-cli/src/commands/version.rs` tests:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_payload_has_cli_and_mismatch_fields() {
        let cli = izba_core::build_info::BuildInfoOwned::current();
        let payload = VersionJson { cli: cli.clone(), daemon: None, proto: 1, mismatch: false };
        let s = serde_json::to_string(&payload).unwrap();
        assert!(s.contains("\"cli\""));
        assert!(s.contains("\"daemon\":null"));
        assert!(s.contains("\"mismatch\":false"));
    }

    #[test]
    fn mismatch_true_when_builds_differ() {
        let cli = izba_core::build_info::BuildInfoOwned::current();
        let mut other = cli.clone();
        other.git_sha = "deadbeef0".into();
        assert!(builds_differ(&cli, &other));
        assert!(!builds_differ(&cli, &cli));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p izba-cli version`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement the version command**

`crates/izba-cli/src/commands/version.rs`:
```rust
use izba_core::build_info::{BuildInfo, BuildInfoOwned};
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, DAEMON_PROTO_VERSION};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use serde::Serialize;

#[derive(Serialize)]
pub struct VersionJson {
    pub cli: BuildInfoOwned,
    pub daemon: Option<BuildInfoOwned>,
    pub proto: u32,
    pub mismatch: bool,
}

pub fn builds_differ(a: &BuildInfoOwned, b: &BuildInfoOwned) -> bool {
    a != b
}

/// Best-effort daemon build: only an already-running daemon (never auto-start).
fn daemon_build(paths: &Paths) -> Option<BuildInfoOwned> {
    let client = DaemonClient::connect_existing(paths).ok().flatten()?;
    Some(client.server_build.clone())
}

pub fn run(paths: &Paths, json: bool) -> anyhow::Result<()> {
    let cli = BuildInfo::current().to_owned();
    let daemon = daemon_build(paths);
    let mismatch = daemon.as_ref().map(|d| builds_differ(&cli, d)).unwrap_or(false);

    if json {
        let payload = VersionJson { cli, daemon, proto: DAEMON_PROTO_VERSION, mismatch };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("Client:\n{}", BuildInfo::current().long());
    match &daemon {
        Some(d) => {
            println!("\nDaemon:\n izba {}\n git: {}\n commit: {} {}", d.pkg_version, d.git_describe, d.sha_short(), d.commit_date);
            if mismatch {
                println!("\n⚠ daemon and CLI builds differ");
            }
        }
        None => println!("\nDaemon: not running"),
    }
    Ok(())
}
```

Register in `crates/izba-cli/src/commands/mod.rs`: `pub mod version;`

In `crates/izba-cli/src/main.rs`:
- Override clap version:
```rust
#[command(
    name = "izba",
    version = izba_core::build_info::BuildInfo::current().short_static(),
    about = "Run coding agents in microVM sandboxes"
)]
```
clap needs a `&'static str`. Since `short()` allocates, add a
`Lazy`/`OnceLock` `&'static str`, OR simpler: use a small helper returning a
leaked static, OR set `version` via `.version()` on the built `Command`. The
cleanest with derive: add to `main.rs`:
```rust
fn version_string() -> &'static str {
    use std::sync::OnceLock;
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| izba_core::build_info::BuildInfo::current().short()).as_str()
}
```
and use `#[command(version = version_string())]` (clap accepts an expression).
- Add `Version { #[arg(long)] json: bool }` to the `Cmd` enum and dispatch to
  `commands::version::run(&paths, json)`.

- [ ] **Step 4: Run tests + manual check**

Run: `cargo test -p izba-cli version`
Expected: PASS.
Run: `cargo run -p izba-cli -- --version` and `cargo run -p izba-cli -- version`
Expected: short line; multi-line block.

- [ ] **Step 5: Show build + mismatch in `izba daemon status`**

In `crates/izba-cli/src/commands/daemon.rs` status rendering, after printing the
daemon status, print `daemon build` (`status.build.short()` + describe) and the
local `BuildInfo::current().short()`, with a `⚠ daemon and CLI builds differ`
line when they differ. (Read the file first to match its print style.)

- [ ] **Step 6: Commit**

```bash
git add crates/izba-cli/src/main.rs crates/izba-cli/src/commands/version.rs crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/commands/daemon.rs
git commit -m "feat(cli): short --version + verbose 'izba version' with daemon build comparison"
```

---

### Task 6: Desktop app — vergen build.rs + version_info command

**Files:**
- Modify: `app/src-tauri/build.rs` (add vergen alongside tauri_build)
- Modify: `app/src-tauri/Cargo.toml` (vergen build-dep)
- Modify: `app/src-tauri/src/daemon.rs` (DaemonApi `version()`)
- Modify: `app/src-tauri/src/fake.rs` (FakeDaemon build)
- Modify: `app/src-tauri/src/commands.rs` (`version_core`)
- Modify: `app/src-tauri/src/views.rs` (`VersionView`)
- Modify: `app/src-tauri/src/lib.rs` (register `version_info` command)

- [ ] **Step 1: Write `version_core` test (commands.rs tests, via FakeDaemon)**

```rust
#[test]
fn version_core_flags_mismatch_when_daemon_differs() {
    let mut d = FakeDaemon { daemon_sha: "deadbeef".into(), ..Default::default() };
    let v = version_core(&mut d).unwrap();
    assert!(v.mismatch);
    assert!(!v.app.git_describe.is_empty());
}

#[test]
fn version_core_no_mismatch_when_daemon_absent() {
    let mut d = FakeDaemon { daemon_absent: true, ..Default::default() };
    let v = version_core(&mut d).unwrap();
    assert!(!v.mismatch);
    assert!(v.daemon.is_none());
}
```

- [ ] **Step 2: Run to verify failure**

Run (app crate is outside the workspace):
```bash
cargo test --manifest-path app/src-tauri/Cargo.toml version_core
```
Expected: FAIL.

- [ ] **Step 3: Implement**

`app/src-tauri/Cargo.toml` build-deps:
```toml
[build-dependencies]
tauri-build = { version = "2", features = [] }
vergen-gitcl = { version = "1", features = ["build", "cargo", "rustc"] }
```

`app/src-tauri/build.rs`:
```rust
use vergen_gitcl::{BuildBuilder, CargoBuilder, Emitter, GitclBuilder, RustcBuilder};

fn main() {
    tauri_build::build();
    let mut emitter = Emitter::default();
    let _ = emitter.add_instructions(&BuildBuilder::all_build().unwrap());
    let _ = emitter.add_instructions(&CargoBuilder::all_cargo().unwrap());
    let _ = emitter.add_instructions(&RustcBuilder::all_rustc().unwrap());
    if let Ok(gitcl) = GitclBuilder::default().describe(true, true, None).sha(false).commit_date(true).build() {
        let _ = emitter.add_instructions(&gitcl);
    }
    emitter.emit().unwrap();
}
```

App's own BuildInfo: the app embeds its own vergen env vars, so add a tiny
`app_build_info()` in `views.rs` mirroring `BuildInfo::current()` but reading the
app crate's env vars (these are the app's, not core's, because build.rs runs per
crate). Reuse `izba_core::build_info::BuildInfoOwned` as the struct.

`views.rs`:
```rust
use izba_core::build_info::BuildInfoOwned;

#[derive(serde::Serialize)]
pub struct VersionView {
    pub app: BuildInfoOwned,
    pub core: BuildInfoOwned,
    pub daemon: Option<BuildInfoOwned>,
    pub proto: u32,
    pub mismatch: bool,
}

pub fn app_build_info() -> BuildInfoOwned {
    BuildInfoOwned {
        pkg_version: env!("CARGO_PKG_VERSION").into(),
        git_describe: option_env!("VERGEN_GIT_DESCRIBE").unwrap_or("unknown").into(),
        git_sha: option_env!("VERGEN_GIT_SHA").unwrap_or("unknown").into(),
        commit_date: option_env!("VERGEN_GIT_COMMIT_DATE").unwrap_or("unknown").into(),
        build_timestamp: option_env!("VERGEN_BUILD_TIMESTAMP").unwrap_or("unknown").into(),
        rustc: option_env!("VERGEN_RUSTC_SEMVER").unwrap_or("unknown").into(),
        target: option_env!("VERGEN_CARGO_TARGET_TRIPLE").unwrap_or("unknown").into(),
        profile: option_env!("VERGEN_CARGO_OPT_LEVEL").unwrap_or("unknown").into(),
    }
}
```

`daemon.rs` — add to the `DaemonApi` trait + `RealDaemon`:
```rust
/// (build, proto) of the connected daemon.
fn version(&mut self) -> anyhow::Result<(BuildInfoOwned, u32)>;
```
`RealDaemon::version` uses `with_client` to read `c.server_build` + `c.server_proto`
(exposed already by the client). Since handshake already captured them, this can
return them without a new request:
```rust
fn version(&mut self) -> anyhow::Result<(BuildInfoOwned, u32)> {
    self.with_client(|c| Ok((c.server_build.clone(), c.server_proto)))
}
```

`fake.rs` — `FakeDaemon` fields `daemon_sha: String`, `daemon_absent: bool`, and
`version()` returns a canned build (or errors when `daemon_absent`).

`commands.rs`:
```rust
pub fn version_core(d: &mut dyn DaemonApi) -> Result<VersionView, String> {
    let app = crate::views::app_build_info();
    let core = izba_core::build_info::BuildInfoOwned::current();
    let (daemon, proto, mismatch) = match d.version() {
        Ok((b, p)) => { let m = b != app; (Some(b), p, m) }
        Err(_) => (None, 0, false),
    };
    Ok(VersionView { app, core, daemon, proto, mismatch })
}
```

`lib.rs` — add `#[tauri::command] async fn version_info(...)` calling
`commands::version_core`, register in `generate_handler!`.

- [ ] **Step 4: Run tests**

Run: `cargo test --manifest-path app/src-tauri/Cargo.toml`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/src-tauri/build.rs app/src-tauri/Cargo.toml app/src-tauri/src/
git commit -m "feat(app): version_info command exposing app/core/daemon builds"
```

---

### Task 7: App frontend About panel

**Files:**
- Create: `app/src/components/About.tsx`
- Modify: `app/src/App.tsx` (an "About" affordance opening the panel)
- Modify/Create: `app/src/lib/` (typed `versionInfo()` invoke wrapper)
- Test: `app/src/test/` (component/render test if the suite supports it)

- [ ] **Step 1: Read existing component + invoke patterns**

Read `app/src/App.tsx`, an existing component in `app/src/components/`, and
`app/src/lib/` to match the `invoke`/typing/styling conventions and the test
setup (vitest/RTL).

- [ ] **Step 2: Write a render test (if a frontend test harness exists)**

A test that renders `<About>` with a mocked `versionInfo()` returning app !=
daemon and asserts the warning text appears. Follow the existing test pattern in
`app/src/test/`.

- [ ] **Step 3: Implement About.tsx**

Component invokes `version_info`, renders App / Core / Daemon describe + commit
date, and shows a warning banner when `mismatch`. Wire an "About" button in the
app chrome (header/footer) to toggle it. Match the existing Calm-Indigo light
theme classes.

- [ ] **Step 4: Run frontend tests + typecheck**

Run: `cd app && npm test` (or the project's script) and `npm run build`/`tsc`.
Expected: PASS / typechecks.

- [ ] **Step 5: Commit**

```bash
git add app/src/
git commit -m "feat(app): About panel comparing app, core, and daemon builds"
```

---

### Task 8: Guest init logs its build to console

**Files:**
- Create: `crates/izba-init/build.rs`
- Modify: `crates/izba-init/Cargo.toml` (vergen build-dep)
- Modify: `crates/izba-init/src/main.rs` (log build line early in boot)

- [ ] **Step 1: Add build.rs + dep**

`crates/izba-init/Cargo.toml`:
```toml
[build-dependencies]
vergen-gitcl = { version = "1", features = ["build", "cargo", "rustc"] }
```
`crates/izba-init/build.rs`: same body as Task 1 Step 2.

- [ ] **Step 2: Log the build line in main.rs**

Early in `main()` boot (after the console/serial is usable — read main.rs to find
the first logging point), emit:
```rust
let describe = option_env!("VERGEN_GIT_DESCRIBE").unwrap_or("unknown");
let built = option_env!("VERGEN_BUILD_TIMESTAMP").unwrap_or("unknown");
println!("izba-init {} {} (built {})", env!("CARGO_PKG_VERSION"), describe, built);
```
(Match the existing logging macro/style in main.rs — it may use a specific
logger rather than `println!`.)

- [ ] **Step 3: Build static musl to confirm the static link is intact**

Run:
```bash
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
```
Expected: builds; binary stays static (vergen is host-only build-dep).

- [ ] **Step 4: Commit**

```bash
git add crates/izba-init/build.rs crates/izba-init/Cargo.toml crates/izba-init/src/main.rs
git commit -m "feat(init): log build version to serial console at boot"
```

---

### Task 9: Full gate sweep + docs

**Files:**
- Modify: `CLAUDE.md` crate map note if needed (mention `build_info`), `README` version note (optional)

- [ ] **Step 1: Run all six CLAUDE.md gates**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```
Expected: all green. (vergen is a host build-dep; the windows-gnu cross gate
must stay green — if vergen pulls a target-incompatible dep, pin features to
`build,cargo,rustc` only, which it already is.)

- [ ] **Step 2: App crate checks (outside workspace)**

```bash
cargo test  --manifest-path app/src-tauri/Cargo.toml
cargo clippy --manifest-path app/src-tauri/Cargo.toml --all-targets -- -D warnings
```

- [ ] **Step 3: Commit any doc tweaks**

```bash
git add CLAUDE.md
git commit -m "docs: note build_info module in crate map"
```

---

## Self-review notes

- **Spec coverage:** §build-source → T1/T6/T8; §wire proto → T2/T3/T4; §status →
  T4/T5; §CLI → T5; §app → T6/T7; §init → T8; §testing → tests in each task +
  T9 gates. All covered.
- **Type consistency:** `BuildInfoOwned` (core) reused everywhere; `VersionView`
  (app) vs `VersionJson` (cli) intentionally distinct (app adds `app`+`core`,
  cli has only `cli`). `server_build`/`server_proto` named consistently across
  client→app.
- **Cross gate risk:** vergen-gitcl features limited to `build,cargo,rustc`
  (+default git) — no networking/tls; build.rs is host-only so windows-gnu
  target is unaffected. Verified in T9.
- **clap version:** `&'static str` via `OnceLock` leak-free helper (T5).
