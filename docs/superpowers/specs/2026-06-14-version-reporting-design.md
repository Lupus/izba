# Detailed version reporting across izba components

**Status:** approved (2026-06-14)
**Scope:** embed rich build metadata at compile time and surface it in the CLI,
the daemon, the desktop app, and (minimally) the guest init — so an operator can
always tell *exactly* which build each component is, and in particular spot when
a running `izbad` is a different build than the `izba` CLI / desktop app talking
to it.

## Motivation

Today every component reports only a bare semver (`0.1.0`) from
`CARGO_PKG_VERSION`:

- `izba --version` → `izba 0.1.0` (clap default), no git provenance.
- The daemon exchanges a version string in its hello frame
  (`transport::daemon_version()` → `CARGO_PKG_VERSION`, overridable by
  `IZBA_DAEMON_VERSION`) and the CLI↔daemon handshake compares it
  **exact-string**, auto-restarting the daemon on any mismatch.
- `DaemonStatus.version` is a bare string shown by `izba daemon status`.
- The desktop app surfaces no version at all.

Gaps: no git tag / commit sha / commit date / build date / rustc / target /
profile anywhere; no honest client/server build comparison; exact-string compat
gating conflates "different build" with "wire-incompatible".

## Goals

1. One compile-time source of truth for build metadata, shared by CLI + daemon
   (same binary) and embedded into the desktop app + core library.
2. `izba --version` short one-liner; `izba version` verbose block + `--json`.
3. `izba daemon status` and `izba version` show **both** the daemon build and
   the local CLI build, flagging a mismatch.
4. Desktop app About panel showing App / Core / Daemon builds with a warning
   when app and daemon builds differ.
5. CLI↔daemon **compatibility** gates on a stable wire protocol version, not on
   the (now sha-bearing) display string — a dev rebuild must not churn-restart
   the daemon.
6. Guest init logs its own build to the serial console at boot.

## Non-goals

- Exposing init's version over the control RPC / `izba inspect` (console log
  only for now).
- A version-negotiation / capability-downgrade scheme. Proto mismatch =
  restart the daemon, same as today.
- Auto-update / upgrade prompts.

## Build metadata source of truth

### Mechanism: `vergen-gitcl`

Add a `build.rs` to `izba-core` that uses **vergen-gitcl**. Rationale:

- `build.rs` runs on the **host**, so shelling out to the host `git` works for
  every target (musl static `izba-init`, `x86_64-pc-windows-gnu` cross gate) —
  no target-libgit2 linkage.
- The git CLI resolves `.git` *files* correctly, so it works inside this repo's
  worktrees (this feature is being built in one).
- Graceful when `.git` is absent (release tarball builds): the affected fields
  become empty / `unknown`; vergen honors `VERGEN_*` env overrides so a release
  workflow can stamp `VERGEN_GIT_DESCRIBE` etc. and tagged artifacts still carry
  the tag. (vergen-git2 was considered and rejected: it pulls libgit2 into our
  build-deps for no benefit here.)

Emitted compile-time env vars (via cargo instructions):

| env var | source | example |
| --- | --- | --- |
| `VERGEN_GIT_DESCRIBE` | `git describe --tags --always --dirty` | `v0.1.0-rc1-3-g9f0d480-dirty` |
| `VERGEN_GIT_SHA` | full commit sha | `9f0d480...` |
| `VERGEN_GIT_COMMIT_DATE` | commit date | `2026-06-14` |
| `VERGEN_BUILD_TIMESTAMP` | build time (UTC) | `2026-06-14T10:00:00Z` |
| `VERGEN_RUSTC_SEMVER` | rustc version | `1.96.0` |
| `VERGEN_CARGO_TARGET_TRIPLE` | target | `x86_64-unknown-linux-gnu` |
| `VERGEN_CARGO_DEBUG` / opt-level | profile | `release` |

Semver always comes from `CARGO_PKG_VERSION` (reliable with or without git).
All git/build fields are read with `option_env!` so a missing var degrades to
`"unknown"` rather than failing the build.

### `izba_core::build_info` module

```rust
/// Compile-time build metadata. All fields resolve at build time; git/build
/// fields fall back to "unknown" when unavailable (e.g. tarball builds).
pub struct BuildInfo {
    pub pkg_version: &'static str,   // CARGO_PKG_VERSION
    pub git_describe: &'static str,  // VERGEN_GIT_DESCRIBE or "unknown"
    pub git_sha: &'static str,
    pub git_sha_short: &'static str, // first 9 of git_sha, or "unknown"
    pub commit_date: &'static str,
    pub build_timestamp: &'static str,
    pub rustc: &'static str,
    pub target: &'static str,
    pub profile: &'static str,
}

impl BuildInfo {
    pub const fn current() -> Self { /* env!/option_env! */ }
    pub fn short(&self) -> String;  // "0.1.0 (9f0d480)"
    pub fn long(&self) -> String;   // multi-line block
    pub fn to_owned(&self) -> BuildInfoOwned;
}

/// Wire/serde form (sent over the daemon protocol, returned to the app UI).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct BuildInfoOwned { /* same fields as String */ }
```

`short()` → `0.1.0 (9f0d480)`. `long()` →

```
izba 0.1.0
 git:     v0.1.0-rc1-3-g9f0d480 (dirty)
 commit:  9f0d480abc... 2026-06-14
 built:   2026-06-14T10:00:00Z
 rustc:   1.96.0   target: x86_64-unknown-linux-gnu
 profile: release
```

**Testability:** `short()`/`long()`/`to_owned()` take `&self`, so tests
construct a `BuildInfo` with injected literal fields and assert on formatting —
never on real git state. This mirrors the existing
`transport::version_from(env_fn)` injection pattern.

## Wire protocol: compatibility vs display (load-bearing contract)

This changes the hello frame on **both** ends plus the client decision logic —
all-ends-or-none per the daemon contract.

- New `pub const DAEMON_PROTO_VERSION: u32 = 1;` in `izba-core::daemon::proto`
  (co-located with the frame types). Bumped **only** on wire-breaking changes.
- `DaemonHello` gains `proto: u32`. Its existing `version: String` now carries
  `BuildInfo::short()` for logging/diagnostics (display, not gating).
- `DaemonResponse::HelloOk` gains `proto: u32` and `build: BuildInfoOwned`. The
  existing `version: String` field is **retained** (set to `build.short()`) for
  one release so a freshly-upgraded CLI talking to a not-yet-restarted old
  daemon still deserializes — additive change, old daemon simply omits the new
  fields which deserialize via `#[serde(default)]`.
- `DaemonClient` gains `server_build: BuildInfoOwned` and `server_proto: u32`
  alongside the existing `server_version`.
- **Compatibility gate** in `connect_with`: compare `server_proto` to the
  client's `DAEMON_PROTO_VERSION` instead of comparing version strings. On proto
  mismatch → existing restart-once-then-bail flow (message updated to cite
  proto + both build strings). On equal proto with differing build string → **no
  restart**; the difference is surfaced for display only.

Back-compat: an old daemon (no `proto` field) deserializes `proto` as `0` via
`#[serde(default)]`; `0 != 1` → the new CLI restarts it once, which upgrades it
to the new binary. Correct and self-healing.

## DaemonStatus enrichment

`DaemonStatus` gains `build: BuildInfoOwned` and `proto: u32` (keep `version:
String` = `build.short()` for one release). `izba daemon status` renders the
daemon build and, beneath it, the invoking CLI's own build, plus a `⚠ daemon
and CLI builds differ` line when `daemon.build != BuildInfo::current()`.

## CLI surfaces

- `izba --version`: override clap's version with `BuildInfo::current().short()`
  via `#[command(version = ...)]` (a `const`/`&str` built once). →
  `izba 0.1.0 (9f0d480)`.
- New `izba version` subcommand:
  - default: prints `BuildInfo::current().long()`; if a daemon is reachable
    (best-effort, non-fatal connect), also prints the daemon build + a mismatch
    note (docker-style `Client:` / `Daemon:`).
  - `--json`: emits `{ "cli": BuildInfoOwned, "daemon": BuildInfoOwned|null,
    "proto": u32, "mismatch": bool }`.

## Desktop app

- `app/src-tauri/build.rs`: extend the existing `tauri_build::build()` with
  vergen-gitcl so the **app binary** carries its own git/build info; app semver
  stays `CARGO_PKG_VERSION` (== `tauri.conf.json` version). The linked **core**
  build comes from `izba_core::build_info::BuildInfo::current()`.
- New Tauri command `version_info` → returns
  `{ app: BuildInfoOwned, core: BuildInfoOwned, daemon: Option<BuildInfoOwned>,
  proto: u32, mismatch: bool }`. `daemon`/`proto`/`mismatch` come through the
  existing `DaemonApi` seam via a new `fn version(&mut self) ->
  anyhow::Result<DaemonVersion>` (daemon status build + proto). `FakeDaemon`
  gains a canned build for tests; `mismatch = app.build != daemon.build`.
- Frontend: a new **About** panel/component listing App / Core / Daemon builds
  (describe + commit date) with a warning banner when `mismatch`. Reached from
  the existing view chrome (a header/footer "About" affordance).

## Guest init (minimal)

`izba-init` is a standalone static-musl binary that does not link `izba-core`,
so it gets its own tiny `build.rs` (same vergen-gitcl emit) and logs
`izba-init <git_describe> (built <timestamp>)` to the serial console early in
`main.rs` boot. This lands in `logs/console.log` and aids boot debugging. No
control-protocol field. Init must remain a static musl build — vergen only adds
a host build-dependency, so the static link is unaffected (verified by the
existing `cargo build -p izba-init --target x86_64-unknown-linux-musl` gate).

## Testing

- `build_info`: unit tests on `short()`/`long()`/`to_owned()` with injected
  literal fields (no real-git assertions). `BuildInfoOwned` serde round-trip.
- Handshake (`daemon/server.rs` + `client.rs` tests): proto match → no restart;
  proto mismatch → restart-once-then-bail; **equal proto + differing build
  string → no restart** (the key new behavior); `HelloOk`/`DaemonHello`
  round-trip with the new fields; old-frame (missing `proto`) deserializes to
  `proto=0`.
- CLI: `izba version --json` shape test (serde structure), mismatch flag logic
  with a fake daemon build.
- App: `version_core` returns app/core/daemon + correct `mismatch` via
  `FakeDaemon` (matching and differing daemon builds).
- Gates: all six CLAUDE.md gates green, including `cargo check`/`clippy
  --target x86_64-pc-windows-gnu` (vergen is a host build-dep — must not break
  the cross gate) and the musl `izba-init` build.

## Risks / decisions

- **vergen-gitcl vs vergen-git2:** chose gitcl (host git, no libgit2 in
  build-deps, worktree- and cross-friendly, graceful without `.git`).
- **Additive wire fields with `#[serde(default)]`:** lets a new CLI handshake an
  old running daemon without a frame-version dance; the proto-0 default triggers
  exactly one self-healing restart.
- **Keeping `version: String` for one release:** smooth rollover; can be dropped
  once no pre-change daemons exist in the wild.
- **Build churn:** adding `build.rs` to `izba-core` + `izba-init` means they
  rebuild when git HEAD moves. Acceptable; vergen emits the right
  `cargo:rerun-if-changed` hooks.
