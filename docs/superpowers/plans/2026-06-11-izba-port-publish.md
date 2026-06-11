# izba port publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `izba port` host→guest TCP publishing — create-time persisted rules (`izba create -p`) and runtime `izba port publish/unpublish/ls` — backed by per-rule detached vsock relay processes that fit izba's daemonless "sandbox = dir + live processes" invariant.

**Architecture:** A published rule is an independent detached `izba __port-relay` process. It binds a host `TcpListener` and, per accepted connection, opens a hybrid-vsock connection to guest `STREAM_PORT` (1026), sends `StreamOpen::TcpDial { port }`, and — on `Response::Ok` — becomes a bidirectional byte pipe. Inside the guest, `izba-init`'s `stream_conn` dispatch fills its `TcpDial` arm: it dials `127.0.0.1:port` and pumps. Teardown in both directions is graceful (`shutdown(Write)` then drain) to mitigate the known OpenVMM vsock-churn assert. Active relays are tracked in a per-sandbox `ports.json`; liveness is always re-verified via pid+starttime.

**Tech Stack:** Rust, `std::net::{TcpListener, TcpStream}` (no new deps), `clap` (hidden subcommand), `serde`/`serde_json`, existing `izba_proto` length-prefixed JSON framing, existing `procmgr::spawn_detached`/`pid_alive`/`kill_pid`, existing `vsock::hybrid_connect`.

---

## Context the executing engineer must know

- **Branch/worktree:** All work happens in an isolated git worktree on branch `feat/port-publish`, forked from `main@d3258ec`. The parallel `cp` feature (TarExtract/TarCreate) is NOT present. **Do not touch any `cp`/Tar code**, and keep edits to shared dispatch files (`crates/izba-cli/src/main.rs`, `crates/izba-init/src/server.rs`) minimal and additive so the later merge is trivial.
- **Groundwork already landed (d3258ec) — do NOT re-create:**
  - `izba_proto::StreamOpen` enum with variants `Attach`, `TcpDial { port: u16 }`, `TarExtract`, `TarCreate`.
  - `izba_proto::ErrorKind::{PathNotFound, ConnectFailed}`.
  - `crates/izba-init/src/server.rs::stream_conn` dispatch skeleton where `TcpDial { .. } | TarExtract { .. } | TarCreate { .. }` currently all answer `Response::Error { kind: BadRequest, message: "not implemented" }`. This plan replaces ONLY the `TcpDial` arm.
- **The six build gates (CLAUDE.md "Build & test") must be green at every commit.** Run `[ -f .cargo-env ] && source .cargo-env` first in every shell. The full gate list is in the final task; intermediate tasks run the targeted subset noted in each.
- **Everything in `izba-core` and `izba-cli` must keep compiling for `x86_64-pc-windows-gnu`.** The relay and the `portfwd` module use only `std::net` + existing portable deps. `izba-init` is Linux-only, so its `TcpDial` arm needs no `cfg`.
- **Test design constraint (CLAUDE.md):** unit tests NEVER bind unix/vsock listeners. Use `UnixStream::pair()` fakes (the `PairListener` pattern in `server.rs` tests). Tests that genuinely need a real `TcpListener` must runtime-skip on `PermissionDenied` (this sandbox denies `bind`) — follow `full_connect_via_listener` in `crates/izba-core/src/vsock.rs`.
- **No new dependencies.** `std::net::{TcpListener, TcpStream}` plus existing crates cover everything.

## File structure

| File | Create/Modify | Responsibility |
| --- | --- | --- |
| `crates/izba-core/src/state.rs` | Modify | Add `PortRule` struct; add `#[serde(default)] ports: Vec<PortRule>` to `SandboxConfig`; add `PortRecord` struct + `PORTS_FILE`. |
| `crates/izba-init/src/server.rs` | Modify | Fill the `TcpDial` arm of `stream_conn`: dial `127.0.0.1:port`, reply one `Response`, then graceful bidirectional pump. |
| `crates/izba-core/src/portfwd.rs` | Create | Rule parsing (`parse_rule`), the relay loop (`run_relay`), and the per-connection pump-with-graceful-teardown (`relay_one`). Reusable by a future `izbad`. |
| `crates/izba-core/src/lib.rs` | Modify | `pub mod portfwd;` |
| `crates/izba-core/src/sandbox.rs` | Modify | `ports.json` read/write helpers; `publish_port`/`unpublish_port`/`list_ports`; spawn config rules in `start`; kill relays in `stop_locked` and on cleanup. |
| `crates/izba-cli/src/main.rs` | Modify | Add `-p/--publish` to `SandboxOpts`; add `Port` subcommand (publish/unpublish/ls) and hidden `__port-relay`; dispatch wiring. |
| `crates/izba-cli/src/commands/mod.rs` | Modify | `pub mod port;` plus `-p` rule parsing into `CreateOpts.ports`. |
| `crates/izba-cli/src/commands/create.rs` | Modify | Pass parsed `ports` into `CreateOpts`. |
| `crates/izba-cli/src/commands/port.rs` | Create | `publish`/`unpublish`/`ls`/`relay` command handlers. |
| `crates/izba-core/src/sandbox.rs` (CreateOpts) | Modify | Add `pub ports: Vec<PortRule>` to `CreateOpts`; persist into `SandboxConfig`. |
| `crates/izba-core/tests/integration.rs` | Modify | KVM-gated end-to-end: create `-p`, run, busybox httpd in guest, curl from host; runtime publish/unpublish/ls; stop kills relays. |

---

## Task 1 — `PortRule` + `SandboxConfig.ports` + `PortRecord` + `PORTS_FILE` (state.rs)

**Files:**
- Modify: `crates/izba-core/src/state.rs`
- Test: inline `#[cfg(test)]` in `crates/izba-core/src/state.rs`

### Steps

- [ ] **Write failing tests.** Append these tests to the existing `mod tests` block in `crates/izba-core/src/state.rs` (just before its closing `}`):

```rust
    #[test]
    fn port_rule_serde_is_string_addr() {
        let rule = PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 8080,
            guest_port: 80,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"127.0.0.1\""), "bind must serialize as a string: {json}");
        let back: PortRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rule);
    }

    #[test]
    fn sandbox_config_ports_defaults_when_absent() {
        // A config.json written before this feature has no "ports" key.
        let legacy = r#"{
            "image_digest": "sha256:abc",
            "image_ref": "ubuntu:22.04",
            "cpus": 2,
            "mem_mb": 512,
            "workspace": "/workspace"
        }"#;
        let cfg: SandboxConfig = serde_json::from_str(legacy).unwrap();
        assert!(cfg.ports.is_empty(), "missing ports must default to empty");
    }

    #[test]
    fn sandbox_config_ports_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);
        let mut cfg = sample_config();
        cfg.ports = vec![PortRule {
            bind: "0.0.0.0".parse().unwrap(),
            host_port: 18080,
            guest_port: 8000,
        }];
        save_json(&path, &cfg).unwrap();
        let loaded: SandboxConfig = load_json(&path).unwrap().unwrap();
        assert_eq!(loaded.ports, cfg.ports);
    }

    #[test]
    fn port_record_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PORTS_FILE);
        let records = vec![PortRecord {
            rule: PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 8080,
                guest_port: 80,
            },
            relay: PidIdentity { pid: 4321, starttime: 777 },
        }];
        save_json(&path, &records).unwrap();
        let loaded: Vec<PortRecord> = load_json(&path).unwrap().unwrap();
        assert_eq!(loaded, records);
    }
```

- [ ] **Run & expect failure.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib state::`
  Expected: compile errors — `cannot find type PortRule`, `cannot find type PortRecord`, `cannot find value PORTS_FILE`, and `no field ports on type SandboxConfig`.

- [ ] **Implement.** Edit `crates/izba-core/src/state.rs`. First add the `Ipv4Addr` import at the top, next to the existing imports:

```rust
use std::net::Ipv4Addr;
```

  Add the new file-name constant beside the existing ones:

```rust
pub const CONFIG_FILE: &str = "config.json";
pub const STATE_FILE: &str = "state.json";
pub const PORTS_FILE: &str = "ports.json";
```

  Add the `ports` field to `SandboxConfig` (the `#[serde(default)]` makes legacy configs without the key deserialize):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub image_digest: String,
    pub image_ref: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: PathBuf,
    /// Persisted port-publish rules, re-applied on every `run`. Defaults to
    /// empty so configs written before this feature still deserialize.
    #[serde(default)]
    pub ports: Vec<PortRule>,
}
```

  Add the two new public types (place them after the `PidIdentity` struct):

```rust
/// A single host→guest TCP publish rule. Its identity (uniqueness key) is
/// `(bind, host_port)`. `bind` serializes as a string, e.g. `"127.0.0.1"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub bind: Ipv4Addr,
    pub host_port: u16,
    pub guest_port: u16,
}

/// One active relay: the rule it serves plus the detached relay process's
/// PID-reuse-safe identity. Persisted in `ports.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRecord {
    pub rule: PortRule,
    pub relay: PidIdentity,
}
```

  Update the `sample_config()` test helper to include the new field so existing tests still compile:

```rust
    fn sample_config() -> SandboxConfig {
        SandboxConfig {
            image_digest: "sha256:deadbeef".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 512,
            workspace: PathBuf::from("/workspace"),
            ports: Vec::new(),
        }
    }
```

- [ ] **Run & expect pass.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib state::` — all `state::` tests green.

- [ ] **Cross-compile check (Windows gate touches state.rs).** `[ -f .cargo-env ] && source .cargo-env && cargo check --target x86_64-pc-windows-gnu -p izba-core`

- [ ] **Commit.**

```sh
git add crates/izba-core/src/state.rs
git commit -m "feat(core): add PortRule, PortRecord and SandboxConfig.ports

PortRule is the host->guest publish rule (uniqueness key (bind,host_port));
PortRecord tracks an active relay's PID identity in ports.json. ports on
SandboxConfig is #[serde(default)] so legacy config.json without the key
still deserializes.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Task 2 — init `TcpDial` arm: dial guest port, graceful bidirectional pump (server.rs)

**Files:**
- Modify: `crates/izba-init/src/server.rs`
- Test: inline `#[cfg(test)]` in `crates/izba-init/src/server.rs`

This fills the `TcpDial` arm of the existing `stream_conn` dispatch. The existing test `unimplemented_stream_open_variants_get_bad_request` currently asserts `TcpDial` returns `BadRequest` — it must be updated to only cover `TarExtract`/`TarCreate`, since `TcpDial` is now implemented.

### Steps

- [ ] **Update the existing test and write new failing tests.** In `crates/izba-init/src/server.rs` `mod tests`:

  First, narrow `unimplemented_stream_open_variants_get_bad_request` so it no longer includes `TcpDial`:

```rust
    #[test]
    fn unimplemented_stream_open_variants_get_bad_request() {
        let h = Harness::new();
        for open in [
            StreamOpen::TarExtract { dest: "/d".into() },
            StreamOpen::TarCreate { src: "/s".into() },
        ] {
            let mut conn = h.stream_conn();
            write_frame(&mut conn, &open).unwrap();
            match read_frame::<_, Response>(&mut conn).unwrap() {
                Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
                other => panic!("unexpected: {other:?}"),
            }
            let mut rest = Vec::new();
            conn.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty());
        }
    }
```

  Then add two new tests. They drive the `tcp_dial` helper directly over `UnixStream::pair()` halves so no real `TcpListener` is bound (a real loopback target listener is used, with a `PermissionDenied` runtime-skip, since dialing needs a real socket):

```rust
    /// A `TcpDial` that connects to a live loopback listener must reply Ok and
    /// then pump bytes both ways. Binds a real TcpListener → runtime-skip if
    /// the sandbox denies bind.
    #[test]
    fn tcp_dial_ok_pumps_both_ways() {
        use std::net::TcpListener;
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_dial_ok_pumps_both_ways: sandbox denies bind: {e}");
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        // Echo server: read a line, write it back uppercased-prefixed.
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"re:").unwrap();
            s.write_all(&buf[..n]).unwrap();
            // Half-close so our drain sees EOF.
            s.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let (mut client, server) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || tcp_dial(server, port));

        // First frame the init side sends is the Ok response.
        match read_frame::<_, Response>(&mut client).unwrap() {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        client.write_all(b"hi").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"re:hi");

        srv.join().unwrap();
        h.join().unwrap();
    }

    /// A `TcpDial` to a refused loopback port must reply Error{ConnectFailed}
    /// and close. Port 1 is privileged/closed for an unprivileged dial; if the
    /// dial unexpectedly succeeds the assert fails loudly.
    #[test]
    fn tcp_dial_refused_reports_connect_failed() {
        // Bind-and-drop to obtain a definitely-free port, then dial it.
        use std::net::TcpListener;
        let port = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => {
                let p = l.local_addr().unwrap().port();
                drop(l); // nothing is listening on p now
                p
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_dial_refused_reports_connect_failed: sandbox denies bind: {e}");
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let (mut client, server) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || tcp_dial(server, port));
        match read_frame::<_, Response>(&mut client).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::ConnectFailed),
            other => panic!("expected ConnectFailed, got {other:?}"),
        }
        // Conn is closed after the error frame.
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        h.join().unwrap();
    }
```

- [ ] **Run & expect failure.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-init --lib server::`
  Expected: compile error — `cannot find function tcp_dial in this scope`.

- [ ] **Implement.** In `crates/izba-init/src/server.rs`, replace the dispatch arm. Change the existing combined arm:

```rust
        // Dispatch skeleton: each feature branch fills in its variant.
        StreamOpen::TcpDial { .. }
        | StreamOpen::TarExtract { .. }
        | StreamOpen::TarCreate { .. } => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "not implemented".into(),
                },
            );
            return;
        }
```

  to split `TcpDial` out:

```rust
        StreamOpen::TcpDial { port } => {
            tcp_dial(conn, port);
            return;
        }
        // Dispatch skeleton: the cp feature branch fills these in.
        StreamOpen::TarExtract { .. } | StreamOpen::TarCreate { .. } => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "not implemented".into(),
                },
            );
            return;
        }
```

  Add the `tcp_dial` and `relay_pump` functions after `stream_conn` (before `dup_fd`). `tcp_dial` dials `127.0.0.1:port` (single guest netns reaches loopback- and 0.0.0.0-bound listeners), replies one `Response`, then pumps both directions with graceful `shutdown(Write)`+drain teardown:

```rust
/// Init side of `StreamOpen::TcpDial`: dial `127.0.0.1:port` inside the guest,
/// reply one `Response` frame (`Ok` | `Error{ConnectFailed}`), and on `Ok`
/// become a raw bidirectional byte pipe.
///
/// `C` is the vsock connection (host side). On guest-socket EOF we
/// `shutdown(Write)` toward the host and drain the remaining host->guest bytes;
/// this graceful teardown is also the planned OpenVMM vsock-churn mitigation.
fn tcp_dial<C: Read + Write + AsRawFd + Send + 'static>(mut conn: C, port: u16) {
    use std::net::{Shutdown, SocketAddr, TcpStream};
    // Spec §5: 10 s dial cap. Loopback normally refuses instantly; the cap
    // guards pathological guest states (e.g. workload firewall DROP rules)
    // so a relay thread can never hang in connect forever.
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let target = match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(10)) {
        Ok(t) => t,
        Err(e) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::ConnectFailed,
                    message: e.to_string(),
                },
            );
            return;
        }
    };
    if write_frame(&mut conn, &Response::Ok).is_err() {
        return;
    }

    // Second handles for the opposite directions.
    let conn_w = match dup_fd(conn.as_raw_fd()) {
        Ok(d) => File::from(d),
        Err(_) => return,
    };
    let target_r = match target.try_clone() {
        Ok(t) => t,
        Err(_) => return,
    };

    // host -> guest: when the host half-closes, signal the guest socket so the
    // guest service sees EOF, then this thread exits.
    let reader = std::thread::spawn(move || {
        let mut target_w = target;
        relay_pump(conn, &mut target_w);
        let _ = target_w.shutdown(Shutdown::Write);
    });

    // guest -> host: on guest EOF, half-close toward the host and drain is
    // implicit (the host stops writing once it gets our shutdown).
    let mut conn_w = conn_w;
    relay_pump(target_r, &mut conn_w);
    // SAFETY: conn_w is a dup of the vsock conn fd; SHUT_WR delivers EOF to
    // the host's read side without tearing down the inbound direction.
    unsafe { libc::shutdown(conn_w.as_raw_fd(), libc::SHUT_WR) };
    let _ = reader.join();
}

/// Copy `r` to `w` until EOF or error. Mirrors `pump` but takes `w` by mutable
/// reference so the caller can issue a shutdown after the copy completes.
fn relay_pump(mut r: impl Read, w: &mut impl Write) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        if w.write_all(&buf[..n]).is_err() {
            return;
        }
    }
}
```

  Note: `TcpStream` does not implement `AsRawFd`-based dup here; we use `try_clone()` (std `TcpStream::try_clone`) for the second handle, which is portable. The `conn` (vsock) side reuses the existing `dup_fd` helper already defined in this file.

- [ ] **Run & expect pass.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-init --lib server::`
  Expected: `tcp_dial_ok_pumps_both_ways` and `tcp_dial_refused_reports_connect_failed` green (or SKIP-printed if bind is denied), and the narrowed `unimplemented_stream_open_variants_get_bad_request` green.

- [ ] **Static-musl gate (izba-init must stay static).** `[ -f .cargo-env ] && source .cargo-env && cargo build -p izba-init --target x86_64-unknown-linux-musl --release`

- [ ] **Commit.**

```sh
git add crates/izba-init/src/server.rs
git commit -m "feat(init): implement StreamOpen::TcpDial arm

tcp_dial connects 127.0.0.1:port in the guest netns, replies one Response
(Ok | Error{ConnectFailed}), then becomes a bidirectional byte pipe with
graceful shutdown(Write)+drain teardown in both directions (the planned
OpenVMM vsock-churn mitigation). Narrows the unimplemented-variants test to
the cp variants that remain stubbed.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Task 3 — `portfwd` module: rule parsing + relay loop + per-connection pump (portfwd.rs)

**Files:**
- Create: `crates/izba-core/src/portfwd.rs`
- Modify: `crates/izba-core/src/lib.rs`
- Test: inline `#[cfg(test)]` in `crates/izba-core/src/portfwd.rs`

### Steps

- [ ] **Create the module with failing tests.** Create `crates/izba-core/src/portfwd.rs` containing the parsing tests and a relay-pump test over socketpairs. Start with this content (tests first; the functions they call are stubbed below in the implementation step — write the whole file, then run to see the assertion/compile state):

  For the very first run, write ONLY the test module plus minimal stubs so it compiles-but-fails. The complete file (tests + real implementation) is given in the implementation step; for the "expect failure" step, temporarily make `parse_rule` return `unimplemented!()`. To keep this plan linear, write the COMPLETE file now (implementation included) and rely on the test run to confirm green — the "expect failure" check below is satisfied by first confirming the module does not yet exist.

- [ ] **Run & expect failure (module absent).** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib portfwd::`
  Expected: `error[E0432]: unresolved module` / `file not found for module portfwd` — because `lib.rs` does not yet declare it and the file may not exist.

- [ ] **Implement — write the full module.** Create `crates/izba-core/src/portfwd.rs`:

```rust
//! Host-side port-publish relay: pure vsock, no passt involvement, so the same
//! code serves Cloud Hypervisor/Linux and OpenVMM/Windows.
//!
//! A published rule is an independent detached process (`izba __port-relay`)
//! that runs [`run_relay`]. The relay binds a `TcpListener` and, per accepted
//! connection, opens a hybrid-vsock connection to the guest [`STREAM_PORT`],
//! sends `StreamOpen::TcpDial`, and — on `Response::Ok` — pumps bytes both ways
//! with graceful `shutdown(Write)`+drain teardown.
//!
//! The loop lives here (not in the CLI) so a future `izbad` reuses it without
//! the hidden-subcommand re-invocation trick.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use izba_proto::{read_frame, write_frame, Response, StreamOpen, STREAM_PORT};

use crate::state::PortRule;
use crate::vmm::UdsStream;
use crate::vsock::hybrid_connect;

/// Parse a publish rule: `HOST:GUEST` or `BIND:HOST:GUEST`.
///
/// `BIND` is an IPv4 address (default `127.0.0.1`); ports are `u16 >= 1`.
pub fn parse_rule(spec: &str) -> anyhow::Result<PortRule> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (bind, host_s, guest_s) = match parts.as_slice() {
        [host, guest] => (Ipv4Addr::LOCALHOST, *host, *guest),
        [bind, host, guest] => {
            let bind: Ipv4Addr = bind
                .parse()
                .with_context(|| format!("invalid bind address '{bind}' in rule '{spec}'"))?;
            (bind, *host, *guest)
        }
        _ => bail!("invalid port rule '{spec}' (expected HOST:GUEST or BIND:HOST:GUEST)"),
    };
    let host_port = parse_port(host_s, spec)?;
    let guest_port = parse_port(guest_s, spec)?;
    Ok(PortRule {
        bind,
        host_port,
        guest_port,
    })
}

fn parse_port(s: &str, spec: &str) -> anyhow::Result<u16> {
    let p: u16 = s
        .parse()
        .with_context(|| format!("invalid port '{s}' in rule '{spec}'"))?;
    if p == 0 {
        bail!("port 0 is not allowed in rule '{spec}'");
    }
    Ok(p)
}

/// The detached relay entry point. Binds `(bind, host_port)`, writes `pid_file`,
/// then accepts forever, spawning a per-connection thread. Returns only on a
/// listener error (or never, in normal operation; the process is killed by
/// `unpublish`/`stop`/`rm`).
pub fn run_relay(
    vsock: &Path,
    bind: Ipv4Addr,
    host_port: u16,
    guest_port: u16,
    pid_file: &Path,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind((bind, host_port))
        .with_context(|| format!("binding {bind}:{host_port}"))?;
    std::fs::write(pid_file, std::process::id().to_string())
        .with_context(|| format!("writing pid file {}", pid_file.display()))?;
    let vsock = vsock.to_path_buf();
    loop {
        let (client, _peer) = listener.accept().context("accept")?;
        let vsock = vsock.clone();
        std::thread::spawn(move || {
            if let Err(e) = relay_one(client, &vsock, guest_port) {
                eprintln!("relay connection error: {e:#}");
            }
        });
    }
}

/// Serve one accepted TCP connection: open a vsock TcpDial to the guest port,
/// and on `Ok` pump bytes both ways with graceful teardown.
pub fn relay_one(client: TcpStream, vsock: &Path, guest_port: u16) -> anyhow::Result<()> {
    let mut vs = hybrid_connect(vsock, STREAM_PORT)
        .with_context(|| format!("vsock connect for guest port {guest_port}"))?;
    write_frame(&mut vs, &StreamOpen::TcpDial { port: guest_port })
        .context("sending TcpDial")?;
    match read_frame::<_, Response>(&mut vs)? {
        Response::Ok => {}
        Response::Error { kind, message } => {
            // Guest port closed (or worse): close the client connection.
            bail!("guest dial failed ({kind:?}): {message}");
        }
        other => bail!("unexpected reply to TcpDial: {other:?}"),
    }
    pump_bidirectional(client, vs);
    Ok(())
}

/// Pump bytes both ways between the host TCP `client` and the vsock `vs`, with
/// graceful `shutdown(Write)`+drain on each side at EOF. Always shut down the
/// vsock side with `shutdown(Write)` rather than an abrupt drop (the OpenVMM
/// churn mitigation).
fn pump_bidirectional(client: TcpStream, vs: UdsStream) {
    let client_r = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let vs_r = match vs.try_clone() {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut client_w = client;
    let mut vs_w = vs;

    // client -> vsock; on client EOF, half-close the vsock write side.
    let up = std::thread::spawn(move || {
        copy_until_eof(client_r, &mut vs_w);
        let _ = vs_w.shutdown(Shutdown::Write);
    });
    // vsock -> client; on vsock EOF, half-close the client write side.
    copy_until_eof(vs_r, &mut client_w);
    let _ = client_w.shutdown(Shutdown::Write);
    let _ = up.join();
}

fn copy_until_eof(mut r: impl Read, w: &mut impl Write) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        if w.write_all(&buf[..n]).is_err() {
            return;
        }
    }
}

/// Default pid-file path for a rule under `run_dir`: `port-<bind>-<hostport>.pid`.
/// Used by both the relay (to write) and the CLI (to choose the spawn arg).
pub fn pid_file_path(run_dir: &Path, bind: Ipv4Addr, host_port: u16) -> PathBuf {
    run_dir.join(format!("port-{bind}-{host_port}.pid"))
}

/// Default log-file name for a rule's relay: `port-<bind>-<hostport>.log`.
pub fn log_file_name(bind: Ipv4Addr, host_port: u16) -> String {
    format!("port-{bind}-{host_port}.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_guest() {
        let r = parse_rule("8080:80").unwrap();
        assert_eq!(r.bind, Ipv4Addr::LOCALHOST);
        assert_eq!(r.host_port, 8080);
        assert_eq!(r.guest_port, 80);
    }

    #[test]
    fn parse_bind_host_guest() {
        let r = parse_rule("0.0.0.0:8080:80").unwrap();
        assert_eq!(r.bind, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(r.host_port, 8080);
        assert_eq!(r.guest_port, 80);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_rule("nope").is_err());
        assert!(parse_rule("a:b:c:d").is_err());
        assert!(parse_rule("8080:notaport").is_err());
        assert!(parse_rule("999.999.999.999:8080:80").is_err());
    }

    #[test]
    fn parse_rejects_port_zero() {
        assert!(parse_rule("0:80").is_err());
        assert!(parse_rule("8080:0").is_err());
    }

    #[test]
    fn pid_and_log_paths() {
        let run = Path::new("/run");
        assert_eq!(
            pid_file_path(run, Ipv4Addr::LOCALHOST, 8080),
            PathBuf::from("/run/port-127.0.0.1-8080.pid")
        );
        assert_eq!(
            log_file_name(Ipv4Addr::new(0, 0, 0, 0), 8080),
            "port-0.0.0.0-8080.log"
        );
    }

    /// Drive the per-connection relay logic without binding a TcpListener:
    /// a UnixStream::pair stands in for the vsock side, and a connected
    /// TcpStream pair stands in for the client. Binds a loopback listener for
    /// the TcpStream pair → runtime-skip on PermissionDenied.
    #[test]
    fn relay_one_pumps_after_ok() {
        // Build a connected TcpStream pair via a throwaway loopback listener.
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP relay_one_pumps_after_ok: sandbox denies bind: {e}");
                return;
            }
            Err(e) => panic!("unexpected bind failure: {e}"),
        };
        let addr = listener.local_addr().unwrap();
        let connect_t = std::thread::spawn(move || TcpStream::connect(addr).unwrap());
        let (server_side, _peer) = listener.accept().unwrap();
        let client_side = connect_t.join().unwrap();

        // Fake guest: a UnixStream::pair where the "init" half answers Ok then
        // echoes. We bypass hybrid_connect by calling the pump directly: split
        // relay_one's post-handshake half into pump_bidirectional here.
        let (init_half, host_half) = UdsStream::pair().unwrap();

        // init side: read host bytes, echo with prefix, then close.
        let init_t = std::thread::spawn(move || {
            let mut s = init_half;
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"re:").unwrap();
            s.write_all(&buf[..n]).unwrap();
            s.shutdown(Shutdown::Write).unwrap();
        });

        // Wire the host TCP client to the host vsock half via the same pump
        // relay_one uses post-Ok.
        let pump_t = std::thread::spawn(move || pump_bidirectional(server_side, host_half));

        // The "curl" side writes through client_side and reads the echo.
        let mut curl = client_side;
        curl.write_all(b"hi").unwrap();
        curl.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        curl.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"re:hi");

        init_t.join().unwrap();
        pump_t.join().unwrap();
    }
}
```

  Then declare the module in `crates/izba-core/src/lib.rs` (insert alphabetically after `paths`):

```rust
mod discover;
pub mod image;
pub mod liveness;
pub mod paths;
pub mod portfwd;
pub mod procmgr;
pub mod sandbox;
pub mod state;
pub mod vmm;
pub mod vsock;
```

- [ ] **Run & expect pass.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib portfwd::`
  Expected: all `portfwd::` tests green (the socketpair test SKIP-prints if bind is denied).

- [ ] **Cross-compile check.** `[ -f .cargo-env ] && source .cargo-env && cargo check --target x86_64-pc-windows-gnu -p izba-core`
  (`std::net` + `UdsStream` alias are portable; `hybrid_connect` already compiles on Windows.)

- [ ] **Commit.**

```sh
git add crates/izba-core/src/portfwd.rs crates/izba-core/src/lib.rs
git commit -m "feat(core): portfwd relay loop and rule parsing

parse_rule handles HOST:GUEST and BIND:HOST:GUEST (default 127.0.0.1, ports
>= 1). run_relay binds the host TcpListener and per connection opens a vsock
TcpDial to the guest; relay_one/pump_bidirectional pump both ways with
graceful shutdown(Write)+drain teardown. Pure vsock so it serves CH/Linux
and OpenVMM/Windows alike, and lives in izba-core for a future izbad.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Task 4 — `CreateOpts.ports` plumbed into `SandboxConfig` (sandbox.rs create)

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs`
- Test: inline `#[cfg(test)]` in `crates/izba-core/src/sandbox.rs`

### Steps

- [ ] **Write a failing test.** Add to `mod tests` in `crates/izba-core/src/sandbox.rs`:

```rust
    #[test]
    fn create_persists_ports() {
        use crate::state::PortRule;
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        let mut o = opts(&ws);
        o.ports = vec![PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 8080,
            guest_port: 80,
        }];
        create(&paths, "web", &o).unwrap();
        let config: SandboxConfig = load_json(&paths.sandbox_dir("web").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(config.ports, o.ports);
    }
```

- [ ] **Run & expect failure.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib sandbox::create_persists_ports`
  Expected: compile error — `no field ports on type CreateOpts`.

- [ ] **Implement.** In `crates/izba-core/src/sandbox.rs`, add the field to `CreateOpts`:

```rust
#[derive(Debug, Clone)]
pub struct CreateOpts {
    pub image_digest: String,
    pub image_ref: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: PathBuf,
    pub rw_size_gb: u64,
    pub ports: Vec<crate::state::PortRule>,
}
```

  In `create`, set the new field on the `SandboxConfig`:

```rust
        let config = SandboxConfig {
            image_digest: opts.image_digest.clone(),
            image_ref: opts.image_ref.clone(),
            cpus: opts.cpus,
            mem_mb: opts.mem_mb,
            workspace: opts.workspace.clone(),
            ports: opts.ports.clone(),
        };
```

  Update the `opts(...)` test helper to include the new field:

```rust
    fn opts(workspace: &Path) -> CreateOpts {
        CreateOpts {
            image_digest: "sha256:abc".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 1024,
            workspace: workspace.to_path_buf(),
            rw_size_gb: 1,
            ports: Vec::new(),
        }
    }
```

- [ ] **Run & expect pass.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib sandbox::`

- [ ] **Commit.**

```sh
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): CreateOpts.ports persisted into config.json

create() now writes the create-time publish rules into SandboxConfig.ports
so run can re-apply them.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Task 5 — ports.json helpers + publish/unpublish/list_ports + lifecycle kill (sandbox.rs)

**Files:**
- Modify: `crates/izba-core/src/sandbox.rs`
- Test: inline `#[cfg(test)]` in `crates/izba-core/src/sandbox.rs`

This task adds the runtime port API and wires relay teardown into `stop_locked`/`cleanup_runtime`. Relays are spawned via `procmgr::spawn_detached(cmd, log)` where `cmd` re-invokes `izba __port-relay`. Because the relay binary path is the running `izba` executable, the spawn command is built from `std::env::current_exe()`.

### Design notes encoded here

- `publish_port(paths, name, rule, connector)`: liveness must be `Running`/`Degraded` (same gate as `exec`/`control`); reject duplicate `(bind, host_port)` already in `ports.json` or in `config.ports` already spawned; parent preflight binds `(bind, host_port)` and drops it (catches port-in-use synchronously); spawn the relay detached; append a `PortRecord`; rewrite `ports.json`.
- `unpublish_port(paths, name, bind, host_port)`: load records, find by `(bind, host_port)`, `kill_pid` the relay, remove the record, rewrite `ports.json`. Missing → error "no such published port".
- `list_ports(paths, name)`: load records, prune dead relays (pid+starttime), rewrite `ports.json` if any pruned, return the live set.
- `spawn_config_ports(paths, name)`: called by `start` after boot health passes; for each `config.ports` rule, preflight-bind then spawn; a bind failure is a warning (eprintln) and the rule is excluded from `ports.json` — it does NOT fail `start`.
- `kill_recorded_relays(paths, name)`: best-effort `kill_pid` every relay in `ports.json`, then remove `ports.json`. Called from `stop_locked` (after VMM teardown) and from the already-stopped early-return path.

### Steps

- [ ] **Write failing tests.** Add to `mod tests` in `crates/izba-core/src/sandbox.rs`. These exercise the record-file plumbing and the lifecycle kill using real `sleep 30` stand-ins for relay processes (publish itself needs a `current_exe` re-invocation + a real bind, so it is covered by the integration suite; the unit tests cover ports.json read/write/prune and that `stop`/`cleanup` kill recorded relays):

```rust
    #[test]
    fn list_ports_prunes_dead_relays() {
        use crate::state::{PortRecord, PortRule, PORTS_FILE};
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let live = spawn_sleep(dir.path());
        let dead = dead_identity();
        let records = vec![
            PortRecord {
                rule: PortRule { bind: "127.0.0.1".parse().unwrap(), host_port: 8080, guest_port: 80 },
                relay: live.clone(),
            },
            PortRecord {
                rule: PortRule { bind: "127.0.0.1".parse().unwrap(), host_port: 9090, guest_port: 90 },
                relay: dead,
            },
        ];
        save_json(&paths.sandbox_dir("web").join(PORTS_FILE), &records).unwrap();

        let live_set = list_ports(&paths, "web").unwrap();
        assert_eq!(live_set.len(), 1, "dead relay must be pruned");
        assert_eq!(live_set[0].rule.host_port, 8080);

        // ports.json must have been rewritten without the dead record.
        let on_disk: Vec<PortRecord> =
            load_json(&paths.sandbox_dir("web").join(PORTS_FILE)).unwrap().unwrap();
        assert_eq!(on_disk.len(), 1);

        let _ = procmgr::kill_pid(&live);
    }

    #[test]
    fn unpublish_kills_and_removes_record() {
        use crate::state::{PortRecord, PortRule, PORTS_FILE};
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        let relay = spawn_sleep(dir.path());
        let records = vec![PortRecord {
            rule: PortRule { bind: "127.0.0.1".parse().unwrap(), host_port: 8080, guest_port: 80 },
            relay: relay.clone(),
        }];
        save_json(&paths.sandbox_dir("web").join(PORTS_FILE), &records).unwrap();

        unpublish_port(&paths, "web", "127.0.0.1".parse().unwrap(), 8080).unwrap();
        assert!(wait_dead(&relay), "unpublish must kill the relay");
        let on_disk: Vec<PortRecord> =
            load_json(&paths.sandbox_dir("web").join(PORTS_FILE)).unwrap().unwrap();
        assert!(on_disk.is_empty(), "record must be removed");

        let err = unpublish_port(&paths, "web", "127.0.0.1".parse().unwrap(), 8080).unwrap_err();
        assert!(err.to_string().contains("no such published port"), "got: {err:#}");
    }

    #[test]
    fn stop_kills_recorded_relays() {
        use crate::state::{PortRecord, PortRule, PORTS_FILE};
        let (dir, paths) = test_paths();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        create(&paths, "web", &opts(&ws)).unwrap();

        // VMM stand-in + a relay stand-in, both real processes.
        let vmm = spawn_sleep(dir.path());
        write_state(&paths, "web", vmm.clone());
        let relay = spawn_sleep(dir.path());
        save_json(
            &paths.sandbox_dir("web").join(PORTS_FILE),
            &vec![PortRecord {
                rule: PortRule { bind: "127.0.0.1".parse().unwrap(), host_port: 8080, guest_port: 80 },
                relay: relay.clone(),
            }],
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let conn = fake_connector(log, Some(vmm.clone()));
        stop(&paths, "web", &conn, Duration::from_secs(5)).unwrap();

        assert!(wait_dead(&relay), "stop must kill recorded relays");
        assert!(
            !paths.sandbox_dir("web").join(PORTS_FILE).exists(),
            "ports.json must be removed by stop"
        );
    }
```

- [ ] **Run & expect failure.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib sandbox::`
  Expected: compile errors — `cannot find function list_ports`, `unpublish_port` in this scope.

- [ ] **Implement.** In `crates/izba-core/src/sandbox.rs`:

  Add imports near the top (extend the existing `use crate::state::...` line and add `Ipv4Addr`):

```rust
use crate::state::{
    load_json, save_json, PortRecord, PortRule, RunState, SandboxConfig, CONFIG_FILE, PORTS_FILE,
    STATE_FILE,
};
```

  And add to the `std` imports block:

```rust
use std::net::Ipv4Addr;
```

  Add the ports-file path helper and the record read/write helpers (place near `liveness_of`):

```rust
fn ports_path(paths: &Paths, name: &str) -> PathBuf {
    paths.sandbox_dir(name).join(PORTS_FILE)
}

fn load_records(paths: &Paths, name: &str) -> anyhow::Result<Vec<PortRecord>> {
    Ok(load_json(&ports_path(paths, name))?.unwrap_or_default())
}

fn save_records(paths: &Paths, name: &str, records: &[PortRecord]) -> anyhow::Result<()> {
    save_json(&ports_path(paths, name), &records.to_vec())
}

/// Build the detached `izba __port-relay` command for a rule.
fn relay_command(
    paths: &Paths,
    name: &str,
    rule: &PortRule,
) -> anyhow::Result<crate::vmm::CommandSpec> {
    let exe = std::env::current_exe().context("locating the izba executable")?;
    let vsock = paths.run_dir(name).join("vsock.sock");
    let pid_file = crate::portfwd::pid_file_path(&paths.run_dir(name), rule.bind, rule.host_port);
    Ok(crate::vmm::CommandSpec {
        argv: vec![
            exe.to_string_lossy().into_owned(),
            "__port-relay".to_string(),
            "--vsock".to_string(),
            vsock.to_string_lossy().into_owned(),
            "--bind".to_string(),
            rule.bind.to_string(),
            "--host-port".to_string(),
            rule.host_port.to_string(),
            "--guest-port".to_string(),
            rule.guest_port.to_string(),
            "--pid-file".to_string(),
            pid_file.to_string_lossy().into_owned(),
        ],
    })
}

/// Parent preflight: bind `(bind, host_port)` and immediately drop it, so the
/// common port-in-use error is caught synchronously before the detached relay
/// is spawned. A residual TOCTOU race is accepted (the relay's own bind
/// failure lands in its log and the rule reads dead in `port ls`).
fn preflight_bind(bind: Ipv4Addr, host_port: u16) -> anyhow::Result<()> {
    std::net::TcpListener::bind((bind, host_port))
        .map(drop)
        .with_context(|| format!("host port {bind}:{host_port} is unavailable"))
}

/// Spawn a relay for `rule` and return its `PortRecord`.
fn spawn_relay(paths: &Paths, name: &str, rule: &PortRule) -> anyhow::Result<PortRecord> {
    let cmd = relay_command(paths, name, rule)?;
    let log = paths
        .logs_dir(name)
        .join(crate::portfwd::log_file_name(rule.bind, rule.host_port));
    let relay = procmgr::spawn_detached(&cmd, &log)?;
    Ok(PortRecord {
        rule: rule.clone(),
        relay,
    })
}
```

  Add the public runtime API:

```rust
/// Publish a runtime port rule against a running sandbox.
pub fn publish_port(
    paths: &Paths,
    name: &str,
    rule: PortRule,
    connector: Connector,
) -> anyhow::Result<()> {
    validate_name(name)?;
    let _lock = lock_sandbox(paths, name)?;
    match liveness_of(paths, name, connector)? {
        Liveness::Running | Liveness::Degraded(_) => {}
        Liveness::Stopped => bail!("sandbox '{name}' is not running"),
    }
    let mut records = load_records(paths, name)?;
    records.retain(|r| procmgr::pid_alive(&r.relay));
    if records
        .iter()
        .any(|r| r.rule.bind == rule.bind && r.rule.host_port == rule.host_port)
    {
        bail!("port already published: {}:{}", rule.bind, rule.host_port);
    }
    preflight_bind(rule.bind, rule.host_port)?;
    let record = spawn_relay(paths, name, &rule)?;
    records.push(record);
    save_records(paths, name, &records)
}

/// Unpublish the rule with key `(bind, host_port)`: kill its relay, drop the
/// record.
pub fn unpublish_port(
    paths: &Paths,
    name: &str,
    bind: Ipv4Addr,
    host_port: u16,
) -> anyhow::Result<()> {
    validate_name(name)?;
    let _lock = lock_sandbox(paths, name)?;
    let mut records = load_records(paths, name)?;
    let idx = records
        .iter()
        .position(|r| r.rule.bind == bind && r.rule.host_port == host_port)
        .with_context(|| format!("no such published port: {bind}:{host_port}"))?;
    let record = records.remove(idx);
    procmgr::kill_pid(&record.relay)?;
    save_records(paths, name, &records)
}

/// List active rules, pruning dead relays (and rewriting `ports.json` if any
/// were pruned).
pub fn list_ports(paths: &Paths, name: &str) -> anyhow::Result<Vec<PortRecord>> {
    validate_name(name)?;
    let _lock = lock_sandbox(paths, name)?;
    let records = load_records(paths, name)?;
    let live: Vec<PortRecord> = records
        .iter()
        .filter(|r| procmgr::pid_alive(&r.relay))
        .cloned()
        .collect();
    if live.len() != records.len() {
        save_records(paths, name, &live)?;
    }
    Ok(live)
}

/// Best-effort: kill every recorded relay and remove `ports.json`.
fn kill_recorded_relays(paths: &Paths, name: &str) {
    if let Ok(records) = load_records(paths, name) {
        for r in &records {
            let _ = procmgr::kill_pid(&r.relay);
        }
    }
    let _ = fs::remove_file(ports_path(paths, name));
}

/// Spawn one relay per `config.ports` rule after a successful boot. A relay
/// that fails its preflight bind is a warning (the VM is up; the port is not)
/// and is excluded from `ports.json` — it does NOT fail `start`.
fn spawn_config_ports(paths: &Paths, name: &str, config: &SandboxConfig) {
    if config.ports.is_empty() {
        return;
    }
    let mut records = Vec::new();
    for rule in &config.ports {
        if let Err(e) = preflight_bind(rule.bind, rule.host_port) {
            eprintln!("warning: not publishing {}:{}: {e:#}", rule.bind, rule.host_port);
            continue;
        }
        match spawn_relay(paths, name, rule) {
            Ok(rec) => records.push(rec),
            Err(e) => eprintln!(
                "warning: failed to spawn relay for {}:{}: {e:#}",
                rule.bind, rule.host_port
            ),
        }
    }
    if let Err(e) = save_records(paths, name, &records) {
        eprintln!("warning: failed to write {PORTS_FILE}: {e:#}");
    }
}
```

  Wire `spawn_config_ports` into `start_with_timeouts`. The boot success path writes `state.json` inside the `booted` closure; spawn the relays right after a successful return. Change the tail of `start_with_timeouts` from:

```rust
    if let Err(e) = booted {
        let _ = handle.kill();
        // Best-effort: clear stale sockets/pid files so a retry starts clean.
        clear_run_dir_files(paths, name);
        return Err(e);
    }
    Ok(())
```

  to:

```rust
    if let Err(e) = booted {
        let _ = handle.kill();
        // Best-effort: clear stale sockets/pid files so a retry starts clean.
        clear_run_dir_files(paths, name);
        return Err(e);
    }
    // Boot succeeded: (re-)apply the persisted publish rules afresh.
    spawn_config_ports(paths, name, &config);
    Ok(())
```

  Wire relay teardown into `stop_locked`. In the already-stopped early-return branch, add the relay kill:

```rust
        (Liveness::Stopped, _) | (_, None) => {
            // VMM is already dead; sidecars (virtiofsd/passt) usually self-exit
            // with their vhost-user peer, but not always — best-effort kill them.
            kill_sidecars_from_state(paths, name);
            kill_recorded_relays(paths, name);
            return cleanup_runtime(paths, name);
        }
```

  And after the escalation block, before `cleanup_runtime(paths, name)` at the end of `stop_locked`, kill the relays:

```rust
    kill_recorded_relays(paths, name);
    cleanup_runtime(paths, name)
```

  (Replace the bare final `cleanup_runtime(paths, name)` line of `stop_locked` with those two lines.)

  Note: `remove(... force)` calls `stop_locked(..., false)`, so the force-remove path kills relays through `stop_locked` automatically; then `fs::remove_dir_all` deletes the whole sandbox dir (including any leftover `ports.json`). No extra change needed in `remove`.

- [ ] **Run & expect pass.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --lib sandbox::`

- [ ] **Cross-compile check.** `[ -f .cargo-env ] && source .cargo-env && cargo check --target x86_64-pc-windows-gnu -p izba-core`
  (`std::net::TcpListener`, `Ipv4Addr`, `current_exe`, `spawn_detached` are all portable.)

- [ ] **Commit.**

```sh
git add crates/izba-core/src/sandbox.rs
git commit -m "feat(core): publish/unpublish/list_ports + lifecycle relay teardown

ports.json tracks active relays; publish_port preflight-binds then spawns a
detached izba __port-relay, rejecting duplicate (bind,host_port);
unpublish_port kills the relay by pid identity and drops the record;
list_ports prunes dead relays. start spawns config.ports relays after boot
(bind failure = warning, not a boot failure); stop/rm kill recorded relays
and remove ports.json.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Task 6 — CLI: `-p` flag, `port` subcommand, hidden `__port-relay` (main.rs + commands)

**Files:**
- Modify: `crates/izba-cli/src/main.rs`
- Modify: `crates/izba-cli/src/commands/mod.rs`
- Modify: `crates/izba-cli/src/commands/create.rs`
- Create: `crates/izba-cli/src/commands/port.rs`
- Test: inline `#[cfg(test)]` in `crates/izba-cli/src/main.rs`

### Steps

- [ ] **Write failing parser tests.** Add to `mod tests` in `crates/izba-cli/src/main.rs`:

```rust
    #[test]
    fn parse_create_publish_flags() {
        let cli = Cli::try_parse_from([
            "izba", "create", "-p", "8080:80", "-p", "0.0.0.0:9090:90", ".",
        ])
        .unwrap();
        let Cmd::Create { opts, .. } = cli.cmd else {
            panic!("expected create");
        };
        assert_eq!(opts.publish, vec!["8080:80".to_string(), "0.0.0.0:9090:90".to_string()]);
    }

    #[test]
    fn parse_port_publish() {
        let cli = Cli::try_parse_from(["izba", "port", "publish", "web", "8080:80"]).unwrap();
        let Cmd::Port(PortCmd::Publish { name, rule }) = cli.cmd else {
            panic!("expected port publish");
        };
        assert_eq!(name, "web");
        assert_eq!(rule, "8080:80");
    }

    #[test]
    fn parse_port_unpublish() {
        let cli = Cli::try_parse_from(["izba", "port", "unpublish", "web", "127.0.0.1:8080"]).unwrap();
        let Cmd::Port(PortCmd::Unpublish { name, key }) = cli.cmd else {
            panic!("expected port unpublish");
        };
        assert_eq!(name, "web");
        assert_eq!(key, "127.0.0.1:8080");
    }

    #[test]
    fn parse_port_ls() {
        let cli = Cli::try_parse_from(["izba", "port", "ls", "web"]).unwrap();
        let Cmd::Port(PortCmd::Ls { name }) = cli.cmd else {
            panic!("expected port ls");
        };
        assert_eq!(name, "web");
    }

    #[test]
    fn parse_hidden_port_relay() {
        let cli = Cli::try_parse_from([
            "izba", "__port-relay",
            "--vsock", "/run/vsock.sock",
            "--bind", "127.0.0.1",
            "--host-port", "8080",
            "--guest-port", "80",
            "--pid-file", "/run/port.pid",
        ])
        .unwrap();
        let Cmd::PortRelay(args) = cli.cmd else {
            panic!("expected __port-relay");
        };
        assert_eq!(args.bind, "127.0.0.1");
        assert_eq!(args.host_port, 8080);
        assert_eq!(args.guest_port, 80);
    }
```

- [ ] **Run & expect failure.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-cli --bin izba parse_`
  Expected: compile errors — `no field publish on SandboxOpts`, `PortCmd`/`Cmd::Port`/`Cmd::PortRelay` not found.

- [ ] **Implement — main.rs.** In `crates/izba-cli/src/main.rs`:

  Add the `publish` field to `SandboxOpts` (repeatable `-p`):

```rust
/// Options shared by `create` and `run`.
#[derive(Debug, Args)]
struct SandboxOpts {
    /// Container image to boot
    #[arg(long, default_value = "ubuntu:24.04")]
    image: String,
    /// Number of virtual CPUs
    #[arg(long, default_value_t = 2)]
    cpus: u32,
    /// Memory in MiB
    #[arg(long, default_value_t = 4096)]
    mem: u32,
    /// Size of the writable scratch disk in GiB
    #[arg(long, default_value_t = 8)]
    rw_size_gb: u64,
    /// Sandbox name (default: derived from the workspace directory name)
    #[arg(long)]
    name: Option<String>,
    /// Publish a host port to the guest: [BIND:]HOST:GUEST (repeatable)
    #[arg(short = 'p', long = "publish", value_name = "[BIND:]HOST:GUEST")]
    publish: Vec<String>,
}
```

  Add the hidden relay args struct and the `PortCmd` subcommand enum (place after `SandboxOpts`):

```rust
/// Args for the hidden `__port-relay` re-invocation.
#[derive(Debug, Args)]
struct PortRelayArgs {
    /// Path to the sandbox's hybrid-vsock unix socket.
    #[arg(long)]
    vsock: PathBuf,
    /// Host bind address.
    #[arg(long)]
    bind: String,
    /// Host port to listen on.
    #[arg(long)]
    host_port: u16,
    /// Guest port to dial.
    #[arg(long)]
    guest_port: u16,
    /// Where the relay writes its own pid.
    #[arg(long)]
    pid_file: PathBuf,
}

#[derive(Debug, Subcommand)]
enum PortCmd {
    /// Publish a port against a running sandbox
    Publish {
        /// Sandbox name
        name: String,
        /// [BIND:]HOST:GUEST
        rule: String,
    },
    /// Remove a published port by its [BIND:]HOST key
    Unpublish {
        /// Sandbox name
        name: String,
        /// [BIND:]HOST (GUEST is not needed)
        key: String,
    },
    /// List active published ports
    Ls {
        /// Sandbox name
        name: String,
    },
}
```

  Add the two new `Cmd` variants (inside `enum Cmd`, after `Rm`):

```rust
    /// Manage published ports (host -> guest TCP)
    Port(#[command(subcommand)] PortCmd),
    /// Internal: the per-rule port-publish relay process (not for direct use)
    #[command(hide = true, name = "__port-relay")]
    PortRelay(PortRelayArgs),
```

  Add dispatch arms (inside `dispatch`, after `Cmd::Rm`):

```rust
        Cmd::Port(pc) => commands::port::run(paths, pc),
        Cmd::PortRelay(args) => commands::port::run_relay(args),
```

  The dispatch arm for `Cmd::Port`/`Cmd::PortRelay` passes the parsed clap types into `commands::port`. To avoid leaking the `main.rs`-private types, define a small conversion: `commands::port::run` takes the clap `PortCmd` and `run_relay` takes `PortRelayArgs`. Make those two types visible to the `port` module by moving the field access into `main.rs` is unnecessary — instead, have the dispatch translate to plain strings. Replace the two arms above with:

```rust
        Cmd::Port(pc) => match pc {
            PortCmd::Publish { name, rule } => commands::port::publish(paths, &name, &rule),
            PortCmd::Unpublish { name, key } => commands::port::unpublish(paths, &name, &key),
            PortCmd::Ls { name } => commands::port::ls(paths, &name),
        },
        Cmd::PortRelay(a) => {
            commands::port::relay(&a.vsock, &a.bind, a.host_port, a.guest_port, &a.pid_file)
        }
```

- [ ] **Implement — commands/mod.rs.** In `crates/izba-cli/src/commands/mod.rs`:

  Add the module declaration:

```rust
pub mod create;
pub mod exec;
pub mod ls;
pub mod port;
pub mod rm;
pub mod run;
pub mod stop;
```

  Add a helper that parses the `-p` specs into `Vec<PortRule>` and extend `create_opts`. Replace `create_opts` with a version that takes parsed ports:

```rust
use izba_core::state::PortRule;

/// Parse the repeatable `-p/--publish` specs into PortRules.
pub fn parse_publish(specs: &[String]) -> anyhow::Result<Vec<PortRule>> {
    specs.iter().map(|s| izba_core::portfwd::parse_rule(s)).collect()
}

fn create_opts(
    opts: &SandboxOpts,
    digest: String,
    workspace: PathBuf,
    ports: Vec<PortRule>,
) -> CreateOpts {
    CreateOpts {
        image_digest: digest,
        image_ref: opts.image.clone(),
        cpus: opts.cpus,
        mem_mb: opts.mem,
        workspace,
        rw_size_gb: opts.rw_size_gb,
        ports,
    }
}
```

  Note: `create_opts` is also called by `run.rs` (`super::create_opts(opts, digest, workspace)`). Update that call in `run.rs` to pass parsed ports too.

- [ ] **Implement — commands/create.rs.** Update `crates/izba-cli/src/commands/create.rs` to parse `-p` and pass it through:

```rust
use crate::SandboxOpts;
use izba_core::paths::Paths;
use izba_core::{image, sandbox};
use std::path::Path;

pub fn run(paths: &Paths, opts: &SandboxOpts, dir: &Path) -> anyhow::Result<i32> {
    let workspace = super::ensure_workspace(dir)?;
    let name = super::name_for(opts, &workspace)?;
    let ports = super::parse_publish(&opts.publish)?;
    eprintln!("resolving {} (pulls if not cached)...", opts.image);
    let digest = image::ensure_image(paths, &opts.image)?;
    sandbox::create(paths, &name, &super::create_opts(opts, digest, workspace, ports))?;
    println!("{name}");
    Ok(0)
}
```

- [ ] **Implement — run.rs call site.** In `crates/izba-cli/src/commands/run.rs`, update the `create_opts` call inside `resolve_or_create` to pass parsed ports:

```rust
    if !paths.sandbox_dir(&name).join(CONFIG_FILE).is_file() {
        eprintln!("resolving {} (pulls if not cached)...", opts.image);
        let digest = image::ensure_image(paths, &opts.image)?;
        let ports = super::parse_publish(&opts.publish)?;
        sandbox::create(paths, &name, &super::create_opts(opts, digest, workspace, ports))?;
    }
```

  Also add `--publish` to the `has_non_default` warning predicate in `run.rs` so a user passing `-p` on an existing sandbox is warned the stored config wins:

```rust
        let has_non_default = opts.image != "ubuntu:24.04"
            || opts.cpus != 2
            || opts.mem != 4096
            || opts.rw_size_gb != 8
            || opts.name.is_some()
            || !opts.publish.is_empty();
```

- [ ] **Implement — commands/port.rs.** Create `crates/izba-cli/src/commands/port.rs`:

```rust
//! `izba port` — publish/unpublish/ls host->guest TCP ports, plus the hidden
//! `__port-relay` worker that each published rule runs as a detached process.

use anyhow::{bail, Context};
use izba_core::paths::Paths;
use izba_core::sandbox;
use std::net::Ipv4Addr;
use std::path::Path;

pub fn publish(paths: &Paths, name: &str, rule_spec: &str) -> anyhow::Result<i32> {
    let rule = izba_core::portfwd::parse_rule(rule_spec)?;
    let connector = sandbox::default_connector();
    sandbox::publish_port(paths, name, rule.clone(), &connector)?;
    println!("{}:{} -> {}", rule.bind, rule.host_port, rule.guest_port);
    Ok(0)
}

pub fn unpublish(paths: &Paths, name: &str, key: &str) -> anyhow::Result<i32> {
    let (bind, host_port) = parse_key(key)?;
    sandbox::unpublish_port(paths, name, bind, host_port)?;
    Ok(0)
}

pub fn ls(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let records = sandbox::list_ports(paths, name)?;
    for r in &records {
        println!(
            "{}:{} -> {} (relay pid {})",
            r.rule.bind, r.rule.host_port, r.rule.guest_port, r.relay.pid
        );
    }
    Ok(0)
}

/// The hidden `__port-relay` worker: runs the blocking relay loop forever.
pub fn relay(
    vsock: &Path,
    bind: &str,
    host_port: u16,
    guest_port: u16,
    pid_file: &Path,
) -> anyhow::Result<i32> {
    let bind: Ipv4Addr = bind
        .parse()
        .with_context(|| format!("invalid bind address '{bind}'"))?;
    izba_core::portfwd::run_relay(vsock, bind, host_port, guest_port, pid_file)?;
    Ok(0)
}

/// Parse an unpublish key `[BIND:]HOST` into `(bind, host_port)` (default bind
/// 127.0.0.1).
fn parse_key(key: &str) -> anyhow::Result<(Ipv4Addr, u16)> {
    let parts: Vec<&str> = key.split(':').collect();
    match parts.as_slice() {
        [host] => Ok((Ipv4Addr::LOCALHOST, parse_port(host, key)?)),
        [bind, host] => {
            let bind: Ipv4Addr = bind
                .parse()
                .with_context(|| format!("invalid bind address '{bind}' in key '{key}'"))?;
            Ok((bind, parse_port(host, key)?))
        }
        _ => bail!("invalid port key '{key}' (expected [BIND:]HOST)"),
    }
}

fn parse_port(s: &str, key: &str) -> anyhow::Result<u16> {
    let p: u16 = s
        .parse()
        .with_context(|| format!("invalid port '{s}' in key '{key}'"))?;
    if p == 0 {
        bail!("port 0 is not allowed in key '{key}'");
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_host_only_defaults_bind() {
        assert_eq!(parse_key("8080").unwrap(), (Ipv4Addr::LOCALHOST, 8080));
    }

    #[test]
    fn key_bind_host() {
        assert_eq!(
            parse_key("0.0.0.0:8080").unwrap(),
            (Ipv4Addr::new(0, 0, 0, 0), 8080)
        );
    }

    #[test]
    fn key_rejects_garbage() {
        assert!(parse_key("a:b:c").is_err());
        assert!(parse_key("0.0.0.0:0").is_err());
        assert!(parse_key("notaport").is_err());
    }
}
```

- [ ] **Run & expect pass.** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-cli`
  Expected: all parser tests and `commands::port::tests` green.

- [ ] **Cross-compile check (gates 5-6).** `[ -f .cargo-env ] && source .cargo-env && cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`

- [ ] **Commit.**

```sh
git add crates/izba-cli/src/main.rs crates/izba-cli/src/commands/mod.rs crates/izba-cli/src/commands/create.rs crates/izba-cli/src/commands/run.rs crates/izba-cli/src/commands/port.rs
git commit -m "feat(cli): izba port publish/unpublish/ls + create -p + hidden __port-relay

-p/--publish (repeatable) on create/run persists rules into config.json. The
port subcommand drives publish_port/unpublish_port/list_ports. The hidden
__port-relay subcommand is the detached per-rule worker that runs the
portfwd relay loop; spawn_relay re-invokes the current izba executable with
it.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Task 7 — KVM-gated integration tests (integration.rs)

**Files:**
- Modify: `crates/izba-core/tests/integration.rs`

The default test image is `alpine:3.20` (busybox), NOT ubuntu — so the in-guest listener uses busybox `httpd -f -p 8000` serving a file out of `/workspace`. `httpd` ships in alpine's busybox. The host side curls with `std::net::TcpStream` (no `curl` dependency) sending a minimal HTTP/1.0 request and asserting the body.

### Steps

- [ ] **Add integration tests.** Append to `crates/izba-core/tests/integration.rs` (before the final closing items). First, add the imports needed at the top `use` block — extend the existing imports:

```rust
use izba_core::state::PortRule;
```

  Add a small helper near the other helpers (after `exec_ok`):

```rust
/// Start a busybox httpd in the guest serving `/workspace`, detached, so it
/// keeps running after the exec returns. Writes `index.html` first.
fn start_guest_httpd(paths: &Paths, name: &str, body: &str, guest_port: u16) {
    exec_ok(
        paths,
        name,
        &["sh", "-c", &format!("printf '%s' '{body}' > /workspace/index.html")],
    );
    // `httpd -f` stays in the foreground; background it with & and disown via
    // setsid so it survives the exec's process-group teardown.
    let cmd = format!("setsid httpd -f -p {guest_port} -h /workspace >/dev/null 2>&1 &");
    exec_ok(paths, name, &["sh", "-c", &cmd]);
    // Give httpd a moment to bind.
    std::thread::sleep(Duration::from_millis(300));
}

/// Minimal HTTP/1.0 GET against a host TCP port; returns the response body
/// (everything after the blank line). Retries briefly while the relay warms up.
fn http_get(host_port: u16) -> anyhow::Result<String> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_err = String::new();
    loop {
        match (|| -> anyhow::Result<String> {
            let mut s = TcpStream::connect(("127.0.0.1", host_port))?;
            s.set_read_timeout(Some(Duration::from_secs(3)))?;
            s.write_all(b"GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
            let mut resp = String::new();
            s.read_to_string(&mut resp)?;
            let body = resp
                .split_once("\r\n\r\n")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            Ok(body)
        })() {
            Ok(body) if !body.is_empty() => return Ok(body),
            Ok(_) => last_err = "empty body".to_string(),
            Err(e) => last_err = e.to_string(),
        }
        if Instant::now() >= deadline {
            anyhow::bail!("http_get({host_port}) never succeeded: {last_err}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
```

  Then add the tests:

```rust
#[test]
fn port_publish_create_time() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("port-create");

    // create with -p 18080:8000 (persisted), then boot.
    let digest = provision_image(&env, &tb.paths);
    sandbox::create(
        &tb.paths,
        "portc",
        &CreateOpts {
            image_digest: digest,
            image_ref: env.image_ref.clone(),
            cpus: 1,
            mem_mb: 1024,
            workspace: ws.to_path_buf(),
            rw_size_gb: 2,
            ports: vec![PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 18080,
                guest_port: 8000,
            }],
        },
    )
    .expect("create");
    tb.names.push("portc".to_string());
    if let Err(e) = start_sandbox(&env, &tb, "portc") {
        panic!("boot failed: {e:#}\nconsole:\n{}", console_tail(&tb.paths, "portc"));
    }

    start_guest_httpd(&tb.paths, "portc", "hello-from-guest", 8000);
    let body = http_get(18080).expect("curl published port");
    assert_eq!(body, "hello-from-guest");

    stop_sandbox(&tb, "portc");
}

#[test]
fn port_publish_runtime_and_unpublish() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("port-runtime");
    boot(&env, &mut tb, "portr", &ws);

    start_guest_httpd(&tb.paths, "portr", "runtime-body", 8000);

    let connector = sandbox::default_connector();
    sandbox::publish_port(
        &tb.paths,
        "portr",
        PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 18081,
            guest_port: 8000,
        },
        &connector,
    )
    .expect("runtime publish");

    let body = http_get(18081).expect("curl runtime-published port");
    assert_eq!(body, "runtime-body");

    // ls shows exactly the one live rule.
    let listed = sandbox::list_ports(&tb.paths, "portr").expect("ls");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].rule.host_port, 18081);

    // unpublish → the host port stops accepting (connection refused).
    sandbox::unpublish_port(&tb.paths, "portr", "127.0.0.1".parse().unwrap(), 18081)
        .expect("unpublish");
    // Give the relay a moment to die and release the port.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        http_get(18081).is_err(),
        "port must be unreachable after unpublish"
    );
    let listed = sandbox::list_ports(&tb.paths, "portr").expect("ls after unpublish");
    assert!(listed.is_empty(), "no rules should remain");

    stop_sandbox(&tb, "portr");
}

#[test]
fn stop_kills_port_relays() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("port-stop");
    boot(&env, &mut tb, "ports", &ws);

    let connector = sandbox::default_connector();
    sandbox::publish_port(
        &tb.paths,
        "ports",
        PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 18082,
            guest_port: 8000,
        },
        &connector,
    )
    .expect("publish");
    let records = sandbox::list_ports(&tb.paths, "ports").expect("ls");
    assert_eq!(records.len(), 1);
    let relay = records[0].relay.clone();
    assert!(procmgr::pid_alive(&relay), "relay must be alive after publish");

    stop_sandbox(&tb, "ports");

    let dead = (0..40).any(|_| {
        if !procmgr::pid_alive(&relay) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
        !procmgr::pid_alive(&relay)
    });
    assert!(dead, "stop must kill the relay (no orphaned __port-relay)");
    assert!(
        !tb.paths.sandbox_dir("ports").join("ports.json").exists(),
        "ports.json must be removed by stop"
    );
}
```

- [ ] **Run gated-off (must self-skip and pass).** `[ -f .cargo-env ] && source .cargo-env && cargo test -p izba-core --test integration`
  Expected: all tests print SKIP and pass (no `IZBA_INTEGRATION=1`).

- [ ] **(Optional, only on a KVM host) run gated-on.** `IZBA_INTEGRATION=1 IZBA_KERNEL=~/.local/share/izba/artifacts/vmlinux IZBA_INITRAMFS=~/.local/share/izba/artifacts/initramfs.cpio.gz cargo test -p izba-core --test integration -- --test-threads=1 --nocapture`
  Expected (on a working host): `port_publish_create_time`, `port_publish_runtime_and_unpublish`, `stop_kills_port_relays` green. If `httpd` is missing from the test image's busybox build, the test panics with the guest stderr — switch the listener to `nc`: `setsid sh -c 'while true; do printf "HTTP/1.0 200 OK\r\n\r\nruntime-body" | nc -l -p 8000; done &'` (alpine busybox `nc` supports `-l -p`).

- [ ] **Commit.**

```sh
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): KVM integration for port publishing

create -p + boot + busybox httpd in guest + host http_get; runtime
publish/unpublish/ls; stop kills relays (no orphaned __port-relay). Uses a
std TcpStream HTTP/1.0 client (no curl dependency); self-skips without
IZBA_INTEGRATION=1.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Task 8 — Final: all six build gates green

**Files:** none (verification only).

### Steps

- [ ] **Run the six gates in order.** All must be green:

```sh
[ -f .cargo-env ] && source .cargo-env
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

- [ ] **Fix any clippy/fmt nits surfaced by the gates** (e.g. needless clones, `format!` in `bail!`, unused imports in the init test's skip path). Re-run the affected gate until clean. Do NOT introduce new dependencies; if clippy flags something requiring a structural change, prefer the minimal idiomatic fix.

- [ ] **Commit any gate fixes** (only if changes were needed):

```sh
git add <files changed by gate fixes>
git commit -m "chore(port-publish): satisfy clippy/fmt across all six gates

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Spec → task traceability

| Spec section | Task(s) |
| --- | --- |
| §2 rule syntax + `(bind,host_port)` uniqueness key | 3 (`parse_rule`), 5 (duplicate rejection), 6 (CLI key parsing) |
| §3 relay architecture + graceful shutdown both directions | 2 (init side), 3 (relay side `pump_bidirectional`) |
| §4 `PortRule` + `#[serde(default)] ports` + `ports.json`/`PortRecord` + lifecycle hooks | 1 (types), 4 (config persist), 5 (lifecycle) |
| §5 hidden `__port-relay` + `izba-core::portfwd` + parent preflight bind + init 10s dial cap* | 6 (subcommand), 3 (module), 5 (`preflight_bind`), 2 (init dial) |
| §6 error table | 5 (duplicate/not-running/no-such), 6 (parse exit 2 via clap), 2 (ConnectFailed) |
| §7 test matrix incl. serde back-compat fixture | 1 (back-compat fixture), 2/3 (pumps + parsing), 7 (integration) |

\* §5's 10 s dial cap is implemented verbatim in Task 2 via
`TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(10))`.
Loopback normally refuses instantly; the cap only guards pathological guest
states (e.g. workload firewall DROP rules) so a relay thread can never hang
in connect forever.

## Notes on merge-friendliness with the parallel `cp` branch

- `izba-init/src/server.rs`: only the `TcpDial` arm changes; the `TarExtract | TarCreate` arm is left in place (and the unimplemented-variants test still covers them). The cp branch fills those arms — no overlap.
- `izba-cli/src/main.rs`: only additive (`SandboxOpts.publish`, new `Cmd::Port`/`Cmd::PortRelay`, two dispatch arms). The cp branch adds its own `Cmd::Cp` arm — no shared lines beyond the enum/`match` blocks, which are additive.
- `izba-proto`: untouched (groundwork already landed).
- `state.rs`/`sandbox.rs`/`portfwd.rs`: port-specific; the cp branch touches different functions/files.
