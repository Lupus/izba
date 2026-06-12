# izba M1 — izbad-owned egress: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** All guest egress (TCP + DNS) flows through izbad over guest-initiated vsock streams; passt/consomme retired from the datapath on both platforms.

**Architecture:** Mirror of the port-publish path, inverted: a guest stub (izba-init) intercepts outbound TCP via nft REDIRECT (+ a local DNS socket), opens one vsock stream per flow to host port 1027 carrying `StreamOpen::TcpConnect`/`Dns`, and izbad — listening on the Firecracker-convention `run/vsock.sock_1027` unix socket — policy-checks, dials out, and splices. Spec: `docs/superpowers/specs/2026-06-12-izba-m1-egress-design.md`.

**Tech Stack:** Rust workspace (izba-proto / izba-core / izba-cli / izba-init), Cloud Hypervisor + OpenVMM hybrid vsock, nftables (vendored static `nft`), `vsock` crate guest-side, `ipconfig` crate (Windows DNS discovery).

**House rules (apply to every task):**
- TDD: failing test first, then minimal code.
- After each task, the six commit gates must pass (run at minimum `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`; the musl-init and the two windows-cross gates whenever the task touches izba-init / izba-proto / izba-core / izba-cli — i.e. effectively always):
  ```sh
  [ -f .cargo-env ] && source .cargo-env
  cargo test --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  cargo fmt --check
  cargo build -p izba-init --target x86_64-unknown-linux-musl --release
  cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
  cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
  ```
- Unit tests must never bind unix/vsock listeners unconditionally — use `UnixStream::pair()` / `UdsStream::pair()` fakes; tests that genuinely bind must runtime-skip on `PermissionDenied` (house pattern, see `crates/izba-core/src/vsock.rs::full_connect_via_listener`).
- KVM-gated steps (integration suite, artifact rebuilds) and Windows-interop steps need the sandbox disabled; they run fine on THIS machine (`/dev/kvm` works unsandboxed; `powershell.exe -NoProfile` reaches the Windows host).
- Conventional commits. Commit messages are given per task.

---

## Phase A — wire protocol + izbad egress + guest DNS half

### Task A1: izba-proto — `TcpConnect`/`Dns` variants, `EGRESS_PORT`, DNS framing helpers

**Files:**
- Modify: `crates/izba-proto/src/messages.rs`
- Create: `crates/izba-proto/src/dns.rs`
- Modify: `crates/izba-proto/src/lib.rs` (add `pub mod dns;`)

- [ ] **Step 1: Write the failing tests** — extend the existing `stream_open_roundtrip_and_stable_tags` test in `messages.rs` and add a new test module in `dns.rs`.

In `messages.rs` tests, add to the roundtrip array and the wire-tag array:

```rust
// in the roundtrip `for open in [...]` list:
            StreamOpen::TcpConnect {
                addr: "93.184.216.34".into(),
                port: 443,
            },
            StreamOpen::Dns,
// in the wire-tag `for (open, tag) in [...]` list:
            (
                StreamOpen::TcpConnect {
                    addr: "1.2.3.4".into(),
                    port: 1,
                },
                r#""type":"tcp_connect""#,
            ),
            (StreamOpen::Dns, r#""type":"dns""#),
```

Also add a port-constant test:

```rust
    #[test]
    fn egress_port_is_1027() {
        assert_eq!(EGRESS_PORT, 1027);
    }
```

Create `crates/izba-proto/src/dns.rs` with its tests (implementation comes in step 3 — write the tests first, with `todo!()`-free stubs absent so it fails to compile, or write the whole file and watch the tests fail if you prefer; for a new file, write tests + implementation together and just verify the tests pass):

```rust
//! DNS message helpers shared by the guest stub and izbad's resolver:
//! RFC 1035 §4.2.2 framing (2-byte big-endian length prefix) and SERVFAIL
//! synthesis. No DNS parsing lives here — messages are opaque bytes.

use std::io::{self, Read, Write};

/// Write one length-prefixed DNS message.
pub fn write_dns_msg<W: Write>(w: &mut W, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns message over 64 KiB"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(msg)
}

/// Read one length-prefixed DNS message; `Ok(None)` on clean EOF at a
/// message boundary (the peer closed between messages).
pub fn read_dns_msg<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    // First byte by hand to distinguish boundary-EOF from a truncated frame.
    if r.read(&mut len[..1])? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut len[1..])?;
    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut msg)?;
    Ok(Some(msg))
}

/// Turn `query` into a SERVFAIL response in place: QR=1, RA=1, RCODE=2.
/// ID and question section are preserved so the client can match it.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() >= 4 {
        resp[2] |= 0x80; // QR: this is a response
        resp[3] = (resp[3] & 0xf0) | 0x02; // RCODE = SERVFAIL
        resp[3] |= 0x80; // RA
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip_and_boundary_eof() {
        let mut buf = Vec::new();
        write_dns_msg(&mut buf, b"query-one").unwrap();
        write_dns_msg(&mut buf, b"q2").unwrap();
        let mut c = Cursor::new(&buf);
        assert_eq!(read_dns_msg(&mut c).unwrap().unwrap(), b"query-one");
        assert_eq!(read_dns_msg(&mut c).unwrap().unwrap(), b"q2");
        assert!(read_dns_msg(&mut c).unwrap().is_none(), "clean EOF -> None");
    }

    #[test]
    fn truncated_frame_is_an_error() {
        let mut buf = Vec::new();
        write_dns_msg(&mut buf, b"hello").unwrap();
        buf.truncate(4); // length prefix promises 5 bytes; only 2 present
        let mut c = Cursor::new(&buf);
        assert!(read_dns_msg(&mut c).is_err());
    }

    #[test]
    fn servfail_sets_qr_ra_rcode_keeps_id() {
        // 12-byte header: ID=0xbeef, flags=0x0100 (RD), 1 question.
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let r = servfail(&q);
        assert_eq!(&r[..2], &[0xbe, 0xef], "ID preserved");
        assert_eq!(r[2], 0x81, "QR set, RD preserved");
        assert_eq!(r[3], 0x82, "RA set, RCODE=2");
        assert_eq!(r.len(), q.len());
    }

    #[test]
    fn servfail_on_runt_query_does_not_panic() {
        assert_eq!(servfail(&[0x01]), vec![0x01]);
    }
}
```

- [ ] **Step 2: Run the proto tests to verify the new ones fail** (the `messages.rs` ones won't compile until the variants exist)

Run: `cargo test -p izba-proto`
Expected: compile FAILURE (`TcpConnect` / `Dns` / `EGRESS_PORT` not found)

- [ ] **Step 3: Add the variants and constant** in `messages.rs`:

```rust
// append to `pub enum StreamOpen` after TarCreate:
    /// Guest egress (vsock 1027, guest-initiated): izbad dials `addr:port`
    /// on the host and replies one `Response` frame (`Ok` |
    /// `Error{ConnectFailed}`); on `Ok` the connection becomes a raw
    /// bidirectional byte pipe. `addr` is an IP literal in M1
    /// (SO_ORIGINAL_DST); a name-carrying form is M5 scope.
    TcpConnect { addr: String, port: u16 },
    /// Guest DNS (vsock 1027, guest-initiated): DNS-over-TCP framing
    /// follows (see `crate::dns`), request/response alternating;
    /// sequential queries allowed; EOF closes.
    Dns,
```

```rust
// next to CONTROL_PORT / STREAM_PORT:
/// Guest-dialed host port for egress streams; the VMM bridges it to the
/// `run/vsock.sock_1027` unix listener owned by izbad (Firecracker hybrid-
/// vsock convention, shared by Cloud Hypervisor and OpenVMM).
pub const EGRESS_PORT: u32 = 1027;
```

And in `lib.rs`: `pub mod dns;`

- [ ] **Step 4: Run the tests**

Run: `cargo test -p izba-proto`
Expected: PASS (all, including the new roundtrip/tag/dns tests)

- [ ] **Step 5: Workspace gates, then commit**

```bash
git add crates/izba-proto/src/messages.rs crates/izba-proto/src/dns.rs crates/izba-proto/src/lib.rs
git commit -m "feat(proto): StreamOpen::TcpConnect/Dns + EGRESS_PORT + DNS framing helpers (M1)"
```

### Task A2: izba-core — egress policy seam (`egress/policy.rs`)

**Files:**
- Create: `crates/izba-core/src/daemon/egress/policy.rs`
- Create: `crates/izba-core/src/daemon/egress/mod.rs` (skeleton: just `pub mod policy;` for now)
- Modify: `crates/izba-core/src/daemon/mod.rs` (add `pub mod egress;`)

- [ ] **Step 1: Write the file with tests**

`crates/izba-core/src/daemon/egress/policy.rs`:

```rust
//! Egress policy seam (M1: allow-all). M2 fills in per-sandbox allow-lists
//! and the audit log; the seam exists now so the daemon grows by extension
//! instead of refactor (roadmap risk #6).

/// One egress connection attempt, as seen at the policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDesc {
    pub sandbox: String,
    /// Destination address as the guest gave it (an IP literal in M1).
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

pub trait Policy: Send + Sync {
    /// Decide AND record: implementations own their audit emission.
    fn check(&self, flow: &FlowDesc) -> Verdict;
}

/// M1 policy: everything allowed; each decision goes to stderr (the daemon
/// log), so the audit trail exists from day one.
pub struct AllowAll;

impl Policy for AllowAll {
    fn check(&self, flow: &FlowDesc) -> Verdict {
        eprintln!(
            "izbad: egress allow {} -> {}:{}",
            flow.sandbox, flow.addr, flow.port
        );
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_allows() {
        let flow = FlowDesc {
            sandbox: "web".into(),
            addr: "1.2.3.4".into(),
            port: 443,
        };
        assert_eq!(AllowAll.check(&flow), Verdict::Allow);
    }
}
```

`crates/izba-core/src/daemon/egress/mod.rs` (this task only):

```rust
//! izbad-owned egress: the guest-initiated vsock 1027 plane. Module seams
//! (policy / dns / router / manager) are deliberately separable — M2 fills
//! policy, M4 fronts dns with member names, M5 branches MITM off the router.

pub mod policy;
```

And in `crates/izba-core/src/daemon/mod.rs` add `pub mod egress;` to the module list.

- [ ] **Step 2: Run + gates + commit**

Run: `cargo test -p izba-core egress::policy`
Expected: PASS

```bash
git add crates/izba-core/src/daemon/egress/ crates/izba-core/src/daemon/mod.rs
git commit -m "feat(core): egress policy seam — FlowDesc/Verdict/Policy + M1 AllowAll"
```

### Task A3: izba-core — DNS resolver seam (`egress/dns.rs`)

**Files:**
- Create: `crates/izba-core/src/daemon/egress/dns.rs`
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (add `pub mod dns;`)
- Modify: `crates/izba-core/Cargo.toml` (Windows-only `ipconfig` dep)

- [ ] **Step 1: Write the failing tests + implementation**

`crates/izba-core/src/daemon/egress/dns.rs`:

```rust
//! DNS resolver seam. M1 production: a raw-packet UDP forwarder to the
//! host's system-configured upstream — no DNS parsing, full fidelity for
//! any qtype/EDNS. M4 slots member-name resolution in front of this.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

pub trait Resolver: Send + Sync {
    /// Raw DNS query in, raw DNS response out. The caller turns an `Err`
    /// into SERVFAIL (`izba_proto::dns::servfail`).
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>>;
}

const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);
/// Big enough for any EDNS response we would relay.
const MAX_DNS_MSG: usize = 4096;

pub struct UdpForwarder {
    upstream: SocketAddr,
}

impl UdpForwarder {
    pub fn new(upstream: SocketAddr) -> Self {
        Self { upstream }
    }

    /// Host-system upstream; falls back to 1.1.1.1:53 (logged) when
    /// discovery fails — a host with no DNS config is already broken.
    pub fn system() -> Self {
        Self::new(system_upstream())
    }
}

impl Resolver for UdpForwarder {
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let local: SocketAddr = if self.upstream.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(local)?;
        sock.set_read_timeout(Some(FORWARD_TIMEOUT))?;
        sock.send_to(query, self.upstream)?;
        let mut buf = vec![0u8; MAX_DNS_MSG];
        let (n, _from) = sock.recv_from(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// First `nameserver` in resolv.conf-style text, as a `:53` socket addr.
fn parse_resolv_conf(text: &str) -> Option<SocketAddr> {
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("nameserver") {
            if let Some(ip) = it.next().and_then(|s| s.parse::<IpAddr>().ok()) {
                return Some(SocketAddr::new(ip, 53));
            }
        }
    }
    None
}

pub fn system_upstream() -> SocketAddr {
    let found = discover_upstream();
    found.unwrap_or_else(|| {
        eprintln!("izbad: no system DNS upstream found; falling back to 1.1.1.1:53");
        "1.1.1.1:53".parse().unwrap()
    })
}

#[cfg(unix)]
fn discover_upstream() -> Option<SocketAddr> {
    parse_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").ok()?)
}

#[cfg(windows)]
fn discover_upstream() -> Option<SocketAddr> {
    let adapters = ipconfig::get_adapters().ok()?;
    adapters
        .iter()
        .filter(|a| a.oper_status() == ipconfig::OperStatus::IfOperStatusUp)
        .flat_map(|a| a.dns_servers())
        .next()
        .map(|ip| SocketAddr::new(*ip, 53))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_first_nameserver() {
        let conf = "# comment\nsearch local\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n";
        assert_eq!(
            parse_resolv_conf(conf),
            Some("10.0.0.2:53".parse().unwrap())
        );
    }

    #[test]
    fn parses_ipv6_nameserver_and_handles_garbage() {
        assert_eq!(
            parse_resolv_conf("nameserver fd00::1\n"),
            Some("[fd00::1]:53".parse().unwrap())
        );
        assert_eq!(parse_resolv_conf("nameserver not-an-ip\n"), None);
        assert_eq!(parse_resolv_conf(""), None);
    }

    /// Forwarder round-trip against a fake upstream. Binds UDP sockets —
    /// runtime-skip where the sandbox denies bind (house pattern).
    #[test]
    fn forwards_raw_packets() {
        let upstream = match UdpSocket::bind(("127.0.0.1", 0)) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP forwards_raw_packets: sandbox denies bind: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let addr = upstream.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, peer) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"fake-query");
            upstream.send_to(b"fake-answer", peer).unwrap();
        });
        let fwd = UdpForwarder::new(addr);
        let resp = fwd.handle(b"fake-query").unwrap();
        assert_eq!(resp, b"fake-answer");
        t.join().unwrap();
    }
}
```

`crates/izba-core/Cargo.toml` — add to the existing `[target.'cfg(windows)'.dependencies]` section (it exists, it carries `uds_windows`):

```toml
ipconfig = "0.3"
```

And `pub mod dns;` in `egress/mod.rs`.

- [ ] **Step 2: Run, gates (esp. the windows cross-check — it compiles the ipconfig path), commit**

Run: `cargo test -p izba-core egress::dns` → PASS
Run: `cargo check --target x86_64-pc-windows-gnu -p izba-core` → PASS

```bash
git add crates/izba-core/src/daemon/egress/ crates/izba-core/Cargo.toml Cargo.lock
git commit -m "feat(core): egress DNS seam — raw UDP forwarder to system upstream"
```

### Task A4: izba-core — egress router (`egress/router.rs`)

**Files:**
- Create: `crates/izba-core/src/daemon/egress/router.rs`
- Modify: `crates/izba-core/src/daemon/egress/mod.rs` (add `pub mod router;`)
- Modify: `crates/izba-core/src/portfwd.rs` (make `pump_bidirectional` `pub(crate)`)

- [ ] **Step 1: Make the splice helper reusable.** In `portfwd.rs`, change `fn pump_bidirectional(client: TcpStream, vs: UdsStream)` to `pub(crate) fn pump_bidirectional(client: TcpStream, vs: UdsStream)`. No behavior change.

- [ ] **Step 2: Write router + tests**

`crates/izba-core/src/daemon/egress/router.rs`:

```rust
//! Per-connection dispatch for the egress plane: read the guest's
//! `StreamOpen` frame, then route. `TcpConnect` → policy → host dial-out →
//! splice; `Dns` (and `TcpConnect` to :53 — a hardcoded-resolver client) →
//! the resolver. The M5 MITM/vault branch hangs off this dispatch point.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use izba_proto::{dns, read_frame, write_frame, ErrorKind, Response, StreamOpen};

use super::dns::Resolver;
use super::policy::{FlowDesc, Policy, Verdict};
use crate::vmm::UdsStream;

/// Same cap as the guest-side TcpDial: a wedged dial must not pin a thread.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve one guest-initiated egress connection (the vsock-1027 bridge).
pub fn handle_conn(
    mut conn: UdsStream,
    sandbox: &str,
    policy: &dyn Policy,
    resolver: &dyn Resolver,
) {
    let open: StreamOpen = match read_frame(&mut conn) {
        Ok(o) => o,
        Err(_) => return,
    };
    match open {
        StreamOpen::TcpConnect { addr, port } => {
            tcp_connect(conn, sandbox, policy, resolver, &addr, port)
        }
        StreamOpen::Dns => dns_loop(conn, resolver),
        _ => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "unsupported StreamOpen on the egress port".into(),
                },
            );
        }
    }
}

fn tcp_connect(
    mut conn: UdsStream,
    sandbox: &str,
    policy: &dyn Policy,
    resolver: &dyn Resolver,
    addr: &str,
    port: u16,
) {
    let flow = FlowDesc {
        sandbox: sandbox.to_string(),
        addr: addr.to_string(),
        port,
    };
    if policy.check(&flow) == Verdict::Deny {
        let _ = write_frame(
            &mut conn,
            &Response::Error {
                kind: ErrorKind::ConnectFailed,
                message: format!("egress to {addr}:{port} denied by policy"),
            },
        );
        return;
    }
    // TCP DNS: izbad IS the resolver — answer locally instead of dialing
    // out. After Ok the raw stream carries RFC 1035 TCP framing, which is
    // exactly the `Dns` stream contract.
    if port == 53 {
        if write_frame(&mut conn, &Response::Ok).is_err() {
            return;
        }
        dns_loop(conn, resolver);
        return;
    }
    let ip: IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: format!("not an IP literal: {addr}"),
                },
            );
            return;
        }
    };
    match TcpStream::connect_timeout(&SocketAddr::new(ip, port), DIAL_TIMEOUT) {
        Ok(target) => {
            if write_frame(&mut conn, &Response::Ok).is_err() {
                return;
            }
            crate::portfwd::pump_bidirectional(target, conn);
        }
        Err(e) => {
            let _ = write_frame(
                &mut conn,
                &Response::Error {
                    kind: ErrorKind::ConnectFailed,
                    message: e.to_string(),
                },
            );
        }
    }
}

/// Framed query/response pairs until EOF; resolver failures become SERVFAIL
/// so the guest client fails fast instead of timing out.
fn dns_loop(mut conn: UdsStream, resolver: &dyn Resolver) {
    while let Ok(Some(query)) = dns::read_dns_msg(&mut conn) {
        let resp = resolver.handle(&query).unwrap_or_else(|e| {
            eprintln!("izbad: dns forward failed: {e:#}");
            dns::servfail(&query)
        });
        if dns::write_dns_msg(&mut conn, &resp).is_err() {
            return;
        }
    }
    let _ = conn.shutdown(std::net::Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::policy::AllowAll;
    use std::io::{Read, Write};

    struct FakeResolver;
    impl Resolver for FakeResolver {
        fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut r = b"ans:".to_vec();
            r.extend_from_slice(query);
            Ok(r)
        }
    }

    struct FailingResolver;
    impl Resolver for FailingResolver {
        fn handle(&self, _q: &[u8]) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("upstream down")
        }
    }

    struct DenyAll;
    impl Policy for DenyAll {
        fn check(&self, _f: &FlowDesc) -> Verdict {
            Verdict::Deny
        }
    }

    fn spawn_handler(
        policy: &'static (dyn Policy + Sync),
        resolver: &'static (dyn Resolver + Sync),
    ) -> UdsStream {
        let (client, server) = UdsStream::pair().unwrap();
        std::thread::spawn(move || handle_conn(server, "web", policy, resolver));
        client
    }

    #[test]
    fn dns_stream_roundtrips_queries() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        dns::write_dns_msg(&mut c, b"q1").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q1");
        dns::write_dns_msg(&mut c, b"q2").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:q2");
        c.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(dns::read_dns_msg(&mut c).unwrap().is_none());
    }

    #[test]
    fn dns_resolver_failure_becomes_servfail() {
        let mut c = spawn_handler(&AllowAll, &FailingResolver);
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        dns::write_dns_msg(&mut c, &q).unwrap();
        let resp = dns::read_dns_msg(&mut c).unwrap().unwrap();
        assert_eq!(&resp[..2], &[0xbe, 0xef]);
        assert_eq!(resp[3] & 0x0f, 0x02, "RCODE=SERVFAIL");
    }

    #[test]
    fn tcp_connect_denied_by_policy() {
        let mut c = spawn_handler(&DenyAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "1.2.3.4".into(),
                port: 443,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::ConnectFailed);
                assert!(message.contains("denied"), "{message}");
            }
            other => panic!("expected deny error, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_bad_addr_is_bad_request() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "not-an-ip".into(),
                port: 80,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn tcp_connect_port53_routes_to_resolver() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "8.8.8.8".into(),
                port: 53,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        dns::write_dns_msg(&mut c, b"tq").unwrap();
        assert_eq!(dns::read_dns_msg(&mut c).unwrap().unwrap(), b"ans:tq");
    }

    #[test]
    fn unsupported_stream_open_is_bad_request() {
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(&mut c, &StreamOpen::TcpDial { port: 80 }).unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Real dial-out happy path + refused port. Binds a TcpListener —
    /// runtime-skip where denied.
    #[test]
    fn tcp_connect_dials_and_splices() {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_connect_dials_and_splices: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        let srv = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"re:").unwrap();
            s.write_all(&buf[..n]).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
        });
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "127.0.0.1".into(),
                port,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Ok => {}
            other => panic!("expected Ok, got {other:?}"),
        }
        c.write_all(b"hi").unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"re:hi");
        srv.join().unwrap();
    }

    #[test]
    fn tcp_connect_refused_reports_connect_failed() {
        let port = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => {
                let p = l.local_addr().unwrap().port();
                drop(l);
                p
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP tcp_connect_refused: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let mut c = spawn_handler(&AllowAll, &FakeResolver);
        write_frame(
            &mut c,
            &StreamOpen::TcpConnect {
                addr: "127.0.0.1".into(),
                port,
            },
        )
        .unwrap();
        match read_frame::<_, Response>(&mut c).unwrap() {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::ConnectFailed),
            other => panic!("expected ConnectFailed, got {other:?}"),
        }
    }
}
```

Note for the windows cross-gate: `UdsStream::pair()` exists on both platforms (uds_windows provides `pair`), and these are unit tests compiled per-host only — but `cargo clippy --target x86_64-pc-windows-gnu --all-targets` DOES compile them; keep the code platform-neutral (it is — no `std::os::unix` imports here).

- [ ] **Step 3: Run, gates, commit**

Run: `cargo test -p izba-core egress::router` → PASS

```bash
git add crates/izba-core/src/daemon/egress/ crates/izba-core/src/portfwd.rs
git commit -m "feat(core): egress router — TcpConnect dial-out + Dns dispatch with policy/resolver seams"
```

### Task A5: izba-core — `EgressManager` (per-sandbox vsock_1027 listeners)

**Files:**
- Modify: `crates/izba-core/src/daemon/egress/mod.rs`

- [ ] **Step 1: Write manager + tests** (replace the module-docs-only `mod.rs`; keep the doc comment):

```rust
//! izbad-owned egress: the guest-initiated vsock 1027 plane. Module seams
//! (policy / dns / router / manager) are deliberately separable — M2 fills
//! policy, M4 fronts dns with member names, M5 branches MITM off the router.

pub mod dns;
pub mod policy;
pub mod router;

use anyhow::Context;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::daemon::transport::UdsListener;
use crate::paths::Paths;
use izba_proto::EGRESS_PORT;
use self::dns::Resolver;
use self::policy::Policy;

/// Host-side unix path the VMM bridges guest-initiated vsock connections
/// to (Firecracker convention, shared by CH and OpenVMM):
/// `<vsock.sock>_<port>`.
pub fn listener_path(paths: &Paths, name: &str) -> PathBuf {
    paths.run_dir(name).join(format!("vsock.sock_{EGRESS_PORT}"))
}

struct EgressSlot {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// All egress listeners, keyed by sandbox name. The daemon owns one
/// instance for its lifetime; daemon restart severs live flows (decided —
/// adopt rebinds for new ones).
pub struct EgressManager {
    inner: Mutex<HashMap<String, EgressSlot>>,
    policy: Arc<dyn Policy>,
    resolver: Arc<dyn Resolver>,
}

impl EgressManager {
    pub fn new(policy: Arc<dyn Policy>, resolver: Arc<dyn Resolver>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            policy,
            resolver,
        }
    }

    /// Idempotent: bind the egress listener for `name` unless one is
    /// already alive. A finished (crashed) accept thread is rebound — this
    /// doubles as the supervisor's respawn path.
    pub fn ensure_listening(&self, paths: &Paths, name: &str) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(slot) = inner.get(name) {
            if !slot.thread.is_finished() {
                return Ok(());
            }
            inner.remove(name);
        }
        let path = listener_path(paths, name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("removing stale {}", path.display()))
            }
        }
        let listener = UdsListener::bind(&path)
            .with_context(|| format!("binding egress listener {}", path.display()))?;
        listener
            .set_nonblocking(true)
            .context("egress listener nonblocking")?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let policy = Arc::clone(&self.policy);
        let resolver = Arc::clone(&self.resolver);
        let sandbox = name.to_string();
        let thread = std::thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _peer)) => {
                        if conn.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let policy = Arc::clone(&policy);
                        let resolver = Arc::clone(&resolver);
                        let sandbox = sandbox.clone();
                        std::thread::spawn(move || {
                            router::handle_conn(conn, &sandbox, &*policy, &*resolver)
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!("izbad: egress accept for '{sandbox}': {e}");
                        return;
                    }
                }
            }
        });
        inner.insert(name.to_string(), EgressSlot { stop, thread });
        Ok(())
    }

    /// Stop and join the listener of `name` (sandbox stop/rm); removes the
    /// socket file so a later VMM bridge attempt fails fast.
    pub fn stop(&self, paths: &Paths, name: &str) {
        let Some(slot) = self.inner.lock().unwrap().remove(name) else {
            return;
        };
        slot.stop.store(true, Ordering::SeqCst);
        let _ = slot.thread.join();
        let _ = std::fs::remove_file(listener_path(paths, name));
    }

    pub fn listening(&self, name: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(name)
            .map(|s| !s.thread.is_finished())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::policy::AllowAll;
    use super::*;
    use crate::vmm::UdsStream;
    use izba_proto::{dns as pdns, write_frame, StreamOpen};

    struct EchoResolver;
    impl Resolver for EchoResolver {
        fn handle(&self, q: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(q.to_vec())
        }
    }

    fn mgr() -> EgressManager {
        EgressManager::new(Arc::new(AllowAll), Arc::new(EchoResolver))
    }

    fn test_paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.run_dir("web")).unwrap();
        (dir, paths)
    }

    #[test]
    fn listener_path_follows_vmm_convention() {
        let p = Paths::with_root("/data/izba".into());
        assert_eq!(
            listener_path(&p, "web"),
            PathBuf::from("/data/izba/sandboxes/web/run/vsock.sock_1027")
        );
    }

    /// Full lifecycle against a real unix listener — runtime-skip where the
    /// sandbox denies bind (house pattern).
    #[test]
    fn ensure_listening_accepts_and_routes() {
        let (_d, paths) = test_paths();
        let m = mgr();
        match m.ensure_listening(&paths, "web") {
            Ok(()) => {}
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
            {
                eprintln!("SKIP ensure_listening_accepts_and_routes: bind denied: {e:#}");
                return;
            }
            Err(e) => panic!("ensure_listening: {e:#}"),
        }
        assert!(m.listening("web"));
        // Idempotent.
        m.ensure_listening(&paths, "web").unwrap();

        // Drive one DNS exchange through the real listener.
        let mut c = UdsStream::connect(listener_path(&paths, "web")).unwrap();
        write_frame(&mut c, &StreamOpen::Dns).unwrap();
        pdns::write_dns_msg(&mut c, b"ping").unwrap();
        assert_eq!(pdns::read_dns_msg(&mut c).unwrap().unwrap(), b"ping");
        drop(c);

        m.stop(&paths, "web");
        assert!(!m.listening("web"));
        assert!(
            !listener_path(&paths, "web").exists(),
            "socket file removed on stop"
        );
    }

    #[test]
    fn stop_unknown_is_a_noop() {
        let (_d, paths) = test_paths();
        mgr().stop(&paths, "ghost");
    }
}
```

- [ ] **Step 2: Run, gates, commit**

Run: `cargo test -p izba-core egress` → PASS (the bind test may SKIP in the claude sandbox; it runs for real in CI/dev shells)

```bash
git add crates/izba-core/src/daemon/egress/mod.rs
git commit -m "feat(core): EgressManager — per-sandbox vsock_1027 unix listeners with accept loops"
```

### Task A6: opt-in plumbing — `EgressMode` through state/create/CLI + guest cmdline

**Files:**
- Modify: `crates/izba-core/src/state.rs` (EgressMode + SandboxConfig field)
- Modify: `crates/izba-core/src/sandbox.rs` (CreateOpts field, create() copy, start() cmdline)
- Modify: `crates/izba-core/src/daemon/proto.rs` (DaemonCreate field)
- Modify: `crates/izba-core/src/daemon/server.rs` (pass through in dispatch Create)
- Modify: `crates/izba-cli/src/main.rs` (`--egress` arg) and `crates/izba-cli/src/commands/mod.rs` + `create.rs` (+ `run.rs` — it shares SandboxOpts)
- Modify: `crates/izba-core/src/testutil.rs` and the existing `CreateOpts{...}` literals in tests (they gain `egress: EgressMode::default()` or rely on `..Default` — CreateOpts has no Default; add the field everywhere the compiler points)

- [ ] **Step 1: Write the failing tests.**

In `state.rs` tests:

```rust
    #[test]
    fn egress_mode_defaults_to_passt_for_old_configs() {
        // A pre-M1 config.json has no "egress" key.
        let old = r#"{"image_digest":"sha256:a","image_ref":"r","cpus":1,
            "mem_mb":256,"workspace":"/w","ports":[]}"#;
        let c: SandboxConfig = serde_json::from_str(old).unwrap();
        assert_eq!(c.egress, EgressMode::Passt);
    }

    #[test]
    fn egress_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EgressMode::Izbad).unwrap(),
            r#""izbad""#
        );
        assert_eq!(
            serde_json::to_string(&EgressMode::Passt).unwrap(),
            r#""passt""#
        );
    }
```

In `sandbox.rs` tests, find the existing cmdline assertion (`spec.cmdline.contains("console=ttyS0 ip=dhcp")` around line 819) and add a sibling test that an `egress: EgressMode::Izbad` config produces a cmdline containing `izba.egress=1` while the default does not. Follow whatever helper that existing test uses to build the spec (it goes through a `MockDriver` recording the `VmSpec` — see `testutil::MockDriver`).

- [ ] **Step 2: Implement.**

`state.rs`:

```rust
/// Which path carries guest egress. M1 transition knob: `Passt` is the v1
/// NAT (passt on CH / consomme on OpenVMM); `Izbad` is the vsock-1027
/// stub. Removed at the M1 phase-C cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    #[default]
    Passt,
    Izbad,
}
```

`SandboxConfig` gains:

```rust
    /// Egress datapath; default keeps pre-M1 configs deserializing.
    #[serde(default)]
    pub egress: EgressMode,
```

`sandbox.rs` — `CreateOpts` gains `pub egress: EgressMode`; `create()` copies it into `SandboxConfig`; `start_with_timeouts()` cmdline becomes:

```rust
    let mut cmdline = format!("console=ttyS0 ip=dhcp izba.hostname={name}");
    if config.egress == EgressMode::Izbad {
        cmdline.push_str(" izba.egress=1");
    }
```

(and `cmdline,` in the `VmSpec` literal).

`daemon/proto.rs` — `DaemonCreate` gains:

```rust
    /// Egress datapath (M1 transition knob). Defaults for old clients.
    #[serde(default)]
    pub egress: crate::state::EgressMode,
```

`daemon/server.rs` dispatch `Create` passes `egress: c.egress` into `CreateOpts`.

CLI `main.rs` `SandboxOpts` gains:

```rust
    /// Egress path: 'passt' (v1 NAT) or 'izbad' (M1 vsock egress)
    #[arg(long, default_value = "passt")]
    egress: String,
```

`commands/mod.rs` gains:

```rust
pub(crate) fn parse_egress(s: &str) -> anyhow::Result<izba_core::state::EgressMode> {
    match s {
        "passt" => Ok(izba_core::state::EgressMode::Passt),
        "izbad" => Ok(izba_core::state::EgressMode::Izbad),
        other => anyhow::bail!("invalid --egress '{other}' (expected 'passt' or 'izbad')"),
    }
}
```

`commands/create.rs` (and the create path inside `commands/run.rs`) add `egress: super::parse_egress(&opts.egress)?` to the `DaemonCreate` literal.

Fix every `CreateOpts{...}` / `DaemonCreate{...}` literal the compiler reports (tests in `sandbox.rs`, `server.rs`, `supervisor.rs`, `integration.rs`, `daemon_e2e.rs`, `testutil.rs`) by adding `egress: EgressMode::Passt` (or `Default::default()`).

- [ ] **Step 3: Run the full workspace tests + gates**

Run: `cargo test --workspace` → PASS

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/src crates/izba-cli/src crates/izba-core/tests crates/izba-cli/tests
git commit -m "feat(core,cli): per-sandbox EgressMode (--egress passt|izbad) + izba.egress=1 cmdline"
```

### Task A7: daemon wiring — bind/teardown/adopt/supervise egress listeners

**Files:**
- Modify: `crates/izba-core/src/daemon/server.rs` (DaemonDeps, Daemon, dispatch Start/Stop/Rm, adopt)
- Modify: `crates/izba-core/src/daemon/supervisor.rs` (tick signature + egress upkeep)

- [ ] **Step 1: Write the failing test** in `server.rs` tests:

```rust
    /// Start on an egress=izbad sandbox binds the vsock_1027 listener;
    /// Stop removes it. Runtime-skips where the sandbox denies bind.
    #[test]
    fn start_binds_egress_listener_stop_removes_it() {
        use crate::daemon::egress;
        use crate::state::EgressMode;
        let (dir, paths) = test_paths();
        std::fs::create_dir_all(dir.path().join("ws")).unwrap();
        let vmm = spawn_sleep(dir.path());
        let mut deps = test_deps();
        deps.connector = Box::new(fake_connector(
            Arc::new(Mutex::new(Vec::new())),
            Some(vmm.clone()),
        ));
        let d = Arc::new(Daemon::new(paths, deps));
        let mut c = client_conn(&d);
        let mut req = create_req(&dir, "web");
        if let DaemonRequest::Create(ref mut dc) = req {
            dc.egress = EgressMode::Izbad;
        }
        assert!(matches!(rpc(&mut c, &req), DaemonResponse::Created { .. }));
        match rpc(&mut c, &DaemonRequest::Start { name: "web".into() }) {
            DaemonResponse::Ok => {}
            DaemonResponse::Error { message }
                if message.contains("denied") || message.contains("Permission") =>
            {
                eprintln!("SKIP start_binds_egress_listener: bind denied: {message}");
                return;
            }
            other => panic!("start: {other:?}"),
        }
        assert!(d.egress.listening("web"));
        assert!(egress::listener_path(&d.paths, "web").exists());

        write_state(&d.paths, "web", vmm.clone());
        assert!(matches!(
            rpc(&mut c, &DaemonRequest::Stop { name: "web".into() }),
            DaemonResponse::Ok
        ));
        assert!(!d.egress.listening("web"));
        assert!(!egress::listener_path(&d.paths, "web").exists());
    }
```

Run: `cargo test -p izba-core daemon::server` → FAIL (no `egress` field on Daemon, no DaemonCreate change needed — that landed in A6)

- [ ] **Step 2: Implement the wiring.**

`DaemonDeps` gains the two seams (and `production()` + `test_deps()` fill them):

```rust
    pub egress_policy: std::sync::Arc<dyn crate::daemon::egress::policy::Policy>,
    pub egress_resolver: std::sync::Arc<dyn crate::daemon::egress::dns::Resolver>,
// production():
            egress_policy: std::sync::Arc::new(crate::daemon::egress::policy::AllowAll),
            egress_resolver: std::sync::Arc::new(crate::daemon::egress::dns::UdpForwarder::system()),
// test_deps(): same AllowAll, plus a fixed-address forwarder (never queried in these tests):
            egress_policy: std::sync::Arc::new(crate::daemon::egress::policy::AllowAll),
            egress_resolver: std::sync::Arc::new(crate::daemon::egress::dns::UdpForwarder::new(
                "127.0.0.1:53".parse().unwrap(),
            )),
```

`Daemon` gains `pub egress: EgressManager`, constructed in `Daemon::new`:

```rust
            egress: EgressManager::new(
                Arc::clone(&deps.egress_policy),
                Arc::clone(&deps.egress_resolver),
            ),
```

(move the two `Arc`s out of `deps` or clone them before `deps` is stored — cloning is simplest; adjust field order so `deps` is still moved in afterwards.)

`dispatch` `Start` — load the config FIRST (before `sandbox::start`), bind the listener BEFORE launch so the guest can dial during boot, and tear it down if start fails:

```rust
            DaemonRequest::Start { name } => {
                progress(format!("starting '{name}'..."));
                let config: SandboxConfig =
                    load_json(&d.paths.sandbox_dir(&name).join(CONFIG_FILE))?
                        .with_context(|| format!("no config.json for '{name}'"))?;
                let art = (d.deps.artifacts)(&d.paths)?;
                if config.egress == EgressMode::Izbad {
                    d.egress.ensure_listening(&d.paths, &name)?;
                }
                if let Err(e) = sandbox::start(&d.paths, &name, d.deps.driver.as_ref(), &art) {
                    d.egress.stop(&d.paths, &name);
                    return Err(e);
                }
                // ... existing relay republish + registry code unchanged ...
            }
```

(The `return Err(e)` form means hoisting the Start arm body into the closure idiom already used — adapt to the surrounding `Ok(match ...)` structure: wrap with an inner closure or restructure as the existing code style allows; the behavior contract is the three bullets above.)

`Stop` and `Rm` arms add `d.egress.stop(&d.paths, &name);` right next to `d.relays.stop_all(&name);`.

`adopt()` — inside the per-info loop, after the relay re-publish branch:

```rust
        if info.liveness != Liveness::Stopped {
            if let Ok(Some(config)) =
                load_json::<SandboxConfig>(&d.paths.sandbox_dir(&info.name).join(CONFIG_FILE))
            {
                if config.egress == EgressMode::Izbad {
                    if let Err(e) = d.egress.ensure_listening(&d.paths, &info.name) {
                        eprintln!("izbad: egress listener for '{}': {e:#}", info.name);
                    }
                }
            }
        }
```

`supervisor.rs` — extend the signature and the loop (both call sites: `run_daemon_with`'s tick thread and the existing tests):

```rust
pub fn tick(
    paths: &Paths,
    registry: &Registry,
    relays: &RelayManager,
    egress: &crate::daemon::egress::EgressManager,
    connector: Connector,
) {
    // ... existing list + loop ...
    for info in &infos {
        if info.liveness == Liveness::Stopped {
            relays.stop_all(&info.name);
            egress.stop(paths, &info.name);
        } else {
            relays.respawn_dead(paths, &info.name);
            if let Ok(Some(config)) = crate::state::load_json::<crate::state::SandboxConfig>(
                &paths.sandbox_dir(&info.name).join(crate::state::CONFIG_FILE),
            ) {
                if config.egress == crate::state::EgressMode::Izbad {
                    let _ = egress.ensure_listening(paths, &info.name);
                }
            }
        }
    }
    registry.replace_all(infos);
}
```

(`ensure_listening` is idempotent and doubles as crash-respawn.) Update `supervisor::tick` call in `server.rs` (`supervisor::tick(&d.paths, &d.registry, &d.relays, &d.egress, d.connector())`) and the supervisor test (pass a `EgressManager::new(Arc::new(AllowAll), Arc::new(UdpForwarder::new("127.0.0.1:53".parse().unwrap())))`).

- [ ] **Step 3: Run, gates, commit**

Run: `cargo test -p izba-core` → PASS

```bash
git add crates/izba-core/src/daemon/
git commit -m "feat(core): izbad binds/supervises per-sandbox egress listeners (start/stop/rm/adopt/tick)"
```

### Task A8: izba-init — DNS half of the egress stub

**Files:**
- Create: `crates/izba-init/src/egress.rs`
- Modify: `crates/izba-init/src/main.rs` (module, cmdline gate, resolv.conf, thread spawn)
- Modify: `crates/izba-init/src/server.rs` (make `relay_pump` and `dup_fd` `pub(crate)` — `dup_fd` is needed in phase B; harmless now)

- [ ] **Step 1: Write `egress.rs` with tests**

```rust
//! Guest egress stub — M1. This file ships the DNS half (UDP :53 →
//! per-query vsock `Dns` stream to izbad); the TCP REDIRECT half (nft +
//! SO_ORIGINAL_DST) lands with the phase-B kernel/nft artifacts.

use izba_proto::{dns, write_frame, StreamOpen, EGRESS_PORT};
use std::io::{self, Read, Write};
use std::net::UdpSocket;

/// Dial the host (CID 2) egress port. Production dialer; tests substitute
/// a socketpair half through the `forward_query` seam.
pub fn dial_host() -> io::Result<vsock::VsockStream> {
    vsock::VsockStream::connect_with_cid_port(libc::VMADDR_CID_HOST, EGRESS_PORT)
}

/// One UDP query → one `Dns` vsock stream → one response. Any failure
/// becomes SERVFAIL so the client fails fast instead of timing out.
pub fn forward_query<S, D>(dial: D, query: &[u8]) -> Vec<u8>
where
    S: Read + Write,
    D: FnOnce() -> io::Result<S>,
{
    match try_forward(dial, query) {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("izba-init: dns forward: {e}");
            dns::servfail(query)
        }
    }
}

fn try_forward<S, D>(dial: D, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: Read + Write,
    D: FnOnce() -> io::Result<S>,
{
    let mut s = dial()?;
    write_frame(&mut s, &StreamOpen::Dns)?;
    dns::write_dns_msg(&mut s, query)?;
    match dns::read_dns_msg(&mut s)? {
        Some(resp) => Ok(resp),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no dns response from izbad",
        )),
    }
}

/// Bind 0.0.0.0:53 and serve forever (daemon thread); one thread per query
/// so a slow upstream cannot head-of-line-block other resolutions.
pub fn serve_dns_udp() -> io::Result<()> {
    let sock = UdpSocket::bind(("0.0.0.0", 53))?;
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => continue,
        };
        let query = buf[..n].to_vec();
        let sock2 = sock.try_clone()?;
        std::thread::spawn(move || {
            let resp = forward_query(dial_host, &query);
            let _ = sock2.send_to(&resp, peer);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::read_frame;
    use std::os::unix::net::UnixStream;

    /// Fake izbad on the far end of a socketpair: expects the `Dns` frame,
    /// answers each framed query with `re:<query>`.
    fn fake_izbad() -> (UnixStream, std::thread::JoinHandle<()>) {
        let (mine, theirs) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(matches!(open, StreamOpen::Dns), "expected Dns, got {open:?}");
            while let Ok(Some(q)) = dns::read_dns_msg(&mut s) {
                let mut r = b"re:".to_vec();
                r.extend_from_slice(&q);
                dns::write_dns_msg(&mut s, &r).unwrap();
            }
        });
        (mine, h)
    }

    #[test]
    fn forwards_one_query() {
        let (sock, h) = fake_izbad();
        let resp = forward_query(|| Ok(sock), b"hello");
        assert_eq!(resp, b"re:hello");
        h.join().unwrap();
    }

    #[test]
    fn dial_failure_becomes_servfail() {
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let resp = forward_query::<UnixStream, _>(
            || Err(io::Error::new(io::ErrorKind::ConnectionRefused, "no izbad")),
            &q,
        );
        assert_eq!(&resp[..2], &[0xbe, 0xef], "ID preserved");
        assert_eq!(resp[3] & 0x0f, 0x02, "SERVFAIL");
    }

    #[test]
    fn truncated_peer_becomes_servfail() {
        let (mine, theirs) = UnixStream::pair().unwrap();
        drop(theirs); // izbad vanished
        let q = [0x00u8, 0x01, 0x01, 0x00];
        let resp = forward_query(|| Ok(mine), &q);
        assert_eq!(resp[3] & 0x0f, 0x02);
    }
}
```

- [ ] **Step 2: Wire `main.rs`.** Add `mod egress;`. After the `izba.ipv4only` block:

```rust
    let egress_on = params.get("izba.egress").map(String::as_str) == Some("1");
```

Replace the `write_resolv_conf();` call with `write_resolv_conf(egress_on);` and change the function:

```rust
/// With izbad egress, the resolver is the local stub (interim: loopback;
/// the dummy0-carried 192.168.127.1 arrives with the phase-C cutover).
/// Otherwise: kernel `ip=dhcp` autoconfig result from /proc/net/pnp.
fn write_resolv_conf(egress_on: bool) {
    let conf = if egress_on {
        "nameserver 127.0.0.1\n".to_string()
    } else {
        let Ok(pnp) = std::fs::read_to_string("/proc/net/pnp") else {
            return;
        };
        pnp.lines()
            .filter(|l| l.starts_with("nameserver") || l.starts_with("domain"))
            .map(|l| format!("{l}\n"))
            .collect()
    };
    let _ = std::fs::create_dir_all("/rootfs/etc");
    if let Err(e) = std::fs::write("/rootfs/etc/resolv.conf", conf) {
        eprintln!("izba-init: writing resolv.conf: {e}");
    }
}
```

After the two server-thread spawns, add:

```rust
    if egress_on {
        std::thread::spawn(|| {
            if let Err(e) = egress::serve_dns_udp() {
                eprintln!("izba-init: dns stub: {e}");
            }
        });
    }
```

In `server.rs`, change `fn relay_pump` → `pub(crate) fn relay_pump` and `fn dup_fd` → `pub(crate) fn dup_fd`.

- [ ] **Step 3: Run, gates (musl build is mandatory here), commit**

Run: `cargo test -p izba-init` → PASS
Run: `cargo build -p izba-init --target x86_64-unknown-linux-musl --release` → PASS

```bash
git add crates/izba-init/src/
git commit -m "feat(init): guest DNS stub — UDP :53 forwarded over vsock Dns streams (izba.egress=1)"
```

### Task A9: KVM integration — egress DNS end-to-end (the guest-initiated-vsock validation)

**Files:**
- Modify: `crates/izba-core/tests/integration.rs`
- Requires: rebuilt initramfs (new izba-init), existing kernel. **Unsandboxed** (KVM).

- [ ] **Step 1: Rebuild the initramfs** (sandbox OFF):

```sh
hack/build-initramfs.sh   # writes dist/initramfs.cpio.gz
cp dist/initramfs.cpio.gz ~/.local/share/izba/artifacts/initramfs.cpio.gz  # or wherever IZBA_INITRAMFS points
```

- [ ] **Step 2: Add the test.** The harness helper `create_sandbox` builds `CreateOpts` — add an `egress: EgressMode` parameter (or a `create_sandbox_with` sibling) per the compiler. New test:

```rust
/// M1 phase A exit: an egress=izbad sandbox resolves DNS through izbad.
/// This is ALSO the runtime validation of guest-initiated hybrid vsock
/// (guest dials CID 2:1027 → CH bridges to run/vsock.sock_1027).
#[test]
fn egress_dns_via_izbad() {
    let Some(env) = want() else { return };
    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-dns");
    create_sandbox_egress(&env, &mut tb, "egress-dns", &ws, EgressMode::Izbad);

    // Daemonless suite: stand in for izbad's listener ourselves.
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};
    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::system()),
    );
    mgr.ensure_listening(&tb.paths, "egress-dns")
        .expect("bind vsock_1027 listener");

    start_sandbox(&env, &tb, "egress-dns").expect("start");

    // getent uses the guest resolv.conf (nameserver 127.0.0.1 -> stub).
    let out = exec_ok(
        &tb.paths,
        "egress-dns",
        &["sh", "-lc", "getent hosts example.com"],
    );
    assert!(
        out.contains("example.com"),
        "expected a resolved address, got: {out}"
    );

    stop_sandbox(&tb, "egress-dns");
    mgr.stop(&tb.paths, "egress-dns");
}
```

(Adapt helper names to the actual harness — `boot`, `exec_ok`, `TestBox` etc. already exist; only the egress-mode-aware create helper is new.)

- [ ] **Step 3: Run the suite** (sandbox OFF):

```sh
IZBA_INTEGRATION=1 IZBA_KERNEL=... IZBA_INITRAMFS=... \
  cargo test -p izba-core --test integration -- --test-threads=1 --nocapture egress_dns_via_izbad
```
Expected: PASS. Then run the FULL suite (all tests, `--test-threads=1`) — must stay 15/15 + the new one.

- [ ] **Step 4: Gates + commit**

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): KVM integration — egress DNS through izbad (guest-initiated vsock validated)"
```

### Task A10: Windows/OpenVMM phase-A validation

**Files:**
- Modify: `hack/spike/validate-izba-windows.ps1` (add an egress-DNS check; read the script first and follow its existing check conventions)
- Requires: Windows interop (`powershell.exe -NoProfile`, unsandboxed), staged izba build (`hack/stage-izba-windows.sh`).

- [ ] **Step 1: Stage the new build to the Windows host** (script exists: `hack/stage-izba-windows.sh`; it cross-builds and copies binaries + artifacts — read it and run it).

- [ ] **Step 2: Add the check to the PS suite** — the shape (adapt to the suite's helper functions for assertions/cleanup):

```powershell
# --- M1 phase A: egress DNS via izbad (guest-initiated vsock) ---
& $izba create --egress izbad --name egress-a $workspace
& $izba run --name egress-a $workspace -- true   # or the suite's start helper
$out = & $izba exec egress-a -- sh -lc "getent hosts example.com"
if ($LASTEXITCODE -ne 0 -or -not ($out -match "example.com")) {
    Fail "egress DNS via izbad: got '$out'"
}
& $izba rm -f egress-a
```

NOTE: the daemon must be running with the new build (`izba daemon …` auto-start covers it). This is the FIRST runtime exercise of OpenVMM's `<PATH>_<port>` guest-initiated bridging — if the guest's `connect(CID 2, 1027)` does not reach `vsock.sock_1027`, STOP and investigate OpenVMM's `support/hybrid_vsock` behavior before continuing (spec §1.1 names this the plan-B trigger; do not work around it silently).

- [ ] **Step 3: Run the suite via interop** (unsandboxed):

```sh
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\path\to\validate-izba-windows.ps1'
```
Expected: previous checks unchanged (the known consomme guest-egress failure may persist — it is retired in phase C), new egress check PASS.

- [ ] **Step 4: Commit**

```bash
git add hack/spike/validate-izba-windows.ps1
git commit -m "test(windows): PS validation — egress DNS via izbad on OpenVMM (vsock_1027 bridge)"
```

**PHASE A CHECKPOINT:** all six gates green; KVM suite green incl. `egress_dns_via_izbad`; Windows PS egress check green on real OpenVMM. The single unverified assumption (guest-initiated vsock, both platforms) is now validated.

---

## Phase B — guest TCP stub: kernel netfilter + vendored nft + REDIRECT

### Task B1: kernel config + artifact rebuild

**Files:**
- Modify: `hack/kernel.config`
- Requires: kernel build environment (see `hack/build-kernel.sh` + `docs/testing.md`), unsandboxed.

- [ ] **Step 1: Append to `hack/kernel.config`:**

```
# Egress stub (M1): nftables REDIRECT + conntrack original-dst recovery
CONFIG_NETFILTER=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_NAT=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_IPV4=y
CONFIG_NFT_NAT=y
CONFIG_NFT_REDIR=y
# NIC-less end state (M1 phase C): dummy0 carries the static guest IP
CONFIG_DUMMY=y
```

- [ ] **Step 2: Rebuild the kernel** (`hack/build-kernel.sh`; olddefconfig may pull dependencies — if the resulting `.config` drops any of the lines above, chase the missing dependency rather than accepting the drop). Install to the artifacts dir `IZBA_KERNEL` points at.

- [ ] **Step 3: Sanity boot:** run the existing KVM integration suite once — all green (config additions must not regress boot time or networking).

- [ ] **Step 4: Commit**

```bash
git add hack/kernel.config
git commit -m "build(kernel): netfilter/nftables + dummy for the M1 egress stub"
```

### Task B2: vendored static `nft` + initramfs hook

**Files:**
- Create: `hack/build-nft.sh`
- Modify: `hack/build-initramfs.sh` (IZBA_NFT hook, mirroring IZBA_MKE2FS)
- Modify: `hack/README.md` (document both)

- [ ] **Step 1: `hack/build-nft.sh`** (docker-based static build; version pins are current at plan time — bump if fetches 404):

```sh
#!/usr/bin/env bash
# Build a static /sbin/nft for the izba initramfs (musl, via Alpine).
# Output: dist/nft  (use: IZBA_NFT=dist/nft hack/build-initramfs.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-dist/nft}"
mkdir -p "$(dirname "$OUT")"

docker run --rm -v "$PWD/dist:/out" alpine:3.22 sh -euc '
  apk add --no-cache build-base bison flex linux-headers pkgconf wget xz
  wget -qO- https://netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2 | tar xj
  (cd libmnl-1.0.5 && ./configure --enable-static --disable-shared && make -j"$(nproc)" && make install)
  wget -qO- https://netfilter.org/projects/libnftnl/files/libnftnl-1.2.9.tar.xz | tar xJ
  (cd libnftnl-1.2.9 && ./configure --enable-static --disable-shared && make -j"$(nproc)" && make install)
  wget -qO- https://netfilter.org/projects/nftables/files/nftables-1.1.3.tar.xz | tar xJ
  (cd nftables-1.1.3 \
    && ./configure --with-mini-gmp --without-cli --with-json=no \
         --enable-static --disable-shared LDFLAGS="-static" \
    && make -j"$(nproc)" \
    && strip src/nft && cp src/nft /out/nft)
'
file "$OUT" | grep -q "statically linked" || { echo "error: $OUT is not static" >&2; exit 1; }
echo "wrote $OUT"
```

(If `--without-cli` is rejected by the configure script, the flag is `--with-cli=no` on some versions — try both; the goal is no readline/linenoise dependency.)

- [ ] **Step 2: initramfs hook** in `hack/build-initramfs.sh`, right after the mke2fs block:

```sh
# Optional static nft — required for the izbad-egress TCP REDIRECT stub.
if [ -n "${IZBA_NFT:-}" ]; then
    if [ ! -f "$IZBA_NFT" ]; then
        echo "error: IZBA_NFT='$IZBA_NFT' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_NFT" "$WORK/sbin/nft"
    chmod 755 "$WORK/sbin/nft"
    echo "  embedded nft from $IZBA_NFT"
fi
```

- [ ] **Step 3: Build + verify** (unsandboxed; needs docker):

```sh
hack/build-nft.sh
IZBA_NFT=dist/nft hack/build-initramfs.sh
zcat dist/initramfs.cpio.gz | cpio -t | grep sbin/nft   # expect: sbin/nft
```

- [ ] **Step 4: Commit** (also archive `dist/nft` the same way `dist/` carries mke2fs — check `.gitignore`; if dist/ is ignored, that is fine, the script is the artifact)

```bash
git add hack/build-nft.sh hack/build-initramfs.sh hack/README.md
git commit -m "build(hack): static nft build + initramfs embedding hook (IZBA_NFT)"
```

### Task B3: izba-init — nft ruleset + TCP redirect listener (SO_ORIGINAL_DST)

**Files:**
- Modify: `crates/izba-init/src/egress.rs`
- Modify: `crates/izba-init/src/main.rs`

- [ ] **Step 1: Write the failing tests** (appended to `egress.rs` tests):

```rust
    #[test]
    fn nft_ruleset_shape() {
        // The contract bits the redirect depends on; the full file is integration-tested.
        assert!(NFT_RULESET.contains("type nat hook output priority -100"));
        assert!(NFT_RULESET.contains("ip daddr 127.0.0.0/8 return"));
        assert!(NFT_RULESET.contains(&format!("redirect to :{REDIRECT_PORT}")));
        assert!(NFT_RULESET.contains("udp dport 53 redirect to :53"));
    }

    /// handle_redirected with an injected orig-dst and a socketpair "izbad":
    /// the TcpConnect frame carries the original destination; bytes flow
    /// both ways after Ok. Binds a loopback TcpListener — runtime-skip
    /// where denied (the accepted TcpStream plays the redirected client).
    #[test]
    fn redirected_conn_speaks_tcp_connect() {
        use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP redirected_conn_speaks_tcp_connect: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        let app = std::thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"GET").unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).unwrap();
            out
        });
        let (client, _) = listener.accept().unwrap();

        let (izbad, theirs) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            match open {
                StreamOpen::TcpConnect { addr, port } => {
                    assert_eq!(addr, "93.184.216.34");
                    assert_eq!(port, 443);
                }
                other => panic!("expected TcpConnect, got {other:?}"),
            }
            write_frame(&mut s, &izba_proto::Response::Ok).unwrap();
            let mut buf = [0u8; 3];
            s.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"GET");
            s.write_all(b"200ok").unwrap();
            // Full close: izbad's splice tears down with drain.
        });

        let orig = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        handle_redirected(client, orig, || Ok(izbad));

        assert_eq!(app.join().unwrap(), b"200ok");
        fake.join().unwrap();
    }
```

Run: `cargo test -p izba-init egress` → FAIL (symbols missing)

- [ ] **Step 2: Implement** (append to `egress.rs`):

```rust
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::AsRawFd;

/// Loopback port the nat-output REDIRECT delivers all outbound TCP to.
pub const REDIRECT_PORT: u16 = 15001;

/// The fixed transparent-redirect ruleset. Loopback destinations are left
/// alone (guest-internal services, the stub itself); everything else TCP
/// goes to the stub; UDP :53 to hardcoded resolvers is pulled to the local
/// DNS socket (conntrack un-NATs the reply source). The stub's own egress
/// is AF_VSOCK — not IP — so no exclusion rule is needed and no redirect
/// loop is possible. Non-DNS UDP is denied structurally (no route once the
/// NIC goes away in phase C), not by a filter rule here.
pub const NFT_RULESET: &str = "\
table ip izba {
  chain output {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
    meta l4proto tcp redirect to :15001
    udp dport 53 redirect to :53
  }
}
";

/// Apply the ruleset via the vendored static nft.
pub fn apply_nft() -> io::Result<()> {
    std::fs::write("/tmp/izba-egress.nft", NFT_RULESET)?;
    let status = std::process::Command::new("/sbin/nft")
        .args(["-f", "/tmp/izba-egress.nft"])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("nft -f exited {status}")));
    }
    Ok(())
}

/// Recover the pre-REDIRECT destination from conntrack.
/// One tiny unsafe getsockopt; integration-covered (needs a real
/// REDIRECTed socket, which unit tests cannot make).
fn original_dst(conn: &TcpStream) -> io::Result<SocketAddrV4> {
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

/// Serve the redirect listener forever (daemon thread).
pub fn serve_tcp_redirect() -> io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", REDIRECT_PORT))?;
    loop {
        let (conn, _peer) = match listener.accept() {
            Ok(x) => x,
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        std::thread::spawn(move || {
            let orig = match original_dst(&conn) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("izba-init: SO_ORIGINAL_DST: {e}");
                    return;
                }
            };
            handle_redirected(conn, orig, dial_host);
        });
    }
}

/// Splice one redirected client connection to izbad via TcpConnect.
///
/// Teardown mirrors server.rs::tcp_dial, with the roles flipped: the
/// client->izbad thread half-closes the vsock leg (best-effort — CH does
/// not propagate guest->host half-close, the accepted v1 limitation that
/// TcpDial shares); once izbad's side is done we full-shutdown both.
pub fn handle_redirected<S, D>(client: TcpStream, orig: SocketAddrV4, dial: D)
where
    S: Read + Write + AsRawFd + Send + 'static,
    D: FnOnce() -> io::Result<S>,
{
    let mut host = match dial() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("izba-init: egress dial for {orig}: {e}");
            return;
        }
    };
    if write_frame(
        &mut host,
        &StreamOpen::TcpConnect {
            addr: orig.ip().to_string(),
            port: orig.port(),
        },
    )
    .is_err()
    {
        return;
    }
    match izba_proto::read_frame::<_, izba_proto::Response>(&mut host) {
        Ok(izba_proto::Response::Ok) => {}
        Ok(izba_proto::Response::Error { kind, message }) => {
            eprintln!("izba-init: egress {orig}: {kind:?}: {message}");
            return; // client socket drops -> app sees RST/EOF (honest refusal)
        }
        _ => return,
    }

    let host_w = match crate::server::dup_fd(host.as_raw_fd()) {
        Ok(d) => File::from(d),
        Err(_) => return,
    };
    let client_r = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    // client -> izbad
    let up = std::thread::spawn(move || {
        let mut host_w = host_w;
        crate::server::relay_pump(client_r, &mut host_w);
        unsafe { libc::shutdown(host_w.as_raw_fd(), libc::SHUT_WR) };
    });
    // izbad -> client; izbad full-closes when the remote is done.
    let mut client_w = client;
    crate::server::relay_pump(&mut host, &mut client_w);
    let _ = client_w.shutdown(std::net::Shutdown::Write);
    // Unblock the up-thread read and finish the vsock teardown.
    unsafe { libc::shutdown(host.as_raw_fd(), libc::SHUT_RDWR) };
    let _ = up.join();
}
```

(`relay_pump` takes `impl Read` — `&mut host` works because `&mut S: Read` when `S: Read`. The two `use` additions at the top of the file as shown.)

- [ ] **Step 3: Wire `main.rs`** — extend the `egress_on` block:

```rust
    if egress_on {
        // Order matters: listeners first, rules second — once REDIRECT is
        // in, every guest TCP connect lands on the stub.
        std::thread::spawn(|| {
            if let Err(e) = egress::serve_dns_udp() {
                eprintln!("izba-init: dns stub: {e}");
            }
        });
        std::thread::spawn(|| {
            if let Err(e) = egress::serve_tcp_redirect() {
                eprintln!("izba-init: tcp redirect stub: {e}");
            }
        });
        if let Err(e) = egress::apply_nft() {
            // Loud but not fatal: DNS still works via resolv.conf; TCP
            // egress is dead until fixed. The console log is captured.
            eprintln!("izba-init: applying nft ruleset: {e}");
        }
    }
```

- [ ] **Step 4: Run, gates (musl!), commit**

Run: `cargo test -p izba-init` → PASS

```bash
git add crates/izba-init/src/
git commit -m "feat(init): TCP egress stub — nft REDIRECT + SO_ORIGINAL_DST + vsock TcpConnect splice"
```

### Task B4: KVM integration — HTTP through the stub

**Files:**
- Modify: `crates/izba-core/tests/integration.rs`
- Requires: phase-B kernel + nft-embedded initramfs in the artifacts dir. **Unsandboxed.**

- [ ] **Step 1: Rebuild artifacts with the stub:**

```sh
hack/build-nft.sh   # if not built yet
IZBA_NFT=dist/nft hack/build-initramfs.sh
cp dist/initramfs.cpio.gz <artifacts>/initramfs.cpio.gz
# kernel from task B1 already installed
```

- [ ] **Step 2: Add the test:**

```rust
/// M1 phase B exit: guest TCP egress rides the stub. The guest wgets a
/// host-served one-shot HTTP page addressed by a routable host IP; the nft
/// REDIRECT intercepts, izbad dials back to the host listener.
#[test]
fn egress_http_via_stub() {
    let Some(env) = want() else { return };
    // A host IP the guest can name and izbad can dial (NOT loopback —
    // 127/8 is excluded from REDIRECT by design).
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    probe.connect(("8.8.8.8", 80)).unwrap();
    let host_ip = probe.local_addr().unwrap().ip();

    let listener = std::net::TcpListener::bind((host_ip, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nizba-m1ok")
            .unwrap();
    });

    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-http");
    create_sandbox_egress(&env, &mut tb, "egress-http", &ws, EgressMode::Izbad);
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};
    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::system()),
    );
    mgr.ensure_listening(&tb.paths, "egress-http").unwrap();
    start_sandbox(&env, &tb, "egress-http").expect("start");

    let out = exec_ok(
        &tb.paths,
        "egress-http",
        &["sh", "-lc", &format!("wget -qO- http://{host_ip}:{port}/")],
    );
    assert_eq!(out.trim(), "izba-m1ok");

    srv.join().unwrap();
    stop_sandbox(&tb, "egress-http");
    mgr.stop(&tb.paths, "egress-http");
}
```

- [ ] **Step 3: Run the new test, then the FULL suite** (`--test-threads=1`) — all green. The pre-existing `guest_networking` test (passt path) must still pass: this proves coexistence.

- [ ] **Step 4: Gates + commit**

```bash
git add crates/izba-core/tests/integration.rs
git commit -m "test(core): KVM integration — guest TCP egress through nft stub + izbad dial-out"
```

### Task B5: Windows/OpenVMM phase-B validation

**Files:**
- Modify: `hack/spike/validate-izba-windows.ps1`
- Requires: Windows interop, staged build + NEW artifacts (initramfs with nft, phase-B kernel) on the host.

- [ ] **Step 1: Re-stage** (`hack/stage-izba-windows.sh` — make sure it ships the rebuilt kernel/initramfs; extend it if it only copies binaries).

- [ ] **Step 2: Extend the egress check** — after the DNS check from A10, add a TCP fetch (mirror of the suite's existing consomme wget check, but on the `--egress izbad` sandbox):

```powershell
$out = & $izba exec egress-a -- sh -lc "wget -qO- http://example.com/ | head -c 64"
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($out)) {
    Fail "egress TCP via izbad stub: got '$out'"
}
```

(Real-internet fetch is intentional here — this is exactly the WSL/VPN-topology bug-class check; the suite's consomme egress check already does the same and FAILS today. The izbad-path one must PASS on the same host.)

- [ ] **Step 3: Run via interop; commit**

```bash
git add hack/spike/validate-izba-windows.ps1
git commit -m "test(windows): PS validation — TCP egress via izbad stub on OpenVMM"
```

**PHASE B CHECKPOINT:** stub egress works end-to-end on both platforms while passt remains the default. The WSL+VPN topology check passes on the izbad path where the consomme path fails.

---

## Phase C — cutover: one network story

### Task C1: the cutover commit (core + cli + init together — "change all ends or none")

This is ONE commit: removing the NIC while init still expects DHCP (or vice versa) breaks boot, so host and guest flip together. Old configs with `"egress":"passt"` keys still deserialize (serde ignores unknown fields once the field is gone); already-running passt sandboxes keep their passt processes until stopped — `kill()`/liveness only consult recorded pids, which remain valid.

**Files:**
- Modify: `crates/izba-core/src/vmm/spec.rs` (delete `net`)
- Modify: `crates/izba-core/src/vmm/cloud_hypervisor.rs` (delete passt + `--net`; stale-list entries `net.sock`/`passt.pid` stay in the stale sweep for one release — they clean up old runs)
- Modify: `crates/izba-core/src/vmm/openvmm.rs` (delete `--net consomme` + the `izba.ipv4only` cmdline append)
- Modify: `crates/izba-core/src/sandbox.rs` (cmdline: drop `ip=dhcp`, drop the EgressMode conditional, always `izba.egress=1`; drop `net:` from VmSpec literal)
- Modify: `crates/izba-core/src/state.rs` (delete `EgressMode` + the `egress` field)
- Modify: `crates/izba-core/src/daemon/proto.rs`, `server.rs`, `supervisor.rs` (Create passthrough gone; Start/adopt/tick bind egress listeners UNCONDITIONALLY for running sandboxes)
- Modify: `crates/izba-cli/src/main.rs`, `commands/mod.rs`, `commands/create.rs`, `commands/run.rs` (delete `--egress`)
- Modify: `crates/izba-init/src/main.rs` (egress always on; resolv.conf static; dummy0 config; drop the `izba.ipv4only` block)
- Modify: `crates/izba-init/src/net.rs` (REWRITE: ipv4only out, interface config in)
- Modify: `crates/izba-init/src/egress.rs` (resolv.conf constant moves here or stays in main — keep in main)
- Modify: all tests that named `net`, `ip=dhcp`, `--net`, passt argv, consomme argv, EgressMode (compiler + grep will find them)

- [ ] **Step 1: Write the failing tests first** (update in place — these are contract tests):

In `cloud_hypervisor.rs`: `ch_invocations` drops the passt assertion entirely (`assert!(inv.passt.is_none())` — or better, the `Invocations` struct loses its `passt` field; let the compiler drive) and the vmm argv loses `--net vhost_user=...`. In `openvmm.rs`: `openvmm_invocation` loses `--net consomme` and ` izba.ipv4only=1`. In `sandbox.rs`: the cmdline test asserts `console=ttyS0 izba.hostname=web izba.egress=1` and asserts `ip=dhcp` is ABSENT.

In `izba-init/src/net.rs` (rewrite; ioctl-based config is integration-covered, the pure parts are unit-tested):

```rust
//! Guest network bring-up for the NIC-less end state: loopback up, dummy0
//! with the static izba subnet (192.168.127.2/24 + the resolver address
//! 192.168.127.1 as an alias), default route via the dummy. Everything the
//! stub does not intercept therefore has nowhere to go — that IS the
//! non-TCP deny posture.
//!
//! All configuration is ioctl-based (SIOCSIFADDR/SIOCSIFNETMASK/
//! SIOCSIFFLAGS/SIOCADDRT) — no netlink dependency in static musl PID 1.

use std::io;
use std::net::Ipv4Addr;

pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);
pub const RESOLVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);
pub const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Bring up lo + dummy0 and install the default route. Errors are
/// reported per step so a console log names the exact failure.
pub fn configure() -> io::Result<()> {
    if_up("lo")?;
    set_addr("dummy0", GUEST_IP, NETMASK)?;
    if_up("dummy0")?;
    // The resolver address rides an ioctl alias interface.
    set_addr("dummy0:1", RESOLVER_IP, NETMASK)?;
    if_up("dummy0:1")?;
    add_default_route(RESOLVER_IP)?;
    Ok(())
}
```

with the ioctl plumbing (complete — this is the whole mechanism):

```rust
fn ctl_socket() -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

fn ifreq_named(name: &str) -> io::Result<libc::ifreq> {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= req.ifr_name.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "ifname too long"));
    }
    for (dst, src) in req.ifr_name.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    Ok(req)
}

fn sockaddr_v4(ip: Ipv4Addr) -> libc::sockaddr {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        },
        sin_zero: [0; 8],
    };
    // sockaddr_in and sockaddr are layout-compatible for this use.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) }
}

fn ioctl(req_no: libc::c_ulong, arg: *mut libc::c_void, what: &str) -> io::Result<()> {
    let sock = ctl_socket()?;
    use std::os::fd::AsRawFd;
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), req_no as _, arg) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(())
}

fn set_addr(ifname: &str, ip: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
    let mut req = ifreq_named(ifname)?;
    req.ifr_ifru.ifru_addr = sockaddr_v4(ip);
    ioctl(libc::SIOCSIFADDR, &mut req as *mut _ as *mut _, ifname)?;
    let mut req = ifreq_named(ifname)?;
    req.ifr_ifru.ifru_addr = sockaddr_v4(mask);
    ioctl(libc::SIOCSIFNETMASK, &mut req as *mut _ as *mut _, ifname)
}

fn if_up(ifname: &str) -> io::Result<()> {
    let mut req = ifreq_named(ifname)?;
    ioctl(libc::SIOCGIFFLAGS, &mut req as *mut _ as *mut _, ifname)?;
    unsafe {
        req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }
    ioctl(libc::SIOCSIFFLAGS, &mut req as *mut _ as *mut _, ifname)
}

fn add_default_route(gw: Ipv4Addr) -> io::Result<()> {
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
    rt.rt_genmask = sockaddr_v4(Ipv4Addr::UNSPECIFIED);
    rt.rt_gateway = sockaddr_v4(gw);
    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    ioctl(libc::SIOCADDRT, &mut rt as *mut _ as *mut _, "default route")
}
```

Unit tests for the pure parts only (`ifreq_named` length guard, `sockaddr_v4` byte order):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_rejects_long_names() {
        assert!(ifreq_named("a-name-longer-than-ifnamsiz!").is_err());
        assert!(ifreq_named("dummy0:1").is_ok());
    }

    #[test]
    fn sockaddr_v4_is_network_order() {
        let sa = sockaddr_v4(Ipv4Addr::new(192, 168, 127, 2));
        let sin: libc::sockaddr_in = unsafe { std::mem::transmute(sa) };
        assert_eq!(u32::from_be(sin.sin_addr.s_addr), 0xC0A87F02);
    }
}
```

- [ ] **Step 2: Implement the rest of the cutover** (the compiler is the checklist — every red site is a decision already made above):
  - `main.rs` (init): delete the ipv4only block; replace `let egress_on = ...` with unconditional egress; call `net::configure()` right before `write_resolv_conf()` (log-and-continue on error — exec/cp/vsock still work without IP networking); `write_resolv_conf()` loses its parameter and always writes `nameserver 192.168.127.1\n`; drop the `/proc/net/pnp` branch.
  - `sandbox.rs`: `cmdline: format!("console=ttyS0 izba.hostname={name} izba.egress=1")`.
  - The daemon Start/adopt/tick paths bind egress listeners for every running sandbox (the config check disappears with the field).
  - `vmm/spec.rs`, drivers, CLI: deletions as listed in **Files**.

- [ ] **Step 3: Full workspace gates** (all six — the cross-compile gates matter here, openvmm.rs changed)

Run: `cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check` → PASS
Run: musl build + both windows-gnu gates → PASS

- [ ] **Step 4: Commit**

```bash
git add crates/ 
git commit -m "feat!: one network story — izbad-owned egress everywhere; passt/consomme retired

Removes virtio-net, ip=dhcp, izba.ipv4only and the --egress knob; the guest
is a pure vsock island (dummy0 static addressing, stub-intercepted TCP/DNS,
izbad dial-out). The host-autodetect bug class (ea9e413, 30e5c67) dies here."
```

### Task C2: integration suite cutover + throughput baseline

**Files:**
- Modify: `crates/izba-core/tests/integration.rs`
- Requires: KVM, phase-B/C artifacts. **Unsandboxed.**

- [ ] **Step 1: Update the suite:**
  - `want()`: drop `passt` from the required-binaries list.
  - `guest_networking`: now exercises the stub path by construction (keep it; it IS the egress test for real internet — `wget` to a real URL, mirroring its current body).
  - `create_sandbox_egress` helper collapses back into `create_sandbox` (no mode).
  - `egress_dns_via_izbad` / `egress_http_via_stub` keep their EgressManager stand-in (the suite is daemonless) — only the create-helper call changes.
  - `boot_to_healthy_under_5s`: unchanged assertion; expect it to get FASTER (no DHCP wait) — if it somehow regresses, investigate before proceeding.

- [ ] **Step 2: Add the throughput baseline** (measured, never gated — roadmap decision):

```rust
/// M1 throughput baseline: bulk transfer through the egress stub.
/// MEASURED, NOT GATED (roadmap decision) — the number is printed for
/// trend-watching; the only assertion is that the transfer completes.
#[test]
fn egress_throughput_baseline() {
    let Some(env) = want() else { return };
    const PAYLOAD: usize = 64 * 1024 * 1024;
    let probe = std::net::UdpSocket::bind(("0.0.0.0", 0)).unwrap();
    probe.connect(("8.8.8.8", 80)).unwrap();
    let host_ip = probe.local_addr().unwrap().ip();
    let listener = std::net::TcpListener::bind((host_ip, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let srv = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        s.write_all(
            format!("HTTP/1.0 200 OK\r\nContent-Length: {PAYLOAD}\r\n\r\n").as_bytes(),
        )
        .unwrap();
        let chunk = vec![0u8; 64 * 1024];
        let mut sent = 0;
        while sent < PAYLOAD {
            let n = (PAYLOAD - sent).min(chunk.len());
            s.write_all(&chunk[..n]).unwrap();
            sent += n;
        }
    });

    let mut tb = TestBox::new();
    let ws = tb.workspace("egress-tput");
    create_sandbox(&env, &mut tb, "egress-tput", &ws);
    use izba_core::daemon::egress::{dns::UdpForwarder, policy::AllowAll, EgressManager};
    let mgr = EgressManager::new(
        std::sync::Arc::new(AllowAll),
        std::sync::Arc::new(UdpForwarder::system()),
    );
    mgr.ensure_listening(&tb.paths, "egress-tput").unwrap();
    start_sandbox(&env, &tb, "egress-tput").expect("start");

    let t0 = std::time::Instant::now();
    exec_ok(
        &tb.paths,
        "egress-tput",
        &["sh", "-lc", &format!("wget -qO /dev/null http://{host_ip}:{port}/")],
    );
    let dt = t0.elapsed();
    eprintln!(
        "EGRESS THROUGHPUT BASELINE: {:.1} MiB/s ({PAYLOAD} bytes in {dt:?})",
        PAYLOAD as f64 / 1024.0 / 1024.0 / dt.as_secs_f64()
    );

    srv.join().unwrap();
    stop_sandbox(&tb, "egress-tput");
    mgr.stop(&tb.paths, "egress-tput");
}
```

- [ ] **Step 3: Run the FULL KVM suite + daemon e2e** (unsandboxed):

```sh
IZBA_INTEGRATION=1 ... cargo test -p izba-core --test integration -- --test-threads=1 --nocapture
IZBA_INTEGRATION=1 ... cargo test -p izba-cli --test daemon_e2e -- --test-threads=1
```
Expected: ALL green, stub-only egress. Note the baseline number in the commit message.

- [ ] **Step 4: Commit**

```bash
git add crates/izba-core/tests/integration.rs crates/izba-cli/tests/
git commit -m "test(core): integration suite on stub-only egress + throughput baseline (<N> MiB/s)"
```

### Task C3: Windows suite cutover

**Files:**
- Modify: `hack/spike/validate-izba-windows.ps1`
- Requires: Windows interop, re-staged build + artifacts.

- [ ] **Step 1:** Remove the consomme egress check (the suite's one open failure — retired with consomme) and the `--egress izbad` flags from the A10/B5 checks (the flag no longer exists). The egress checks become the suite's networking checks.

- [ ] **Step 2:** Run the full PS suite via interop. Expected: **all checks green** — including on this VPN'd host, which is the WSL+VPN/Tailscale exit criterion for the Windows side.

- [ ] **Step 3: Commit**

```bash
git add hack/spike/validate-izba-windows.ps1
git commit -m "test(windows): PS suite on izbad egress — consomme checks retired, all green under VPN"
```

### Task C4: docs + roadmap + memory

**Files:**
- Modify: `CLAUDE.md` — load-bearing contracts: **vsock ports** bullet gains 1027 (guest-initiated, `vsock.sock_1027` listener convention, TcpConnect/Dns framing); **Cmdline chain** bullet rewritten (no `ip=dhcp`, no `izba.ipv4only`, `izba.egress` gone post-cutover, dummy0 static addressing + 192.168.127.1 resolver, `CONFIG_DUMMY`/netfilter in kernel.config); crate map note for `daemon/egress/`.
- Modify: `README.md` — networking section: one network story, agent-firewall teaser (M2).
- Modify: `docs/testing.md` — artifact rebuild now needs `hack/build-nft.sh` + `IZBA_NFT`; kernel config additions listed.
- Modify: `docs/roadmap.md` — M1 marked ✅ DONE with date + exit-criteria evidence (suite results, baseline number, Windows-under-VPN green); "Where we are" updated.
- Modify: `hack/README.md` — build-nft.sh documented (if not already from B2).

- [ ] **Step 1:** Make the edits. Keep CLAUDE.md contract bullets in the existing terse style.
- [ ] **Step 2:** `cargo fmt --check` (docs don't need gates, but run the six anyway — cheap insurance before the milestone-closing commit).
- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md docs/ hack/README.md
git commit -m "docs: M1 done — one network story; contracts, testing runbook, roadmap updated"
```

- [ ] **Step 4:** Update auto-memory (`izba-project-state.md`): M1 DONE, next = M2 (egress policy + audit log) or M3/Track T per roadmap.

**PHASE C / M1 EXIT:** all suites green with stub-only egress on both platforms; WSL+VPN and Tailscale topologies work with zero host sniffing; passt, consomme and `izba.ipv4only` are gone from the datapath.
