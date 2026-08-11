//! Auth-injecting loopback proxy for the embedded VNC desktop.
//!
//! WebView2 (Chromium) refuses credentials embedded in subresource URLs, so
//! the Display tab cannot iframe the daemon's credentialed `vnc_url`
//! (`http://izba:<pw>@127.0.0.1:<port>/`) directly. This proxy accepts
//! credential-less HTTP from the app's webview on an ephemeral loopback port,
//! injects the `Authorization: Basic` header server-side, and splices to the
//! daemon's VNC relay — including the websocket upgrade, since KasmVNC gates
//! HTTP *and* ws behind Basic auth.
//!
//! **Accepted risk (single-user desktop, same class as `izba vnc open`'s argv
//! exposure):** while running, any local process can reach the desktop through
//! this port without credentials. It binds `127.0.0.1` only, and runs only
//! while a Display tab is embedding it — the proxy's lifetime is the tab's.
//!
//! Nothing here logs request contents, and no error message ever carries the
//! source URL or the password.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{bail, Context};
use base64::Engine as _;

/// A request head larger than this is refused rather than buffered: a browser
/// head is a few KiB, so anything past this is not a client we serve.
const MAX_HEAD: usize = 64 * 1024;

/// Deadline for a client to deliver its complete request head. A local
/// process that connects and never finishes its header would otherwise park
/// a handler thread and its socket for the app's lifetime — the accepted-risk
/// model bounds WHO can connect (loopback), not how long they may stall.
/// The deadline is lifted once the head is in: a live desktop session's
/// splice must block indefinitely.
#[cfg(not(test))]
const HEAD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Test builds shorten the deadline so the stalled-client test observes the
/// drop in milliseconds instead of ten seconds.
#[cfg(test)]
const HEAD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(400);

/// Where a proxy sends its traffic, and what it authenticates with.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    /// Loopback port of the daemon's VNC relay.
    pub port: u16,
    /// The full header value, e.g. `Basic aXpiYTpwdw==`.
    pub authorization: String,
}

/// Hand-written so a panic message, log line, or `unwrap` never prints the
/// encoded desktop password.
impl std::fmt::Debug for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyTarget")
            .field("port", &self.port)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

/// Parse the daemon's fixed `vnc_url` shape
/// `http://<user>:<password>@127.0.0.1:<port>/` into a proxy target.
///
/// The password alphabet is `[A-Za-z0-9]` (see `crate::vnc` on the daemon
/// side), so there is no percent-decoding to do. Errors never echo the input.
pub fn parse_vnc_url(url: &str) -> anyhow::Result<ProxyTarget> {
    let rest = url
        .strip_prefix("http://")
        .context("vnc url is not an http:// url")?;
    // Userinfo ends at the last '@' BEFORE the path, so a '@' in the path
    // cannot be mistaken for the delimiter.
    let authority = rest.split('/').next().unwrap_or(rest);
    let at = authority
        .rfind('@')
        .context("vnc url carries no credentials")?;
    let (userinfo, hostport) = (&authority[..at], &authority[at + 1..]);
    let (user, password) = userinfo
        .split_once(':')
        .context("vnc url credentials are not user:password")?;
    if user.is_empty() || password.is_empty() {
        bail!("vnc url credentials are empty");
    }
    let (host, port) = hostport
        .rsplit_once(':')
        .context("vnc url has no host:port")?;
    // The proxy always dials 127.0.0.1, so a non-loopback host would silently
    // be redirected — refuse it instead.
    if host != "127.0.0.1" {
        bail!("vnc url host is not 127.0.0.1");
    }
    let port: u16 = port.parse().context("vnc url port is not a port number")?;
    let authorization = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    );
    Ok(ProxyTarget {
        port,
        authorization,
    })
}

/// Rewrite one HTTP request head (request line + headers) for the upstream
/// relay, returning the new head and whether this is a websocket upgrade.
///
/// The client's own `Authorization` is dropped and ours appended, so a webview
/// can never talk the relay into using a header it supplied. Non-upgrade
/// requests get `Connection: close` (their `Connection`/`Keep-Alive` headers
/// are dropped): the splice below serves exactly one request per connection,
/// so the relay must close after the response and the browser must open a
/// fresh connection per request — negligible on loopback. Upgrade requests
/// keep their `Connection`/`Upgrade` headers verbatim; everything else,
/// including the request line, is preserved byte-for-byte.
///
/// The returned head is complete: it ends with the blank line, ready to write.
fn rewrite_request_head(head: &str, authorization: &str) -> anyhow::Result<(String, bool)> {
    let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
    let request_line = lines.next().context("empty request head")?;
    let headers: Vec<&str> = lines.collect();

    let is_upgrade = headers.iter().any(|h| {
        h.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade") && value.to_ascii_lowercase().contains("websocket")
        })
    });

    let mut out = String::with_capacity(head.len() + authorization.len() + 32);
    out.push_str(request_line);
    out.push_str("\r\n");
    for h in headers {
        let name = h.split(':').next().unwrap_or("").trim();
        let drop = name.eq_ignore_ascii_case("authorization")
            || (!is_upgrade
                && (name.eq_ignore_ascii_case("connection")
                    || name.eq_ignore_ascii_case("keep-alive")));
        if !drop {
            out.push_str(h);
            out.push_str("\r\n");
        }
    }
    if !is_upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("Authorization: ");
    out.push_str(authorization);
    out.push_str("\r\n\r\n");
    Ok((out, is_upgrade))
}

/// Whether an `accept` error means the LISTENER is gone, or just one queued
/// connection.
///
/// A client that queues a connection and then resets it before we accept is
/// routine — Chromium preconnects and cancels — and the OS reports it against
/// `accept`: `ECONNABORTED` on unix, `WSAECONNRESET` (→ `ConnectionReset`) on
/// Windows. `Interrupted` is a signal. Breaking the loop on any of those would
/// close the port while `vnc_proxy_url`'s registry still hands it out, so the
/// tab would embed a dead port until the app restarts.
fn accept_error_is_fatal(kind: std::io::ErrorKind) -> bool {
    !matches!(
        kind,
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
    )
}

/// A running proxy. Dropping it stops accepting.
pub struct VncProxy {
    port: u16,
    target: ProxyTarget,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl VncProxy {
    /// Bind an ephemeral loopback port and start serving `target`.
    pub fn start(target: ProxyTarget) -> anyhow::Result<VncProxy> {
        let listener = TcpListener::bind("127.0.0.1:0").context("bind loopback proxy port")?;
        let port = listener.local_addr().context("proxy local addr")?.port();
        let stop = Arc::new(AtomicBool::new(false));

        let accept_target = target.clone();
        let accept_stop = Arc::clone(&stop);
        let accept = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if accept_stop.load(Ordering::SeqCst) {
                    break;
                }
                match conn {
                    Ok(client) => {
                        let t = accept_target.clone();
                        // Detached: an in-flight connection is not tracked, it
                        // dies when its sockets close (both are shut down by
                        // the splice, and the browser drops them with the tab).
                        std::thread::spawn(move || {
                            let _ = serve_connection(client, &t);
                        });
                    }
                    // A per-connection failure is not the listener's death;
                    // any other accept error is, and ending the loop beats
                    // spinning on it.
                    Err(e) if accept_error_is_fatal(e.kind()) => break,
                    Err(_) => {}
                }
            }
        });

        Ok(VncProxy {
            port,
            target,
            stop,
            accept: Some(accept),
        })
    }

    /// The loopback port the webview should point at.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether this proxy already serves exactly `t` — a reused proxy must not
    /// be pointed at a relay it was not started for.
    pub fn target_matches(&self, t: &ProxyTarget) -> bool {
        &self.target == t
    }

    /// Whether the accept loop is still running. A proxy whose loop has ended
    /// holds a closed port: it can never serve again, so a matching target is
    /// NOT enough to reuse it — the registry must rekey.
    pub fn is_live(&self) -> bool {
        self.accept.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Test-only: end the accept loop and join it, leaving a bound-but-dead
    /// proxy — exactly the state a fatal accept error produces in the field.
    #[cfg(test)]
    pub fn stop_for_test(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for VncProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // `accept` blocks; one throwaway connection wakes it so it can observe
        // the flag and return.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

/// One client connection: read its head, rewrite it, then be a raw byte pipe.
/// `Read` adapter enforcing an ABSOLUTE deadline across every read of the
/// head phase. A per-read timeout alone restarts on each byte, so a client
/// dripping one header byte per interval would hold its handler thread
/// forever; this adapter re-arms the socket timeout with the REMAINING time
/// before each read and fails once the deadline has passed.
struct DeadlineReader<'a> {
    stream: &'a TcpStream,
    deadline: std::time::Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "head deadline exceeded",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        (&mut &*self.stream).read(buf)
    }
}

fn serve_connection(client: TcpStream, target: &ProxyTarget) -> anyhow::Result<()> {
    // Bounded head phase (see HEAD_READ_TIMEOUT); a timed-out or overdue
    // read surfaces as an error here and the connection is dropped.
    let (head, body) = read_request_head(&mut DeadlineReader {
        stream: &client,
        deadline: std::time::Instant::now() + HEAD_READ_TIMEOUT,
    })?;
    // Head is in — from here on the connection is a live session whose reads
    // legitimately block for as long as the desktop is idle.
    client
        .set_read_timeout(None)
        .context("clear head deadline")?;
    // The upgrade answer does not change what we do: past the head, a plain
    // response and a websocket are both just bytes to splice.
    let (rewritten, _is_upgrade) = rewrite_request_head(&head, &target.authorization)?;

    let mut upstream =
        TcpStream::connect(("127.0.0.1", target.port)).context("connect vnc relay")?;
    upstream.write_all(rewritten.as_bytes())?;
    if !body.is_empty() {
        upstream.write_all(&body)?;
    }
    upstream.flush()?;

    splice(client, upstream)
}

/// Read up to and including the head terminator, returning the head (request
/// line + headers, `\r\n`-terminated) and whatever body bytes came with it.
fn read_request_head<R: Read>(client: &mut R) -> anyhow::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let terminator = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() >= MAX_HEAD {
            bail!("request head exceeds {MAX_HEAD} bytes");
        }
        match client.read(&mut chunk)? {
            0 => bail!("client closed before sending a request head"),
            n => buf.extend_from_slice(&chunk[..n]),
        }
    };
    // Keep the last header's CRLF, drop the blank line: the rewriter re-adds
    // the terminator once it has appended our own headers.
    let head = String::from_utf8(buf[..terminator + 2].to_vec())
        .context("request head is not valid utf-8")?;
    Ok((head, buf[terminator + 4..].to_vec()))
}

/// Index of the `\r\n\r\n` that ends a request head.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Pump bytes both ways until either side ends, then tear both down so the
/// opposite direction's copy cannot linger.
fn splice(client: TcpStream, upstream: TcpStream) -> anyhow::Result<()> {
    let mut client_read = client.try_clone().context("clone client socket")?;
    let mut upstream_write = upstream.try_clone().context("clone upstream socket")?;
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Both);
        let _ = client_read.shutdown(Shutdown::Both);
    });

    let mut upstream_read = upstream;
    let mut client_write = client;
    let _ = std::io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Both);
    let _ = upstream_read.shutdown(Shutdown::Both);
    let _ = up.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vnc_url_extracts_port_and_auth() {
        let t = parse_vnc_url("http://izba:s3cr3t@127.0.0.1:4444/").unwrap();
        assert_eq!(t.port, 4444);
        // base64("izba:s3cr3t")
        assert_eq!(t.authorization, "Basic aXpiYTpzM2NyM3Q=");
    }

    #[test]
    fn parse_vnc_url_rejects_garbage_without_leaking_it() {
        for bad in [
            "",
            "not-a-url",
            "http://127.0.0.1:4444/",
            "http://izba:pw@nohost/",
        ] {
            let err = parse_vnc_url(bad).unwrap_err().to_string();
            assert!(
                !err.contains("pw"),
                "error must not echo credentials: {err}"
            );
        }
    }

    #[test]
    fn rewrite_injects_auth_and_connection_close() {
        let head = "GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:9\r\nConnection: keep-alive\r\nAuthorization: Basic evil\r\nAccept: */*\r\n";
        let (out, upgrade) = rewrite_request_head(head, "Basic good").unwrap();
        assert!(!upgrade);
        assert!(out.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(out.contains("Accept: */*\r\n"));
        assert!(out.contains("Authorization: Basic good\r\n"));
        assert!(!out.contains("evil"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(!out.contains("keep-alive"));
    }

    #[test]
    fn rewrite_keeps_websocket_upgrade_headers() {
        let head = "GET /websockify HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n";
        let (out, upgrade) = rewrite_request_head(head, "Basic good").unwrap();
        assert!(upgrade);
        assert!(out.contains("Connection: Upgrade\r\n"));
        assert!(out.contains("Upgrade: websocket\r\n"));
        assert!(out.contains("Authorization: Basic good\r\n"));
        assert!(!out.contains("Connection: close"));
    }

    #[test]
    fn read_request_head_keeps_body_bytes_read_past_the_head() {
        let wire = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody";
        let (head, body) = read_request_head(&mut std::io::Cursor::new(&wire[..])).unwrap();
        assert_eq!(head, "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n");
        assert_eq!(body, b"body");
    }

    #[test]
    fn read_request_head_refuses_an_oversized_head() {
        let mut wire = b"GET / HTTP/1.1\r\n".to_vec();
        while wire.len() < MAX_HEAD + 4096 {
            wire.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        wire.extend_from_slice(b"\r\n");
        let err = read_request_head(&mut std::io::Cursor::new(&wire[..])).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn a_reset_connection_does_not_kill_the_accept_loop() {
        // Chromium preconnects then cancels; the OS reports that against
        // `accept` as ECONNABORTED (unix) or WSAECONNRESET (Windows). Treating
        // either as fatal closes the port while the registry still serves it.
        for benign in [
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::Interrupted,
        ] {
            assert!(!accept_error_is_fatal(benign), "{benign:?}");
        }
        // A listener that is genuinely gone still ends the loop.
        for fatal in [
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::PermissionDenied,
        ] {
            assert!(accept_error_is_fatal(fatal), "{fatal:?}");
        }
    }

    /// Some sandboxes deny `bind` with EPERM; those runs SKIP rather than fail.
    fn try_listener() -> Option<std::net::TcpListener> {
        match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => Some(l),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP: sandbox denies TCP bind");
                None
            }
            Err(e) => panic!("bind: {e}"),
        }
    }

    /// Read one request head off a socket, returning it as a string (test-side
    /// mirror of the proxy's own head read).
    fn read_head(sock: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            match sock.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => buf.push(byte[0]),
                Err(e) => panic!("read head: {e}"),
            }
        }
        String::from_utf8(buf).expect("head is utf-8")
    }

    #[test]
    fn proxy_injects_auth_end_to_end() {
        let Some(upstream) = try_listener() else {
            return;
        };
        let upstream_port = upstream.local_addr().unwrap().port();
        let target =
            parse_vnc_url(&format!("http://izba:s3cr3t@127.0.0.1:{upstream_port}/")).unwrap();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = upstream.accept().unwrap();
            let head = read_head(&mut sock);
            assert!(
                head.contains("Authorization: Basic aXpiYTpzM2NyM3Q=\r\n"),
                "upstream head: {head}"
            );
            assert!(head.contains("Connection: close\r\n"), "head: {head}");
            assert!(!head.contains("evil"), "head: {head}");
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .unwrap();
        });

        let proxy = VncProxy::start(target).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        client
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: x\r\nAuthorization: Basic evil\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        server.join().unwrap();
        assert!(resp.contains("HTTP/1.1 200 OK"), "response: {resp}");
        assert!(resp.contains("hi"), "response: {resp}");
    }

    #[test]
    fn proxy_splices_websocket_bytes_both_ways() {
        let Some(upstream) = try_listener() else {
            return;
        };
        let upstream_port = upstream.local_addr().unwrap().port();
        let target = parse_vnc_url(&format!("http://izba:pw1@127.0.0.1:{upstream_port}/")).unwrap();

        let server = std::thread::spawn(move || {
            let (mut sock, _) = upstream.accept().unwrap();
            let head = read_head(&mut sock);
            assert!(
                head.contains("Authorization: Basic aXpiYTpwdzE=\r\n"),
                "upstream head: {head}"
            );
            assert!(head.contains("Upgrade: websocket\r\n"), "head: {head}");
            sock.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .unwrap();
            let mut frame = [0u8; 4];
            sock.read_exact(&mut frame).unwrap();
            sock.write_all(b"ok:").unwrap();
            sock.write_all(&frame).unwrap();
        });

        let proxy = VncProxy::start(target).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        client
            .write_all(
                b"GET /websockify HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\n\
                  Upgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n",
            )
            .unwrap();
        client.write_all(b"ping").unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        server.join().unwrap();
        assert!(
            resp.contains("HTTP/1.1 101 Switching Protocols"),
            "response: {resp}"
        );
        assert!(resp.contains("ok:ping"), "response: {resp}");
    }

    #[test]
    fn is_live_follows_the_accept_loop() {
        let Some(upstream) = try_listener() else {
            return;
        };
        let mut proxy = VncProxy::start(ProxyTarget {
            port: upstream.local_addr().unwrap().port(),
            authorization: "Basic good".into(),
        })
        .unwrap();
        assert!(proxy.is_live(), "a just-started proxy is live");
        proxy.stop_for_test();
        assert!(!proxy.is_live(), "a proxy whose accept loop ended is dead");
    }

    #[test]
    fn proxy_drops_a_client_that_never_finishes_its_head() {
        let Some(upstream) = try_listener() else {
            return;
        };
        let upstream_port = upstream.local_addr().unwrap().port();
        let proxy = VncProxy::start(ProxyTarget {
            port: upstream_port,
            authorization: "Basic good".into(),
        })
        .unwrap();
        // Connect and send NOTHING: the head deadline (shortened under
        // cfg(test)) must expire and the handler must drop the socket —
        // observed as EOF/error on our end — instead of parking forever.
        let mut stalled = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        stalled
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 16];
        let start = std::time::Instant::now();
        let n = stalled.read(&mut buf);
        assert!(
            matches!(n, Ok(0) | Err(_)),
            "expected the proxy to close the stalled connection, got {n:?}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "proxy did not enforce the head deadline (waited {:?})",
            start.elapsed()
        );
    }

    #[test]
    fn proxy_drops_a_drip_feeding_client_at_the_absolute_deadline() {
        let Some(upstream) = try_listener() else {
            return;
        };
        let upstream_port = upstream.local_addr().unwrap().port();
        let proxy = VncProxy::start(ProxyTarget {
            port: upstream_port,
            authorization: "Basic good".into(),
        })
        .unwrap();
        // Drip one header byte per interval, faster than any per-read
        // timeout: only an ABSOLUTE deadline across the whole head phase can
        // end this connection. (A per-read timeout restarts on every byte.)
        let mut writer = TcpStream::connect(("127.0.0.1", proxy.port())).unwrap();
        let mut reader = writer.try_clone().unwrap();
        let feeder = std::thread::spawn(move || {
            for _ in 0..60 {
                if writer.write_all(b"G").is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 16];
        let start = std::time::Instant::now();
        let n = reader.read(&mut buf);
        assert!(
            matches!(n, Ok(0) | Err(_)),
            "expected the proxy to close the drip-fed connection, got {n:?}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "proxy did not enforce the absolute head deadline (waited {:?})",
            start.elapsed()
        );
        let _ = feeder.join();
    }

    #[test]
    fn proxy_drop_stops_listening() {
        let Some(upstream) = try_listener() else {
            return;
        };
        let upstream_port = upstream.local_addr().unwrap().port();
        let proxy = VncProxy::start(ProxyTarget {
            port: upstream_port,
            authorization: "Basic good".into(),
        })
        .unwrap();
        let port = proxy.port();
        assert!(proxy.target_matches(&ProxyTarget {
            port: upstream_port,
            authorization: "Basic good".into(),
        }));
        assert!(!proxy.target_matches(&ProxyTarget {
            port: upstream_port,
            authorization: "Basic other".into(),
        }));
        drop(proxy);

        // The OS may need a moment to reap the closed listener.
        let mut refused = false;
        for _ in 0..50 {
            if TcpStream::connect(("127.0.0.1", port)).is_err() {
                refused = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(refused, "proxy port {port} still accepts after drop");
    }
}
