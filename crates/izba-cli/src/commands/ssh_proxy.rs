//! `izba __ssh-proxy` — hidden ProxyCommand bridge that wires
//! `process stdin/stdout ↔ guest TCP :22` over the daemon's guest-stream path.
//!
//! Designed to be called by the system `ssh` client as a ProxyCommand:
//!
//! ```text
//! ssh -o ProxyCommand="izba __ssh-proxy izba-<name>" izba-<name>
//! ```
//!
//! Flow:
//! 1. Strip the `izba-` prefix from the host alias to get the sandbox name.
//! 2. Open a guest stream via `DaemonClient::open_guest_stream`.
//! 3. Write `StreamOpen::TcpDial { port: 22 }`.
//! 4. Read the `Response` frame — `Ok` proceeds; `Error` prints to stderr and
//!    returns exit 1.
//! 5. Splice `process stdin → conn` (background thread) and `conn → stdout`
//!    (main thread) until both sides reach EOF.

use anyhow::bail;
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::vmm::UdsStream;
use izba_proto::{read_frame, write_frame, Response, StreamOpen};
use std::io::{self, Read, Write};
use std::net::Shutdown;

/// Strip a leading `izba-` prefix from an SSH host alias to obtain the sandbox
/// name.
///
/// ```
/// # use izba_cli::commands::ssh_proxy::sandbox_name_from_alias;
/// assert_eq!(sandbox_name_from_alias("izba-foo"), "foo");
/// assert_eq!(sandbox_name_from_alias("bar"), "bar");
/// ```
pub fn sandbox_name_from_alias(alias: &str) -> &str {
    alias.strip_prefix("izba-").unwrap_or(alias)
}

/// Pump bytes from `from` into `to` until EOF or an error.
pub fn pump(mut from: impl Read, mut to: impl Write) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    return;
                }
                let _ = to.flush();
            }
        }
    }
}

/// Splice `stdin → conn_write` (background thread, signals EOF via
/// `shutdown(Write)`) and `conn_read → stdout` (main thread).
///
/// `conn_read` and `conn_write` should be two halves (via `try_clone()`) of the
/// same underlying stream connection to the guest.
pub fn splice(
    stdin: impl Read + Send + 'static,
    stdout: impl Write + Send + 'static,
    conn_read: UdsStream,
    conn_write: UdsStream,
) {
    // Background: stdin → conn_write; half-close on stdin EOF.
    let bg = std::thread::spawn(move || {
        let mut conn_w = conn_write;
        let mut stdin_r = stdin;
        pump(&mut stdin_r, &mut conn_w);
        let _ = conn_w.shutdown(Shutdown::Write);
    });

    // Main: conn_read → stdout.
    let mut conn_r = conn_read;
    let mut stdout_w = stdout;
    pump(&mut conn_r, &mut stdout_w);

    let _ = bg.join();
}

// reason: opens a guest stream through a live izbad and splices process stdio;
// not unit-testable on hosted runners. The two unit-testable pieces — the
// stdio splice (`splice`) and the alias→name mapping (`sandbox_name_from_alias`)
// — are covered by tests; the daemon stream path is exercised by KVM-gated e2e.
#[mutants::skip]
pub fn run(paths: &Paths, host_alias: &str) -> anyhow::Result<i32> {
    let name = sandbox_name_from_alias(host_alias);
    let mut conn = DaemonClient::open_guest_stream(paths, name)?;
    write_frame(&mut conn, &StreamOpen::TcpDial { port: 22 })?;
    match read_frame::<_, Response>(&mut conn)? {
        Response::Ok => {}
        Response::Error { message, .. } => {
            eprintln!("izba: sandbox '{name}' is not running: {message}");
            return Ok(1);
        }
        other => bail!("unexpected reply to TcpDial:22: {other:?}"),
    }
    let conn_write = conn.try_clone()?;
    splice(io::stdin(), io::stdout(), conn, conn_write);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_izba_prefix() {
        assert_eq!(sandbox_name_from_alias("izba-foo"), "foo");
        assert_eq!(sandbox_name_from_alias("bar"), "bar");
        assert_eq!(sandbox_name_from_alias("izba-"), "");
        assert_eq!(sandbox_name_from_alias(""), "");
    }

    /// Verify that `splice` moves bytes in both directions and terminates on EOF.
    ///
    /// Uses two `UnixStream::pair()` to simulate the stream connection without
    /// binding any real listeners.
    ///
    /// Layout:
    /// ```text
    ///   fake_stdin  ─────────────────► conn_write (b_write) → b_peer (peer reads stdin bytes)
    ///   a_peer (peer writes "world") → conn_read (a_read) ──► fake_stdout
    /// ```
    #[cfg(unix)]
    #[test]
    fn splice_flows_both_directions() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        use std::sync::{Arc, Mutex};

        // pair A: a_read = conn_read, a_peer = test's write/control end
        let (a_read, a_peer) = UnixStream::pair().unwrap();
        // pair B: b_write = conn_write, b_peer = test reads what splice wrote
        let (b_peer, b_write) = UnixStream::pair().unwrap();

        let conn_read: UdsStream = a_read;
        let conn_write: UdsStream = b_write;

        // Fake stdin bytes — splice will forward these to conn_write → b_peer.
        let stdin_bytes: Vec<u8> = b"hello".to_vec();
        let fake_stdin = std::io::Cursor::new(stdin_bytes.clone());

        // Collector for what splice writes to stdout.
        let out_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let out_buf_clone = out_buf.clone();

        struct CollectorWrite(Arc<Mutex<Vec<u8>>>);
        impl Write for CollectorWrite {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // Test peer thread: reads what splice forwarded from stdin (via b_peer),
        // then writes "world" back through a_peer so splice's main thread sees it.
        let peer_thread = std::thread::spawn(move || {
            // Read `hello` from b_peer (what splice forwarded from fake_stdin to conn_write).
            let mut b = b_peer;
            let mut got = vec![0u8; stdin_bytes.len()];
            b.read_exact(&mut got).unwrap();
            assert_eq!(got, b"hello", "peer saw wrong stdin bytes");

            // Write back "world" through a_peer, then close so splice's conn_read
            // read loop returns EOF.
            let mut a = a_peer;
            a.write_all(b"world").unwrap();
            drop(a); // EOF on conn_read side
            drop(b); // Close b_peer too
        });

        splice(
            fake_stdin,
            CollectorWrite(out_buf_clone),
            conn_read,
            conn_write,
        );
        peer_thread.join().unwrap();

        let collected = out_buf.lock().unwrap();
        assert_eq!(&*collected, b"world", "stdout should receive peer bytes");
    }
}
