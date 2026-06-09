use anyhow::{bail, Context};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Connect to a guest vsock `port` through cloud-hypervisor's hybrid-vsock unix socket.
///
/// Cloud-Hypervisor hybrid-vsock protocol:
///   1. Connect to the unix socket.
///   2. Send `CONNECT <port>\n`.
///   3. Read the response line byte-by-byte (CRITICAL: must not buffer ahead — any
///      bytes past the `\n` belong to the stream data).
///   4. If the response starts with `OK `, the handshake succeeded and the stream
///      is raw guest-vsock data. Otherwise return an error containing the response.
///
/// A read timeout of 5 s is applied during the handshake and cleared afterwards
/// so that a hung VMM cannot block the caller forever.
pub fn hybrid_connect(socket: &Path, port: u32) -> anyhow::Result<UnixStream> {
    let mut s = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {}", socket.display()))?;

    // Apply handshake timeout so a hung VMM can't block forever.
    s.set_read_timeout(Some(Duration::from_secs(5)))?;

    s.write_all(format!("CONNECT {port}\n").as_bytes())?;

    // Read the response byte-by-byte: buffering would swallow stream data.
    let mut line = Vec::with_capacity(32);
    loop {
        let mut b = [0u8; 1];
        let n = s.read(&mut b)?;
        if n == 0 {
            bail!("vsock handshake: EOF before response");
        }
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 128 {
            bail!("vsock handshake: oversized response");
        }
    }

    // Clear the handshake timeout — stream is now raw data.
    s.set_read_timeout(None)?;

    let resp = String::from_utf8_lossy(&line);
    if !resp.starts_with("OK ") {
        bail!("vsock connect to port {port} refused: {resp}");
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;

    #[test]
    fn handshake() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(s.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(line, "CONNECT 1025\n");
            s.write_all(b"OK 1073741824\n").unwrap();
            s.write_all(b"ping").unwrap();
        });
        let mut c = hybrid_connect(&sock, 1025).unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        t.join().unwrap();
    }

    #[test]
    fn refused_port() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // Read and discard the CONNECT line.
            let mut line = String::new();
            std::io::BufReader::new(s.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            // Respond with an error.
            s.write_all(b"ERR\n").unwrap();
        });
        let result = hybrid_connect(&sock, 9999);
        assert!(result.is_err(), "should fail on ERR response");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("ERR"),
            "error should mention the refused reply, got: {msg}"
        );
        t.join().unwrap();
    }

    #[test]
    fn missing_socket_errors() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("nonexistent.sock");
        let result = hybrid_connect(&sock, 1025);
        assert!(result.is_err(), "should error when socket does not exist");
    }
}
