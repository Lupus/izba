//! Guest egress stub — M1. This file ships the DNS half (UDP :53 →
//! per-query vsock `Dns` stream to izbad); the TCP REDIRECT half (nft +
//! SO_ORIGINAL_DST) lands with the phase-B kernel/nft artifacts.

use izba_proto::{dns, write_frame, StreamOpen, EGRESS_PORT};
use std::io::{self, Read, Write};
use std::net::UdpSocket;

/// Dial the host (CID 2) egress port. Production dialer; tests substitute
/// a socketpair half through the `forward_query` seam.
///
/// `VMADDR_CID_HOST` (2) is the host CID in the vsock world.  The VMM
/// bridges `connect(cid=2, port=EGRESS_PORT)` to the unix socket at
/// `run/vsock.sock_1027` owned by izbad.
///
/// vsock 0.5: `VsockStream::connect_with_cid_port(u32, u32)` is a static
/// that returns `io::Result<VsockStream>` (the crate uses `std::io::Result`
/// internally, not a nix::Result), so no error conversion is needed.
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

/// One `Dns` vsock stream: send `StreamOpen::Dns`, write the framed query,
/// read back one framed response.
///
/// `write_frame` returns `Result<(), FrameError>` (not `io::Result`). We
/// map the `FrameError` to `io::Error` via its `Display` impl. The DNS
/// framing helpers (`write_dns_msg`, `read_dns_msg`) already return
/// `io::Result`, so no conversion is needed there.
fn try_forward<S, D>(dial: D, query: &[u8]) -> io::Result<Vec<u8>>
where
    S: Read + Write,
    D: FnOnce() -> io::Result<S>,
{
    let mut s = dial()?;
    write_frame(&mut s, &StreamOpen::Dns).map_err(|e| io::Error::other(e.to_string()))?;
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
/// M1: unbounded thread-per-query (and one izbad conn each) — the host-side bound is M2 scope.
pub fn serve_dns_udp() -> io::Result<()> {
    let sock = UdpSocket::bind(("0.0.0.0", 53))?;
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("izba-init: dns stub recv: {e}");
                continue;
            }
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
            assert!(
                matches!(open, StreamOpen::Dns),
                "expected Dns, got {open:?}"
            );
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
