//! DNS resolver seam. M1 production: a raw-packet UDP forwarder to the
//! host's system-configured upstream — no DNS parsing, full fidelity for
//! any qtype/EDNS. M4 slots member-name resolution in front of this.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub trait Resolver: Send + Sync {
    /// Raw DNS query in, raw DNS response out, for a UDP-origin query. The
    /// caller turns an `Err` into SERVFAIL (`izba_proto::dns::servfail`).
    /// A resolver that re-encodes answers caps them at the 512-byte non-EDNS
    /// UDP limit and sets TC=1 on overflow so the guest retries over TCP.
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// As [`handle`](Resolver::handle), but for a query that reached the guest
    /// stub over TCP:53: answers may exceed 512 bytes (DNS-over-TCP allows up
    /// to 64 KiB), so a re-encoding resolver must NOT truncate. The default
    /// delegates to `handle` — correct for forwarders and test fakes that do
    /// not re-encode/truncate; the terminating `SystemResolver` overrides it.
    fn handle_tcp(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.handle(query)
    }
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
}

impl Resolver for UdpForwarder {
    /// Single-shot forward: send the raw query, wait for one reply. No retry
    /// — a timeout surfaces as `Err` → SERVFAIL at the caller; DNS clients
    /// handle retries themselves.
    fn handle(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let local: SocketAddr = if self.upstream.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let sock = UdpSocket::bind(local)?;
        // Connected socket: the kernel drops datagrams from any source
        // other than the upstream (off-path response-injection hardening).
        sock.connect(self.upstream)?;
        sock.set_read_timeout(Some(FORWARD_TIMEOUT))?;
        sock.send(query)?;
        let mut buf = vec![0u8; MAX_DNS_MSG];
        let n = sock.recv(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
