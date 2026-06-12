//! DNS resolver seam. M1 production: a raw-packet UDP forwarder to the
//! host's system-configured upstream — no DNS parsing, full fidelity for
//! any qtype/EDNS. M4 slots member-name resolution in front of this.

#[cfg(unix)]
use std::net::IpAddr;
use std::net::{SocketAddr, UdpSocket};
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
    ///
    /// The upstream is captured from resolv.conf at construction time. Host
    /// DNS config changes require a daemon restart — deliberate for M1.
    pub fn system() -> Self {
        Self::new(system_upstream())
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

/// First `nameserver` in resolv.conf-style text, as a `:53` socket addr.
#[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn parses_first_nameserver() {
        let conf = "# comment\nsearch local\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n";
        assert_eq!(
            parse_resolv_conf(conf),
            Some("10.0.0.2:53".parse().unwrap())
        );
    }

    #[cfg(unix)]
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
