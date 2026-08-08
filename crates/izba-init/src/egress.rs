//! Guest egress stub. The DNS half forwards guest resolution to izbad over
//! vsock: UDP :53 → per-query `Dns` stream (answers capped at 512 bytes, TC=1
//! on overflow) and TCP :53 → per-connection `DnsTcp` stream (full answers, so
//! a TC=1 UDP retry succeeds). The TCP REDIRECT half (nft + SO_ORIGINAL_DST)
//! tunnels all other guest TCP to izbad via `TcpConnect`.

use izba_proto::{dns, write_frame, StreamOpen, EGRESS_PORT};
use nix::sys::socket::{
    recvmsg, sendmsg, setsockopt, sockopt, ControlMessage, ControlMessageOwned, MsgFlags,
    SockaddrIn,
};
use std::fs::File;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;

/// nix `Errno` → `std::io::Error` for the few socket syscalls that bypass the
/// std wrappers (recvmsg/sendmsg/setsockopt for the transparent-reply cmsgs).
fn nix_to_io(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

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

/// Enable `IP_RECVORIGDSTADDR` so each received datagram carries its (post-NAT)
/// destination address as an `IP_ORIGDSTADDR` control message. For a query the
/// nft `udp dport 53 redirect to :53` rule pulled in, that address is the
/// REDIRECT target (`127.0.0.1`); replying FROM it (see [`reply_dns`]) is what
/// lets conntrack reverse the DNAT so a client that hardcoded an external
/// resolver (e.g. `8.8.8.8:53`) accepts the answer. See [`NFT_RULESET`].
fn set_recv_origdst(sock: &UdpSocket) -> io::Result<()> {
    setsockopt(sock, sockopt::Ipv4OrigDstAddr, &true).map_err(nix_to_io)
}

/// Bind 0.0.0.0:53. Split out of `serve_dns_udp` so the bind can happen on
/// the main thread BEFORE `apply_nft` (the redirect rule is meaningless, and
/// worse, blackholes :53, if nothing is listening), giving a real
/// happens-before between "listener exists" and "rule installed".
pub fn bind_dns_udp() -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(("0.0.0.0", 53))?;
    set_recv_origdst(&sock)?;
    Ok(sock)
}

/// Receive one datagram together with the original destination address it was
/// delivered to (`IP_ORIGDSTADDR`). Returns `(n, peer, orig_dst)`; `orig_dst`
/// is `None` if the kernel attached no such control message (it should always
/// be present once [`set_recv_origdst`] ran, but we degrade gracefully).
fn recv_with_origdst(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SockaddrIn, Option<Ipv4Addr>)> {
    let mut iov = [IoSliceMut::new(buf)];
    // One IP_ORIGDSTADDR (a sockaddr_in) is all we ask for.
    let mut cmsg_buf = nix::cmsg_space!(libc::sockaddr_in);
    let msg = recvmsg::<SockaddrIn>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(nix_to_io)?;
    let peer = msg
        .address
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "recvmsg: no peer address"))?;
    let mut orig = None;
    for cmsg in msg.cmsgs().map_err(nix_to_io)? {
        if let ControlMessageOwned::Ipv4OrigDstAddr(sin) = cmsg {
            orig = Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
        }
    }
    Ok((msg.bytes, peer, orig))
}

/// Send `resp` to `peer`. When `orig` is known, source the reply FROM that
/// address via `IP_PKTINFO` (`ipi_spec_dst`) so conntrack reverses the
/// REDIRECT's DNAT — the transparent-reply fix. Without `orig` we fall back to
/// a plain send with the kernel's default source (correct for the loopback
/// resolver path, which is never REDIRECTed).
fn reply_dns(
    sock: &UdpSocket,
    resp: &[u8],
    peer: &SockaddrIn,
    orig: Option<Ipv4Addr>,
) -> io::Result<usize> {
    let fd = sock.as_raw_fd();
    let iov = [IoSlice::new(resp)];
    match orig {
        Some(src) => {
            let pktinfo = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr {
                    s_addr: u32::from(src).to_be(),
                },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            sendmsg(
                fd,
                &iov,
                &[ControlMessage::Ipv4PacketInfo(&pktinfo)],
                MsgFlags::empty(),
                Some(peer),
            )
        }
        None => sendmsg::<SockaddrIn>(fd, &iov, &[], MsgFlags::empty(), Some(peer)),
    }
    .map_err(nix_to_io)
}

/// Serve DNS forever (daemon thread) on an already-bound socket; one thread
/// per query so a slow upstream cannot head-of-line-block other resolutions.
/// M1: unbounded thread-per-query (and one izbad conn each) — the host-side bound is M2 scope.
// reason: 1-line delegation wiring the real `dial_host` (CID 2 vsock) into the
// tested serve loop; the loop logic lives in `serve_dns_udp_with`, which is
// unit-tested with a fake izbad over a socketpair.
#[mutants::skip]
pub fn serve_dns_udp(sock: UdpSocket) -> io::Result<()> {
    serve_dns_udp_with(sock, dial_host)
}

/// The serve loop, generic over the izbad dialer so it can be unit-tested with a
/// socketpair fake (production passes [`dial_host`]). Each datagram is recv'd
/// with its original destination, forwarded over a fresh `Dns` stream, and the
/// answer is sent back FROM that destination so conntrack un-NATs a REDIRECTed
/// hardcoded-resolver query (e.g. 8.8.8.8:53). The loopback resolver path is not
/// REDIRECTed, but `orig` is still 127.0.0.1 there, so the same path serves both.
fn serve_dns_udp_with<S, D>(sock: UdpSocket, dial: D) -> io::Result<()>
where
    S: Read + Write + Send + 'static,
    D: Fn() -> io::Result<S> + Clone + Send + 'static,
{
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer, orig) = match recv_with_origdst(&sock, &mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("izba-init: dns stub recv: {e}");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let sock2 = sock.try_clone()?;
        let dial = dial.clone();
        std::thread::spawn(move || {
            let resp = forward_query(dial, &query);
            if let Err(e) = reply_dns(&sock2, &resp, &peer, orig) {
                eprintln!("izba-init: dns stub reply: {e}");
            }
        });
    }
}

/// Bind 0.0.0.0:53 for DNS-over-TCP. Split out like [`bind_dns_udp`] so the
/// bind happens on the main thread BEFORE [`apply_nft`].
///
/// Two client paths reach this listener:
///   1. the resolv.conf resolver (`127.0.0.1:53`): the nat-output
///      `ip daddr 127.0.0.0/8 return` rule means a TCP retry to `127.0.0.1:53`
///      is never redirected — it is delivered straight here. This is the path a
///      resolver takes after izbad answers a UDP query with TC=1 (an answer
///      over the 512-byte non-EDNS limit); without it, large or split-horizon
///      record sets are unresolvable in the guest.
///   2. a hardcoded external resolver over TCP (e.g. `dig +tcp @1.1.1.1`): the
///      `tcp dport 53 redirect to :53` rule REDIRECTs it here just like the UDP
///      `udp dport 53 redirect to :53` rule, so any in-guest DNS — UDP or TCP,
///      loopback or hardcoded — funnels through izbad's resolver.
///
/// Unlike the UDP stub, no source-address fixup is needed: each connection is an
/// accepted (connected) socket whose local address is the REDIRECT target, so
/// conntrack reverse-NATs replies automatically (the same reason the `:15001`
/// TCP relay works). See [`NFT_RULESET`].
pub fn bind_dns_tcp() -> io::Result<TcpListener> {
    TcpListener::bind(("0.0.0.0", 53))
}

/// Serve DNS-over-TCP forever (daemon thread) on an already-bound listener; one
/// thread per connection so a slow upstream cannot head-of-line-block others.
pub fn serve_dns_tcp(listener: TcpListener) -> io::Result<()> {
    loop {
        let (conn, _peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("izba-init: dns-tcp accept: {e}");
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        std::thread::spawn(move || forward_tcp_conn(conn, dial_host));
    }
}

/// One client TCP connection ↔ one `DnsTcp` vsock stream to izbad. DNS-over-TCP
/// framing (RFC 1035 §4.2.2, 2-byte length prefix) IS the `izba_proto::dns`
/// wire form, so each framed message relays verbatim in both directions; the
/// `DnsTcp` open frame tells izbad to return full answers rather than capping
/// at the 512-byte UDP limit. A failed forward becomes SERVFAIL for that query
/// (the client fails fast), then the connection closes. Sequential queries on
/// one connection are supported (RFC 7766) while the vsock stream stays healthy.
fn forward_tcp_conn<C, S, D>(mut client: C, dial: D)
where
    C: Read + Write,
    S: Read + Write,
    D: FnOnce() -> io::Result<S>,
{
    let mut host = match dial() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("izba-init: dns-tcp dial: {e}");
            return; // client sees the connection close → resolver fails fast
        }
    };
    if let Err(e) = write_frame(&mut host, &StreamOpen::DnsTcp) {
        eprintln!("izba-init: dns-tcp open: {e}");
        return;
    }
    // Ends on clean boundary EOF (client done) or a truncated/short frame.
    while let Ok(Some(query)) = dns::read_dns_msg(&mut client) {
        match relay_tcp_query(&mut host, &query) {
            Ok(resp) => {
                if dns::write_dns_msg(&mut client, &resp).is_err() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("izba-init: dns-tcp relay: {e}");
                let _ = dns::write_dns_msg(&mut client, &dns::servfail(&query));
                break; // the vsock stream is likely broken; close the conn
            }
        }
    }
}

/// Forward one framed query to izbad over the open `DnsTcp` stream and read back
/// its framed response.
fn relay_tcp_query<S: Read + Write>(host: &mut S, query: &[u8]) -> io::Result<Vec<u8>> {
    dns::write_dns_msg(host, query)?;
    dns::read_dns_msg(host)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no dns response from izbad"))
}

/// Loopback port all outbound TCP is delivered to: the nat-output REDIRECT
/// (shared-netns mode) or, in docker mode, the nat-prerouting REDIRECT that
/// intercepts traffic arriving over the veth from the workload's own netns
/// (see [`NFT_DOCKER_PREROUTING`]) — same relay stub, two different nft
/// hooks depending on which netns topology this boot is running.
pub const REDIRECT_PORT: u16 = 15001;

/// The fixed transparent-redirect ruleset. Loopback destinations (`return`)
/// are never redirected — that is the primary DNS path (resolv.conf points to
/// 127.0.0.1; the UDP stub answers from 0.0.0.0:53 and the loopback reply
/// matches; a client's TCP retry to 127.0.0.1:53 is likewise delivered
/// straight to the TCP stub on 0.0.0.0:53, no redirect involved).
///
/// Both `dport 53` rules pull hardcoded-resolver queries (e.g. an app that
/// bakes in `8.8.8.8:53`/`1.1.1.1:53`) to the in-guest DNS stub so ALL DNS —
/// UDP or TCP, loopback or hardcoded — funnels through izbad's resolver:
///   - `udp dport 53 redirect to :53` → the UDP stub. Its reply path works
///     because the stub recovers the REDIRECT's destination via
///     `IP_ORIGDSTADDR` and answers FROM it with `IP_PKTINFO` (see
///     [`serve_dns_udp`]/[`reply_dns`]); conntrack then un-NATs the source back
///     to the address the client targeted. `route_localnet` (set in
///     `net::configure`) lets that 127.0.0.1-sourced reply route to the guest
///     IP without being treated as martian.
///   - `tcp dport 53 redirect to :53` → the DNS-over-TCP stub. No source fixup
///     is needed (accepted connected socket ⇒ conntrack auto-un-NATs replies).
///
/// All non-DNS TCP (`tcp dport != 53`) goes to the relay stub at :15001. The
/// `!= 53` carve-out (rather than `meta l4proto tcp`) makes the rules
/// non-overlapping, so a `tcp:53` packet is REDIRECTed only to the DNS stub
/// regardless of whether nft treats `redirect` as terminal. The stub's own
/// egress is AF_VSOCK — not IP — so no exclusion rule is needed and no redirect
/// loop is possible. Non-DNS UDP is denied structurally (no route once the NIC
/// goes away in phase C).
pub const NFT_RULESET: &str = "\
table ip izba {
  chain output {
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
    tcp dport 53 redirect to :53
    udp dport 53 redirect to :53
    tcp dport != 53 redirect to :15001
  }
}
";

/// Docker-mode prerouting chain (spec §3): traffic from the workload's own
/// netns arrives over the veth and traverses prerouting, never output. Same
/// interception surface; REDIRECT rewrites the destination to the ingress
/// interface's address, which is why bind_tcp_redirect binds wildcard.
const NFT_DOCKER_PREROUTING: &str = "\
table ip izba {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    tcp dport 53 redirect to :53
    udp dport 53 redirect to :53
    tcp dport != 53 redirect to :15001
  }
}
";

/// The output chain for this boot. Identical to [`NFT_RULESET`] except that
/// docker mode adds ONE rule: `ip daddr <GUEST_IP> return`.
///
/// That rule is load-bearing for published ports. In docker mode
/// `server::tcp_dial` falls back to `net::GUEST_IP` (the container side of the
/// veth) after loopback misses — that dial is INIT-originated, so unlike the
/// workload's own traffic it DOES traverse this `output` hook, where
/// `tcp dport != 53 redirect to :15001` would swallow it into the egress relay.
/// The relay then asks izbad — on the HOST — to connect to `192.168.127.2`,
/// which exists nowhere on the host, and the port relay dies with
/// `izba-init: egress 192.168.127.2:8080: ConnectFailed: connection timed out`
/// (observed on a real boot, Task 7). Exempting the veth peer keeps that dial
/// on the wire it belongs on.
///
/// This is NOT a policy hole: only init's own netns traverses `output`, and
/// the only thing at `GUEST_IP` is the workload container izba itself just
/// dialed on the user's behalf. The workload's egress still arrives via
/// `prerouting` and is intercepted exactly as before.
fn output_chain(docker: bool) -> String {
    let veth_return = if docker {
        format!("    ip daddr {} return\n", crate::net::GUEST_IP)
    } else {
        String::new()
    };
    format!(
        "table ip izba {{
  chain output {{
    type nat hook output priority -100; policy accept;
    ip daddr 127.0.0.0/8 return
{veth_return}    tcp dport 53 redirect to :53
    udp dport 53 redirect to :53
    tcp dport != 53 redirect to :15001
  }}
}}
"
    )
}

/// The nft ruleset for this boot: the output chain ([`output_chain`]), plus
/// the prerouting chain when docker mode is on. In docker mode the workload
/// runs in its OWN netns (reached over the veth pair set up by `veth::apply`),
/// so its traffic never traverses init's `output` hook at all — the
/// `prerouting` chain is what actually intercepts it; the `output` chain stays
/// in place too because init's own netns processes still traverse it (and, in
/// docker mode, gains the veth-peer exemption `output_chain` documents).
pub fn ruleset(docker: bool) -> String {
    if docker {
        format!("{}{NFT_DOCKER_PREROUTING}", output_chain(true))
    } else {
        NFT_RULESET.to_string()
    }
}

/// Apply the ruleset via the vendored static nft.
///
/// `#[mutants::skip]`: shells out to a real `/sbin/nft -f` against a real
/// file path, only meaningful inside a booted guest with nft present; the
/// unit suite has neither. The branching logic it delegates to (`ruleset`) is
/// the pure, unit-tested part.
#[mutants::skip]
pub fn apply_nft(docker: bool) -> io::Result<()> {
    std::fs::write("/tmp/izba-egress.nft", ruleset(docker))?;
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

/// Bind the redirect listener on the wildcard address. Split out of
/// `serve_tcp_redirect` so the bind happens on the main thread BEFORE `apply_nft`:
/// the REDIRECT rule sends all guest TCP here, so a listener must already exist or
/// every connect gets a loopback RST. Returning the bound listener gives apply_nft
/// a happens-before. Wildcard bind is necessary because prerouting REDIRECT (docker
/// mode, spec §3) rewrites the destination to the veth interface's address
/// (192.168.127.1), not loopback, while output-hook REDIRECT delivers to loopback
/// — a single listener must accept on any local address.
pub fn bind_tcp_redirect() -> io::Result<TcpListener> {
    TcpListener::bind(("0.0.0.0", REDIRECT_PORT))
}

/// Serve the redirect listener forever (daemon thread) on an already-bound
/// listener.
pub fn serve_tcp_redirect(listener: TcpListener) -> io::Result<()> {
    loop {
        let (conn, _peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                eprintln!("izba-init: tcp redirect accept: {e}");
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
/// Teardown mirrors server.rs::tcp_dial, with the roles flipped, but it has
/// to shut down BOTH sockets at the end where tcp_dial shuts down only one.
/// In tcp_dial both pumps touch the same `conn` fd, so the terminal
/// `shutdown(conn, SHUT_RDWR)` happens to unblock the reader thread too.
/// Here the two pumps read DIFFERENT sockets: the up-thread reads the client
/// (`client_r`), the main pump reads the vsock (`host`). The terminal
/// `shutdown(host, SHUT_RDWR)` only unblocks the main-side reader/vsock — it
/// does nothing for the up-thread, which is parked in `client_r.read()`. If
/// the remote closed first while the app still holds its write side open, the
/// up-thread would block forever and `up.join()` would hang (leaking the
/// thread + its fds). So once the main host->client pump is done we also
/// fully shut down the client socket, which delivers EOF to the up-thread's
/// read and lets it (and the join) finish.
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
    // Full shutdown (Both), not just Write: the inbound direction has nowhere
    // to deliver now that the host pump is done, and — unlike tcp_dial, whose
    // two pumps share one fd — the up-thread reads THIS client socket, so it
    // will sit in client_r.read() forever unless we close its read side too.
    // SHUT_RDWR here delivers EOF to the up-thread (releasing up.join()).
    let _ = client_w.shutdown(std::net::Shutdown::Both);
    // Unblock the main-side vsock and finish the vsock teardown.
    unsafe { libc::shutdown(host.as_raw_fd(), libc::SHUT_RDWR) };
    let _ = up.join();
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

    /// Fake izbad on the far end of a socketpair for the TCP-DNS path: expects
    /// the `DnsTcp` open frame, then answers each framed query with `re:<query>`.
    fn fake_izbad_tcp() -> (UnixStream, std::thread::JoinHandle<()>) {
        let (mine, theirs) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(
                matches!(open, StreamOpen::DnsTcp),
                "expected DnsTcp, got {open:?}"
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
    fn tcp_conn_forwards_sequential_queries() {
        let (host, izbad) = fake_izbad_tcp();
        let (mut app, loop_side) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || forward_tcp_conn(loop_side, || Ok(host)));
        dns::write_dns_msg(&mut app, b"q1").unwrap();
        assert_eq!(dns::read_dns_msg(&mut app).unwrap().unwrap(), b"re:q1");
        dns::write_dns_msg(&mut app, b"q2").unwrap();
        assert_eq!(dns::read_dns_msg(&mut app).unwrap().unwrap(), b"re:q2");
        app.shutdown(std::net::Shutdown::Write).unwrap();
        drop(app);
        h.join().unwrap();
        izbad.join().unwrap();
    }

    /// The whole point of the TCP path: a >512-byte answer relays through the
    /// guest stub intact (no truncation on the guest leg — izbad decides size).
    #[test]
    fn tcp_conn_relays_large_answer_untruncated() {
        let (host, theirs) = UnixStream::pair().unwrap();
        let big = vec![0xABu8; 4000];
        let big2 = big.clone();
        let izbad = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(matches!(open, StreamOpen::DnsTcp));
            let _q = dns::read_dns_msg(&mut s).unwrap().unwrap();
            dns::write_dns_msg(&mut s, &big2).unwrap();
        });
        let (mut app, loop_side) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || forward_tcp_conn(loop_side, || Ok(host)));
        dns::write_dns_msg(&mut app, b"q").unwrap();
        let resp = dns::read_dns_msg(&mut app).unwrap().unwrap();
        assert_eq!(resp.len(), 4000, "full answer relayed without truncation");
        assert_eq!(resp, big);
        app.shutdown(std::net::Shutdown::Write).unwrap();
        drop(app);
        h.join().unwrap();
        izbad.join().unwrap();
    }

    /// A failed egress dial closes the client connection (the resolver fails
    /// fast) rather than hanging.
    #[test]
    fn tcp_dial_failure_closes_connection() {
        let (mut app, loop_side) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            forward_tcp_conn::<UnixStream, UnixStream, _>(loop_side, || {
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "no izbad"))
            })
        });
        h.join().unwrap();
        // The loop side was dropped on return → the app's read sees EOF.
        let mut buf = Vec::new();
        assert_eq!(app.read_to_end(&mut buf).unwrap(), 0);
    }

    /// izbad accepts the `DnsTcp` open then vanishes mid-query: the relay error
    /// becomes a SERVFAIL for that query so the client fails fast.
    #[test]
    fn tcp_relay_failure_becomes_servfail() {
        let (host, theirs) = UnixStream::pair().unwrap();
        let izbad = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(matches!(open, StreamOpen::DnsTcp));
            // Drop without answering: the relay read sees EOF → SERVFAIL.
        });
        let (mut app, loop_side) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || forward_tcp_conn(loop_side, || Ok(host)));
        let q = [0xbeu8, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        dns::write_dns_msg(&mut app, &q).unwrap();
        let resp = dns::read_dns_msg(&mut app).unwrap().unwrap();
        assert_eq!(&resp[..2], &[0xbe, 0xef], "ID preserved");
        assert_eq!(resp[3] & 0x0f, 0x02, "SERVFAIL");
        h.join().unwrap();
        izbad.join().unwrap();
    }

    #[test]
    fn nix_to_io_maps_errno() {
        let e = nix_to_io(nix::errno::Errno::EINVAL);
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
    }

    /// The serve loop end-to-end with a fake izbad over a socketpair (driving the
    /// injected-dialer seam, so it is deterministic — no real vsock): a datagram
    /// in → forwarded over a `Dns` stream → the fake's `re:<query>` answer is
    /// sent back to the client. Proves recv→forward→reply wiring runs (and kills
    /// the `-> Ok(())` mutant). Runtime-skips where the sandbox denies UDP bind.
    #[test]
    fn serve_dns_udp_loop_forwards_and_replies() {
        let server = match UdpSocket::bind(("127.0.0.1", 0)) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP serve_dns_udp_loop_forwards_and_replies: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        set_recv_origdst(&server).expect("enable IP_RECVORIGDSTADDR");
        let saddr = server.local_addr().unwrap();

        // Fresh fake izbad per dial: expect the `Dns` open frame, echo `re:<q>`.
        let dial = || -> io::Result<UnixStream> {
            let (mine, theirs) = UnixStream::pair().unwrap();
            std::thread::spawn(move || {
                let mut s = theirs;
                if read_frame::<_, StreamOpen>(&mut s).is_err() {
                    return;
                }
                while let Ok(Some(q)) = dns::read_dns_msg(&mut s) {
                    let mut r = b"re:".to_vec();
                    r.extend_from_slice(&q);
                    if dns::write_dns_msg(&mut s, &r).is_err() {
                        break;
                    }
                }
            });
            Ok(mine)
        };
        std::thread::spawn(move || {
            let _ = serve_dns_udp_with(server, dial);
        });

        let client = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        client.send_to(b"hello", saddr).unwrap();
        let mut buf = [0u8; 64];
        let (n, _from) = client
            .recv_from(&mut buf)
            .expect("serve_dns_udp must reply (loop ran)");
        assert_eq!(&buf[..n], b"re:hello");
    }

    #[test]
    fn nft_ruleset_shape() {
        // The contract bits the redirect depends on; the full file is integration-tested.
        assert!(NFT_RULESET.contains("type nat hook output priority -100"));
        assert!(NFT_RULESET.contains("ip daddr 127.0.0.0/8 return"));
        assert!(NFT_RULESET.contains("udp dport 53 redirect to :53"));
        assert!(NFT_RULESET.contains("tcp dport 53 redirect to :53"));
        // The general TCP relay carve-out must EXCLUDE dport 53 so a tcp:53
        // packet only ever hits the DNS rule (terminality-independent), and it
        // must still target the relay port.
        assert!(NFT_RULESET.contains(&format!("tcp dport != 53 redirect to :{REDIRECT_PORT}")));
        // Ordering: both DNS rules must precede the general TCP relay.
        let dns_tcp = NFT_RULESET.find("tcp dport 53 redirect").unwrap();
        let relay = NFT_RULESET.find("tcp dport != 53 redirect").unwrap();
        assert!(
            dns_tcp < relay,
            "tcp:53 DNS rule must precede the relay rule"
        );
    }

    #[test]
    fn ruleset_without_docker_is_the_base_const() {
        assert_eq!(ruleset(false), NFT_RULESET);
    }

    #[test]
    fn ruleset_with_docker_adds_prerouting_chain() {
        let r = ruleset(true);
        assert!(
            r.starts_with(NFT_RULESET.trim_end_matches('\n')) || r.contains("chain output"),
            "base output chain must remain"
        );
        assert!(r.contains("type nat hook prerouting"));
        // Same interception surface as the output chain, veth-delivered.
        assert!(r.contains("tcp dport 53 redirect to :53"));
        assert!(r.contains("udp dport 53 redirect to :53"));
        assert!(r.contains(&format!("tcp dport != 53 redirect to :{REDIRECT_PORT}")));
    }

    #[test]
    fn ruleset_with_docker_keeps_output_chain_too() {
        // init's own outbound traffic (the DNS/TCP stub dialing izbad) still
        // needs the output-hook chain even when the workload uses prerouting.
        let r = ruleset(true);
        assert!(r.contains("type nat hook output priority -100"));
        // Everything the base output chain does is still there (the docker
        // variant ADDS the veth-peer exemption, it removes nothing).
        for rule in [
            "ip daddr 127.0.0.0/8 return",
            "tcp dport 53 redirect to :53",
            "udp dport 53 redirect to :53",
        ] {
            assert!(r.contains(rule), "docker output chain lost {rule:?}");
        }
        assert!(r.contains(&format!("tcp dport != 53 redirect to :{REDIRECT_PORT}")));
    }

    #[test]
    fn output_chain_without_docker_is_exactly_the_documented_const() {
        // Guards against the generated chain drifting from NFT_RULESET, whose
        // doc comment is the reference explanation of every rule.
        assert_eq!(output_chain(false), NFT_RULESET);
    }

    #[test]
    fn docker_output_chain_exempts_the_veth_peer_before_the_relay_rule() {
        // The init-side dial to the container (server::tcp_dial's docker
        // fallback) must NOT be swallowed by `tcp dport != 53 redirect`, or
        // izbad tries to reach 192.168.127.2 from the HOST and the port relay
        // times out (real-boot failure, Task 7).
        let r = output_chain(true);
        let exempt = format!("ip daddr {} return", crate::net::GUEST_IP);
        let at = r
            .find(&exempt)
            .unwrap_or_else(|| panic!("docker output chain must exempt the veth peer:\n{r}"));
        let relay = r.find("tcp dport != 53 redirect").expect("relay rule");
        assert!(
            at < relay,
            "the exemption must precede the relay rule:\n{r}"
        );
        // ...and it must NOT leak into the shared-netns ruleset, where the same
        // address is the guest's own dummy0 and nothing dials it from init.
        assert!(!output_chain(false).contains(&exempt));
    }

    #[test]
    fn tcp_redirect_listener_binds_wildcard() {
        // Prerouting REDIRECT (docker mode, spec §3) rewrites the destination to
        // the ingress interface's address (192.168.127.1), not loopback — the
        // listener must accept on any local address. Wildcard is harmless on the
        // NIC-less island. Runtime-skip where the sandbox denies bind (repo test
        // constraint).
        let l = match bind_tcp_redirect() {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return, // parallel test run owns :15001
            Err(e) => panic!("bind: {e}"),
        };
        assert!(l.local_addr().unwrap().ip().is_unspecified());
    }

    /// The transparent-reply plumbing end-to-end on plain loopback (no NAT, so
    /// the original destination is just the listener's own 127.0.0.1): a query
    /// arrives, `recv_with_origdst` recovers that destination from the
    /// IP_ORIGDSTADDR cmsg, and `reply_dns` sources the answer FROM it via
    /// IP_PKTINFO so the client receives it. This exercises the exact recvmsg/
    /// sendmsg cmsg machinery the REDIRECT reply path relies on; the conntrack
    /// un-NAT itself is covered by the KVM integration suite (which needs a
    /// real REDIRECT rule unit tests cannot install). Runtime-skips where the
    /// sandbox denies UDP bind.
    #[test]
    fn origdst_recv_and_pktinfo_reply_roundtrip() {
        let server = match UdpSocket::bind(("127.0.0.1", 0)) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP origdst_recv_and_pktinfo_reply_roundtrip: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        set_recv_origdst(&server).expect("enable IP_RECVORIGDSTADDR");
        let saddr = server.local_addr().unwrap();

        let client = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        client.send_to(b"query", saddr).unwrap();

        let mut buf = [0u8; 64];
        let (n, peer, orig) = recv_with_origdst(&server, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"query");
        assert_eq!(
            orig,
            Some(Ipv4Addr::LOCALHOST),
            "IP_ORIGDSTADDR must report the delivery address"
        );

        reply_dns(&server, b"answer", &peer, orig).unwrap();
        let mut rbuf = [0u8; 64];
        let (rn, from) = client.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..rn], b"answer");
        assert_eq!(
            from.ip(),
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            "reply must be sourced from the original destination"
        );
    }

    /// `reply_dns` with no known original destination falls back to a plain
    /// send (kernel-chosen source) and still delivers.
    #[test]
    fn reply_without_origdst_falls_back() {
        let server = match UdpSocket::bind(("127.0.0.1", 0)) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP reply_without_origdst_falls_back: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        set_recv_origdst(&server).expect("enable IP_RECVORIGDSTADDR");
        let saddr = server.local_addr().unwrap();
        let client = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        client.send_to(b"q", saddr).unwrap();
        let mut buf = [0u8; 64];
        let (_n, peer, _orig) = recv_with_origdst(&server, &mut buf).unwrap();
        reply_dns(&server, b"a", &peer, None).unwrap();
        let mut rbuf = [0u8; 64];
        let (rn, _from) = client.recv_from(&mut rbuf).unwrap();
        assert_eq!(&rbuf[..rn], b"a");
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

    /// Regression: the up-thread reads the app's client socket, not the vsock.
    /// If izbad closes first while the app keeps its write side open, the
    /// terminal shutdown(host) alone never unblocks that read — handle_redirected
    /// would hang in up.join(). The full client shutdown(Both) is what frees it.
    /// We assert (a) handle_redirected returns at all, and (b) the app's pending
    /// read sees EOF because handle_redirected fully closed the client socket.
    #[test]
    fn remote_close_first_does_not_hang() {
        use std::net::{TcpListener, TcpStream};
        use std::sync::mpsc;
        use std::time::Duration;

        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP remote_close_first_does_not_hang: bind denied: {e}");
                return;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = listener.local_addr().unwrap().port();

        // The app connects but deliberately never closes its write side; it
        // just blocks reading until EOF. If handle_redirected leaves the client
        // socket's read side open, this read parks forever.
        let (app_eof_tx, app_eof_rx) = mpsc::channel::<usize>();
        let app = std::thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"hi").unwrap();
            // No shutdown(Write): the app holds its write side open.
            let mut out = Vec::new();
            let n = s.read_to_end(&mut out).unwrap();
            app_eof_tx.send(n).unwrap();
        });
        let (client, _) = listener.accept().unwrap();

        // Fake izbad: reply Ok, then immediately close (remote closes first).
        let (izbad, theirs) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(matches!(open, StreamOpen::TcpConnect { .. }));
            write_frame(&mut s, &izba_proto::Response::Ok).unwrap();
            // Drop `s` -> izbad's side closes while the app's write side stays open.
        });

        let orig = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443);
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            handle_redirected(client, orig, || Ok(izbad));
            let _ = done_tx.send(());
        });

        // Watchdog: handle_redirected must return; a hang means the up-thread
        // never unblocked.
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("handle_redirected hung: up-thread never unblocked");
        handle.join().unwrap();

        // And the full client shutdown must have delivered EOF to the app.
        let n = app_eof_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("app read never saw EOF: client socket not fully shut down");
        assert_eq!(n, 0, "app should see EOF with no inbound bytes");
        app.join().unwrap();
        fake.join().unwrap();
    }

    /// A loopback TcpStream to play the redirected client, plus its accepting
    /// listener; runtime-skips where the sandbox denies bind.
    fn loopback_client() -> Option<(TcpStream, std::thread::JoinHandle<Vec<u8>>)> {
        let listener = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("SKIP: sandbox denies bind: {e}");
                return None;
            }
            Err(e) => panic!("bind probe: {e}"),
        };
        let port = listener.local_addr().unwrap().port();
        // The app connects and reads until EOF — it expects an honest
        // RST/EOF when izbad refuses the dial.
        let app = std::thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
            out
        });
        let (client, _) = listener.accept().unwrap();
        Some((client, app))
    }

    /// When the egress dial itself fails, handle_redirected must log and return
    /// (dropping the client so the app sees EOF) — never panic or hang.
    #[test]
    fn redirected_dial_failure_returns() {
        let Some((client, app)) = loopback_client() else {
            return;
        };
        let orig = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80);
        handle_redirected::<UnixStream, _>(client, orig, || {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "no izbad"))
        });
        // The dropped client delivers EOF to the app's pending read.
        assert!(app.join().unwrap().is_empty());
    }

    /// When izbad replies Error (upstream refused), handle_redirected must
    /// return after the Error frame — the client drops so the app sees EOF,
    /// the honest refusal path.
    #[test]
    fn redirected_error_response_returns() {
        let Some((client, app)) = loopback_client() else {
            return;
        };
        let (izbad, theirs) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut s = theirs;
            let open: StreamOpen = read_frame(&mut s).unwrap();
            assert!(
                matches!(open, StreamOpen::TcpConnect { .. }),
                "expected TcpConnect, got {open:?}"
            );
            write_frame(
                &mut s,
                &izba_proto::Response::Error {
                    kind: izba_proto::ErrorKind::ConnectFailed,
                    message: "upstream refused".into(),
                },
            )
            .unwrap();
            // Drop `s`: izbad's side closes after the Error frame.
        });
        let orig = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80);
        handle_redirected(client, orig, || Ok(izbad));
        assert!(app.join().unwrap().is_empty(), "app sees EOF after refusal");
        fake.join().unwrap();
    }
}
