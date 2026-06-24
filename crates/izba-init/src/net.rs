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

pub(crate) const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 2);
pub(crate) const RESOLVER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 127, 1);
/// resolv.conf nameserver. Loopback, NOT `RESOLVER_IP`: 127.0.0.0/8 is
/// exempt from the nft REDIRECT rule, so the reply path stays clean. A
/// non-loopback address would be REDIRECTed to :53, but the stub's wildcard
/// socket replies from the wrong source address — conntrack never matches the
/// reverse-NAT tuple and the reply is dropped. See `main::write_resolv_conf`
/// and NFT_RULESET's doc in `egress.rs`.
pub(crate) const DNS_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

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
    enable_route_localnet()?;
    Ok(())
}

/// Permit 127/8 to appear as a route source/destination on real interfaces.
/// The nft `udp dport 53 redirect` rule rewrites a hardcoded-resolver query's
/// destination to 127.0.0.1; the DNS stub then replies FROM 127.0.0.1 to the
/// guest IP so conntrack can reverse the DNAT (see `egress::NFT_RULESET`).
/// Without `route_localnet` the kernel treats that 127.0.0.1 source as a
/// martian and drops the reply. Harmless on this NIC-less island — there is no
/// external interface for a 127/8 address to leak onto.
fn enable_route_localnet() -> io::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/conf/all/route_localnet", "1\n")
}

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
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ifname too long",
        ));
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
    ioctl(
        libc::SIOCADDRT,
        &mut rt as *mut _ as *mut _,
        "default route",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_rejects_long_names() {
        assert!(ifreq_named("a-name-longer-than-ifnamsiz!").is_err());
        assert!(ifreq_named("dummy0:1").is_ok());
    }

    #[test]
    fn dns_nameserver_is_loopback() {
        // The resolv.conf nameserver MUST be loopback: a non-loopback address
        // is REDIRECTed by nft, and the stub's wildcard-socket reply is
        // dropped (source-address mismatch; see NFT_RULESET's doc in egress.rs).
        assert!(
            DNS_LOOPBACK.is_loopback(),
            "resolv.conf nameserver must be a loopback address, got {DNS_LOOPBACK}"
        );
    }

    #[test]
    fn sockaddr_v4_is_network_order() {
        let sa = sockaddr_v4(Ipv4Addr::new(192, 168, 127, 2));
        let sin: libc::sockaddr_in = unsafe { std::mem::transmute(sa) };
        assert_eq!(u32::from_be(sin.sin_addr.s_addr), 0xC0A87F02);
    }
}
