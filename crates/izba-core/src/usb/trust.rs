//! How much to trust the configured usbip upstream, and what to tell the human.
//!
//! usbip has no authentication, no authorization and no encryption. The only
//! meaningful question is therefore *whose machine* is on the other end, and
//! "is it loopback?" answers that badly on izba's primary platform: under WSL2
//! NAT the user's own Windows host is an RFC1918 default gateway. So the
//! gateway case is classified separately and gets an informational note, while
//! a genuine third-party LAN box gets the loud one.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTrust {
    /// Same machine as izbad.
    OwnHostLoopback,
    /// The user's own Windows host, reached across the WSL2 NAT boundary.
    OwnHostWslGateway,
    /// A private-range address that is not this machine.
    PrivateLan,
    /// Globally routable.
    Public,
}

impl UpstreamTrust {
    /// Stable kebab-case token for the wire and for scripts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OwnHostLoopback => "own-host-loopback",
            Self::OwnHostWslGateway => "own-host-wsl-gateway",
            Self::PrivateLan => "private-lan",
            Self::Public => "public",
        }
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            // Unique-local fc00::/7 and link-local fe80::/10.
            let seg = v6.segments();
            (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Classify `ip` given the host's default gateway (if known) and whether izbad
/// is running under WSL. Both inputs are injected so this stays pure.
pub fn classify(ip: IpAddr, gateway: Option<IpAddr>, under_wsl: bool) -> UpstreamTrust {
    if ip.is_loopback() {
        return UpstreamTrust::OwnHostLoopback;
    }
    if under_wsl && gateway == Some(ip) {
        return UpstreamTrust::OwnHostWslGateway;
    }
    if is_private(ip) {
        return UpstreamTrust::PrivateLan;
    }
    UpstreamTrust::Public
}

/// A public upstream is refused outright unless the user opted in; every other
/// class is allowed (with or without a warning).
pub fn is_refused(t: UpstreamTrust, allow_remote_upstream: bool) -> bool {
    matches!(t, UpstreamTrust::Public) && !allow_remote_upstream
}

/// The human-facing note for this class, or `None` when the configuration is
/// the recommended one and silence is correct.
pub fn describe(t: UpstreamTrust, host: &str) -> Option<String> {
    match t {
        UpstreamTrust::OwnHostLoopback => None,
        UpstreamTrust::OwnHostWslGateway => Some(format!(
            "note: {host} is your Windows host across the WSL boundary.\n\
             Any other WSL distro on this machine can attach the same devices."
        )),
        UpstreamTrust::PrivateLan => Some(format!(
            "⚠  {host} is another machine on your network.\n\
             USB/IP has no authentication and no encryption: anyone who can route\n\
             there can attach the same devices, and can read or modify everything\n\
             your sandbox sends to and receives from them."
        )),
        UpstreamTrust::Public => Some(format!(
            "⚠  {host} is reachable from the internet.\n\
             USB/IP has no authentication and no encryption. Anyone who can reach\n\
             this address can attach the same devices, and can read or modify the\n\
             traffic. This is not a supported configuration."
        )),
    }
}

/// Parse the default gateway out of `/proc/net/route` contents.
///
/// Deliberately NOT derived from `resolv.conf`: with izba's DNS tunnelling the
/// guest's nameserver is a stub address, not the host.
pub fn default_gateway_from_proc_route(table: &str) -> Option<IpAddr> {
    for line in table.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (_iface, dest, gw) = (f.next()?, f.next()?, f.next()?);
        if dest != "00000000" {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(gw, 16) else {
            continue;
        };
        if raw == 0 {
            continue;
        }
        // The kernel prints the address in host byte order.
        let b = raw.to_le_bytes();
        return Some(IpAddr::from([b[0], b[1], b[2], b[3]]));
    }
    None
}

pub fn wsl_from_osrelease(release: &str) -> bool {
    let r = release.to_ascii_lowercase();
    r.contains("microsoft") || r.contains("wsl")
}

/// Read the host's default gateway. `None` on any platform or failure — the
/// caller then classifies without the WSL special case, which is the safe
/// direction (knowing the gateway can only ever *soften* a warning).
// reason: thin /proc reader; the parsing is fully unit-tested through
// `default_gateway_from_proc_route`.
#[mutants::skip]
pub fn host_default_gateway() -> Option<IpAddr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    default_gateway_from_proc_route(&table)
}

/// Whether izbad is running under WSL. `false` on any failure — again the safe
/// direction, since the WSL case is the one that downgrades a warning.
// reason: thin /proc reader; `wsl_from_osrelease` carries the logic.
#[mutants::skip]
pub fn running_under_wsl() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|r| wsl_from_osrelease(&r))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_is_the_recommended_configuration() {
        for a in ["127.0.0.1", "127.5.5.5", "::1"] {
            assert_eq!(classify(ip(a), None, false), UpstreamTrust::OwnHostLoopback);
        }
        assert!(describe(UpstreamTrust::OwnHostLoopback, "127.0.0.1").is_none());
    }

    #[test]
    fn the_wsl_default_gateway_is_your_own_windows_host() {
        let gw = ip("172.24.32.1");
        assert_eq!(
            classify(gw, Some(gw), true),
            UpstreamTrust::OwnHostWslGateway
        );
        let msg = describe(UpstreamTrust::OwnHostWslGateway, "172.24.32.1").unwrap();
        assert!(msg.contains("Windows host"), "{msg}");
        // The honest caveat: usbipd-win serves every WSL distro on this machine.
        assert!(msg.contains("WSL"), "{msg}");
    }

    #[test]
    fn the_same_address_off_wsl_is_just_a_lan_host() {
        // Identical address, but izbad is not under WSL: it is someone's box.
        let gw = ip("172.24.32.1");
        assert_eq!(classify(gw, Some(gw), false), UpstreamTrust::PrivateLan);
    }

    #[test]
    fn a_private_address_that_is_not_the_gateway_is_lan_even_under_wsl() {
        assert_eq!(
            classify(ip("192.168.1.50"), Some(ip("172.24.32.1")), true),
            UpstreamTrust::PrivateLan
        );
    }

    #[test]
    fn an_unknown_gateway_never_upgrades_trust() {
        // If /proc/net/route could not be read, the WSL carve-out must not fire.
        assert_eq!(
            classify(ip("172.24.32.1"), None, true),
            UpstreamTrust::PrivateLan
        );
    }

    #[test]
    fn private_ranges_are_recognised_including_ula() {
        for a in [
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.9",
            "fd00::1",
            "fe80::1",
            "169.254.1.1",
        ] {
            assert_eq!(
                classify(ip(a), None, false),
                UpstreamTrust::PrivateLan,
                "{a}"
            );
        }
        // 172.32/12 is NOT private — a classic off-by-one in RFC1918 checks.
        assert_eq!(
            classify(ip("172.32.0.1"), None, false),
            UpstreamTrust::Public
        );
        assert_eq!(
            classify(ip("172.15.0.1"), None, false),
            UpstreamTrust::Public
        );
        assert_eq!(
            classify(ip("2001:db8::1"), None, false),
            UpstreamTrust::Public
        );
    }

    #[test]
    fn lan_warning_names_who_is_being_trusted() {
        let msg = describe(UpstreamTrust::PrivateLan, "192.168.1.50").unwrap();
        assert!(msg.contains("192.168.1.50"), "{msg}");
        assert!(msg.contains("no authentication"), "{msg}");
        // F-USB-5: the upstream can attack the guest USB stack, so say so.
        assert!(msg.contains("read or modify"), "{msg}");
    }

    #[test]
    fn public_upstreams_are_refused_unless_explicitly_allowed() {
        assert_eq!(
            classify(ip("93.184.216.34"), None, false),
            UpstreamTrust::Public
        );
        assert!(is_refused(UpstreamTrust::Public, false));
        assert!(!is_refused(UpstreamTrust::Public, true));
        for t in [
            UpstreamTrust::OwnHostLoopback,
            UpstreamTrust::OwnHostWslGateway,
            UpstreamTrust::PrivateLan,
        ] {
            assert!(!is_refused(t, false), "{t:?} must not need the opt-out");
        }
    }

    #[test]
    fn a_public_upstream_still_warns_after_being_allowed() {
        let msg = describe(UpstreamTrust::Public, "203.0.113.7").unwrap();
        assert!(msg.contains("internet"), "{msg}");
        assert!(msg.contains("203.0.113.7"), "{msg}");
    }

    #[test]
    fn trust_tokens_are_stable_and_distinct() {
        let all = [
            UpstreamTrust::OwnHostLoopback,
            UpstreamTrust::OwnHostWslGateway,
            UpstreamTrust::PrivateLan,
            UpstreamTrust::Public,
        ];
        assert_eq!(
            all.map(|t| t.as_str()),
            [
                "own-host-loopback",
                "own-host-wsl-gateway",
                "private-lan",
                "public"
            ]
        );
    }

    #[test]
    fn gateway_comes_from_proc_net_route_never_from_resolv_conf() {
        // Destination 00000000 marks the default route; the Gateway column is
        // the address in host byte order, so 0120CDAC reads back as 172.205.32.1.
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t0000E0AC\t00000000\t0001\t0\t0\t0\t0000F0FF\n\
eth0\t00000000\t0120CDAC\t0003\t0\t0\t0\t00000000\n";
        assert_eq!(
            default_gateway_from_proc_route(table),
            Some(ip("172.205.32.1"))
        );
    }

    #[test]
    fn the_first_default_route_wins_and_non_default_rows_are_skipped() {
        let table = "\
Iface\tDestination\tGateway\n\
eth0\t0000E0AC\t0101A8C0\n\
eth0\t00000000\t0101A8C0\n\
eth1\t00000000\t0202A8C0\n";
        assert_eq!(
            default_gateway_from_proc_route(table),
            Some(ip("192.168.1.1"))
        );
    }

    #[test]
    fn a_route_table_with_no_usable_default_route_yields_no_gateway() {
        let table = "Iface\tDestination\tGateway\n\
eth0\t0000E0AC\t00000000\t0001\t0\t0\t0\t0000F0FF\n";
        assert_eq!(default_gateway_from_proc_route(table), None);
        assert_eq!(default_gateway_from_proc_route(""), None);
        assert_eq!(default_gateway_from_proc_route("header only\n"), None);
        // A default route with a zero gateway is an on-link route, not a gateway.
        assert_eq!(
            default_gateway_from_proc_route("h\neth0\t00000000\t00000000\n"),
            None
        );
        // A malformed gateway column must be skipped, not abort the whole scan.
        assert_eq!(
            default_gateway_from_proc_route("h\neth0\t00000000\tZZZZ\neth0\t00000000\t0101A8C0\n"),
            Some(ip("192.168.1.1"))
        );
    }

    #[test]
    fn wsl_is_detected_from_the_kernel_release_string() {
        assert!(wsl_from_osrelease("5.15.167.4-microsoft-standard-WSL2"));
        assert!(wsl_from_osrelease("6.6.87.2-microsoft-standard-WSL2+"));
        assert!(wsl_from_osrelease("6.6.0-MICROSOFT"));
        assert!(!wsl_from_osrelease("6.8.0-45-generic"));
        assert!(!wsl_from_osrelease(""));
    }
}
