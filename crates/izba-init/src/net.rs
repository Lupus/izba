//! Guest network policy knobs.
//!
//! `izba.ipv4only=1` (set by the OpenVMM driver) disables IPv6 on eth0:
//! consomme advertises SLAAC whenever the Windows host has *any*
//! non-link-local IPv6 address (e.g. a Tailscale ULA), even with no IPv6
//! default route — every guest IPv6 connect then fails host-side and comes
//! back as an RST ("Connection refused" mid-`wget`, racing SLAAC). Writing
//! `disable_ipv6` flushes any already-acquired SLAAC address and its routes
//! atomically, so applying it after the kernel's `ip=dhcp` is race-free.
//! Loopback is left alone: workloads may bind `::1`.

use std::io;
use std::path::Path;

/// Disables IPv6 on `eth0` (and `default`, for any later-created interface)
/// under `conf_dir` (`/proc/sys/net/ipv6/conf` in the guest).
pub fn apply_ipv4only(conf_dir: &Path) -> io::Result<()> {
    for iface in ["eth0", "default"] {
        std::fs::write(conf_dir.join(iface).join("disable_ipv6"), "1")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_conf_dir(ifaces: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for iface in ifaces {
            let d = dir.path().join(iface);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("disable_ipv6"), "0").unwrap();
        }
        dir
    }

    #[test]
    fn writes_disable_ipv6_for_eth0_and_default_only() {
        let dir = fake_conf_dir(&["eth0", "default", "lo", "all"]);
        apply_ipv4only(dir.path()).unwrap();
        for iface in ["eth0", "default"] {
            let v = std::fs::read_to_string(dir.path().join(iface).join("disable_ipv6")).unwrap();
            assert_eq!(v, "1", "{iface} must be disabled");
        }
        // Loopback (and the `all` aggregate, which would also hit lo) stay
        // untouched so ::1 keeps working for workloads.
        for iface in ["lo", "all"] {
            let v = std::fs::read_to_string(dir.path().join(iface).join("disable_ipv6")).unwrap();
            assert_eq!(v, "0", "{iface} must be left alone");
        }
    }

    #[test]
    fn missing_interface_is_an_error() {
        let dir = fake_conf_dir(&["default"]); // no eth0
        assert!(apply_ipv4only(dir.path()).is_err());
    }
}
