//! Per-sandbox device grants — the consent record.
//!
//! Persisted on `SandboxConfig.usb`, i.e. inside the host-only managed truth
//! (`<data>/sandboxes/<name>/config.json`). Never in the overlay, never in a
//! virtiofs share, never in `izba.yml` (D8): hardware consent is
//! machine-specific and must not live in an agent-writable repo file. `izba rm`
//! removes the sandbox dir, so a reused name can never inherit hardware.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::DeviceId;

/// One standing grant (D7): it survives replug and re-attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbGrant {
    pub device: DeviceId,
    /// Disambiguates two identical `vid:pid` devices (D9). `None` ⇒ the
    /// upstream must expose exactly one match or the attach is an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub busid_pin: Option<String>,
    /// Free text from the upstream's device record, for display only.
    #[serde(default)]
    pub description: String,
    pub granted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbConfig {
    #[serde(default)]
    pub devices: Vec<UsbGrant>,
}

impl UsbConfig {
    /// Whether this sandbox holds any hardware consent. This is the single
    /// input to the egress `UsbGuard`'s `sandbox_usb_enabled`.
    pub fn is_enabled(&self) -> bool {
        !self.devices.is_empty()
    }
}

/// A busid is a kernel-assigned port path like `3-2` or `1-1.4.2`. It is
/// upstream-supplied data that ends up in a protocol field and in logs, so it
/// is validated on the way in rather than sanitised on the way out.
pub fn valid_busid(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

pub fn find(cfg: &UsbConfig, device: DeviceId) -> Option<&UsbGrant> {
    cfg.devices.iter().find(|g| g.device == device)
}

pub fn grant(cfg: &mut UsbConfig, g: UsbGrant) -> Result<()> {
    if let Some(pin) = &g.busid_pin {
        if !valid_busid(pin) {
            bail!("'{pin}' is not a valid busid (expected e.g. 3-2 or 1-1.4.2)");
        }
    }
    if find(cfg, g.device).is_some() {
        bail!(
            "{} is already granted to this sandbox; revoke it first to change its pin",
            g.device
        );
    }
    cfg.devices.push(g);
    Ok(())
}

pub fn revoke(cfg: &mut UsbConfig, device: DeviceId) -> Result<()> {
    let before = cfg.devices.len();
    cfg.devices.retain(|g| g.device != device);
    if cfg.devices.len() == before {
        bail!("{device} is not granted to this sandbox");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> DeviceId {
        s.parse().unwrap()
    }

    fn cfg_with(entries: &[(&str, Option<&str>)]) -> UsbConfig {
        let mut c = UsbConfig::default();
        for (d, pin) in entries {
            grant(
                &mut c,
                UsbGrant {
                    device: id(d),
                    busid_pin: pin.map(|s| s.to_string()),
                    description: String::new(),
                    granted_at_unix_ms: 1,
                },
            )
            .unwrap();
        }
        c
    }

    #[test]
    fn a_fresh_sandbox_holds_no_grants() {
        let c = UsbConfig::default();
        assert!(c.devices.is_empty());
        assert!(!c.is_enabled(), "no grants ⇒ USB is not enabled here");
    }

    #[test]
    fn granting_a_device_enables_usb_for_the_sandbox() {
        let c = cfg_with(&[("0403:6001", None)]);
        assert!(c.is_enabled());
        assert_eq!(c.devices.len(), 1);
        assert!(find(&c, id("0403:6001")).is_some());
        assert!(find(&c, id("1a86:7523")).is_none());
    }

    #[test]
    fn granting_the_same_device_twice_is_refused_not_duplicated() {
        // Silently deduplicating would hide that the second grant's busid_pin
        // never took effect; a grant is a consent record, so say so.
        let mut c = cfg_with(&[("0403:6001", None)]);
        let err = grant(
            &mut c,
            UsbGrant {
                device: id("0403:6001"),
                busid_pin: Some("3-2".into()),
                description: String::new(),
                granted_at_unix_ms: 2,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("0403:6001"), "{err}");
        assert!(err.contains("already"), "{err}");
        assert_eq!(c.devices.len(), 1);
        assert!(c.devices[0].busid_pin.is_none(), "the first grant stands");
    }

    #[test]
    fn revoking_removes_exactly_one_grant() {
        let mut c = cfg_with(&[("0403:6001", None), ("1a86:7523", None)]);
        revoke(&mut c, id("0403:6001")).unwrap();
        assert_eq!(c.devices.len(), 1);
        assert_eq!(c.devices[0].device, id("1a86:7523"));
        assert!(c.is_enabled(), "one grant remains");
    }

    #[test]
    fn revoking_the_last_grant_disables_usb_again() {
        let mut c = cfg_with(&[("0403:6001", None)]);
        revoke(&mut c, id("0403:6001")).unwrap();
        assert!(!c.is_enabled());
    }

    #[test]
    fn revoking_something_never_granted_is_an_error_not_a_silent_ok() {
        let mut c = UsbConfig::default();
        let err = revoke(&mut c, id("0403:6001")).unwrap_err().to_string();
        assert!(err.contains("0403:6001"), "{err}");
        assert!(err.contains("not granted"), "{err}");
    }

    #[test]
    fn a_busid_pin_must_look_like_a_busid() {
        let mut c = UsbConfig::default();
        let long = "9".repeat(64);
        for bad in ["", "3-2; rm -rf /", "../../etc", "3-2\n", "3 2", &long] {
            let err = grant(
                &mut c,
                UsbGrant {
                    device: id("0403:6001"),
                    busid_pin: Some(bad.to_string()),
                    description: String::new(),
                    granted_at_unix_ms: 1,
                },
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("busid"), "{bad:?}: {err}");
        }
        assert!(c.devices.is_empty(), "nothing is persisted on rejection");
    }

    #[test]
    fn a_plausible_busid_pin_is_kept() {
        let c = cfg_with(&[("0403:6001", Some("3-2"))]);
        assert_eq!(c.devices[0].busid_pin.as_deref(), Some("3-2"));
        let c = cfg_with(&[("0403:6001", Some("1-1.4.2"))]);
        assert_eq!(c.devices[0].busid_pin.as_deref(), Some("1-1.4.2"));
        // 31 chars is the last accepted length; 32 is not (see valid_busid).
        assert!(valid_busid(&"1".repeat(31)));
        assert!(!valid_busid(&"1".repeat(32)));
    }

    #[test]
    fn grants_serialize_with_a_stable_shape() {
        let c = cfg_with(&[("0403:6001", Some("3-2"))]);
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains(r#""device":{"vid":1027,"pid":24577}"#), "{s}");
        assert!(s.contains(r#""busid_pin":"3-2""#), "{s}");
        let back: UsbConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn an_unpinned_grant_omits_the_pin_rather_than_writing_null() {
        let c = cfg_with(&[("0403:6001", None)]);
        let s = serde_json::to_string(&c).unwrap();
        assert!(!s.contains("busid_pin"), "{s}");
        let back: UsbConfig = serde_json::from_str(&s).unwrap();
        assert!(back.devices[0].busid_pin.is_none());
    }

    #[test]
    fn an_absent_usb_key_deserializes_to_no_grants() {
        let c: UsbConfig = serde_json::from_str("{}").unwrap();
        assert!(c.devices.is_empty());
    }
}
