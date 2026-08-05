//! Host-side USB passthrough: identity, consent, settings, and inventory.
//!
//! Everything here runs on the host and is reachable only from a human-driven
//! CLI/GUI action or from izbad's own outbound dial. The guest never sees a
//! device list and never supplies an upstream address (D1/F-USB-9). The
//! guest-facing broker plane lands in a later phase as `usb::broker`.

pub mod grants;
pub mod ids;
pub mod inventory;
pub mod settings;
pub mod trust;
pub mod usbipd_state;

pub use grants::{UsbConfig, UsbGrant};
pub use ids::DeviceId;
pub use settings::{Upstream, UsbSettings};

/// The single "is this feature on?" predicate. USB is configured exactly when a
/// human set an upstream; nothing else turns it on.
pub fn is_configured(s: &UsbSettings) -> bool {
    s.upstream.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_is_off_until_a_human_sets_an_upstream() {
        assert!(!is_configured(&UsbSettings::default()));
        assert!(is_configured(&UsbSettings {
            upstream: Some(Upstream {
                host: "127.0.0.1".into(),
                port: 3240,
            }),
            allow_remote_upstream: false,
        }));
    }

    #[test]
    fn allowing_a_remote_upstream_alone_does_not_turn_the_feature_on() {
        // The flag is a permission, not a switch: without an address there is
        // nothing to dial and every USB RPC must still refuse.
        assert!(!is_configured(&UsbSettings {
            upstream: None,
            allow_remote_upstream: true,
        }));
    }
}
