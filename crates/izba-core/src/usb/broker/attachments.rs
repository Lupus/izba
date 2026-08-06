//! Which sandbox is holding each device right now.
//!
//! izbad does not have to ask the guest what it has attached — izbad **is** the
//! attachment: every live device is a splice this process is running. Asking the
//! guest would mean trusting a hostile party (A1) about a fact the host already
//! owns.
//!
//! The entry exists for exactly as long as the splice does: [`Attachments::hold`]
//! inserts and the returned guard's `Drop` removes it, so a handler that
//! returns, errors, or panics cannot leave a device looking attached when it is
//! already back on the host.

use crate::usb::DeviceId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct Attachments {
    inner: Arc<Mutex<HashMap<DeviceId, String>>>,
}

impl Attachments {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `device` as held by `sandbox` until the returned guard drops.
    pub fn hold(&self, sandbox: &str, device: DeviceId) -> AttachmentGuard {
        lock(&self.inner).insert(device, sandbox.to_string());
        AttachmentGuard {
            inner: Arc::clone(&self.inner),
            device,
        }
    }

    /// Device → holding sandbox, across every sandbox this daemon serves.
    pub fn map(&self) -> HashMap<DeviceId, String> {
        lock(&self.inner).clone()
    }

    /// What one sandbox is holding, in a stable order — a listing that reorders
    /// between polls reads as churn in a UI that re-renders it.
    pub fn held_by(&self, sandbox: &str) -> Vec<DeviceId> {
        let mut v: Vec<DeviceId> = lock(&self.inner)
            .iter()
            .filter(|(_, s)| s.as_str() == sandbox)
            .map(|(d, _)| *d)
            .collect();
        v.sort();
        v
    }
}

/// A poisoned lock here means some other holder panicked mid-mutation. The map
/// is a plain `HashMap` with no cross-entry invariant, and refusing to release a
/// device would strand it, so recover rather than propagate.
fn lock(
    m: &Mutex<HashMap<DeviceId, String>>,
) -> std::sync::MutexGuard<'_, HashMap<DeviceId, String>> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub struct AttachmentGuard {
    inner: Arc<Mutex<HashMap<DeviceId, String>>>,
    device: DeviceId,
}

impl Drop for AttachmentGuard {
    fn drop(&mut self) {
        lock(&self.inner).remove(&self.device);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(s: &str) -> DeviceId {
        s.parse().unwrap()
    }

    #[test]
    fn a_device_is_held_only_while_its_guard_lives() {
        let a = Attachments::new();
        assert!(a.map().is_empty());
        {
            let _g = a.hold("web", dev("0403:6001"));
            assert_eq!(
                a.map().get(&dev("0403:6001")).map(String::as_str),
                Some("web")
            );
            assert_eq!(a.held_by("web"), vec![dev("0403:6001")]);
        }
        // The splice ended: the device is back on the host. Saying otherwise
        // would tell a user to detach something already detached.
        assert!(a.map().is_empty());
        assert!(a.held_by("web").is_empty());
    }

    #[test]
    fn a_panicking_handler_still_releases_the_device() {
        let a = Attachments::new();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = a.hold("web", dev("0403:6001"));
            panic!("splice blew up");
        }));
        assert!(res.is_err());
        assert!(
            a.map().is_empty(),
            "a leaked entry is a device that looks permanently attached"
        );
        // And the map is still usable after the poisoning panic.
        let _g = a.hold("web", dev("10c4:ea60"));
        assert_eq!(a.held_by("web"), vec![dev("10c4:ea60")]);
    }

    #[test]
    fn a_sandbox_holding_several_devices_lists_them_sorted() {
        let a = Attachments::new();
        let _g1 = a.hold("web", dev("10c4:ea60"));
        let _g2 = a.hold("web", dev("0403:6001"));
        assert_eq!(a.held_by("web"), vec![dev("0403:6001"), dev("10c4:ea60")]);
    }

    #[test]
    fn devices_held_by_other_sandboxes_are_not_listed_as_this_ones() {
        let a = Attachments::new();
        let _g1 = a.hold("web", dev("0403:6001"));
        let _g2 = a.hold("api", dev("10c4:ea60"));
        assert_eq!(a.held_by("web"), vec![dev("0403:6001")]);
        assert_eq!(a.held_by("api"), vec![dev("10c4:ea60")]);
        assert_eq!(a.map().len(), 2);
    }
}
