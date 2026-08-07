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
//!
//! What "each device" means is [`AttachmentKey`] — a `vid:pid` *and* the
//! upstream port it came from, because the id alone does not name one piece of
//! hardware.

use crate::usb::DeviceId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What one live attachment is keyed on: the granted `vid:pid` **and the
/// upstream busid it was imported from**.
///
/// The busid belongs in the key because a `vid:pid` does not name one piece of
/// hardware — that ambiguity is exactly why [`crate::usb::UsbGrant::busid_pin`]
/// exists (D9). Two identical boards can be granted to two different sandboxes,
/// pinned to different ports, and both attach: the imports are distinct devices
/// on the upstream. Keyed on the id alone, the second hold would overwrite the
/// first (the map would name the wrong sandbox) and the first guard's drop would
/// then erase the second sandbox's live loan — reporting hardware that is
/// currently spliced into a running VM as free. A busid names a port on the
/// upstream, so the pair identifies the physical device the splice is carrying.
pub type AttachmentKey = (DeviceId, String);

/// Live attachment → the sandbox holding it, across every sandbox this daemon
/// serves.
pub type AttachmentMap = HashMap<AttachmentKey, String>;

#[derive(Clone, Default)]
pub struct Attachments {
    inner: Arc<Mutex<AttachmentMap>>,
}

impl Attachments {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark `device`, imported from `busid`, as held by `sandbox` until the
    /// returned guard drops.
    pub fn hold(&self, sandbox: &str, device: DeviceId, busid: &str) -> AttachmentGuard {
        let key = (device, busid.to_string());
        lock(&self.inner).insert(key.clone(), sandbox.to_string());
        AttachmentGuard {
            inner: Arc::clone(&self.inner),
            key,
        }
    }

    /// Every live attachment, keyed by [`AttachmentKey`].
    pub fn map(&self) -> AttachmentMap {
        lock(&self.inner).clone()
    }

    /// What one sandbox is holding, in a stable order — a listing that reorders
    /// between polls reads as churn in a UI that re-renders it.
    ///
    /// Deduplicated because the key space is wider than what this returns:
    /// `grants::grant` already refuses a second grant for the same `vid:pid` in
    /// one sandbox, so two ports cannot both be loaned to it — but this is a
    /// display path, and collapsing here does not depend on that invariant
    /// holding elsewhere.
    pub fn held_by(&self, sandbox: &str) -> Vec<DeviceId> {
        let mut v: Vec<DeviceId> = lock(&self.inner)
            .iter()
            .filter(|(_, s)| s.as_str() == sandbox)
            .map(|((d, _), _)| *d)
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

/// A poisoned lock here means some other holder panicked mid-mutation. The map
/// is a plain `HashMap` with no cross-entry invariant, and refusing to release a
/// device would strand it, so recover rather than propagate.
fn lock(m: &Mutex<AttachmentMap>) -> std::sync::MutexGuard<'_, AttachmentMap> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub struct AttachmentGuard {
    inner: Arc<Mutex<AttachmentMap>>,
    /// The full key, so a drop releases exactly the port this splice held and
    /// never an identical board another sandbox is still using.
    key: AttachmentKey,
}

impl Drop for AttachmentGuard {
    fn drop(&mut self) {
        lock(&self.inner).remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(s: &str) -> DeviceId {
        s.parse().unwrap()
    }

    #[test]
    fn one_sandbox_detaching_does_not_free_an_identical_board_another_still_holds() {
        // Two physically distinct boards can share a vid:pid — that ambiguity is
        // the whole reason `UsbGrant.busid_pin` exists (D9). Both imports
        // succeed, because they are different ports on the upstream.
        let a = Attachments::new();
        let g_a = a.hold("A", dev("303a:1001"), "3-2");
        let _g_b = a.hold("B", dev("303a:1001"), "3-3");
        // A returns its board. B is still spliced.
        drop(g_a);
        assert_eq!(
            a.held_by("B"),
            vec![dev("303a:1001")],
            "B is still splicing its board; saying otherwise reports in-use \
             hardware as free"
        );
    }

    #[test]
    fn two_sandboxes_holding_the_same_vid_pid_on_different_ports_are_both_visible() {
        let a = Attachments::new();
        let _g_a = a.hold("A", dev("303a:1001"), "3-2");
        let _g_b = a.hold("B", dev("303a:1001"), "3-3");
        let m = a.map();
        assert_eq!(m.len(), 2, "two boards are two loans, not one");
        assert_eq!(
            m.get(&(dev("303a:1001"), "3-2".to_string()))
                .map(String::as_str),
            Some("A")
        );
        assert_eq!(
            m.get(&(dev("303a:1001"), "3-3".to_string()))
                .map(String::as_str),
            Some("B")
        );
    }

    #[test]
    fn one_sandbox_holding_the_same_model_on_two_ports_lists_it_once() {
        // `grants::grant` refuses a second grant for the same vid:pid in one
        // sandbox, so this should be unreachable — but `held_by` returns ids
        // out of a wider key space, and a listing that repeated a row would
        // read as two devices. Collapse here rather than trusting a rule
        // enforced somewhere else.
        let a = Attachments::new();
        let _g1 = a.hold("web", dev("303a:1001"), "3-2");
        let _g2 = a.hold("web", dev("303a:1001"), "3-3");
        assert_eq!(a.map().len(), 2, "two ports are still two loans");
        assert_eq!(a.held_by("web"), vec![dev("303a:1001")]);
    }

    #[test]
    fn a_device_is_held_only_while_its_guard_lives() {
        let a = Attachments::new();
        assert!(a.map().is_empty());
        {
            let _g = a.hold("web", dev("0403:6001"), "3-2");
            assert_eq!(
                a.map()
                    .get(&(dev("0403:6001"), "3-2".to_string()))
                    .map(String::as_str),
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
            let _g = a.hold("web", dev("0403:6001"), "3-2");
            panic!("splice blew up");
        }));
        assert!(res.is_err());
        assert!(
            a.map().is_empty(),
            "a leaked entry is a device that looks permanently attached"
        );
        // And the map is still usable after the poisoning panic.
        let _g = a.hold("web", dev("10c4:ea60"), "1-4");
        assert_eq!(a.held_by("web"), vec![dev("10c4:ea60")]);
    }

    #[test]
    fn a_sandbox_holding_several_devices_lists_them_sorted() {
        let a = Attachments::new();
        let _g1 = a.hold("web", dev("10c4:ea60"), "1-4");
        let _g2 = a.hold("web", dev("0403:6001"), "3-2");
        assert_eq!(a.held_by("web"), vec![dev("0403:6001"), dev("10c4:ea60")]);
    }

    #[test]
    fn devices_held_by_other_sandboxes_are_not_listed_as_this_ones() {
        let a = Attachments::new();
        let _g1 = a.hold("web", dev("0403:6001"), "3-2");
        let _g2 = a.hold("api", dev("10c4:ea60"), "1-4");
        assert_eq!(a.held_by("web"), vec![dev("0403:6001")]);
        assert_eq!(a.held_by("api"), vec![dev("10c4:ea60")]);
        assert_eq!(a.map().len(), 2);
    }
}
