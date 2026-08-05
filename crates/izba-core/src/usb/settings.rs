//! Daemon-level USB settings: `<data>/usb/settings.json`.
//!
//! Absent or unreadable means the feature is OFF. This is the inverse of
//! `ssh::settings` (whose default is on) and it is deliberate: an upstream is
//! the address izbad will dial from the host's network position, so "I could
//! not read your intent" must never resolve to "dial something".

use std::path::Path;

use serde::{Deserialize, Serialize};

/// The usbip server izbad talks to. `host` is stored as the user typed it so
/// `izba usb upstream show` can echo it back; resolution happens per use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
}

/// The IANA-registered usbip port; also usbipd-win's default.
pub const DEFAULT_UPSTREAM_PORT: u16 = 3240;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbSettings {
    /// `None` ⇒ USB passthrough is not configured; every USB RPC refuses.
    #[serde(default)]
    pub upstream: Option<Upstream>,
    /// Permit a globally-routable upstream. Off by default: an unauthenticated,
    /// unencrypted protocol over the open internet is refused, not warned about.
    #[serde(default)]
    pub allow_remote_upstream: bool,
}

const FILE: &str = "settings.json";

/// Never fails: an unreadable or malformed file reads as "not configured".
pub fn load(usb_dir: &Path) -> UsbSettings {
    match std::fs::read(usb_dir.join(FILE)) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
        Err(_) => UsbSettings::default(),
    }
}

pub fn save(usb_dir: &Path, s: &UsbSettings) -> anyhow::Result<()> {
    std::fs::create_dir_all(usb_dir)?;
    let path = usb_dir.join(FILE);
    crate::state::save_json(&path, s)?;
    // The file names the machine that holds the user's hardware; keep it out of
    // reach on a multi-user host, matching the ca/ and daemon/ posture.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_with_no_upstream() {
        let s = UsbSettings::default();
        assert!(s.upstream.is_none(), "no upstream ⇒ the feature is off");
        assert!(!s.allow_remote_upstream, "remote upstreams are opt-in");
    }

    #[test]
    fn missing_file_reads_as_off() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(tmp.path()).upstream.is_none());
    }

    #[test]
    fn corrupt_file_reads_as_off_not_as_permissive_defaults() {
        // Inverted from ssh::settings (default ON): an unreadable USB config must
        // never leave the feature enabled, because "enabled" is what arms the
        // grant plane and relaxes nothing else.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("settings.json"), b"{ not json").unwrap();
        let s = load(tmp.path());
        assert!(s.upstream.is_none());
        assert!(!s.allow_remote_upstream);
    }

    #[test]
    fn roundtrips_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let want = UsbSettings {
            upstream: Some(Upstream {
                host: "172.24.32.1".into(),
                port: 3240,
            }),
            allow_remote_upstream: true,
        };
        save(tmp.path(), &want).unwrap();
        let got = load(tmp.path());
        assert_eq!(got, want);
    }

    #[test]
    fn save_creates_the_directory_when_it_does_not_exist_yet() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("usb");
        save(&dir, &UsbSettings::default()).unwrap();
        assert!(dir.join("settings.json").is_file());
    }

    #[test]
    fn omitted_allow_remote_defaults_to_refusing_public_upstreams() {
        let s: UsbSettings =
            serde_json::from_str(r#"{"upstream":{"host":"127.0.0.1","port":3240}}"#).unwrap();
        assert!(!s.allow_remote_upstream);
        assert_eq!(s.upstream.unwrap().port, 3240);
    }

    #[test]
    fn the_default_port_is_the_registered_usbip_port() {
        assert_eq!(DEFAULT_UPSTREAM_PORT, 3240);
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        save(tmp.path(), &UsbSettings::default()).unwrap();
        let mode = std::fs::metadata(tmp.path().join("settings.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "settings name the user's hardware host"
        );
    }
}
