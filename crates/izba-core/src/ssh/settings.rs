use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSettings {
    #[serde(default = "default_true")]
    pub config_management: bool,
}

fn default_true() -> bool {
    true
}

impl Default for SshSettings {
    fn default() -> Self {
        Self {
            config_management: true,
        }
    }
}

const FILE: &str = "settings.json";

pub fn load(ssh_dir: &Path) -> SshSettings {
    match std::fs::read(ssh_dir.join(FILE)) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
        Err(_) => SshSettings::default(),
    }
}

pub fn save(ssh_dir: &Path, s: &SshSettings) -> anyhow::Result<()> {
    std::fs::create_dir_all(ssh_dir)?;
    crate::state::save_json(&ssh_dir.join(FILE), s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_on_and_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(tmp.path()).config_management, "default must be on");
        save(
            tmp.path(),
            &SshSettings {
                config_management: false,
            },
        )
        .unwrap();
        assert!(!load(tmp.path()).config_management);
    }

    #[test]
    fn corrupt_settings_falls_back_to_default() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("settings.json"), b"{ not json").unwrap();
        assert!(load(tmp.path()).config_management);
    }
}
