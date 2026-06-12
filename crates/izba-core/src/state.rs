use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "config.json";
pub const STATE_FILE: &str = "state.json";
pub const PORTS_FILE: &str = "ports.json";

/// Which path carries guest egress. M1 transition knob: `Passt` is the v1
/// NAT (passt on CH / consomme on OpenVMM); `Izbad` is the vsock-1027
/// stub. Removed at the M1 phase-C cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    #[default]
    Passt,
    Izbad,
}

/// Identity that defeats PID reuse: `starttime` is a platform-specific
/// equality token captured at spawn (Linux: field 22 of `/proc/<pid>/stat`;
/// Windows: the process creation `FILETIME`) — see [`crate::procmgr`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidIdentity {
    pub pid: u32,
    pub starttime: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub image_digest: String,
    pub image_ref: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub workspace: PathBuf,
    /// Persisted port-publish rules, re-applied on every `run`. Defaults to
    /// empty so configs written before this feature still deserialize.
    #[serde(default)]
    pub ports: Vec<PortRule>,
    /// Egress datapath; default keeps pre-M1 configs deserializing.
    #[serde(default)]
    pub egress: EgressMode,
}

/// A single host→guest TCP publish rule. Its identity (uniqueness key) is
/// `(bind, host_port)`. `bind` serializes as a string, e.g. `"127.0.0.1"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRule {
    pub bind: Ipv4Addr,
    pub host_port: u16,
    pub guest_port: u16,
}

/// One active relay: the rule it serves plus the detached relay process's
/// PID-reuse-safe identity. Persisted in `ports.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRecord {
    pub rule: PortRule,
    pub relay: PidIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunState {
    pub vmm_pid: PidIdentity,
    /// `(role, identity)` — roles like `"virtiofsd:workspace"`, `"passt"`.
    pub sidecar_pids: Vec<(String, PidIdentity)>,
    pub started_unix_ms: u64,
}

/// Crash-safe write: serialise to a sibling `.tmp` file in the same directory,
/// then atomically rename to `path`.
pub fn save_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let parent = path.parent().context("path has no parent directory")?;
    let tmp_path = parent.join(format!(
        "{}.tmp",
        path.file_name()
            .context("path has no file name")?
            .to_string_lossy()
    ));

    let data = serde_json::to_string_pretty(value).context("serialise to JSON")?;
    std::fs::write(&tmp_path, &data).with_context(|| format!("write tmp {tmp_path:?}"))?;
    std::fs::rename(&tmp_path, path).with_context(|| format!("rename {tmp_path:?} -> {path:?}"))?;
    Ok(())
}

/// Returns `Ok(None)` when the file does not exist.
pub fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(data) => {
            let value = serde_json::from_str(&data)
                .with_context(|| format!("deserialise JSON from {path:?}"))?;
            Ok(Some(value))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {path:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> SandboxConfig {
        SandboxConfig {
            image_digest: "sha256:deadbeef".to_string(),
            image_ref: "ubuntu:22.04".to_string(),
            cpus: 2,
            mem_mb: 512,
            workspace: PathBuf::from("/workspace"),
            ports: Vec::new(),
            egress: EgressMode::Passt,
        }
    }

    fn sample_run_state() -> RunState {
        RunState {
            vmm_pid: PidIdentity {
                pid: 1234,
                starttime: 9999,
            },
            sidecar_pids: vec![
                (
                    "virtiofsd:workspace".to_string(),
                    PidIdentity {
                        pid: 5678,
                        starttime: 11111,
                    },
                ),
                (
                    "passt".to_string(),
                    PidIdentity {
                        pid: 5679,
                        starttime: 22222,
                    },
                ),
            ],
            started_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn roundtrip_sandbox_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);

        let original = sample_config();
        save_json(&path, &original).unwrap();

        let loaded: SandboxConfig = load_json(&path).unwrap().expect("file must exist");
        assert_eq!(loaded.image_digest, original.image_digest);
        assert_eq!(loaded.image_ref, original.image_ref);
        assert_eq!(loaded.cpus, original.cpus);
        assert_eq!(loaded.mem_mb, original.mem_mb);
        assert_eq!(loaded.workspace, original.workspace);
    }

    #[test]
    fn roundtrip_run_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE);

        let original = sample_run_state();
        save_json(&path, &original).unwrap();

        let loaded: RunState = load_json(&path).unwrap().expect("file must exist");
        assert_eq!(loaded.vmm_pid, original.vmm_pid);
        assert_eq!(loaded.sidecar_pids, original.sidecar_pids);
        assert_eq!(loaded.started_unix_ms, original.started_unix_ms);
    }

    #[test]
    fn load_json_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        let result: anyhow::Result<Option<SandboxConfig>> = load_json(&path);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn port_rule_serde_is_string_addr() {
        let rule = PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 8080,
            guest_port: 80,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(
            json.contains("\"127.0.0.1\""),
            "bind must serialize as a string: {json}"
        );
        let back: PortRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rule);
    }

    #[test]
    fn sandbox_config_ports_defaults_when_absent() {
        // A config.json written before this feature has no "ports" key.
        let legacy = r#"{
            "image_digest": "sha256:abc",
            "image_ref": "ubuntu:22.04",
            "cpus": 2,
            "mem_mb": 512,
            "workspace": "/workspace"
        }"#;
        let cfg: SandboxConfig = serde_json::from_str(legacy).unwrap();
        assert!(cfg.ports.is_empty(), "missing ports must default to empty");
    }

    #[test]
    fn egress_mode_defaults_to_passt_for_old_configs() {
        // A pre-M1 config.json has no "egress" key.
        let old = r#"{"image_digest":"sha256:a","image_ref":"r","cpus":1,
            "mem_mb":256,"workspace":"/w","ports":[]}"#;
        let c: SandboxConfig = serde_json::from_str(old).unwrap();
        assert_eq!(c.egress, EgressMode::Passt);
    }

    #[test]
    fn egress_mode_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&EgressMode::Izbad).unwrap(),
            r#""izbad""#
        );
        assert_eq!(
            serde_json::to_string(&EgressMode::Passt).unwrap(),
            r#""passt""#
        );
    }

    #[test]
    fn sandbox_config_ports_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);
        let mut cfg = sample_config();
        cfg.ports = vec![PortRule {
            bind: "0.0.0.0".parse().unwrap(),
            host_port: 18080,
            guest_port: 8000,
        }];
        save_json(&path, &cfg).unwrap();
        let loaded: SandboxConfig = load_json(&path).unwrap().unwrap();
        assert_eq!(loaded.ports, cfg.ports);
    }

    #[test]
    fn port_record_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PORTS_FILE);
        let records = vec![PortRecord {
            rule: PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 8080,
                guest_port: 80,
            },
            relay: PidIdentity {
                pid: 4321,
                starttime: 777,
            },
        }];
        save_json(&path, &records).unwrap();
        let loaded: Vec<PortRecord> = load_json(&path).unwrap().unwrap();
        assert_eq!(loaded, records);
    }

    #[test]
    fn save_json_no_tmp_debris() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);

        save_json(&path, &sample_config()).unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "expected exactly one file, found: {entries:?}"
        );
        assert_eq!(entries[0], CONFIG_FILE);
    }
}
