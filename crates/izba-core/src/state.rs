use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "config.json";
pub const STATE_FILE: &str = "state.json";
pub const PORTS_FILE: &str = "ports.json";

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
    /// User-declared volumes (extra block devices). Defaults to empty so
    /// configs written before this feature still deserialize.
    #[serde(default)]
    pub volumes: Vec<crate::volume::VolumeSpec>,
    /// When true, a read-write `izba-buildout` virtiofs share is mounted at
    /// guest `/out` for builder VMs. Defaults to false so configs written
    /// before this field was added still deserialize correctly (back-compat).
    #[serde(default)]
    pub builder: bool,
    /// Build recipe this sandbox's image was produced from, when it came from a
    /// `build:` manifest (vs a plain image ref). `serde(default)` keeps configs
    /// written before this field deserializing (disk-state back-compat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<crate::manifest::schema::BuildSpec>,
    /// Scratch rw disk size requested at create time, in whole GiB.  Persisted
    /// here so `izba export` can emit a valid `rootDisk.size` without reading
    /// the physical `rw.img` file length (which truncates to 0 for sub-GiB
    /// images).  `serde(default)` keeps old `config.json` files (without this
    /// field) deserializing — 0 means "unknown; fall back to file-length
    /// recovery for backwards compatibility".
    #[serde(default)]
    pub rw_size_gb: u64,
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
    /// `(role, identity)` — roles like `"virtiofsd:workspace"`.
    pub sidecar_pids: Vec<(String, PidIdentity)>,
    pub started_unix_ms: u64,
    /// Host-side confinement achieved for the VMM at launch. `Option` +
    /// `serde(default)` so a `state.json` written before this field still
    /// deserializes (it then reads as `None` ⇒ "unknown" in status).
    #[serde(default)]
    pub confinement: Option<crate::procmgr::ConfinementStatus>,
    /// The runtime (socket) dir this run's VMM was launched with. `Option` +
    /// `serde(default)` so a `state.json` written before this field still
    /// deserializes — `None` ⇒ the pre-hash legacy `<sandbox>/run` layout,
    /// which is exactly where such a run's sockets live. Live-management
    /// paths (egress rebind/stop, connectors, relays) resolve through
    /// [`crate::sandbox::live_run_dir`], never `Paths::run_dir` directly.
    #[serde(default)]
    pub run_dir: Option<std::path::PathBuf>,
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
            volumes: Vec::new(),
            builder: false,
            build: None,
            rw_size_gb: 8,
        }
    }

    #[test]
    fn config_without_volumes_defaults_empty() {
        let json = r#"{"image_digest":"sha256:x","image_ref":"img",
            "cpus":2,"mem_mb":1024,"workspace":"/w"}"#;
        let c: SandboxConfig = serde_json::from_str(json).unwrap();
        assert!(c.volumes.is_empty());
        assert!(c.ports.is_empty());
    }

    #[test]
    fn config_roundtrips_volumes() {
        let mut c = sample_config();
        c.volumes = vec![crate::volume::VolumeSpec {
            name: Some("cache".into()),
            guest_path: "/data".into(),
            size_bytes: 1 << 30,
            eph_id: None,
        }];
        let s = serde_json::to_string(&c).unwrap();
        let back: SandboxConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.volumes, c.volumes);
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
                    "virtiofsd:cache".to_string(),
                    PidIdentity {
                        pid: 5679,
                        starttime: 22222,
                    },
                ),
            ],
            started_unix_ms: 1_700_000_000_000,
            confinement: None,
            run_dir: None,
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
    fn run_state_without_confinement_defaults_none() {
        // A state.json written before the confinement field must still load
        // (the field is Option + serde(default) ⇒ None ⇒ "unknown" in status).
        let legacy = r#"{
            "vmm_pid": {"pid": 1, "starttime": 2},
            "sidecar_pids": [],
            "started_unix_ms": 0
        }"#;
        let s: RunState = serde_json::from_str(legacy).unwrap();
        assert!(s.confinement.is_none());
    }

    #[test]
    fn run_state_roundtrips_confinement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STATE_FILE);
        let mut s = sample_run_state();
        s.confinement = Some(crate::procmgr::ConfinementStatus::applied(
            &crate::procmgr::ConfinementPolicy::vmm_default(),
        ));
        save_json(&path, &s).unwrap();
        let loaded: RunState = load_json(&path).unwrap().unwrap();
        assert_eq!(loaded.confinement, s.confinement);
    }

    #[test]
    fn run_state_without_run_dir_deserializes_to_none() {
        // A state.json written before the field existed (disk back-compat).
        let json = r#"{
            "vmm_pid": {"pid": 1, "starttime": 2},
            "sidecar_pids": [],
            "started_unix_ms": 3
        }"#;
        let s: RunState = serde_json::from_str(json).unwrap();
        assert_eq!(s.run_dir, None);
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
    fn old_config_with_egress_key_still_deserializes() {
        // M1 phase-C removed the `egress` field; pre-cutover config.json
        // files carry one. SandboxConfig has no deny_unknown_fields, so serde
        // ignores it.
        let old = r#"{"image_digest":"sha256:a","image_ref":"r","cpus":1,
            "mem_mb":256,"workspace":"/w","ports":[],"egress":"passt"}"#;
        let c: SandboxConfig = serde_json::from_str(old).unwrap();
        assert_eq!(c.cpus, 1);
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
    fn sandbox_config_build_defaults_none_when_absent() {
        // A config.json written before the `build` field was added must still
        // load correctly; `serde(default)` makes it deserialize as `None`.
        let legacy = r#"{
            "image_digest": "sha256:abc",
            "image_ref": "ubuntu:24.04",
            "cpus": 2,
            "mem_mb": 512,
            "workspace": "/workspace"
        }"#;
        let cfg: SandboxConfig = serde_json::from_str(legacy).unwrap();
        assert!(
            cfg.build.is_none(),
            "missing build field must default to None"
        );
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

    /// Back-compat: a config.json written before `rw_size_gb` was added must
    /// still deserialize — the missing field must default to 0 ("unknown").
    #[test]
    fn sandbox_config_rw_size_gb_defaults_zero_when_absent() {
        let legacy = r#"{
            "image_digest": "sha256:abc",
            "image_ref": "ubuntu:24.04",
            "cpus": 2,
            "mem_mb": 512,
            "workspace": "/workspace"
        }"#;
        let cfg: SandboxConfig = serde_json::from_str(legacy).unwrap();
        assert_eq!(
            cfg.rw_size_gb, 0,
            "missing rw_size_gb must default to 0 (unknown)"
        );
    }

    /// New configs with `rw_size_gb` set must round-trip faithfully.
    #[test]
    fn sandbox_config_rw_size_gb_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE);
        let mut cfg = sample_config();
        cfg.rw_size_gb = 16;
        save_json(&path, &cfg).unwrap();
        let loaded: SandboxConfig = load_json(&path).unwrap().unwrap();
        assert_eq!(
            loaded.rw_size_gb, 16,
            "rw_size_gb must round-trip via save/load"
        );
    }
}
