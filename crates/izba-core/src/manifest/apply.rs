//! Turn a target `Normalized` into (a) a delta plan the CLI enacts live via the
//! daemon and (b) the durable managed files (config.json + policy.yaml).

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::manifest::diff;
use crate::manifest::normalize::Normalized;
use crate::paths::Paths;
use crate::state::{load_json, save_json, PortRule, SandboxConfig, CONFIG_FILE};
use crate::volume::VolumeSpec;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyPlan {
    pub policy_changed: bool,
    pub ports_added: Vec<PortRule>,
    pub ports_removed: Vec<PortRule>,
    pub volumes_added: Vec<VolumeSpec>,
    pub volumes_removed: Vec<PathBuf>,
    pub restart_fields: Vec<String>,
    pub image_changed: bool,
}

/// Compute the live/restart deltas turning `current` into `target`.
pub fn plan(current: &Normalized, target: &Normalized) -> ApplyPlan {
    let mut p = ApplyPlan {
        policy_changed: current.egress != target.egress,
        image_changed: current.image != target.image,
        ..Default::default()
    };
    p.ports_added = target
        .ports
        .iter()
        .filter(|r| !current.ports.contains(r))
        .cloned()
        .collect();
    p.ports_removed = current
        .ports
        .iter()
        .filter(|r| !target.ports.contains(r))
        .cloned()
        .collect();
    p.volumes_added = target
        .volumes
        .iter()
        .filter(|v| !current.volumes.contains(v))
        .cloned()
        .collect();
    p.volumes_removed = current
        .volumes
        .iter()
        .filter(|v| !target.volumes.contains(v))
        .map(|v| v.guest_path.clone())
        .collect();
    for d in diff::diff(current, target) {
        if d.class == diff::FieldClass::Restart || d.class == diff::FieldClass::Image {
            p.restart_fields.push(d.field);
        }
    }
    p
}

/// Write the managed truth: config.json (cpus/mem/image/ports/volumes from
/// `target`, with `image_digest` resolved by the caller) and policy.yaml from
/// `target.egress`. Preserves `workspace` and `builder` from the existing config.
pub fn write_managed(
    paths: &Paths,
    name: &str,
    target: &Normalized,
    image_digest: &str,
) -> Result<()> {
    let dir = paths.sandbox_dir(name);
    let mut cfg: SandboxConfig = load_json(&dir.join(CONFIG_FILE))?
        .with_context(|| format!("no config.json for sandbox {name:?}"))?;
    cfg.cpus = target.cpus;
    cfg.mem_mb = target.mem_mb;
    cfg.image_digest = image_digest.to_string();
    if let crate::manifest::normalize::ImageSource::Ref(r) = &target.image {
        cfg.image_ref = r.clone();
    }
    cfg.ports = target.ports.clone();
    let mut volumes = target.volumes.clone();
    crate::volume::assign_eph_ids(&mut volumes);
    cfg.volumes = volumes;
    save_json(&dir.join(CONFIG_FILE), &cfg)?;
    std::fs::write(
        crate::daemon::egress::config::EgressPolicyConfig::path_in(&dir),
        target.egress.to_yaml(),
    )
    .with_context(|| format!("writing policy.yaml for {name:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::{AllowEntry, EgressPolicyConfig};
    use crate::manifest::normalize::{ImageSource, Normalized};
    use crate::state::{load_json, PortRule, SandboxConfig, CONFIG_FILE};
    use crate::volume::VolumeSpec;

    fn n(cpus: u32) -> Normalized {
        Normalized {
            name: "x".into(),
            image: ImageSource::Ref("ubuntu:24.04".into()),
            cpus,
            mem_mb: 4096,
            rw_size_gb: 8,
            volumes: vec![],
            ports: vec![],
            egress: EgressPolicyConfig::default(),
        }
    }

    #[test]
    fn plan_marks_restart_for_cpu_change() {
        let p = plan(&n(2), &n(4));
        assert_eq!(p.restart_fields, vec!["cpus".to_string()]);
        assert!(!p.policy_changed);
        assert!(!p.image_changed);
    }

    #[test]
    fn plan_computes_port_and_volume_deltas() {
        let mut from = n(2);
        from.ports = vec![PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 1,
            guest_port: 1,
        }];
        let mut to = n(2);
        to.ports = vec![PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 2,
            guest_port: 2,
        }];
        to.volumes = vec![VolumeSpec {
            name: Some("d".into()),
            guest_path: "/d".into(),
            size_bytes: 1 << 30,
            eph_id: None,
        }];
        let p = plan(&from, &to);
        assert_eq!(p.ports_added.len(), 1);
        assert_eq!(p.ports_removed.len(), 1);
        assert_eq!(p.volumes_added.len(), 1);
        assert!(p.volumes_removed.is_empty());
    }

    #[test]
    fn plan_marks_policy_changed_and_image_changed() {
        let mut to = n(2);
        to.egress.allow = vec![AllowEntry::Host("h".into())];
        to.image = ImageSource::Ref("ubuntu:22.04".into());
        let p = plan(&n(2), &to);
        assert!(p.policy_changed);
        assert!(p.image_changed);
    }

    #[test]
    fn write_managed_persists_config_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("x")).unwrap();
        // Seed an existing config (write_managed preserves workspace + builder).
        let seed = SandboxConfig {
            image_digest: "sha256:old".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
        };
        crate::state::save_json(&paths.sandbox_dir("x").join(CONFIG_FILE), &seed).unwrap();

        let mut target = n(8);
        target.egress.allow = vec![AllowEntry::Host("github.com".into())];
        write_managed(&paths, "x", &target, "sha256:new").unwrap();

        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("x").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.cpus, 8);
        assert_eq!(cfg.image_digest, "sha256:new");
        assert_eq!(
            cfg.workspace.to_str().unwrap(),
            "/ws",
            "workspace preserved"
        );
        let eg = EgressPolicyConfig::load(&paths.sandbox_dir("x"))
            .unwrap()
            .unwrap();
        assert!(eg.allow.iter().any(|e| e.host() == "github.com"));
    }
}
