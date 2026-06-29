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

/// Write ONLY `policy.yaml` (the egress allow-list) into the sandbox dir.
///
/// Split out so `promote` can land the durable policy BEFORE the live
/// `ReloadPolicy` RPC (which re-reads policy.yaml from disk), while deferring
/// the config.json commit until after all live effects succeed. `write_managed`
/// reuses this so config.json + policy.yaml stay consistent.
pub fn write_policy(
    dir: &std::path::Path,
    egress: &crate::daemon::egress::config::EgressPolicyConfig,
) -> Result<()> {
    std::fs::write(
        crate::daemon::egress::config::EgressPolicyConfig::path_in(dir),
        egress.to_yaml(),
    )
    .with_context(|| format!("writing policy.yaml in {}", dir.display()))
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
    match &target.image {
        crate::manifest::normalize::ImageSource::Ref(r) => {
            cfg.image_ref = r.clone();
            cfg.build = None;
        }
        crate::manifest::normalize::ImageSource::Build(b) => {
            cfg.build = Some(b.clone());
            // Store the tag as image_ref for display/legacy purposes;
            // from_managed uses cfg.build for authoritative reconstruction.
            if let Some(tag) = &b.tag {
                cfg.image_ref = tag.clone();
            }
        }
    }
    cfg.ports = target.ports.clone();
    let mut volumes = target.volumes.clone();
    crate::volume::assign_eph_ids(&mut volumes);
    cfg.volumes = volumes;
    save_json(&dir.join(CONFIG_FILE), &cfg)?;
    write_policy(&dir, &target.egress)?;
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

    /// An image change must also be recorded as a restart-class field, since the
    /// VM must restart to boot the new base (exercises the `== Image` arm in the
    /// restart_fields classification loop).
    #[test]
    fn plan_records_image_as_a_restart_field() {
        let mut to = n(2);
        to.image = ImageSource::Ref("ubuntu:22.04".into());
        let p = plan(&n(2), &to);
        assert!(
            p.restart_fields.iter().any(|f| f == "image"),
            "image change must appear in restart_fields; got {:?}",
            p.restart_fields
        );
    }

    /// A volume present in `current` but absent from `target` must be reported in
    /// `volumes_removed` (exercises the `!target.volumes.contains` filter).
    #[test]
    fn plan_reports_removed_volume() {
        let vol = VolumeSpec {
            name: Some("d".into()),
            guest_path: "/d".into(),
            size_bytes: 1 << 30,
            eph_id: None,
        };
        let mut from = n(2);
        from.volumes = vec![vol.clone()];
        let to = n(2); // no volumes
        let p = plan(&from, &to);
        assert_eq!(
            p.volumes_removed,
            vec![std::path::PathBuf::from("/d")],
            "a volume dropped from target must be in volumes_removed"
        );
        assert!(
            p.volumes_added.is_empty(),
            "nothing should be added in a pure-removal plan"
        );
    }

    #[test]
    fn write_policy_writes_round_trippable_policy() {
        let dir = tempfile::tempdir().unwrap();
        let egress = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("github.com".into())],
            git: vec![],
        };

        write_policy(dir.path(), &egress).unwrap();

        let back = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert!(back.enforce);
        assert!(back.allow.iter().any(|e| e.host() == "github.com"));
    }

    #[test]
    fn write_managed_persists_config_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("x")).unwrap();
        // Seed an existing config (write_managed preserves workspace + builder + rw_size_gb).
        let seed = SandboxConfig {
            image_digest: "sha256:old".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 8,
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

    #[test]
    fn write_managed_with_build_target_persists_build_provenance() {
        use crate::manifest::normalize::ImageSource;
        use crate::manifest::schema::BuildSpec;
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("y")).unwrap();
        let seed = SandboxConfig {
            image_digest: "sha256:old".into(),
            image_ref: "myapp:latest".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        crate::state::save_json(&paths.sandbox_dir("y").join(CONFIG_FILE), &seed).unwrap();

        let build_spec = BuildSpec {
            context: Some(".".into()),
            dockerfile: Some("Dockerfile".into()),
            tag: Some("myapp:latest".into()),
            allow: vec![],
            resources: None,
        };
        let mut target = n(2);
        target.image = ImageSource::Build(build_spec.clone());
        write_managed(&paths, "y", &target, "sha256:built").unwrap();

        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("y").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert!(
            cfg.build.is_some(),
            "build provenance must be persisted in config.json"
        );
        assert_eq!(cfg.build.unwrap(), build_spec);
    }

    #[test]
    fn build_manifest_diff_is_empty_after_promote_round_trip() {
        // Regression test: after promote writes config.json for a build-spec
        // sandbox, from_managed must reconstruct Build so diff(managed, repo)
        // is empty (no perpetual drift).
        use crate::manifest::diff;
        use crate::manifest::normalize::{ImageSource, Normalized};
        use crate::manifest::schema::BuildSpec;
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("z")).unwrap();
        let seed = SandboxConfig {
            image_digest: "sha256:old".into(),
            image_ref: "myapp:latest".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        crate::state::save_json(&paths.sandbox_dir("z").join(CONFIG_FILE), &seed).unwrap();

        let build_spec = BuildSpec {
            context: Some(".".into()),
            dockerfile: Some("Dockerfile".into()),
            tag: Some("myapp:latest".into()),
            allow: vec![],
            resources: None,
        };
        let mut repo = n(2);
        repo.name = "z".into();
        repo.image = ImageSource::Build(build_spec.clone());
        // Simulate promote: write managed with the build target.
        write_managed(&paths, "z", &repo, "sha256:built").unwrap();

        // Simulate diff: load managed and compare to repo.
        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("z").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        let egress = EgressPolicyConfig::load(&paths.sandbox_dir("z"))
            .unwrap()
            .unwrap_or_default();
        let managed = Normalized::from_managed("z", &cfg, &egress);
        let deltas = diff::diff(&managed, &repo);
        assert!(
            deltas.is_empty(),
            "no drift expected after promote round-trip, got: {deltas:?}"
        );
    }

    /// write_managed must NOT clobber rw_size_gb: it's immutable post-create.
    #[test]
    fn write_managed_preserves_rw_size_gb() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::Paths::with_root(dir.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("rw")).unwrap();
        let seed = SandboxConfig {
            image_digest: "sha256:old".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 12, // persisted at create time
        };
        crate::state::save_json(&paths.sandbox_dir("rw").join(CONFIG_FILE), &seed).unwrap();

        // write_managed updates cpus but must not touch rw_size_gb.
        write_managed(&paths, "rw", &n(8), "sha256:new").unwrap();

        let cfg: SandboxConfig = load_json(&paths.sandbox_dir("rw").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg.rw_size_gb, 12,
            "write_managed must preserve the existing rw_size_gb (immutable post-create)"
        );
    }
}
