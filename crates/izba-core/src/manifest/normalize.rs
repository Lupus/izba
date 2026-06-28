//! The canonical comparison form. Both an `izba.yml` and the managed truth
//! (config.json + policy.yaml) normalize to `Normalized`; the structural diff
//! then compares two `Normalized` values field-by-field, order-insensitively.

use std::net::Ipv4Addr;

use anyhow::{Context, Result};

use crate::daemon::egress::config::EgressPolicyConfig;
use crate::manifest::quantity;
use crate::manifest::schema::{
    self, BuildSpec, Manifest, Metadata, PortMapping, Resources, RootDisk, SandboxSpec, VolumeMount,
};
use crate::state::{PortRule, SandboxConfig};
use crate::volume::VolumeSpec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    Ref(String),
    Build(BuildSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    pub name: String,
    pub image: ImageSource,
    pub cpus: u32,
    pub mem_mb: u32,
    pub rw_size_gb: u64,
    pub volumes: Vec<VolumeSpec>,
    pub ports: Vec<PortRule>,
    pub egress: EgressPolicyConfig,
}

fn sort_canonical(
    volumes: &mut [VolumeSpec],
    ports: &mut [PortRule],
    egress: &mut EgressPolicyConfig,
) {
    volumes.sort_by(|a, b| a.guest_path.cmp(&b.guest_path));
    ports.sort_by_key(|p| (p.bind.to_string(), p.host_port, p.guest_port));
    egress.allow.sort_by(|a, b| a.host().cmp(b.host()));
    egress.git.sort_by_key(|g| format!("{:?}", g.target));
}

impl Normalized {
    pub fn from_manifest(m: &Manifest, default_name: &str) -> Result<Normalized> {
        let s = &m.spec;
        let image = match (&s.image, &s.build) {
            (Some(r), None) => ImageSource::Ref(r.clone()),
            (None, Some(b)) => ImageSource::Build(b.clone()),
            _ => anyhow::bail!("manifest must set exactly one of image or build"),
        };
        let mut volumes = Vec::with_capacity(s.volumes.len());
        for v in &s.volumes {
            volumes.push(VolumeSpec {
                name: v.name.clone(),
                guest_path: v.mount_path.clone(),
                size_bytes: quantity::parse_bytes(&v.size)
                    .with_context(|| format!("volume {:?} size", v.mount_path))?,
                eph_id: None,
            });
        }
        let mut ports = Vec::with_capacity(s.ports.len());
        for p in &s.ports {
            let bind: Ipv4Addr = match &p.bind {
                Some(b) => b.parse().with_context(|| format!("port bind {b:?}"))?,
                None => Ipv4Addr::LOCALHOST,
            };
            ports.push(PortRule {
                bind,
                host_port: p.host,
                guest_port: p.guest,
            });
        }
        let mut egress = s.egress.clone().unwrap_or_default();
        let mut n = Normalized {
            name: m
                .metadata
                .name
                .clone()
                .unwrap_or_else(|| default_name.to_string()),
            image,
            cpus: s.resources.cpus,
            mem_mb: quantity::parse_mib(&s.resources.memory).context("resources.memory")?,
            rw_size_gb: quantity::parse_gib(&s.root_disk.size).context("rootDisk.size")?,
            volumes,
            ports,
            egress: std::mem::take(&mut egress),
        };
        sort_canonical(&mut n.volumes, &mut n.ports, &mut n.egress);
        Ok(n)
    }

    pub fn from_managed(
        name: &str,
        cfg: &SandboxConfig,
        egress: &EgressPolicyConfig,
    ) -> Normalized {
        let mut volumes = cfg.volumes.clone();
        // eph_id is a backing-store detail, not config — drop it for comparison.
        for v in &mut volumes {
            v.eph_id = None;
        }
        let ports = cfg.ports.clone();
        let mut egress = egress.clone();
        let image = match &cfg.build {
            Some(b) => ImageSource::Build(b.clone()),
            None => ImageSource::Ref(cfg.image_ref.clone()),
        };
        let mut n = Normalized {
            name: name.to_string(),
            image,
            cpus: cfg.cpus,
            mem_mb: cfg.mem_mb,
            // SandboxConfig does not record rw scratch size post-create (it sizes
            // rw.img at create time only). Task 4's diff() ignores rw_size_gb to
            // avoid spurious "rootDisk changed" drift on every comparison.
            rw_size_gb: 0,
            volumes,
            ports,
            egress: std::mem::take(&mut egress),
        };
        sort_canonical(&mut n.volumes, &mut n.ports, &mut n.egress);
        n
    }

    pub fn to_manifest(&self) -> Manifest {
        let (image, build) = match &self.image {
            ImageSource::Ref(r) => (Some(r.clone()), None),
            ImageSource::Build(b) => (None, Some(b.clone())),
        };
        Manifest {
            api_version: schema::API_VERSION.to_string(),
            kind: schema::KIND_SANDBOX.to_string(),
            metadata: Metadata {
                name: Some(self.name.clone()),
                labels: Default::default(),
            },
            spec: SandboxSpec {
                image,
                build,
                resources: Resources {
                    cpus: self.cpus,
                    memory: quantity::format(u64::from(self.mem_mb) << 20),
                },
                root_disk: RootDisk {
                    size: quantity::format(self.rw_size_gb << 30),
                },
                volumes: self
                    .volumes
                    .iter()
                    .map(|v| VolumeMount {
                        name: v.name.clone(),
                        mount_path: v.guest_path.clone(),
                        size: quantity::format(v.size_bytes),
                    })
                    .collect(),
                ports: self
                    .ports
                    .iter()
                    .map(|p| PortMapping {
                        guest: p.guest_port,
                        host: p.host_port,
                        bind: Some(p.bind.to_string()),
                    })
                    .collect(),
                egress: Some(self.egress.clone()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::{AllowEntry, EgressPolicyConfig};
    use crate::manifest::schema::Manifest;

    const SAMPLE: &str = r#"
apiVersion: izba.dev/v1alpha1
kind: Sandbox
metadata: { name: myapp }
spec:
  image: ubuntu:24.04
  resources: { cpus: 2, memory: 4Gi }
  rootDisk: { size: 8Gi }
  volumes:
    - { name: data, mountPath: /data, size: 8Gi }
  ports:
    - { guest: 80, host: 8080, bind: 127.0.0.1 }
  egress:
    enforce: true
    allow: [github.com]
"#;

    #[test]
    fn from_manifest_maps_units_and_fields() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        let n = Normalized::from_manifest(&m, "fallback").unwrap();
        assert_eq!(n.name, "myapp");
        assert_eq!(n.cpus, 2);
        assert_eq!(n.mem_mb, 4096);
        assert_eq!(n.rw_size_gb, 8);
        assert_eq!(n.image, ImageSource::Ref("ubuntu:24.04".into()));
        assert_eq!(n.volumes[0].name.as_deref(), Some("data"));
        assert_eq!(n.volumes[0].size_bytes, 8u64 << 30);
        assert_eq!(n.ports[0].host_port, 8080);
        assert_eq!(n.ports[0].bind.to_string(), "127.0.0.1");
        assert!(n.egress.enforce);
    }

    #[test]
    fn from_manifest_uses_default_name_when_absent() {
        let y = SAMPLE.replace("metadata: { name: myapp }", "metadata: {}");
        let n = Normalized::from_manifest(&Manifest::load_str(&y).unwrap(), "fallback").unwrap();
        assert_eq!(n.name, "fallback");
    }

    #[test]
    fn port_default_bind_is_loopback() {
        let y = SAMPLE.replace(", bind: 127.0.0.1", "");
        let n = Normalized::from_manifest(&Manifest::load_str(&y).unwrap(), "f").unwrap();
        assert_eq!(n.ports[0].bind.to_string(), "127.0.0.1");
    }

    #[test]
    fn round_trips_manifest_to_normalized_to_manifest() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        let n = Normalized::from_manifest(&m, "f").unwrap();
        let m2 = n.to_manifest();
        let n2 = Normalized::from_manifest(&m2, "f").unwrap();
        assert_eq!(n, n2);
    }

    #[test]
    fn from_managed_renders_ref_image_and_egress() {
        let cfg = crate::state::SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 4,
            mem_mb: 2048,
            workspace: "/w".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        let eg = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Host("github.com".into())],
            git: vec![],
        };
        let n = Normalized::from_managed("myapp", &cfg, &eg);
        assert_eq!(n.name, "myapp");
        assert_eq!(n.cpus, 4);
        assert_eq!(n.mem_mb, 2048);
        assert_eq!(n.image, ImageSource::Ref("ubuntu:24.04".into()));
        assert!(n.egress.enforce);
    }

    #[test]
    fn from_managed_with_build_yields_build_image_source() {
        use crate::manifest::schema::BuildSpec;
        let build_spec = BuildSpec {
            context: Some(".".into()),
            dockerfile: Some("Dockerfile".into()),
            tag: Some("myapp:latest".into()),
            allow: vec![],
            resources: None,
        };
        let cfg = crate::state::SandboxConfig {
            image_digest: "sha256:built".into(),
            image_ref: "myapp:latest".into(),
            cpus: 2,
            mem_mb: 1024,
            workspace: "/w".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: Some(build_spec.clone()),
            rw_size_gb: 8,
        };
        let n = Normalized::from_managed("myapp", &cfg, &EgressPolicyConfig::default());
        assert_eq!(n.image, ImageSource::Build(build_spec));
    }

    #[test]
    fn from_managed_with_no_build_yields_ref_image_source() {
        let cfg = crate::state::SandboxConfig {
            image_digest: "sha256:abc".into(),
            image_ref: "ubuntu:24.04".into(),
            cpus: 2,
            mem_mb: 1024,
            workspace: "/w".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: None,
            rw_size_gb: 8,
        };
        let n = Normalized::from_managed("myapp", &cfg, &EgressPolicyConfig::default());
        assert_eq!(n.image, ImageSource::Ref("ubuntu:24.04".into()));
    }

    #[test]
    fn to_manifest_with_build_source_emits_build_block_not_image() {
        use crate::manifest::schema::BuildSpec;
        let build_spec = BuildSpec {
            context: Some(".".into()),
            dockerfile: Some("Dockerfile".into()),
            tag: Some("myapp:latest".into()),
            allow: vec![],
            resources: None,
        };
        let cfg = crate::state::SandboxConfig {
            image_digest: "sha256:built".into(),
            image_ref: "myapp:latest".into(),
            cpus: 2,
            mem_mb: 1024,
            workspace: "/w".into(),
            ports: vec![],
            volumes: vec![],
            builder: false,
            build: Some(build_spec.clone()),
            rw_size_gb: 8,
        };
        let n = Normalized::from_managed("myapp", &cfg, &EgressPolicyConfig::default());
        let m = n.to_manifest();
        assert!(m.spec.build.is_some(), "build block must be present");
        assert!(m.spec.image.is_none(), "image field must be absent");
        assert_eq!(m.spec.build.unwrap(), build_spec);
    }

    #[test]
    fn canonical_order_is_stable_regardless_of_input_order() {
        let y = SAMPLE.replace(
            "    - { name: data, mountPath: /data, size: 8Gi }\n",
            "    - { name: z, mountPath: /z, size: 1Gi }\n    - { name: a, mountPath: /a, size: 1Gi }\n",
        );
        let n = Normalized::from_manifest(&Manifest::load_str(&y).unwrap(), "f").unwrap();
        assert_eq!(n.volumes[0].guest_path.to_str().unwrap(), "/a");
        assert_eq!(n.volumes[1].guest_path.to_str().unwrap(), "/z");
    }
}
