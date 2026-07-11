//! The `izba.yml` document model. k8s-style: `apiVersion`/`kind`/`metadata`/
//! `spec`. The `egress` block reuses `EgressPolicyConfig` verbatim — it is
//! structurally identical to `policy.yaml`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::daemon::egress::config::EgressPolicyConfig;

pub const API_VERSION: &str = "izba.dev/v1alpha1";
pub const KIND_SANDBOX: &str = "Sandbox";

/// Product-wide sandbox resource defaults — the single source of truth shared
/// by the manifest schema defaults (below) and the CLI's clap defaults
/// (`izba-cli commands::DEFAULT_*`). A manifest that omits `resources`/
/// `rootDisk` boots identically to a bare `izba run` (#122).
pub const DEFAULT_CPUS: u32 = 2;
pub const DEFAULT_MEM_MB: u32 = 4096;
pub const DEFAULT_MEMORY: &str = "4Gi";
pub const DEFAULT_RW_GB: u64 = 8;
pub const DEFAULT_ROOT_DISK_SIZE: &str = "8Gi";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: Metadata,
    pub spec: SandboxSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildSpec>,
    #[serde(default)]
    pub resources: Resources,
    #[serde(default, rename = "rootDisk")]
    pub root_disk: RootDisk,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeMount>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMapping>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressPolicyConfig>,
}

fn default_cpus() -> u32 {
    DEFAULT_CPUS
}
fn default_memory() -> String {
    DEFAULT_MEMORY.to_string()
}
fn default_root_disk_size() -> String {
    DEFAULT_ROOT_DISK_SIZE.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default = "default_memory")]
    pub memory: String,
}

impl Default for Resources {
    fn default() -> Self {
        Resources {
            cpus: default_cpus(),
            memory: default_memory(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootDisk {
    #[serde(default = "default_root_disk_size")]
    pub size: String,
}

impl Default for RootDisk {
    fn default() -> Self {
        RootDisk {
            size: default_root_disk_size(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeMount {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "mountPath")]
    pub mount_path: PathBuf,
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortMapping {
    pub guest: u16,
    pub host: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,
}

impl Manifest {
    /// Parse + validate a manifest document. Dispatches on apiVersion/kind and
    /// enforces the `image` xor `build` rule.
    pub fn load_str(s: &str) -> Result<Manifest> {
        let m: Manifest = serde_yaml::from_str(s).context("parsing izba.yml")?;
        if m.api_version != API_VERSION {
            bail!(
                "unsupported apiVersion {:?} (this izba understands {:?}); \
                 a newer izba may be needed",
                m.api_version,
                API_VERSION
            );
        }
        if m.kind != KIND_SANDBOX {
            bail!(
                "unsupported kind {:?} (this izba understands {:?})",
                m.kind,
                KIND_SANDBOX
            );
        }
        match (&m.spec.image, &m.spec.build) {
            (Some(_), Some(_)) => bail!("spec.image and spec.build are mutually exclusive"),
            (None, None) => bail!("spec must set exactly one of image or build"),
            _ => {}
        }
        Ok(m)
    }

    /// Serialize to canonical YAML.
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("Manifest serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
apiVersion: izba.dev/v1alpha1
kind: Sandbox
metadata:
  name: myapp
  labels:
    project: acme
spec:
  image: ubuntu:24.04
  resources:
    cpus: 2
    memory: 4Gi
  rootDisk:
    size: 8Gi
  volumes:
    - name: data
      mountPath: /data
      size: 8Gi
  ports:
    - guest: 80
      host: 8080
      bind: 127.0.0.1
  egress:
    enforce: true
    allow:
      - github.com
"#;

    #[test]
    fn parses_full_sample() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        assert_eq!(m.api_version, API_VERSION);
        assert_eq!(m.kind, KIND_SANDBOX);
        assert_eq!(m.metadata.name.as_deref(), Some("myapp"));
        assert_eq!(m.metadata.labels.get("project").unwrap(), "acme");
        assert_eq!(m.spec.image.as_deref(), Some("ubuntu:24.04"));
        assert_eq!(m.spec.resources.cpus, 2);
        assert_eq!(m.spec.resources.memory, "4Gi");
        assert_eq!(m.spec.root_disk.size, "8Gi");
        assert_eq!(m.spec.volumes[0].mount_path.to_str().unwrap(), "/data");
        assert_eq!(m.spec.ports[0].guest, 80);
        assert_eq!(m.spec.ports[0].bind.as_deref(), Some("127.0.0.1"));
        let eg = m.spec.egress.as_ref().unwrap();
        assert!(eg.enforce);
        assert_eq!(eg.allow.len(), 1);
    }

    #[test]
    fn rejects_unknown_api_version() {
        let y = SAMPLE.replace("izba.dev/v1alpha1", "izba.dev/v2");
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("apiVersion"), "got: {err}");
        assert!(err.contains("newer izba"), "must hint upgrade: {err}");
    }

    #[test]
    fn rejects_unknown_kind() {
        let y = SAMPLE.replace("kind: Sandbox", "kind: Project");
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("kind"), "got: {err}");
    }

    #[test]
    fn rejects_both_image_and_build() {
        let y = SAMPLE.replace(
            "  image: ubuntu:24.04\n",
            "  image: ubuntu:24.04\n  build:\n    context: .\n",
        );
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("image") && err.contains("build"), "got: {err}");
    }

    #[test]
    fn rejects_neither_image_nor_build() {
        let y = SAMPLE.replace("  image: ubuntu:24.04\n", "");
        let err = Manifest::load_str(&y).unwrap_err().to_string();
        assert!(err.contains("image") || err.contains("build"), "got: {err}");
    }

    #[test]
    fn rejects_unknown_field() {
        // deny_unknown_fields catches typos like `cpu:` for `cpus:`.
        let y = SAMPLE.replace("    cpus: 2\n", "    cpus: 2\n    cpu: 9\n");
        assert!(Manifest::load_str(&y).is_err());
    }

    #[test]
    fn build_block_parses() {
        let y = SAMPLE.replace(
            "  image: ubuntu:24.04\n",
            "  build:\n    context: .\n    dockerfile: Dockerfile\n    allow:\n      - get.example.com\n",
        );
        let m = Manifest::load_str(&y).unwrap();
        let b = m.spec.build.as_ref().unwrap();
        assert_eq!(b.context.as_deref(), Some("."));
        assert_eq!(b.dockerfile.as_deref(), Some("Dockerfile"));
        assert_eq!(b.allow, vec!["get.example.com".to_string()]);
        assert!(m.spec.image.is_none());
    }

    #[test]
    fn to_yaml_round_trips() {
        let m = Manifest::load_str(SAMPLE).unwrap();
        let back = Manifest::load_str(&m.to_yaml()).unwrap();
        assert_eq!(back.spec.resources.memory, "4Gi");
        assert_eq!(back.metadata.name, m.metadata.name);
    }

    /// #122: a minimal manifest (image only) must parse, inheriting the same
    /// defaults a bare `izba run` uses — 2 cpus / 4Gi memory / 8Gi rootDisk.
    #[test]
    fn minimal_manifest_defaults_resources_and_root_disk() {
        let y = "apiVersion: izba.dev/v1alpha1\nkind: Sandbox\nspec:\n  image: ubuntu:24.04\n";
        let m = Manifest::load_str(y).expect("image-only manifest must be valid");
        assert_eq!(m.spec.resources.cpus, DEFAULT_CPUS);
        assert_eq!(m.spec.resources.memory, DEFAULT_MEMORY);
        assert_eq!(m.spec.root_disk.size, DEFAULT_ROOT_DISK_SIZE);
    }

    /// Greptile P1: a PARTIAL resources/rootDisk block inherits per-field
    /// defaults — overriding one field must not force spelling out the rest.
    #[test]
    fn partial_resources_and_root_disk_inherit_field_defaults() {
        let y = concat!(
            "apiVersion: izba.dev/v1alpha1\n",
            "kind: Sandbox\n",
            "spec:\n",
            "  image: ubuntu:24.04\n",
            "  resources:\n",
            "    cpus: 4\n",
            "  rootDisk: {}\n",
        );
        let m = Manifest::load_str(y).expect("partial blocks must parse");
        assert_eq!(m.spec.resources.cpus, 4, "explicit override wins");
        assert_eq!(m.spec.resources.memory, DEFAULT_MEMORY, "memory inherited");
        assert_eq!(m.spec.root_disk.size, DEFAULT_ROOT_DISK_SIZE, "size inherited");
    }

    /// The string defaults and the numeric defaults must agree — the numeric
    /// pair is what the CLI's clap defaults reuse (single source of truth).
    #[test]
    fn default_strings_match_numeric_defaults() {
        use crate::manifest::quantity;
        assert_eq!(quantity::parse_mib(DEFAULT_MEMORY).unwrap(), DEFAULT_MEM_MB);
        assert_eq!(
            quantity::parse_gib(DEFAULT_ROOT_DISK_SIZE).unwrap(),
            DEFAULT_RW_GB
        );
    }
}
