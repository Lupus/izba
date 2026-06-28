//! Structural, order-insensitive diff between two `Normalized` configs, with a
//! field-class (Live/Restart/Image) and a `weakens_egress` flag per change, plus
//! the base/repo/managed 3-way state classifier.

use std::collections::BTreeMap;

use crate::daemon::egress::config::{Access, EgressPolicyConfig};
use crate::manifest::normalize::{ImageSource, Normalized};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    Live,
    Restart,
    Image,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDelta {
    pub field: String,
    pub from: String,
    pub to: String,
    pub class: FieldClass,
    pub weakens_egress: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftState {
    InSync,
    RepoAhead,
    ManagedAhead,
    Diverged,
}

fn image_str(i: &ImageSource) -> String {
    match i {
        ImageSource::Ref(r) => r.clone(),
        ImageSource::Build(b) => format!(
            "build({:?})",
            b.dockerfile.as_deref().unwrap_or("Dockerfile")
        ),
    }
}

/// Build a host -> (sorted ports, access) view of an allow-list for comparison.
fn allow_index(eg: &EgressPolicyConfig) -> BTreeMap<String, (Vec<u16>, Access)> {
    eg.allow
        .iter()
        .map(|e| {
            let mut ports = e.ports();
            ports.sort_unstable();
            (e.host().to_string(), (ports, e.access()))
        })
        .collect()
}

/// True if turning `from` egress into `to` egress LOOSENS the firewall:
/// disabling enforce, adding a host, adding ports to a host, widening access
/// (read -> read-write), or adding/loosening a git rule.
fn egress_weakens(from: &EgressPolicyConfig, to: &EgressPolicyConfig) -> bool {
    if from.enforce && !to.enforce {
        return true;
    }
    let (fi, ti) = (allow_index(from), allow_index(to));
    for (host, (to_ports, to_access)) in &ti {
        match fi.get(host) {
            None => return true, // new host allowed
            Some((from_ports, from_access)) => {
                if to_ports.iter().any(|p| !from_ports.contains(p)) {
                    return true; // new port on an existing host
                }
                if *from_access == Access::Read && *to_access == Access::ReadWrite {
                    return true; // widened verb
                }
            }
        }
    }
    // git: a new rule, or any rule whose access widened read -> read-write.
    let fg: BTreeMap<String, Access> = from
        .git
        .iter()
        .map(|g| (format!("{:?}", g.target), g.access))
        .collect();
    for g in &to.git {
        let key = format!("{:?}", g.target);
        match fg.get(&key) {
            None => return true,
            Some(a) if *a == Access::Read && g.access == Access::ReadWrite => return true,
            _ => {}
        }
    }
    false
}

/// Changes that turn `from` into `to`. Ignores `name` (identity) and
/// `rw_size_gb` (not persisted in managed config; see normalize.rs note).
pub fn diff(from: &Normalized, to: &Normalized) -> Vec<FieldDelta> {
    let mut out = Vec::new();
    if from.image != to.image {
        out.push(FieldDelta {
            field: "image".into(),
            from: image_str(&from.image),
            to: image_str(&to.image),
            class: FieldClass::Image,
            weakens_egress: false,
        });
    }
    if from.cpus != to.cpus {
        out.push(FieldDelta {
            field: "cpus".into(),
            from: from.cpus.to_string(),
            to: to.cpus.to_string(),
            class: FieldClass::Restart,
            weakens_egress: false,
        });
    }
    if from.mem_mb != to.mem_mb {
        out.push(FieldDelta {
            field: "memory".into(),
            from: format!("{} MiB", from.mem_mb),
            to: format!("{} MiB", to.mem_mb),
            class: FieldClass::Restart,
            weakens_egress: false,
        });
    }
    if from.ports != to.ports {
        out.push(FieldDelta {
            field: "ports".into(),
            from: format!("{:?}", from.ports),
            to: format!("{:?}", to.ports),
            class: FieldClass::Live,
            weakens_egress: false,
        });
    }
    if from.volumes != to.volumes {
        out.push(FieldDelta {
            field: "volumes".into(),
            from: format!("{:?}", from.volumes),
            to: format!("{:?}", to.volumes),
            class: FieldClass::Live,
            weakens_egress: false,
        });
    }
    if from.egress != to.egress {
        out.push(FieldDelta {
            field: "egress".into(),
            from: from.egress.to_yaml(),
            to: to.egress.to_yaml(),
            class: FieldClass::Live,
            weakens_egress: egress_weakens(&from.egress, &to.egress),
        });
    }
    out
}

/// 3-way state. `repo`/`managed` are each compared to `base` via `diff`.
pub fn classify(base: &Normalized, repo: &Normalized, managed: &Normalized) -> DriftState {
    let repo_changed = !diff(base, repo).is_empty();
    let managed_changed = !diff(base, managed).is_empty();
    match (repo_changed, managed_changed) {
        (false, false) => DriftState::InSync,
        (true, false) => DriftState::RepoAhead,
        (false, true) => DriftState::ManagedAhead,
        (true, true) => DriftState::Diverged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::egress::config::{Access, AllowEntry, EgressPolicyConfig};
    use crate::manifest::normalize::{ImageSource, Normalized};
    use crate::state::PortRule;

    fn base() -> Normalized {
        Normalized {
            name: "x".into(),
            image: ImageSource::Ref("ubuntu:24.04".into()),
            cpus: 2,
            mem_mb: 4096,
            rw_size_gb: 8,
            volumes: vec![],
            ports: vec![],
            egress: EgressPolicyConfig {
                enforce: true,
                allow: vec![],
                git: vec![],
            },
        }
    }

    #[test]
    fn no_changes_is_empty() {
        assert!(diff(&base(), &base()).is_empty());
    }

    #[test]
    fn cpus_change_is_restart_class() {
        let mut to = base();
        to.cpus = 4;
        let d = diff(&base(), &to);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "cpus");
        assert_eq!(d[0].class, FieldClass::Restart);
        assert!(!d[0].weakens_egress);
    }

    #[test]
    fn image_change_is_image_class() {
        let mut to = base();
        to.image = ImageSource::Ref("ubuntu:22.04".into());
        let d = diff(&base(), &to);
        assert_eq!(d[0].field, "image");
        assert_eq!(d[0].class, FieldClass::Image);
    }

    #[test]
    fn port_change_is_live_class() {
        let mut to = base();
        to.ports = vec![PortRule {
            bind: "127.0.0.1".parse().unwrap(),
            host_port: 8080,
            guest_port: 80,
        }];
        let d = diff(&base(), &to);
        assert_eq!(d[0].field, "ports");
        assert_eq!(d[0].class, FieldClass::Live);
    }

    #[test]
    fn adding_allow_host_weakens_egress() {
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Host("evil.com".into())];
        let d = diff(&base(), &to);
        assert_eq!(d[0].field, "egress");
        assert_eq!(d[0].class, FieldClass::Live);
        assert!(
            d[0].weakens_egress,
            "adding an allowed host loosens the firewall"
        );
    }

    #[test]
    fn disabling_enforce_weakens_egress() {
        let mut to = base();
        to.egress.enforce = false;
        assert!(diff(&base(), &to)[0].weakens_egress);
    }

    #[test]
    fn read_to_readwrite_weakens_but_readwrite_to_read_does_not() {
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Scoped {
            host: "h".into(),
            ports: None,
            access: Access::Read,
        }];
        let mut to = from.clone();
        if let AllowEntry::Scoped { access, .. } = &mut to.egress.allow[0] {
            *access = Access::ReadWrite;
        }
        assert!(
            diff(&from, &to)[0].weakens_egress,
            "read -> read-write loosens"
        );
        assert!(
            !diff(&to, &from)[0].weakens_egress,
            "read-write -> read tightens"
        );
    }

    #[test]
    fn removing_an_allow_host_does_not_weaken() {
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Host("ok.com".into())];
        let to = base();
        let d = diff(&from, &to);
        assert!(!d[0].weakens_egress, "removing a host tightens");
    }

    #[test]
    fn classify_repo_ahead_managed_ahead_diverged_insync() {
        let b = base();
        let mut repo = base();
        repo.cpus = 4;
        let mut managed = base();
        managed.mem_mb = 8192;
        assert_eq!(classify(&b, &b, &b), DriftState::InSync);
        assert_eq!(classify(&b, &repo, &b), DriftState::RepoAhead);
        assert_eq!(classify(&b, &b, &managed), DriftState::ManagedAhead);
        assert_eq!(classify(&b, &repo, &managed), DriftState::Diverged);
    }
}
