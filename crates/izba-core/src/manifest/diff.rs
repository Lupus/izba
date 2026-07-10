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

/// Build a (host, port) -> max-access view of an allow-list for comparison.
///
/// Expanding to per-port rows prevents the old host-keyed last-wins collapse:
/// two entries for the same host with different verbs (e.g. one port read-only,
/// another read-write) are now distinct cells, so a verb widening on one of them
/// is correctly flagged as a firewall loosening even when the other tightens.
fn allow_index(eg: &EgressPolicyConfig) -> BTreeMap<(String, u16), Access> {
    let mut m: BTreeMap<(String, u16), Access> = BTreeMap::new();
    for e in &eg.allow {
        let host = e.host().to_string();
        let acc = e.access();
        for p in e.ports() {
            // Take max-access across duplicate (host, port) pairs so the "from"
            // side is never understated and the "to" side is not over-flagged.
            let entry = m.entry((host.clone(), p)).or_insert(acc);
            if acc == Access::ReadWrite {
                *entry = Access::ReadWrite;
            }
        }
    }
    m
}

/// True if turning `from` egress into `to` egress LOOSENS the firewall:
/// disabling enforce, adding a (host, port) pair, widening access
/// (read -> read-write) on any (host, port), or adding/loosening a git rule.
/// An unenforced `from` allowed everything, so nothing weakens from it (#124).
fn egress_weakens(from: &EgressPolicyConfig, to: &EgressPolicyConfig) -> bool {
    if from.enforce && !to.enforce {
        return true;
    }
    if !from.enforce {
        // `from` allowed everything (unenforced); no `to` can be weaker (#124).
        return false;
    }
    let (fi, ti) = (allow_index(from), allow_index(to));
    for ((host, port), to_access) in &ti {
        match fi.get(&(host.clone(), *port)) {
            None => return true, // new (host, port) allowed
            Some(from_access) => {
                if *from_access == Access::Read && *to_access == Access::ReadWrite {
                    return true; // widened verb on this (host, port)
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

    /// image_str must render the actual ref/build strings into `from`/`to`
    /// (not an empty/constant string).
    #[test]
    fn image_delta_renders_actual_image_strings() {
        let mut to = base();
        to.image = ImageSource::Ref("ubuntu:22.04".into());
        let d = diff(&base(), &to);
        assert_eq!(d[0].from, "ubuntu:24.04", "from must be the base image ref");
        assert_eq!(d[0].to, "ubuntu:22.04", "to must be the target image ref");
    }

    /// A Ref -> Build image change renders the build dockerfile in `to`.
    #[test]
    fn image_delta_renders_build_source() {
        use crate::manifest::schema::BuildSpec;
        let mut to = base();
        to.image = ImageSource::Build(BuildSpec {
            context: Some(".".into()),
            dockerfile: Some("Dockerfile.prod".into()),
            tag: None,
            allow: vec![],
            resources: None,
        });
        let d = diff(&base(), &to);
        assert_eq!(d[0].from, "ubuntu:24.04");
        assert!(
            d[0].to.contains("Dockerfile.prod"),
            "build image must render its dockerfile name; got {:?}",
            d[0].to
        );
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

    /// Fix 1: duplicate allow-list entries for the same host must not collapse
    /// last-wins. A verb widening on any (host, port) cell must be flagged.
    #[test]
    fn duplicate_host_verb_widening_weakens_egress() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![443]),
                access: Access::Read,
            },
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![80]),
                access: Access::Read,
            },
        ];
        let mut to = from.clone();
        // Widen the second entry (port 80) from Read to ReadWrite.
        if let AllowEntry::Scoped { access, .. } = &mut to.egress.allow[1] {
            *access = Access::ReadWrite;
        }
        let d = diff(&from, &to);
        assert!(!d.is_empty(), "a change must be detected");
        assert!(
            d[0].weakens_egress,
            "verb widening on a duplicate-host entry must flag weakens_egress"
        );
    }

    /// Adding a NEW git rule that did not exist before LOOSENS the firewall
    /// (exercises the `None => return true` arm of the git loop).
    #[test]
    fn adding_a_git_rule_weakens_egress() {
        use crate::daemon::egress::config::{GitRule, GitTarget};
        let from = base();
        let mut to = base();
        to.egress.git = vec![GitRule {
            target: GitTarget::Host("github.com".into()),
            access: Access::Read,
        }];
        let d = diff(&from, &to);
        assert_eq!(d[0].field, "egress");
        assert!(
            d[0].weakens_egress,
            "adding a git rule that did not exist must flag weakening"
        );
    }

    /// Widening a git rule's access read -> read-write LOOSENS; the reverse, or
    /// an identical rule, does NOT (exercises the git match guard).
    #[test]
    fn git_rule_verb_widening_weakens_but_tightening_and_identity_do_not() {
        use crate::daemon::egress::config::{GitRule, GitTarget};
        let mut from = base();
        from.egress.git = vec![GitRule {
            target: GitTarget::Repo("github.com/o/a".into()),
            access: Access::Read,
        }];
        let mut to = from.clone();
        to.egress.git[0].access = Access::ReadWrite;
        assert!(
            diff(&from, &to)[0].weakens_egress,
            "git read -> read-write must flag weakening"
        );
        assert!(
            !diff(&to, &from)[0].weakens_egress,
            "git read-write -> read must NOT flag weakening"
        );
        // Identical git rule on both sides: no egress delta at all.
        assert!(
            diff(&from, &from.clone()).is_empty(),
            "identical egress must produce no delta"
        );
    }

    /// An unchanged Read git rule must not be flagged as weakening even when
    /// some OTHER egress field changes in a tightening direction. This isolates
    /// the `&&` in the git guard: `from==Read` is true but `to==ReadWrite` is
    /// false, so a `||` would wrongly fire on the unchanged rule.
    #[test]
    fn unchanged_read_git_rule_with_other_tightening_does_not_weaken() {
        use crate::daemon::egress::config::{GitRule, GitTarget};
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Host("removed.example".into())];
        from.egress.git = vec![GitRule {
            target: GitTarget::Repo("github.com/o/a".into()),
            access: Access::Read,
        }];
        let mut to = base();
        to.egress.allow = vec![]; // host removed -> tightening
        to.egress.git = vec![GitRule {
            target: GitTarget::Repo("github.com/o/a".into()),
            access: Access::Read, // unchanged
        }];
        let d = diff(&from, &to);
        assert_eq!(d[0].field, "egress");
        assert!(
            !d[0].weakens_egress,
            "removing a host with an unchanged Read git rule is a pure tightening"
        );
    }

    /// Fix 1 (negative): a pure tightening on duplicate-host entries must NOT
    /// flag weakening.
    #[test]
    fn duplicate_host_pure_tightening_does_not_weaken() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
            },
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![80]),
                access: Access::ReadWrite,
            },
        ];
        let mut to = from.clone();
        // Tighten the second entry (port 80) from ReadWrite to Read.
        if let AllowEntry::Scoped { access, .. } = &mut to.egress.allow[1] {
            *access = Access::Read;
        }
        let d = diff(&from, &to);
        assert!(!d.is_empty(), "a change must be detected");
        assert!(
            !d[0].weakens_egress,
            "pure tightening on a duplicate-host entry must NOT flag weakens_egress"
        );
    }

    /// #124 repro (dogfood 2026-07-02/09): turning enforcement ON — even while
    /// adding allow entries — is a net TIGHTENING (the unenforced `from` allowed
    /// everything), and must NOT flag `⚠ weakens egress`.
    #[test]
    fn enabling_enforce_with_allow_entries_does_not_weaken() {
        let mut from = base();
        from.egress.enforce = false;
        let mut to = base();
        to.egress.enforce = true;
        to.egress.allow = vec![AllowEntry::Host("github.com".into())];
        let d = diff(&from, &to);
        assert_eq!(d[0].field, "egress");
        assert!(
            !d[0].weakens_egress,
            "enforce off->on is a tightening even with new allow entries"
        );
    }

    /// While unenforced on BOTH sides, allow/git entries are inert — adding one
    /// changes nothing effective and must not flag weakening.
    #[test]
    fn unenforced_to_unenforced_allow_changes_do_not_weaken() {
        let mut from = base();
        from.egress.enforce = false;
        let mut to = from.clone();
        to.egress.allow = vec![AllowEntry::Host("example.com".into())];
        assert!(
            !diff(&from, &to)[0].weakens_egress,
            "allow entries are inert while unenforced"
        );
    }
}
