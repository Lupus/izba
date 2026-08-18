//! Structural, order-insensitive diff between two `Normalized` configs, with a
//! field-class (Live/Restart/Image) and a `weakens_egress` flag per change, plus
//! the base/repo/managed 3-way state classifier.

use std::collections::BTreeMap;

use crate::daemon::egress::config::{
    is_wildcard_host, normalize_policy_host, Access, EgressPolicyConfig,
};
use crate::daemon::egress::inspect::InspectionTable;
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

/// Human `from`/`to` for the ports field: the CLI flag syntax
/// (`BIND:HOST:GUEST`), one rule per line so diff renderers can compare
/// line-wise. NOT the derived `Debug` of `Vec<PortRule>`, which leaked Rust
/// struct syntax into `izba diff` and the app's Manifest tab.
fn ports_str(ports: &[crate::state::PortRule]) -> String {
    if ports.is_empty() {
        return "(none)".into();
    }
    ports
        .iter()
        .map(|p| format!("{}:{}:{}", p.bind, p.host_port, p.guest_port))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A volume size in the CLI flag units (`10g` / `512m`), falling back to raw
/// bytes for a value neither unit divides (never produced by the flag parser,
/// but honest if it appears).
fn size_str(bytes: u64) -> String {
    if bytes > 0 && bytes.is_multiple_of(1 << 30) {
        format!("{}g", bytes >> 30)
    } else if bytes > 0 && bytes.is_multiple_of(1 << 20) {
        format!("{}m", bytes >> 20)
    } else {
        format!("{bytes} bytes")
    }
}

/// Human `from`/`to` for the volumes field: the CLI flag syntax
/// (`[NAME:]GUEST_PATH:SIZE`), one volume per line. See `ports_str`.
fn volumes_str(vols: &[crate::volume::VolumeSpec]) -> String {
    if vols.is_empty() {
        return "(none)".into();
    }
    vols.iter()
        .map(|v| {
            let path = v.guest_path.display();
            let size = size_str(v.size_bytes);
            match &v.name {
                Some(n) => format!("{n}:{path}:{size}"),
                None => format!("{path}:{size}"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Build the (host, port) -> access view of an allow-list for comparison,
/// folded exactly like `to_rego_data_json` compiles it (#172):
///
/// - **Exact hosts** compile into `sandbox_host_rules`, a JSON MAP keyed by
///   normalized host: a later normalize-equal entry's whole `{ports, access}`
///   object OVERWRITES the earlier one. So each exact-host entry first clears
///   every cell of that host, then inserts its own ports — last-wins,
///   whole-entry.
/// - **Wildcard hosts** compile into `sandbox_wildcard_host_rules`, a JSON
///   LIST where every rule grants independently (UNION): a cell's effective
///   access is the max across the entries that carry it, so cells accumulate
///   and duplicates take max-access.
///
/// Keyed on `normalize_policy_host` (trim + trailing-dot strip + lowercase),
/// the same comparison identity `EgressPolicyConfig`'s own mutation methods
/// and `to_rego_data_json` use (#170). Folding compile-faithfully is
/// load-bearing for the `⚠ weakens egress` gate: a max-access fold overstated
/// the "from" side of duplicate-carrying configs, letting a two-promote
/// sequence widen enforcement read -> read-write with neither step flagged
/// (#172).
fn allow_index(eg: &EgressPolicyConfig) -> BTreeMap<(String, u16), Access> {
    let mut m: BTreeMap<(String, u16), Access> = BTreeMap::new();
    for e in &eg.allow {
        let host = normalize_policy_host(e.host());
        let acc = e.access();
        if is_wildcard_host(&host) {
            for p in e.ports() {
                let entry = m.entry((host.clone(), p)).or_insert(acc);
                if acc == Access::ReadWrite {
                    *entry = Access::ReadWrite;
                }
            }
        } else {
            // JSON-map overwrite: this entry replaces ALL prior cells for
            // this host, not just the ports it shares with them.
            m.retain(|(h, _), _| h != &host);
            for p in e.ports() {
                m.insert((host.clone(), p), acc);
            }
        }
    }
    m
}

/// True if turning `from` egress into `to` egress LOOSENS the firewall:
/// disabling enforce, adding a (host, port) pair, widening access
/// (read -> read-write) on any (host, port), opening a new pinning
/// passthrough, losing L7 inspection on a still-reachable port, or
/// adding/loosening a git rule. An unenforced `from` allowed everything, so
/// nothing weakens from it (#124).
///
/// The inspectability axis (M5 §5.2) is deliberately NOT folded into
/// `allow_index`. `allow_index` is host+port-keyed, compile-faithful to
/// `to_rego_data_json`'s per-host JSON structures (#172) — but
/// `InspectionTable::from_config`'s `inspect_ports` is a policy-GLOBAL union
/// keyed on port ALONE: the router's tier-1 gate decides whether to
/// terminate before the TLS handshake, with only an (ip, port) and no host
/// yet, so there is no host-keyed answer available at that point (see that
/// type's doc). A host+port-keyed fold cannot represent that shape, and
/// reimplementing it here would be a THIRD independent computation of this
/// axis — Task 3 already spent a day on a live security bypass caused by two
/// (`InspectionTable::from_config` and `to_rego_data_json`) disagreeing. So
/// this asks `InspectionTable`'s own public methods instead — the same ones
/// the datapath calls. Do not "simplify" this back into `allow_index`.
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

    let (from_insp, to_insp) = (
        InspectionTable::from_config(from),
        InspectionTable::from_config(to),
    );

    // 1. A NEW pinning passthrough on an exact (host, port) removes L7
    //    enforcement for that host even though its port stays in the global
    //    inspected set — an explicit `tcp` entry never removes its own port
    //    from `inspects` (see `InspectionTable`'s
    //    `an_explicit_tcp_entry_does_not_uninspect_its_port`). This is the
    //    titled `http -> tcp` transition, caught directly rather than
    //    inferred from a protocol pair.
    for e in &to.allow {
        for p in e.ports() {
            if to_insp.passthrough_host(e.host(), p) && !from_insp.passthrough_host(e.host(), p) {
                return true;
            }
        }
    }

    // 2. Losing GLOBAL inspection on a port some `to` entry can still reach
    //    is a weakening even when no entry declares an explicit passthrough
    //    — e.g. removing the one entry that pulled a shared port into the
    //    inspected set silently un-inspects every OTHER host still on that
    //    port. Vacuous (not flagged) when nothing in `to` reaches the port
    //    any more — that is a pure reachability tightening, already handled
    //    by the (host, port) loop above never seeing a removed cell.
    let candidate_ports: std::collections::BTreeSet<u16> = from
        .allow
        .iter()
        .flat_map(|e| e.ports())
        .chain(to.allow.iter().flat_map(|e| e.ports()))
        .collect();
    for p in candidate_ports {
        if from_insp.inspects(p)
            && !to_insp.inspects(p)
            && to.allow.iter().any(|e| e.ports().contains(&p))
        {
            return true;
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
            from: ports_str(&from.ports),
            to: ports_str(&to.ports),
            class: FieldClass::Live,
            weakens_egress: false,
        });
    }
    if from.volumes != to.volumes {
        out.push(FieldDelta {
            field: "volumes".into(),
            from: volumes_str(&from.volumes),
            to: volumes_str(&to.volumes),
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
    use crate::daemon::egress::config::{Access, AllowEntry, EgressPolicyConfig, Protocol};
    use crate::manifest::normalize::{ImageSource, Normalized};
    use crate::state::PortRule;

    fn eg(yaml: &str) -> EgressPolicyConfig {
        EgressPolicyConfig::from_yaml(yaml).expect("parses")
    }

    #[test]
    fn dropping_inspection_from_http_to_tcp_weakens_egress() {
        let from = eg("enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n");
        let to = eg(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        assert!(
            egress_weakens(&from, &to),
            "the hatch drops L7 enforcement for this host — it must be flagged"
        );
    }

    #[test]
    fn adding_inspection_from_tcp_to_http_does_not_weaken() {
        let from = eg(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        );
        let to = eg("enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n");
        assert!(!egress_weakens(&from, &to), "restoring inspection tightens");
    }

    #[test]
    fn declaring_the_implied_protocol_is_not_a_change() {
        let from = eg("enforce: true\nallow:\n  - host: h.example.com\n    ports: [443]\n");
        let to = eg(
            "enforce: true\nallow:\n  - host: h.example.com\n    ports: [443]\n    protocol: http\n",
        );
        assert!(
            !egress_weakens(&from, &to),
            "writing down what was already true"
        );
        assert!(!egress_weakens(&to, &from));
    }

    #[test]
    fn opening_a_new_inspected_port_still_weakens_as_new_reachability() {
        let from = eg("enforce: true\nallow:\n  - host: h.example.com\n    ports: [443]\n");
        let to = eg(
            "enforce: true\nallow:\n  - host: h.example.com\n    ports: [443, 8000]\n    protocol: http\n",
        );
        assert!(
            egress_weakens(&from, &to),
            "a new (host, port) is new reach"
        );
    }

    /// The counter-example that stopped this task mid-flight (M5 P1 review,
    /// task 6): `inspect_ports` is a policy-GLOBAL union keyed on port alone
    /// (the router decides termination before the TLS handshake, with only an
    /// (ip, port) and no host yet — see `InspectionTable::from_config`'s doc).
    /// h1 never declares a protocol at all, but h2's `protocol: http` on the
    /// SAME port globally pulls port 8000 into the inspected set, so h1 is
    /// actually inspected in `from`. Removing h2's entry entirely (not
    /// touching h1's) drops 8000 out of the global set, so h1 loses L7
    /// enforcement in `to` even though h1's own entry never changed and is
    /// still reachable. No host+port-keyed fold (i.e. `allow_index`) can see
    /// this, because the change that causes it — h2's removal — isn't a cell
    /// `egress_weakens` ever inspects (removing a host must not itself flag,
    /// per `removing_an_allow_host_does_not_weaken`). This is why the check
    /// below asks `InspectionTable` directly instead of folding protocol into
    /// `allow_index`. Verified directly against `InspectionTable::from_config`
    /// before this test was written.
    #[test]
    fn losing_global_inspection_on_a_still_reachable_port_weakens_egress() {
        let from = eg(
            "enforce: true\nallow:\n  - host: h1.example.com\n    ports: [8000]\n  - host: h2.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        let to = eg("enforce: true\nallow:\n  - host: h1.example.com\n    ports: [8000]\n");
        assert!(
            egress_weakens(&from, &to),
            "h1 was inspected on 8000 only because h2's entry pulled the port into the \
             global inspected set; removing h2 silently un-inspects h1's still-reachable port"
        );
    }

    /// The complement of the test above: if NOTHING in `to` can reach the
    /// port any more, losing its global inspection is vacuous — flagging it
    /// would fire the review-token gate for a change that is a pure
    /// reachability tightening.
    #[test]
    fn losing_global_inspection_on_a_now_unreachable_port_does_not_weaken() {
        let from = eg(
            "enforce: true\nallow:\n  - host: h1.example.com\n    ports: [8000]\n  - host: h2.example.com\n    ports: [8000]\n    protocol: http\n",
        );
        let to = eg("enforce: true\nallow: []\n");
        assert!(
            !egress_weakens(&from, &to),
            "nothing reaches 8000 any more in `to`; un-inspecting it is vacuous"
        );
    }

    // DP-7: the manifest reuses EgressPolicyConfig verbatim, so `protocol`
    // rides `spec.egress` with no mirroring — pin that so a future refactor
    // that forks the type is caught here.
    #[test]
    fn protocol_round_trips_through_a_manifest_spec_egress_block() {
        let spec: crate::manifest::schema::SandboxSpec = serde_yaml::from_str(
            "image: alpine\negress:\n  enforce: true\n  allow:\n    - host: pinned.vendor.com\n      ports: [443]\n      protocol: tcp\n",
        )
        .expect("spec.egress deserializes through EgressPolicyConfig's strict walk");
        assert_eq!(
            spec.egress.expect("egress block present").allow[0].declared_protocol(),
            Some(Protocol::Tcp)
        );
    }

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

    /// Port deltas render in the CLI flag syntax (`BIND:HOST:GUEST`, one rule
    /// per line) — never `Vec<PortRule>`'s Rust `Debug` output, which is what
    /// users used to see in `izba diff` and the app's Manifest tab.
    #[test]
    fn port_delta_renders_flag_syntax_one_per_line() {
        let mut to = base();
        to.ports = vec![
            PortRule {
                bind: "127.0.0.1".parse().unwrap(),
                host_port: 8080,
                guest_port: 80,
            },
            PortRule {
                bind: "0.0.0.0".parse().unwrap(),
                host_port: 9000,
                guest_port: 90,
            },
        ];
        let d = diff(&base(), &to);
        assert_eq!(d[0].from, "(none)");
        assert_eq!(d[0].to, "127.0.0.1:8080:80\n0.0.0.0:9000:90");
        assert!(
            !d[0].to.contains("PortRule"),
            "no Rust Debug syntax in user-facing delta: {:?}",
            d[0].to
        );
    }

    /// Volume deltas render in the CLI flag syntax (`[NAME:]GUEST_PATH:SIZE`,
    /// one per line) with `g`/`m` size units matching `parse_size`.
    #[test]
    fn volume_delta_renders_flag_syntax_one_per_line() {
        use crate::volume::VolumeSpec;
        let mut to = base();
        to.volumes = vec![
            VolumeSpec {
                name: Some("cache".into()),
                guest_path: "/data".into(),
                size_bytes: 1 << 30,
                eph_id: None,
            },
            VolumeSpec {
                name: None,
                guest_path: "/scratch".into(),
                size_bytes: 512 << 20,
                eph_id: None,
            },
        ];
        let d = diff(&base(), &to);
        assert_eq!(d[0].from, "(none)");
        assert_eq!(d[0].to, "cache:/data:1g\n/scratch:512m");
        assert!(
            !d[0].to.contains("VolumeSpec"),
            "no Rust Debug syntax in user-facing delta: {:?}",
            d[0].to
        );
    }

    /// `size_str` unit selection: whole GiB wins over MiB, and a value neither
    /// unit divides falls back to honest raw bytes. Zero is "0 bytes", not
    /// "0g" — the `bytes > 0` guards are load-bearing (every unit divides 0).
    #[test]
    fn size_str_picks_largest_exact_unit() {
        assert_eq!(size_str(2 << 30), "2g");
        assert_eq!(size_str(512 << 20), "512m");
        assert_eq!(size_str((1 << 30) + 1), "1073741825 bytes");
        assert_eq!(size_str(0), "0 bytes");
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
            protocol: None,
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

    /// Duplicate exact-host entries fold last-wins at compile, so the LAST
    /// entry is the enforced one — widening ITS verb must flag. (Originally
    /// "Fix 1": a host-keyed index used to mask per-port verb widenings; kept
    /// as a pin that the enforced cell's widen is always caught.)
    #[test]
    fn duplicate_host_verb_widening_weakens_egress() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![80]),
                access: Access::Read,
                protocol: None,
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

    /// Fix 1 (negative): tightening the verb on the enforced (last) duplicate
    /// entry is a pure tightening and must NOT flag.
    #[test]
    fn duplicate_host_pure_tightening_does_not_weaken() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "h".into(),
                ports: Some(vec![80]),
                access: Access::ReadWrite,
                protocol: None,
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

    /// #170: a pure respelling of the same host (case + trailing dot) must not
    /// be flagged as weakening, and must produce no egress delta at all — the
    /// allow-index keys on normalized identity, not raw string equality.
    #[test]
    fn respelling_only_host_change_does_not_weaken() {
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Scoped {
            host: "api.example.com".into(),
            ports: Some(vec![443]),
            access: Access::Read,
            protocol: None,
        }];
        let mut to = from.clone();
        if let AllowEntry::Scoped { host, .. } = &mut to.egress.allow[0] {
            *host = "API.example.com.".into();
        }
        assert!(!egress_weakens(&from.egress, &to.egress));
        // The raw host spelling still differs between the two configs (this is
        // a structural diff, and human-facing output must keep the source
        // spelling verbatim — see the module doc), so `diff()` may still
        // report an "egress" delta reflecting that respelling; but it must
        // never be flagged as a firewall weakening.
        let d0 = diff(&from, &to)
            .into_iter()
            .find(|f| f.field == "egress")
            .expect("respelling rewrites managed yaml, so a delta row is expected");
        assert!(
            !d0.weakens_egress,
            "a pure respelling must not be flagged ⚠ weakens egress"
        );
    }

    /// #172: exact-host duplicates fold LAST-WINS, whole-entry — exactly like
    /// the `sandbox_host_rules` JSON-map compile — NOT max-access. With
    /// `[rw first, read last]` the enforced access is read (the last
    /// normalize-equal entry's whole object wins), so a later single-entry
    /// `[rw]` proposal is a genuine widen and must be flagged. A max-access
    /// fold would call the from-side rw and let this widen through unflagged
    /// (step 2 of the #172 two-promote sequence).
    #[test]
    fn exact_host_duplicates_fold_last_wins_not_max() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "Host.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            },
        ];
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Scoped {
            host: "host.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
            protocol: None,
        }];
        assert!(
            egress_weakens(&from.egress, &to.egress),
            "compiled enforcement was read (last duplicate wins); an rw proposal widens and must flag"
        );
    }

    /// #170: a genuine access widening that happens to also change spelling
    /// (case) must still be flagged — normalization must not mask a real
    /// widen.
    #[test]
    fn genuine_widen_across_spellings_still_flagged() {
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Scoped {
            host: "Host.com".into(),
            ports: Some(vec![443]),
            access: Access::Read,
            protocol: None,
        }];
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Scoped {
            host: "host.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
            protocol: None,
        }];
        assert!(egress_weakens(&from.egress, &to.egress));
    }

    /// #170: a "new" host that is actually just a respelling of an existing
    /// host is NOT new — a new port on it still weakens, but the identical
    /// port/access under a different spelling must not.
    #[test]
    fn new_host_detection_across_spellings() {
        let from_single = {
            let mut f = base();
            f.egress.allow = vec![AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            }];
            f
        };

        let mut widened_port = base();
        widened_port.egress.allow = vec![AllowEntry::Scoped {
            host: "HOST.com".into(),
            ports: Some(vec![8080]),
            access: Access::Read,
            protocol: None,
        }];
        assert!(
            egress_weakens(&from_single.egress, &widened_port.egress),
            "a new port on a respelled host must still weaken"
        );

        let mut same_port = base();
        same_port.egress.allow = vec![AllowEntry::Scoped {
            host: "HOST.com".into(),
            ports: Some(vec![443]),
            access: Access::Read,
            protocol: None,
        }];
        assert!(
            !egress_weakens(&from_single.egress, &same_port.egress),
            "the same (host, port, access) under a different spelling must not weaken"
        );
    }

    /// #172: the two-promote widening sequence, end-to-end at the diff layer.
    /// Step 1 — appending a narrower normalize-equal duplicate
    /// (`[h rw 443]` -> `[h rw 443, h read 443]`) NARROWS enforcement to read
    /// (the last duplicate's whole object wins at compile) and must NOT flag.
    /// Step 2 — dropping the duplicate again (`[h rw 443, h read 443]` ->
    /// `[h rw 443]`) WIDENS enforcement read -> read-write and MUST flag.
    /// Before #172, the max-access fold left BOTH steps unflagged.
    #[test]
    fn two_promote_duplicate_sequence_flags_the_widening_step() {
        let mut managed = base();
        managed.egress.allow = vec![AllowEntry::Scoped {
            host: "host.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
            protocol: None,
        }];
        let mut with_dup = base();
        with_dup.egress.allow = vec![
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            },
        ];
        assert!(
            !egress_weakens(&managed.egress, &with_dup.egress),
            "step 1 narrows enforcement (rw -> read); no flag"
        );
        assert!(
            egress_weakens(&with_dup.egress, &managed.egress),
            "step 2 widens enforcement (read -> rw); MUST flag"
        );
    }

    /// #172 per-port variant: `[h{443} read, h{8080} rw]` compiles to ONLY
    /// 8080/read-write — the last entry's whole `{ports, access}` object wins,
    /// dropping 443 entirely. A proposal keeping just `[h{443} read]`
    /// therefore re-opens 443, an effectively NEW (host, port), and must flag
    /// even though it looks like a pure removal textually.
    #[test]
    fn exact_host_whole_entry_overwrite_drops_earlier_ports() {
        let mut from = base();
        from.egress.allow = vec![
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "host.com".into(),
                ports: Some(vec![8080]),
                access: Access::ReadWrite,
                protocol: None,
            },
        ];
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Scoped {
            host: "host.com".into(),
            ports: Some(vec![443]),
            access: Access::Read,
            protocol: None,
        }];
        assert!(
            egress_weakens(&from.egress, &to.egress),
            "443 was not enforced before (8080-only entry won at compile); re-opening it must flag"
        );
    }

    /// #172: wildcard duplicates fold as UNION, not last-wins. With
    /// `[*.x rw 443, *.x read 443]` (rw FIRST, read LAST) the union already
    /// grants read-write on 443, so collapsing to `[*.x rw 443]` is not a
    /// widen — a last-wins fold would wrongly call the from-side read and
    /// false-positive here. Adding a redundant read duplicate to an rw
    /// wildcard is likewise not a widen.
    #[test]
    fn wildcard_duplicates_fold_as_union_not_last_wins() {
        let mut dup = base();
        dup.egress.allow = vec![
            AllowEntry::Scoped {
                host: "*.example.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "*.example.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            },
        ];
        let mut single = base();
        single.egress.allow = vec![AllowEntry::Scoped {
            host: "*.example.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
            protocol: None,
        }];
        assert!(
            !egress_weakens(&dup.egress, &single.egress),
            "union already granted rw on 443; collapsing duplicates is no widen"
        );
        assert!(
            !egress_weakens(&single.egress, &dup.egress),
            "adding a redundant read duplicate under an rw wildcard is no widen"
        );
    }

    /// #172 mutation-gate kill: a SINGLE wildcard entry's access verb must
    /// fold through to its cells — read -> read-write on a wildcard pattern
    /// is a widen and must flag; the reverse tightens and must not. Pins the
    /// ReadWrite-upgrade guard in `allow_index`'s wildcard arm, which the
    /// incremental mutation gate reported unkilled (`replace == with !=`):
    /// that mutant upgrades Read cells to ReadWrite, overstating a wildcard
    /// from-side and masking exactly this widen.
    #[test]
    fn wildcard_single_entry_verb_widening_flags() {
        let mut from = base();
        from.egress.allow = vec![AllowEntry::Scoped {
            host: "*.example.com".into(),
            ports: Some(vec![443]),
            access: Access::Read,
            protocol: None,
        }];
        let mut to = base();
        to.egress.allow = vec![AllowEntry::Scoped {
            host: "*.example.com".into(),
            ports: Some(vec![443]),
            access: Access::ReadWrite,
            protocol: None,
        }];
        assert!(
            egress_weakens(&from.egress, &to.egress),
            "wildcard read -> read-write widens"
        );
        assert!(
            !egress_weakens(&to.egress, &from.egress),
            "wildcard read-write -> read tightens"
        );
    }
}
