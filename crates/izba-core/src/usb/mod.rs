//! Host-side USB passthrough: identity, consent, settings, and inventory.
//!
//! Everything here runs on the host and is reachable only from a human-driven
//! CLI/GUI action or from izbad's own outbound dial. The guest never sees a
//! device list and never supplies an upstream address (D1/F-USB-9). The
//! The guest-facing broker plane is [`broker`], which binds a listener only
//! for a sandbox that already holds a grant.

pub mod broker;
pub mod grants;
pub mod ids;
pub mod inventory;
pub mod settings;
pub mod trust;
pub mod usbipd_state;

pub use grants::{UsbConfig, UsbGrant};
pub use ids::DeviceId;
pub use settings::{Upstream, UsbSettings};

use std::collections::HashMap;

use crate::daemon::egress::router::UsbGuard;
use crate::daemon::proto::UsbDeviceInfo;
use crate::paths::Paths;

/// The single "is this feature on?" predicate. USB is configured exactly when a
/// human set an upstream; nothing else turns it on.
pub fn is_configured(s: &UsbSettings) -> bool {
    s.upstream.is_some()
}

/// Wall-clock stamp for a new grant.
// reason: reads the system clock; there is no behaviour to mutate.
#[mutants::skip]
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolve the configured upstream to an address the egress guard can compare
/// against.
///
/// `None` when USB is unconfigured or the host does not resolve — the guard then
/// falls back to the well-known port alone, which is the honest answer rather
/// than a guess at what the user meant.
pub fn resolve_upstream(s: &UsbSettings) -> Option<(std::net::IpAddr, u16)> {
    use std::net::ToSocketAddrs;
    let up = s.upstream.as_ref()?;
    if let Ok(ip) = up.host.parse::<std::net::IpAddr>() {
        return Some((ip, up.port));
    }
    (up.host.as_str(), up.port)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|sa| (sa.ip(), up.port))
}

/// Resolve and classify an upstream host.
///
/// An unresolvable host classifies as `Public` — the most restricted class, not
/// the safest-sounding one: izba does not know whose machine it is, so it does
/// not grant it the benefit of the doubt.
pub fn classify_configured(
    host: &str,
    port: u16,
) -> (Option<std::net::IpAddr>, trust::UpstreamTrust) {
    let resolved = resolve_upstream(&UsbSettings {
        upstream: Some(Upstream {
            host: host.to_string(),
            port,
        }),
        allow_remote_upstream: false,
    })
    .map(|(ip, _)| ip);
    let class = match resolved {
        Some(ip) => trust::classify(
            ip,
            trust::host_default_gateway(),
            trust::running_under_wsl(),
        ),
        None => trust::UpstreamTrust::Public,
    };
    (resolved, class)
}

/// Resolve the configured upstream to an address izbad may actually dial,
/// re-applying the trust decision **at dial time**.
///
/// A name classified when it was stored is not a promise about later: the record
/// can change benignly, or be moved deliberately (DNS rebinding). izbad dials
/// from the host's network position, so the refusal is enforced again here
/// rather than trusted from the moment it was configured — otherwise a
/// private-looking hostname could be re-pointed at a public USB/IP server and
/// izbad would dial and parse it without the operator's opt-in.
pub fn dialable_upstream(s: &UsbSettings) -> anyhow::Result<std::net::SocketAddr> {
    let up = s
        .upstream
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("usb passthrough is not configured"))?;
    let (resolved, class) = classify_configured(&up.host, up.port);
    let ip = resolved.ok_or_else(|| {
        anyhow::anyhow!(
            "the configured usbip upstream '{}' does not resolve",
            up.host
        )
    })?;
    if trust::is_refused(class, s.allow_remote_upstream) {
        anyhow::bail!(
            "refusing to dial the configured usbip upstream '{}': it now resolves \
             to {ip}, which is reachable from the internet. Re-run \
             `izba usb upstream set` with --allow-remote if that is intended.",
            up.host
        );
    }
    Ok(std::net::SocketAddr::new(ip, up.port))
}

/// Whether a sandbox should have a USB plane bound at all.
///
/// Both halves are required, and each says something different: a grant is the
/// human's consent, and a configured upstream is the only place a device could
/// come from. Without the grant there is nothing to authorize; without the
/// upstream the plane could only ever answer "nowhere to import from" — so
/// binding it would add a guest-reachable surface that cannot succeed.
pub fn plane_wanted(paths: &Paths, name: &str) -> bool {
    grants_of(paths, name).is_enabled() && is_configured(&settings::load(&paths.usb_dir()))
}

/// Read one sandbox's grants off disk, treating anything unreadable as "no
/// grants" — the direction that never invents consent.
pub fn grants_of(paths: &Paths, name: &str) -> UsbConfig {
    crate::state::load_json::<crate::state::SandboxConfig>(
        &paths.sandbox_dir(name).join(crate::state::CONFIG_FILE),
    )
    .ok()
    .flatten()
    .map(|c| c.usb)
    .unwrap_or_default()
}

/// Build the egress USB guard for one sandbox.
///
/// Enabled exactly when the sandbox holds a grant, and carrying the configured
/// upstream endpoint so the guard can deny it by address as well as by the
/// well-known port — a single usbipd is multi-homed (loopback, WSL gateway, LAN
/// address, and their IPv4-mapped forms).
pub fn guard_for(paths: &Paths, name: &str) -> UsbGuard {
    UsbGuard {
        sandbox_usb_enabled: grants_of(paths, name).is_enabled(),
        upstream: resolve_upstream(&settings::load(&paths.usb_dir())),
    }
}

/// Which sandboxes hold a grant for each device.
fn grants_by_device(paths: &Paths) -> HashMap<DeviceId, Vec<String>> {
    let mut out: HashMap<DeviceId, Vec<String>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(paths.sandboxes_dir()) else {
        return out;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    // Stable output: a listing that reorders between runs reads as churn.
    names.sort();
    for name in names {
        for g in grants_of(paths, &name).devices {
            out.entry(g.device).or_default().push(name.clone());
        }
    }
    out
}

/// Annotate the upstream's exported devices with existing grants, then append
/// the devices usbipd knows about but has not shared — each carrying the exact
/// command the human must run elevated to share it.
///
/// izba never runs that command itself: binding needs Administrator, and
/// wrapping usbipd-win is explicitly out of scope.
///
/// `attached` is the live attachment→holder map from the broker, so a row can
/// say which sandbox currently has the hardware — the difference between
/// "granted" and "gone from your desk right now". It is keyed on
/// `(vid:pid, busid)`, so a row is attributed to whoever holds **that port**:
/// two identical boards are two rows, and one being on loan says nothing about
/// the other.
pub fn list_devices(
    paths: &Paths,
    shared: &[inventory::UpstreamDevice],
    known: Option<Vec<usbipd_state::UsbipdDevice>>,
    attached: &broker::AttachmentMap,
) -> Vec<UsbDeviceInfo> {
    let grants = grants_by_device(paths);
    let known = known.unwrap_or_default();
    let mut out: Vec<UsbDeviceInfo> = shared
        .iter()
        .map(|d| UsbDeviceInfo {
            busid: d.busid.clone(),
            device: d.id.to_string(),
            // The wire format carries only a sysfs path; usbipd knows the
            // product name. Prefer the name, keep the path as the fallback.
            description: usbipd_state::describe(&known, &d.busid, d.id)
                .unwrap_or(&d.description)
                .to_string(),
            shared: true,
            granted_to: grants.get(&d.id).cloned().unwrap_or_default(),
            attached_to: attached.get(&(d.id, d.busid.clone())).cloned(),
            bind_command: None,
        })
        .collect();
    // Only the UNBOUND rows are additive: a bound device is already in `shared`,
    // and listing it twice would read as two pieces of hardware.
    for k in known.into_iter().filter(|k| !k.bound) {
        out.push(UsbDeviceInfo {
            bind_command: Some(usbipd_state::bind_command(&k)),
            granted_to: grants.get(&k.id).cloned().unwrap_or_default(),
            // An unshared device cannot be attached, but deriving it the same
            // way keeps the two arms honest rather than asserting that here.
            attached_to: attached.get(&(k.id, k.busid.clone())).cloned(),
            busid: k.busid,
            device: k.id.to_string(),
            description: k.description,
            shared: false,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usb_is_off_until_a_human_sets_an_upstream() {
        assert!(!is_configured(&UsbSettings::default()));
        assert!(is_configured(&UsbSettings {
            upstream: Some(Upstream {
                host: "127.0.0.1".into(),
                port: 3240,
            }),
            allow_remote_upstream: false,
        }));
    }

    #[test]
    fn allowing_a_remote_upstream_alone_does_not_turn_the_feature_on() {
        // The flag is a permission, not a switch: without an address there is
        // nothing to dial and every USB RPC must still refuse.
        assert!(!is_configured(&UsbSettings {
            upstream: None,
            allow_remote_upstream: true,
        }));
    }

    fn paths_with_sandboxes(specs: &[(&str, &[&str])]) -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        for (name, devices) in specs {
            let dir = paths.sandbox_dir(name);
            std::fs::create_dir_all(&dir).unwrap();
            let mut usb = UsbConfig::default();
            for d in *devices {
                grants::grant(
                    &mut usb,
                    UsbGrant {
                        device: d.parse().unwrap(),
                        busid_pin: None,
                        description: String::new(),
                        granted_at_unix_ms: 1,
                    },
                )
                .unwrap();
            }
            let cfg = crate::state::SandboxConfig {
                image_digest: "sha256:x".into(),
                image_ref: "img".into(),
                cpus: 1,
                mem_mb: 512,
                workspace: "/ws".into(),
                ports: vec![],
                volumes: vec![],
                builder: false,
                docker: false,
                build: None,
                rw_size_gb: 0,
                usb,
                vnc: false,
            };
            crate::state::save_json(&dir.join(crate::state::CONFIG_FILE), &cfg).unwrap();
        }
        (tmp, paths)
    }

    fn upstream_device(busid: &str, id: &str) -> inventory::UpstreamDevice {
        inventory::UpstreamDevice {
            busid: busid.into(),
            id: id.parse().unwrap(),
            description: "USB Serial Converter".into(),
            speed: 2,
        }
    }

    #[test]
    fn an_ip_literal_upstream_needs_no_resolution() {
        let s = UsbSettings {
            upstream: Some(Upstream {
                host: "172.24.32.1".into(),
                port: 3240,
            }),
            allow_remote_upstream: false,
        };
        assert_eq!(
            resolve_upstream(&s),
            Some(("172.24.32.1".parse().unwrap(), 3240))
        );
    }

    #[test]
    fn an_unconfigured_upstream_resolves_to_nothing() {
        assert_eq!(resolve_upstream(&UsbSettings::default()), None);
    }

    fn settings_for(host: &str, allow_remote: bool) -> UsbSettings {
        UsbSettings {
            upstream: Some(Upstream {
                host: host.into(),
                port: 3240,
            }),
            allow_remote_upstream: allow_remote,
        }
    }

    #[test]
    fn a_loopback_upstream_is_dialable() {
        let addr = dialable_upstream(&settings_for("127.0.0.1", false)).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:3240");
    }

    #[test]
    fn a_public_upstream_is_refused_at_dial_time_not_only_when_it_was_set() {
        // The stored classification is not a promise about later: a name can be
        // re-pointed at a public address after it was accepted as private, and
        // izbad dials from the host's network position. So the refusal is
        // re-applied here, on the address actually about to be dialed.
        let err = dialable_upstream(&settings_for("203.0.113.7", false))
            .unwrap_err()
            .to_string();
        assert!(err.contains("203.0.113.7"), "{err}");
        assert!(err.contains("internet"), "{err}");
        assert!(err.contains("--allow-remote"), "name the opt-in: {err}");
    }

    #[test]
    fn a_public_upstream_the_operator_opted_into_is_dialable() {
        let addr = dialable_upstream(&settings_for("203.0.113.7", true)).unwrap();
        assert_eq!(addr.to_string(), "203.0.113.7:3240");
    }

    #[test]
    fn an_unconfigured_upstream_is_not_dialable() {
        let err = dialable_upstream(&UsbSettings::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not configured"), "{err}");
    }

    #[test]
    fn a_host_that_does_not_resolve_is_not_dialable() {
        let err = dialable_upstream(&settings_for("no-such-host.invalid", false))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not resolve") || err.contains("internet"),
            "an unresolvable host must never be dialed: {err}"
        );
    }

    #[test]
    fn a_sandbox_with_no_grants_gets_a_disabled_guard() {
        let (_t, paths) = paths_with_sandboxes(&[("web", &[])]);
        let g = guard_for(&paths, "web");
        assert!(!g.sandbox_usb_enabled);
        assert!(g.upstream.is_none(), "no upstream is configured");
    }

    #[test]
    fn a_sandbox_that_does_not_exist_gets_a_disabled_guard() {
        // The guard must never invent consent for a name it cannot read.
        let (_t, paths) = paths_with_sandboxes(&[]);
        assert!(!guard_for(&paths, "ghost").sandbox_usb_enabled);
    }

    #[test]
    fn a_granted_sandbox_gets_an_enabled_guard_carrying_the_upstream() {
        let (_t, paths) = paths_with_sandboxes(&[("web", &["0403:6001"])]);
        settings::save(
            &paths.usb_dir(),
            &UsbSettings {
                upstream: Some(Upstream {
                    host: "127.0.0.1".into(),
                    port: 3240,
                }),
                allow_remote_upstream: false,
            },
        )
        .unwrap();

        let g = guard_for(&paths, "web");
        assert!(g.sandbox_usb_enabled);
        assert_eq!(
            g.upstream,
            Some(("127.0.0.1".parse().unwrap(), 3240)),
            "the guard denies the configured endpoint on its own port too"
        );
    }

    #[test]
    fn a_shared_device_is_annotated_with_every_sandbox_holding_it() {
        let (_t, paths) = paths_with_sandboxes(&[
            ("web", &["0403:6001"]),
            ("api", &["0403:6001", "1a86:7523"]),
            ("idle", &[]),
        ]);
        let listed = list_devices(
            &paths,
            &[upstream_device("3-2", "0403:6001")],
            None,
            &HashMap::new(),
        );
        assert_eq!(listed.len(), 1);
        assert!(listed[0].shared);
        assert_eq!(listed[0].granted_to, vec!["api", "web"], "sorted by name");
        assert!(listed[0].bind_command.is_none(), "already shared");
    }

    #[test]
    fn a_row_is_attributed_to_whoever_holds_that_port_not_that_vid_pid() {
        // Two identical boards, granted to two sandboxes and imported from two
        // ports. One being on loan says nothing about the other — attributing
        // by `vid:pid` alone would name the wrong sandbox on one row and, once
        // the other detaches, report a spliced device as free.
        let (_t, paths) = paths_with_sandboxes(&[("web", &["303a:1001"]), ("api", &["303a:1001"])]);
        let attached: broker::AttachmentMap = [(
            ("303a:1001".parse::<DeviceId>().unwrap(), "3-3".to_string()),
            "api".to_string(),
        )]
        .into_iter()
        .collect();
        let listed = list_devices(
            &paths,
            &[
                upstream_device("3-2", "303a:1001"),
                upstream_device("3-3", "303a:1001"),
            ],
            None,
            &attached,
        );
        assert_eq!(listed[0].busid, "3-2");
        assert_eq!(
            listed[0].attached_to, None,
            "the board on 3-2 is still sitting on the host"
        );
        assert_eq!(listed[1].busid, "3-3");
        assert_eq!(listed[1].attached_to.as_deref(), Some("api"));
    }

    #[test]
    fn an_unshared_row_is_not_claimed_by_a_holder_of_an_identical_board() {
        // The appended arm derives `attached_to` the same way, so it must be
        // just as port-specific: an unbound device cannot be attached, and a
        // twin on another port being on loan must not say it is.
        let (_t, paths) = paths_with_sandboxes(&[]);
        let known = vec![usbipd_state::UsbipdDevice {
            busid: "1-4".into(),
            id: "303a:1001".parse().unwrap(),
            description: "USB JTAG/serial debug unit".into(),
            bound: false,
            attached: false,
        }];
        let attached: broker::AttachmentMap = [(
            ("303a:1001".parse::<DeviceId>().unwrap(), "3-3".to_string()),
            "api".to_string(),
        )]
        .into_iter()
        .collect();
        let listed = list_devices(&paths, &[], Some(known), &attached);
        assert_eq!(listed[0].busid, "1-4");
        assert_eq!(listed[0].attached_to, None);
    }

    #[test]
    fn an_ungranted_device_lists_with_no_holders() {
        let (_t, paths) = paths_with_sandboxes(&[("web", &["1a86:7523"])]);
        let listed = list_devices(
            &paths,
            &[upstream_device("3-2", "0403:6001")],
            None,
            &HashMap::new(),
        );
        assert!(listed[0].granted_to.is_empty());
    }

    #[test]
    fn an_unshared_device_is_appended_with_the_command_to_share_it() {
        let (_t, paths) = paths_with_sandboxes(&[]);
        let known = vec![usbipd_state::UsbipdDevice {
            busid: "1-4".into(),
            id: "1a86:7523".parse().unwrap(),
            description: "USB-SERIAL CH340".into(),
            bound: false,
            attached: false,
        }];
        let listed = list_devices(
            &paths,
            &[upstream_device("3-2", "0403:6001")],
            Some(known),
            &HashMap::new(),
        );
        assert_eq!(listed.len(), 2);
        assert!(!listed[1].shared);
        assert_eq!(
            listed[1].bind_command.as_deref(),
            Some("usbipd bind --busid 1-4")
        );
    }

    #[test]
    fn a_bound_device_is_not_listed_twice() {
        // It already came back in the devlist; repeating it from usbipd's table
        // would read as two pieces of hardware.
        let (_t, paths) = paths_with_sandboxes(&[]);
        let known = vec![usbipd_state::UsbipdDevice {
            busid: "3-2".into(),
            id: "0403:6001".parse().unwrap(),
            description: "USB Serial Converter".into(),
            bound: true,
            attached: false,
        }];
        let listed = list_devices(
            &paths,
            &[upstream_device("3-2", "0403:6001")],
            Some(known),
            &HashMap::new(),
        );
        assert_eq!(listed.len(), 1);
        assert!(listed[0].shared);
    }

    #[test]
    fn an_unshared_device_still_shows_who_already_holds_a_grant_for_it() {
        // A grant can outlive the sharing: the user unbound the device on the
        // host, and must be able to see that the consent is still standing.
        let (_t, paths) = paths_with_sandboxes(&[("web", &["1a86:7523"])]);
        let known = vec![usbipd_state::UsbipdDevice {
            busid: "1-4".into(),
            id: "1a86:7523".parse().unwrap(),
            description: "USB-SERIAL CH340".into(),
            bound: false,
            attached: false,
        }];
        let listed = list_devices(&paths, &[], Some(known), &HashMap::new());
        assert_eq!(listed[0].granted_to, vec!["web"]);
        assert!(listed[0].bind_command.is_some());
    }

    #[test]
    fn a_shared_row_borrows_the_product_name_usbipd_knows_for_it() {
        let (_tmp, paths) = paths_with_sandboxes(&[]);
        let shared = [upstream_device("12-4", "303a:1001")];
        let known = vec![usbipd_state::UsbipdDevice {
            busid: "12-4".to_string(),
            id: "303a:1001".parse().unwrap(),
            description: "USB JTAG/serial debug unit".to_string(),
            bound: true,
            attached: false,
        }];
        let out = list_devices(&paths, &shared, Some(known), &HashMap::new());
        assert_eq!(out.len(), 1, "a bound device must not be listed twice");
        assert_eq!(out[0].description, "USB JTAG/serial debug unit");
    }

    #[test]
    fn a_shared_row_keeps_its_own_description_when_usbipd_offers_no_better_name() {
        let (_tmp, paths) = paths_with_sandboxes(&[]);
        let shared = [upstream_device("12-4", "303a:1001")];
        let out = list_devices(&paths, &shared, None, &HashMap::new());
        assert_eq!(
            out[0].description, "USB Serial Converter",
            "expected the unenriched fallback, got {:?}",
            out[0].description
        );
    }

    #[test]
    fn a_missing_usbipd_table_just_yields_the_shared_devices() {
        let (_t, paths) = paths_with_sandboxes(&[]);
        let listed = list_devices(
            &paths,
            &[upstream_device("3-2", "0403:6001")],
            None,
            &HashMap::new(),
        );
        assert_eq!(listed.len(), 1);
    }
}
