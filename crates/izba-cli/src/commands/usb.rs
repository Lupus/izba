//! `izba usb` — configure a usbip upstream and grant devices to sandboxes.
//!
//! Deliberately thin: izba never runs `usbipd bind` and never elevates. When a
//! device needs sharing, izba prints the exact command for the human to run
//! themselves. Wrapping usbipd-win would mean izba asking for Administrator on
//! the user's behalf, which is a bigger ask than this feature is worth.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{bail, Result};
use clap::Subcommand;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, UsbDeviceInfo};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use izba_core::usb::settings::DEFAULT_UPSTREAM_PORT;

#[derive(Debug, Subcommand)]
pub enum UsbCmd {
    /// Show or set the usbip server izba dials
    #[command(subcommand)]
    Upstream(UpstreamCmd),
    /// List devices the upstream shares (and ones it knows but has not shared)
    List,
    /// Grant one device to one sandbox (requires typing the device id back)
    Allow {
        /// Sandbox name
        name: String,
        /// Device to grant, as VID:PID (e.g. 0403:6001)
        #[arg(short, long)]
        device: String,
        /// Pin the grant to one busid, when two identical devices are present
        #[arg(long)]
        busid: Option<String>,
        /// Non-interactive confirmation; must equal --device
        #[arg(long)]
        confirm: Option<String>,
    },
    /// Withdraw a device grant from a sandbox
    Revoke {
        /// Sandbox name
        name: String,
        /// Device to revoke, as VID:PID
        #[arg(short, long)]
        device: String,
    },
    /// Attach a granted device to a running sandbox
    Attach {
        /// Sandbox name
        name: String,
        /// Device to attach, as VID:PID
        #[arg(short, long)]
        device: String,
    },
    /// Detach a device from a running sandbox
    Detach {
        /// Sandbox name
        name: String,
        /// Device to detach, as VID:PID
        #[arg(short, long)]
        device: String,
    },
    /// Show a sandbox's device grants
    Status {
        /// Sandbox name
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum UpstreamCmd {
    /// Print the configured upstream and how much izba trusts it
    Show,
    /// Point izba at a usbip server (HOST or HOST:PORT; default port 3240)
    Set {
        /// HOST, HOST:PORT, or [IPV6]:PORT
        target: String,
        /// Permit a globally-routable upstream (NOT recommended)
        #[arg(long)]
        allow_remote: bool,
    },
}

pub fn run(paths: &Paths, cmd: &UsbCmd) -> Result<i32> {
    match cmd {
        UsbCmd::Upstream(UpstreamCmd::Show) => upstream_show(paths),
        UsbCmd::Upstream(UpstreamCmd::Set {
            target,
            allow_remote,
        }) => upstream_set(paths, target, *allow_remote),
        UsbCmd::List => list(paths),
        UsbCmd::Allow {
            name,
            device,
            busid,
            confirm,
        } => allow(paths, name, device, busid.as_deref(), confirm.as_deref()),
        UsbCmd::Revoke { name, device } => revoke(paths, name, device),
        UsbCmd::Attach { name, device } => attach(paths, name, device, true),
        UsbCmd::Detach { name, device } => attach(paths, name, device, false),
        UsbCmd::Status { name } => status(paths, name),
    }
}

/// Split `HOST` / `HOST:PORT` / `[V6]:PORT`, defaulting the port.
///
/// A bare IPv6 literal is full of colons, so the bracket form is the only way
/// to give one a port — and an unbracketed literal must NOT be read as
/// host-plus-port.
pub(crate) fn parse_upstream_arg(s: &str) -> Result<(String, u16)> {
    let bad = || anyhow::anyhow!("expected HOST, HOST:PORT, or [IPV6]:PORT, got '{s}'");
    let port = |p: &str| -> Result<u16> {
        match p.parse::<u16>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(anyhow::anyhow!("'{p}' is not a valid TCP port")),
        }
    };
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(bad)?;
        if host.is_empty() {
            return Err(bad());
        }
        return match tail.strip_prefix(':') {
            Some(p) => Ok((host.to_string(), port(p)?)),
            None if tail.is_empty() => Ok((host.to_string(), DEFAULT_UPSTREAM_PORT)),
            None => Err(bad()),
        };
    }
    if s.is_empty() {
        return Err(bad());
    }
    // Two or more colons means an unbracketed IPv6 literal: no port here.
    if s.matches(':').count() > 1 {
        return Ok((s.to_string(), DEFAULT_UPSTREAM_PORT));
    }
    match s.split_once(':') {
        Some((host, p)) if !host.is_empty() => Ok((host.to_string(), port(p)?)),
        Some(_) => Err(bad()),
        None => Ok((s.to_string(), DEFAULT_UPSTREAM_PORT)),
    }
}

/// The loud consent banner. Every clause is a consequence the human is
/// accepting, not decoration.
pub(crate) fn consent_banner(sandbox: &str, device: &str, description: &str) -> String {
    let what = if description.is_empty() {
        device.to_string()
    } else {
        format!("{device} ({description})")
    };
    format!(
        "\n⚠  Granting {what} to sandbox '{sandbox}'.\n\
         \n\
         The agent in that sandbox gets raw, transfer-level access to this device.\n\
         It can reflash it, change its firmware, or permanently damage it.\n\
         \n\
         USB traffic is NOT visible to the egress firewall: `izba netlog` will not\n\
         show what crosses this link, and no allow-list applies to it.\n\
         \n\
         While attached, the device is unavailable to the host and to every other\n\
         sandbox.\n\
         \n\
         izba cannot verify that this is the physical object in front of you — the\n\
         USB/IP protocol carries no serial number, and a device asserts its own id.\n"
    )
}

/// Whether `typed` confirms `device`.
///
/// Case-insensitive and whitespace-trimmed: the human is retyping an id they
/// read off a listing, and the device is what is being confirmed, not the
/// formatting.
pub(crate) fn confirm_matches(device: &str, typed: &str) -> bool {
    typed.trim().eq_ignore_ascii_case(device.trim())
}

/// Decide whether a grant may proceed without prompting.
///
/// `Ok(true)` ⇒ already confirmed via the flag. `Ok(false)` ⇒ interactive, so
/// the caller must prompt. A script cannot answer a prompt, so running without
/// a terminal and without the flag names the flag instead of hanging or
/// silently aborting at exit 0.
pub(crate) fn resolve_confirmation(
    device: &str,
    confirm: Option<&str>,
    is_tty: bool,
) -> Result<bool> {
    match confirm {
        Some(c) if confirm_matches(device, c) => Ok(true),
        Some(c) => bail!("--confirm '{c}' does not match --device '{device}'"),
        None if is_tty => Ok(false),
        None => bail!(
            "refusing to grant {device} without confirmation: stdin is not a \
             terminal — re-run with --confirm {device}"
        ),
    }
}

fn upstream_show(paths: &Paths) -> Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::UsbUpstreamShow, &mut |_| {})? {
        DaemonResponse::UsbUpstream { upstream: None } => {
            println!(
                "no usbip upstream configured\n\
                 \n\
                 Set one with:  izba usb upstream set <host>\n\
                 On Windows, that host is usually your own machine across the WSL\n\
                 boundary; on Linux, 127.0.0.1 if usbipd runs alongside izba."
            );
            Ok(0)
        }
        DaemonResponse::UsbUpstream {
            upstream: Some(u), ..
        } => {
            println!("upstream: {}:{}", u.host, u.port);
            match &u.resolved {
                Some(ip) if *ip != u.host => println!("resolves to: {ip}"),
                Some(_) => {}
                None => println!("resolves to: (does not resolve)"),
            }
            println!("trust: {}", u.trust);
            if let Some(w) = &u.warning {
                eprintln!("\n{w}");
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

fn upstream_set(paths: &Paths, target: &str, allow_remote: bool) -> Result<i32> {
    let (host, port) = parse_upstream_arg(target)?;
    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::UsbUpstreamSet {
            host: host.clone(),
            port,
            allow_remote,
        },
        &mut |_| {},
    )?)?;
    println!("usbip upstream set to {host}:{port}");
    // Re-read it so the trust classification and any warning are printed by the
    // one code path that owns them.
    upstream_show(paths)
}

/// Render the device table. Separate from the daemon call so the layout is
/// unit-testable.
pub(crate) fn render_devices(devices: &[UsbDeviceInfo]) -> String {
    if devices.is_empty() {
        return "the upstream shares no devices\n\
                \n\
                Plug one in and share it on the USB host, then run `izba usb list`\n\
                again. On Windows: `usbipd list` to find its busid, then\n\
                `usbipd bind --busid <busid>` in an elevated shell.\n"
            .to_string();
    }
    let mut out = format!(
        "{:<10} {:<12} {:<7} {:<14} {}\n",
        "BUSID", "DEVICE", "SHARED", "GRANTED TO", "DESCRIPTION"
    );
    for d in devices {
        let granted = if d.granted_to.is_empty() {
            "-".to_string()
        } else {
            d.granted_to.join(",")
        };
        out.push_str(&format!(
            "{:<10} {:<12} {:<7} {:<14} {}\n",
            d.busid,
            d.device,
            if d.shared { "yes" } else { "no" },
            granted,
            d.description
        ));
        if let Some(cmd) = &d.bind_command {
            out.push_str(&format!(
                "  ↳ not shared yet — run this elevated on the USB host:  {cmd}\n"
            ));
        }
    }
    out
}

fn list(paths: &Paths) -> Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::UsbListDevices, &mut |_| {})? {
        DaemonResponse::UsbDevices { devices } => {
            print!("{}", render_devices(&devices));
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

fn allow(
    paths: &Paths,
    name: &str,
    device: &str,
    busid: Option<&str>,
    confirm: Option<&str>,
) -> Result<i32> {
    // Parse before prompting: making someone read the whole banner and retype an
    // id, only to be told the id was malformed, is a bad trade.
    let id: izba_core::usb::DeviceId = device.parse()?;
    let device = id.to_string();

    // One decision, one branch: either the flag already confirmed it, or the
    // human types the id back after reading the banner.
    let confirmed = match resolve_confirmation(&device, confirm, std::io::stdin().is_terminal())? {
        true => true,
        false => {
            eprint!("{}", consent_banner(name, &device, ""));
            eprint!("\nType the device id to confirm: ");
            std::io::stderr().flush()?;
            prompt_confirms(&device)?
        }
    };
    if !confirmed {
        eprintln!("aborted");
        return Ok(1);
    }

    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::UsbAllow {
            name: name.to_string(),
            device: device.clone(),
            busid_pin: busid.map(|s| s.to_string()),
        },
        &mut |_| {},
    )?)?;
    println!("granted {device} to '{name}'");
    Ok(0)
}

// reason: thin real-stdin wrapper (locks stdin, reads one line) — the decision
// logic lives in `confirm_matches`, which is fully unit-tested.
#[mutants::skip]
fn prompt_confirms(device: &str) -> Result<bool> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(confirm_matches(device, &line))
}

fn revoke(paths: &Paths, name: &str, device: &str) -> Result<i32> {
    let id: izba_core::usb::DeviceId = device.parse()?;
    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::UsbRevoke {
            name: name.to_string(),
            device: id.to_string(),
        },
        &mut |_| {},
    )?)?;
    println!("revoked {id} from '{name}'");
    Ok(0)
}

/// Attach or detach an already-granted device.
///
/// No consent prompt: consent was given at `allow` time, and attaching a device
/// the user already granted is not a second decision. The attach line does say
/// what it costs elsewhere — the device leaves the host while it is held —
/// because that is a side effect on hardware outside the sandbox, and nothing
/// else in the session will mention it.
fn attach(paths: &Paths, name: &str, device: &str, attach: bool) -> Result<i32> {
    let id: izba_core::usb::DeviceId = device.parse()?;
    let mut client = DaemonClient::connect(paths)?;
    let req = if attach {
        DaemonRequest::UsbAttach {
            name: name.to_string(),
            device: id.to_string(),
        }
    } else {
        DaemonRequest::UsbDetach {
            name: name.to_string(),
            device: id.to_string(),
        }
    };
    super::expect_ok(client.request(&req, &mut |_| {})?)?;
    if attach {
        println!("attached {id} to '{name}' — it appears at /dev/izba inside the sandbox");
        println!(
            "  the device is unavailable to the host and to other sandboxes until you detach it"
        );
    } else {
        println!("detached {id} from '{name}'");
    }
    Ok(0)
}

fn status(paths: &Paths, name: &str) -> Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(
        &DaemonRequest::UsbStatus {
            name: name.to_string(),
        },
        &mut |_| {},
    )? {
        DaemonResponse::UsbStatus { grants } => {
            if grants.is_empty() {
                println!("'{name}' has no USB device grants");
            } else {
                println!("{:<12} {:<8} DESCRIPTION", "DEVICE", "BUSID");
                for g in &grants {
                    println!(
                        "{:<12} {:<8} {}",
                        g.device,
                        g.busid_pin.as_deref().unwrap_or("-"),
                        g.description
                    );
                }
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_banner_states_every_consequence_of_a_grant() {
        let b = consent_banner("web", "0403:6001", "USB Serial Converter");
        for must in [
            "0403:6001",
            "web",
            "USB Serial Converter",
            // Raw transfer-level access: reflash, brick.
            "reflash",
            // USB traffic is invisible to the egress firewall (F-USB-7).
            "egress firewall",
            // Exclusive while attached.
            "unavailable to the host",
            // F-USB-3: izba can only relay what the server asserts.
            "cannot verify",
        ] {
            assert!(b.contains(must), "banner must mention {must:?}:\n{b}");
        }
    }

    #[test]
    fn the_banner_omits_an_empty_description_rather_than_printing_empty_parens() {
        let b = consent_banner("web", "0403:6001", "");
        assert!(b.contains("Granting 0403:6001 to"), "{b}");
        assert!(!b.contains("()"), "{b}");
    }

    #[test]
    fn confirmation_requires_the_exact_device_id_typed_back() {
        let id = "0403:6001";
        assert!(confirm_matches(id, "0403:6001"));
        assert!(confirm_matches(id, " 0403:6001\n"), "trims whitespace");
        for wrong in ["", "y", "yes", "0403:6002", "1a86:7523", "0403", "6001"] {
            assert!(!confirm_matches(id, wrong), "must reject {wrong:?}");
        }
    }

    #[test]
    fn an_uppercase_confirmation_of_the_same_device_is_accepted() {
        // The human is retyping an id off a listing; case is not what is being
        // confirmed, the device is.
        assert!(confirm_matches("1a86:7523", "1A86:7523"));
    }

    #[test]
    fn a_scripted_grant_needs_the_confirm_flag() {
        let err = resolve_confirmation("0403:6001", None, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--confirm"), "{err}");
        assert!(err.contains("not a terminal"), "{err}");
    }

    #[test]
    fn a_scripted_grant_with_a_matching_confirm_flag_proceeds() {
        assert!(resolve_confirmation("0403:6001", Some("0403:6001"), false).unwrap());
    }

    #[test]
    fn a_scripted_grant_with_a_mismatched_confirm_flag_is_refused() {
        let err = resolve_confirmation("0403:6001", Some("1a86:7523"), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn an_interactive_grant_without_the_flag_falls_through_to_the_prompt() {
        assert!(!resolve_confirmation("0403:6001", None, true).unwrap());
    }

    #[test]
    fn the_confirm_flag_is_honoured_on_a_terminal_too() {
        // Passing --confirm from an interactive shell must skip the prompt, not
        // ask twice.
        assert!(resolve_confirmation("0403:6001", Some("0403:6001"), true).unwrap());
    }

    #[test]
    fn upstream_arg_parses_host_and_optional_port() {
        assert_eq!(
            parse_upstream_arg("127.0.0.1").unwrap(),
            ("127.0.0.1".to_string(), 3240)
        );
        assert_eq!(
            parse_upstream_arg("host.local:1234").unwrap(),
            ("host.local".to_string(), 1234)
        );
        assert_eq!(
            parse_upstream_arg("[::1]:9").unwrap(),
            ("::1".to_string(), 9)
        );
        assert_eq!(
            parse_upstream_arg("[fd00::1]").unwrap(),
            ("fd00::1".to_string(), 3240)
        );
    }

    #[test]
    fn a_bare_ipv6_literal_is_a_host_not_a_host_and_port() {
        // "fd00::1" ends in ":1"; reading that as port 1 would silently dial the
        // wrong place.
        assert_eq!(
            parse_upstream_arg("fd00::1").unwrap(),
            ("fd00::1".to_string(), 3240)
        );
        assert_eq!(
            parse_upstream_arg("::1").unwrap(),
            ("::1".to_string(), 3240)
        );
    }

    #[test]
    fn a_malformed_upstream_arg_is_refused() {
        for bad in [
            "",
            ":",
            ":3240",
            "host:",
            "host:0",
            "host:99999",
            "host:abc",
            "[::1",
            "[]:1",
            "[::1]x",
        ] {
            assert!(parse_upstream_arg(bad).is_err(), "must reject {bad:?}");
        }
    }

    fn dev(busid: &str, device: &str, shared: bool, granted: &[&str]) -> UsbDeviceInfo {
        UsbDeviceInfo {
            busid: busid.into(),
            device: device.into(),
            description: "USB Serial Converter".into(),
            shared,
            granted_to: granted.iter().map(|s| s.to_string()).collect(),
            bind_command: (!shared).then(|| format!("usbipd bind --busid {busid}")),
        }
    }

    #[test]
    fn an_empty_listing_says_how_to_share_a_device() {
        // "no devices" with no next step is the failure mode that sends people
        // to the issue tracker.
        let out = render_devices(&[]);
        assert!(out.contains("usbipd bind"), "{out}");
    }

    #[test]
    fn a_shared_device_lists_its_holders_and_needs_no_bind_command() {
        let out = render_devices(&[dev("3-2", "0403:6001", true, &["web", "api"])]);
        assert!(out.contains("3-2"), "{out}");
        assert!(out.contains("0403:6001"), "{out}");
        assert!(out.contains("web,api"), "{out}");
        assert!(!out.contains("usbipd bind"), "{out}");
    }

    #[test]
    fn an_unshared_device_carries_the_exact_command_to_share_it() {
        let out = render_devices(&[dev("1-4", "1a86:7523", false, &[])]);
        assert!(out.contains("usbipd bind --busid 1-4"), "{out}");
        assert!(out.contains(" no "), "must render as unshared: {out}");
    }

    #[test]
    fn a_device_nobody_holds_renders_a_dash_rather_than_a_blank_column() {
        let out = render_devices(&[dev("3-2", "0403:6001", true, &[])]);
        assert!(out.contains(" - "), "{out}");
    }
}
