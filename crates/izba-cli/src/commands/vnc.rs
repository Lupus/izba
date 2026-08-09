//! `izba vnc` — enable/disable the KasmVNC desktop and reach it once it's up.
//!
//! Credentialed-URL discipline (spec 2026-08-09): `SandboxDetail.vnc_url`
//! carries the desktop's plaintext password in its userinfo. `izba vnc url`
//! (and `izba vnc open`, which never prints it at all) are the ONLY surfaces
//! allowed to expose it — `izba status` shows state only (see `status.rs`).

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse, SandboxDetail};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[derive(Debug, Subcommand)]
pub enum VncCmd {
    /// Enable VNC on a sandbox (a running sandbox needs a restart to boot it)
    On {
        /// Sandbox name
        name: String,
    },
    /// Disable VNC on a sandbox (a running sandbox needs a restart to drop it)
    Off {
        /// Sandbox name
        name: String,
    },
    /// Print the credentialed VNC URL for a running desktop
    Url {
        /// Sandbox name
        name: String,
    },
    /// Open the VNC URL in the platform's default browser
    Open {
        /// Sandbox name
        name: String,
    },
}

// reason: drives a live daemon (VncSet/Inspect RPCs) end to end and, for
// `Open`, hands the URL to the platform opener — nothing here is meaningfully
// assertable from a unit test. The decision logic it calls into
// (`url_or_reason`, `dead_desktop_warning`, `restart_required_line`) is pure
// and unit-tested separately, per the `status.rs` `run`/`render` split.
#[mutants::skip]
pub fn run(paths: &Paths, cmd: &VncCmd) -> Result<i32> {
    match cmd {
        VncCmd::On { name } => vnc_set(paths, name, true),
        VncCmd::Off { name } => vnc_set(paths, name, false),
        VncCmd::Url { name } => {
            let det = inspect(paths, name)?;
            match url_or_reason(&det) {
                Ok(url) => {
                    if let Some(w) = disabled_but_still_running_warning(&det) {
                        eprintln!("{w}");
                    }
                    if let Some(w) = dead_desktop_warning(&det) {
                        eprintln!("{w}");
                    }
                    println!("{url}");
                    Ok(0)
                }
                Err(reason) => bail!(reason),
            }
        }
        VncCmd::Open { name } => {
            let det = inspect(paths, name)?;
            match url_or_reason(&det) {
                Ok(url) => {
                    if let Some(w) = disabled_but_still_running_warning(&det) {
                        eprintln!("{w}");
                    }
                    if let Some(w) = dead_desktop_warning(&det) {
                        eprintln!("{w}");
                    }
                    match platform_open(&url) {
                        Ok(code) => Ok(code),
                        Err(e) => {
                            // Folded minor (c): a missing/failing platform
                            // opener (headless host, no `xdg-open` installed)
                            // must not swallow the URL — fall back to
                            // printing it, same as `vnc url`, rather than
                            // failing with nothing actionable to copy.
                            eprintln!(
                                "note: could not launch the platform URL opener ({e}); \
                                 open this URL yourself:"
                            );
                            println!("{url}");
                            Ok(0)
                        }
                    }
                }
                Err(reason) => bail!(reason),
            }
        }
    }
}

/// `On`/`Off`: flip `config.vnc` via `VncSet`, then re-Inspect so the restart
/// guidance reflects the daemon's actual (post-flip) truth rather than a
/// client-side guess.
fn vnc_set(paths: &Paths, name: &str, enabled: bool) -> Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    super::expect_ok(client.request(
        &DaemonRequest::VncSet {
            name: name.to_string(),
            enabled,
        },
        &mut |_| {},
    )?)?;
    println!(
        "vnc {} for '{name}'",
        if enabled { "enabled" } else { "disabled" }
    );
    let det = inspect(paths, name)?;
    if det.vnc_restart_required {
        eprintln!("{}", restart_required_line(name));
    }
    Ok(0)
}

fn inspect(paths: &Paths, name: &str) -> Result<SandboxDetail> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(&DaemonRequest::Inspect { name: name.into() }, &mut |_| {})? {
        DaemonResponse::Inspect(det) => Ok(det),
        DaemonResponse::Error { message } => bail!(message),
        other => bail!("unexpected daemon reply: {other:?}"),
    }
}

/// Hand the credentialed URL to the platform's default browser.
///
/// Folded minor (d): this puts the plaintext VNC password (in the URL's
/// userinfo) into the opener's argv — visible in `/proc/<pid>/cmdline` for
/// the process's short lifetime — and into the browser's history/address
/// bar, same as any other credentialed URL a human opens by hand. Accepted
/// as a single-user-desktop tradeoff: izba's threat model is a hostile
/// GUEST, not a hostile co-tenant on the operator's own desktop session.
///
/// Folded minor (e): on Windows, `cmd /C start "" <url>` is safe against
/// argument-injection specifically BECAUSE the URL's only variable part is
/// the password, which is drawn from `vnc::PASSWORD_ALPHABET`
/// (`[A-Za-z0-9]`, no shell metacharacters) and the URL carries no query
/// string — if either of those ever changes, this call needs revisiting.
// reason: spawns the OS's URL opener (a real subprocess/browser) — nothing
// about a successful launch is assertable from a unit test.
#[mutants::skip]
fn platform_open(url: &str) -> Result<i32> {
    let status = if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
    } else {
        std::process::Command::new("xdg-open").arg(url).status()
    }
    .context("launching the platform URL opener")?;
    if status.success() {
        Ok(0)
    } else {
        bail!("the platform URL opener exited with {status}");
    }
}

/// The `vnc: restart required — …` line `On`/`Off` print when the sandbox is
/// running and its live run is behind the just-persisted `config.vnc`
/// (`det.vnc_restart_required`, which `handle_vnc_set`'s `needs_vnc_restart`
/// computes bidirectionally — enabling OR disabling both need one). Pure so
/// the wording is unit-tested without a daemon.
fn restart_required_line(name: &str) -> String {
    format!("vnc: restart required — stop and start '{name}' to apply")
}

/// The URL to print for `vnc url`/`vnc open`, or the reason one can't be
/// printed yet.
///
/// `det.vnc_url` is checked FIRST, ahead of `det.vnc` (Task 11 review I4,
/// controller ruling): `Inspect` keys `vnc_url` on the live RELAY, never on
/// `config.vnc` alone, so a `vnc off` against an already-running sandbox
/// flips `det.vnc` to `false` immediately while the desktop it booted with —
/// and its relay — are still live. That desktop is real and reachable; the
/// honest answer is to hand back its URL (the caller pairs this with
/// `disabled_but_still_running_warning`), not to claim VNC is "not enabled".
///
/// Once `vnc_url` is ruled out, the remaining cases:
/// - not configured at all → tell the user how to turn it on;
/// - configured but the sandbox isn't running → tell them how to start it;
/// - configured and running but the live run booted without it (a `vnc on`
///   since the last boot, `vnc_restart_required`) → no relay exists yet, so
///   there's no URL to give; tell them to restart.
pub(crate) fn url_or_reason(det: &SandboxDetail) -> std::result::Result<String, String> {
    if let Some(url) = &det.vnc_url {
        return Ok(url.clone());
    }
    if !det.vnc {
        return Err(format!(
            "vnc not enabled — run `izba vnc on {}` (restart required if running)",
            det.name
        ));
    }
    if det.status != "running" {
        return Err(format!("sandbox not running — `izba start {}`", det.name));
    }
    Err(restart_required_line(&det.name))
}

/// The stderr warning `vnc url`/`vnc open` print alongside a working relay
/// URL when the guest's KasmVNC process isn't actually answering behind it —
/// the relay/websocket still connects, but nothing useful is on the other
/// end, and the guest log is the only lead. Pure so the wording is
/// unit-tested without a daemon.
fn dead_desktop_warning(det: &SandboxDetail) -> Option<String> {
    if det.vnc_url.is_some() && !det.vnc_running {
        Some(format!(
            "warning: the desktop is not answering (guest log: /var/log/izba-vnc.log \
             inside the sandbox — `izba exec {} -- cat /var/log/izba-vnc.log`)",
            det.name
        ))
    } else {
        None
    }
}

/// The stderr warning `vnc url`/`vnc open` print alongside a working relay
/// URL when `config.vnc` has since moved AHEAD of the live run — `vnc off`
/// against an already-running sandbox flips `det.vnc` immediately, but the
/// booted desktop (and its relay) are still up, so `url_or_reason` still
/// hands back the URL. Pure so the wording is unit-tested without a daemon.
fn disabled_but_still_running_warning(det: &SandboxDetail) -> Option<String> {
    if !det.vnc && det.vnc_url.is_some() {
        Some("warning: vnc is disabled in config; this desktop stops at the next restart".into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(vnc: bool, status: &str, vnc_running: bool, vnc_url: Option<&str>) -> SandboxDetail {
        SandboxDetail {
            name: "web".into(),
            image_ref: "ubuntu:24.04".into(),
            image_digest: "sha256:abc".into(),
            cpus: 2,
            mem_mb: 4096,
            workspace: "/ws".into(),
            status: status.into(),
            ports: vec![],
            volumes: vec![],
            confinement: None,
            container: None,
            user_fallback: None,
            docker: false,
            vnc,
            vnc_running,
            vnc_url: vnc_url.map(String::from),
            vnc_restart_required: false,
        }
    }

    #[test]
    fn url_or_reason_when_not_enabled() {
        let det = detail(false, "running", false, None);
        let err = url_or_reason(&det).unwrap_err();
        assert_eq!(
            err,
            "vnc not enabled — run `izba vnc on web` (restart required if running)"
        );
    }

    #[test]
    fn url_or_reason_when_enabled_but_stopped() {
        let det = detail(true, "stopped", false, None);
        let err = url_or_reason(&det).unwrap_err();
        assert_eq!(err, "sandbox not running — `izba start web`");
    }

    #[test]
    fn url_or_reason_when_enabled_running_but_not_yet_booted_with_it() {
        // vnc_restart_required-shaped state: config says on, sandbox is
        // running, but the live run booted without it — no relay, no URL.
        let det = detail(true, "running", false, None);
        let err = url_or_reason(&det).unwrap_err();
        assert_eq!(err, "vnc: restart required — stop and start 'web' to apply");
    }

    #[test]
    fn url_or_reason_when_enabled_running_and_relayed() {
        let det = detail(
            true,
            "running",
            true,
            Some("http://izba:s3cr3t@127.0.0.1:4444/"),
        );
        assert_eq!(
            url_or_reason(&det).unwrap(),
            "http://izba:s3cr3t@127.0.0.1:4444/"
        );
    }

    #[test]
    fn url_or_reason_still_returns_the_url_after_a_live_off() {
        // Task 11 review I4: `vnc off` against an already-running sandbox
        // flips `det.vnc` to false immediately, but `vnc_url` is keyed on the
        // live relay, not on config — so the desktop is still real and
        // reachable, and the honest answer is its URL, not "not enabled".
        let det = detail(
            false,
            "running",
            true,
            Some("http://izba:s3cr3t@127.0.0.1:4444/"),
        );
        assert_eq!(
            url_or_reason(&det).unwrap(),
            "http://izba:s3cr3t@127.0.0.1:4444/"
        );
    }

    #[test]
    fn disabled_but_still_running_warning_fires_after_a_live_off() {
        let det = detail(
            false,
            "running",
            true,
            Some("http://izba:s3cr3t@127.0.0.1:4444/"),
        );
        let w = disabled_but_still_running_warning(&det).expect("must warn");
        assert!(w.contains("disabled in config"), "{w}");
        assert!(w.contains("next restart"), "{w}");
    }

    #[test]
    fn disabled_but_still_running_warning_silent_when_enabled() {
        let det = detail(
            true,
            "running",
            true,
            Some("http://izba:s3cr3t@127.0.0.1:4444/"),
        );
        assert!(disabled_but_still_running_warning(&det).is_none());
    }

    #[test]
    fn disabled_but_still_running_warning_silent_when_no_relay_at_all() {
        let det = detail(false, "stopped", false, None);
        assert!(disabled_but_still_running_warning(&det).is_none());
    }

    #[test]
    fn dead_desktop_warning_fires_when_relayed_but_not_answering() {
        let det = detail(
            true,
            "running",
            false,
            Some("http://izba:s3cr3t@127.0.0.1:4444/"),
        );
        let w = dead_desktop_warning(&det).expect("must warn");
        assert!(w.contains("/var/log/izba-vnc.log"), "{w}");
        assert!(
            w.contains("izba exec web -- cat /var/log/izba-vnc.log"),
            "{w}"
        );
    }

    #[test]
    fn dead_desktop_warning_silent_when_answering() {
        let det = detail(
            true,
            "running",
            true,
            Some("http://izba:s3cr3t@127.0.0.1:4444/"),
        );
        assert!(dead_desktop_warning(&det).is_none());
    }

    #[test]
    fn dead_desktop_warning_silent_when_no_relay_at_all() {
        // No URL to attach the warning to — url_or_reason already carries
        // the actionable message for this case (restart required).
        let det = detail(true, "running", false, None);
        assert!(dead_desktop_warning(&det).is_none());
    }

    #[test]
    fn restart_required_line_names_the_sandbox() {
        assert_eq!(
            restart_required_line("web"),
            "vnc: restart required — stop and start 'web' to apply"
        );
    }
}
