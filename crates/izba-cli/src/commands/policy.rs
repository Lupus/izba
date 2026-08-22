use anyhow::Context;
use clap::Subcommand;
use izba_core::daemon::egress::config::{
    edit_policy_file, try_edit_policy_file, usbip_exposure_warning, Access, AllowEntry,
    EgressPolicyConfig, GitRule, GitTarget, Protocol,
};
use izba_core::daemon::egress::inspect::InspectionTable;
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Print the effective allow-list (host + ports) and enforce posture (on/off)
    Show {
        /// Sandbox name (or dir)
        name: String,
    },
    /// Add HOST to the sandbox's HTTP(S) allow-list. A bare HOST opens the web ports (80 + 443); HOST:PORT opens exactly that port; access is read-write unless --read
    /// (NOTE: the opposite default of `policy git allow`, which grants read-only unless --write). Every invocation echoes the effective access level granted.
    /// `*.HOST` matches exactly one subdomain label and `**.HOST` matches any depth; the apex HOST is never matched by a wildcard and needs its own entry.
    /// To actually block anything else, enforcement must be on (see `enforce`).
    /// A grant that would extend a host's declared `protocol: tcp` pinning passthrough to a
    /// port it does not already cover is REFUSED unless --passthrough acknowledges it.
    /// Auto-reloads a running sandbox.
    Allow {
        /// Sandbox name (or dir)
        name: String,
        /// Destination to allow: HOST, *.HOST, **.HOST, or HOST:PORT (bare host = web ports 80+443; :PORT = exactly that port)
        target: String,
        /// Restrict to read-only HTTP access (GET/HEAD only); default is read-write
        #[arg(long)]
        read: bool,
        /// Acknowledge that the new port(s) inherit this host's declared `protocol: tcp`
        /// pinning passthrough — spliced opaquely, with no L7 rules, no request audit and
        /// no upstream certificate verification. Without it, such a grant is REFUSED.
        /// Has no effect on a host that declares no passthrough.
        #[arg(long)]
        passthrough: bool,
    },
    /// Remove HOST from the allow-list. A bare HOST removes the web ports (80 + 443); HOST:PORT removes exactly that port; auto-reloads.
    /// `*.HOST` matches exactly one subdomain label and `**.HOST` matches any depth; the apex HOST is never matched by a wildcard and needs its own entry.
    Block {
        /// Sandbox name (or dir)
        name: String,
        /// Destination to remove: HOST, *.HOST, **.HOST, or HOST:PORT (bare host = web ports 80+443; :PORT = exactly that port)
        target: String,
    },
    /// Seed the allow-list from the sandbox's currently-allowed traffic, then reload
    Enable {
        /// Sandbox name (or dir)
        name: String,
    },
    /// Re-read a sandbox's policy.yaml and apply it to new connections (no
    /// restart). That file is the managed truth, kept host-side at
    /// `<izba data dir>/sandboxes/<name>/policy.yaml`; edit it there and reload
    /// to change settings this CLI has no flag for, such as an entry's
    /// `protocol:`. `izba policy show` prints its effective contents
    Reload {
        /// Sandbox name (or dir)
        name: String,
    },
    /// Fine-grained git controls (clone/fetch/push per repo)
    #[command(subcommand)]
    Git(GitSub),
    /// Turn the firewall on (default-deny: only allow-listed egress) or off
    /// (log-only: everything allowed). A bare sandbox is off; an empty
    /// allow-list with enforce on denies all egress.
    Enforce {
        /// Sandbox name (or dir)
        name: String,
        /// on (default-deny) or off (log-only)
        state: EnforceState,
    },
}

#[derive(Debug, Subcommand)]
pub enum GitSub {
    /// Allow git on REPO (host/owner/repo, globs ok) or a whole HOST; access is read-only (clone/fetch) unless --write
    /// (NOTE: the opposite default of `policy allow`, which grants read-write unless --read). Every invocation echoes the effective access level granted.
    Allow {
        /// Sandbox name (or dir)
        name: String,
        /// Git target: REPO (host/owner/repo, globs ok) or a whole HOST
        target: String,
        /// Also allow push; default is read-only (clone/fetch)
        #[arg(long)]
        write: bool,
    },
    /// Remove a git rule for REPO/HOST
    Block {
        /// Sandbox name (or dir)
        name: String,
        /// Git target to remove: REPO (host/owner/repo) or HOST
        target: String,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum EnforceState {
    On,
    Off,
}

pub fn run(paths: &Paths, cmd: &PolicyCmd) -> anyhow::Result<i32> {
    match cmd {
        PolicyCmd::Show { name } => show(paths, name),
        PolicyCmd::Allow {
            name,
            target,
            read,
            passthrough,
        } => {
            let dir = require_sandbox_dir(paths, name)?;
            let (host, ports) = parse_target(target)?;
            let (cfg, pinned) = apply_allow_edit(&dir, &host, &ports, *read, *passthrough)?;
            let granted: Vec<AllowEntry> =
                cfg.entries_for_host(&host).into_iter().cloned().collect();
            print!("{}", render_allow_grant(&granted));
            if !pinned.is_empty() {
                eprint!("{}", render_pin_widening_warning(&host, &pinned));
            }
            warn_usbip_exposure(paths, &cfg);
            maybe_reload(paths, name);
            Ok(0)
        }
        PolicyCmd::Block { name, target } => {
            let dir = require_sandbox_dir(paths, name)?;
            let (host, ports) = parse_target(target)?;
            apply_block_edit(&dir, &host, &ports)?;
            maybe_reload(paths, name);
            Ok(0)
        }
        PolicyCmd::Enable { name } => enable(paths, name),
        PolicyCmd::Reload { name } => reload(paths, name),
        PolicyCmd::Git(GitSub::Allow {
            name,
            target,
            write,
        }) => {
            let access = if *write {
                Access::ReadWrite
            } else {
                Access::Read
            };
            let gt = GitTarget::parse(target);
            let dir = require_sandbox_dir(paths, name)?;
            edit_policy_file(&dir, |c| {
                c.git_allow(gt.clone(), access);
            })?;
            print!("{}", render_git_grant(&GitRule { target: gt, access }));
            maybe_reload(paths, name);
            Ok(0)
        }
        PolicyCmd::Git(GitSub::Block { name, target }) => {
            let gt = GitTarget::parse(target);
            let dir = require_sandbox_dir(paths, name)?;
            edit_policy_file(&dir, |c| {
                c.git_block(&gt);
            })?;
            maybe_reload(paths, name);
            Ok(0)
        }
        PolicyCmd::Enforce { name, state } => {
            let on = matches!(state, EnforceState::On);
            let dir = require_sandbox_dir(paths, name)?;
            edit_policy_file(&dir, |c| {
                c.set_enforce(on);
            })?;
            maybe_reload(paths, name);
            Ok(0)
        }
    }
}

/// Parse a `HOST` or `HOST:PORT` target. A bare `HOST` means the web ports
/// (80 + 443, `AllowEntry::DEFAULT_PORTS`) — the same meaning a bare host
/// has in `policy.yaml`; `HOST:PORT` means exactly that one port.
pub(crate) fn parse_target(s: &str) -> anyhow::Result<(String, Vec<u16>)> {
    match s.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .with_context(|| format!("invalid port in '{s}'"))?;
            Ok((host.to_string(), vec![port]))
        }
        None => Ok((s.to_string(), AllowEntry::DEFAULT_PORTS.to_vec())),
    }
}

/// Every policy verb addresses an existing sandbox. Fail with a clean domain
/// error — not a raw ENOENT that leaks the data-dir path — when it doesn't
/// exist (#82). Mirrors the guard `show`/`enable` already had.
fn require_sandbox_dir(paths: &Paths, name: &str) -> anyhow::Result<std::path::PathBuf> {
    let dir = paths.sandbox_dir(name);
    if !dir.exists() {
        anyhow::bail!("no such sandbox: {name}");
    }
    Ok(dir)
}

/// The daemon-free core of `policy allow`: refuse-or-grant, persisted in ONE
/// write. Returns the new config plus the ports that were added as pinning
/// passthroughs (empty for every ordinary grant), so the caller can echo them.
///
/// One write: grant the port(s), then (only when `read`) narrow the access
/// verb, all in the same closure. Folding both mutations into a single write
/// matters here — splitting them across two `edit_policy_file` calls would
/// leave a window where a crash between the writes persists the host at the
/// WIDER read-write default, which is the wrong failure direction for a
/// security-posture flag (#84 fix-wave finding 1).
///
/// The pinning-passthrough gate (#235) runs INSIDE that same closure, against
/// the config the grant is about to mutate, and BEFORE any mutation — so a
/// refusal leaves `policy.yaml` untouched (`try_edit_policy_file` writes
/// nothing on `Err`). `protocol` is stored per-ENTRY while the hatch is
/// semantically per-PORT, so appending a port to an entry declaring
/// `protocol: tcp` hands that port an opaque splice the operator never named:
/// no L7 rules, no request audit, no upstream certificate verification. That
/// transition passes no other gate — `policy allow` deliberately bypasses the
/// `izba diff`/`promote` weakening check (DP-6), `izba status` renders no
/// egress posture, and `izba policy show` is not on this command's path — so
/// this is the only place it can be caught. It therefore FAILS CLOSED: refused
/// unless `passthrough` explicitly acknowledges it, and loud when it does.
///
/// Whether a port would newly become a passthrough is asked of
/// `InspectionTable` and nothing else, so the answer is the datapath's own
/// fold (last-wins supersession, wildcard exclusion) rather than a second
/// reading of `protocol` — see `InspectionTable::widening_ports`. That table
/// is deliberately blind to the access verb, so a `--read` grant on a
/// hatch-carrying host is gated too, even though `access: read` cancels the
/// splice at the router: the narrowing is one `policy allow` away from being
/// undone, at which point the hatch springs to life on a port nobody named.
pub(crate) fn apply_allow_edit(
    sandbox_dir: &std::path::Path,
    host: &str,
    ports: &[u16],
    read: bool,
    passthrough: bool,
) -> anyhow::Result<(EgressPolicyConfig, Vec<u16>)> {
    let mut pinned: Vec<u16> = Vec::new();
    let cfg = try_edit_policy_file(sandbox_dir, |cfg| {
        let widened = InspectionTable::widening_ports(cfg, host, ports);
        if !widened.is_empty() && !passthrough {
            anyhow::bail!("{}", render_pin_refusal(host, &widened));
        }
        for &port in ports {
            cfg.allow(host, port);
        }
        if read {
            cfg.set_host_access(host, Access::Read);
        }
        pinned = widened;
        Ok(())
    })?;
    Ok((cfg, pinned))
}

/// `port 8080` / `ports 80, 443`, so neither message reads as machine output.
fn ports_phrase(ports: &[u16]) -> String {
    let list = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if ports.len() == 1 {
        format!("port {list}")
    } else {
        format!("ports {list}")
    }
}

/// `it`/`them` for a port list, so the follow-up clauses agree in number.
fn them(ports: &[u16]) -> &'static str {
    if ports.len() == 1 {
        "it"
    } else {
        "them"
    }
}

/// The refusal for an un-acknowledged hatch widening. Names the host, every
/// port at stake, what those ports would lose, and both ways forward — the
/// widening one and the inspected one.
fn render_pin_refusal(host: &str, ports: &[u16]) -> String {
    let phrase = ports_phrase(ports);
    let them = them(ports);
    format!(
        "'{host}' declares `protocol: tcp` (a TLS-pinning passthrough), so granting \
         {phrase} would splice {them} opaquely too: no L7 rules, no request audit, no \
         upstream certificate verification. You declared that hatch for the ports the \
         entry already lists, not for {phrase}.\n\
         \n\
         \x20 to add {phrase} as a pinning passthrough deliberately, re-run with \
         --passthrough\n\
         \x20 to keep {them} inspected, give {them} a separate entry in policy.yaml \
         (`izba policy show` prints the current one) and `izba policy reload`"
    )
}

/// The loud echo when `--passthrough` acknowledges the widening. `izba policy
/// show` is otherwise the only surface that reveals a hatch, and it is not on
/// this command's path — so this line carries that weight alone.
fn render_pin_widening_warning(host: &str, ports: &[u16]) -> String {
    format!(
        "\u{26A0} {} added to '{host}' as a pinning passthrough, inherited from its \
         declared `protocol: tcp`: spliced opaquely — no L7 rules, no request audit, \
         no upstream certificate verification.\n",
        ports_phrase(ports),
    )
}

/// The daemon-free core of `policy block`: persist the port removal(s) to
/// `policy.yaml`. (The `allow` side is inlined in `run()`'s `Allow` arm as a
/// single `edit_policy_file` closure — see the comment there — so this is
/// block-only now; it used to be a shared `Edit::{Allow,Block}` dispatcher.)
pub(crate) fn apply_block_edit(
    sandbox_dir: &std::path::Path,
    host: &str,
    ports: &[u16],
) -> anyhow::Result<()> {
    edit_policy_file(sandbox_dir, |cfg| {
        for &port in ports {
            let _ = cfg.block(host, port);
        }
    })?;
    Ok(())
}

/// The loud access-grant echo for `policy allow` (#149): one line per
/// post-edit entry matching the target host, always stating the effective
/// access level. Read-write points at `--read` (the narrowing flag) because
/// a user who learned "allow = read-only" from the git verb would otherwise
/// over-trust the grant; read spells out its GET/HEAD-only meaning. Pure
/// string builder (same pattern as `render_policy`) so it unit-tests
/// without a sandbox dir; `run()` prints the result verbatim.
fn render_allow_grant(entries: &[AllowEntry]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for e in entries {
        let ports = e
            .ports()
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let access = match e.access() {
            Access::Read => "read (HTTP GET/HEAD only)",
            Access::ReadWrite => "read-write (all methods; --read narrows to GET/HEAD)",
        };
        let _ = writeln!(out, "allowed {}  [{ports}]  access: {access}", e.host());
    }
    out
}

/// The loud access-grant echo for `policy git allow` (#149) — the mirror of
/// `render_allow_grant`, pointing read at `--write` (the widening flag) and
/// spelling out that read-write includes push.
fn render_git_grant(rule: &GitRule) -> String {
    let target = match &rule.target {
        GitTarget::Repo(s) => s.as_str(),
        GitTarget::Host(s) => s.as_str(),
    };
    let access = match rule.access {
        Access::Read => "read (clone/fetch only; --write also allows push)",
        Access::ReadWrite => "read-write (clone/fetch + push)",
    };
    format!("allowed git {target}  access: {access}\n")
}

fn show(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let dir = require_sandbox_dir(paths, name)?;
    let cfg = EgressPolicyConfig::load(&dir)?;
    print!("{}", render_policy(name, cfg.as_ref()));
    Ok(0)
}

/// Render a loaded policy config for `policy show`, as a pure string builder
/// so the rendering can be unit-tested without a sandbox dir. Every line ends
/// in `\n`; `show()` prints the result verbatim.
fn render_policy(name: &str, cfg: Option<&EgressPolicyConfig>) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    match cfg {
        None => {
            let _ = writeln!(out, "'{name}' has no egress policy (all egress allowed)");
        }
        Some(cfg) => {
            let enforce_str = if cfg.enforce { "on" } else { "off" };
            let _ = writeln!(out, "'{name}' egress policy (enforce: {enforce_str}):");
            if cfg.allow.is_empty() {
                // An empty allow-list denies everything only when enforcement
                // is ON: `EgressPolicyConfig::compile` returns AllowAll for
                // `enforce: false` whatever the list says. Reporting "deny
                // all" for a bare sandbox — the most common state anyone runs
                // `policy show` against — would misstate the posture in the
                // safe-looking direction, on the one surface that reveals it.
                if cfg.enforce {
                    let _ = writeln!(out, "  http: deny all (empty allow-list)");
                } else {
                    let _ = writeln!(out, "  http: all egress allowed (enforce off)");
                }
            } else {
                let _ = writeln!(out, "  http allow-list:");
                for e in &cfg.allow {
                    let ports = e
                        .ports()
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    let access_str = match e.access() {
                        Access::Read => "read",
                        Access::ReadWrite => "read-write",
                    };
                    // The inspectability axis (M5 §5). Silent when the entry
                    // declares nothing, so an existing policy renders exactly
                    // as it did; loud for the pinning hatch, which is the one
                    // value that gives enforcement up. `izba policy show` is
                    // the ONLY surface that reveals a pinning passthrough —
                    // `izba status` renders no egress posture at all, and
                    // `izba policy allow` writes policy.yaml directly without
                    // passing the diff/promote weakening gate — so the
                    // wording here carries its own weight.
                    let proto_str = match e.declared_protocol() {
                        None => String::new(),
                        Some(Protocol::Http) => "  protocol: http (inspected)".to_string(),
                        // A narrower access level CANCELS the hatch: the splice
                        // is decided on a methodless (tier-2) flow, which
                        // `access: read` never authorizes (`egress.rego`'s
                        // `host_access_ok("read")` requires GET/HEAD), so
                        // `router::passthrough_names` drops the host and the
                        // connection stays terminated. Warning either way —
                        // announcing an opaque splice that will not happen
                        // strands a pinning client on izba's certificate with
                        // no hint why.
                        Some(Protocol::Tcp) if e.access() != Access::ReadWrite => {
                            "  \u{26A0} protocol: tcp — pinning passthrough NOT in effect: \
                            an opaque splice carries no HTTP method, so this entry's access \
                            level never authorizes one; the connection stays terminated at L7 \
                            (a pinning client still sees izba's certificate) — widen to \
                            read-write to pin"
                                .to_string()
                        }
                        Some(Protocol::Tcp) => "  \u{26A0} protocol: tcp — pinning passthrough: \
                            spliced opaquely; no L7 rules, no request audit, \
                            no credential injection"
                            .to_string(),
                    };
                    let _ = writeln!(out, "    {}  [{ports}] ({access_str}){proto_str}", e.host());
                }
            }
            if !cfg.git.is_empty() {
                let _ = writeln!(out, "  git:");
                for r in &cfg.git {
                    let target_str = match &r.target {
                        GitTarget::Repo(s) => s.as_str(),
                        GitTarget::Host(s) => s.as_str(),
                    };
                    let access_str = match r.access {
                        Access::Read => "read",
                        Access::ReadWrite => "read-write",
                    };
                    let _ = writeln!(out, "    {target_str} ({access_str})");
                }
            }
        }
    }
    out
}

fn enable(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    use izba_core::daemon::egress::audit::{aggregate, parse_line};
    let dir = require_sandbox_dir(paths, name)?;
    let audit_path = paths.logs_dir(name).join("egress-audit.jsonl");
    let text = std::fs::read_to_string(&audit_path).unwrap_or_default();
    let summaries = aggregate(text.lines().filter_map(parse_line));
    let mut added = 0usize;
    edit_policy_file(&dir, |cfg| {
        added = cfg.add_observed_allowed(&summaries);
    })?;
    println!("added {added} observed endpoint(s) to '{name}' allow-list");
    maybe_reload(paths, name);
    Ok(0)
}

fn reload(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    client.reload_policy(name)?;
    println!("reloaded egress policy for '{name}' (applies to new connections)");
    Ok(0)
}

/// Print the USB/IP exposure notice when a rule opens a path to a usbip server.
///
/// The rule is honored; this steers the user toward izba's per-device allowlist,
/// which grants ONE device rather than everything the server exports. Written to
/// stderr so it stands out from the grant echo without polluting stdout.
fn warn_usbip_exposure(paths: &Paths, cfg: &EgressPolicyConfig) {
    // Now that an upstream can be configured, a rule naming that exact endpoint
    // is flagged even on a non-standard port — not just the well-known 3240.
    let upstream =
        izba_core::usb::resolve_upstream(&izba_core::usb::settings::load(&paths.usb_dir()));
    if let Some(msg) = usbip_exposure_warning(cfg, upstream) {
        eprintln!("\n{msg}");
    }
}

/// Live-reload after an edit when the daemon is already running; otherwise note
/// that the change will apply on next start. Never spawns a daemon just to reload.
fn maybe_reload(paths: &Paths, name: &str) {
    match DaemonClient::connect_existing(paths) {
        Ok(Some(mut c)) => match c.reload_policy(name) {
            Ok(()) => println!("reloaded egress policy for '{name}' (applies to new connections)"),
            Err(e) => println!("policy updated; reload deferred ({e})"),
        },
        _ => println!("policy updated (daemon not running; applies on next start)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only convenience mirroring the pre-fix-wave `apply_edit(...,
    /// Edit::Allow, ...)` shape: grant `ports` on `host`, no access change.
    /// Kept INSIDE the test module (not a crate-level `pub(crate)` fn) so it
    /// never appears in the non-test build — a crate-level helper used only
    /// by tests would itself become the same "never constructed outside
    /// tests" dead-code trap that motivated removing `Edit::Allow`.
    fn allow_ports(dir: &std::path::Path, host: &str, ports: &[u16]) -> anyhow::Result<()> {
        edit_policy_file(dir, |cfg| {
            for &port in ports {
                cfg.allow(host, port);
            }
        })?;
        Ok(())
    }

    // --- #235: `policy allow` must not silently widen a pinning passthrough ---

    fn pinned_policy(dir: &std::path::Path) {
        std::fs::write(
            dir.join("policy.yaml"),
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .unwrap();
    }

    /// The exact reported sequence. Without the opt-in flag the command
    /// REFUSES, and the refusal is actionable: it names the host, the port
    /// that would become an opaque splice, and the flag that declares it
    /// deliberately.
    #[test]
    fn policy_allow_refuses_to_widen_a_pinning_passthrough() {
        let dir = tempfile::tempdir().unwrap();
        pinned_policy(dir.path());
        let before = std::fs::read(dir.path().join("policy.yaml")).unwrap();

        let err = apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, false)
            .expect_err("extending a declared hatch to a new port must not be silent");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("pinned.vendor.com"),
            "must name the host: {msg}"
        );
        assert!(msg.contains("8080"), "must name the port at stake: {msg}");
        assert!(
            msg.contains("--passthrough"),
            "must name how to declare it deliberately: {msg}"
        );

        assert_eq!(
            std::fs::read(dir.path().join("policy.yaml")).unwrap(),
            before,
            "a refusal must leave policy.yaml completely untouched — not even reserialized"
        );
    }

    /// With the opt-in flag the grant lands AND the operator is told which
    /// ports became passthroughs, so neither branch of the resolution is
    /// silent.
    #[test]
    fn policy_allow_with_the_flag_widens_and_reports_the_pinned_ports() {
        let dir = tempfile::tempdir().unwrap();
        pinned_policy(dir.path());

        let (cfg, pinned) =
            apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, true).unwrap();
        assert_eq!(pinned, vec![8080], "the widened port must be reported back");
        assert_eq!(
            cfg.entries_for_host("pinned.vendor.com")[0].ports(),
            vec![443, 8080],
            "the grant must still land"
        );
    }

    /// The end of the reported sequence, asserted where it actually bites:
    /// the passthrough set the datapath consults. The refusal must leave 8080
    /// OUT of it; the acknowledged grant puts it in, which is exactly the
    /// transition `--passthrough` exists to make the operator say out loud.
    #[test]
    fn the_resulting_passthrough_set_matches_the_chosen_resolution() {
        use izba_core::daemon::egress::inspect::InspectionTable;

        let dir = tempfile::tempdir().unwrap();
        pinned_policy(dir.path());

        apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, false)
            .expect_err("refused");
        let stored = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert!(
            !InspectionTable::from_config(&stored).passthrough_host("pinned.vendor.com", 8080),
            "a refused grant must leave 8080 inspected"
        );

        let (cfg, _) =
            apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, true).unwrap();
        assert!(
            InspectionTable::from_config(&cfg).passthrough_host("pinned.vendor.com", 8080),
            "the acknowledged grant is what actually pins 8080 — the operator was told so"
        );
    }

    /// The flag gates ONLY the hatch. An ordinary host has nothing to
    /// acknowledge, so the plain command keeps working untouched.
    #[test]
    fn policy_allow_on_an_undeclared_host_needs_no_flag() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, pinned) =
            apply_allow_edit(dir.path(), "plain.example.com", &[8080], false, false).unwrap();
        assert!(pinned.is_empty(), "nothing was pinned: {pinned:?}");
        assert_eq!(
            cfg.entries_for_host("plain.example.com")[0].ports(),
            vec![8080]
        );
    }

    /// Re-running the same acknowledged grant is a no-op that reports nothing
    /// — the flag must stay idempotent rather than re-warning about a port
    /// the operator already exempted.
    #[test]
    fn policy_allow_with_the_flag_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        pinned_policy(dir.path());
        apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, true).unwrap();

        let (_, pinned) =
            apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, true).unwrap();
        assert!(
            pinned.is_empty(),
            "8080 already carried the hatch; nothing new to announce: {pinned:?}"
        );
    }

    /// AC 5: this issue changes no stored shape. A policy carrying a
    /// declaration must survive the refusal path AND the acknowledged path
    /// with its `protocol:` intact and its parse unchanged.
    #[test]
    fn the_stored_policy_shape_is_unchanged_by_the_resolution() {
        let dir = tempfile::tempdir().unwrap();
        pinned_policy(dir.path());
        apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, true).unwrap();

        let yaml = std::fs::read_to_string(dir.path().join("policy.yaml")).unwrap();
        assert!(
            yaml.contains("protocol: tcp"),
            "the declaration must survive the edit verbatim: {yaml}"
        );
        let reparsed = EgressPolicyConfig::from_yaml(&yaml).unwrap();
        assert_eq!(
            reparsed.to_yaml(),
            yaml,
            "the written file must round-trip byte-identically"
        );
    }

    /// A bare `izba policy allow <pinned-host>` grants BOTH web ports, so the
    /// refusal must name every one it would pin, not just the first.
    #[test]
    fn a_bare_host_refusal_names_every_port_it_would_pin() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("policy.yaml"),
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [8443]\n    protocol: tcp\n",
        )
        .unwrap();

        let err = apply_allow_edit(dir.path(), "pinned.vendor.com", &[80, 443], false, false)
            .expect_err("both web ports would be pinned");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("ports 80, 443"),
            "must name every port it would pin, in the plural: {msg}"
        );
        assert!(
            msg.contains("splice them opaquely"),
            "the follow-up clauses must agree in number: {msg}"
        );
    }

    /// The singular half of the same phrasing. Pinned separately so a
    /// collapsed plural branch cannot pass by rendering one wording for both.
    #[test]
    fn a_single_port_refusal_reads_in_the_singular() {
        let dir = tempfile::tempdir().unwrap();
        pinned_policy(dir.path());

        let err = apply_allow_edit(dir.path(), "pinned.vendor.com", &[8080], false, false)
            .expect_err("8080 would be pinned");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("port 8080") && !msg.contains("ports 8080"),
            "one port reads as `port 8080`, not `ports 8080`: {msg}"
        );
        assert!(
            msg.contains("splice it opaquely"),
            "the follow-up clauses must agree in number: {msg}"
        );
    }

    /// The acknowledgement echo must state what the port actually loses, not
    /// merely that something happened — `policy show`'s warning is otherwise
    /// the only place that says it.
    #[test]
    fn render_pin_widening_warning_names_what_is_lost() {
        let out = render_pin_widening_warning("pinned.vendor.com", &[8080]);
        assert!(
            out.contains("pinned.vendor.com"),
            "must name the host: {out}"
        );
        assert!(
            out.contains("port 8080") && !out.contains("ports 8080"),
            "must name the port, in the singular: {out}"
        );
        assert!(
            render_pin_widening_warning("pinned.vendor.com", &[80, 443]).contains("ports 80, 443"),
            "and in the plural when more than one port was pinned"
        );
        assert!(
            out.contains("protocol: tcp"),
            "must name the declaration it inherited: {out}"
        );
        assert!(
            out.contains("certificate verification"),
            "must state that upstream certificate verification is given up: {out}"
        );
        assert!(
            out.contains("audit") || out.contains("L7"),
            "must state that inspection is given up: {out}"
        );
    }

    #[test]
    fn parse_policy_allow_passthrough() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "izba",
            "policy",
            "allow",
            "web",
            "pinned.vendor.com:8080",
            "--passthrough",
        ])
        .unwrap();
        let crate::Cmd::Policy(PolicyCmd::Allow {
            passthrough, read, ..
        }) = cli.cmd
        else {
            panic!("expected policy allow")
        };
        assert!(passthrough, "--passthrough must parse");
        assert!(!read, "--read is independent of --passthrough");
    }

    #[test]
    fn parse_policy_git_allow_write() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from([
            "izba",
            "policy",
            "git",
            "allow",
            "web",
            "github.com/o/a",
            "--write",
        ])
        .unwrap();
        let crate::Cmd::Policy(PolicyCmd::Git(GitSub::Allow {
            name,
            target,
            write,
        })) = cli.cmd
        else {
            panic!("expected policy git allow");
        };
        assert_eq!(name, "web");
        assert_eq!(target, "github.com/o/a");
        assert!(write, "--write flag must be true");

        // Without --write, the field must be false (read-only default, #149).
        let cli =
            crate::Cli::try_parse_from(["izba", "policy", "git", "allow", "web", "github.com/o/a"])
                .unwrap();
        let crate::Cmd::Policy(PolicyCmd::Git(GitSub::Allow { write, .. })) = cli.cmd else {
            panic!("expected policy git allow");
        };
        assert!(!write, "write must default to false");
    }

    /// #149: `policy git allow` through the full `run()` entry point — the
    /// read-only default and the `--write` widening must be what actually
    /// lands in `policy.yaml`'s `GitRule`, not just what clap parses.
    #[test]
    fn git_allow_default_is_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        run(
            &paths,
            &PolicyCmd::Git(GitSub::Allow {
                name: "web".into(),
                target: "github.com/o/a".into(),
                write: false,
            }),
        )
        .unwrap();
        let cfg = EgressPolicyConfig::load(&paths.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg.git[0].access,
            Access::Read,
            "git allow without --write must record read-only"
        );

        run(
            &paths,
            &PolicyCmd::Git(GitSub::Allow {
                name: "web".into(),
                target: "github.com/o/a".into(),
                write: true,
            }),
        )
        .unwrap();
        let cfg = EgressPolicyConfig::load(&paths.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.git.len(), 1, "upsert, not append");
        assert_eq!(cfg.git[0].access, Access::ReadWrite);
    }

    // ── access-grant echo (#149) ──────────────────────────────────────────────

    /// Every `policy allow` invocation must loudly state the effective access
    /// level it granted: read-write points at the `--read` narrowing flag,
    /// read spells out the GET/HEAD-only meaning.
    #[test]
    fn render_allow_grant_states_effective_access() {
        let rw = AllowEntry::Scoped {
            host: "api.x.com".into(),
            ports: Some(vec![80, 443]),
            access: Access::ReadWrite,
            protocol: None,
        };
        let out = render_allow_grant(std::slice::from_ref(&rw));
        assert!(out.contains("api.x.com"), "must name the host: {out}");
        assert!(out.contains("[80, 443]"), "must list the ports: {out}");
        assert!(
            out.contains("access: read-write"),
            "must state the effective access: {out}"
        );
        assert!(
            out.contains("--read"),
            "read-write echo must point at the narrowing flag: {out}"
        );

        let ro = AllowEntry::Scoped {
            host: "api.x.com".into(),
            ports: Some(vec![443]),
            access: Access::Read,
            protocol: None,
        };
        let out = render_allow_grant(&[ro]);
        assert!(
            out.contains("access: read (HTTP GET/HEAD only)"),
            "read echo must spell out the GET/HEAD meaning: {out}"
        );
    }

    /// A mixed-access wildcard host keeps multiple entries (union
    /// enforcement); the echo must render every one, not just the first.
    #[test]
    fn render_allow_grant_lists_every_matching_entry() {
        let entries = [
            AllowEntry::Scoped {
                host: "*.x.com".into(),
                ports: Some(vec![443]),
                access: Access::Read,
                protocol: None,
            },
            AllowEntry::Scoped {
                host: "*.x.com".into(),
                ports: Some(vec![8443]),
                access: Access::ReadWrite,
                protocol: None,
            },
        ];
        let out = render_allow_grant(&entries);
        assert_eq!(out.lines().count(), 2, "one line per entry: {out}");
    }

    /// Every `policy git allow` invocation must loudly state the effective
    /// access level: read points at the `--write` widening flag, read-write
    /// spells out that push is included.
    #[test]
    fn render_git_grant_states_effective_access() {
        let read = GitRule {
            target: GitTarget::Repo("github.com/o/a".into()),
            access: Access::Read,
        };
        let out = render_git_grant(&read);
        assert!(
            out.contains("github.com/o/a"),
            "must name the target: {out}"
        );
        assert!(
            out.contains("access: read (clone/fetch only"),
            "must state the read-only meaning: {out}"
        );
        assert!(
            out.contains("--write"),
            "read echo must point at the widening flag: {out}"
        );

        let rw = GitRule {
            target: GitTarget::Host("github.com".into()),
            access: Access::ReadWrite,
        };
        let out = render_git_grant(&rw);
        assert!(out.contains("github.com"), "must name the target: {out}");
        assert!(
            out.contains("access: read-write"),
            "must state the effective access: {out}"
        );
        assert!(
            out.contains("push"),
            "read-write echo must spell out that push is included: {out}"
        );
    }

    #[test]
    fn parse_policy_allow_read() {
        use clap::Parser;
        let cli =
            crate::Cli::try_parse_from(["izba", "policy", "allow", "web", "api.x.com", "--read"])
                .unwrap();
        let crate::Cmd::Policy(PolicyCmd::Allow {
            name, target, read, ..
        }) = cli.cmd
        else {
            panic!("expected policy allow");
        };
        assert_eq!(name, "web");
        assert_eq!(target, "api.x.com");
        assert!(read, "--read flag must be true");

        // Without --read, the field must be false (back-compat default).
        let cli =
            crate::Cli::try_parse_from(["izba", "policy", "allow", "web", "api.x.com"]).unwrap();
        let crate::Cmd::Policy(PolicyCmd::Allow { read, .. }) = cli.cmd else {
            panic!("expected policy allow");
        };
        assert!(!read, "read must default to false");
    }

    #[test]
    fn parse_policy_enforce_on() {
        use clap::Parser;
        let cli = crate::Cli::try_parse_from(["izba", "policy", "enforce", "web", "on"]).unwrap();
        let crate::Cmd::Policy(PolicyCmd::Enforce { name, state }) = cli.cmd else {
            panic!("expected policy enforce");
        };
        assert_eq!(name, "web");
        assert!(matches!(state, EnforceState::On));
    }

    #[test]
    fn parse_target_bare_host_means_web_ports() {
        // a bare host must mean the same thing it means in policy.yaml
        assert_eq!(
            parse_target("api.x.com").unwrap(),
            ("api.x.com".to_string(), vec![80, 443])
        );
    }

    #[test]
    fn parse_target_explicit_port_is_exactly_that_port() {
        assert_eq!(
            parse_target("api.x.com:8080").unwrap(),
            ("api.x.com".to_string(), vec![8080])
        );
        assert_eq!(
            parse_target("db.internal:5432").unwrap(),
            ("db.internal".to_string(), vec![5432])
        );
        assert!(parse_target("api.x.com:notaport").is_err());
    }

    #[test]
    fn bare_allow_and_block_are_symmetric_web_ports() {
        use izba_core::daemon::egress::config::EgressPolicyConfig;
        let dir = tempfile::tempdir().unwrap();
        allow_ports(dir.path(), "api.x.com", &[80, 443]).unwrap();
        let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(
            cfg.allow[0],
            AllowEntry::Scoped {
                host: "api.x.com".to_string(),
                ports: Some(vec![80, 443]),
                access: Access::ReadWrite,
                protocol: None,
            }
        );
        apply_block_edit(dir.path(), "api.x.com", &[80, 443]).unwrap();
        let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert!(cfg.allow.is_empty());
    }

    #[test]
    fn bare_block_leaves_explicitly_added_ports() {
        use izba_core::daemon::egress::config::EgressPolicyConfig;
        let dir = tempfile::tempdir().unwrap();
        allow_ports(dir.path(), "api.x.com", &[80, 443]).unwrap();
        allow_ports(dir.path(), "api.x.com", &[8443]).unwrap();
        apply_block_edit(dir.path(), "api.x.com", &[80, 443]).unwrap();
        let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(cfg.allow[0].ports(), vec![8443]);
    }

    #[test]
    fn allow_accepts_wildcard_target() {
        use izba_core::daemon::egress::config::EgressPolicyConfig;
        let dir = tempfile::tempdir().unwrap();
        allow_ports(dir.path(), "*.example.com", &[443]).unwrap();
        let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "*.example.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
                protocol: None,
            }]
        );
    }

    #[test]
    fn allow_rejects_malformed_wildcard_target_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            allow_ports(dir.path(), "foo.*.com", &[443]).expect_err("mid-label wildcard must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("foo.*.com"),
            "must name the bad pattern: {msg}"
        );
        assert!(
            !dir.path().join("policy.yaml").exists(),
            "failed edit must leave no policy.yaml"
        );
    }

    /// `izba policy allow NAME HOST --read` / without `--read` through the full
    /// `run()` entry point (the single `edit_policy_file` closure, not a
    /// lower-level helper), pinning both the new `--read` behavior and the
    /// back-compat "plain allow never widens an existing read entry" contract
    /// (#147-style, now through the CLI).
    #[test]
    fn allow_read_records_read_access() {
        use izba_core::daemon::egress::config::EgressPolicyConfig;

        // Fresh dir, allow with --read -> Access::Read.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();
        run(
            &paths,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com".into(),
                read: true,
                passthrough: false,
            },
        )
        .unwrap();
        let cfg = EgressPolicyConfig::load(&paths.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.allow[0].access(), Access::Read);

        // Fresh dir, allow WITHOUT --read -> Access::ReadWrite (back-compat pin).
        let tmp2 = tempfile::tempdir().unwrap();
        let paths2 = Paths::with_root(tmp2.path().to_path_buf());
        std::fs::create_dir_all(paths2.sandbox_dir("web")).unwrap();
        run(
            &paths2,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com".into(),
                read: false,
                passthrough: false,
            },
        )
        .unwrap();
        let cfg2 = EgressPolicyConfig::load(&paths2.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg2.allow[0].access(), Access::ReadWrite);

        // Plain allow (no --read) on a different port of an EXISTING read
        // entry must NOT silently widen it to read-write.
        let tmp3 = tempfile::tempdir().unwrap();
        let paths3 = Paths::with_root(tmp3.path().to_path_buf());
        std::fs::create_dir_all(paths3.sandbox_dir("web")).unwrap();
        run(
            &paths3,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com:443".into(),
                read: true,
                passthrough: false,
            },
        )
        .unwrap();
        run(
            &paths3,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com:8443".into(),
                read: false,
                passthrough: false,
            },
        )
        .unwrap();
        let cfg3 = EgressPolicyConfig::load(&paths3.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg3.allow[0].access(),
            Access::Read,
            "plain allow must not widen an existing read entry"
        );
        assert_eq!(cfg3.allow[0].ports(), vec![443, 8443]);

        // allow --read on an existing read-write entry -> explicit narrowing.
        let tmp4 = tempfile::tempdir().unwrap();
        let paths4 = Paths::with_root(tmp4.path().to_path_buf());
        std::fs::create_dir_all(paths4.sandbox_dir("web")).unwrap();
        run(
            &paths4,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com".into(),
                read: false,
                passthrough: false,
            },
        )
        .unwrap();
        run(
            &paths4,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com".into(),
                read: true,
                passthrough: false,
            },
        )
        .unwrap();
        let cfg4 = EgressPolicyConfig::load(&paths4.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg4.allow[0].access(), Access::Read);
    }

    /// Greptile P1 regression (#84 fix-wave): `izba policy allow --read
    /// api.x.com` followed by a PLAIN `izba policy allow API.X.COM` (a
    /// different case spelling of the same host) must NOT create a second,
    /// separate read-write entry that silently wins at Rego-compile time
    /// (later duplicate JSON key overwrites the earlier one). The two CLI
    /// invocations must collapse into exactly one allow-list entry that
    /// stays `Access::Read`.
    #[test]
    fn allow_case_variant_does_not_widen_existing_read_entry() {
        use izba_core::daemon::egress::config::EgressPolicyConfig;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        std::fs::create_dir_all(paths.sandbox_dir("web")).unwrap();

        run(
            &paths,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com".into(),
                read: true,
                passthrough: false,
            },
        )
        .unwrap();
        run(
            &paths,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "API.X.COM".into(),
                read: false,
                passthrough: false,
            },
        )
        .unwrap();

        let cfg = EgressPolicyConfig::load(&paths.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg.allow.len(),
            1,
            "a case-variant spelling must merge into the same entry, not append a new one: {:?}",
            cfg.allow
        );
        assert_eq!(cfg.allow[0].host(), "api.x.com");
        assert_eq!(
            cfg.allow[0].access(),
            Access::Read,
            "the plain (non-read) allow of a case variant must not widen the existing read entry"
        );
    }

    // ── show()/render_policy ──────────────────────────────────────────────────

    #[test]
    fn render_policy_shows_no_policy() {
        let out = render_policy("web", None);
        assert!(out.contains("'web' has no egress policy (all egress allowed)"));
    }

    #[test]
    fn render_policy_shows_empty_allow_list() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![],
            git: vec![],
        };
        let out = render_policy("web", Some(&cfg));
        assert!(out.contains("http: deny all (empty allow-list)"));
    }

    /// A non-enforcing sandbox with an empty allow-list allows ALL egress
    /// (`compile` → `AllowAll`), so the empty-list line must not claim
    /// deny-all there — `policy show` is the only surface that reveals egress
    /// posture, and a false "locked down" is its worst failure mode. The
    /// enforcing wording is pinned byte-for-byte in the same test so the two
    /// postures can never drift into each other.
    #[test]
    fn render_policy_empty_allow_list_is_honest_when_enforcement_is_off() {
        let mut cfg = EgressPolicyConfig {
            enforce: false,
            allow: vec![],
            git: vec![],
        };
        let out = render_policy("web", Some(&cfg));
        assert!(
            out.contains("  http: all egress allowed (enforce off)\n"),
            "a non-enforcing sandbox must be reported as allowing egress:\n{out}"
        );
        assert!(
            !out.contains("deny all"),
            "nothing is denied here — claiming deny-all is the dangerous direction:\n{out}"
        );

        cfg.enforce = true;
        let enforcing = render_policy("web", Some(&cfg));
        assert!(
            enforcing.contains("  http: deny all (empty allow-list)\n"),
            "the enforcing wording must stay byte-identical:\n{enforcing}"
        );
    }

    #[test]
    fn show_marks_a_declared_http_port_as_inspected() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: internal.example.com\n    ports: [8000]\n    protocol: http\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(out.contains("internal.example.com"), "{out}");
        assert!(out.contains("http (inspected)"), "{out}");
    }

    #[test]
    fn show_is_loud_about_a_pinning_passthrough() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(out.contains("passthrough"), "{out}");
        assert!(
            out.contains('\u{26A0}'),
            "the passthrough line must carry a warning glyph like every other \
             loud signal in this product (e.g. `izba diff`'s ⚠ weakens egress):\n{out}"
        );
        assert!(
            out.contains("no L7 rules"),
            "the operator must see what they gave up:\n{out}"
        );
        assert!(
            out.contains("no request audit"),
            "netlog/audit visibility is a separate loss from L7 rules — name it:\n{out}"
        );
        assert!(
            out.contains("no credential injection"),
            "credential injection is a separate loss (per Protocol's own doc) — name it:\n{out}"
        );
    }

    // Dogfooding, m5p1 run: `policy show` promised an opaque splice that
    // `access: read` silently cancels — `InspectionTable` never consults
    // `AllowEntry::access()`, but `router::passthrough_names`'s per-name
    // `policy.check` filter drops the host, because a methodless (tier-2) flow
    // fails `egress.rego`'s `host_access_ok("read")`. The datapath is right
    // (more inspection, not less); the rendering said the opposite. Display
    // only — this asserts the string, never the decision.
    #[test]
    fn show_says_a_narrow_access_level_cancels_the_passthrough() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    access: read\n    protocol: tcp\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(
            out.contains('\u{26A0}'),
            "still a warning — an operator who wrote `protocol: tcp` for a pinning \
             client must learn their client will not get an opaque splice:\n{out}"
        );
        assert!(
            out.contains("NOT in effect"),
            "the cancellation is the headline:\n{out}"
        );
        assert!(
            out.contains("izba's certificate"),
            "name the consequence a pinning client actually hits:\n{out}"
        );
        assert!(
            !out.contains("spliced opaquely"),
            "the ordinary passthrough promise must NOT be printed for this entry — \
             that claim is what the finding was about:\n{out}"
        );
    }

    // The other half of the pair: the read-write rendering must not drift when
    // the combined case above is edited (the string is asserted by
    // `show_is_loud_about_a_pinning_passthrough` and by the m5p1 corpus).
    #[test]
    fn show_keeps_the_read_write_passthrough_wording_unchanged() {
        let cfg = EgressPolicyConfig::from_yaml(
            "enforce: true\nallow:\n  - host: pinned.vendor.com\n    ports: [443]\n    protocol: tcp\n",
        )
        .unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(
            out.contains(
                "\u{26A0} protocol: tcp — pinning passthrough: spliced opaquely; \
                 no L7 rules, no request audit, no credential injection\n"
            ),
            "the read-write passthrough line must stay byte-identical:\n{out}"
        );
        assert!(
            !out.contains("NOT in effect"),
            "the cancellation wording belongs only to the narrowed-access case:\n{out}"
        );
    }

    #[test]
    fn show_is_unchanged_for_a_policy_that_declares_nothing() {
        let cfg = EgressPolicyConfig::from_yaml("enforce: true\nallow:\n  - github.com\n").unwrap();
        let out = render_policy("web", Some(&cfg));
        assert!(
            !out.contains("passthrough") && !out.contains("inspected"),
            "the default rendering must not grow noise:\n{out}"
        );
    }

    #[test]
    fn render_policy_annotates_read_and_read_write_hosts() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "pypi.org".into(),
                    ports: None,
                    access: Access::Read,
                    protocol: None,
                },
                AllowEntry::Scoped {
                    host: "api.x.com".into(),
                    ports: None,
                    access: Access::ReadWrite,
                    protocol: None,
                },
            ],
            git: vec![],
        };
        let out = render_policy("web", Some(&cfg));
        assert!(
            out.contains("pypi.org  [80, 443] (read)"),
            "missing read annotation, got:\n{out}"
        );
        assert!(
            out.contains("api.x.com  [80, 443] (read-write)"),
            "missing read-write annotation, got:\n{out}"
        );
    }

    /// Mutation-gap closure (#84 incremental gate): `render_policy`'s git
    /// section is guarded by `if !cfg.git.is_empty()`; deleting that `!`
    /// (rendering the section only when git rules are ABSENT) passed the
    /// whole suite before this test existed. Pin both directions: a config
    /// with a git rule must render the `git:` header and its entry, and a
    /// config with none must NOT mention `git:` at all.
    #[test]
    fn render_policy_shows_git_section_only_when_rules_present() {
        use izba_core::daemon::egress::config::GitRule;

        let with_git = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: None,
                access: Access::ReadWrite,
                protocol: None,
            }],
            git: vec![GitRule {
                target: GitTarget::Repo("github.com/o/a".into()),
                access: Access::Read,
            }],
        };
        let out = render_policy("web", Some(&with_git));
        assert!(
            out.contains("  git:"),
            "a config with git rules must render the git: header, got:\n{out}"
        );
        assert!(
            out.contains("    github.com/o/a (read)"),
            "a config with git rules must render its entry, got:\n{out}"
        );

        let without_git = EgressPolicyConfig {
            enforce: true,
            allow: vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: None,
                access: Access::ReadWrite,
                protocol: None,
            }],
            git: vec![],
        };
        let out2 = render_policy("web", Some(&without_git));
        assert!(
            !out2.contains("git:"),
            "a config with no git rules must not render a git section, got:\n{out2}"
        );
    }

    #[test]
    fn verbs_bail_cleanly_on_unknown_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        let cases: Vec<PolicyCmd> = vec![
            PolicyCmd::Show {
                name: "ghost".into(),
            },
            PolicyCmd::Allow {
                name: "ghost".into(),
                target: "example.com".into(),
                read: false,
                passthrough: false,
            },
            PolicyCmd::Block {
                name: "ghost".into(),
                target: "example.com".into(),
            },
            PolicyCmd::Enable {
                name: "ghost".into(),
            },
            PolicyCmd::Enforce {
                name: "ghost".into(),
                state: EnforceState::On,
            },
            PolicyCmd::Git(GitSub::Allow {
                name: "ghost".into(),
                target: "github.com/foo/bar".into(),
                write: false,
            }),
            PolicyCmd::Git(GitSub::Block {
                name: "ghost".into(),
                target: "github.com".into(),
            }),
            // A malformed target must not surface "invalid port" for a sandbox
            // that doesn't exist in the first place — the sandbox guard wins.
            PolicyCmd::Allow {
                name: "ghost".into(),
                target: "example.com:notaport".into(),
                read: false,
                passthrough: false,
            },
            PolicyCmd::Block {
                name: "ghost".into(),
                target: "example.com:notaport".into(),
            },
        ];
        for cmd in cases {
            let err = run(&paths, &cmd).expect_err("unknown sandbox must fail");
            let msg = format!("{err:#}");
            assert_eq!(msg, "no such sandbox: ghost", "cmd {cmd:?} leaked: {msg}");
        }
        // The failed verbs must not have created any stub state.
        assert!(!paths.sandbox_dir("ghost").exists());
    }
}
