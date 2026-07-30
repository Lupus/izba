use anyhow::Context;
use clap::Subcommand;
use izba_core::daemon::egress::config::{
    edit_policy_file, Access, AllowEntry, EgressPolicyConfig, GitTarget,
};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Print the effective allow-list (host + ports) and enforce posture (on/off)
    Show {
        /// Sandbox name (or dir)
        name: String,
    },
    /// Add HOST to the sandbox's HTTP(S) allow-list. A bare HOST opens the web ports (80 + 443); HOST:PORT opens exactly that port; access is read-write unless --read.
    /// `*.HOST` matches exactly one subdomain label and `**.HOST` matches any depth; the apex HOST is never matched by a wildcard and needs its own entry.
    /// To actually block anything else, enforcement must be on (see `enforce`).
    /// Auto-reloads a running sandbox.
    Allow {
        /// Sandbox name (or dir)
        name: String,
        /// Destination to allow: HOST, *.HOST, **.HOST, or HOST:PORT (bare host = web ports 80+443; :PORT = exactly that port)
        target: String,
        /// Restrict to read-only HTTP access (GET/HEAD only); default is read-write
        #[arg(long)]
        read: bool,
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
    /// Re-read a sandbox's policy.yaml and apply it to new connections (no restart)
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
    /// Allow git on REPO (host/owner/repo, globs ok) or a whole HOST; read unless --write
    Allow {
        /// Sandbox name (or dir)
        name: String,
        /// Git target: REPO (host/owner/repo, globs ok) or a whole HOST
        target: String,
        /// Also allow push (read-only otherwise)
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
        PolicyCmd::Allow { name, target, read } => {
            let dir = require_sandbox_dir(paths, name)?;
            let (host, ports) = parse_target(target)?;
            // One write: grant the port(s), then (only when --read) narrow the
            // access verb, all in the same edit_policy_file closure. Folding
            // both mutations into a single write matters here — splitting them
            // across two `edit_policy_file` calls would leave a window where a
            // crash between the writes persists the host at the WIDER
            // read-write default, which is the wrong failure direction for a
            // security-posture flag (#84 fix-wave finding 1).
            edit_policy_file(&dir, |cfg| {
                for &port in &ports {
                    cfg.allow(&host, port);
                }
                if *read {
                    cfg.set_host_access(&host, Access::Read);
                }
            })?;
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
                let _ = writeln!(out, "  http: deny all (empty allow-list)");
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
                    let _ = writeln!(out, "    {}  [{ports}] ({access_str})", e.host());
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
    }

    #[test]
    fn parse_policy_allow_read() {
        use clap::Parser;
        let cli =
            crate::Cli::try_parse_from(["izba", "policy", "allow", "web", "api.x.com", "--read"])
                .unwrap();
        let crate::Cmd::Policy(PolicyCmd::Allow { name, target, read }) = cli.cmd else {
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
            },
        )
        .unwrap();
        run(
            &paths3,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com:8443".into(),
                read: false,
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
            },
        )
        .unwrap();
        run(
            &paths4,
            &PolicyCmd::Allow {
                name: "web".into(),
                target: "api.x.com".into(),
                read: true,
            },
        )
        .unwrap();
        let cfg4 = EgressPolicyConfig::load(&paths4.sandbox_dir("web"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg4.allow[0].access(), Access::Read);
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

    #[test]
    fn render_policy_annotates_read_and_read_write_hosts() {
        let cfg = EgressPolicyConfig {
            enforce: true,
            allow: vec![
                AllowEntry::Scoped {
                    host: "pypi.org".into(),
                    ports: None,
                    access: Access::Read,
                },
                AllowEntry::Scoped {
                    host: "api.x.com".into(),
                    ports: None,
                    access: Access::ReadWrite,
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
