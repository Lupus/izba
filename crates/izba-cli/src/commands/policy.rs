use anyhow::Context;
use clap::Subcommand;
use izba_core::daemon::egress::config::{edit_policy_file, Access, EgressPolicyConfig, GitTarget};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Print the effective allow-list (host + ports) and enforce posture (on/off)
    Show {
        /// Sandbox name (or dir)
        name: String,
    },
    /// Allow an HTTP(S) destination: HOST or HOST:PORT (port defaults to 443;
    /// access is read-write). To actually block anything else, enforcement must
    /// be on (see `enforce`). Auto-reloads a running sandbox.
    Allow {
        /// Sandbox name (or dir)
        name: String,
        /// Destination to allow: HOST or HOST:PORT (port defaults to 443)
        target: String,
    },
    /// Block a destination: HOST or HOST:PORT (port defaults to 443); auto-reloads
    Block {
        /// Sandbox name (or dir)
        name: String,
        /// Destination to remove: HOST or HOST:PORT (port defaults to 443)
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

/// Which mutation an edit verb performs.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Edit {
    Allow,
    Block,
}

pub fn run(paths: &Paths, cmd: &PolicyCmd) -> anyhow::Result<i32> {
    match cmd {
        PolicyCmd::Show { name } => show(paths, name),
        PolicyCmd::Allow { name, target } => {
            let dir = require_sandbox_dir(paths, name)?;
            let (host, port) = parse_target(target)?;
            apply_edit(&dir, Edit::Allow, &host, port)?;
            maybe_reload(paths, name);
            Ok(0)
        }
        PolicyCmd::Block { name, target } => {
            let dir = require_sandbox_dir(paths, name)?;
            let (host, port) = parse_target(target)?;
            apply_edit(&dir, Edit::Block, &host, port)?;
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

/// Parse a `HOST` or `HOST:PORT` target (port defaults to 443).
pub(crate) fn parse_target(s: &str) -> anyhow::Result<(String, u16)> {
    match s.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .with_context(|| format!("invalid port in '{s}'"))?;
            Ok((host.to_string(), port))
        }
        None => Ok((s.to_string(), 443)),
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

/// The daemon-free core of allow/block: persist the edit to `policy.yaml`.
pub(crate) fn apply_edit(
    sandbox_dir: &std::path::Path,
    edit: Edit,
    host: &str,
    port: u16,
) -> anyhow::Result<()> {
    edit_policy_file(sandbox_dir, |cfg| match edit {
        Edit::Allow => {
            cfg.allow(host, port);
        }
        Edit::Block => {
            let _ = cfg.block(host, port);
        }
    })?;
    Ok(())
}

fn show(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let dir = require_sandbox_dir(paths, name)?;
    match EgressPolicyConfig::load(&dir)? {
        None => println!("'{name}' has no egress policy (all egress allowed)"),
        Some(cfg) => {
            let enforce_str = if cfg.enforce { "on" } else { "off" };
            println!("'{name}' egress policy (enforce: {enforce_str}):");
            if cfg.allow.is_empty() {
                println!("  http: deny all (empty allow-list)");
            } else {
                println!("  http allow-list:");
                for e in &cfg.allow {
                    let ports = e
                        .ports()
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!("    {}  [{ports}]", e.host());
                }
            }
            if !cfg.git.is_empty() {
                println!("  git:");
                for r in &cfg.git {
                    let target_str = match &r.target {
                        GitTarget::Repo(s) => s.as_str(),
                        GitTarget::Host(s) => s.as_str(),
                    };
                    let access_str = match r.access {
                        Access::Read => "read",
                        Access::ReadWrite => "read-write",
                    };
                    println!("    {target_str} ({access_str})");
                }
            }
        }
    }
    Ok(0)
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
    fn parse_target_defaults_to_443() {
        assert_eq!(
            parse_target("api.x.com").unwrap(),
            ("api.x.com".to_string(), 443)
        );
        assert_eq!(
            parse_target("db.internal:5432").unwrap(),
            ("db.internal".to_string(), 5432)
        );
        assert!(parse_target("api.x.com:notaport").is_err());
    }

    #[test]
    fn allow_then_block_round_trips_a_policy_file() {
        use izba_core::daemon::egress::config::{AllowEntry, EgressPolicyConfig};
        let dir = tempfile::tempdir().unwrap();
        // `apply_edit` is the daemon-free core of the allow/block verbs.
        apply_edit(dir.path(), Edit::Allow, "api.x.com", 443).unwrap();
        let cfg = EgressPolicyConfig::load(dir.path()).unwrap().unwrap();
        use izba_core::daemon::egress::config::Access;
        assert_eq!(
            cfg.allow,
            vec![AllowEntry::Scoped {
                host: "api.x.com".into(),
                ports: Some(vec![443]),
                access: Access::ReadWrite,
            }]
        );
        apply_edit(dir.path(), Edit::Block, "api.x.com", 443).unwrap();
        assert!(EgressPolicyConfig::load(dir.path())
            .unwrap()
            .unwrap()
            .allow
            .is_empty());
    }

    #[test]
    fn mutating_verbs_bail_cleanly_on_unknown_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().to_path_buf());
        let cases: Vec<PolicyCmd> = vec![
            PolicyCmd::Allow {
                name: "ghost".into(),
                target: "example.com".into(),
            },
            PolicyCmd::Block {
                name: "ghost".into(),
                target: "example.com".into(),
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
