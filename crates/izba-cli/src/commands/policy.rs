use anyhow::Context;
use clap::Subcommand;
use izba_core::daemon::egress::config::{
    edit_policy_file, seed_from_summaries, EgressPolicyConfig,
};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// Print the effective egress allow-list (host + ports) for a sandbox
    Show { name: String },
    /// Allow a destination: HOST or HOST:PORT (port defaults to 443); auto-reloads
    Allow { name: String, target: String },
    /// Block a destination: HOST or HOST:PORT (port defaults to 443); auto-reloads
    Block { name: String, target: String },
    /// Seed the allow-list from the sandbox's currently-allowed traffic, then reload
    Enable { name: String },
    /// Re-read a sandbox's policy.yaml and apply it to new connections (no restart)
    Reload { name: String },
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
            let (host, port) = parse_target(target)?;
            apply_edit(&paths.sandbox_dir(name), Edit::Allow, &host, port)?;
            maybe_reload(paths, name);
            Ok(0)
        }
        PolicyCmd::Block { name, target } => {
            let (host, port) = parse_target(target)?;
            apply_edit(&paths.sandbox_dir(name), Edit::Block, &host, port)?;
            maybe_reload(paths, name);
            Ok(0)
        }
        PolicyCmd::Enable { name } => enable(paths, name),
        PolicyCmd::Reload { name } => reload(paths, name),
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
    let dir = paths.sandbox_dir(name);
    if !dir.exists() {
        anyhow::bail!("no such sandbox: {name}");
    }
    match EgressPolicyConfig::load(&dir)? {
        None => println!("'{name}' has no egress policy (all egress allowed)"),
        Some(cfg) if cfg.allow.is_empty() => {
            println!("'{name}' egress policy: deny all (empty allow-list)")
        }
        Some(cfg) => {
            println!("'{name}' egress allow-list:");
            for e in &cfg.allow {
                let ports = e
                    .ports()
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("  {}  [{ports}]", e.host());
            }
        }
    }
    Ok(0)
}

fn enable(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    use izba_core::daemon::egress::audit::{aggregate, parse_line};
    let dir = paths.sandbox_dir(name);
    if !dir.exists() {
        anyhow::bail!("no such sandbox: {name}");
    }
    let audit_path = paths.logs_dir(name).join("egress-audit.jsonl");
    let text = std::fs::read_to_string(&audit_path).unwrap_or_default();
    let records = text.lines().filter_map(parse_line);
    let seeded = seed_from_summaries(&aggregate(records));
    edit_policy_file(&dir, |cfg| *cfg = seeded.clone())?;
    let n = seeded.allow.len();
    println!("enabled firewall for '{name}': seeded {n} host(s) from observed traffic");
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
}
