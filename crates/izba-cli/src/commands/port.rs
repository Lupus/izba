//! `izba port` — publish/unpublish/ls host->guest TCP ports, plus the hidden
//! `__port-relay` worker that each published rule runs as a detached process.

use anyhow::{bail, Context};
use izba_core::paths::Paths;
use izba_core::sandbox;
use std::net::Ipv4Addr;
use std::path::Path;

pub fn publish(paths: &Paths, name: &str, rule_spec: &str) -> anyhow::Result<i32> {
    let rule = izba_core::portfwd::parse_rule(rule_spec)?;
    let connector = sandbox::default_connector();
    sandbox::publish_port(paths, name, rule.clone(), &connector)?;
    println!("{}:{} -> {}", rule.bind, rule.host_port, rule.guest_port);
    Ok(0)
}

pub fn unpublish(paths: &Paths, name: &str, key: &str) -> anyhow::Result<i32> {
    let (bind, host_port) = parse_key(key)?;
    sandbox::unpublish_port(paths, name, bind, host_port)?;
    Ok(0)
}

pub fn ls(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let records = sandbox::list_ports(paths, name)?;
    for r in &records {
        println!(
            "{}:{} -> {} (relay pid {})",
            r.rule.bind, r.rule.host_port, r.rule.guest_port, r.relay.pid
        );
    }
    Ok(0)
}

/// The hidden `__port-relay` worker: runs the blocking relay loop forever.
pub fn relay(
    vsock: &Path,
    bind: &str,
    host_port: u16,
    guest_port: u16,
    pid_file: &Path,
) -> anyhow::Result<i32> {
    let bind: Ipv4Addr = bind
        .parse()
        .with_context(|| format!("invalid bind address '{bind}'"))?;
    izba_core::portfwd::run_relay(vsock, bind, host_port, guest_port, pid_file)?;
    Ok(0)
}

/// Parse an unpublish key `[BIND:]HOST` into `(bind, host_port)` (default bind
/// 127.0.0.1).
fn parse_key(key: &str) -> anyhow::Result<(Ipv4Addr, u16)> {
    let parts: Vec<&str> = key.split(':').collect();
    match parts.as_slice() {
        [host] => Ok((Ipv4Addr::LOCALHOST, parse_port(host, key)?)),
        [bind, host] => {
            let bind: Ipv4Addr = bind
                .parse()
                .with_context(|| format!("invalid bind address '{bind}' in key '{key}'"))?;
            Ok((bind, parse_port(host, key)?))
        }
        _ => bail!("invalid port key '{key}' (expected [BIND:]HOST)"),
    }
}

fn parse_port(s: &str, key: &str) -> anyhow::Result<u16> {
    let p: u16 = s
        .parse()
        .with_context(|| format!("invalid port '{s}' in key '{key}'"))?;
    if p == 0 {
        bail!("port 0 is not allowed in key '{key}'");
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_host_only_defaults_bind() {
        assert_eq!(parse_key("8080").unwrap(), (Ipv4Addr::LOCALHOST, 8080));
    }

    #[test]
    fn key_bind_host() {
        assert_eq!(
            parse_key("0.0.0.0:8080").unwrap(),
            (Ipv4Addr::new(0, 0, 0, 0), 8080)
        );
    }

    #[test]
    fn key_rejects_garbage() {
        assert!(parse_key("a:b:c").is_err());
        assert!(parse_key("0.0.0.0:0").is_err());
        assert!(parse_key("notaport").is_err());
    }
}
