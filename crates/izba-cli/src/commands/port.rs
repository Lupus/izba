//! `izba port` — publish/unpublish/ls host->guest TCP ports. Rules are owned
//! by izbad: each published rule is a relay thread inside the daemon (no more
//! detached `__port-relay` worker processes).

use anyhow::{bail, Context};
use izba_core::daemon::proto::{DaemonRequest, DaemonResponse};
use izba_core::daemon::DaemonClient;
use izba_core::paths::Paths;
use std::net::Ipv4Addr;

pub fn publish(paths: &Paths, name: &str, rule_spec: &str) -> anyhow::Result<i32> {
    let rule = izba_core::portfwd::parse_rule(rule_spec)?;
    let mut client = DaemonClient::connect(paths)?;
    let resp = client.request(
        &DaemonRequest::PortPublish {
            name: name.to_string(),
            rule: rule.clone(),
            persist: false,
        },
        &mut |_| {},
    )?;
    super::expect_ok(resp)?;
    println!("{}:{} -> {}", rule.bind, rule.host_port, rule.guest_port);
    Ok(0)
}

pub fn unpublish(paths: &Paths, name: &str, key: &str) -> anyhow::Result<i32> {
    let (bind, host_port) = parse_key(key)?;
    let mut client = DaemonClient::connect(paths)?;
    let resp = client.request(
        &DaemonRequest::PortUnpublish {
            name: name.to_string(),
            bind,
            host_port,
        },
        &mut |_| {},
    )?;
    super::expect_ok(resp)?;
    Ok(0)
}

pub fn ls(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    let mut client = DaemonClient::connect(paths)?;
    match client.request(
        &DaemonRequest::PortList {
            name: name.to_string(),
        },
        &mut |_| {},
    )? {
        DaemonResponse::Ports { rules } => {
            for r in &rules {
                println!("{}:{} -> {}", r.bind, r.host_port, r.guest_port);
            }
            Ok(0)
        }
        DaemonResponse::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!("unexpected daemon reply: {other:?}"),
    }
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
