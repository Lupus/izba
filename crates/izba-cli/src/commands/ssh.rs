//! `izba ssh <name>` — exec the system `ssh` client into a running sandbox,
//! using `izba __ssh-proxy` as the ProxyCommand.
//!
//! Works independently of the SSH config manager (`ssh/config.rs`): all
//! connection knobs are passed as inline `-o` options so the command succeeds
//! even when `config_management = false`.

use izba_core::paths::Paths;
use std::process::Command;

/// Build the argument list for `ssh` that connects to `izba-<name>`.
///
/// All knobs are inline `-o` options — no dependency on a managed
/// `~/.ssh/config`.
///
/// # Arguments
/// - `paths` — izba data root; used to resolve `ssh_dir()`.
/// - `name` — sandbox name (without the `izba-` prefix).
/// - `extra` — additional arguments passed verbatim after the host alias
///   (e.g. a remote command).
pub fn build_ssh_args(paths: &Paths, name: &str, extra: &[String]) -> Vec<String> {
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("izba"))
        .to_string_lossy()
        .into_owned();
    let ssh_dir = paths.ssh_dir();
    let host_alias = format!("izba-{name}");
    let identity_file = ssh_dir.join("id_ed25519").to_string_lossy().into_owned();
    let known_hosts = ssh_dir.join("known_hosts").to_string_lossy().into_owned();

    let mut args = vec![
        "-o".to_string(),
        // Use ssh's own `%h` token (the target host) rather than interpolating
        // the alias into the string: ssh expands %h before handing ProxyCommand
        // to /bin/sh, so the alias never passes through shell tokenization. This
        // matches the managed-config form (ssh/config.rs render_managed).
        format!("ProxyCommand=\"{exe}\" __ssh-proxy %h"),
        "-o".to_string(),
        "IdentitiesOnly=yes".to_string(),
        "-o".to_string(),
        format!("IdentityFile={identity_file}"),
        "-o".to_string(),
        format!("UserKnownHostsFile={known_hosts}"),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        "User=root".to_string(),
        host_alias,
    ];
    args.extend_from_slice(extra);
    args
}

pub fn run(paths: &Paths, name: &str, extra: Vec<String>) -> anyhow::Result<i32> {
    izba_core::ssh::identity::ensure_identity(&paths.ssh_dir())?;
    let args = build_ssh_args(paths, name, &extra);
    let status = Command::new("ssh").args(&args).status()?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::paths::Paths;
    use std::path::PathBuf;

    fn test_paths() -> Paths {
        Paths::with_root(PathBuf::from("/data/izba"))
    }

    #[test]
    fn build_ssh_args_contains_proxy_command() {
        let paths = test_paths();
        let args = build_ssh_args(&paths, "foo", &[]);

        // Find the ProxyCommand value.
        let proxy_cmd = args
            .windows(2)
            .find(|w| w[0] == "-o" && w[1].starts_with("ProxyCommand="))
            .map(|w| w[1].clone())
            .expect("ProxyCommand not found");

        // Must call `__ssh-proxy %h` — ssh expands %h (the target host) itself
        // before invoking /bin/sh, so the alias never passes through shell
        // tokenization. The target host (izba-foo) is the positional arg.
        assert!(
            proxy_cmd.contains("__ssh-proxy %h"),
            "ProxyCommand should call __ssh-proxy with %h, got: {proxy_cmd}"
        );

        // The exe portion must be double-quoted so spaces in the path are safe
        // when ssh passes ProxyCommand to /bin/sh -c.
        assert!(
            proxy_cmd.starts_with("ProxyCommand=\""),
            "ProxyCommand exe must be double-quoted, got: {proxy_cmd}"
        );
        assert!(
            proxy_cmd.contains("\" __ssh-proxy %h"),
            "ProxyCommand must have closing quote before __ssh-proxy, got: {proxy_cmd}"
        );
    }

    #[test]
    fn build_ssh_args_host_alias_and_identities() {
        let paths = test_paths();
        let args = build_ssh_args(&paths, "foo", &[]);

        // Host alias must be the last positional element (before any extra).
        let last = args.last().expect("args must not be empty");
        assert_eq!(last, "izba-foo", "host alias must be izba-foo");

        // IdentitiesOnly=yes must be present.
        let has_ids_only = args
            .windows(2)
            .any(|w| w[0] == "-o" && w[1] == "IdentitiesOnly=yes");
        assert!(has_ids_only, "IdentitiesOnly=yes must be present");
    }

    #[test]
    fn build_ssh_args_extra_appended_after_host() {
        let paths = test_paths();
        let extra = vec!["ls".to_string(), "-la".to_string()];
        let args = build_ssh_args(&paths, "foo", &extra);

        let host_pos = args
            .iter()
            .position(|a| a == "izba-foo")
            .expect("host alias not found");
        assert_eq!(
            &args[host_pos + 1..],
            &["ls", "-la"],
            "extra args must follow the host alias"
        );
    }

    #[test]
    fn build_ssh_args_identity_file_and_known_hosts() {
        let paths = test_paths();
        let args = build_ssh_args(&paths, "foo", &[]);

        let identity_val = args
            .windows(2)
            .find(|w| w[0] == "-o" && w[1].starts_with("IdentityFile="))
            .map(|w| w[1].clone())
            .expect("IdentityFile not found");
        assert!(
            identity_val.contains("id_ed25519"),
            "IdentityFile must point to id_ed25519, got: {identity_val}"
        );

        let kh_val = args
            .windows(2)
            .find(|w| w[0] == "-o" && w[1].starts_with("UserKnownHostsFile="))
            .map(|w| w[1].clone())
            .expect("UserKnownHostsFile not found");
        assert!(
            kh_val.contains("known_hosts"),
            "UserKnownHostsFile must point to known_hosts, got: {kh_val}"
        );
    }

    #[test]
    fn build_ssh_args_strict_host_checking_accept_new() {
        let paths = test_paths();
        let args = build_ssh_args(&paths, "foo", &[]);
        let has = args
            .windows(2)
            .any(|w| w[0] == "-o" && w[1] == "StrictHostKeyChecking=accept-new");
        assert!(has, "StrictHostKeyChecking=accept-new must be present");
    }
}
