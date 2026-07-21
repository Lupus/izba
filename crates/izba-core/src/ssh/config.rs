use anyhow::Context;
use std::path::{Path, PathBuf};

use crate::paths::Paths;
use crate::ssh::{identity, settings};
use identity::SshIdentity;

/// Returns `~/.ssh/config` on Unix, `%USERPROFILE%\.ssh\config` on Windows,
/// reading the home directory from `env`.
pub fn user_ssh_config_path_with(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env("USERPROFILE").map(|p| PathBuf::from(p).join(".ssh").join("config"))
    }
    #[cfg(not(windows))]
    {
        env("HOME").map(|p| PathBuf::from(p).join(".ssh").join("config"))
    }
}

/// Pure function — no disk I/O.
///
/// Renders the full text of the izba-managed SSH config file:
/// - a wildcard `Host izba-*` block with all behavior directives
/// - per-sandbox stub lines (`Host izba-<name>`) for tab-completion
pub fn render_managed(
    proxy_exe: &Path,
    identity: &SshIdentity,
    known_hosts: &Path,
    sandbox_names: &[String],
) -> String {
    let proxy = proxy_exe.display();
    let user_priv = identity.user_private.display();
    let kh = known_hosts.display();

    let mut out = format!(
        "# Managed by izba — do not edit. Regenerated on sandbox start/stop.\n\
         Host izba-*\n\
         \x20   ProxyCommand \"{proxy}\" __ssh-proxy %h\n\
         \x20   IdentityFile \"{user_priv}\"\n\
         \x20   IdentitiesOnly yes\n\
         \x20   User root\n\
         \x20   UserKnownHostsFile \"{kh}\"\n\
         \x20   StrictHostKeyChecking accept-new\n\
         \x20   LogLevel ERROR\n\
         \n\
         # --- per-sandbox completion stubs (running sandboxes) ---\n"
    );

    for name in sandbox_names {
        out.push_str(&format!("Host izba-{name}\n"));
    }

    out
}

/// Atomically write `bytes` to `path` using a sibling `.tmp` file + rename.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().context("path has no parent")?;
    let tmp = parent.join(format!(
        "{}.tmp",
        path.file_name()
            .context("path has no file name")?
            .to_string_lossy()
    ));
    std::fs::write(&tmp, bytes).with_context(|| format!("write tmp {}", tmp.display()))?;
    // On Windows `fs::rename` replaces an existing file, same as on Unix.
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Idempotently prepend `Include "<include_target>"\n\n` to `user_config`.
///
/// If the file does not yet exist it is created. If a line already containing
/// the exact include path is present, the file is left untouched.
pub fn ensure_include_line(user_config: &Path, include_target: &Path) -> anyhow::Result<()> {
    let target_str = include_target.to_string_lossy();
    let existing = if user_config.exists() {
        std::fs::read_to_string(user_config)
            .with_context(|| format!("reading {}", user_config.display()))?
    } else {
        String::new()
    };

    // Idempotency: match the exact directive line we write so that the path
    // appearing in a comment or HostName does not suppress a real injection.
    let include_line = format!("Include \"{target_str}\"");
    if existing.lines().any(|l| l.trim() == include_line) {
        return Ok(());
    }

    let new_content = format!("{include_line}\n\n{existing}");
    if let Some(parent) = user_config.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    atomic_write(user_config, new_content.as_bytes())
}

/// Idempotently remove the exact `Include "<include_target>"` directive line
/// previously injected by [`ensure_include_line`] (plus the one blank
/// separator line it wrote). Everything else is preserved; a missing file or
/// absent directive is a no-op.
pub fn remove_include_line(user_config: &Path, include_target: &Path) -> anyhow::Result<()> {
    if !user_config.exists() {
        return Ok(());
    }
    let existing = std::fs::read_to_string(user_config)
        .with_context(|| format!("reading {}", user_config.display()))?;
    let include_line = format!("Include \"{}\"", include_target.to_string_lossy());
    if !existing.lines().any(|l| l.trim() == include_line) {
        return Ok(());
    }
    let mut out: Vec<&str> = Vec::new();
    let mut lines = existing.lines().peekable();
    while let Some(l) = lines.next() {
        if l.trim() == include_line {
            if lines.peek().is_some_and(|n| n.trim().is_empty()) {
                lines.next(); // the separator blank ensure_include_line added
            }
            continue;
        }
        out.push(l);
    }
    let mut new_content = out.join("\n");
    if existing.ends_with('\n') && !new_content.is_empty() {
        new_content.push('\n');
    }
    atomic_write(user_config, new_content.as_bytes())
}

/// Regenerate the izba-managed SSH config and inject the Include line,
/// reading the home directory via `env` instead of the process environment.
///
/// When `config_management` is disabled in settings, no config is written and
/// a previously-injected Include line is REMOVED from the user config — the
/// managed file stops tracking reality the moment management is off, so
/// leaving the Include behind would serve stale data forever.
pub fn regenerate_with(
    paths: &Paths,
    sandbox_names: &[String],
    env: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<()> {
    let ssh_dir = paths.ssh_dir();
    if !settings::load(&ssh_dir).config_management {
        if let Some(user_cfg) = user_ssh_config_path_with(env) {
            remove_include_line(&user_cfg, &ssh_dir.join("config"))?;
        }
        return Ok(());
    }
    let id = identity::ensure_identity(&ssh_dir)?;
    let known_hosts = ssh_dir.join("known_hosts");
    let hostpub = identity::host_public_openssh(&ssh_dir)?;
    atomic_write(&known_hosts, format!("* {hostpub}\n").as_bytes())?;
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("izba"));
    let managed = render_managed(&exe, &id, &known_hosts, sandbox_names);
    atomic_write(&ssh_dir.join("config"), managed.as_bytes())?;
    if let Some(user_cfg) = user_ssh_config_path_with(env) {
        if let Some(parent) = user_cfg.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        ensure_include_line(&user_cfg, &ssh_dir.join("config"))?;
    }
    Ok(())
}

/// Regenerate the izba-managed SSH config and inject the Include line.
///
/// Early-returns `Ok(())` if `config_management` is disabled in settings.
// reason: thin wrapper that binds `regenerate_with` to the real process env;
// the logic is unit-tested through `regenerate_with` with an injected env, and
// calling this directly in a test would mutate the real ~/.ssh/config.
#[mutants::skip]
pub fn regenerate(paths: &Paths, sandbox_names: &[String]) -> anyhow::Result<()> {
    regenerate_with(paths, sandbox_names, &|k| std::env::var(k).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::identity::SshIdentity;

    fn fake_identity() -> SshIdentity {
        SshIdentity {
            user_private: PathBuf::from("/d/ssh/id_ed25519"),
            user_public: PathBuf::from("/d/ssh/id_ed25519.pub"),
            host_private: PathBuf::from("/d/ssh/ssh_host_ed25519_key"),
            host_public: PathBuf::from("/d/ssh/ssh_host_ed25519_key.pub"),
        }
    }

    #[test]
    fn render_contains_wildcard_and_stubs() {
        let id = fake_identity();
        let out = render_managed(
            Path::new("/usr/bin/izba"),
            &id,
            Path::new("/d/ssh/known_hosts"),
            &["foo".into(), "bar".into()],
        );
        assert!(out.contains("Host izba-*"));
        assert!(out.contains("ProxyCommand \"/usr/bin/izba\" __ssh-proxy %h"));
        assert!(out.contains("User root"));
        assert!(out.contains("\nHost izba-foo\n"));
        assert!(out.contains("\nHost izba-bar\n"));
        // stubs carry no body
        assert!(!out.contains("Host izba-foo\n    "));
    }

    #[test]
    fn render_quotes_proxy_exe() {
        let id = fake_identity();
        let out = render_managed(
            Path::new("/path with spaces/izba"),
            &id,
            Path::new("/d/ssh/known_hosts"),
            &[],
        );
        assert!(out.contains("ProxyCommand \"/path with spaces/izba\" __ssh-proxy %h"));
    }

    #[test]
    fn include_injected_once_and_preserves_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        std::fs::write(&cfg, "Host myserver\n    HostName example.com\n").unwrap();
        let inc = Path::new("/data/ssh/config");
        ensure_include_line(&cfg, inc).unwrap();
        ensure_include_line(&cfg, inc).unwrap(); // idempotent
        let body = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(body.matches("Include").count(), 1);
        assert!(body.contains("Host myserver")); // preserved
        assert!(body.starts_with("Include ")); // at top
    }

    #[test]
    fn include_not_suppressed_by_path_in_comment() {
        // Regression: old guard used `contains(path)` which matched path inside a comment.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        // User config whose body contains the managed path in a comment only.
        let inc = Path::new("/data/ssh/config");
        let initial = format!(
            "# backup of {}\nHost myserver\n    HostName example.com\n",
            inc.display()
        );
        std::fs::write(&cfg, &initial).unwrap();
        ensure_include_line(&cfg, inc).unwrap();
        let body = std::fs::read_to_string(&cfg).unwrap();
        // The real Include directive must be present exactly once.
        let include_line = format!("Include \"{}\"", inc.display());
        assert_eq!(
            body.lines().filter(|l| l.trim() == include_line).count(),
            1,
            "expected exactly one Include directive line; got:\n{body}"
        );
        // The comment must still be there.
        assert!(body.contains("# backup of"), "comment was lost");
        // The Include must be at the very top.
        assert!(
            body.starts_with(&include_line),
            "Include not at top of file"
        );
    }

    #[test]
    fn regenerate_skips_when_config_management_disabled() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("data"));
        let ssh_dir = paths.ssh_dir();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Write settings with config_management = false
        crate::ssh::settings::save(
            &ssh_dir,
            &crate::ssh::settings::SshSettings {
                config_management: false,
            },
        )
        .unwrap();
        let home = tmp.path().join("home");
        let home_str = home.to_string_lossy().to_string();
        let env = move |k: &str| (k == "HOME" || k == "USERPROFILE").then(|| home_str.clone());
        regenerate_with(&paths, &[], &env).unwrap();
        // The managed config should NOT have been written
        assert!(
            !ssh_dir.join("config").exists(),
            "config written despite disabled"
        );
        assert!(
            !ssh_dir.join("known_hosts").exists(),
            "known_hosts written despite disabled"
        );
        // And no user config should have been created either.
        assert!(
            !home.join(".ssh").join("config").exists(),
            "user config created despite disabled"
        );
    }

    #[test]
    fn disabling_config_management_removes_stale_include() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("data"));
        let ssh_dir = paths.ssh_dir();
        std::fs::create_dir_all(&ssh_dir).unwrap();
        // Simulate the managed era: the Include was injected into the user
        // config alongside the user's own content.
        let home = tmp.path().join("home");
        let user_cfg = home.join(".ssh").join("config");
        std::fs::create_dir_all(user_cfg.parent().unwrap()).unwrap();
        std::fs::write(&user_cfg, "Host myserver\n    HostName example.com\n").unwrap();
        ensure_include_line(&user_cfg, &ssh_dir.join("config")).unwrap();
        assert!(std::fs::read_to_string(&user_cfg)
            .unwrap()
            .contains("Include "));

        // Now the user turns management off: the next regenerate must clean
        // up the Include instead of leaving it pointing at a stale file.
        crate::ssh::settings::save(
            &ssh_dir,
            &crate::ssh::settings::SshSettings {
                config_management: false,
            },
        )
        .unwrap();
        let home_str = home.to_string_lossy().to_string();
        let env = move |k: &str| (k == "HOME" || k == "USERPROFILE").then(|| home_str.clone());
        regenerate_with(&paths, &[], &env).unwrap();

        let body = std::fs::read_to_string(&user_cfg).unwrap();
        assert!(
            !body.contains("Include "),
            "stale Include left behind: {body}"
        );
        assert!(body.contains("Host myserver"), "user content lost: {body}");
    }

    #[test]
    fn remove_include_line_is_noop_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        // Missing file: fine.
        remove_include_line(&cfg, Path::new("/data/ssh/config")).unwrap();
        assert!(!cfg.exists());
        // Present file without the directive: byte-identical afterwards.
        let initial = "Host myserver\n    HostName example.com\n";
        std::fs::write(&cfg, initial).unwrap();
        remove_include_line(&cfg, Path::new("/data/ssh/config")).unwrap();
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), initial);
    }
}
