//! `izba lockdown/unlock/windows-cleanup` — per-sandbox Windows account
//! provisioning, deprovisioning, and orphan cleanup.
//!
//! All three verbs call into `izba_core::jail_account::orchestrate` via the
//! real [`WinBackend`].  On non-Windows the backend's methods return a clear
//! "only available on Windows hosts" error which propagates naturally; the verbs
//! remain available on all platforms so that scripts stay portable.

use anyhow::bail;
use izba_core::jail_account::orchestrate::{self, LockdownOutcome, WinBackend};
use izba_core::paths::Paths;
use izba_core::state::CONFIG_FILE;

/// `izba lockdown <name>` — provision a per-sandbox Windows account + firewall
/// rule (pops a UAC prompt on Windows).
pub fn run(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    // Validate the sandbox exists by checking for its config.json.
    let config_path = paths.sandbox_dir(name).join(CONFIG_FILE);
    if !config_path.exists() {
        bail!("no sandbox named {name:?} (no config.json found)");
    }

    match orchestrate::lockdown(&WinBackend, paths, name)? {
        LockdownOutcome::Locked(info) => {
            println!(
                "Locked down '{name}' as {} (network-blocked). \
                 Restart the sandbox (izba stop {name} && izba run {name}) to apply.",
                info.account
            );
        }
        LockdownOutcome::Cancelled => {
            println!("Lock-down cancelled (UAC declined); '{name}' unchanged.");
        }
    }
    Ok(0)
}

/// `izba unlock <name>` — remove the per-sandbox Windows account + firewall
/// rule (pops a UAC prompt on Windows).
pub fn unlock(paths: &Paths, name: &str) -> anyhow::Result<i32> {
    // Validate the sandbox exists by checking for its config.json (same guard
    // as `run`/lockdown so `izba unlock bad-name` gives a clean error).
    let config_path = paths.sandbox_dir(name).join(CONFIG_FILE);
    if !config_path.exists() {
        bail!("no sandbox named {name:?} (no config.json found)");
    }

    orchestrate::unlock(&WinBackend, paths, name)?;
    println!("Unlocked '{name}' (account + firewall rule removed). Restart to drop the account.");
    Ok(0)
}

/// `izba windows-cleanup` — sweep orphaned lock-down accounts / rules whose
/// sandbox no longer exists (pops a UAC prompt on Windows).
pub fn cleanup(paths: &Paths) -> anyhow::Result<i32> {
    let live = live_sandbox_names(paths);
    orchestrate::windows_cleanup(&WinBackend, paths, &live)?;
    println!("Swept orphaned lock-down accounts/rules.");
    Ok(0)
}

/// Enumerate sandbox names from disk (same approach as `sandbox::list`): read
/// every subdirectory of `sandboxes_dir` that contains a `config.json`.
/// This is a best-effort read-only probe — no daemon connection needed.
fn live_sandbox_names(paths: &Paths) -> Vec<String> {
    let dir = paths.sandboxes_dir();
    let mut names = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return names;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // Skip tombstone dirs left by interrupted removes.
        if name.contains(".removing-") {
            continue;
        }
        // Only count directories that have a config.json (i.e. real sandboxes).
        if entry.path().join(CONFIG_FILE).exists() {
            names.push(name);
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::paths::Paths;

    fn test_paths(tmp: &tempfile::TempDir) -> Paths {
        Paths::with_root(tmp.path().to_path_buf())
    }

    // ── live_sandbox_names ────────────────────────────────────────────────────

    #[test]
    fn live_sandbox_names_empty_when_no_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        // sandboxes_dir does not exist yet.
        let names = live_sandbox_names(&paths);
        assert!(names.is_empty());
    }

    #[test]
    fn live_sandbox_names_finds_sandboxes_with_config() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let sb_dir = paths.sandbox_dir("web");
        std::fs::create_dir_all(&sb_dir).unwrap();
        std::fs::write(sb_dir.join(CONFIG_FILE), b"{}").unwrap();

        let names = live_sandbox_names(&paths);
        assert_eq!(names, vec!["web".to_string()]);
    }

    #[test]
    fn live_sandbox_names_skips_dirs_without_config() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        // A dir without config.json is skipped.
        std::fs::create_dir_all(paths.sandbox_dir("partial")).unwrap();
        let names = live_sandbox_names(&paths);
        assert!(names.is_empty(), "unexpected names: {names:?}");
    }

    #[test]
    fn live_sandbox_names_skips_tombstone_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let tomb = paths.sandboxes_dir().join("web.removing-12345");
        std::fs::create_dir_all(&tomb).unwrap();
        std::fs::write(tomb.join(CONFIG_FILE), b"{}").unwrap();

        let names = live_sandbox_names(&paths);
        assert!(names.is_empty(), "unexpected names: {names:?}");
    }

    // ── run returns windows-only on non-Windows ───────────────────────────────

    #[cfg(not(windows))]
    #[test]
    fn lockdown_run_returns_windows_only_on_non_windows() {
        use izba_core::state::{save_json, SandboxConfig};

        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let sb_dir = paths.sandbox_dir("test");
        std::fs::create_dir_all(&sb_dir).unwrap();
        // Write a minimal valid SandboxConfig so lockdown() can deserialise it
        // before calling the backend's elevate() — which is where the
        // "only available on Windows hosts" error comes from on non-Windows.
        save_json(
            &sb_dir.join(CONFIG_FILE),
            &SandboxConfig {
                image_digest: "sha256:abc".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 2,
                mem_mb: 512,
                workspace: std::path::PathBuf::from("/workspace"),
                ports: vec![],
                volumes: vec![],
                builder: false,
                build: None,
                rw_size_gb: 8,
            },
        )
        .unwrap();

        let result = run(&paths, "test");
        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("only available on Windows"),
            "expected windows-only error, got: {err:#}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn lockdown_unlock_returns_windows_only_on_non_windows() {
        use izba_core::state::{save_json, SandboxConfig};

        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let sb_dir = paths.sandbox_dir("test");
        std::fs::create_dir_all(&sb_dir).unwrap();
        // Write a minimal valid SandboxConfig so the existence check passes
        // and we reach the backend's elevate() — which returns the
        // "only available on Windows hosts" error on non-Windows.
        save_json(
            &sb_dir.join(CONFIG_FILE),
            &SandboxConfig {
                image_digest: "sha256:abc".into(),
                image_ref: "ubuntu:24.04".into(),
                cpus: 2,
                mem_mb: 512,
                workspace: std::path::PathBuf::from("/workspace"),
                ports: vec![],
                volumes: vec![],
                builder: false,
                build: None,
                rw_size_gb: 8,
            },
        )
        .unwrap();

        let result = unlock(&paths, "test");
        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("only available on Windows"),
            "expected windows-only error, got: {err:#}"
        );
    }

    #[test]
    fn unlock_rejects_missing_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        // No sandbox dir created — should get a clean "no sandbox named" error.
        let result = unlock(&paths, "ghost");
        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("no sandbox named"),
            "expected 'no sandbox named' error, got: {err:#}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn lockdown_cleanup_returns_windows_only_on_non_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = test_paths(&tmp);
        let result = cleanup(&paths);
        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("only available on Windows"),
            "expected windows-only error, got: {err:#}"
        );
    }
}
