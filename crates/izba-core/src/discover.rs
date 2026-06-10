//! Locate external tool binaries: explicit env-var override, then a copy
//! bundled next to the running executable (`<exe dir>/libexec/`, Docker's
//! convention — installers rely on this), then `$PATH`.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

pub(crate) fn find_tool(env_var: &str, exe_name: &str) -> Result<PathBuf> {
    find_tool_from(
        env_var,
        exe_name,
        std::env::var_os(env_var).map(PathBuf::from),
        std::env::current_exe().ok(),
    )
}

fn find_tool_from(
    env_var: &str,
    exe_name: &str,
    env_override: Option<PathBuf>,
    current_exe: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(p) = env_override {
        if p.is_file() {
            return Ok(p);
        }
        bail!(
            "{env_var} is set to {} but no file exists there",
            p.display()
        );
    }
    if let Some(dir) = current_exe.as_deref().and_then(Path::parent) {
        let bundled = dir.join("libexec").join(exe_name);
        if bundled.is_file() {
            return Ok(bundled);
        }
    }
    which::which(exe_name).map_err(|_| {
        anyhow::anyhow!(
            "{exe_name} not found (checked ${env_var}, <exe dir>/libexec/{exe_name}, PATH) — \
             install it or set {env_var}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let fake = dir.path().join("my-tool");
        std::fs::write(&fake, b"").unwrap();
        let got = find_tool_from("IZBA_TOOL", "tool", Some(fake.clone()), None).unwrap();
        assert_eq!(got, fake);
    }

    #[test]
    fn env_override_beats_bundled() {
        let override_dir = tempfile::TempDir::new().unwrap();
        let override_file = override_dir.path().join("my-tool-override");
        std::fs::write(&override_file, b"").unwrap();

        let exe_dir = tempfile::TempDir::new().unwrap();
        let libexec = exe_dir.path().join("libexec");
        std::fs::create_dir(&libexec).unwrap();
        std::fs::write(libexec.join("tool"), b"").unwrap();

        let got = find_tool_from(
            "IZBA_TOOL",
            "tool",
            Some(override_file.clone()),
            Some(exe_dir.path().join("izba")),
        )
        .unwrap();
        assert_eq!(got, override_file);
    }

    #[test]
    fn env_override_missing_is_error() {
        let err = find_tool_from(
            "IZBA_TOOL",
            "tool",
            Some(PathBuf::from("/nonexistent/x")),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("IZBA_TOOL"));
    }

    #[test]
    fn bundled_libexec_beats_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let libexec = dir.path().join("libexec");
        std::fs::create_dir(&libexec).unwrap();
        let bundled = libexec.join("tool");
        std::fs::write(&bundled, b"").unwrap();
        let got = find_tool_from("IZBA_TOOL", "tool", None, Some(dir.path().join("izba"))).unwrap();
        assert_eq!(got, bundled);
    }

    #[test]
    fn falls_back_to_path() {
        // No override, no bundled copy: outcome depends on the host having
        // an `sh` on PATH (universally true on Linux/CI) vs a junk name.
        assert!(find_tool_from("IZBA_TOOL", "sh", None, None).is_ok());
        let err =
            find_tool_from("IZBA_TOOL", "definitely-not-a-real-tool-xyz", None, None).unwrap_err();
        assert!(err.to_string().contains("PATH"));
    }
}
