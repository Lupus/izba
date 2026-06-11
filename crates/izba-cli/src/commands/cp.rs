//! `izba cp SRC DST` — copy files between host and a running sandbox.
//!
//! Exactly one operand is a guest ref `NAME:GUEST_PATH` (where NAME is an
//! existing sandbox); the other is a host path. Guest-ref detection: split at
//! the first `:`; it is a guest ref iff the prefix is a syntactically valid
//! sandbox name AND a sandbox dir with that exact name exists. So `C:\x` is a
//! host path (uppercase `C` is never a valid sandbox name), and ambiguity is
//! resolvable by prefixing the host path with `./`.

use anyhow::{bail, Context};
use izba_core::cp;
use izba_core::paths::Paths;
use izba_core::sandbox;
use std::path::PathBuf;

/// One parsed operand.
#[derive(Debug, PartialEq, Eq)]
enum Operand {
    Host(PathBuf),
    Guest { name: String, path: String },
}

/// Parse a single operand into Host or Guest. `paths` is consulted to check
/// that a candidate sandbox name actually exists.
fn parse_operand(paths: &Paths, raw: &str) -> Operand {
    if let Some((prefix, rest)) = raw.split_once(':') {
        if sandbox::validate_name(prefix).is_ok() && paths.sandbox_dir(prefix).is_dir() {
            return Operand::Guest {
                name: prefix.to_string(),
                path: rest.to_string(),
            };
        }
    }
    Operand::Host(PathBuf::from(raw))
}

pub fn run(paths: &Paths, src: &str, dst: &str) -> anyhow::Result<i32> {
    let src_op = parse_operand(paths, src);
    let dst_op = parse_operand(paths, dst);

    match (src_op, dst_op) {
        (Operand::Host(_), Operand::Host(_)) => {
            bail!("at least one of SRC, DST must be NAME:PATH (a guest ref)")
        }
        (Operand::Guest { .. }, Operand::Guest { .. }) => {
            bail!("only one of SRC, DST may be a guest ref")
        }
        (Operand::Host(host_src), Operand::Guest { name, path }) => {
            let conn = open_stream(paths, &name)?;
            cp::copy_to_guest(conn, &host_src, &guest_abs(&path))
                .with_context(|| format!("copying {} to {name}:{path}", host_src.display()))?;
            Ok(0)
        }
        (Operand::Guest { name, path }, Operand::Host(host_dest)) => {
            let conn = open_stream(paths, &name)?;
            cp::copy_from_guest(conn, &guest_abs(&path), &host_dest)
                .with_context(|| format!("copying {name}:{path} to {}", host_dest.display()))?;
            Ok(0)
        }
    }
}

/// Relative guest paths resolve against `/workspace` (exec's default cwd).
fn guest_abs(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else if path.is_empty() {
        "/workspace".to_string()
    } else {
        format!("/workspace/{path}")
    }
}

/// Open one stream-port connection through the daemon (which liveness-gates
/// the sandbox — same error family as exec's "not running").
fn open_stream(paths: &Paths, name: &str) -> anyhow::Result<izba_core::vmm::UdsStream> {
    izba_core::daemon::DaemonClient::open_guest_stream(paths, name)
        .with_context(|| format!("opening cp stream to '{name}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths_with_sandbox(name: &str) -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(dir.path().join("izba"));
        std::fs::create_dir_all(paths.sandbox_dir(name)).unwrap();
        (dir, paths)
    }

    #[test]
    fn parses_guest_ref_when_sandbox_exists() {
        let (_d, paths) = paths_with_sandbox("web");
        assert_eq!(
            parse_operand(&paths, "web:/etc/app"),
            Operand::Guest {
                name: "web".into(),
                path: "/etc/app".into()
            }
        );
    }

    #[test]
    fn unknown_name_is_host_path() {
        let (_d, paths) = paths_with_sandbox("web");
        // No sandbox named "db" -> treated as a host path.
        assert_eq!(
            parse_operand(&paths, "db:/x"),
            Operand::Host(PathBuf::from("db:/x"))
        );
    }

    #[test]
    fn windows_drive_is_host_path() {
        let (_d, paths) = paths_with_sandbox("web");
        // `C` is uppercase -> never a valid sandbox name -> host path.
        assert_eq!(
            parse_operand(&paths, r"C:\Users\me\file"),
            Operand::Host(PathBuf::from(r"C:\Users\me\file"))
        );
    }

    #[test]
    fn dot_slash_disambiguates_host_path() {
        let (_d, paths) = paths_with_sandbox("web");
        // `./web:foo` has no `:`-prefixed valid name (prefix is `./web`).
        assert_eq!(
            parse_operand(&paths, "./web:foo"),
            Operand::Host(PathBuf::from("./web:foo"))
        );
    }

    #[test]
    fn both_host_is_rejected() {
        let (_d, paths) = paths_with_sandbox("web");
        let err = run(&paths, "a.txt", "b.txt").unwrap_err();
        assert!(err.to_string().contains("guest ref"), "got: {err:#}");
    }

    #[test]
    fn both_guest_is_rejected() {
        let (_d, paths) = paths_with_sandbox("web");
        let err = run(&paths, "web:/a", "web:/b").unwrap_err();
        assert!(err.to_string().contains("only one"), "got: {err:#}");
    }

    #[test]
    fn relative_guest_path_resolves_under_workspace() {
        assert_eq!(guest_abs("a/b"), "/workspace/a/b");
        assert_eq!(guest_abs("/etc/x"), "/etc/x");
        assert_eq!(guest_abs(""), "/workspace");
    }
}
