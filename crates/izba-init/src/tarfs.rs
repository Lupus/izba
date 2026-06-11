//! Guest side of `izba cp`: extract a tar stream under the workload root and
//! create a tar stream of a guest path — both confined to the workload root
//! (`/rootfs` in the guest) so no tar entry, dest, or symlink can escape into
//! init's initramfs. Host-testable: every function takes the root as an
//! explicit `&Path`, exactly like `ExecEngine::new(Some("/rootfs"))`.
//!
// NOTE: the resolver primitives below are exercised only from `#[cfg(test)]`
// in this first commit; their non-test callers (`extract`/`create`) land in
// the following commits. Allow dead_code so the resolver-only commit stays
// clippy-clean; the allow is removed once the real callers exist.
#![allow(dead_code)]

use izba_proto::ErrorKind;
use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
use nix::sys::stat::Mode;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

type TarError = (ErrorKind, String);

fn internal(msg: impl std::fmt::Display) -> TarError {
    (ErrorKind::Internal, msg.to_string())
}

/// Open `root` itself as a directory fd, to serve as the `dirfd` anchor for
/// every `openat2(RESOLVE_IN_ROOT)` below. Resolution can never climb above
/// this fd.
fn open_root_dir(root: &Path) -> Result<OwnedFd, TarError> {
    // The anchor path is init's own constant (never attacker-controlled), so a
    // plain open is safe; all relative opens are then re-anchored to this fd
    // with RESOLVE_IN_ROOT.
    let raw = nix::fcntl::open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| internal(format!("opening workload root {}: {e}", root.display())))?;
    // SAFETY: freshly opened, owned by no one else.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Resolve `rel` (a guest path, leading `/` stripped) under the workload
/// root using `openat2(RESOLVE_BENEATH)`. Any attempt to escape (via `..`, an
/// absolute symlink, or an upward symlink) fails with `EXDEV`/`ELOOP`, mapped
/// to `BadRequest`. Inner relative symlinks that stay beneath the root resolve
/// normally. Returns an `OwnedFd` for the resolved path opened with `flags`.
///
/// NOTE: the plan named `RESOLVE_IN_ROOT`, but that flag *clamps* escapes back
/// into the root (`..` at the root is a no-op, absolute symlinks are
/// reinterpreted relative to the root), so an escaping path silently resolves
/// to a non-existent in-root path (`ENOENT`) instead of erroring. The spec (§7)
/// requires escapes to be *rejected* with `BadRequest`. `RESOLVE_BENEATH`
/// delivers that: it forbids leaving the dirfd subtree entirely and returns
/// `EXDEV`, while still permitting in-tree relative symlinks. Containment is
/// guaranteed either way; `RESOLVE_BENEATH` additionally makes the rejection
/// observable.
fn resolve_under_root(root_dir: &OwnedFd, rel: &Path, flags: OFlag) -> Result<OwnedFd, TarError> {
    let how = OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(Mode::empty())
        .resolve(ResolveFlag::RESOLVE_BENEATH);
    match openat2(root_dir.as_raw_fd(), rel, how) {
        Ok(raw) => Ok(unsafe { OwnedFd::from_raw_fd(raw) }),
        Err(nix::errno::Errno::EXDEV) | Err(nix::errno::Errno::ELOOP) => Err((
            ErrorKind::BadRequest,
            "path escapes workload root".to_string(),
        )),
        Err(nix::errno::Errno::ENOENT) => Err((
            ErrorKind::PathNotFound,
            format!("{}: no such file or directory", display_rel(rel)),
        )),
        Err(e) => Err(internal(format!("resolving {}: {e}", display_rel(rel)))),
    }
}

/// Normalize a guest path to a root-relative path: strip a single leading
/// `/`, and treat empty as `.`. Pure string work; the actual containment is
/// enforced by `openat2`, not here.
fn root_relative(guest_path: &str) -> PathBuf {
    let trimmed = guest_path.trim_start_matches('/');
    if trimmed.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(trimmed)
    }
}

fn display_rel(p: &Path) -> String {
    format!("/{}", p.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn resolve_stays_in_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("inside.txt"), b"ok").unwrap();
        let root_dir = open_root_dir(root).unwrap();
        // A plain file inside the root resolves fine.
        resolve_under_root(&root_dir, &root_relative("/inside.txt"), OFlag::O_RDONLY)
            .expect("inside path must resolve");
    }

    #[test]
    fn resolve_rejects_dotdot_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();
        // A sibling secret OUTSIDE the root.
        fs::write(dir.path().join("secret"), b"top").unwrap();
        let root_dir = open_root_dir(&root).unwrap();
        let (kind, msg) =
            resolve_under_root(&root_dir, &root_relative("/../secret"), OFlag::O_RDONLY)
                .expect_err("../ must not escape the root");
        assert_eq!(kind, ErrorKind::BadRequest, "{msg}");
        assert!(msg.contains("escapes"), "{msg}");
    }

    #[test]
    fn resolve_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(dir.path().join("secret"), b"top").unwrap();
        // A symlink inside the root pointing OUT of it.
        std::os::unix::fs::symlink(dir.path().join("secret"), root.join("link")).unwrap();
        let root_dir = open_root_dir(&root).unwrap();
        let (kind, _msg) = resolve_under_root(&root_dir, &root_relative("/link"), OFlag::O_RDONLY)
            .expect_err("an escaping symlink must be rejected");
        assert_eq!(kind, ErrorKind::BadRequest);
    }

    #[test]
    fn resolve_missing_is_path_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let root_dir = open_root_dir(dir.path()).unwrap();
        let (kind, _msg) = resolve_under_root(&root_dir, &root_relative("/nope"), OFlag::O_RDONLY)
            .expect_err("missing path");
        assert_eq!(kind, ErrorKind::PathNotFound);
    }
}
