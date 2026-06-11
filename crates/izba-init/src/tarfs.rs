//! Guest side of `izba cp`: extract a tar stream under the workload root and
//! create a tar stream of a guest path — both confined to the workload root
//! (`/rootfs` in the guest) so no tar entry, dest, or symlink can escape into
//! init's initramfs. Host-testable: every function takes the root as an
//! explicit `&Path`, exactly like `ExecEngine::new(Some("/rootfs"))`.

use izba_proto::ErrorKind;
use nix::fcntl::{openat2, OFlag, OpenHow, ResolveFlag};
use nix::sys::stat::Mode;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

type TarError = (ErrorKind, String);

fn internal(msg: impl std::fmt::Display) -> TarError {
    (ErrorKind::Internal, msg.to_string())
}

/// Open `root` itself as a directory fd, to serve as the `dirfd` anchor for
/// every `openat2(RESOLVE_BENEATH)` below. Resolution can never climb above
/// this fd.
fn open_root_dir(root: &Path) -> Result<OwnedFd, TarError> {
    // The anchor path is init's own constant (never attacker-controlled), so a
    // plain open is safe; all relative opens are then re-anchored to this fd
    // with RESOLVE_BENEATH.
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

/// Extract a tar `stream` under the guest path `dest`, confined to `root`,
/// arbitrating the §3 dest-rule matrix locally (this is the receiving side —
/// the only one that can stat the guest filesystem).
///
/// The host always sends entries rooted at the source's basename (a single
/// top-level component). We resolve `dest` (already absolutized against
/// `/workspace` upstream) and decide:
///   - dest is an existing DIRECTORY → into-dir: extract entries as-is under
///     dest, so the source lands at `dest/<basename>`.
///   - dest is an existing NON-directory → peek the first entry: a single
///     regular file overwrites (rewrite top component to `basename(dest)`,
///     extract under `parent(dest)`); a directory → `BadRequest`.
///   - dest does not exist → `parent(dest)` must exist (else `PathNotFound`)
///     → rename: rewrite top component to `basename(dest)`, extract under
///     `parent(dest)`.
///
/// Every entry is unpacked through a per-entry `openat2`-validated path
/// (`guard_entry`). Any entry that would escape the root (`..`, escaping
/// symlink) aborts with `BadRequest`; partial extraction may remain
/// (documented — same as an interrupted `docker cp`). An empty archive is an
/// `Ok` no-op.
pub fn extract<R: Read>(root: &Path, dest: &str, stream: &mut R) -> Result<(), TarError> {
    let root_dir = open_root_dir(root)?;
    let dest_rel = root_relative(dest);

    // Classify dest under the root WITHOUT following an escaping path: does it
    // exist, and if so is it a directory?
    let dest_kind = classify(&root_dir, &dest_rel)?;

    let mut archive = tar::Archive::new(stream);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(false);

    let mut iter = archive.entries().map_err(internal)?;

    // Peek the first entry to learn the source type (dir-walk → first entry
    // is the top directory; single-file → first entry is the regular file)
    // and to decide the unpack base + top-component rewrite per the matrix.
    let Some(first) = iter.next() else {
        return Ok(()); // empty archive: nothing to do
    };
    let mut first = first.map_err(truncated_or_internal)?;
    let first_is_dir = first.header().entry_type().is_dir();
    let first_top = top_component(&first.path().map_err(internal)?);

    // (base_rel = the root-relative dir entries land under; rename = Some(new)
    // when the top component must be rewritten to a new name.)
    let (base_rel, rename): (PathBuf, Option<String>) = match dest_kind {
        DestKind::Dir => (dest_rel.clone(), None), // into-dir: as-is under dest
        DestKind::NonDir => {
            if first_is_dir {
                return Err((
                    ErrorKind::BadRequest,
                    "cannot overwrite non-directory with directory".to_string(),
                ));
            }
            (parent_rel(&dest_rel), Some(base_name(&dest_rel)))
        }
        DestKind::Missing => {
            // Parent must exist and be a directory.
            let parent = parent_rel(&dest_rel);
            resolve_under_root(&root_dir, &parent, OFlag::O_RDONLY | OFlag::O_DIRECTORY)?;
            (parent, Some(base_name(&dest_rel)))
        }
    };

    // Unpack the peeked first entry, then the rest, rewriting the top
    // component when renaming.
    unpack_one(
        &root_dir,
        root,
        &base_rel,
        &mut first,
        &first_top,
        rename.as_deref(),
    )?;
    for entry in iter {
        let mut entry = entry.map_err(truncated_or_internal)?;
        unpack_one(
            &root_dir,
            root,
            &base_rel,
            &mut entry,
            &first_top,
            rename.as_deref(),
        )?;
    }
    Ok(())
}

/// Whether dest already exists under the root and, if so, its kind.
enum DestKind {
    Dir,
    NonDir,
    Missing,
}

/// Classify `dest_rel` under the root via `openat2`. A directory resolves
/// with `O_DIRECTORY`; a non-directory resolves without it; `ENOENT` → Missing.
/// An escape during resolution is still surfaced as `BadRequest`.
fn classify(root_dir: &OwnedFd, dest_rel: &Path) -> Result<DestKind, TarError> {
    match resolve_under_root(root_dir, dest_rel, OFlag::O_RDONLY | OFlag::O_DIRECTORY) {
        Ok(_) => Ok(DestKind::Dir),
        Err((ErrorKind::PathNotFound, _)) => {
            // Either dest is missing, OR it exists but is not a directory
            // (O_DIRECTORY on a non-dir yields ENOTDIR, not ENOENT). Retry
            // without O_DIRECTORY to disambiguate.
            match resolve_under_root(root_dir, dest_rel, OFlag::O_RDONLY) {
                Ok(_) => Ok(DestKind::NonDir),
                Err((ErrorKind::PathNotFound, _)) => Ok(DestKind::Missing),
                Err(other) => Err(other),
            }
        }
        Err((ErrorKind::Internal, msg)) if msg.contains("ENOTDIR") => {
            // O_DIRECTORY on an existing non-dir → ENOTDIR (mapped to Internal
            // by resolve_under_root). Confirm it resolves plainly.
            resolve_under_root(root_dir, dest_rel, OFlag::O_RDONLY)?;
            Ok(DestKind::NonDir)
        }
        Err(other) => Err(other),
    }
}

/// Unpack a single tar `entry` under `base_rel` (root-relative), rewriting its
/// top path component to `rename` when set. The landing path's parent is
/// validated with `openat2` (escape → `BadRequest`) before tar writes.
fn unpack_one<R: Read>(
    root_dir: &OwnedFd,
    root: &Path,
    base_rel: &Path,
    entry: &mut tar::Entry<'_, R>,
    src_top: &str,
    rename: Option<&str>,
) -> Result<(), TarError> {
    let entry_path = entry.path().map_err(internal)?.into_owned();
    let rewritten = rewrite_top(&entry_path, src_top, rename);
    let landing_rel = base_rel.join(&rewritten);
    guard_entry(root_dir, &landing_rel)?;
    // Per-entry unpack to the computed absolute host path (entry names were
    // rewritten, so `unpack_in` is unusable; the openat2 guard above is the
    // authoritative escape check).
    let landing_abs = root.join(&landing_rel);
    entry.unpack(&landing_abs).map_err(truncated_or_internal)?;
    Ok(())
}

/// The first path component of an entry path (its source-basename root).
fn top_component(p: &Path) -> String {
    match p.components().next() {
        Some(std::path::Component::Normal(c)) => c.to_string_lossy().into_owned(),
        _ => String::new(),
    }
}

/// Rewrite the first component of `path` from `src_top` to `rename` (when
/// set); identity otherwise.
fn rewrite_top(path: &Path, src_top: &str, rename: Option<&str>) -> PathBuf {
    let Some(rename) = rename else {
        return path.to_path_buf();
    };
    let mut comps = path.components();
    match comps.next() {
        Some(std::path::Component::Normal(c)) if c.to_string_lossy() == src_top => {
            let rest = comps.as_path();
            // `Path::join("")` appends a trailing separator, which tar's
            // `create_new` open rejects for a single-component rename target.
            if rest.as_os_str().is_empty() {
                PathBuf::from(rename)
            } else {
                Path::new(rename).join(rest)
            }
        }
        _ => path.to_path_buf(),
    }
}

/// Root-relative parent of `rel` (`.` when `rel` is a single component).
fn parent_rel(rel: &Path) -> PathBuf {
    match rel.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Final path component of `rel` as a String (`.` when empty).
fn base_name(rel: &Path) -> String {
    rel.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string())
}

/// Authoritative containment check for one entry's landing path. Resolving
/// it with `RESOLVE_BENEATH`: a missing final component is fine (we are about
/// to create it), but any *escape* during resolution of the existing prefix
/// is rejected. We resolve the PARENT directory of the landing path; if the
/// parent escapes, reject; if the parent does not yet exist (an intermediate
/// dir entry earlier in the archive will create it) we treat it as acceptable.
fn guard_entry(root_dir: &OwnedFd, landing_rel: &Path) -> Result<(), TarError> {
    let parent = parent_rel(landing_rel);
    // Resolving the parent dir under the root catches `..` and escaping
    // symlinks in the path prefix. A non-existent parent is PathNotFound,
    // which for an in-archive intermediate dir is normal: tar's own unpack
    // creates parents, so we only enforce containment here, treating a
    // not-yet-existing (but in-root) parent as acceptable.
    match resolve_under_root(root_dir, &parent, OFlag::O_RDONLY | OFlag::O_DIRECTORY) {
        Ok(_fd) => Ok(()),
        Err((ErrorKind::PathNotFound, _)) => Ok(()), // parent created by tar
        Err(other) => Err(other),
    }
}

/// A read error mid-archive (missing tar EOF blocks) surfaces as
/// `UnexpectedEof`; map it to a clear truncation message, everything else to
/// `Internal`.
fn truncated_or_internal(e: std::io::Error) -> TarError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        (ErrorKind::Internal, "transfer truncated".to_string())
    } else {
        internal(e)
    }
}

/// A resolved cp source: the absolute host path under the root plus the
/// in-archive top-level name (the source's basename, so the host can rename
/// it).
pub struct ResolvedSrc {
    pub abs: PathBuf,
    pub arc_root: OsString,
}

/// Resolve the guest path `src` under `root` (confined by `openat2`) WITHOUT
/// touching the output stream — so a missing (`PathNotFound`) or escaping
/// (`BadRequest`) src can be reported as the *leading* status frame with no
/// tar bytes in front of it (§4). Opens read-only without `O_DIRECTORY` so a
/// file src is accepted too.
pub fn resolve_src(root: &Path, src: &str) -> Result<ResolvedSrc, TarError> {
    let root_dir = open_root_dir(root)?;
    let src_rel = root_relative(src);
    let _src_fd = resolve_under_root(&root_dir, &src_rel, OFlag::O_RDONLY)?;
    let abs = root.join(&src_rel);
    let arc_root: OsString = src_rel
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| OsString::from("."));
    Ok(ResolvedSrc { abs, arc_root })
}

/// Walk a resolved `src` and STREAM the tar directly into `out` (never
/// buffered). Entry names are rooted at `src.arc_root`. Regular files,
/// directories and symlinks are archived; sockets/fifos/devices are skipped
/// with a stderr warning. A mid-walk I/O error returns `Err` and leaves a
/// truncated archive on the wire — the host detects the missing EOF and
/// reports "transfer truncated".
pub fn stream_tar<W: Write>(src: &ResolvedSrc, out: &mut W) -> Result<(), TarError> {
    let mut builder = tar::Builder::new(out);
    // Symlinks INSIDE the tree are preserved (not followed). The top-level
    // src symlink was already followed by openat2 resolution in resolve_src.
    builder.follow_symlinks(false);
    append_recursive(&mut builder, &src.abs, Path::new(&src.arc_root))?;
    builder.finish().map_err(internal)?;
    Ok(())
}

/// Convenience used by tests: resolve `src` then stream the tar into `out` in
/// one call. The dispatch layer (server.rs) instead calls `resolve_src` and
/// `stream_tar` separately so it can emit the leading status frame between
/// them.
#[cfg(test)]
pub fn create<W: Write>(root: &Path, src: &str, out: &mut W) -> Result<(), TarError> {
    let resolved = resolve_src(root, src)?;
    stream_tar(&resolved, out)
}

/// Recursively append `host_path` to `builder` under in-archive name
/// `arc_name`. Symlinks are archived as links; special files are skipped.
fn append_recursive<W: Write>(
    builder: &mut tar::Builder<W>,
    host_path: &Path,
    arc_name: &Path,
) -> Result<(), TarError> {
    let meta = std::fs::symlink_metadata(host_path)
        .map_err(|e| internal(format!("stat {}: {e}", host_path.display())))?;
    let ft = meta.file_type();

    if ft.is_symlink() {
        let target = std::fs::read_link(host_path)
            .map_err(|e| internal(format!("readlink {}: {e}", host_path.display())))?;
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_metadata(&meta);
        h.set_cksum();
        builder
            .append_link(&mut h, arc_name, &target)
            .map_err(internal)?;
    } else if ft.is_dir() {
        // Emit the directory entry itself so empty dirs survive.
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        h.set_metadata(&meta);
        h.set_cksum();
        builder
            .append_data(&mut h, arc_name, &mut std::io::empty())
            .map_err(internal)?;
        let mut entries: Vec<_> = std::fs::read_dir(host_path)
            .map_err(|e| internal(format!("readdir {}: {e}", host_path.display())))?
            .filter_map(Result::ok)
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let child_host = e.path();
            let child_arc = arc_name.join(e.file_name());
            append_recursive(builder, &child_host, &child_arc)?;
        }
    } else if ft.is_file() {
        let mut f = std::fs::File::open(host_path)
            .map_err(|e| internal(format!("open {}: {e}", host_path.display())))?;
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_metadata(&meta);
        h.set_cksum();
        builder
            .append_data(&mut h, arc_name, &mut f)
            .map_err(internal)?;
    } else {
        // Socket / fifo / device / etc.: skip with a warning side-channel.
        eprintln!(
            "izba-init: cp: skipping unsupported file type at {}",
            host_path.display()
        );
    }
    Ok(())
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

    /// Build a single-file tar whose only entry is the regular file `base`
    /// (the source basename, no extra prefix), with content/mode.
    fn tar_file(base: &str, data: &[u8], mode: u32) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_mtime(0);
        h.set_cksum();
        b.append_data(&mut h, base, &mut &data[..]).unwrap();
        b.into_inner().unwrap()
    }

    /// Build a directory tar rooted at `base` (the source basename): a leading
    /// directory entry `base/`, then the given files and symlinks beneath it.
    /// The first entry is the top directory, as a real dir-walk produces.
    fn tar_dir(base: &str, files: &[(&str, &[u8], u32)], symlinks: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut dh = tar::Header::new_gnu();
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_size(0);
        dh.set_mode(0o755);
        dh.set_mtime(0);
        dh.set_cksum();
        b.append_data(&mut dh, format!("{base}/"), &mut std::io::empty())
            .unwrap();
        for (name, data, mode) in files {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_mtime(0);
            h.set_cksum();
            b.append_data(&mut h, format!("{base}/{name}"), &mut &data[..])
                .unwrap();
        }
        for (name, target) in symlinks {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            h.set_mtime(0);
            h.set_cksum();
            b.append_link(&mut h, format!("{base}/{name}"), target)
                .unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn extract_file_into_existing_dir_lands_inside() {
        // file→existing-dir: dest is a dir, source lands at dest/<basename>.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let archive = tar_file("foo.txt", b"hello", 0o644);
        let mut cursor = std::io::Cursor::new(archive);
        extract(root, "/etc", &mut cursor).expect("extract ok");
        assert_eq!(std::fs::read(root.join("etc/foo.txt")).unwrap(), b"hello");
    }

    #[test]
    fn extract_dir_into_existing_dir_nests_under_srcname() {
        // dir→existing-dir: source tree nests as dest/<srcname>/...
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let archive = tar_dir(
            "tree",
            &[
                ("a.txt", b"hello", 0o644),
                ("bin.sh", b"#!/bin/sh\n", 0o755),
            ],
            &[("link", "a.txt")],
        );
        let mut cursor = std::io::Cursor::new(archive);
        extract(root, "/etc", &mut cursor).expect("extract ok");
        assert_eq!(
            std::fs::read(root.join("etc/tree/a.txt")).unwrap(),
            b"hello"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("etc/tree/bin.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "exec bit must survive");
        let target = std::fs::read_link(root.join("etc/tree/link")).unwrap();
        assert_eq!(target, std::path::Path::new("a.txt"), "symlink preserved");
    }

    #[test]
    fn extract_file_to_missing_name_renames() {
        // file→missing-name: dest does not exist, parent does → rename.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let archive = tar_file("foo.txt", b"hello", 0o644);
        let mut cursor = std::io::Cursor::new(archive);
        extract(root, "/etc/renamed.txt", &mut cursor).expect("extract ok");
        assert_eq!(
            std::fs::read(root.join("etc/renamed.txt")).unwrap(),
            b"hello"
        );
    }

    #[test]
    fn extract_dir_to_missing_name_becomes_tree_root() {
        // dir→missing-name: directory source becomes the new tree root named dest.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        let archive = tar_dir("tree", &[("a.txt", b"hi", 0o644)], &[]);
        let mut cursor = std::io::Cursor::new(archive);
        extract(root, "/etc/newroot", &mut cursor).expect("extract ok");
        assert_eq!(
            std::fs::read(root.join("etc/newroot/a.txt")).unwrap(),
            b"hi"
        );
    }

    #[test]
    fn extract_file_over_existing_file_overwrites() {
        // file→existing-file: overwrite rule.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/target.txt"), b"old").unwrap();
        let archive = tar_file("foo.txt", b"new", 0o644);
        let mut cursor = std::io::Cursor::new(archive);
        extract(root, "/etc/target.txt", &mut cursor).expect("extract ok");
        assert_eq!(std::fs::read(root.join("etc/target.txt")).unwrap(), b"new");
    }

    #[test]
    fn extract_dir_over_existing_file_is_bad_request() {
        // dir→existing-file: cannot overwrite non-directory with directory.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/target"), b"old").unwrap();
        let archive = tar_dir("tree", &[("a.txt", b"hi", 0o644)], &[]);
        let mut cursor = std::io::Cursor::new(archive);
        let (kind, msg) =
            extract(root, "/etc/target", &mut cursor).expect_err("dir onto file must fail");
        assert_eq!(kind, ErrorKind::BadRequest, "{msg}");
        assert!(msg.contains("cannot overwrite"), "{msg}");
        // The pre-existing file is untouched.
        assert_eq!(std::fs::read(root.join("etc/target")).unwrap(), b"old");
    }

    #[test]
    fn extract_rejects_escaping_entry() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(dir.path().join("secret"), b"top").unwrap();
        // A malicious archive whose entry name climbs out of the root. The
        // high-level `append_data`/`set_path` refuse `..`, so we write the raw
        // GNU header name bytes directly and use `append` (which does not
        // re-validate the path) to forge the entry.
        let mut b = tar::Builder::new(Vec::new());
        let payload = b"pwned";
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(payload.len() as u64);
        h.set_mode(0o644);
        let name = b"../secret";
        let gnu = h.as_gnu_mut().unwrap();
        gnu.name[..name.len()].copy_from_slice(name);
        h.set_cksum();
        b.append(&h, &payload[..]).unwrap();
        let archive = b.into_inner().unwrap();

        // dest is the existing root dir → into-dir rule, entries extracted as-is,
        // so the `../secret` entry is caught by the per-entry guard.
        let mut cursor = std::io::Cursor::new(archive);
        let (kind, _msg) = extract(&root, "/", &mut cursor).expect_err("escape must fail");
        assert_eq!(kind, ErrorKind::BadRequest);
        // The sibling secret must be untouched.
        assert_eq!(std::fs::read(dir.path().join("secret")).unwrap(), b"top");
    }

    #[test]
    fn extract_dest_parent_missing_is_path_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let archive = tar_file("x", b"1", 0o644);
        let mut cursor = std::io::Cursor::new(archive);
        // `/missing/d` — neither `/missing/d` nor its parent `/missing` exists.
        let (kind, _msg) =
            extract(dir.path(), "/missing/d", &mut cursor).expect_err("missing parent");
        assert_eq!(kind, ErrorKind::PathNotFound);
    }

    #[test]
    fn create_walks_tree_with_modes_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("src/sub")).unwrap();
        std::fs::write(root.join("src/a.txt"), b"hello").unwrap();
        std::fs::write(root.join("src/sub/run.sh"), b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.join("src/sub/run.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("a.txt", root.join("src/link")).unwrap();

        let mut buf = Vec::new();
        create(root, "/src", &mut buf).expect("create ok");

        // Re-read the produced archive and assert the entry set.
        let mut got: std::collections::BTreeMap<String, (tar::EntryType, u32)> = Default::default();
        let mut links: std::collections::BTreeMap<String, String> = Default::default();
        let mut ar = tar::Archive::new(std::io::Cursor::new(&buf));
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            let p = e.path().unwrap().to_string_lossy().into_owned();
            let ty = e.header().entry_type();
            let mode = e.header().mode().unwrap() & 0o777;
            if ty == tar::EntryType::Symlink {
                links.insert(
                    p.clone(),
                    e.link_name()
                        .unwrap()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            got.insert(p, (ty, mode));
        }
        assert!(got.contains_key("src/a.txt"), "{got:?}");
        assert_eq!(got["src/sub/run.sh"].1, 0o755, "exec bit in archive");
        assert_eq!(links.get("src/link").map(String::as_str), Some("a.txt"));
    }

    #[test]
    fn create_missing_src_is_path_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let mut buf = Vec::new();
        let (kind, _msg) = create(dir.path(), "/nope", &mut buf).expect_err("missing src");
        assert_eq!(kind, ErrorKind::PathNotFound);
    }

    #[test]
    fn create_rejects_escaping_src() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(dir.path().join("secret"), b"top").unwrap();
        let mut buf = Vec::new();
        let (kind, _msg) = create(&root, "/../secret", &mut buf).expect_err("escape");
        assert_eq!(kind, ErrorKind::BadRequest);
    }
}
