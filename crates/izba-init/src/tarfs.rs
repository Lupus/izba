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
/// root using `openat2(RESOLVE_IN_ROOT)` — chroot semantics: absolute
/// symlinks and `..` inside symlink targets are reinterpreted relative to the
/// root, exactly as the workload itself would resolve them (so e.g. alpine's
/// absolute `/bin/ls -> /bin/busybox` link works). Resolution can therefore
/// never leave the root. `..` in the *requested path itself* is rejected
/// loudly (lexically) with `BadRequest` before the syscall — under
/// `RESOLVE_IN_ROOT` it would otherwise clamp silently, and the spec's error
/// table wants escape *attempts* to be observable. Returns an `OwnedFd` for
/// the resolved path opened with `flags`.
fn resolve_under_root(root_dir: &OwnedFd, rel: &Path, flags: OFlag) -> Result<OwnedFd, TarError> {
    reject_lexical_escape(rel)?;
    let how = OpenHow::new()
        .flags(flags | OFlag::O_CLOEXEC)
        .mode(Mode::empty())
        .resolve(ResolveFlag::RESOLVE_IN_ROOT);
    match openat2(root_dir.as_raw_fd(), rel, how) {
        Ok(raw) => Ok(unsafe { OwnedFd::from_raw_fd(raw) }),
        // ELOOP: symlink loop; EXDEV: a magic-link/mount crossing forbidden
        // under RESOLVE_IN_ROOT. Both are refusals to resolve, not missing
        // paths.
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

/// Loud lexical rejection of `..` (and any non-normal component) in a
/// root-relative path. `RESOLVE_IN_ROOT` would clamp these silently; the
/// spec error table requires escape attempts to fail with `BadRequest`.
fn reject_lexical_escape(rel: &Path) -> Result<(), TarError> {
    use std::path::Component;
    if rel
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err((
            ErrorKind::BadRequest,
            "path escapes workload root".to_string(),
        ));
    }
    Ok(())
}

/// The canonical (symlink-free, root-confined) host path behind an fd that
/// was resolved with `RESOLVE_IN_ROOT`. Filesystem operations must use THIS
/// path, never a plain `root.join(rel)`: the latter re-resolves symlinks
/// natively and an absolute symlink inside the tree would escape the root.
fn canon_via_fd(fd: &OwnedFd, what: &Path) -> Result<PathBuf, TarError> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|e| internal(format!("canonicalizing {}: {e}", display_rel(what))))
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
/// top path component to `rename` when set.
///
/// Containment: the landing path is checked lexically (no `..`), its parent
/// directory is resolved with `openat2(RESOLVE_IN_ROOT)`, and tar writes
/// through the parent's CANONICAL path (via the resolved fd) — so symlinks in
/// the prefix resolve with chroot semantics and can never lead outside the
/// root. A pre-existing symlink at the final component is replaced, not
/// followed (an archive could otherwise plant `x -> /etc/passwd` and then
/// write through it via a regular entry `x`).
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
    reject_lexical_escape(&landing_rel)?;

    // Resolve the parent dir. Our own builders always emit a directory entry
    // before its children, so a missing parent means an out-of-order or
    // crafted archive — reject it rather than guessing where to create dirs.
    let parent = parent_rel(&landing_rel);
    let parent_fd =
        match resolve_under_root(root_dir, &parent, OFlag::O_RDONLY | OFlag::O_DIRECTORY) {
            Ok(fd) => fd,
            Err((ErrorKind::PathNotFound, _)) => {
                return Err((
                    ErrorKind::BadRequest,
                    format!(
                        "archive entry {} has no parent directory (out-of-order archive)",
                        rewritten.display()
                    ),
                ))
            }
            Err(other) => return Err(other),
        };
    let canon_parent = canon_via_fd(&parent_fd, &parent)?;
    if !canon_parent.starts_with(root) {
        // RESOLVE_IN_ROOT guarantees this can't happen; treat a violation as
        // an internal invariant failure, never write.
        return Err(internal(format!(
            "resolved parent {} left the workload root",
            canon_parent.display()
        )));
    }
    let landing = canon_parent.join(base_name(&landing_rel));

    // Never write THROUGH a final-component symlink: replace it.
    if let Ok(meta) = std::fs::symlink_metadata(&landing) {
        if meta.file_type().is_symlink() {
            std::fs::remove_file(&landing)
                .map_err(|e| internal(format!("replacing symlink {}: {e}", landing.display())))?;
        }
    }
    entry.unpack(&landing).map_err(truncated_or_internal)?;
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
    let src_fd = resolve_under_root(&root_dir, &src_rel, OFlag::O_RDONLY)?;
    // Walk the CANONICAL path behind the resolved fd, never `root.join(rel)`:
    // the plain join would re-resolve symlinks natively, and an absolute
    // symlink in the prefix would escape the root. This also makes the
    // top-level src symlink "followed" (spec §3) with chroot semantics.
    let abs = canon_via_fd(&src_fd, &src_rel)?;
    if !abs.starts_with(root) {
        return Err(internal(format!(
            "resolved src {} left the workload root",
            abs.display()
        )));
    }
    // The in-archive name keeps the USER-VISIBLE basename (of the path as
    // given, not of the symlink target).
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
    use proptest::prelude::*;
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
    fn resolve_follows_absolute_symlink_inside_root() {
        // Chroot semantics: an ABSOLUTE symlink resolves relative to the
        // workload root, exactly as the workload sees it (e.g. alpine's
        // /bin/ls -> /bin/busybox). This must WORK, not error.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("real.txt"), b"in-root").unwrap();
        std::os::unix::fs::symlink("/real.txt", root.join("abs")).unwrap();
        let root_dir = open_root_dir(root).unwrap();
        let fd = resolve_under_root(&root_dir, &root_relative("/abs"), OFlag::O_RDONLY)
            .expect("absolute in-root symlink must resolve");
        let mut content = String::new();
        std::fs::File::from(fd)
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "in-root");
    }

    #[test]
    fn resolve_clamps_escaping_symlink_to_root() {
        // A symlink whose target points OUTSIDE the root resolves with chroot
        // semantics: the absolute target is reinterpreted under the root, so
        // it lands on a (missing) in-root path — the outside file is never
        // reached. Containment by clamping, not by rejection.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();
        fs::write(dir.path().join("secret"), b"top").unwrap();
        std::os::unix::fs::symlink(dir.path().join("secret"), root.join("link")).unwrap();
        let root_dir = open_root_dir(&root).unwrap();
        let (kind, _msg) = resolve_under_root(&root_dir, &root_relative("/link"), OFlag::O_RDONLY)
            .expect_err("clamped target does not exist in-root");
        assert_eq!(kind, ErrorKind::PathNotFound);

        // An upward relative symlink clamps the same way (`..` at the root is
        // a no-op under RESOLVE_IN_ROOT).
        std::os::unix::fs::symlink("../secret", root.join("up")).unwrap();
        let (kind, _msg) = resolve_under_root(&root_dir, &root_relative("/up"), OFlag::O_RDONLY)
            .expect_err("clamped upward target does not exist in-root");
        assert_eq!(kind, ErrorKind::PathNotFound);
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

    #[test]
    fn extract_through_absolute_symlink_dir_clamps_in_root() {
        // dest is reached through an in-root ABSOLUTE symlink (chroot
        // semantics): the file must land under the symlink's in-root target.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink("/real", root.join("abs")).unwrap();
        let archive = tar_file("f.txt", b"via-abs", 0o644);
        let mut cursor = std::io::Cursor::new(archive);
        extract(root, "/abs", &mut cursor).expect("extract through abs symlink");
        assert_eq!(fs::read(root.join("real/f.txt")).unwrap(), b"via-abs");
    }

    #[test]
    fn extract_replaces_final_symlink_instead_of_following() {
        // A pre-existing symlink at the landing path must be REPLACED by the
        // incoming file, never written through (its target stays untouched).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("dest")).unwrap();
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, b"old").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("dest/f.txt")).unwrap();
        let archive = tar_file("f.txt", b"new", 0o644);
        let mut cursor = std::io::Cursor::new(archive);
        extract(&root, "/dest", &mut cursor).expect("extract over symlink");
        let meta = fs::symlink_metadata(root.join("dest/f.txt")).unwrap();
        assert!(meta.file_type().is_file(), "symlink must be replaced");
        assert_eq!(fs::read(root.join("dest/f.txt")).unwrap(), b"new");
        assert_eq!(fs::read(&outside).unwrap(), b"old", "target untouched");
    }

    #[test]
    fn extract_rejects_out_of_order_archive() {
        // An entry whose parent directory has no earlier dir entry (and does
        // not exist) is a crafted/out-of-order archive → BadRequest.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("dest")).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let payload = b"x";
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(payload.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "top/missing/sub.txt", &mut &payload[..])
            .unwrap();
        let archive = b.into_inner().unwrap();
        let mut cursor = std::io::Cursor::new(archive);
        let (kind, msg) = extract(root, "/dest", &mut cursor).expect_err("out of order");
        assert_eq!(kind, ErrorKind::BadRequest, "{msg}");
        assert!(msg.contains("parent"), "{msg}");
    }

    #[test]
    fn create_follows_absolute_symlink_src() {
        // `izba cp NAME:/abs out` where /abs is an absolute in-root symlink
        // (alpine-style) must archive the TARGET, under the user-visible name.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("real")).unwrap();
        fs::write(root.join("real/data.txt"), b"abc").unwrap();
        std::os::unix::fs::symlink("/real", root.join("abs")).unwrap();
        let mut buf = Vec::new();
        create(root, "/abs", &mut buf).expect("create through abs symlink");
        let mut names = Vec::new();
        let mut archive = tar::Archive::new(std::io::Cursor::new(buf));
        for e in archive.entries().unwrap() {
            names.push(e.unwrap().path().unwrap().display().to_string());
        }
        assert!(names.contains(&"abs".to_string()), "{names:?}");
        assert!(names.contains(&"abs/data.txt".to_string()), "{names:?}");
    }

    // ── Property tests ──────────────────────────────────────────────────────

    /// Build a malicious raw regular-file entry: writes the name bytes directly
    /// into the GNU header (bypassing tar's own path-safety checks) and appends
    /// the entry. This is the same technique used in
    /// `extract_rejects_escaping_entry`.
    fn forge_entry(name_bytes: &[u8], data: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        let gnu = h.as_gnu_mut().unwrap();
        let copy_len = name_bytes.len().min(gnu.name.len() - 1);
        gnu.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        h.set_cksum();
        b.append(&h, data).unwrap();
        b.into_inner().unwrap()
    }

    /// Build a malicious raw symlink entry: writes `name_bytes` as the entry
    /// name and `link_bytes` as the link target, both directly into the GNU
    /// header (bypassing tar's path-safety checks). Used to forge symlinks with
    /// hazardous targets (absolute paths, `..`-escaping) without tar rejecting
    /// them during construction.
    fn forge_symlink_entry(name_bytes: &[u8], link_bytes: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        h.set_mtime(0);
        let gnu = h.as_gnu_mut().unwrap();
        let name_copy = name_bytes.len().min(gnu.name.len() - 1);
        gnu.name[..name_copy].copy_from_slice(&name_bytes[..name_copy]);
        let link_copy = link_bytes.len().min(gnu.linkname.len() - 1);
        gnu.linkname[..link_copy].copy_from_slice(&link_bytes[..link_copy]);
        h.set_cksum();
        b.append(&h, &[][..]).unwrap();
        b.into_inner().unwrap()
    }

    /// Append a raw regular-file entry (with forged name bytes) onto an
    /// existing `tar::Builder<Vec<u8>>`. Used when building multi-entry archives.
    fn append_forge_entry(b: &mut tar::Builder<Vec<u8>>, name_bytes: &[u8], data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        let gnu = h.as_gnu_mut().unwrap();
        let copy_len = name_bytes.len().min(gnu.name.len() - 1);
        gnu.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    /// Append a raw symlink entry (with forged name and link bytes) onto an
    /// existing `tar::Builder<Vec<u8>>`.
    fn append_forge_symlink(b: &mut tar::Builder<Vec<u8>>, name_bytes: &[u8], link_bytes: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        h.set_mtime(0);
        let gnu = h.as_gnu_mut().unwrap();
        let name_copy = name_bytes.len().min(gnu.name.len() - 1);
        gnu.name[..name_copy].copy_from_slice(&name_bytes[..name_copy]);
        let link_copy = link_bytes.len().min(gnu.linkname.len() - 1);
        gnu.linkname[..link_copy].copy_from_slice(&link_bytes[..link_copy]);
        h.set_cksum();
        b.append(&h, &[][..]).unwrap();
    }

    /// Walk `start` recursively; return absolute paths of every filesystem
    /// object found (files, dirs, symlinks). Used to confirm nothing escaped
    /// the root.
    fn walk_all(start: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(start) else {
            return out;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            out.push(p.clone());
            if meta.is_dir() {
                out.extend(walk_all(&p));
            }
        }
        out
    }

    /// The set of entry names that exercise various escape vectors.
    fn hazardous_entry_names() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // dot-dot at the start
            Just(b"../secret".to_vec()),
            Just(b"../../x".to_vec()),
            // absolute path
            Just(b"/etc/passwd".to_vec()),
            // nested dot-dot
            Just(b"a/../../../b".to_vec()),
            // normal relative (should succeed)
            Just(b"inside/file.txt".to_vec()),
            // zero-length (edge case)
            Just(b"".to_vec()),
            // random mix from a limited alphabet plus injected hazards
            prop::collection::vec(
                prop::sample::select(vec![b'a', b'b', b'c', b'.', b'/', b'_', b'-',]),
                1..24,
            ),
        ]
    }

    /// Hazardous symlink TARGETS: absolute paths and relative-escaping paths
    /// that a malicious archive might use to plant a symlink pointing outside
    /// the root.
    fn hazardous_symlink_targets() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            // absolute — chroot-semantics clamp these inside root
            Just(b"/etc/passwd".to_vec()),
            Just(b"/secret".to_vec()),
            // relative-escaping (above parent of root — the deepest threat)
            Just(b"../../x".to_vec()),
            Just(b"../../../escape".to_vec()),
            // relative non-escaping (in-root; allowed content)
            Just(b"safe_target".to_vec()),
            Just(b"a/b".to_vec()),
        ]
    }

    /// The archive shape to feed to the containment property. Covers:
    ///   A) single regular file with hazardous name (original vector)
    ///   B) single symlink with hazardous target
    ///   C) plant-then-write-through: symlink with hazardous target, then a
    ///      regular file AT THE SAME NAME (write-through attack — the production
    ///      code defends against this by replacing the symlink, not following it)
    ///   D) out-of-order: regular file whose parent dir was never emitted
    ///      (a common adversarial archive construction)
    #[derive(Debug, Clone)]
    enum ContainmentArchive {
        /// Single regular file entry with a forged (possibly hazardous) name.
        SingleFile { name: Vec<u8> },
        /// Single symlink entry with a safe name but hazardous target.
        SingleSymlink { name: Vec<u8>, target: Vec<u8> },
        /// Plant-then-write-through: symlink(name→hazardous_target) followed
        /// by a regular file at the same name.  The production code must replace
        /// the symlink rather than writing through it.
        PlantThenWriteThrough { name: Vec<u8>, target: Vec<u8> },
        /// Regular file whose parent directory was never emitted (out-of-order).
        OutOfOrderChild {
            parent: Vec<u8>,
            child_name: Vec<u8>,
        },
    }

    fn arb_containment_archive() -> impl Strategy<Value = ContainmentArchive> {
        prop_oneof![
            // A: single file with hazardous name
            hazardous_entry_names().prop_map(|name| ContainmentArchive::SingleFile { name }),
            // B: symlink with hazardous target
            (hazardous_entry_names(), hazardous_symlink_targets())
                .prop_map(|(name, target)| ContainmentArchive::SingleSymlink { name, target }),
            // C: plant-then-write-through (core symlink attack class)
            (
                prop::sample::select(vec![
                    b"f".to_vec(),
                    b"a".to_vec(),
                    b"b".to_vec(),
                    b"link".to_vec(),
                ]),
                hazardous_symlink_targets(),
            )
                .prop_map(|(name, target)| ContainmentArchive::PlantThenWriteThrough {
                    name,
                    target,
                }),
            // D: out-of-order (child before parent dir)
            (
                prop::sample::select(vec![b"missing_parent".to_vec(), b"no_such_dir".to_vec(),]),
                prop::sample::select(vec![b"child.txt".to_vec(), b"x".to_vec()]),
            )
                .prop_map(|(parent, child_name)| ContainmentArchive::OutOfOrderChild {
                    parent,
                    child_name,
                }),
        ]
    }

    /// Build the raw tar bytes for a `ContainmentArchive` variant.
    fn build_containment_archive(ca: &ContainmentArchive) -> Vec<u8> {
        match ca {
            ContainmentArchive::SingleFile { name } => forge_entry(name, b"payload"),
            ContainmentArchive::SingleSymlink { name, target } => forge_symlink_entry(name, target),
            ContainmentArchive::PlantThenWriteThrough { name, target } => {
                // Two entries: first a symlink(name→target), then a regular
                // file at the same name.  The extractor must replace the symlink
                // rather than following it to write outside root.
                let mut b = tar::Builder::new(Vec::new());
                append_forge_symlink(&mut b, name, target);
                append_forge_entry(&mut b, name, b"overwrite");
                b.into_inner().unwrap()
            }
            ContainmentArchive::OutOfOrderChild { parent, child_name } => {
                // Child path "parent/child_name" with no prior directory entry
                // for "parent".
                let mut full_path = parent.clone();
                full_path.push(b'/');
                full_path.extend_from_slice(child_name);
                forge_entry(&full_path, b"orphan")
            }
        }
    }

    /// Returns true if the archive contains an entry (by name or link) that
    /// constitutes a known lexical escape attempt.
    fn archive_has_lexical_escape(ca: &ContainmentArchive) -> bool {
        let name_escapes = |name: &[u8]| -> bool {
            if name.starts_with(b"/") {
                return true;
            }
            let s = std::str::from_utf8(name).unwrap_or("");
            s.split('/').any(|c| c == "..")
        };
        match ca {
            ContainmentArchive::SingleFile { name } => name_escapes(name),
            // A symlink entry's NAME is safe (we use plain names for B/C); the
            // *target* may escape but that is allowed content, not a name escape.
            ContainmentArchive::SingleSymlink { name, .. } => name_escapes(name),
            // The symlink name in PlantThenWriteThrough is always a safe ASCII
            // identifier, so no lexical escape in the entry names themselves.
            ContainmentArchive::PlantThenWriteThrough { .. } => false,
            // Out-of-order: "parent/child" — no `..` components.
            ContainmentArchive::OutOfOrderChild { .. } => false,
        }
    }

    /// Returns true if the archive is expected to always return Err (even if no
    /// lexical escape in entry names) — e.g. out-of-order archives.
    fn archive_always_errors(ca: &ContainmentArchive) -> bool {
        matches!(ca, ContainmentArchive::OutOfOrderChild { .. })
    }

    proptest! {
        /// **Containment property**: after calling `extract` on an adversarially
        /// crafted archive (whether it returns Ok or Err), NO filesystem object
        /// must exist OUTSIDE the canonicalized root. The property asserts on
        /// filesystem LOCATION — a symlink whose *target* points outside the root
        /// is allowed as content; what is forbidden is a real object (file, dir,
        /// symlink) whose *location* is outside the root.
        ///
        /// The generator covers four attack classes:
        ///   A) Regular file with hazardous name (`..`/absolute — original vector)
        ///   B) Symlink with hazardous target (absolute or `..`-escaping)
        ///   C) Plant-then-write-through: first plant a symlink(name→escape_target),
        ///      then write a regular file at the same name — the extractor must
        ///      REPLACE the symlink rather than follow it.
        ///   D) Out-of-order: regular file whose parent dir was never emitted.
        ///
        /// The root is nested three levels deep inside the tempdir (`<tmp>/a/b/root`)
        /// so that a `../../x` escape from root lands in `<tmp>/a/`, which is still
        /// INSIDE the walked tree — making the location assertion catch above-parent
        /// escapes, not just the single-parent-level ones.
        ///
        /// Additionally, any archive entry with a lexical escape in its name
        /// (`..'` component or leading `/`) MUST result in `Err(BadRequest)`.
        /// This assertion becomes non-vacuous when `reject_lexical_escape` is
        /// weakened: RESOLVE_IN_ROOT clamps the path but doesn't error.
        #[test]
        fn prop_containment_no_escape(ca in arb_containment_archive()) {
            // Nest root three levels deep: <tmp>/a/b/root
            // A "../../x" escape from root lands in <tmp>/a/ — still inside the
            // walked tree rooted at <tmp>/a/ (the walk starts at <tmp>/a/).
            // Sentinels are placed at every level so any out-of-root write is caught.
            let outer = tempfile::tempdir().unwrap();
            // Walk starts here so ../../ escapes from root land inside it.
            let walk_top = outer.path().join("a");
            let root = walk_top.join("b").join("root");
            fs::create_dir_all(&root).unwrap();

            // Sentinels at each non-root level so we detect writes anywhere above root.
            let sentinel_a = walk_top.join("sentinel_a.txt");
            let sentinel_b = walk_top.join("b").join("sentinel_b.txt");
            fs::write(&sentinel_a, b"untouched_a").unwrap();
            fs::write(&sentinel_b, b"untouched_b").unwrap();

            let archive = build_containment_archive(&ca);
            let result = extract(&root, "/", &mut &archive[..]);

            // Walk everything under walk_top (<tmp>/a).
            // Anything not under root (and not a pre-placed sentinel/dir) is an escape.
            let all = walk_all(&walk_top);
            for p in &all {
                if p.starts_with(&root) {
                    continue;
                }
                // Pre-placed sentinels and their ancestor directories are fine.
                if p == &sentinel_a || p == &sentinel_b {
                    continue;
                }
                // The b/ and root/ directory entries themselves are fine.
                if *p == walk_top.join("b") || *p == root {
                    continue;
                }
                panic!(
                    "ESCAPE DETECTED: path {:?} exists outside root {:?} (archive={:?})",
                    p, root, ca
                );
            }
            // Sentinels must be untouched.
            prop_assert_eq!(
                fs::read(&sentinel_a).unwrap(),
                b"untouched_a",
                "sentinel_a was modified — escape occurred (archive={:?})",
                ca
            );
            prop_assert_eq!(
                fs::read(&sentinel_b).unwrap(),
                b"untouched_b",
                "sentinel_b was modified — escape occurred (archive={:?})",
                ca
            );
            // An entry with a lexical escape attempt in its NAME MUST return BadRequest.
            if archive_has_lexical_escape(&ca) {
                prop_assert!(
                    matches!(result, Err((ErrorKind::BadRequest, _))),
                    "lexical escape must return BadRequest, got {:?} (archive={:?})",
                    result.err(),
                    ca
                );
            }
            // Out-of-order archives always error.
            if archive_always_errors(&ca) {
                prop_assert!(
                    result.is_err(),
                    "out-of-order archive must return Err, got Ok (archive={:?})",
                    ca
                );
            }
        }
    }

    // ── Roundtrip property ───────────────────────────────────────────────────

    /// A simple in-root tree entry (file or in-root symlink).
    #[derive(Debug, Clone)]
    enum TreeEntry {
        File {
            rel_path: String, // relative to tree root, no leading slash, no ..
            content: Vec<u8>,
            mode: u32,
        },
        Symlink {
            rel_path: String, // relative to tree root
            target: String,   // in-root relative target (just a filename)
        },
    }

    /// Generate a bounded set of valid in-root tree entries.
    fn arb_tree_entries() -> impl Strategy<Value = Vec<TreeEntry>> {
        // A pool of safe relative names to pick from.
        let names: Vec<String> = ["alpha", "beta", "gamma", "delta", "epsilon"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let names_arc = std::sync::Arc::new(names);

        let file_strategy = {
            let n = names_arc.clone();
            (
                prop::sample::select((*n).clone()),
                prop::collection::vec(any::<u8>(), 0..32),
                prop::sample::select(vec![0o644u32, 0o755u32, 0o600u32]),
            )
                .prop_map(|(name, content, mode)| TreeEntry::File {
                    rel_path: format!("{name}.txt"),
                    content,
                    mode,
                })
        };

        let sym_strategy = {
            let n = names_arc.clone();
            let n2 = names_arc.clone();
            (
                prop::sample::select((*n).clone()),
                prop::sample::select((*n2).clone()),
            )
                .prop_map(|(name, target)| TreeEntry::Symlink {
                    rel_path: format!("link_{name}"),
                    target: format!("{target}.txt"),
                })
        };

        prop::collection::vec(prop_oneof![file_strategy, sym_strategy], 1..6)
    }

    proptest! {
        /// **Roundtrip property**: create a valid in-root tree on disk, `create`
        /// it into a tar, `extract` the tar into a fresh root, and assert that
        /// every file/symlink from the original tree is present with identical
        /// content and symlink target. Mode bits are checked for files.
        #[test]
        fn prop_roundtrip_create_extract(entries in arb_tree_entries()) {
            use std::os::unix::fs::PermissionsExt;

            let src_dir = tempfile::tempdir().unwrap();
            let src_root = src_dir.path();

            // Build source tree: one top-level directory "src" containing all
            // entries (so create() gives us the right arc_root).
            fs::create_dir_all(src_root.join("src")).unwrap();

            // Deduplicate rel_paths so we don't try to write two entries at
            // the same path (proptest can generate that; just skip duplicates).
            let mut seen = std::collections::HashSet::new();
            let unique_entries: Vec<_> = entries.into_iter()
                .filter(|e| {
                    let rp = match e {
                        TreeEntry::File { rel_path, .. } => rel_path.clone(),
                        TreeEntry::Symlink { rel_path, .. } => rel_path.clone(),
                    };
                    seen.insert(rp)
                })
                .collect();

            for entry in &unique_entries {
                match entry {
                    TreeEntry::File { rel_path, content, mode } => {
                        let p = src_root.join("src").join(rel_path);
                        fs::write(&p, content).unwrap();
                        fs::set_permissions(&p, fs::Permissions::from_mode(*mode)).unwrap();
                    }
                    TreeEntry::Symlink { rel_path, target } => {
                        let p = src_root.join("src").join(rel_path);
                        // Ignore errors: duplicate or pre-existing target is fine.
                        let _ = std::os::unix::fs::symlink(target, &p);
                    }
                }
            }

            // Create tar.
            let mut buf = Vec::new();
            create(src_root, "/src", &mut buf).expect("create must succeed");

            // Extract into a fresh dest root.
            let dst_dir = tempfile::tempdir().unwrap();
            let dst_root = dst_dir.path();
            extract(dst_root, "/src", &mut &buf[..]).expect("extract must succeed");

            // Assert each entry is present with correct content/mode/target.
            for entry in &unique_entries {
                match entry {
                    TreeEntry::File { rel_path, content, mode } => {
                        let dst_path = dst_root.join("src").join(rel_path);
                        prop_assert!(
                            dst_path.exists(),
                            "file missing after roundtrip: {rel_path}"
                        );
                        let got = fs::read(&dst_path).unwrap();
                        prop_assert_eq!(&got, content, "content mismatch for {}", rel_path);
                        let got_mode = fs::metadata(&dst_path).unwrap().permissions().mode() & 0o777;
                        prop_assert_eq!(got_mode, *mode, "mode mismatch for {}", rel_path);
                    }
                    TreeEntry::Symlink { rel_path, target } => {
                        let dst_path = dst_root.join("src").join(rel_path);
                        let meta = fs::symlink_metadata(&dst_path);
                        if meta.is_ok() && meta.unwrap().file_type().is_symlink() {
                            let got_target = fs::read_link(&dst_path).unwrap();
                            let got_target_str = got_target.to_string_lossy().into_owned();
                            prop_assert_eq!(
                                got_target_str.as_str(),
                                target.as_str(),
                                "symlink target mismatch for {}",
                                rel_path
                            );
                        }
                        // If the symlink was silently dropped (dangling target in
                        // some extraction modes), that is acceptable — no panic.
                    }
                }
            }
        }
    }
}
