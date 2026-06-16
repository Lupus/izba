//! Host side of `izba cp`: drive a tar stream over one stream-port
//! connection. Direction and framing per the cp design §4:
//!   - to-guest: send `StreamOpen::TarExtract{dest}`, stream a tar, read one
//!     trailing `Response`.
//!   - from-guest: send `StreamOpen::TarCreate{src}`, read one leading
//!     `Response`, then unpack the tar that follows.
//!
//! Tar entries are ALWAYS rooted at the source's basename (a single
//! top-level component). The §3 dest-rule matrix is arbitrated on the
//! RECEIVING side — the only one that can stat dest: the guest's
//! `tarfs::extract` for host→guest (we send `guest_dest` verbatim, doing no
//! arbitration here), and `host_dest_plan` locally for guest→host.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use izba_proto::{read_frame, write_frame, ErrorKind, Response, StreamOpen};

/// Abstracts the stream-port connection so tests can substitute a
/// `UnixStream::pair()` half. The production caller passes the
/// `default_stream_connector` result (a `UdsStream`).
pub trait CpStream: Read + Write {}
impl<T: Read + Write> CpStream for T {}

/// Copy a host path/tree into the guest at `guest_dest`.
///
/// We do NO dest-rule arbitration here — the host cannot stat the guest.
/// The archive is ALWAYS rooted at `basename(host_src)` (a single top-level
/// component), and `guest_dest` is sent VERBATIM as the `TarExtract` dest.
/// The guest's `tarfs::extract` is the receiving side that applies the §3
/// matrix (into-dir / rename / overwrite / dir-onto-file) against the real
/// guest dest. `host_src` is followed if it is itself a top-level symlink
/// (docker behavior); `std::fs::metadata` (vs `symlink_metadata`) follows it.
pub fn copy_to_guest<S: CpStream>(
    mut conn: S,
    host_src: &Path,
    guest_dest: &str,
) -> anyhow::Result<()> {
    // `metadata` follows a top-level src symlink (docker behavior); the
    // archive root keeps the link's own basename.
    let meta = std::fs::metadata(host_src)
        .with_context(|| format!("{}: no such file or directory", host_src.display()))?;
    let top_name = base_component(&host_src.to_string_lossy());

    write_frame(
        &mut conn,
        &StreamOpen::TarExtract {
            dest: guest_dest.to_string(),
        },
    )
    .context("sending cp stream header")?;

    // Build the archive directly into the connection, rooted at the source
    // basename. The guest decides where it lands.
    let write_result = (|| -> anyhow::Result<()> {
        let mut builder = tar::Builder::new(&mut conn);
        builder.follow_symlinks(false);
        if meta.is_dir() {
            append_dir(&mut builder, host_src, Path::new(&top_name))
                .context("archiving directory")?;
        } else {
            append_file(&mut builder, host_src, Path::new(&top_name)).context("archiving file")?;
        }
        builder.finish().context("finishing tar stream")?;
        Ok(())
    })();

    // A write failure usually means the guest rejected the transfer early
    // (e.g. dir-onto-file) and closed its end mid-archive, so our write hit a
    // broken pipe. The guest's trailing status frame carries the real reason;
    // try to read it and surface that instead of the raw pipe error. Only if
    // no frame is available do we propagate the original write error.
    if let Err(write_err) = write_result {
        return match read_frame::<_, Response>(&mut conn) {
            Ok(Response::Error { kind, message }) => {
                Err(map_guest_error(kind, message, guest_dest))
            }
            Ok(Response::Ok) => Err(write_err),
            Ok(other) => Err(write_err.context(format!("unexpected cp reply: {other:?}"))),
            Err(_) => Err(write_err),
        };
    }

    match read_frame::<_, Response>(&mut conn).context("reading cp result")? {
        Response::Ok => Ok(()),
        Response::Error { kind, message } => Err(map_guest_error(kind, message, guest_dest)),
        other => bail!("unexpected cp reply: {other:?}"),
    }
}

/// Copy a guest path/tree out to `host_dest`, applying host-side dest rules.
pub fn copy_from_guest<S: CpStream>(
    mut conn: S,
    guest_src: &str,
    host_dest: &Path,
) -> anyhow::Result<()> {
    write_frame(
        &mut conn,
        &StreamOpen::TarCreate {
            src: guest_src.to_string(),
        },
    )
    .context("sending cp stream header")?;

    // Leading status frame first.
    match read_frame::<_, Response>(&mut conn).context("reading cp result")? {
        Response::Ok => {}
        Response::Error { kind, message } => return Err(map_guest_error(kind, message, guest_src)),
        other => bail!("unexpected cp reply: {other:?}"),
    }

    // The guest archives entries rooted at basename(src). Apply host dest
    // rules by rewriting that top-level component as we unpack.
    let src_base = base_component(guest_src);
    let dest_is_file = host_dest.is_file();
    let (unpack_base, rename_top) = host_dest_plan(host_dest, &src_base)?;

    unpack_stream(
        &mut conn,
        &unpack_base,
        &src_base,
        rename_top.as_deref(),
        dest_is_file,
        guest_src,
        host_dest,
    )
}

/// Unpack a guest-produced tar `reader` under `unpack_base`, applying the §3
/// dest rules (top-component rewrite + dir-onto-file guard) AND containing the
/// extraction against a hostile guest. This is the security-load-bearing seam:
/// the host side of boundary B-CP (threat-model §7 invariant 1 — "no host-FS
/// write outside the dest root from any guest action"). The archive is
/// **untrusted** (the guest builds it), so we mirror the guest-side
/// `izba-init/tarfs.rs` hardening here rather than trusting the `tar` crate,
/// whose `entry.unpack` does NOT contain absolute paths, `..`, or symlink
/// targets (verified by the `poc_*` abuse tests):
///
///   - Reject any entry whose landing path is lexically absolute or contains a
///     `..` component (after the top-component rewrite), before joining.
///   - Refuse to traverse a symlink while materializing the parent
///     (`safe_create_dir_all`), and verify the realized parent stays within
///     `unpack_base`. This blocks entry B of the two-step symlink escape.
///   - Symlink/hardlink ENTRIES whose target escapes `unpack_base` (absolute,
///     or `..` climbing above the base) are refused. This blocks entry A.
///   - A pre-existing symlink AT the final component is replaced, never
///     followed.
///
/// Portable across Linux (KVM) and Windows (WHP) — the baseline is pure path
/// arithmetic + `symlink_metadata`, no `openat2`. `unpack_base` must already
/// exist (the dest-plan guarantees it). Split out of `copy_from_guest` so
/// abuse-case tests can drive it with an in-memory tar via `std::io::Cursor`
/// instead of a real vsock connection.
#[allow(clippy::too_many_arguments)]
fn unpack_stream<R: Read>(
    reader: R,
    unpack_base: &Path,
    src_base: &str,
    rename_top: Option<&str>,
    dest_is_file: bool,
    guest_src: &str,
    host_dest: &Path,
) -> anyhow::Result<()> {
    // Canonical base, used to confine every per-entry parent resolution. The
    // base is host-chosen (never attacker-controlled) and known to exist.
    let canon_base = unpack_base
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", unpack_base.display()))?;

    let mut archive = tar::Archive::new(reader);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(false);

    let mut saw_entry = false;
    for entry in archive.entries().context("reading guest archive")? {
        let mut entry = entry.map_err(truncated)?;
        let entry_type = entry.header().entry_type();
        // §3 matrix: a directory source cannot overwrite an existing file.
        // The first entry reveals the source type (dir-walk tars emit the
        // top directory entry first).
        if !saw_entry && dest_is_file && entry_type == tar::EntryType::Directory {
            bail!(
                "cannot overwrite non-directory {} with directory {}",
                host_dest.display(),
                guest_src
            );
        }
        saw_entry = true;
        let path = entry.path().context("reading entry path")?.into_owned();
        let rewritten = rewrite_top(&path, src_base, rename_top);

        // (1) Lexical containment: no absolute path, no `..` component. Under a
        // plain `unpack_base.join(rewritten)` an absolute `rewritten` REPLACES
        // the base entirely, and a `..` climbs out (both PoC-confirmed).
        reject_lexical_escape(&rewritten)
            .with_context(|| format!("refusing guest archive entry {}", rewritten.display()))?;

        let dest_path = canon_base.join(&rewritten);

        // (2) Link entries: refuse a symlink/hardlink whose target escapes the
        // base (absolute, or `..` above the base). Blocks entry A of the
        // two-step symlink escape (planting `x -> /tmp/evil`).
        if matches!(entry_type, tar::EntryType::Symlink | tar::EntryType::Link) {
            if let Some(link) = entry.link_name().context("reading entry link target")? {
                reject_escaping_link_target(&link, &rewritten, &canon_base).with_context(|| {
                    format!(
                        "refusing guest archive link {} -> {}",
                        rewritten.display(),
                        link.display()
                    )
                })?;
            }
        }

        // (3) Materialize the parent WITHOUT following any symlink prefix, then
        // verify the realized parent is still inside the base.
        // `safe_create_dir_all` refuses to descend through an existing symlink
        // component, so entry B of the two-step escape (writing `x/payload`
        // where `x` is a planted symlink) cannot reach outside.
        if let Some(parent) = dest_path.parent() {
            safe_create_dir_all(&canon_base, parent)
                .with_context(|| format!("creating {}", parent.display()))?;
            let canon_parent = parent
                .canonicalize()
                .with_context(|| format!("canonicalizing {}", parent.display()))?;
            if !canon_parent.starts_with(&canon_base) {
                bail!(
                    "refusing guest archive entry {}: parent {} escapes {}",
                    rewritten.display(),
                    canon_parent.display(),
                    canon_base.display()
                );
            }
        }

        // (4) Never write THROUGH a final-component symlink: replace it (an
        // archive could otherwise plant `x -> /etc/passwd` then write `x`).
        if let Ok(meta) = std::fs::symlink_metadata(&dest_path) {
            if meta.file_type().is_symlink() {
                std::fs::remove_file(&dest_path).with_context(|| {
                    format!("replacing pre-existing symlink {}", dest_path.display())
                })?;
            }
        }

        entry
            .unpack(&dest_path)
            .map_err(truncated)
            .with_context(|| format!("writing {}", dest_path.display()))?;
    }
    if !saw_entry {
        bail!("transfer truncated (no archive entries received)");
    }
    Ok(())
}

/// Loud lexical rejection of an absolute path or any `..`/non-normal component
/// in a base-relative landing path. Mirrors `izba-init/tarfs.rs`'s
/// `reject_lexical_escape`: `RootDir`/`Prefix` (absolute) and `ParentDir`
/// (`..`) escape; only `Normal`/`CurDir` are allowed.
fn reject_lexical_escape(rel: &Path) -> anyhow::Result<()> {
    use std::path::Component;
    if rel
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        bail!("path escapes the destination root");
    }
    Ok(())
}

/// Refuse a symlink/hardlink whose `target`, resolved lexically relative to the
/// link's own location, would land outside `canon_base`. An absolute target is
/// always refused; a relative target is joined onto the link's parent and
/// reduced lexically (`..`-collapsed) before the containment check. Pure path
/// arithmetic — no filesystem access (the prefix is contained separately by
/// `safe_create_dir_all`).
fn reject_escaping_link_target(
    target: &Path,
    link_rel: &Path,
    canon_base: &Path,
) -> anyhow::Result<()> {
    if target.is_absolute() {
        bail!("link target is absolute");
    }
    let link_parent = link_rel.parent().unwrap_or_else(|| Path::new(""));
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    for comp in canon_base.join(link_parent).join(target).components() {
        use std::path::Component;
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                stack.clear();
                stack.push(comp.as_os_str().to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                stack.pop();
            }
            Component::Normal(c) => stack.push(c.to_os_string()),
        }
    }
    let resolved: PathBuf = stack.iter().collect();
    if !resolved.starts_with(canon_base) {
        bail!("link target escapes the destination root");
    }
    Ok(())
}

/// `create_dir_all` that refuses to traverse an existing symlink: it walks the
/// path component-by-component under `canon_base`, and if any existing
/// component is a symlink it bails rather than following it. The host analogue
/// of the guest's per-entry `openat2(RESOLVE_IN_ROOT)` parent resolution —
/// portable (Linux + Windows) and the always-on baseline.
fn safe_create_dir_all(canon_base: &Path, dir: &Path) -> anyhow::Result<()> {
    // `dir` is `canon_base.join(rel)`; walk only the relative tail.
    let rel = dir.strip_prefix(canon_base).unwrap_or(dir);
    let mut cur = canon_base.to_path_buf();
    for comp in rel.components() {
        use std::path::Component;
        match comp {
            Component::Normal(c) => cur.push(c),
            Component::CurDir => continue,
            // Should never occur (the lexical check ran first); refuse loudly.
            _ => bail!("refusing to create directory through {}", dir.display()),
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "refusing to descend through existing symlink {}",
                    cur.display()
                );
            }
            Ok(meta) if meta.is_dir() => {} // already a real directory: fine
            Ok(_) => bail!("{} exists and is not a directory", cur.display()),
            Err(_) => {
                std::fs::create_dir(&cur).with_context(|| format!("creating {}", cur.display()))?
            }
        }
    }
    Ok(())
}

// -------------------------------------------------------------------------
// dest-rule helpers
// -------------------------------------------------------------------------

/// The final path component of a path string (e.g. `/etc/app` -> `app`).
fn base_component(p: &str) -> String {
    Path::new(p)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string())
}

/// Decide where to unpack a guest->host archive and whether to rename its
/// top-level component, per §3:
///
/// - dest is an existing directory -> unpack INTO it, keep src basename.
/// - dest does not exist -> rename top component to dest base, unpack under
///   dest's parent.
/// - dest is an existing file -> caller validated file-vs-dir; rename to dest
///   base under parent.
///
/// Returns (unpack_base, Some(rename) | None).
fn host_dest_plan(host_dest: &Path, src_base: &str) -> anyhow::Result<(PathBuf, Option<String>)> {
    if host_dest.is_dir() {
        return Ok((host_dest.to_path_buf(), None));
    }
    // Rename: parent must exist.
    let parent = host_dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("{}: no such file or directory", parent.display());
    }
    let new_top = host_dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| src_base.to_string());
    Ok((parent.to_path_buf(), Some(new_top)))
}

/// Rewrite the first path component of `path` from `src_base` to `rename`
/// (when renaming); identity when `rename` is None.
fn rewrite_top(path: &Path, src_base: &str, rename: Option<&str>) -> PathBuf {
    let Some(rename) = rename else {
        return path.to_path_buf();
    };
    let mut comps = path.components();
    let first = comps.next();
    match first {
        Some(std::path::Component::Normal(c)) if c.to_string_lossy() == src_base => {
            let rest = comps.as_path();
            if rest.as_os_str().is_empty() {
                PathBuf::from(rename)
            } else {
                Path::new(rename).join(rest)
            }
        }
        _ => path.to_path_buf(),
    }
}

fn map_guest_error(kind: ErrorKind, message: String, path: &str) -> anyhow::Error {
    match kind {
        ErrorKind::PathNotFound => {
            anyhow::anyhow!("{path}: no such file or directory")
        }
        _ => anyhow::anyhow!("cp failed ({kind:?}): {message}"),
    }
}

fn truncated(e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        anyhow::anyhow!("transfer truncated")
    } else {
        anyhow::Error::from(e)
    }
}

// -------------------------------------------------------------------------
// local tar walk (host side)
// -------------------------------------------------------------------------

fn append_file<W: Write>(
    builder: &mut tar::Builder<W>,
    host_path: &Path,
    arc_name: &Path,
) -> anyhow::Result<()> {
    let mut f = std::fs::File::open(host_path)
        .with_context(|| format!("opening {}", host_path.display()))?;
    let meta = f.metadata()?;
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_metadata(&meta);
    h.set_cksum();
    builder.append_data(&mut h, arc_name, &mut f)?;
    Ok(())
}

fn append_dir<W: Write>(
    builder: &mut tar::Builder<W>,
    host_path: &Path,
    arc_name: &Path,
) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(host_path)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = std::fs::read_link(host_path)?;
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_metadata(&meta);
        h.set_cksum();
        builder.append_link(&mut h, arc_name, &target)?;
        return Ok(());
    }
    if ft.is_dir() {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        h.set_metadata(&meta);
        h.set_cksum();
        builder.append_data(&mut h, arc_name, &mut std::io::empty())?;
        let mut entries: Vec<_> = std::fs::read_dir(host_path)?
            .filter_map(Result::ok)
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            append_dir(builder, &e.path(), &arc_name.join(e.file_name()))?;
        }
        return Ok(());
    }
    if ft.is_file() {
        return append_file(builder, host_path, arc_name);
    }
    eprintln!(
        "izba: cp: skipping unsupported file type at {}",
        host_path.display()
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    /// A fake guest that handles ONE cp stream over a socketpair half. It
    /// mirrors the real `tarfs::extract` arbitration so the host-side tests
    /// exercise the true contract (host sends entries rooted at the source
    /// basename + `dest` verbatim; the RECEIVER arbitrates the §3 matrix).
    ///
    /// For extract: reads the StreamOpen + tar, arbitrates dest rules against
    /// `root/<dest>`, unpacks, replies one trailing Ok/Error. For create:
    /// reads StreamOpen, replies leading Ok, then streams a tar built from
    /// `root/<src>` rooted at its basename.
    fn spawn_fake_guest(server: UnixStream, root: PathBuf) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let mut s = server;
            let open: StreamOpen = match read_frame(&mut s) {
                Ok(o) => o,
                Err(_) => return,
            };
            match open {
                StreamOpen::TarExtract { dest } => {
                    // Drive a tar::Archive straight off the stream (stops at
                    // the tar EOF blocks, NOT socket EOF — the host is still
                    // waiting to read our reply). Arbitrate the §3 matrix
                    // against `root/<dest>` exactly like tarfs::extract.
                    let dest_abs = root.join(dest.trim_start_matches('/'));
                    let resp = match fake_extract(&dest_abs, &mut s) {
                        Ok(()) => Response::Ok,
                        Err((kind, message)) => Response::Error { kind, message },
                    };
                    let _ = write_frame(&mut s, &resp);
                }
                StreamOpen::TarCreate { src } => {
                    let path = root.join(src.trim_start_matches('/'));
                    if !path.exists() {
                        let _ = write_frame(
                            &mut s,
                            &Response::Error {
                                kind: ErrorKind::PathNotFound,
                                message: "missing".into(),
                            },
                        );
                        return;
                    }
                    let _ = write_frame(&mut s, &Response::Ok);
                    let top = path.file_name().unwrap().to_os_string();
                    let mut b = tar::Builder::new(&mut s);
                    b.follow_symlinks(false);
                    if path.is_dir() {
                        b.append_dir_all(&top, &path).unwrap();
                    } else {
                        let mut h = tar::Header::new_gnu();
                        let meta = std::fs::metadata(&path).unwrap();
                        h.set_entry_type(tar::EntryType::Regular);
                        h.set_metadata(&meta);
                        h.set_cksum();
                        let mut f = std::fs::File::open(&path).unwrap();
                        b.append_data(&mut h, &top, &mut f).unwrap();
                    }
                    b.finish().unwrap();
                }
                other => panic!("fake guest got unexpected open: {other:?}"),
            }
        })
    }

    /// Faithful (privilege-free) stand-in for `tarfs::extract`'s dest-rule
    /// arbitration, used only by the host-side cp tests. Entries arrive
    /// rooted at the source basename; we classify `dest_abs` and decide the
    /// unpack base + top-component rewrite per §3.
    fn fake_extract<R: Read>(dest_abs: &Path, stream: &mut R) -> Result<(), (ErrorKind, String)> {
        let mut ar = tar::Archive::new(stream);
        ar.set_preserve_permissions(true);
        ar.set_preserve_mtime(true);
        let mut iter = ar
            .entries()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        let Some(first) = iter.next() else {
            return Ok(()); // empty archive
        };
        let mut first = first.map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        let first_is_dir = first.header().entry_type().is_dir();
        let first_top = first
            .path()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .components()
            .next()
            .and_then(|c| match c {
                std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .unwrap_or_default();

        let (base, rename): (PathBuf, Option<String>) = if dest_abs.is_dir() {
            (dest_abs.to_path_buf(), None)
        } else if dest_abs.exists() {
            if first_is_dir {
                return Err((
                    ErrorKind::BadRequest,
                    "cannot overwrite non-directory with directory".to_string(),
                ));
            }
            (
                dest_abs.parent().unwrap().to_path_buf(),
                dest_abs
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned()),
            )
        } else {
            let parent = dest_abs.parent().unwrap_or_else(|| Path::new("."));
            if !parent.is_dir() {
                return Err((
                    ErrorKind::PathNotFound,
                    format!("{}: no such file or directory", dest_abs.display()),
                ));
            }
            (
                parent.to_path_buf(),
                dest_abs
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned()),
            )
        };

        let rewrite = |p: &Path| -> PathBuf { rewrite_top(p, &first_top, rename.as_deref()) };
        // `Archive::new(stream)` where `stream: &mut R` yields entries over
        // `&mut R`, not `R`, so the closure parameter must match.
        let unpack = |entry: &mut tar::Entry<'_, &mut R>| -> Result<(), (ErrorKind, String)> {
            let p = entry
                .path()
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?
                .into_owned();
            let dst = base.join(rewrite(&p));
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            entry
                .unpack(&dst)
                .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
            Ok(())
        };
        unpack(&mut first)?;
        for entry in iter {
            let mut entry = entry.map_err(|e| (ErrorKind::Internal, e.to_string()))?;
            unpack(&mut entry)?;
        }
        Ok(())
    }

    #[test]
    fn to_guest_rename_places_file_at_dest() {
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("a.txt"), b"hi").unwrap();
        // Guest dest /b.txt under an existing root dir.
        let (client, server) = UnixStream::pair().unwrap();
        let h = spawn_fake_guest(server, guest.path().to_path_buf());
        copy_to_guest(client, &host.path().join("a.txt"), "/b.txt").unwrap();
        h.join().unwrap();
        assert_eq!(std::fs::read(guest.path().join("b.txt")).unwrap(), b"hi");
    }

    #[test]
    fn to_guest_directory_tree() {
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(host.path().join("tree/sub")).unwrap();
        std::fs::write(host.path().join("tree/sub/x"), b"1").unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let h = spawn_fake_guest(server, guest.path().to_path_buf());
        copy_to_guest(client, &host.path().join("tree"), "/dst").unwrap();
        h.join().unwrap();
        assert_eq!(std::fs::read(guest.path().join("dst/sub/x")).unwrap(), b"1");
    }

    #[test]
    fn to_guest_file_into_existing_dir_lands_inside() {
        // dest is an EXISTING dir → into-dir rule: source lands at
        // dest/<basename>. The host sends `dest` verbatim; the guest decides.
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("foo.txt"), b"hi").unwrap();
        std::fs::create_dir_all(guest.path().join("etc")).unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let h = spawn_fake_guest(server, guest.path().to_path_buf());
        copy_to_guest(client, &host.path().join("foo.txt"), "/etc").unwrap();
        h.join().unwrap();
        assert_eq!(
            std::fs::read(guest.path().join("etc/foo.txt")).unwrap(),
            b"hi"
        );
    }

    #[test]
    fn to_guest_dir_onto_existing_file_is_error() {
        // dir source onto an existing file → BadRequest, surfaced to the host.
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(host.path().join("tree")).unwrap();
        std::fs::write(host.path().join("tree/x"), b"1").unwrap();
        std::fs::write(guest.path().join("target"), b"old").unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let h = spawn_fake_guest(server, guest.path().to_path_buf());
        let err = copy_to_guest(client, &host.path().join("tree"), "/target")
            .expect_err("dir onto file must error");
        h.join().unwrap();
        assert!(
            err.to_string().contains("cannot overwrite") || err.to_string().contains("cp failed"),
            "got: {err:#}"
        );
    }

    #[test]
    fn from_guest_into_existing_dir_keeps_basename() {
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::write(guest.path().join("src.txt"), b"data").unwrap();
        let into = host.path().join("into");
        std::fs::create_dir_all(&into).unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let h = spawn_fake_guest(server, guest.path().to_path_buf());
        copy_from_guest(client, "/src.txt", &into).unwrap();
        h.join().unwrap();
        assert_eq!(std::fs::read(into.join("src.txt")).unwrap(), b"data");
    }

    #[test]
    fn from_guest_rename_to_nonexistent_dest() {
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::write(guest.path().join("src.txt"), b"data").unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let h = spawn_fake_guest(server, guest.path().to_path_buf());
        let dest = host.path().join("renamed.txt");
        copy_from_guest(client, "/src.txt", &dest).unwrap();
        h.join().unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"data");
    }

    #[test]
    fn from_guest_dir_onto_existing_file_errors() {
        // §3 matrix, guest→host direction: a directory source cannot
        // overwrite an existing host file. Detected from the stream's
        // first entry type.
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(guest.path().join("srcdir")).unwrap();
        std::fs::write(guest.path().join("srcdir/x"), b"1").unwrap();
        let dest = host.path().join("target");
        std::fs::write(&dest, b"old").unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let _h = spawn_fake_guest(server, guest.path().to_path_buf());
        let err = copy_from_guest(client, "/srcdir", &dest).expect_err("dir onto file must error");
        assert!(
            err.to_string().contains("cannot overwrite non-directory"),
            "got: {err:#}"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"old", "dest untouched");
    }

    #[test]
    fn from_guest_missing_src_errors() {
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let h = spawn_fake_guest(server, guest.path().to_path_buf());
        let err = copy_from_guest(client, "/nope", &host.path().join("x"))
            .expect_err("missing src must error");
        h.join().unwrap();
        assert!(
            err.to_string().contains("no such file or directory"),
            "got: {err:#}"
        );
    }

    #[test]
    fn from_guest_rename_parent_missing_errors() {
        let host = tempfile::tempdir().unwrap();
        let guest = tempfile::tempdir().unwrap();
        std::fs::write(guest.path().join("src.txt"), b"d").unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let _h = spawn_fake_guest(server, guest.path().to_path_buf());
        let dest = host.path().join("missing-parent/renamed.txt");
        let err =
            copy_from_guest(client, "/src.txt", &dest).expect_err("missing parent must error");
        assert!(
            err.to_string().contains("no such file or directory"),
            "got: {err:#}"
        );
    }

    // ---------------------------------------------------------------------
    // F-08 abuse cases: a hostile guest crafts the archive. `unpack_stream`
    // is the host-side receiver and the only line of defense (boundary B-CP,
    // threat-model §7 invariant 1: no host-FS write outside the dest root).
    // These drive `unpack_stream` directly with an in-memory `Cursor` (no
    // vsock), exactly like tarfs.rs's host-testable extract.
    // ---------------------------------------------------------------------

    /// Append a forged entry with a RAW GNU header name, bypassing the
    /// high-level `append_data`/`set_path` `..`-validation (which a real
    /// hostile guest sidesteps trivially by writing tar bytes by hand).
    fn forge_entry(
        b: &mut tar::Builder<Vec<u8>>,
        name: &[u8],
        etype: tar::EntryType,
        link_target: Option<&str>,
        data: &[u8],
    ) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(etype);
        h.set_mode(0o644);
        h.set_mtime(0);
        if let Some(t) = link_target {
            h.set_size(0);
            h.set_link_name(t).unwrap();
        } else {
            h.set_size(data.len() as u64);
        }
        let gnu = h.as_gnu_mut().unwrap();
        gnu.name[..name.len()].copy_from_slice(name);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    /// Helper: run `unpack_stream` over `archive` into an existing `dest` dir,
    /// keeping the src basename (into-dir rule, no rename).
    fn run_unpack_into_dir(archive: Vec<u8>, dest: &Path, src_base: &str) -> anyhow::Result<()> {
        unpack_stream(
            std::io::Cursor::new(archive),
            dest,
            src_base,
            None,
            false,
            src_base,
            dest,
        )
    }

    #[test]
    fn poc_two_step_absolute_symlink_escape_blocked() {
        // The classic two-step escape: entry A is a symlink `x -> <victim>`
        // (absolute, OUTSIDE the unpack root), entry B is a regular file
        // `x/payload` that, if `x` is followed, lands at <victim>/payload on
        // the host. The unpack root is `into`; the victim is a SEPARATE
        // tempdir the guest must never reach.
        let host = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        let into = host.path().join("into");
        std::fs::create_dir_all(&into).unwrap();

        let victim_abs = victim.path().to_string_lossy().into_owned();
        let mut b = tar::Builder::new(Vec::new());
        // entry A: symlink x -> /abs/victim
        forge_entry(
            &mut b,
            b"src/x",
            tar::EntryType::Symlink,
            Some(&victim_abs),
            b"",
        );
        // entry B: regular file x/payload
        forge_entry(
            &mut b,
            b"src/x/payload",
            tar::EntryType::Regular,
            None,
            b"PWNED",
        );
        let archive = b.into_inner().unwrap();

        let res = run_unpack_into_dir(archive, &into, "src");

        // The victim location must be untouched no matter what.
        let escaped = victim.path().join("payload");
        assert!(
            !escaped.exists(),
            "ESCAPE: guest wrote through symlink to {}",
            escaped.display()
        );
        // And the unpack must have refused.
        assert!(res.is_err(), "escape attempt must error, got Ok");
    }

    #[test]
    fn poc_dotdot_traversal_entry_blocked() {
        // A single entry whose name climbs out with `..` after the (unchanged)
        // top component. `rewrite_top` only touches the FIRST component, so the
        // `..` rides through the join.
        let host = tempfile::tempdir().unwrap();
        let into = host.path().join("into");
        std::fs::create_dir_all(&into).unwrap();
        // Victim sits as a sibling of `into`.
        let victim = host.path().join("victim.txt");

        let mut b = tar::Builder::new(Vec::new());
        forge_entry(
            &mut b,
            b"src/../victim.txt",
            tar::EntryType::Regular,
            None,
            b"PWNED",
        );
        let archive = b.into_inner().unwrap();

        let res = run_unpack_into_dir(archive, &into, "src");
        assert!(
            !victim.exists(),
            "ESCAPE: `..` entry wrote to {}",
            victim.display()
        );
        assert!(res.is_err(), "`..` entry must error, got Ok");
    }

    #[test]
    fn poc_absolute_path_entry_blocked() {
        // An entry with an ABSOLUTE name. `unpack_base.join("/abs/...")`
        // discards the base entirely under POSIX join semantics.
        let host = tempfile::tempdir().unwrap();
        let into = host.path().join("into");
        std::fs::create_dir_all(&into).unwrap();
        let victim = host.path().join("abs-victim.txt");
        let victim_abs = victim.to_string_lossy().into_owned();

        let mut b = tar::Builder::new(Vec::new());
        // raw absolute name (leading slash kept verbatim in the GNU header)
        forge_entry(
            &mut b,
            victim_abs.as_bytes(),
            tar::EntryType::Regular,
            None,
            b"PWNED",
        );
        let archive = b.into_inner().unwrap();

        let res = run_unpack_into_dir(archive, &into, "src");
        assert!(
            std::fs::read(&victim)
                .map(|d| d != b"PWNED")
                .unwrap_or(true),
            "ESCAPE: absolute entry wrote to {}",
            victim.display()
        );
        assert!(res.is_err(), "absolute entry must error, got Ok");
    }

    #[test]
    fn poc_dotdot_symlink_target_escape_blocked() {
        // Two-step escape with a RELATIVE `..` symlink target instead of an
        // absolute one: x -> ../../<victim-dir>, then x/payload.
        let host = tempfile::tempdir().unwrap();
        let root = host.path().join("a/b/into");
        std::fs::create_dir_all(&root).unwrap();
        let victim_dir = host.path().join("a/victim");
        std::fs::create_dir_all(&victim_dir).unwrap();

        let mut b = tar::Builder::new(Vec::new());
        // From <root>/src/x, `../../../victim` climbs to <host>/a/victim.
        forge_entry(
            &mut b,
            b"src/x",
            tar::EntryType::Symlink,
            Some("../../../victim"),
            b"",
        );
        forge_entry(
            &mut b,
            b"src/x/payload",
            tar::EntryType::Regular,
            None,
            b"PWNED",
        );
        let archive = b.into_inner().unwrap();

        let res = run_unpack_into_dir(archive, &root, "src");
        let escaped = victim_dir.join("payload");
        assert!(
            !escaped.exists(),
            "ESCAPE: relative-symlink escape wrote to {}",
            escaped.display()
        );
        assert!(res.is_err(), "relative-symlink escape must error, got Ok");
    }

    #[test]
    fn legit_archive_with_inner_symlink_still_extracts() {
        // Defense must NOT break the legitimate case: a directory tree with an
        // INNER, in-root relative symlink extracts fine (mirrors the guest's
        // `extract_dir_into_existing_dir_nests_under_srcname`).
        let host = tempfile::tempdir().unwrap();
        let into = host.path().join("into");
        std::fs::create_dir_all(&into).unwrap();

        let mut b = tar::Builder::new(Vec::new());
        // top dir entry first (as a real dir-walk emits)
        let mut dh = tar::Header::new_gnu();
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_size(0);
        dh.set_mode(0o755);
        dh.set_mtime(0);
        dh.set_cksum();
        b.append_data(&mut dh, "tree/", &mut std::io::empty())
            .unwrap();
        forge_entry(
            &mut b,
            b"tree/a.txt",
            tar::EntryType::Regular,
            None,
            b"hello",
        );
        // a safe inner symlink pointing at a sibling inside the tree
        forge_entry(
            &mut b,
            b"tree/link",
            tar::EntryType::Symlink,
            Some("a.txt"),
            b"",
        );
        let archive = b.into_inner().unwrap();

        run_unpack_into_dir(archive, &into, "tree").expect("legit archive must extract");
        assert_eq!(std::fs::read(into.join("tree/a.txt")).unwrap(), b"hello");
        let target = std::fs::read_link(into.join("tree/link")).unwrap();
        assert_eq!(target, std::path::Path::new("a.txt"));
    }
}
