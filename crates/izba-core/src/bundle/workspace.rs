//! Workspace handling for bundles: tar the workspace tree verbatim (dotfiles,
//! `.git`, symlinks — never followed), restore it entry-by-entry without ever
//! writing through a symlink, and translate the source workspace path for a
//! host on another OS.

use crate::bundle::fsutil::ExactLen;
use crate::bundle::manifest::{check_portable_rel, validate_entry_path, SourceOs};
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

/// Directory entries of `dir`, sorted by name so the archive is deterministic.
fn sorted_entries(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    let mut v = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading {}", dir.display()))?;
    v.sort_by_key(|e| e.file_name());
    Ok(v)
}

#[cfg(unix)]
fn entry_mode(meta: &fs::Metadata, _rel: &Path, _exec_bits: &HashSet<PathBuf>) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

/// Windows has no mode bits: files are 0644 (0755 when git records the exec
/// bit for `rel`), directories 0755.
#[cfg(not(unix))]
fn entry_mode(meta: &fs::Metadata, rel: &Path, exec_bits: &HashSet<PathBuf>) -> u32 {
    if meta.is_dir() || exec_bits.contains(rel) {
        0o755
    } else {
        0o644
    }
}

fn mtime(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// What `append_workspace` archived and what it left out.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WorkspaceStats {
    /// Bytes of regular-file content archived.
    pub bytes: u64,
    /// Relative paths of sockets, FIFOs and devices, which cannot be archived
    /// (e.g. git's fsmonitor socket) and are skipped rather than failing the save.
    pub skipped: Vec<PathBuf>,
}

/// Appends every entry under `root` (dirs, files, symlinks — never followed)
/// at `<archive_prefix>/<rel>` with forward slashes; the root itself gets no
/// entry. Returns the bytes of regular-file content.
pub fn append_workspace<W: Write>(
    tar: &mut tar::Builder<W>,
    root: &Path,
    archive_prefix: &str,
    exec_bits: &HashSet<PathBuf>,
) -> Result<WorkspaceStats> {
    fn walk<W: Write>(
        tar: &mut tar::Builder<W>,
        dir: &Path,
        rel_dir: &Path,
        prefix: &str,
        exec_bits: &HashSet<PathBuf>,
        stats: &mut WorkspaceStats,
    ) -> Result<()> {
        for de in sorted_entries(dir)? {
            let path = de.path();
            let rel = rel_dir.join(de.file_name());
            let mut name = prefix.to_string();
            for c in rel.components() {
                let s = c
                    .as_os_str()
                    .to_str()
                    .with_context(|| format!("non-UTF-8 workspace path {}", rel.display()))?;
                name.push('/');
                name.push_str(s);
            }
            // Never emit a name some load would refuse (spec §10): the whole
            // archive would otherwise be unloadable, found out only on load.
            validate_entry_path(&name)
                .and_then(|()| check_portable_rel(&name[prefix.len() + 1..]))
                .with_context(|| {
                    format!(
                        "workspace file {} cannot be restored portably; rename it or \
                         save without --with-workspace",
                        rel.display()
                    )
                })?;
            let meta =
                fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
            let ft = meta.file_type();
            let mut h = tar::Header::new_gnu();
            h.set_mtime(mtime(&meta));
            h.set_mode(entry_mode(&meta, &rel, exec_bits));
            h.set_uid(0);
            h.set_gid(0);
            if ft.is_symlink() {
                let target =
                    fs::read_link(&path).with_context(|| format!("readlink {}", path.display()))?;
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                tar.append_link(&mut h, &name, &target)
                    .with_context(|| format!("archiving symlink {}", rel.display()))?;
            } else if ft.is_dir() {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                tar.append_data(&mut h, &name, std::io::empty())
                    .with_context(|| format!("archiving {}", rel.display()))?;
                walk(tar, &path, &rel, prefix, exec_bits, stats)?;
            } else if ft.is_file() {
                h.set_entry_type(tar::EntryType::Regular);
                // The length comes from the OPEN handle, never the earlier
                // stat: the file may have been replaced in between.
                let f = open_no_follow(&path)?;
                let open_meta = f
                    .metadata()
                    .with_context(|| format!("stat {}", path.display()))?;
                if !open_meta.is_file() {
                    bail!(
                        "{} changed while being archived; retry the save",
                        rel.display()
                    );
                }
                let len = open_meta.len();
                append_regular(tar, &mut h, &name, f, len)
                    .with_context(|| format!("archiving {}", rel.display()))?;
                stats.bytes += len;
            } else {
                stats.skipped.push(rel);
            }
        }
        Ok(())
    }
    let mut stats = WorkspaceStats::default();
    walk(
        tar,
        root,
        Path::new(""),
        archive_prefix.trim_end_matches('/'),
        exec_bits,
        &mut stats,
    )?;
    Ok(stats)
}

/// Opens a workspace file for archiving without following a symlink swapped
/// in since the directory walk stat'ed it (Unix; Windows opens normally).
fn open_no_follow(path: &Path) -> Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// Appends a regular-file entry of exactly `len` bytes (header size `len`):
/// a shorter reader fails the save, a longer one is cut at `len` (see
/// [`ExactLen`]), so the tar stream can never desync from its headers.
fn append_regular<W: Write, R: Read>(
    tar: &mut tar::Builder<W>,
    h: &mut tar::Header,
    name: &str,
    reader: R,
    len: u64,
) -> Result<()> {
    h.set_size(len);
    tar.append_data(h, name, ExactLen::new(reader, len))?;
    Ok(())
}

/// Sum of regular-file sizes under `root` (symlinks not followed).
pub fn workspace_bytes(root: &Path) -> Result<u64> {
    let mut total = 0;
    for de in sorted_entries(root)? {
        let meta = fs::symlink_metadata(de.path())?;
        if meta.is_dir() {
            total += workspace_bytes(&de.path())?;
        } else if meta.is_file() {
            total += meta.len();
        }
    }
    Ok(total)
}

/// Paths git records as executable (`100755`) under `root`. Only needed for
/// Windows sources, where the filesystem carries no mode bits. Empty on any
/// failure (no git, not a repo, ...): the files then simply archive as 0644.
pub fn git_exec_bits(root: &Path) -> HashSet<PathBuf> {
    let Ok(git) = which::which("git") else {
        return HashSet::new();
    };
    let Ok(out) = std::process::Command::new(git)
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-s", "-z"])
        .output()
    else {
        return HashSet::new();
    };
    if !out.status.success() {
        return HashSet::new();
    }
    // Records: "<mode> <sha> <stage>\t<path>\0".
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter_map(|rec| {
            let (meta, path) = rec.split_once('\t')?;
            (meta.split(' ').next()? == "100755").then(|| PathBuf::from(path))
        })
        .collect()
}

/// Directory modes deferred by `unpack_entry`. A directory whose recorded mode
/// lacks owner-write (e.g. 0555) is created owner-writable so its children can
/// still be extracted; call `apply` after ALL entries are unpacked to set the
/// recorded modes (deepest first, so a read-only parent never blocks a child).
/// A no-op on non-Unix hosts.
#[derive(Debug, Default)]
pub struct DirModes {
    #[cfg(unix)]
    modes: Vec<(PathBuf, u32)>,
}

impl DirModes {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(unix)]
    pub fn apply(mut self) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        self.modes
            .sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
        for (p, mode) in self.modes {
            fs::set_permissions(&p, fs::Permissions::from_mode(mode))
                .with_context(|| format!("restoring mode of {}", p.display()))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn apply(self) -> Result<()> {
        Ok(())
    }
}

/// Restores one archive entry at `dest_root/rel`. Refuses to write through ANY
/// pre-existing symlinked ancestor inside `dest_root`, and refuses when the
/// final target itself already exists as a symlink (the unpack would follow
/// it). A symlink entry's own target is kept verbatim — it is only data.
pub fn unpack_entry<R: Read>(
    entry: &mut tar::Entry<R>,
    dest_root: &Path,
    rel: &Path,
    dir_modes: &mut DirModes,
) -> Result<()> {
    let mut target = dest_root.to_path_buf();
    for c in rel.components() {
        match c {
            Component::Normal(p) => {
                target.push(p);
                // Every prefix of `rel`, the final target included.
                if fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
                    bail!("refusing to write {} through a symlink", rel.display());
                }
            }
            _ => bail!("refusing unsafe workspace path {}", rel.display()),
        }
    }
    if target == dest_root {
        bail!("empty workspace path");
    }
    let ty = entry.header().entry_type();
    if !matches!(
        ty,
        tar::EntryType::Regular | tar::EntryType::Directory | tar::EntryType::Symlink
    ) {
        bail!("unsupported entry type in workspace: {}", rel.display());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let res = entry.unpack(&target);
    #[cfg(unix)]
    if res.is_ok() && ty == tar::EntryType::Directory {
        use std::os::unix::fs::PermissionsExt;
        let recorded = entry.header().mode().unwrap_or(0o755) & 0o7777;
        if recorded & 0o200 == 0 {
            let cur = fs::metadata(&target)?.permissions().mode() & 0o7777;
            fs::set_permissions(&target, fs::Permissions::from_mode(cur | 0o700))?;
            dir_modes.modes.push((target.clone(), recorded));
        }
    }
    #[cfg(not(unix))]
    let _ = dir_modes;
    match res {
        Ok(_) => Ok(()),
        #[cfg(windows)]
        Err(e) if ty == tar::EntryType::Symlink => bail!(
            "creating symlink {}: {e} — enable Windows Developer Mode (Settings → For developers) or run elevated, then re-run izba load",
            rel.display()
        ),
        Err(e) => Err(e).with_context(|| format!("unpacking {}", rel.display())),
    }
}

/// Splits `s` into path components the way `os` spells paths, dropping a
/// leading `\\?\` verbatim prefix and empty pieces.
fn split_source(s: &str, os: &SourceOs) -> Vec<String> {
    if *os == SourceOs::Windows {
        s.strip_prefix(r"\\?\")
            .unwrap_or(s)
            .split(['\\', '/'])
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        s.split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// Where a saved sandbox's workspace lands on this host. Same OS keeps the
/// path verbatim; across OSes a path under the source home is re-rooted under
/// `target_home`, anything else needs an explicit `--workspace` (`None`).
pub fn translate_workspace(
    source: &str,
    source_home: Option<&str>,
    source_os: &SourceOs,
    target_home: &Path,
) -> Option<PathBuf> {
    if *source_os == SourceOs::current() {
        return Some(PathBuf::from(source));
    }
    let src = split_source(source, source_os);
    let home = split_source(source_home?, source_os);
    let ci = *source_os == SourceOs::Windows;
    let under = src.len() > home.len()
        && home.iter().zip(&src).all(|(h, s)| {
            if ci {
                h.to_lowercase() == s.to_lowercase()
            } else {
                h == s
            }
        });
    if !under {
        return None;
    }
    let rebased = &src[home.len()..];
    // The components are attacker-controlled archive data: none may climb out
    // of `target_home` (`..`) or turn into a separator/drive on the target OS.
    if rebased
        .iter()
        .any(|c| c == "." || c == ".." || c.contains(['/', '\\', ':', '\0']))
    {
        return None;
    }
    let mut out = target_home.to_path_buf();
    for c in rebased {
        out.push(c);
    }
    Some(out)
}

/// A restore target is free when it does not exist or is an empty directory.
pub fn is_free_target(p: &Path) -> bool {
    match fs::symlink_metadata(p) {
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        Ok(m) if m.is_dir() => fs::read_dir(p).is_ok_and(|mut d| d.next().is_none()),
        Ok(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::manifest::SourceOs;
    use std::path::{Path, PathBuf};

    #[test]
    fn translate_same_os_keeps_path() {
        let p = translate_workspace(
            "/home/u/proj",
            Some("/home/u"),
            &SourceOs::current(),
            Path::new("/home/v"),
        );
        assert_eq!(p, Some(PathBuf::from("/home/u/proj")));
    }

    #[test]
    fn translate_linux_to_other_os_rebases_under_home() {
        let other = if SourceOs::current() == SourceOs::Linux {
            SourceOs::Windows
        } else {
            SourceOs::Linux
        };
        let (src, home) = match other {
            SourceOs::Windows => (r"C:\Users\u\code\proj", r"C:\Users\u"),
            _ => ("/home/u/code/proj", "/home/u"),
        };
        let t = Path::new("/target/home");
        assert_eq!(
            translate_workspace(src, Some(home), &other, t),
            Some(t.join("code").join("proj"))
        );
    }

    #[test]
    fn translate_outside_home_needs_explicit_workspace() {
        let other = if SourceOs::current() == SourceOs::Linux {
            SourceOs::Windows
        } else {
            SourceOs::Linux
        };
        let (src, home) = match other {
            SourceOs::Windows => (r"D:\work\proj", r"C:\Users\u"),
            _ => ("/srv/proj", "/home/u"),
        };
        assert_eq!(
            translate_workspace(src, Some(home), &other, Path::new("/t")),
            None
        );
    }

    #[test]
    fn translate_strips_windows_verbatim_prefix() {
        if SourceOs::current() == SourceOs::Windows {
            return;
        }
        let p = translate_workspace(
            r"\\?\C:\Users\u\proj",
            Some(r"C:\Users\u"),
            &SourceOs::Windows,
            Path::new("/h"),
        );
        assert_eq!(p, Some(PathBuf::from("/h/proj")));
    }

    #[test]
    fn translate_windows_source_compares_case_insensitively() {
        if SourceOs::current() == SourceOs::Windows {
            return;
        }
        let p = translate_workspace(
            r"c:\users\U\proj",
            Some(r"C:\Users\u"),
            &SourceOs::Windows,
            Path::new("/h"),
        );
        assert_eq!(p, Some(PathBuf::from("/h/proj")));
    }

    #[test]
    fn translate_rejects_escaping_or_drive_shaped_components() {
        let other = if SourceOs::current() == SourceOs::Linux {
            SourceOs::Windows
        } else {
            SourceOs::Linux
        };
        let t = Path::new("/target/home");
        let (dotdot, drive, home) = match other {
            SourceOs::Windows => (r"C:\Users\u\..\..\etc", r"C:\Users\u\C:foo", r"C:\Users\u"),
            _ => ("/home/u/../../etc/x", "/home/u/C:foo", "/home/u"),
        };
        assert_eq!(translate_workspace(dotdot, Some(home), &other, t), None);
        assert_eq!(translate_workspace(drive, Some(home), &other, t), None);
    }

    #[test]
    fn translate_without_home_is_none() {
        let other = if SourceOs::current() == SourceOs::Linux {
            SourceOs::Windows
        } else {
            SourceOs::Linux
        };
        assert_eq!(
            translate_workspace("/x/y", None, &other, Path::new("/t")),
            None
        );
    }

    #[test]
    fn is_free_target_rules() {
        let t = tempfile::tempdir().unwrap();
        assert!(is_free_target(&t.path().join("nope")));
        assert!(is_free_target(t.path()));
        std::fs::write(t.path().join("f"), b"x").unwrap();
        assert!(!is_free_target(t.path()));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_round_trips_files_modes_symlinks_and_dotfiles() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        std::fs::create_dir_all(src.join(".git/objects")).unwrap();
        std::fs::write(src.join(".env"), b"SECRET=1").unwrap();
        std::fs::write(src.join("run.sh"), b"#!/bin/sh").unwrap();
        std::fs::set_permissions(src.join("run.sh"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        std::fs::write(src.join(".git/HEAD"), b"ref").unwrap();
        symlink("run.sh", src.join("link")).unwrap();
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let n = append_workspace(&mut b, &src, "workspaces/a", &Default::default())
                .unwrap()
                .bytes;
            assert_eq!(n, 8 + 9 + 3);
            b.finish().unwrap();
        }
        assert_eq!(workspace_bytes(&src).unwrap(), 20);
        let dst = t.path().join("dst");
        let mut ar = tar::Archive::new(&buf[..]);
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let p = e.path().unwrap().into_owned();
            let rel = p.strip_prefix("workspaces/a").unwrap().to_path_buf();
            if rel.as_os_str().is_empty() {
                continue;
            }
            unpack_entry(&mut e, &dst, &rel, &mut DirModes::new()).unwrap();
        }
        assert_eq!(std::fs::read(dst.join(".env")).unwrap(), b"SECRET=1");
        assert_eq!(std::fs::read(dst.join(".git/HEAD")).unwrap(), b"ref");
        assert_eq!(
            std::fs::metadata(dst.join("run.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::read_link(dst.join("link")).unwrap(),
            PathBuf::from("run.sh")
        );
    }

    #[cfg(unix)]
    fn one_file_archive(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut b = tar::Builder::new(&mut buf);
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, &b"z"[..]).unwrap();
        b.finish().unwrap();
        drop(b);
        buf
    }

    #[cfg(unix)]
    #[test]
    fn unpack_refuses_to_write_through_a_symlink() {
        // An entry `link/x` after `link -> /elsewhere` must not escape dest.
        let t = tempfile::tempdir().unwrap();
        let dst = t.path().join("dst");
        let outside = t.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::os::unix::fs::symlink(&outside, dst.join("link")).unwrap();
        let buf = one_file_archive("workspaces/a/link/x");
        let mut ar = tar::Archive::new(&buf[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert!(unpack_entry(&mut e, &dst, Path::new("link/x"), &mut DirModes::new()).is_err());
        assert!(!outside.join("x").exists());
    }

    #[cfg(unix)]
    #[test]
    fn unpack_refuses_a_symlinked_final_target() {
        let t = tempfile::tempdir().unwrap();
        let dst = t.path().join("dst");
        let victim = t.path().join("victim");
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, dst.join("x")).unwrap();
        let buf = one_file_archive("workspaces/a/x");
        let mut ar = tar::Archive::new(&buf[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert!(unpack_entry(&mut e, &dst, Path::new("x"), &mut DirModes::new()).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn unpack_refuses_escaping_rel_paths() {
        let t = tempfile::tempdir().unwrap();
        let buf = one_file_archive("workspaces/a/x");
        let mut ar = tar::Archive::new(&buf[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert!(unpack_entry(&mut e, t.path(), Path::new("../x"), &mut DirModes::new()).is_err());
        assert!(unpack_entry(&mut e, t.path(), Path::new("/abs"), &mut DirModes::new()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_dir_restores_with_children_then_ends_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        std::fs::create_dir_all(src.join("ro")).unwrap();
        std::fs::write(src.join("ro/f"), b"x").unwrap();
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            append_workspace(&mut b, &src, "workspaces/w", &Default::default()).unwrap();
            b.finish().unwrap();
        }
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let dst = t.path().join("dst");
        let mut modes = DirModes::new();
        let mut ar = tar::Archive::new(&buf[..]);
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let rel = e
                .path()
                .unwrap()
                .strip_prefix("workspaces/w")
                .unwrap()
                .to_path_buf();
            unpack_entry(&mut e, &dst, &rel, &mut modes).unwrap();
        }
        modes.apply().unwrap();
        assert_eq!(std::fs::read(dst.join("ro/f")).unwrap(), b"x");
        assert_eq!(
            std::fs::metadata(dst.join("ro"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        // let tempdir cleanup succeed
        std::fs::set_permissions(dst.join("ro"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_skipped_and_reported() {
        use std::os::unix::ffi::OsStrExt;
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("f"), b"abc").unwrap();
        let c = std::ffi::CString::new(t.path().join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let mut buf = Vec::new();
        let mut b = tar::Builder::new(&mut buf);
        let st = append_workspace(&mut b, t.path(), "workspaces/w", &Default::default()).unwrap();
        assert_eq!(st.bytes, 3);
        assert_eq!(st.skipped, vec![PathBuf::from("fifo")]);
    }

    fn gnu_file_header() -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0o644);
        h
    }

    #[test]
    fn a_workspace_file_shorter_than_its_declared_len_fails() {
        let mut tar = tar::Builder::new(Vec::new());
        let e =
            append_regular(&mut tar, &mut gnu_file_header(), "w/f", &b"abc"[..], 5).unwrap_err();
        assert!(format!("{e:#}").contains("shrank"), "{e:#}");
    }

    #[test]
    fn a_workspace_file_longer_than_its_declared_len_is_cut_and_the_stream_stays_in_sync() {
        let mut tar = tar::Builder::new(Vec::new());
        append_regular(
            &mut tar,
            &mut gnu_file_header(),
            "w/f",
            &b"hello, grown"[..],
            5,
        )
        .unwrap();
        append_regular(&mut tar, &mut gnu_file_header(), "w/g", &b"next"[..], 4).unwrap();
        let bytes = tar.into_inner().unwrap();
        let mut ar = tar::Archive::new(&bytes[..]);
        let got: Vec<(String, Vec<u8>)> = ar
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let p = e.path().unwrap().to_string_lossy().into_owned();
                let mut b = Vec::new();
                e.read_to_end(&mut b).unwrap();
                (p, b)
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("w/f".into(), b"hello".to_vec()),
                ("w/g".into(), b"next".to_vec())
            ]
        );
    }

    #[test]
    fn git_exec_bits_is_empty_outside_a_repo() {
        let t = tempfile::tempdir().unwrap();
        assert!(git_exec_bits(&t.path().join("missing")).is_empty());
    }
}
