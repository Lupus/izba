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
            let rel_name = rel
                .components()
                .map(|c| {
                    c.as_os_str()
                        .to_str()
                        .with_context(|| format!("non-UTF-8 workspace path {}", rel.display()))
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            let name = format!("{prefix}/{rel_name}");
            // Never emit a name some load would refuse (spec §10): the whole
            // archive would otherwise be unloadable, found out only on load.
            validate_entry_path(&name)
                .and_then(|()| check_portable_rel(&rel_name))
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
                // Windows needs to know a link's kind at creation; a
                // dangling link (no target metadata) is recorded as a file.
                if fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
                    append_pax_record(tar, SYMLINK_DIR_PAX_RECORD)
                        .with_context(|| format!("archiving symlink {}", rel.display()))?;
                }
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

/// PAX extended-header key marking a symlink entry whose target is a
/// directory (value `"1"`). Only a Windows load acts on it (it must create a
/// directory symlink explicitly); tar readers ignore unknown PAX keys.
pub const SYMLINK_DIR_PAX_KEY: &str = "IZBA.symlink.dir";

/// The PAX record marking a directory symlink: `<len> <key>=<value>\n`,
/// where `<len>` counts the WHOLE record including its own digits — the 20
/// bytes of ` IZBA.symlink.dir=1\n` plus the two of `22`. A literal rather
/// than a computed fixed point (pinned against [`SYMLINK_DIR_PAX_KEY`] by a
/// test): izba writes no other PAX record.
const SYMLINK_DIR_PAX_RECORD: &str = "22 IZBA.symlink.dir=1\n";

/// Appends a PAX local extended header (`x`) carrying `record`; it applies to
/// the NEXT entry and is consumed by the reader (it is never yielded as an
/// entry). The header's own name is short and fixed, so it never needs a GNU
/// long-name entry of its own.
fn append_pax_record<W: Write>(tar: &mut tar::Builder<W>, record: &str) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::XHeader);
    // A PAX header is metadata, never extracted as a file: its mode is
    // unused, so it is owner-only like every other non-workspace entry.
    h.set_mode(0o600);
    h.set_size(record.len() as u64);
    tar.append_data(&mut h, "PaxHeader", record.as_bytes())?;
    Ok(())
}

/// Whether a symlink entry was saved pointing at a directory
/// ([`SYMLINK_DIR_PAX_KEY`]). Any malformed PAX data reads as "no".
pub fn is_dir_symlink<R: Read>(entry: &mut tar::Entry<R>) -> bool {
    let Ok(Some(exts)) = entry.pax_extensions() else {
        return false;
    };
    exts.flatten()
        .any(|x| x.key() == Ok(SYMLINK_DIR_PAX_KEY) && x.value() == Ok("1"))
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
    // tar-rs creates every symlink as a FILE symlink on Windows, which
    // would leave a saved directory link broken: create those explicitly.
    #[cfg(windows)]
    let res = if ty == tar::EntryType::Symlink && is_dir_symlink(entry) {
        let link = entry
            .link_name()?
            .with_context(|| format!("symlink {} has no target", rel.display()))?
            .to_string_lossy()
            .replace('/', "\\");
        std::os::windows::fs::symlink_dir(link, &target)
    } else {
        entry.unpack(&target).map(drop)
    };
    #[cfg(not(windows))]
    let res = entry.unpack(&target).map(drop);
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

/// Where a saved sandbox's workspace lands on this host. A path under the
/// source home is re-rooted under `target_home` — across OSes, and on the same
/// OS when the homes differ (another user / another machine layout); the same
/// home keeps it verbatim. Anything outside the source home keeps its path on
/// the same OS and needs an explicit `--workspace` across OSes (`None`).
pub fn translate_workspace(
    source: &str,
    source_home: Option<&str>,
    source_os: &SourceOs,
    target_home: &Path,
) -> Option<PathBuf> {
    let same_os = *source_os == SourceOs::current();
    let ci = *source_os == SourceOs::Windows;
    let eq = |a: &String, b: &String| {
        if ci {
            a.to_lowercase() == b.to_lowercase()
        } else {
            a == b
        }
    };
    let src = split_source(source, source_os);
    let home = source_home.map(|h| split_source(h, source_os));
    let under = home
        .as_ref()
        .is_some_and(|home| src.len() > home.len() && home.iter().zip(&src).all(|(h, s)| eq(h, s)));
    if !under {
        return same_os.then(|| PathBuf::from(source));
    }
    let home = home.unwrap_or_default();
    if same_os {
        let tgt = split_source(&target_home.to_string_lossy(), source_os);
        if tgt.len() == home.len() && tgt.iter().zip(&home).all(|(t, h)| eq(t, h)) {
            return Some(PathBuf::from(source));
        }
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

    /// `(source workspace, source home, target home)` spelled for this OS.
    fn same_os_paths() -> (&'static str, &'static str, &'static str) {
        if SourceOs::current() == SourceOs::Windows {
            (r"C:\Users\u\proj", r"C:\Users\u", r"D:\home\v")
        } else {
            ("/home/u/proj", "/home/u", "/home/v")
        }
    }

    #[test]
    fn translate_same_os_same_home_keeps_path() {
        let (src, home, _) = same_os_paths();
        let p = translate_workspace(src, Some(home), &SourceOs::current(), Path::new(home));
        assert_eq!(p, Some(PathBuf::from(src)));
    }

    #[test]
    fn translate_same_os_different_home_rebases_under_the_target_home() {
        let (src, home, tgt) = same_os_paths();
        let p = translate_workspace(src, Some(home), &SourceOs::current(), Path::new(tgt));
        assert_eq!(p, Some(Path::new(tgt).join("proj")));
    }

    #[test]
    fn translate_same_os_outside_home_keeps_path() {
        let (_, home, tgt) = same_os_paths();
        let outside = if SourceOs::current() == SourceOs::Windows {
            r"E:\work\proj"
        } else {
            "/srv/proj"
        };
        for h in [Some(home), None] {
            let p = translate_workspace(outside, h, &SourceOs::current(), Path::new(tgt));
            assert_eq!(p, Some(PathBuf::from(outside)));
        }
    }

    #[cfg(unix)]
    #[test]
    fn translate_same_os_rebase_rejects_escaping_components() {
        let p = translate_workspace(
            "/home/u/../../etc",
            Some("/home/u"),
            &SourceOs::current(),
            Path::new("/home/v"),
        );
        assert_eq!(p, None);
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
    #[test]
    fn a_directory_symlink_carries_the_pax_dir_marker() {
        use std::os::unix::fs::symlink;
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("src");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("f"), b"x").unwrap();
        symlink("sub", src.join("dlink")).unwrap();
        symlink("f", src.join("flink")).unwrap();
        symlink("nowhere", src.join("gone")).unwrap();
        let mut buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            append_workspace(&mut b, &src, "workspaces/a", &Default::default()).unwrap();
            b.finish().unwrap();
        }
        let mut seen = std::collections::BTreeMap::new();
        let mut ar = tar::Archive::new(&buf[..]);
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let p = e.path().unwrap().to_string_lossy().into_owned();
            // The PAX record is consumed by the reader, never an entry.
            assert!(p.starts_with("workspaces/a/"), "{p}");
            if e.header().entry_type() == tar::EntryType::Symlink {
                seen.insert(p, is_dir_symlink(&mut e));
            }
        }
        assert_eq!(
            seen,
            [
                ("workspaces/a/dlink".to_string(), true),
                ("workspaces/a/flink".to_string(), false),
                ("workspaces/a/gone".to_string(), false),
            ]
            .into_iter()
            .collect()
        );
        // Unix restores it as the plain symlink it was.
        let dst = t.path().join("dst");
        let mut ar = tar::Archive::new(&buf[..]);
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let rel = e
                .path()
                .unwrap()
                .strip_prefix("workspaces/a")
                .unwrap()
                .to_path_buf();
            unpack_entry(&mut e, &dst, &rel, &mut DirModes::new()).unwrap();
        }
        assert_eq!(
            std::fs::read_link(dst.join("dlink")).unwrap(),
            Path::new("sub")
        );
        assert!(dst.join("dlink").is_dir());
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

    #[test]
    fn translate_same_os_keeps_the_home_itself_and_longer_paths_outside_it() {
        let (_, home, tgt) = same_os_paths();
        let outside = if SourceOs::current() == SourceOs::Windows {
            r"E:\work\deep\proj"
        } else {
            "/opt/work/deep/proj"
        };
        // The source home itself is not "under" it; a path longer than the
        // home but outside it is not either: both keep their path.
        for src in [home, outside] {
            let p = translate_workspace(src, Some(home), &SourceOs::current(), Path::new(tgt));
            assert_eq!(p, Some(PathBuf::from(src)), "{src}");
        }
    }

    #[test]
    fn translate_same_os_rebases_under_a_target_home_nested_in_the_source_home() {
        let (src, home, _) = same_os_paths();
        let tgt = Path::new(home).join("sub");
        let p = translate_workspace(src, Some(home), &SourceOs::current(), &tgt);
        assert_eq!(p, Some(tgt.join("proj")));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_an_empty_dir_is_not_a_free_target() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("empty")).unwrap();
        std::os::unix::fs::symlink(t.path().join("empty"), t.path().join("link")).unwrap();
        assert!(!is_free_target(&t.path().join("link")));
    }

    #[test]
    fn mtime_is_the_modification_time_in_unix_seconds() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("f");
        let f = std::fs::File::create(&p).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567))
            .unwrap();
        drop(f);
        assert_eq!(mtime(&std::fs::metadata(&p).unwrap()), 1_234_567);
    }

    #[test]
    fn the_symlink_dir_pax_record_is_self_describing() {
        let (len, body) = SYMLINK_DIR_PAX_RECORD.split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), SYMLINK_DIR_PAX_RECORD.len());
        assert_eq!(body, format!("{SYMLINK_DIR_PAX_KEY}=1\n"));
    }

    /// A symlink entry preceded by the PAX `record` (if any), read back.
    fn symlink_after_pax(record: Option<&str>) -> bool {
        let mut b = tar::Builder::new(Vec::new());
        if let Some(r) = record {
            append_pax_record(&mut b, r).unwrap();
        }
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "workspaces/a/l", "target").unwrap();
        let buf = b.into_inner().unwrap();
        let mut ar = tar::Archive::new(&buf[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(e.path().unwrap(), Path::new("workspaces/a/l"));
        is_dir_symlink(&mut e)
    }

    #[test]
    fn only_the_exact_dir_marker_makes_a_dir_symlink() {
        assert!(symlink_after_pax(Some(SYMLINK_DIR_PAX_RECORD)));
        assert!(!symlink_after_pax(None));
        // The marker key with another value, or another key valued "1".
        assert!(!symlink_after_pax(Some("22 IZBA.symlink.dir=0\n")));
        assert!(!symlink_after_pax(Some("6 x=1\n")));
    }

    #[test]
    fn git_exec_bits_lists_the_files_git_records_as_executable() {
        if which::which("git").is_err() {
            return; // no git here: nothing to ask
        }
        let t = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let st = std::process::Command::new("git")
                .arg("-C")
                .arg(t.path())
                .args(args)
                .output()
                .unwrap();
            assert!(st.status.success(), "git {args:?}: {st:?}");
        };
        git(&["init", "-q"]);
        std::fs::write(t.path().join("run.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::write(t.path().join("data.txt"), b"x").unwrap();
        git(&["add", "run.sh", "data.txt"]);
        git(&["update-index", "--chmod=+x", "run.sh"]);
        git(&["update-index", "--chmod=-x", "data.txt"]);
        assert_eq!(
            git_exec_bits(t.path()),
            HashSet::from([PathBuf::from("run.sh")])
        );
    }

    #[cfg(unix)]
    fn one_entry(ty: tar::EntryType, name: &str, mode: u32) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(ty);
        h.set_mode(mode);
        let body: &[u8] = if ty == tar::EntryType::Regular {
            b"z"
        } else {
            b""
        };
        h.set_size(body.len() as u64);
        h.set_cksum();
        b.append_data(&mut h, name, body).unwrap();
        b.into_inner().unwrap()
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn only_a_read_only_directory_is_made_writable_and_deferred() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let mut modes = DirModes::new();
        let unpack = |ty, rel: &str, mode, modes: &mut DirModes| {
            let buf = one_entry(ty, &format!("workspaces/a/{rel}"), mode);
            let mut ar = tar::Archive::new(&buf[..]);
            let mut e = ar.entries().unwrap().next().unwrap().unwrap();
            unpack_entry(&mut e, t.path(), Path::new(rel), modes).unwrap();
        };
        // A read-only FILE keeps its mode and is not deferred.
        unpack(tar::EntryType::Regular, "f", 0o444, &mut modes);
        assert_eq!(mode_of(&t.path().join("f")) & 0o200, 0);
        assert!(modes.modes.is_empty(), "{:?}", modes.modes);
        // A read-only DIRECTORY is owner-rwx meanwhile (and nothing more),
        // its recorded mode deferred.
        unpack(tar::EntryType::Directory, "ro", 0o555, &mut modes);
        let m = mode_of(&t.path().join("ro"));
        assert_eq!((m & 0o700, m & 0o7000), (0o700, 0), "{m:o}");
        assert_eq!(modes.modes, vec![(t.path().join("ro"), 0o555)]);
        std::fs::set_permissions(t.path().join("ro"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    /// Windows files carry no mode bits: files are 0644 unless git records
    /// the exec bit, directories 0755.
    #[cfg(not(unix))]
    #[test]
    fn windows_entry_modes_come_from_the_kind_and_git_exec_bits() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("run.sh"), b"x").unwrap();
        std::fs::write(t.path().join("data.txt"), b"x").unwrap();
        let exec = HashSet::from([PathBuf::from("run.sh")]);
        let mode = |rel: &str| {
            let meta = std::fs::metadata(t.path().join(rel)).unwrap();
            entry_mode(&meta, Path::new(rel), &exec)
        };
        assert_eq!(mode("run.sh"), 0o755);
        assert_eq!(mode("data.txt"), 0o644);
        assert_eq!(mode(""), 0o755);
    }

    /// Windows creates a directory symlink only when asked explicitly; a
    /// failure to create a symlink hints at Developer Mode, any other
    /// unpack failure does not.
    #[cfg(windows)]
    #[test]
    fn windows_symlink_kinds_and_errors() {
        use std::os::windows::fs::FileTypeExt;
        let t = tempfile::tempdir().unwrap();
        let unpack = |rel: &str, record: Option<&str>, ty: tar::EntryType| {
            let mut b = tar::Builder::new(Vec::new());
            if let Some(r) = record {
                append_pax_record(&mut b, r).unwrap();
            }
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(ty);
            h.set_size(0);
            h.set_mode(0o755);
            if ty == tar::EntryType::Symlink {
                b.append_link(&mut h, format!("w/{rel}"), "target").unwrap();
            } else {
                h.set_cksum();
                b.append_data(&mut h, format!("w/{rel}"), &b""[..]).unwrap();
            }
            let buf = b.into_inner().unwrap();
            let mut ar = tar::Archive::new(&buf[..]);
            let mut e = ar.entries().unwrap().next().unwrap().unwrap();
            unpack_entry(&mut e, t.path(), Path::new(rel), &mut DirModes::new())
        };
        std::fs::create_dir(t.path().join("target")).unwrap();
        if let Err(e) = unpack("flink", None, tar::EntryType::Symlink) {
            if format!("{e:#}").contains("Developer Mode") {
                return; // no symlink privilege on this host
            }
            panic!("{e:#}");
        }
        let kind = |rel: &str| {
            std::fs::symlink_metadata(t.path().join(rel))
                .unwrap()
                .file_type()
        };
        assert!(kind("flink").is_symlink_file());
        unpack(
            "dlink",
            Some(SYMLINK_DIR_PAX_RECORD),
            tar::EntryType::Symlink,
        )
        .unwrap();
        assert!(kind("dlink").is_symlink_dir());
        // An existing file in the way: a symlink failure hints, a
        // directory failure does not.
        std::fs::write(t.path().join("taken"), b"x").unwrap();
        let e = unpack(
            "taken",
            Some(SYMLINK_DIR_PAX_RECORD),
            tar::EntryType::Symlink,
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("Developer Mode"), "{e:#}");
        let e = unpack("taken", None, tar::EntryType::Directory).unwrap_err();
        let e = format!("{e:#}");
        assert!(
            e.contains("unpacking") && !e.contains("Developer Mode"),
            "{e}"
        );
    }
}
