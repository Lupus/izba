//! Bundle load: restore sandboxes from a `.izba` archive (spec §3, §4.3, §7).
//!
//! The archive is UNTRUSTED input. Nothing is written until the manifest
//! passes preflight (format, selection, names, workspace targets, free
//! space). Every entry is then streamed into a stage dir on the data root's
//! filesystem (`<data>/.load-<pid>-<seq>/`; bundled workspaces stage beside
//! their target), verified against the `checksums.json` trailer, and only
//! then committed by renames in a fixed order — images → named volumes →
//! workspaces → sandbox dirs → tags. Each commit step records what it
//! created; any failure undoes exactly that (in reverse), so a failed load
//! leaves the target as it found it. Pre-existing images and identical named
//! volumes are reused and never touched.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fsutil::{human_bytes, nearest_existing};
use super::manifest::{
    check_format, validate_entry_path, Checksums, Manifest, SandboxEntry, CHECKSUMS_PATH,
    MANIFEST_PATH,
};
use super::save::{EGRESS_AUDIT_FILE, IMAGE_FILES, SANDBOX_FILES};
use super::sparse::{content_digest, create_sparse, parse_chunk_entry};
use super::workspace::{is_free_target, translate_workspace, unpack_entry, DirModes};
use super::{Progress, MAX_CHUNK};
use crate::paths::Paths;
use crate::state::{load_json, save_json, PortRule, SandboxConfig, CONFIG_FILE};

/// Image files an existing-but-incomplete target cache entry may gain.
const IMAGE_META: [&str; 3] = ["config.json", "passwd", "group"];

/// Upper bound on the manifest / trailer JSON read into memory.
const MAX_JSON: u64 = 16 << 20;

pub struct LoadOpts {
    pub archive: PathBuf,
    /// Sandboxes to load by their archived name; empty = all.
    pub select: Vec<String>,
    /// New name (`--as`); requires exactly one selected sandbox.
    pub rename: Option<String>,
    /// Explicit workspace dir; requires exactly one selected sandbox.
    pub workspace: Option<PathBuf>,
    /// Each workspace goes to `<root>/<basename(source workspace)>`.
    pub workspace_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoadedSandbox {
    pub name: String,
    pub image_ref: String,
    pub workspace: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LoadReport {
    pub sandboxes: Vec<LoadedSandbox>,
    /// Non-fatal observations (reused volume, busy host port, ...).
    pub warnings: Vec<String>,
    /// What the user must redo on this host (re-plug USB, re-run lockdown).
    pub redo: Vec<String>,
}

/// Test seams: free-space and port probes, the home dir used for cross-OS
/// workspace translation, and a fault injected just before a commit step.
pub(crate) struct LoadHooks<'a> {
    pub free_bytes: &'a dyn Fn(&Path) -> anyhow::Result<u64>,
    pub port_in_use: &'a dyn Fn(&PortRule) -> bool,
    pub target_home: PathBuf,
    pub fail_at: Option<CommitStep>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitStep {
    Images,
    Volumes,
    Workspaces,
    Sandboxes,
}

pub fn load(paths: &Paths, opts: &LoadOpts, progress: Progress) -> anyhow::Result<LoadReport> {
    load_with(
        paths,
        opts,
        progress,
        &LoadHooks {
            free_bytes: &super::fsutil::free_bytes,
            port_in_use: &host_port_in_use,
            target_home: home_dir()?,
            fail_at: None,
        },
    )
}

fn home_dir() -> anyhow::Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .with_context(|| format!("{var} is not set; cannot place workspaces"))
}

/// A host port is busy when binding it fails right now (the probe listener
/// is dropped at once). Only a warning is derived from it.
fn host_port_in_use(rule: &PortRule) -> bool {
    std::net::TcpListener::bind((rule.bind, rule.host_port)).is_err()
}

/// One thing a failed load must undo, applied in reverse order.
enum Undo {
    /// Remove a file or directory tree this load created.
    Remove(PathBuf),
    /// Re-create an empty directory this load removed.
    Recreate(PathBuf),
    /// Put a file's previous bytes back (`None` = it did not exist).
    Restore(PathBuf, Option<Vec<u8>>),
}

/// A selected sandbox, resolved at preflight.
struct Sel {
    src: String,
    name: String,
    entry: SandboxEntry,
    ws_target: PathBuf,
    /// Staging dir beside `ws_target` (bundled workspaces only).
    ws_stage: Option<PathBuf>,
}

/// Where a disk entry's bytes go.
#[derive(Clone)]
enum DiskKind {
    Named(String),
    Sandbox(String),
}

enum DiskState {
    /// Being written into the stage. `next` = lowest offset the next chunk
    /// may start at (chunks are strictly ascending and non-overlapping).
    Open { file: File, len: u64, next: u64 },
    /// Not needed here (reused volume / unselected sandbox): chunks drained.
    Skip { len: u64 },
}

pub(crate) fn load_with(
    paths: &Paths,
    opts: &LoadOpts,
    progress: Progress,
    hooks: &LoadHooks,
) -> anyhow::Result<LoadReport> {
    let mut undo = Vec::new();
    let mut scratch = Vec::new();
    let res = run(paths, opts, progress, hooks, &mut undo, &mut scratch);
    // Stage dirs go in every case; a staged workspace can hold read-only
    // dirs. Best-effort: a leftover `.load-*` is swept by a later load.
    for p in scratch.iter().rev() {
        let _ = force_remove(p);
    }
    res.map_err(|e| {
        let failed = rollback(undo);
        if failed.is_empty() {
            e
        } else {
            e.context(format!(
                "load failed and its rollback is incomplete: {}",
                failed.join("; ")
            ))
        }
    })
}

/// Apply `undo` in reverse; returns one line per step that could not be undone.
fn rollback(undo: Vec<Undo>) -> Vec<String> {
    let mut failed = Vec::new();
    for u in undo.into_iter().rev() {
        let (what, res, p) = match u {
            Undo::Remove(p) => ("remove", force_remove(&p), p),
            Undo::Recreate(p) => ("re-create", fs::create_dir(&p), p),
            Undo::Restore(p, Some(bytes)) => ("restore", fs::write(&p, bytes), p),
            Undo::Restore(p, None) => ("remove", remove_file_if_present(&p), p),
        };
        if let Err(e) = res {
            failed.push(format!("could not {what} {}: {e}", p.display()));
        }
    }
    failed
}

fn remove_file_if_present(p: &Path) -> std::io::Result<()> {
    match fs::remove_file(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// Remove a file or tree (absent = done), making read-only directories
/// writable first if a plain removal fails.
fn force_remove(p: &Path) -> std::io::Result<()> {
    let Ok(m) = fs::symlink_metadata(p) else {
        return Ok(());
    };
    if !m.is_dir() {
        return remove_file_if_present(p);
    }
    match fs::remove_dir_all(p) {
        Ok(()) => Ok(()),
        // Unix only: a staged 0555 dir blocks removal of its children.
        #[cfg(unix)]
        Err(_) => {
            chmod_tree(p);
            fs::remove_dir_all(p)
        }
        #[cfg(not(unix))]
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn chmod_tree(d: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o700));
    if let Ok(rd) = fs::read_dir(d) {
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                chmod_tree(&e.path());
            }
        }
    }
}

/// `create_dir_all(dir)` (0700 inside `root` when given), recording the
/// topmost directory this call created so a rollback removes exactly that.
fn mkdirs(undo: &mut Vec<Undo>, dir: &Path, root: Option<&Path>) -> anyhow::Result<()> {
    let mut top = None;
    let mut cur = Some(dir);
    while let Some(p) = cur {
        if p.exists() {
            break;
        }
        top = Some(p.to_path_buf());
        cur = p.parent();
    }
    match root {
        Some(r) => crate::paths::create_dir_700(dir, r)?,
        None => fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?,
    }
    if let Some(t) = top {
        undo.push(Undo::Remove(t));
    }
    Ok(())
}

fn run(
    paths: &Paths,
    opts: &LoadOpts,
    progress: Progress,
    hooks: &LoadHooks,
    undo: &mut Vec<Undo>,
    scratch: &mut Vec<PathBuf>,
) -> anyhow::Result<LoadReport> {
    let file =
        File::open(&opts.archive).with_context(|| format!("opening {}", opts.archive.display()))?;
    let dec = zstd::Decoder::new(file).context("reading archive (not zstd?)")?;
    let mut ar = tar::Archive::new(dec);
    let mut entries = ar.entries().context("reading archive")?;

    // ---- preflight: nothing is written before this block passes ----------
    let manifest: Manifest = {
        let mut e = match entries.next() {
            Some(e) => e.context("reading archive")?,
            None => bail!("not an izba archive (manifest.json must come first)"),
        };
        if entry_name(&e)? != MANIFEST_PATH {
            bail!("not an izba archive (manifest.json must come first)");
        }
        serde_json::from_slice(&read_bounded(&mut e, MANIFEST_PATH)?)
            .context("parsing manifest.json")?
    };
    check_format(&manifest)?;
    validate_manifest(&manifest)?;
    let mut sels = select(paths, opts, &manifest, hooks)?;
    check_space(paths, &manifest, &sels, hooks)?;
    let mut report = LoadReport::default();

    // ---- stage -----------------------------------------------------------
    sweep_stale_stages(paths.root());
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    mkdirs(undo, paths.root(), Some(paths.root()))?;
    let stage = paths.root().join(format!(".load-{pid}-{seq}"));
    crate::paths::create_dir_700(&stage, paths.root())?;
    scratch.push(stage.clone());
    for s in sels.iter_mut().filter(|s| s.entry.workspace_bundled) {
        let parent = s
            .ws_target
            .parent()
            .with_context(|| format!("workspace {} has no parent", s.ws_target.display()))?;
        mkdirs(undo, parent, None)?;
        let base = s
            .ws_target
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let ws_stage = parent.join(format!(".izba-load-{pid}-{seq}-{base}"));
        fs::create_dir(&ws_stage).with_context(|| format!("creating {}", ws_stage.display()))?;
        scratch.push(ws_stage.clone());
        s.ws_stage = Some(ws_stage);
    }

    progress(format!("reading {}", opts.archive.display()));
    let mut st = Stager::new(paths, &manifest, &sels, stage.clone());
    for e in entries.by_ref() {
        let mut e = e.context("reading archive (truncated or corrupt?)")?;
        st.entry(&mut e, progress)?;
    }
    // Read to the end of the zstd frame so its content checksum (the
    // workspace's transport integrity) is actually verified.
    std::io::copy(&mut ar.into_inner(), &mut std::io::sink())
        .context("archive is truncated or corrupt (zstd)")?;
    let staged = st.finish()?;

    // ---- verify ----------------------------------------------------------
    progress("verifying checksums".into());
    let sums = staged.sums.as_ref().unwrap();
    for (p, (_, sha)) in &staged.files {
        match sums.files.get(p) {
            None => bail!("archive is truncated or corrupt (no checksum for {p})"),
            Some(want) if want != sha => bail!("checksum mismatch for {p}: archive is corrupt"),
            Some(_) => {}
        }
    }
    for (prefix, path) in &staged.disks {
        let want = sums.files.get(prefix).with_context(|| {
            format!("archive is truncated or corrupt (no checksum for {prefix})")
        })?;
        if &content_digest(path)? != want {
            bail!("checksum mismatch for {prefix}: archive is corrupt");
        }
    }

    // ---- configs + reuse decisions (still before any commit) -------------
    let store = crate::image::ImageStore::new(paths);
    let mut configs = Vec::new();
    let mut need_images = BTreeSet::new();
    let mut need_volumes = BTreeSet::new();
    let mut reused = BTreeSet::new();
    let mut refs = Vec::new();
    for s in &sels {
        let cfg = prepare_config(s, &manifest, &staged, hooks, &mut report)?;
        let d = &cfg.image_digest;
        let named: BTreeSet<&String> = cfg.volumes.iter().filter_map(|v| v.name.as_ref()).collect();
        if *d != s.entry.image_digest || named != s.entry.named_volumes.iter().collect() {
            bail!(
                "archive is corrupt: config.json of '{}' disagrees with the manifest",
                s.src
            );
        }
        refs.push((cfg.image_ref.clone(), d.clone()));
        if !store.is_complete(d) {
            let dir = paths.image_dir(d);
            let has =
                |f: &str| dir.join(f).is_file() || staged.files.contains_key(&image_entry(d, f));
            if !has("rootfs.erofs") || !has("config.json") {
                if dir.exists() {
                    bail!(
                        "image {d} is incomplete here and the archive cannot complete it; \
                         remove {} and retry",
                        dir.display()
                    );
                }
                bail!("archive is missing image {d}");
            }
            need_images.insert(d.clone());
        }
        for v in cfg.volumes.iter().filter_map(|v| v.name.as_deref()) {
            let prefix = format!("volumes/{v}.img");
            let existing = paths.volume_image(v);
            if existing.exists() {
                let want = sums.files.get(&prefix).with_context(|| {
                    format!(
                        "archive does not carry named volume '{v}' used by '{}'",
                        s.src
                    )
                })?;
                if &content_digest(&existing)? != want {
                    bail!(
                        "named volume '{v}' already exists here with different contents; \
                         remove or rename it first (izba volume rm {v})"
                    );
                }
                if reused.insert(v.to_string()) {
                    report.warnings.push(format!(
                        "reusing identical volume '{v}' already on this host"
                    ));
                }
            } else if staged.disks.contains_key(&prefix) {
                need_volumes.insert(v.to_string());
            } else {
                bail!(
                    "archive does not carry named volume '{v}' used by '{}'",
                    s.src
                );
            }
        }
        configs.push(cfg);
    }

    // ---- commit ----------------------------------------------------------
    let fail = |step: CommitStep| -> anyhow::Result<()> {
        if hooks.fail_at == Some(step) {
            bail!("injected failure before commit step {step:?}");
        }
        Ok(())
    };

    fail(CommitStep::Images)?;
    for d in &need_images {
        let dst = paths.image_dir(d);
        let from = stage
            .join("images")
            .join(dst.file_name().unwrap_or_default());
        if !dst.exists() {
            mkdirs(undo, &paths.images_dir(), Some(paths.root()))?;
            fs::rename(&from, &dst).with_context(|| format!("installing image {d}"))?;
            undo.push(Undo::Remove(dst));
            continue;
        }
        // Existing but incomplete: its rootfs is kept; add only the verified
        // metadata it lacks (and undo only those files).
        if !store.config_path(d).exists() && from.join("config.json").is_file() {
            store.persist_config(d, &fs::read(from.join("config.json"))?)?;
            undo.push(Undo::Remove(store.config_path(d)));
        }
        for (f, path) in [
            ("passwd", store.passwd_path(d)),
            ("group", store.group_path(d)),
        ] {
            if path.exists() || !from.join(f).is_file() {
                continue;
            }
            let bytes = fs::read(from.join(f))?;
            let (pw, gr) = if f == "passwd" {
                (Some(&bytes[..]), None)
            } else {
                (None, Some(&bytes[..]))
            };
            store.persist_user_dbs(d, pw, gr)?;
            undo.push(Undo::Remove(path));
        }
    }

    fail(CommitStep::Volumes)?;
    for v in &need_volumes {
        let dst = paths.volume_image(v);
        mkdirs(undo, &paths.volumes_dir(), Some(paths.root()))?;
        // No-replace install: a hard link fails if `dst` exists, so a volume
        // created concurrently is never overwritten (a rename would be).
        let from = stage.join(format!("volumes/{v}.img"));
        match fs::hard_link(&from, &dst) {
            Ok(()) => undo.push(Undo::Remove(dst)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                bail!("named volume '{v}' appeared on this host during the load; retry")
            }
            Err(e) => {
                return Err(e).with_context(|| format!("installing volume '{v}'"));
            }
        }
        let _ = fs::remove_file(&from);
    }

    fail(CommitStep::Workspaces)?;
    for s in &sels {
        let Some(ws_stage) = &s.ws_stage else {
            continue;
        };
        let t = &s.ws_target;
        if t.exists() {
            if !is_free_target(t) {
                bail!(
                    "workspace target {} is not empty; pass --workspace <empty-or-new dir>",
                    t.display()
                );
            }
            fs::remove_dir(t).with_context(|| format!("replacing {}", t.display()))?;
            undo.push(Undo::Recreate(t.clone()));
        }
        fs::rename(ws_stage, t).with_context(|| format!("placing workspace {}", t.display()))?;
        undo.push(Undo::Remove(t.clone()));
        crate::procmgr::ensure_confinable(t)?;
    }

    fail(CommitStep::Sandboxes)?;
    mkdirs(undo, &paths.sandboxes_dir(), Some(paths.root()))?;
    for (s, mut cfg) in sels.iter().zip(configs) {
        let dir = paths.sandbox_dir(&s.name);
        // Exclusive: a concurrent create/load of the same name loses here.
        fs::create_dir(&dir).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow::anyhow!("{}", exists_msg(&s.name))
            } else {
                anyhow::Error::new(e).context(format!("creating {}", dir.display()))
            }
        })?;
        undo.push(Undo::Remove(dir.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        crate::paths::create_dir_700(&paths.logs_dir(&s.name), paths.root())?;
        let run = paths.run_dir(&s.name);
        let run_top = std::iter::successors(Some(run.as_path()), |p| p.parent())
            .take_while(|p| !p.exists())
            .last()
            .map(Path::to_path_buf);
        let marker = run.join(crate::sandbox::RUN_DIR_OWNER);
        let marker_existed = marker.exists();
        crate::sandbox::claim_run_dir(paths, &s.name)?;
        match run_top {
            Some(t) => undo.push(Undo::Remove(t)),
            // A pre-existing run dir (e.g. left behind by an `rm`): undo only
            // the owner marker this claim wrote.
            None if !marker_existed => undo.push(Undo::Remove(marker)),
            None => {}
        }
        cfg.workspace = s
            .ws_target
            .canonicalize()
            .with_context(|| format!("resolving workspace {}", s.ws_target.display()))?;
        save_json(&dir.join(CONFIG_FILE), &cfg)?;
        let prefix = format!("sandboxes/{}/", s.src);
        let files = staged.files.iter().map(|(p, (path, _))| (p, path));
        for (p, from) in files.chain(staged.disks.iter()) {
            let Some(rel) = p.strip_prefix(&prefix) else {
                continue;
            };
            if rel == CONFIG_FILE {
                continue; // rewritten above
            }
            let to = if rel == EGRESS_AUDIT_FILE {
                paths.logs_dir(&s.name).join(rel)
            } else {
                dir.join(rel)
            };
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(from, &to).with_context(|| format!("installing {}", to.display()))?;
        }
        report.sandboxes.push(LoadedSandbox {
            name: s.name.clone(),
            image_ref: cfg.image_ref.clone(),
            workspace: cfg.workspace.clone(),
        });
    }

    // Tags last. Only a loaded sandbox's own `image_ref`, mapped by the
    // archive to that sandbox's digest, and only when it does not resolve
    // here: an archive can never plant a tag that shadows an unrelated
    // (e.g. bare registry) name. Every tag created is reported.
    let mut tags_saved = false;
    let mut seen = BTreeSet::new();
    for (tag, digest) in &refs {
        if manifest.tags.get(tag) != Some(digest)
            || !seen.insert(tag)
            || crate::image::tags::resolve_tag(paths, tag)?.is_some()
        {
            continue;
        }
        if !tags_saved {
            let tp = crate::image::tags::tags_path(paths);
            undo.push(Undo::Restore(tp.clone(), fs::read(&tp).ok()));
            tags_saved = true;
        }
        crate::image::tags::set_tag(paths, tag, digest)?;
        report.warnings.push(format!(
            "created local image tag '{tag}' → {digest} (from the archive)"
        ));
    }
    Ok(report)
}

fn exists_msg(name: &str) -> String {
    format!(
        "sandbox '{name}' already exists here; pass --as <new-name> to load it under another name"
    )
}

fn image_entry(digest: &str, file: &str) -> String {
    format!("images/{}/{file}", digest.replace(':', "-"))
}

/// Structural checks on the (untrusted) manifest before anything is used.
fn validate_manifest(m: &Manifest) -> anyhow::Result<()> {
    let mut names = BTreeSet::new();
    for s in &m.sandboxes {
        crate::sandbox::validate_name(&s.name)?;
        if !names.insert(&s.name) {
            bail!("archive lists sandbox '{}' twice", s.name);
        }
        let own = format!("sandboxes/{}/", s.name);
        for d in &s.disks {
            validate_entry_path(&d.path)?;
            let rel = d.path.strip_prefix(&own).unwrap_or("");
            let anon_ok = rel
                .strip_prefix("volumes/")
                .and_then(|f| f.strip_suffix(".img"))
                .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()));
            if rel != "rw.img" && !anon_ok {
                bail!("unexpected disk {:?} for sandbox '{}'", d.path, s.name);
            }
        }
        if !m.images.contains(&s.image_digest) {
            bail!(
                "sandbox '{}': image {:?} is not in the archive",
                s.name,
                s.image_digest
            );
        }
        for v in &s.named_volumes {
            if !m
                .named_volumes
                .iter()
                .any(|b| b.path == format!("volumes/{v}.img"))
            {
                bail!(
                    "sandbox '{}': named volume {v:?} is not in the archive",
                    s.name
                );
            }
        }
    }
    for v in &m.named_volumes {
        let name = v
            .path
            .strip_prefix("volumes/")
            .and_then(|p| p.strip_suffix(".img"))
            .unwrap_or("");
        if !crate::volume::valid_name(name) {
            bail!("unexpected named volume path {:?} in archive", v.path);
        }
    }
    for d in &m.images {
        if !valid_digest(d) {
            bail!("invalid image digest {d:?} in archive");
        }
    }
    Ok(())
}

/// `<alg>:<hex>`, lowercase alphanumerics only: safe as one path component.
fn valid_digest(d: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    d.split_once(':').is_some_and(|(a, h)| ok(a) && ok(h))
}

/// Resolve the selection, final names and workspace targets.
fn select(
    paths: &Paths,
    opts: &LoadOpts,
    m: &Manifest,
    hooks: &LoadHooks,
) -> anyhow::Result<Vec<Sel>> {
    let available = || {
        m.sandboxes
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut picked: Vec<&SandboxEntry> = Vec::new();
    if opts.select.is_empty() {
        picked.extend(&m.sandboxes);
    } else {
        for n in &opts.select {
            let e = m.sandboxes.iter().find(|s| &s.name == n).with_context(|| {
                format!(
                    "sandbox '{n}' is not in this archive (available: {})",
                    available()
                )
            })?;
            if !picked.iter().any(|p| p.name == e.name) {
                picked.push(e);
            }
        }
    }
    if picked.is_empty() {
        bail!("archive holds no sandboxes");
    }
    if picked.len() != 1 {
        if opts.rename.is_some() {
            bail!(
                "--as requires exactly one selected sandbox (this archive holds: {})",
                available()
            );
        }
        if opts.workspace.is_some() {
            bail!(
                "--workspace requires exactly one selected sandbox (use --workspace-root \
                 for several; this archive holds: {})",
                available()
            );
        }
    }
    let mut sels: Vec<Sel> = Vec::new();
    for e in picked {
        let name = opts.rename.clone().unwrap_or_else(|| e.name.clone());
        crate::sandbox::validate_name(&name)?;
        crate::paths::ensure_socket_budget(paths, &name)?;
        if paths.sandbox_dir(&name).exists() {
            bail!("{}", exists_msg(&name));
        }
        let target = workspace_target(opts, e, m, hooks)?;
        if e.workspace_bundled {
            if !is_free_target(&target) {
                bail!(
                    "workspace target {} is not empty; pass --workspace <empty-or-new dir>",
                    target.display()
                );
            }
            if sels
                .iter()
                .any(|s| s.entry.workspace_bundled && s.ws_target == target)
            {
                bail!(
                    "two sandboxes would restore their workspace to {}; pass --workspace-root",
                    target.display()
                );
            }
        } else {
            if !target.is_dir() {
                bail!(
                    "workspace {} does not exist; clone/copy it there or pass --workspace <dir> \
                     (or save with --with-workspace)",
                    target.display()
                );
            }
            crate::procmgr::ensure_confinable(&target)?;
        }
        sels.push(Sel {
            src: e.name.clone(),
            name,
            entry: e.clone(),
            ws_target: target,
            ws_stage: None,
        });
    }
    Ok(sels)
}

/// Explicit `--workspace` > `--workspace-root/<basename>` > the source path
/// (translated across OSes).
fn workspace_target(
    opts: &LoadOpts,
    e: &SandboxEntry,
    m: &Manifest,
    hooks: &LoadHooks,
) -> anyhow::Result<PathBuf> {
    let p = if let Some(w) = &opts.workspace {
        w.clone()
    } else if let Some(root) = &opts.workspace_root {
        root.join(source_basename(&e.source_workspace).with_context(|| {
            format!(
                "sandbox '{}': source workspace {} has no usable name; pass --workspace <dir>",
                e.name, e.source_workspace
            )
        })?)
    } else {
        translate_workspace(
            &e.source_workspace,
            e.source_home.as_deref(),
            &m.source_os,
            &hooks.target_home,
        )
        .with_context(|| {
            format!(
                "sandbox '{}': cannot place workspace {} on this host; pass --workspace <dir>",
                e.name, e.source_workspace
            )
        })?
    };
    std::path::absolute(&p).with_context(|| format!("resolving {}", p.display()))
}

/// Last component of a source path, split on either separator; `None` for
/// anything that is not one plain component on this host.
fn source_basename(s: &str) -> Option<&str> {
    let b = s.rsplit(['/', '\\']).find(|c| !c.is_empty())?;
    (b != "." && b != ".." && !b.contains([':', '\0'])).then_some(b)
}

/// Image digests and named volumes the selected sandboxes use (per the
/// manifest; each staged config is later checked to agree with it).
fn selection_needs(sels: &[Sel]) -> (BTreeSet<String>, BTreeSet<String>) {
    let images = sels.iter().map(|s| s.entry.image_digest.clone()).collect();
    let volumes = sels
        .iter()
        .flat_map(|s| s.entry.named_volumes.iter().cloned())
        .collect();
    (images, volumes)
}

/// Allocated bytes needed per target filesystem (keyed by the nearest
/// existing ancestor), with 5% headroom: the selected sandboxes' disks, the
/// named volumes and images they use that this host lacks, and bundled
/// workspaces (`workspace_bytes` is only an estimate).
fn check_space(paths: &Paths, m: &Manifest, sels: &[Sel], hooks: &LoadHooks) -> anyhow::Result<()> {
    let mut need: BTreeMap<PathBuf, u64> = BTreeMap::new();
    let mut data: u64 = sels
        .iter()
        .flat_map(|s| &s.entry.disks)
        .map(|d| d.allocated)
        .fold(0, u64::saturating_add);
    let (images, volumes) = selection_needs(sels);
    for v in &m.named_volumes {
        let name = v
            .path
            .trim_start_matches("volumes/")
            .trim_end_matches(".img");
        if volumes.contains(name) && !paths.volume_image(name).exists() {
            data = data.saturating_add(v.allocated);
        }
    }
    let store = crate::image::ImageStore::new(paths);
    for d in images.iter().filter(|d| !store.is_complete(d)) {
        data = data.saturating_add(m.image_sizes.get(d).copied().unwrap_or(0));
    }
    *need.entry(nearest_existing(paths.root())?).or_default() += data;
    for s in sels.iter().filter(|s| s.entry.workspace_bundled) {
        let e = need.entry(nearest_existing(&s.ws_target)?).or_default();
        *e = e.saturating_add(s.entry.workspace_bytes);
    }
    for (dir, n) in need {
        if n == 0 {
            continue;
        }
        let want = (n as u128 * 105 / 100).min(u64::MAX as u128) as u64;
        let free = (hooks.free_bytes)(&dir)?;
        if free < want {
            bail!(
                "not enough free space on {}: need {}, have {}",
                dir.display(),
                human_bytes(want),
                human_bytes(free)
            );
        }
    }
    Ok(())
}

/// Remove `<root>/.load-<pid>-*` stage dirs left by a dead process. Only on
/// Linux, where `/proc/<pid>` answers liveness cheaply; elsewhere they stay.
fn sweep_stale_stages(root: &Path) {
    #[cfg(target_os = "linux")]
    {
        let Ok(rd) = fs::read_dir(root) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(pid) = name
                .strip_prefix(".load-")
                .and_then(|r| r.split('-').next())
                .and_then(|p| p.parse::<u32>().ok())
            else {
                continue;
            };
            if !Path::new(&format!("/proc/{pid}")).exists() {
                let _ = force_remove(&e.path());
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = root;
}

/// What streaming produced.
struct Staged {
    /// archive path -> (staged file, sha256 hex) for plain files.
    files: BTreeMap<String, (PathBuf, String)>,
    /// disk prefix -> staged sparse file.
    disks: BTreeMap<String, PathBuf>,
    sums: Option<Checksums>,
}

struct Stager<'a> {
    paths: &'a Paths,
    m: &'a Manifest,
    stage: PathBuf,
    /// source name -> selected sandbox's workspace stage (bundled only).
    selected: HashMap<String, Option<PathBuf>>,
    known_disks: HashMap<String, (DiskKind, u64)>,
    /// image dir name -> digest.
    image_dirs: HashMap<String, String>,
    /// What the selection uses; everything else is drained unstaged.
    need_images: BTreeSet<String>,
    need_volumes: BTreeSet<String>,
    disks: HashMap<String, DiskState>,
    dir_modes: HashMap<String, DirModes>,
    out: Staged,
}

impl<'a> Stager<'a> {
    fn new(paths: &'a Paths, m: &'a Manifest, sels: &[Sel], stage: PathBuf) -> Self {
        let mut known_disks = HashMap::new();
        for v in &m.named_volumes {
            let name = v
                .path
                .trim_start_matches("volumes/")
                .trim_end_matches(".img");
            known_disks.insert(
                v.path.clone(),
                (DiskKind::Named(name.into()), v.logical_len),
            );
        }
        for s in &m.sandboxes {
            for d in &s.disks {
                known_disks.insert(
                    d.path.clone(),
                    (DiskKind::Sandbox(s.name.clone()), d.logical_len),
                );
            }
        }
        let (need_images, need_volumes) = selection_needs(sels);
        Self {
            paths,
            m,
            stage,
            need_images,
            need_volumes,
            selected: sels
                .iter()
                .map(|s| (s.src.clone(), s.ws_stage.clone()))
                .collect(),
            known_disks,
            image_dirs: m
                .images
                .iter()
                .map(|d| (d.replace(':', "-"), d.clone()))
                .collect(),
            disks: HashMap::new(),
            dir_modes: HashMap::new(),
            out: Staged {
                files: BTreeMap::new(),
                disks: BTreeMap::new(),
                sums: None,
            },
        }
    }

    fn entry<R: Read>(&mut self, e: &mut tar::Entry<R>, progress: Progress) -> anyhow::Result<()> {
        let p = entry_name(e)?;
        validate_entry_path(&p)?;
        if self.out.sums.is_some() {
            bail!("unexpected archive entry {p} after checksums.json (corrupt archive)");
        }
        let ty = e.header().entry_type();
        if let Some(rest) = p.strip_prefix("workspaces/") {
            return self.workspace_entry(e, &p, rest);
        }
        if !ty.is_file() {
            bail!("archive entry {p} is not a regular file");
        }
        if p == CHECKSUMS_PATH {
            self.out.sums = Some(
                serde_json::from_slice(&read_bounded(e, CHECKSUMS_PATH)?)
                    .context("parsing checksums.json")?,
            );
            return Ok(());
        }
        if p == MANIFEST_PATH {
            bail!("archive holds a second manifest.json (corrupt archive)");
        }
        if let Some(prefix) = p.strip_suffix(".len") {
            if let Some((kind, logical)) = self.known_disks.get(prefix).cloned() {
                return self.len_marker(e, &p, prefix, kind, logical, progress);
            }
        }
        if p.contains(".d/") {
            return self.chunk(e, &p);
        }
        if let Some(rest) = p.strip_prefix("images/") {
            return self.image_file(e, &p, rest, progress);
        }
        if let Some(rest) = p.strip_prefix("sandboxes/") {
            let (src, file) = rest.split_once('/').unwrap_or((rest, ""));
            if !self.m.sandboxes.iter().any(|s| s.name == src)
                || !(SANDBOX_FILES.contains(&file) || file == EGRESS_AUDIT_FILE)
            {
                bail!("unexpected archive entry {p}");
            }
            if !self.selected.contains_key(src) {
                return drain(e);
            }
            let dst = self.stage.join(&p);
            let sha = stage_file(e, &dst)?;
            return self.add_file(&p, dst, sha);
        }
        bail!("unexpected archive entry {p}")
    }

    fn add_file(&mut self, p: &str, dst: PathBuf, sha: String) -> anyhow::Result<()> {
        if self.out.files.insert(p.to_string(), (dst, sha)).is_some() {
            bail!("archive entry {p} appears twice (corrupt archive)");
        }
        Ok(())
    }

    fn image_file<R: Read>(
        &mut self,
        e: &mut tar::Entry<R>,
        p: &str,
        rest: &str,
        progress: Progress,
    ) -> anyhow::Result<()> {
        let (dir, file) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(digest) = self.image_dirs.get(dir) else {
            bail!("unexpected archive entry {p} (image not in manifest)");
        };
        if !IMAGE_FILES.contains(&file) {
            bail!("unexpected archive entry {p}");
        }
        if !self.need_images.contains(digest)
            || crate::image::ImageStore::new(self.paths).is_complete(digest)
        {
            return drain(e); // unused here, or the target's copy is kept
        }
        let target = self.paths.image_dir(digest);
        // An incomplete target entry (#222: rootfs without config.json) keeps
        // its rootfs; only the metadata it lacks is taken from the archive.
        if target.exists() && (!IMAGE_META.contains(&file) || target.join(file).exists()) {
            return drain(e);
        }
        progress(format!("staging image {digest} ({file})"));
        let dst = self.stage.join(p);
        let sha = stage_file(e, &dst)?;
        self.add_file(p, dst, sha)
    }

    fn len_marker<R: Read>(
        &mut self,
        e: &mut tar::Entry<R>,
        p: &str,
        prefix: &str,
        kind: DiskKind,
        logical: u64,
        progress: Progress,
    ) -> anyhow::Result<()> {
        let mut b = [0u8; 8];
        if e.size() != 8 {
            bail!("archive entry {p} is not an 8-byte length (corrupt archive)");
        }
        e.read_exact(&mut b)
            .with_context(|| format!("reading {p}"))?;
        let len = u64::from_le_bytes(b);
        if len != logical {
            bail!("archive entry {p} disagrees with the manifest (corrupt archive)");
        }
        if self.disks.contains_key(prefix) {
            bail!("archive entry {p} appears twice (corrupt archive)");
        }
        let wanted = match &kind {
            DiskKind::Named(v) => {
                self.need_volumes.contains(v) && !self.paths.volume_image(v).exists()
            }
            DiskKind::Sandbox(src) => self.selected.contains_key(src),
        };
        let state = if wanted {
            progress(format!("restoring {prefix}"));
            let dst = self.stage.join(prefix);
            fs::create_dir_all(dst.parent().unwrap_or(&self.stage))?;
            let file = create_sparse(&dst, len)?;
            self.out.disks.insert(prefix.to_string(), dst);
            DiskState::Open { file, len, next: 0 }
        } else {
            DiskState::Skip { len }
        };
        self.disks.insert(prefix.to_string(), state);
        Ok(())
    }

    fn chunk<R: Read>(&mut self, e: &mut tar::Entry<R>, p: &str) -> anyhow::Result<()> {
        let Some((prefix, off)) = parse_chunk_entry(p) else {
            bail!("malformed chunk entry {p} (corrupt archive)");
        };
        let size = e.size();
        let Some(state) = self.disks.get_mut(prefix) else {
            bail!("chunk entry {p} arrives before its {prefix}.len marker (corrupt archive)");
        };
        let len = match state {
            DiskState::Open { len, .. } | DiskState::Skip { len } => *len,
        };
        if size == 0 || size > MAX_CHUNK || off.checked_add(size).is_none_or(|end| end > len) {
            bail!("chunk entry {p} exceeds the disk's declared length or chunk size (corrupt archive)");
        }
        match state {
            DiskState::Skip { .. } => drain(e),
            DiskState::Open { file, next, .. } => {
                if off < *next {
                    bail!("chunk entry {p} overlaps an earlier chunk (corrupt archive)");
                }
                file.seek(SeekFrom::Start(off))?;
                let n = std::io::copy(e, file).with_context(|| format!("restoring {p}"))?;
                if n != size {
                    bail!("chunk entry {p} is short (truncated archive)");
                }
                *next = off + size;
                Ok(())
            }
        }
    }

    fn workspace_entry<R: Read>(
        &mut self,
        e: &mut tar::Entry<R>,
        p: &str,
        rest: &str,
    ) -> anyhow::Result<()> {
        let (src, rel) = rest.split_once('/').unwrap_or((rest, ""));
        let Some(entry) = self.m.sandboxes.iter().find(|s| s.name == src) else {
            bail!("unexpected archive entry {p}");
        };
        if !entry.workspace_bundled || rel.is_empty() {
            bail!("unexpected archive entry {p}");
        }
        let Some(Some(ws_stage)) = self.selected.get(src) else {
            return drain(e);
        };
        let rel_path: PathBuf = rel.split('/').collect();
        let modes = self.dir_modes.entry(src.to_string()).or_default();
        unpack_entry(e, ws_stage, &rel_path, modes)
    }

    fn finish(mut self) -> anyhow::Result<Staged> {
        if self.out.sums.is_none() {
            bail!("archive is truncated or corrupt (no checksums.json)");
        }
        self.disks.clear(); // close staged disk files
        for (_, modes) in self.dir_modes.drain() {
            modes.apply()?;
        }
        // Everything the selection needs must have arrived.
        for s in self
            .m
            .sandboxes
            .iter()
            .filter(|s| self.selected.contains_key(&s.name))
        {
            let cfg = format!("sandboxes/{}/{CONFIG_FILE}", s.name);
            if !self.out.files.contains_key(&cfg) {
                bail!("archive is truncated or corrupt (missing {cfg})");
            }
            for d in &s.disks {
                if !self.out.disks.contains_key(&d.path) {
                    bail!("archive is truncated or corrupt (missing {})", d.path);
                }
            }
        }
        Ok(self.out)
    }
}

/// Parse, validate and rewrite the staged `config.json` of `s` for this
/// host. The workspace is set at commit, once the target exists.
fn prepare_config(
    s: &Sel,
    m: &Manifest,
    staged: &Staged,
    hooks: &LoadHooks,
    report: &mut LoadReport,
) -> anyhow::Result<SandboxConfig> {
    let p = format!("sandboxes/{}/{CONFIG_FILE}", s.src);
    let (path, _) = &staged.files[&p];
    let mut cfg: SandboxConfig =
        load_json(path)?.with_context(|| format!("archive is corrupt (empty {p})"))?;
    let n = &s.name;
    if !m.images.contains(&cfg.image_digest) {
        bail!(
            "sandbox '{}': image {} is not in the archive",
            s.src,
            cfg.image_digest
        );
    }
    if cfg.docker && cfg.builder {
        bail!(
            "sandbox '{}': docker and builder are mutually exclusive",
            s.src
        );
    }
    crate::volume::validate_volumes(&cfg.volumes, cfg.vnc)?;
    for v in &cfg.volumes {
        let gp = v.guest_path.to_string_lossy();
        if !gp.starts_with('/') || gp.contains(',') {
            bail!("sandbox '{}': invalid volume guest path {gp:?}", s.src);
        }
        match (&v.name, v.eph_id) {
            (Some(name), _) => {
                if !crate::volume::valid_name(name) {
                    bail!("sandbox '{}': invalid volume name {name:?}", s.src);
                }
            }
            (None, Some(id)) => {
                let disk = format!("sandboxes/{}/volumes/{id}.img", s.src);
                if !staged.disks.contains_key(&disk) {
                    bail!("archive is truncated or corrupt (missing {disk})");
                }
            }
            (None, None) => bail!("sandbox '{}': anonymous volume without an id", s.src),
        }
    }
    for g in &mut cfg.usb.devices {
        if g.busid_pin.take().is_some() {
            report.warnings.push(format!(
                "sandbox '{n}': USB busid pin for {} cleared (host-specific)",
                g.device
            ));
        }
        report
            .redo
            .push(format!("re-plug USB device {} for '{n}'", g.device));
    }
    for r in cfg.ports.iter().filter(|r| (hooks.port_in_use)(r)) {
        report.warnings.push(format!(
            "sandbox '{n}': host port {}:{} is in use here; publishing it to guest port {} \
             will fail until it is free",
            r.bind, r.host_port, r.guest_port
        ));
    }
    if s.entry.locked {
        report.redo.push(format!(
            "run `izba lockdown {n}` to re-apply Windows account confinement"
        ));
    }
    cfg.disk_owner = Some(s.entry.disk_owner);
    Ok(cfg)
}

/// Raw entry path as UTF-8 (never normalized by the tar crate).
fn entry_name<R: Read>(e: &tar::Entry<R>) -> anyhow::Result<String> {
    String::from_utf8(e.path_bytes().into_owned())
        .map_err(|_| anyhow::anyhow!("archive entry with a non-UTF-8 path (corrupt archive)"))
}

fn read_bounded<R: Read>(e: &mut R, what: &str) -> anyhow::Result<Vec<u8>> {
    let mut v = Vec::new();
    e.take(MAX_JSON + 1)
        .read_to_end(&mut v)
        .with_context(|| format!("reading {what}"))?;
    if v.len() as u64 > MAX_JSON {
        bail!("{what} is implausibly large (corrupt archive)");
    }
    Ok(v)
}

fn drain<R: Read>(e: &mut R) -> anyhow::Result<()> {
    std::io::copy(e, &mut std::io::sink()).context("reading archive")?;
    Ok(())
}

/// Copy an entry body to `dst`, returning its sha256.
fn stage_file<R: Read>(e: &mut R, dst: &Path) -> anyhow::Result<String> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = File::create(dst).with_context(|| format!("creating {}", dst.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = e.read(&mut buf).context("reading archive")?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        f.write_all(&buf[..n])?;
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::sparse::content_digest;
    use crate::bundle::testutil::{
        add_sandbox, opts_bundled, read_entries, rewrite_archive, write_sparse_disk, Src, Tgt,
    };
    use crate::state::load_json;

    fn opts(archive: PathBuf, workspace: Option<PathBuf>) -> LoadOpts {
        LoadOpts {
            archive,
            select: vec![],
            rename: None,
            workspace,
            workspace_root: None,
        }
    }

    fn no_stage_left(tgt: &Tgt) -> bool {
        !tgt.paths.root().read_dir().unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".load-")
        })
    }

    #[test]
    fn round_trip_is_byte_identical_and_rewrites_host_fields() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let rep = load_with(
            &tgt.paths,
            &opts(ar, Some(ws.clone())),
            &mut |_| {},
            &tgt.hooks(),
        )
        .unwrap();
        assert_eq!(rep.sandboxes.len(), 1);
        assert_eq!(rep.sandboxes[0].name, "a");
        assert_eq!(rep.sandboxes[0].image_ref, "fixture:latest");
        assert_eq!(rep.sandboxes[0].workspace, ws.canonicalize().unwrap());
        for (s, t) in src.disk_pairs("a", "a", &tgt.paths) {
            assert_eq!(content_digest(&s).unwrap(), content_digest(&t).unwrap());
            assert_eq!(std::fs::read(&s).unwrap(), std::fs::read(&t).unwrap());
        }
        let dir = tgt.paths.sandbox_dir("a");
        let cfg: SandboxConfig = load_json(&dir.join(CONFIG_FILE)).unwrap().unwrap();
        assert_eq!(cfg.workspace, ws.canonicalize().unwrap());
        assert_eq!(cfg.usb.devices.len(), 1);
        assert!(cfg.usb.devices.iter().all(|g| g.busid_pin.is_none()));
        assert!(cfg.disk_owner.is_some());
        assert!(dir.join("policy.yaml").is_file());
        assert_eq!(
            std::fs::read(tgt.paths.logs_dir("a").join("egress-audit.jsonl")).unwrap(),
            b"{}\n"
        );
        // Host-bound state is never recreated by a load.
        assert!(!dir.join("lockdown.json").exists());
        assert!(tgt.paths.run_dir("a").join("owner").is_file());
        // The image arrived complete.
        assert!(crate::image::ImageStore::new(&tgt.paths).is_complete("sha256:aa"));
        assert!(no_stage_left(&tgt));
        assert!(rep.redo.iter().any(|r| r.contains("USB")), "{:?}", rep.redo);
        assert!(
            rep.redo.iter().any(|r| r.contains("izba lockdown a")),
            "{:?}",
            rep.redo
        );
    }

    #[test]
    fn bundled_workspace_is_restored_to_the_chosen_dir() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        let ws = tgt.dir("ws/a");
        assert_eq!(std::fs::read(ws.join("README")).unwrap(), b"hello");
        assert_eq!(rep.sandboxes[0].workspace, ws.canonicalize().unwrap());
        // The workspace staging dir beside the target is gone.
        let left: Vec<_> = std::fs::read_dir(tgt.dir("ws"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, vec![std::ffi::OsString::from("a")]);
        assert!(no_stage_left(&tgt));
    }

    #[test]
    fn existing_sandbox_name_is_refused_and_as_renames() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let o = opts(ar.clone(), Some(ws.clone()));
        load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("already exists") && e.contains("--as"), "{e}");
        let renamed = LoadOpts {
            rename: Some("b".into()),
            ..opts(ar, Some(ws))
        };
        let rep = load_with(&tgt.paths, &renamed, &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(rep.sandboxes[0].name, "b");
        for (s, t) in src.disk_pairs("a", "b", &tgt.paths) {
            assert_eq!(std::fs::read(&s).unwrap(), std::fs::read(&t).unwrap());
        }
        assert!(tgt.paths.run_dir("b").join("owner").is_file());
        // "a" is untouched by the second, refused load.
        assert!(tgt.paths.sandbox_dir("a").join(CONFIG_FILE).is_file());
        assert!(no_stage_left(&tgt));
    }

    #[test]
    fn existing_image_is_kept() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let img = tgt.paths.image_dir("sha256:aa");
        std::fs::create_dir_all(&img).unwrap();
        std::fs::write(img.join("rootfs.erofs"), b"target's own rootfs").unwrap();
        std::fs::write(img.join("config.json"), b"{}").unwrap();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(
            std::fs::read(img.join("rootfs.erofs")).unwrap(),
            b"target's own rootfs"
        );
        assert_eq!(std::fs::read(img.join("config.json")).unwrap(), b"{}");
        assert!(!img.join("ref.txt").exists());
    }

    #[test]
    fn identical_named_volume_is_reused() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let vol = tgt.paths.volume_image("data");
        write_sparse_disk(&vol, 0xCD); // same bytes as the source's "data"
        let before = std::fs::metadata(&vol).unwrap().modified().unwrap();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let rep = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks()).unwrap();
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("reusing") && w.contains("'data'")),
            "{:?}",
            rep.warnings
        );
        assert_eq!(std::fs::metadata(&vol).unwrap().modified().unwrap(), before);
        assert_eq!(
            content_digest(&vol).unwrap(),
            content_digest(&src.paths.volume_image("data")).unwrap()
        );
    }

    #[test]
    fn different_named_volume_is_refused() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let vol = tgt.paths.volume_image("data");
        write_sparse_disk(&vol, 0x99);
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("'data'") && e.contains("izba volume rm data"),
            "{e}"
        );
        assert!(!tgt.paths.sandbox_dir("a").exists());
        assert_eq!(tgt.snapshot(), before);
        let mut still = vec![0u8; 1];
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&vol).unwrap();
        f.seek(SeekFrom::Start(crate::bundle::testutil::DATA_OFF))
            .unwrap();
        f.read_exact(&mut still).unwrap();
        assert_eq!(still, [0x99]);
    }

    #[test]
    fn rollback_at_each_commit_step_leaves_target_untouched() {
        for step in [
            CommitStep::Images,
            CommitStep::Volumes,
            CommitStep::Workspaces,
            CommitStep::Sandboxes,
        ] {
            let tgt = Tgt::new();
            let o = opts_bundled(&tgt);
            let before = tgt.snapshot();
            let mut hooks = tgt.hooks();
            hooks.fail_at = Some(step);
            let e = load_with(&tgt.paths, &o, &mut |_| {}, &hooks).unwrap_err();
            assert!(e.to_string().contains("injected"), "{step:?}: {e}");
            assert_eq!(tgt.snapshot(), before, "{step:?} left debris");
        }
    }

    #[test]
    fn rollback_after_the_workspace_commit_restores_a_pre_existing_empty_target() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        std::fs::create_dir_all(tgt.dir("ws/a")).unwrap();
        let before = tgt.snapshot();
        let mut hooks = tgt.hooks();
        hooks.fail_at = Some(CommitStep::Sandboxes);
        load_with(&tgt.paths, &o, &mut |_| {}, &hooks).unwrap_err();
        assert_eq!(tgt.snapshot(), before);
        assert!(tgt.dir("ws/a").is_dir());
        // Without the injected failure the empty target is filled.
        load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        assert!(tgt.dir("ws/a/README").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn rollback_removes_a_restored_read_only_workspace_dir() {
        use std::os::unix::fs::PermissionsExt;
        let set = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let src = Src::new();
        let ro = crate::bundle::testutil::workspace_of(&src.paths, "a").join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::write(ro.join("f"), b"x").unwrap();
        set(&ro, 0o555);
        let tgt = Tgt::new();
        let ar = tgt.dir("in.izba");
        src.save_to(&["a"], true, &ar);
        set(&ro, 0o755);
        let o = opts(ar, Some(tgt.dir("ws/a")));
        let before = tgt.snapshot();
        let mut hooks = tgt.hooks();
        hooks.fail_at = Some(CommitStep::Sandboxes);
        load_with(&tgt.paths, &o, &mut |_| {}, &hooks).unwrap_err();
        assert_eq!(tgt.snapshot(), before);
        // A successful load restores the recorded mode.
        load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        let mode = std::fs::metadata(tgt.dir("ws/a/ro"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o555);
        set(&tgt.dir("ws/a/ro"), 0o755);
    }

    /// Edit the source sandbox's config.json in place.
    fn edit_src_config(src: &Src, name: &str, f: impl FnOnce(&mut SandboxConfig)) {
        let cp = src.paths.sandbox_dir(name).join(CONFIG_FILE);
        let mut c: SandboxConfig = load_json(&cp).unwrap().unwrap();
        f(&mut c);
        crate::state::save_json(&cp, &c).unwrap();
    }

    /// Edit the archive's manifest.json (not covered by the trailer).
    fn edit_manifest(archive: &Path, f: impl FnOnce(&mut Manifest)) {
        let mut f = Some(f);
        rewrite_archive(archive, |name, body| {
            if name != MANIFEST_PATH {
                return Some(body);
            }
            let mut m: Manifest = serde_json::from_slice(&body).unwrap();
            (f.take().unwrap())(&mut m);
            Some(serde_json::to_vec(&m).unwrap())
        });
    }

    #[test]
    fn a_selective_load_leaves_the_other_sandboxes_image_and_volume_behind() {
        let src = Src::new();
        add_sandbox(&src.paths, "b", "sha256:bb", &[]);
        let ar = src.save(&["a", "b"], false);
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let o = LoadOpts {
            select: vec!["b".into()],
            ..opts(ar, Some(ws))
        };
        let mut msgs = Vec::new();
        load_with(&tgt.paths, &o, &mut |m| msgs.push(m), &tgt.hooks()).unwrap();
        let store = crate::image::ImageStore::new(&tgt.paths);
        assert!(store.is_complete("sha256:bb"));
        assert!(!tgt.paths.image_dir("sha256:aa").exists());
        assert!(!tgt.paths.volume_image("data").exists());
        // Never even staged.
        assert!(msgs.iter().any(|m| m.contains("sha256:bb")), "{msgs:?}");
        assert!(
            !msgs
                .iter()
                .any(|m| m.contains("sha256:aa") || m.contains("data.img")),
            "{msgs:?}"
        );
    }

    #[test]
    fn space_check_counts_an_absent_image() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        edit_manifest(&ar, |m| {
            assert!(m.image_sizes["sha256:aa"] > 0);
            m.image_sizes.insert("sha256:aa".into(), 1 << 50);
        });
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let some = |_: &Path| -> anyhow::Result<u64> { Ok(1 << 40) };
        let mut hooks = tgt.hooks();
        hooks.free_bytes = &some;
        let o = opts(ar, Some(ws));
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &hooks)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not enough free space"), "{e}");
        // Once the image is already here, it no longer counts.
        crate::bundle::testutil::add_image(&tgt.paths, "sha256:aa");
        load_with(&tgt.paths, &o, &mut |_| {}, &hooks).unwrap();
    }

    #[test]
    fn only_a_loaded_image_ref_becomes_a_local_tag() {
        let src = Src::new();
        edit_src_config(&src, "a", |c| c.image_ref = "mine".into());
        crate::image::tags::set_tag(&src.paths, "mine", "sha256:aa").unwrap();
        let ar = src.save(&["a"], false);
        edit_manifest(&ar, |m| {
            assert_eq!(m.tags.get("mine").map(String::as_str), Some("sha256:aa"));
            m.tags.insert("ubuntu".into(), "sha256:aa".into());
        });
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let rep = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks()).unwrap();
        let resolve = |t| crate::image::tags::resolve_tag(&tgt.paths, t).unwrap();
        assert_eq!(resolve("mine").as_deref(), Some("sha256:aa"));
        assert_eq!(
            resolve("ubuntu"),
            None,
            "unreferenced manifest tag was planted"
        );
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("created local image tag 'mine'")),
            "{:?}",
            rep.warnings
        );
    }

    #[test]
    fn an_existing_tag_is_never_overridden() {
        let src = Src::new();
        edit_src_config(&src, "a", |c| c.image_ref = "mine".into());
        crate::image::tags::set_tag(&src.paths, "mine", "sha256:aa").unwrap();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        crate::image::tags::set_tag(&tgt.paths, "mine", "sha256:other").unwrap();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let rep = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(
            crate::image::tags::resolve_tag(&tgt.paths, "mine")
                .unwrap()
                .as_deref(),
            Some("sha256:other")
        );
        assert!(!rep
            .warnings
            .iter()
            .any(|w| w.contains("created local image tag")));
    }

    #[test]
    fn an_incomplete_target_image_gains_only_the_metadata_it_lacks() {
        let src = Src::new();
        let src_img = src.paths.image_dir("sha256:aa");
        std::fs::write(src_img.join("passwd"), b"root:x:0:0::/root:/bin/sh\n").unwrap();
        let ar = src.save(&["a"], false);
        let incomplete = |tgt: &Tgt| {
            let img = tgt.paths.image_dir("sha256:aa");
            std::fs::create_dir_all(&img).unwrap();
            std::fs::write(img.join("rootfs.erofs"), b"legacy rootfs").unwrap();
            img
        };
        // A failed load removes exactly what it added to the entry.
        let tgt = Tgt::new();
        incomplete(&tgt);
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let o = opts(ar.clone(), Some(ws));
        let before = tgt.snapshot();
        let mut hooks = tgt.hooks();
        hooks.fail_at = Some(CommitStep::Volumes);
        load_with(&tgt.paths, &o, &mut |_| {}, &hooks).unwrap_err();
        assert_eq!(tgt.snapshot(), before);
        // A successful one completes it without touching the rootfs.
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(rep.sandboxes.len(), 1);
        let img = tgt.paths.image_dir("sha256:aa");
        assert_eq!(
            std::fs::read(img.join("rootfs.erofs")).unwrap(),
            b"legacy rootfs"
        );
        assert_eq!(
            std::fs::read(img.join("config.json")).unwrap(),
            std::fs::read(src_img.join("config.json")).unwrap()
        );
        assert_eq!(
            std::fs::read(img.join("passwd")).unwrap(),
            std::fs::read(src_img.join("passwd")).unwrap()
        );
        assert!(!img.join("group").exists());
        assert!(!img.join("ref.txt").exists());
    }

    #[test]
    fn rollback_after_the_sandbox_commit_removes_the_run_dir_owner_marker() {
        // An invalid tag makes the load fail AFTER the sandbox dir and the
        // run-dir claim were committed (tags are the last step).
        let src = Src::new();
        edit_src_config(&src, "a", |c| c.image_ref = "Not A Tag".into());
        let ar = src.save(&["a"], false);
        edit_manifest(&ar, |m| {
            m.tags.insert("Not A Tag".into(), "sha256:aa".into());
        });
        let tgt = Tgt::new();
        // A run dir left without an owner marker (pre-existing, unclaimed).
        std::fs::create_dir_all(tgt.paths.run_dir("a")).unwrap();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks()).unwrap_err();
        assert!(format!("{e:#}").contains("tag"), "{e:#}");
        assert_eq!(tgt.snapshot(), before);
        assert!(!tgt.paths.run_dir("a").join("owner").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rollback_reports_what_it_could_not_undo() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return; // root ignores the permission this relies on
        }
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("locked");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("f"), b"x").unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
        let failed = rollback(vec![
            Undo::Remove(d.join("f")),
            Undo::Remove(t.path().join("absent")),
        ]);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(failed.len(), 1, "{failed:?}");
        assert!(failed[0].contains("could not remove") && failed[0].contains("locked/f"));
    }

    #[test]
    fn corrupt_chunk_fails_checksum_and_leaves_nothing() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        let mut flipped = false;
        rewrite_archive(&o.archive, |name, mut body| {
            if name.starts_with("sandboxes/a/rw.img.d/") && !flipped {
                body[100] ^= 0xFF;
                flipped = true;
            }
            Some(body)
        });
        assert!(flipped);
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("checksum") && e.contains("sandboxes/a/rw.img"),
            "{e}"
        );
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn corrupt_plain_file_fails_checksum() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        rewrite_archive(&o.archive, |name, body| {
            Some(if name == "sandboxes/a/policy.yaml" {
                b"allow: [evil]\n".to_vec()
            } else {
                body
            })
        });
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("checksum") && e.contains("policy.yaml"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn truncated_archive_without_trailer_is_refused() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        rewrite_archive(&o.archive, |name, body| {
            (name != CHECKSUMS_PATH).then_some(body)
        });
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("truncated or corrupt"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn a_missing_disk_is_refused_even_with_a_trailer() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        rewrite_archive(&o.archive, |name, body| {
            (!name.starts_with("sandboxes/a/volumes/3.img")).then_some(body)
        });
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("sandboxes/a/volumes/3.img"), "{e}");
    }

    #[test]
    fn future_format_is_refused_before_writing_anything() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        rewrite_archive(&o.archive, |name, body| {
            if name != MANIFEST_PATH {
                return Some(body);
            }
            let mut m: serde_json::Value = serde_json::from_slice(&body).unwrap();
            m["format"] = 99.into();
            Some(serde_json::to_vec(&m).unwrap())
        });
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("newer izba"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn manifest_must_come_first() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        let mut manifest = None;
        rewrite_archive(&o.archive, |name, body| {
            if name == MANIFEST_PATH {
                manifest = Some(body);
                return None;
            }
            Some(body)
        });
        assert!(manifest.is_some());
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("manifest.json must come first"), "{e}");
    }

    #[test]
    fn entries_after_the_trailer_are_refused() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        let mut entries = read_entries(&o.archive);
        let trailer = entries.pop().unwrap();
        assert_eq!(trailer.0, CHECKSUMS_PATH);
        let ws = entries
            .iter()
            .position(|(n, _)| n.starts_with("workspaces/"))
            .unwrap();
        entries.insert(ws, trailer);
        write_entries(&o.archive, &entries);
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("after checksums.json"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn malformed_chunk_names_and_bounds_are_refused() {
        type Mutate = fn(&str) -> Option<String>;
        let cases: [(Mutate, &str); 3] = [
            // Uppercase hex offset.
            (
                |n| {
                    n.starts_with("sandboxes/a/rw.img.d/0000000000100000")
                        .then(|| n.replace("0000000000100000", "00000000001000A0"))
                },
                "malformed chunk entry",
            ),
            // Unaligned offset.
            (
                |n| {
                    n.starts_with("sandboxes/a/rw.img.d/0000000000100000")
                        .then(|| n.replace("0000000000100000", "0000000000100001"))
                },
                "malformed chunk entry",
            ),
            // Offset past the declared logical length.
            (
                |n| {
                    n.starts_with("sandboxes/a/rw.img.d/0000000000100000")
                        .then(|| n.replace("0000000000100000", "0000000001000000"))
                },
                "exceeds",
            ),
        ];
        for (mutate, want) in cases {
            let tgt = Tgt::new();
            let o = opts_bundled(&tgt);
            rename_entries(&o.archive, mutate);
            let before = tgt.snapshot();
            let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
                .unwrap_err()
                .to_string();
            assert!(e.contains(want) && e.contains("rw.img.d/"), "{want}: {e}");
            assert_eq!(tgt.snapshot(), before);
        }
    }

    #[test]
    fn a_chunk_before_its_len_marker_is_refused() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        // Rename the marker so the chunks arrive with no `.len` seen.
        rename_entries(&o.archive, |n| {
            (n == "sandboxes/a/rw.img.len").then(|| "sandboxes/a/rw.img.lex".to_string())
        });
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("rw.img"), "{e}");
        // Drop the marker entirely: the first chunk is refused by name.
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        rewrite_archive(&o.archive, |n, b| {
            (n != "sandboxes/a/rw.img.len").then_some(b)
        });
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("before its") && e.contains("rw.img.d/"), "{e}");
    }

    /// Re-encode `entries` as plain regular-file entries, in order.
    fn write_entries(archive: &Path, entries: &[(String, Vec<u8>)]) {
        let mut b = tar::Builder::new(Vec::new());
        for (n, body) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, n, &body[..]).unwrap();
        }
        let tar = b.into_inner().unwrap();
        std::fs::write(archive, zstd::encode_all(&tar[..], 3).unwrap()).unwrap();
    }

    /// Re-encode with entry names passed through `f` (`Some` = new name).
    fn rename_entries(archive: &Path, f: impl Fn(&str) -> Option<String>) {
        let entries: Vec<_> = read_entries(archive)
            .into_iter()
            .map(|(n, b)| (f(&n).unwrap_or(n), b))
            .collect();
        write_entries(archive, &entries);
    }

    #[test]
    fn not_enough_space_is_refused_up_front() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        let tiny = |_: &Path| -> anyhow::Result<u64> { Ok(1) };
        let mut hooks = tgt.hooks();
        hooks.free_bytes = &tiny;
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &hooks)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not enough free space"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn bundled_workspace_refuses_non_empty_target() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        std::fs::create_dir_all(tgt.dir("ws/a")).unwrap();
        std::fs::write(tgt.dir("ws/a/mine"), b"keep").unwrap();
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("not empty") && e.contains("--workspace"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn unbundled_workspace_must_exist() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let e = load_with(
            &tgt.paths,
            &opts(ar, Some(tgt.dir("nowhere"))),
            &mut |_| {},
            &tgt.hooks(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("does not exist") && e.contains("--workspace"),
            "{e}"
        );
        assert!(!tgt.paths.sandbox_dir("a").exists());
    }

    #[test]
    fn workspace_root_places_the_workspace_by_basename() {
        let src = Src::new();
        let ar = src.save(&["a"], true);
        let tgt = Tgt::new();
        let o = LoadOpts {
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar, None)
        };
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        // The source workspace is `<src>/ws/a`: basename "a".
        let want = tgt.dir("projects/a");
        assert!(want.join("README").is_file());
        assert_eq!(rep.sandboxes[0].workspace, want.canonicalize().unwrap());
    }

    #[test]
    fn rename_with_multiple_selected_is_refused() {
        let src = Src::new();
        add_sandbox(&src.paths, "b", "sha256:aa", &[]);
        let ar = src.save(&["a", "b"], false);
        let tgt = Tgt::new();
        let o = LoadOpts {
            rename: Some("c".into()),
            ..opts(ar.clone(), None)
        };
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("exactly one"), "{e}");
        let o = LoadOpts {
            workspace: Some(tgt.dir("x")),
            ..opts(ar.clone(), None)
        };
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("exactly one"), "{e}");
        // Selecting one of the two makes --as valid; the other is not loaded.
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let o = LoadOpts {
            select: vec!["b".into()],
            rename: Some("c".into()),
            ..opts(ar, Some(ws))
        };
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(rep.sandboxes[0].name, "c");
        assert!(!tgt.paths.sandbox_dir("a").exists());
        assert!(!tgt.paths.sandbox_dir("b").exists());
        // b has no named volume: a's "data" volume is not brought along.
        assert!(!tgt.paths.volume_image("data").exists());
    }

    #[test]
    fn unknown_selection_lists_what_the_archive_holds() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let o = LoadOpts {
            select: vec!["ghost".into()],
            ..opts(ar, None)
        };
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("'ghost'") && e.contains("available: a"), "{e}");
    }

    #[test]
    fn busy_host_ports_are_warned() {
        let src = Src::new();
        let cp = src.paths.sandbox_dir("a").join(CONFIG_FILE);
        let mut c: SandboxConfig = load_json(&cp).unwrap().unwrap();
        c.ports = vec![PortRule {
            bind: std::net::Ipv4Addr::LOCALHOST,
            host_port: 8080,
            guest_port: 80,
        }];
        crate::state::save_json(&cp, &c).unwrap();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let busy = |r: &PortRule| r.host_port == 8080;
        let mut hooks = tgt.hooks();
        hooks.port_in_use = &busy;
        let rep = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &hooks).unwrap();
        assert!(
            rep.warnings.iter().any(|w| w.contains("8080")),
            "{:?}",
            rep.warnings
        );
        let cfg: SandboxConfig = load_json(&tgt.paths.sandbox_dir("a").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.ports.len(), 1, "rules are kept");
    }

    #[test]
    fn a_config_escaping_the_data_root_is_refused() {
        // A hostile archive whose config names a named volume "../../evil".
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        rewrite_archive(&o.archive, |name, body| {
            if name != "sandboxes/a/config.json" {
                return Some(body);
            }
            let mut c: serde_json::Value = serde_json::from_slice(&body).unwrap();
            c["volumes"][0]["name"] = "../../evil".into();
            Some(serde_json::to_vec(&c).unwrap())
        });
        // Keep the checksum consistent so only the validation can refuse it.
        let entries = read_entries(&o.archive);
        let cfg = entries
            .iter()
            .find(|(n, _)| n == "sandboxes/a/config.json")
            .unwrap()
            .1
            .clone();
        rewrite_archive(&o.archive, |name, body| {
            if name != CHECKSUMS_PATH {
                return Some(body);
            }
            let mut s: Checksums = serde_json::from_slice(&body).unwrap();
            s.files.insert(
                "sandboxes/a/config.json".into(),
                hex::encode(Sha256::digest(&cfg)),
            );
            Some(serde_json::to_vec(&s).unwrap())
        });
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("evil"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }
}
