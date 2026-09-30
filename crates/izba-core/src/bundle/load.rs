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
//! volumes are reused and never touched — a volume only while no sandbox here
//! references it (single writer).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fsutil::{human_bytes, nearest_existing};
use super::manifest::{
    check_format, check_portable_rel, validate_entry_path, Checksums, Manifest, SandboxEntry,
    CHECKSUMS_PATH, MANIFEST_PATH,
};
use super::save::{EGRESS_AUDIT_FILE, IMAGE_FILES, SANDBOX_FILES};
use super::sparse::{content_digest, create_sparse, parse_chunk_entry};
use super::workspace::{is_free_target, translate_workspace, unpack_entry, DirModes};
use super::{Progress, MAX_CHUNK};
use crate::paths::Paths;
use crate::state::{load_json, save_json, PortRule, SandboxConfig, CONFIG_FILE};

/// Image files an existing-but-incomplete target cache entry may gain.
const IMAGE_META: [&str; 3] = ["config.json", "passwd", "group"];

/// Context on a bundled workspace that cannot be created where it maps to.
const PLACE_HINT: &str = "cannot place the bundled workspace there; \
                          pass --workspace <dir> or --workspace-root <dir>";

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

// reason: thin environment reader; the workspace translation it feeds is
// tested through the `LoadHooks::target_home` seam (tests never touch the
// process environment, which other threads share).
#[mutants::skip]
fn home_dir() -> anyhow::Result<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .with_context(|| format!("{var} is not set; cannot place workspaces"))
}

/// A host port is busy when binding it fails right now (the probe listener
/// is dropped at once). Only a warning is derived from it.
// reason: a bare bind probe, and unit tests never bind listeners; the
// warning derived from it is tested through the `LoadHooks::port_in_use`
// seam (busy_host_ports_are_warned).
#[mutants::skip]
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
    /// Archived tree (`workspaces/<tree>/`) holding a bundled workspace: the
    /// sandbox's own name, or its `workspace_from`. `None` = not bundled.
    ws_tree: Option<String>,
    /// Staging dir beside `ws_target` (bundled workspaces only; shared by
    /// every selected sandbox of the same tree).
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
    /// Not needed here (reused volume / unselected sandbox): chunks skipped.
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
    res.or_else(|e| {
        let failed = rollback(undo);
        if failed.is_empty() {
            return Err(e);
        }
        Err(e).with_context(|| {
            format!(
                "load failed and its rollback is incomplete: {}",
                failed.join("; ")
            )
        })
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
    let manifest = read_manifest(&mut entries)?;
    check_format(&manifest)?;
    validate_manifest(&manifest)?;
    let mut sels = select(paths, opts, &manifest, hooks)?;
    check_volume_writers(paths, &sels)?;
    check_space(paths, &manifest, &sels, hooks)?;
    let mut report = LoadReport::default();

    // ---- stage -----------------------------------------------------------
    sweep_stale_stages(paths.root());
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let run_id = format!("{}-{seq}", std::process::id());
    mkdirs(undo, paths.root(), Some(paths.root()))?;
    let stage = paths.root().join(format!(".load-{run_id}"));
    crate::paths::create_dir_700(&stage, paths.root())?;
    scratch.push(stage.clone());
    create_workspace_stages(&mut sels, &run_id, undo, scratch)?;

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
    verify_staged(&staged)?;

    // ---- configs + reuse decisions (still before any commit) -------------
    let prep = prepare(paths, &manifest, &sels, &staged, hooks, &mut report)?;

    // ---- commit ----------------------------------------------------------
    fail_at(hooks, CommitStep::Images)?;
    commit_images(paths, &prep.need_images, &stage, undo)?;
    fail_at(hooks, CommitStep::Volumes)?;
    commit_volumes(paths, &prep.need_volumes, &stage, undo)?;
    fail_at(hooks, CommitStep::Workspaces)?;
    commit_workspaces(&sels, undo)?;
    fail_at(hooks, CommitStep::Sandboxes)?;
    mkdirs(undo, &paths.sandboxes_dir(), Some(paths.root()))?;
    for (s, cfg) in sels.iter().zip(prep.configs) {
        install_sandbox(paths, s, cfg, &staged, undo, &mut report)?;
    }
    commit_tags(paths, &manifest, &prep.refs, undo, &mut report)?;
    Ok(report)
}

/// The first entry, which must be `manifest.json`, parsed.
fn read_manifest<R: Read>(entries: &mut tar::Entries<'_, R>) -> anyhow::Result<Manifest> {
    let not_izba = || anyhow::anyhow!("not an izba archive (manifest.json must come first)");
    let mut e = entries
        .next()
        .ok_or_else(not_izba)?
        .context("reading archive")?;
    if entry_name(&e)? != MANIFEST_PATH {
        return Err(not_izba());
    }
    serde_json::from_slice(&read_bounded(&mut e, MANIFEST_PATH)?).context("parsing manifest.json")
}

/// One staging dir per bundled workspace tree, beside its target (so the
/// final placement is a rename). Created owner-only: under a shared parent
/// (e.g. `/tmp`) the extracted files — possibly secrets — must not be
/// readable by other users before the tree is placed; the placed root gets
/// its ordinary mode back in `commit_workspaces`.
fn create_workspace_stages(
    sels: &mut [Sel],
    run_id: &str,
    undo: &mut Vec<Undo>,
    scratch: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    let mut tree_stages: HashMap<String, PathBuf> = HashMap::new();
    for s in sels.iter_mut() {
        let Some(tree) = s.ws_tree.clone() else {
            continue;
        };
        if let Some(stage) = tree_stages.get(&tree) {
            s.ws_stage = Some(stage.clone());
            continue;
        }
        let parent = s
            .ws_target
            .parent()
            .with_context(|| format!("workspace {} has no parent", s.ws_target.display()))?;
        mkdirs(undo, parent, None).context(PLACE_HINT)?;
        let base = s
            .ws_target
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let ws_stage = parent.join(format!(".izba-load-{run_id}-{base}"));
        create_private_dir(&ws_stage)
            .with_context(|| format!("creating {}", ws_stage.display()))
            .context(PLACE_HINT)?;
        scratch.push(ws_stage.clone());
        tree_stages.insert(tree, ws_stage.clone());
        s.ws_stage = Some(ws_stage);
    }
    Ok(())
}

/// `create_dir` with mode 0700 from the start on Unix (no chmod window).
fn create_private_dir(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(p)
    }
    #[cfg(not(unix))]
    fs::create_dir(p)
}

/// The mode a plain `create_dir` gives a new directory here (`0777 & !umask`,
/// the umask read from `/proc/self/status` — reading it via `umask(2)` would
/// briefly change it for every thread). A placed workspace root gets this, so
/// its private staging mode never outlives the load. Falls back to umask 022.
#[cfg(unix)]
fn default_dir_mode() -> u32 {
    let umask = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Umask:"))
                .and_then(|v| u32::from_str_radix(v.trim(), 8).ok())
        })
        .unwrap_or(0o022);
    0o777 & !umask
}

fn verify_staged(staged: &Staged) -> anyhow::Result<()> {
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
    Ok(())
}

/// Every selected sandbox's verified config plus what the commit must add.
struct Prepared {
    configs: Vec<SandboxConfig>,
    need_images: BTreeSet<String>,
    need_volumes: BTreeSet<String>,
    /// `(image_ref, digest)` of each loaded sandbox, for the tag step.
    refs: Vec<(String, String)>,
}

fn prepare(
    paths: &Paths,
    manifest: &Manifest,
    sels: &[Sel],
    staged: &Staged,
    hooks: &LoadHooks,
    report: &mut LoadReport,
) -> anyhow::Result<Prepared> {
    let store = crate::image::ImageStore::new(paths);
    let mut p = Prepared {
        configs: Vec::new(),
        need_images: BTreeSet::new(),
        need_volumes: BTreeSet::new(),
        refs: Vec::new(),
    };
    let mut reused = BTreeSet::new();
    for s in sels {
        let cfg = prepare_config(s, manifest, staged, hooks, report)?;
        let d = &cfg.image_digest;
        let named: BTreeSet<&String> = cfg.volumes.iter().filter_map(|v| v.name.as_ref()).collect();
        if *d != s.entry.image_digest || named != s.entry.named_volumes.iter().collect() {
            bail!(
                "archive is corrupt: config.json of '{}' disagrees with the manifest",
                s.src
            );
        }
        p.refs.push((cfg.image_ref.clone(), d.clone()));
        if image_needed(paths, &store, d, staged)? {
            p.need_images.insert(d.clone());
        }
        for v in cfg.volumes.iter().filter_map(|v| v.name.as_deref()) {
            if volume_needed(paths, v, s, staged, &mut reused, report)? {
                p.need_volumes.insert(v.to_string());
            }
        }
        p.configs.push(cfg);
    }
    Ok(p)
}

/// Whether image `d` must be installed from the archive (it is not complete
/// here); refused when neither this host nor the archive can complete it.
fn image_needed(
    paths: &Paths,
    store: &crate::image::ImageStore,
    d: &str,
    staged: &Staged,
) -> anyhow::Result<bool> {
    if store.is_complete(d) {
        return Ok(false);
    }
    let dir = paths.image_dir(d);
    let has = |f: &str| dir.join(f).is_file() || staged.files.contains_key(&image_entry(d, f));
    if has("rootfs.erofs") && has("config.json") {
        return Ok(true);
    }
    if dir.exists() {
        bail!(
            "image {d} is incomplete here and the archive cannot complete it; \
             remove {} and retry",
            dir.display()
        );
    }
    bail!("archive is missing image {d}")
}

/// Whether named volume `v` must be installed from the archive; an identical
/// one already here is reused (reported once), a different one is refused.
fn volume_needed(
    paths: &Paths,
    v: &str,
    s: &Sel,
    staged: &Staged,
    reused: &mut BTreeSet<String>,
    report: &mut LoadReport,
) -> anyhow::Result<bool> {
    let prefix = format!("volumes/{v}.img");
    let existing = paths.volume_image(v);
    let not_carried = || {
        format!(
            "archive does not carry named volume '{v}' used by '{}'",
            s.src
        )
    };
    if !existing.exists() {
        if staged.disks.contains_key(&prefix) {
            return Ok(true);
        }
        bail!("{}", not_carried());
    }
    let sums = staged.sums.as_ref().unwrap();
    let want = sums.files.get(&prefix).with_context(not_carried)?;
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
    Ok(false)
}

fn fail_at(hooks: &LoadHooks, step: CommitStep) -> anyhow::Result<()> {
    if hooks.fail_at == Some(step) {
        bail!("injected failure before commit step {step:?}");
    }
    Ok(())
}

fn commit_images(
    paths: &Paths,
    need_images: &BTreeSet<String>,
    stage: &Path,
    undo: &mut Vec<Undo>,
) -> anyhow::Result<()> {
    let store = crate::image::ImageStore::new(paths);
    for d in need_images {
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
        complete_image(&store, d, &from, undo)?;
    }
    Ok(())
}

/// Existing but incomplete image `d`: its rootfs is kept; add only the
/// verified metadata it lacks (and undo only those files).
fn complete_image(
    store: &crate::image::ImageStore,
    d: &str,
    from: &Path,
    undo: &mut Vec<Undo>,
) -> anyhow::Result<()> {
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
    Ok(())
}

fn commit_volumes(
    paths: &Paths,
    need_volumes: &BTreeSet<String>,
    stage: &Path,
    undo: &mut Vec<Undo>,
) -> anyhow::Result<()> {
    for v in need_volumes {
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
    Ok(())
}

fn commit_workspaces(sels: &[Sel], undo: &mut Vec<Undo>) -> anyhow::Result<()> {
    let mut placed = BTreeSet::new();
    for s in sels {
        let Some(ws_stage) = &s.ws_stage else {
            continue;
        };
        if !placed.insert(ws_stage) {
            continue; // a shared tree, already placed for an earlier sharer
        }
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
        fs::rename(ws_stage, t)
            .with_context(|| format!("placing workspace {}", t.display()))
            .context(PLACE_HINT)?;
        undo.push(Undo::Remove(t.clone()));
        // The stage was private; the placed root gets what a fresh dir would.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(t, fs::Permissions::from_mode(default_dir_mode()))
                .with_context(|| format!("setting the mode of {}", t.display()))?;
        }
        crate::procmgr::ensure_confinable(t)?;
    }
    Ok(())
}

/// Creates the sandbox dir (exclusively: a concurrent create/load of the
/// same name loses here), claims its run dir and installs its staged files.
fn install_sandbox(
    paths: &Paths,
    s: &Sel,
    mut cfg: SandboxConfig,
    staged: &Staged,
    undo: &mut Vec<Undo>,
    report: &mut LoadReport,
) -> anyhow::Result<()> {
    let dir = paths.sandbox_dir(&s.name);
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => bail!("{}", exists_msg(&s.name)),
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    undo.push(Undo::Remove(dir.clone()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    crate::paths::create_dir_700(&paths.logs_dir(&s.name), paths.root())?;
    claim_run_dir(paths, &s.name, undo)?;
    cfg.workspace = s
        .ws_target
        .canonicalize()
        .with_context(|| format!("resolving workspace {}", s.ws_target.display()))?;
    save_json(&dir.join(CONFIG_FILE), &cfg)?;
    install_sandbox_files(paths, s, &dir, staged)?;
    // The workspace's izba.yml still names the sandbox it was saved as
    // (metadata.name, or the dir basename by default): diff/promote there
    // would resolve to that name, not the one this load created.
    if s.name != s.src && cfg.workspace.join("izba.yml").is_file() {
        report.warnings.push(format!(
            "sandbox '{}' was loaded as '{}': izba diff/promote in {} will resolve to \
             '{}' — update metadata.name in izba.yml or pass --name {}",
            s.src,
            s.name,
            cfg.workspace.display(),
            s.src,
            s.name
        ));
    }
    report.sandboxes.push(LoadedSandbox {
        name: s.name.clone(),
        image_ref: cfg.image_ref.clone(),
        workspace: cfg.workspace,
    });
    Ok(())
}

/// `sandbox::claim_run_dir`, recording exactly what it created for undo.
fn claim_run_dir(paths: &Paths, name: &str, undo: &mut Vec<Undo>) -> anyhow::Result<()> {
    let run = paths.run_dir(name);
    let run_top = std::iter::successors(Some(run.as_path()), |p| p.parent())
        .take_while(|p| !p.exists())
        .last()
        .map(Path::to_path_buf);
    let marker = run.join(crate::sandbox::RUN_DIR_OWNER);
    let marker_existed = marker.exists();
    crate::sandbox::claim_run_dir(paths, name)?;
    match run_top {
        Some(t) => undo.push(Undo::Remove(t)),
        // A pre-existing run dir (e.g. left behind by an `rm`): undo only
        // the owner marker this claim wrote.
        None if !marker_existed => undo.push(Undo::Remove(marker)),
        None => {}
    }
    Ok(())
}

/// Moves the sandbox's staged files and disks (all but `config.json`,
/// rewritten by the caller) into `dir`; the egress audit log goes to logs/.
fn install_sandbox_files(
    paths: &Paths,
    s: &Sel,
    dir: &Path,
    staged: &Staged,
) -> anyhow::Result<()> {
    let prefix = format!("sandboxes/{}/", s.src);
    let files = staged.files.iter().map(|(p, (path, _))| (p, path));
    for (p, from) in files.chain(staged.disks.iter()) {
        let Some(rel) = p.strip_prefix(&prefix) else {
            continue;
        };
        if rel == CONFIG_FILE {
            continue;
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
    Ok(())
}

/// Tags last. Only a loaded sandbox's own `image_ref`, mapped by the
/// archive to that sandbox's digest, and only when it does not resolve
/// here: an archive can never plant a tag that shadows an unrelated
/// (e.g. bare registry) name. Every tag created is reported.
fn commit_tags(
    paths: &Paths,
    manifest: &Manifest,
    refs: &[(String, String)],
    undo: &mut Vec<Undo>,
    report: &mut LoadReport,
) -> anyhow::Result<()> {
    let mut tags_saved = false;
    let mut seen = BTreeSet::new();
    for (tag, digest) in refs {
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
    Ok(())
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
        validate_disks(s)?;
        validate_workspace_from(m, s)?;
        validate_references(m, s)?;
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

/// A sandbox's disks are its own `rw.img` (mandatory) and anonymous volumes.
fn validate_disks(s: &SandboxEntry) -> anyhow::Result<()> {
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
    // Every sandbox has a writable layer; without it the staged-disk
    // completeness check would have nothing to demand.
    let rw = format!("{own}rw.img");
    if !s.disks.iter().any(|d| d.path == rw) {
        bail!(
            "archive is corrupt: sandbox '{}' lists no disk {rw}",
            s.name
        );
    }
    Ok(())
}

/// The owner named by `workspace_from` holds the tree and must describe the
/// SAME source dir: every sharer then maps to the owner's one restore target.
fn validate_workspace_from(m: &Manifest, s: &SandboxEntry) -> anyhow::Result<()> {
    let Some(from) = &s.workspace_from else {
        return Ok(());
    };
    let owner = m.sandboxes.iter().find(|o| &o.name == from);
    let ok = s.workspace_bundled
        && owner.is_some_and(|o| {
            o.name != s.name
                && o.workspace_bundled
                && o.workspace_from.is_none()
                && o.source_workspace == s.source_workspace
        });
    if !ok {
        bail!(
            "archive is corrupt: sandbox '{}' takes its workspace from {from:?}, \
             which holds no matching bundled workspace",
            s.name
        );
    }
    Ok(())
}

/// The image and named volumes a sandbox entry names are in the archive.
fn validate_references(m: &Manifest, s: &SandboxEntry) -> anyhow::Result<()> {
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
        let ws_tree = e
            .workspace_bundled
            .then(|| e.workspace_from.clone().unwrap_or_else(|| e.name.clone()));
        if e.workspace_bundled {
            if !is_free_target(&target) {
                bail!(
                    "workspace target {} is not empty; pass --workspace <empty-or-new dir>",
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
        check_target_collision(&sels, e, &name, &target, ws_tree.as_deref())?;
        sels.push(Sel {
            src: e.name.clone(),
            name,
            entry: e.clone(),
            ws_target: target,
            ws_tree,
            ws_stage: None,
        });
    }
    Ok(sels)
}

/// A bundled tree may only land on a dir no other selected sandbox resolves
/// to — bundled or not — unless both describe the SAME source workspace
/// (sharers restore one tree, once, together; an unbundled sharer then uses
/// it). Otherwise the load would bind a sandbox to another one's files.
fn check_target_collision(
    sels: &[Sel],
    e: &SandboxEntry,
    name: &str,
    target: &Path,
    ws_tree: Option<&str>,
) -> anyhow::Result<()> {
    let clash = sels.iter().find(|s| {
        s.ws_target == target
            && (ws_tree.is_some() || s.ws_tree.is_some())
            && match (ws_tree, s.ws_tree.as_deref()) {
                (Some(a), Some(b)) => a != b,
                _ => s.entry.source_workspace != e.source_workspace,
            }
    });
    if let Some(other) = clash {
        bail!(
            "two sandboxes would use workspace {} ('{}' and '{name}' were saved from different \
             workspaces); load them one at a time with --workspace <dir>",
            target.display(),
            other.name
        );
    }
    Ok(())
}

/// The single-writer invariant (`sandbox::ensure_volume_not_shared`): a
/// named volume may be bound to at most one sandbox config on this host —
/// so also to at most one sandbox of the selection. A loaded sandbox may reuse an identical volume only while NO existing
/// sandbox here references it — otherwise the load would bind it twice.
fn check_volume_writers(paths: &Paths, sels: &[Sel]) -> anyhow::Result<()> {
    // Two sandboxes of this very load binding one volume break it just the
    // same: once one runs, the other can never start.
    let mut first: HashMap<&str, &str> = HashMap::new();
    for s in sels {
        for v in &s.entry.named_volumes {
            if let Some(other) = first.insert(v, &s.name) {
                bail!(
                    "named volume '{v}' is used by both '{other}' and '{}' in this archive (a \
                     named volume has a single writer); load them one at a time by naming \
                     one of them",
                    s.name
                );
            }
        }
    }
    let (_, volumes) = selection_needs(sels);
    for v in &volumes {
        if let Some(other) = crate::sandbox::volume_referrers(paths, v)?.first() {
            bail!(
                "named volume '{v}' is already in use by sandbox '{other}' here (a named \
                 volume has a single writer); remove that sandbox or detach the volume \
                 there first"
            );
        }
    }
    Ok(())
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
    let mut counted = BTreeSet::new();
    for s in sels.iter().filter(|s| s.ws_tree.is_some()) {
        if !counted.insert(&s.ws_tree) {
            continue; // a shared tree is restored (and needs room) once
        }
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
    /// Source names of the selected sandboxes.
    selected: HashSet<String>,
    /// Archived workspace tree name -> its stage (trees the selection uses).
    ws_trees: HashMap<String, PathBuf>,
    known_disks: HashMap<String, (DiskKind, u64)>,
    /// image dir name -> digest.
    image_dirs: HashMap<String, String>,
    /// What the selection uses; everything else is skipped unstaged.
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
            selected: sels.iter().map(|s| s.src.clone()).collect(),
            ws_trees: sels
                .iter()
                .filter_map(|s| Some((s.ws_tree.clone()?, s.ws_stage.clone()?)))
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
            // An entry left unread is skipped by the tar reader when the next
            // one is requested: not staging it is all it takes to drop it.
            if !self.selected.contains(src) {
                return Ok(());
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
            return Ok(()); // unused here, or the target's copy is kept
        }
        let target = self.paths.image_dir(digest);
        // An incomplete target entry (#222: rootfs without config.json) keeps
        // its rootfs; only the metadata it lacks is taken from the archive.
        if target.exists() && (!IMAGE_META.contains(&file) || target.join(file).exists()) {
            return Ok(());
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
            DiskKind::Sandbox(src) => self.selected.contains(src),
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
            DiskState::Skip { .. } => Ok(()),
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
        // Only a tree owner has entries; a sharer's workspace is its owner's.
        if !entry.workspace_bundled || entry.workspace_from.is_some() || rel.is_empty() {
            bail!("unexpected archive entry {p}");
        }
        let Some(ws_stage) = self.ws_trees.get(src) else {
            return Ok(());
        };
        // A Windows host cannot recreate every name another OS can hold
        // (`a:b` would write an alternate data stream, `con` the console
        // device); save refuses them already, a crafted archive is refused here.
        if cfg!(windows) {
            check_portable_rel(rel)
                .with_context(|| format!("workspace entry {p} cannot be restored on this host"))?;
        }
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
            .filter(|s| self.selected.contains(&s.name))
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

    #[cfg(unix)]
    #[test]
    fn a_bundled_directory_symlink_loads_as_a_symlink() {
        let src = Src::new();
        let ws = crate::bundle::testutil::workspace_of(&src.paths, "a");
        std::fs::create_dir(ws.join("sub")).unwrap();
        std::os::unix::fs::symlink("sub", ws.join("dlink")).unwrap();
        let tgt = Tgt::new();
        let ar = tgt.dir("in.izba");
        src.save_to(&["a"], true, &ar);
        load_with(
            &tgt.paths,
            &opts(ar, Some(tgt.dir("ws/a"))),
            &mut |_| {},
            &tgt.hooks(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_link(tgt.dir("ws/a/dlink")).unwrap(),
            PathBuf::from("sub")
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unplaceable_bundled_workspace_hints_at_the_flags() {
        use std::os::unix::fs::PermissionsExt;
        if nix::unistd::geteuid().is_root() {
            return; // root ignores the permission this relies on
        }
        let tgt = Tgt::new();
        let mut o = opts_bundled(&tgt);
        let ro = tgt.dir("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        o.workspace = Some(ro.join("deeper/ws"));
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap_err();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        let msg = format!("{e:#}");
        assert!(
            msg.contains("pass --workspace <dir> or --workspace-root <dir>"),
            "{msg}"
        );
        assert_eq!(tgt.snapshot(), before);
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
        // `a` now holds the named volume "data": a second copy loaded next to
        // it would share it (single-writer), so --as is refused until `a` goes.
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &renamed, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("named volume 'data'") && e.contains("already in use by sandbox 'a'"),
            "{e}"
        );
        assert_eq!(tgt.snapshot(), before);
        std::fs::remove_dir_all(tgt.paths.sandbox_dir("a")).unwrap();
        let rep = load_with(&tgt.paths, &renamed, &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(rep.sandboxes[0].name, "b");
        for (s, t) in src.disk_pairs("a", "b", &tgt.paths) {
            assert_eq!(std::fs::read(&s).unwrap(), std::fs::read(&t).unwrap());
        }
        assert!(tgt.paths.run_dir("b").join("owner").is_file());
        assert!(no_stage_left(&tgt));
    }

    #[test]
    fn a_renamed_load_warns_about_a_workspace_izba_yml() {
        let src = Src::new();
        let ws = crate::bundle::testutil::workspace_of(&src.paths, "a");
        std::fs::write(ws.join("izba.yml"), b"metadata:\n  name: a\n").unwrap();
        let tgt = Tgt::new();
        let ar = tgt.dir("in.izba");
        src.save_to(&["a"], true, &ar);
        let renamed = LoadOpts {
            rename: Some("b".into()),
            ..opts(ar.clone(), Some(tgt.dir("ws/b")))
        };
        let rep = load_with(&tgt.paths, &renamed, &mut |_| {}, &tgt.hooks()).unwrap();
        let w: Vec<_> = rep
            .warnings
            .iter()
            .filter(|w| w.contains("izba.yml"))
            .collect();
        assert_eq!(w.len(), 1, "{:?}", rep.warnings);
        assert!(
            w[0].contains("resolve to 'a'")
                && w[0].contains("metadata.name")
                && w[0].contains("--name"),
            "{}",
            w[0]
        );
        // Not renamed: nothing to warn about.
        std::fs::remove_dir_all(tgt.paths.sandbox_dir("b")).unwrap();
        let plain = opts(ar, Some(tgt.dir("ws/a")));
        let rep = load_with(&tgt.paths, &plain, &mut |_| {}, &tgt.hooks()).unwrap();
        assert!(
            !rep.warnings.iter().any(|w| w.contains("izba.yml")),
            "{:?}",
            rep.warnings
        );
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
    fn an_identical_named_volume_used_by_a_target_sandbox_is_refused() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        // Same bytes as the source's "data", but already bound to "other".
        add_sandbox(&tgt.paths, "other", "sha256:aa", &[("data", "/data")]);
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("named volume 'data'") && e.contains("already in use by sandbox 'other'"),
            "{e}"
        );
        assert!(!tgt.paths.sandbox_dir("a").exists());
        assert_eq!(tgt.snapshot(), before);
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
        // A successful one completes it without touching the rootfs, and
        // stages only the metadata files the entry lacks.
        let mut msgs = Vec::new();
        let rep = load_with(&tgt.paths, &o, &mut |m| msgs.push(m), &tgt.hooks()).unwrap();
        assert_eq!(rep.sandboxes.len(), 1);
        let staged: Vec<_> = msgs
            .iter()
            .filter(|m| m.starts_with("staging image"))
            .collect();
        assert_eq!(
            staged,
            [
                "staging image sha256:aa (config.json)",
                "staging image sha256:aa (passwd)"
            ],
            "{msgs:?}"
        );
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
    fn a_manifest_without_the_rw_disk_is_refused() {
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        edit_manifest(&o.archive, |m| {
            m.sandboxes[0]
                .disks
                .retain(|d| !d.path.ends_with("/rw.img"));
        });
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        // Refused by the manifest preflight, not later by the stray entry.
        assert!(e.contains("lists no disk sandboxes/a/rw.img"), "{e}");
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

    /// Source with "a" (the Src fixture) plus "b", whose config points at
    /// `b_workspace(src)` instead of its own workspace.
    fn src_with_b(b_workspace: impl FnOnce(&Src) -> PathBuf) -> Src {
        let src = Src::new();
        add_sandbox(&src.paths, "b", "sha256:aa", &[]);
        let ws = b_workspace(&src);
        std::fs::create_dir_all(&ws).unwrap();
        edit_src_config(&src, "b", |c| c.workspace = ws);
        src
    }

    fn shared(src: &Src) -> PathBuf {
        crate::bundle::testutil::workspace_of(&src.paths, "a")
    }

    #[test]
    fn a_shared_bundled_workspace_is_restored_once_for_every_sharer() {
        let src = src_with_b(shared);
        let ar = src.save(&["a", "b"], true);
        let tgt = Tgt::new();
        let o = LoadOpts {
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar.clone(), None)
        };
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        let want = tgt.dir("projects/a").canonicalize().unwrap();
        assert_eq!(std::fs::read(want.join("README")).unwrap(), b"hello");
        assert_eq!(
            rep.sandboxes
                .iter()
                .map(|s| (s.name.as_str(), s.workspace.clone()))
                .collect::<Vec<_>>(),
            vec![("a", want.clone()), ("b", want.clone())]
        );
        assert!(no_stage_left(&tgt));
        // Only the sharer: its workspace comes from the owner's tree.
        let tgt = Tgt::new();
        let o = LoadOpts {
            select: vec!["b".into()],
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar, None)
        };
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        let want = tgt.dir("projects/a").canonicalize().unwrap();
        assert_eq!(rep.sandboxes[0].workspace, want);
        assert_eq!(std::fs::read(want.join("README")).unwrap(), b"hello");
        assert!(!tgt.paths.sandbox_dir("a").exists());
    }

    #[test]
    fn different_workspaces_mapping_to_one_target_are_still_refused() {
        // b's own workspace is `<src>/other/a`: same basename as a's.
        let src = src_with_b(|s| s.t.path().join("other/a"));
        let ar = src.save(&["a", "b"], true);
        let tgt = Tgt::new();
        let o = LoadOpts {
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar, None)
        };
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("two sandboxes would use workspace"), "{e}");
    }

    #[test]
    fn a_shared_unbundled_workspace_binds_both_sandboxes() {
        let src = src_with_b(shared);
        let ar = src.save(&["a", "b"], false);
        let tgt = Tgt::new();
        std::fs::create_dir_all(tgt.dir("projects/a")).unwrap();
        let o = LoadOpts {
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar, None)
        };
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        let want = tgt.dir("projects/a").canonicalize().unwrap();
        assert!(rep.sandboxes.iter().all(|s| s.workspace == want), "{rep:?}");
    }

    /// Archive of "a" + "b" (b's config from `b_workspace`) saved WITH
    /// workspaces, then rewritten so `unbundled` is not bundled (its tree, if
    /// any, dropped): a mixed selection only a crafted manifest can express.
    fn mixed_archive(b_workspace: impl FnOnce(&Src) -> PathBuf, unbundled: &str) -> (Src, PathBuf) {
        let src = src_with_b(b_workspace);
        let ar = src.save(&["a", "b"], true);
        let tree = format!("workspaces/{unbundled}/");
        rewrite_archive(&ar, |n, b| (!n.starts_with(&tree)).then_some(b));
        edit_manifest(&ar, |m| {
            let e = m
                .sandboxes
                .iter_mut()
                .find(|s| s.name == unbundled)
                .unwrap();
            e.workspace_bundled = false;
            e.workspace_from = None;
            e.workspace_bytes = 0;
        });
        (src, ar)
    }

    #[test]
    fn a_bundled_workspace_may_not_land_where_an_unbundled_sandbox_resolves() {
        // b's own workspace is `<src>/other/a`: same basename as a's, so with
        // --workspace-root both resolve to `projects/a` — an EMPTY existing
        // dir, which is both a free bundled target and an existing unbundled one.
        for unbundled in ["b", "a"] {
            let (_src, ar) = mixed_archive(|s| s.t.path().join("other/a"), unbundled);
            let tgt = Tgt::new();
            std::fs::create_dir_all(tgt.dir("projects/a")).unwrap();
            let o = LoadOpts {
                workspace_root: Some(tgt.dir("projects")),
                ..opts(ar, None)
            };
            let before = tgt.snapshot();
            let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("two sandboxes would") && e.contains("'a'") && e.contains("'b'"),
                "{unbundled}: {e}"
            );
            assert_eq!(tgt.snapshot(), before, "{unbundled}");
        }
    }

    #[test]
    fn an_unbundled_sharer_of_a_bundled_workspace_is_still_allowed() {
        let (_src, ar) = mixed_archive(shared, "b");
        let tgt = Tgt::new();
        std::fs::create_dir_all(tgt.dir("projects/a")).unwrap();
        let o = LoadOpts {
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar, None)
        };
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        let want = tgt.dir("projects/a").canonicalize().unwrap();
        assert_eq!(std::fs::read(want.join("README")).unwrap(), b"hello");
        assert!(rep.sandboxes.iter().all(|s| s.workspace == want), "{rep:?}");
    }

    #[test]
    fn a_named_volume_shared_by_two_selected_sandboxes_is_refused() {
        let src = Src::new();
        add_sandbox(&src.paths, "b", "sha256:aa", &[("data", "/data")]);
        let ar = src.save(&["a", "b"], false);
        let tgt = Tgt::new();
        for n in ["a", "b"] {
            std::fs::create_dir_all(tgt.dir(&format!("projects/{n}"))).unwrap();
        }
        let o = LoadOpts {
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar.clone(), None)
        };
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("named volume 'data'") && e.contains("'a'") && e.contains("'b'"),
            "{e}"
        );
        assert_eq!(tgt.snapshot(), before);
        // One of them alone is fine.
        let o = LoadOpts {
            select: vec!["b".into()],
            workspace_root: Some(tgt.dir("projects")),
            ..opts(ar, None)
        };
        load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        assert!(tgt.paths.volume_image("data").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_bundled_workspace_is_staged_privately_and_placed_with_the_default_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let tgt = Tgt::new();
        let o = opts_bundled(&tgt);
        let mut stage_modes = Vec::new();
        load_with(
            &tgt.paths,
            &o,
            &mut |_| {
                let Ok(rd) = std::fs::read_dir(tgt.dir("ws")) else {
                    return;
                };
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().starts_with(".izba-load-") {
                        stage_modes.push(mode(&e.path()));
                    }
                }
            },
            &tgt.hooks(),
        )
        .unwrap();
        assert!(!stage_modes.is_empty());
        assert!(stage_modes.iter().all(|m| *m == 0o700), "{stage_modes:?}");
        // The placed root ends with what a plain new directory gets here.
        let probe = tgt.dir("probe");
        std::fs::create_dir(&probe).unwrap();
        assert_eq!(mode(&tgt.dir("ws/a")), mode(&probe));
    }

    #[test]
    fn a_bad_workspace_from_is_refused() {
        let src = src_with_b(shared);
        let ar = src.save(&["a", "b"], true);
        type Edit = fn(&mut Manifest);
        let cases: [Edit; 4] = [
            |m| m.sandboxes[1].workspace_from = Some("ghost".into()),
            |m| m.sandboxes[1].workspace_from = Some("b".into()),
            |m| m.sandboxes[0].workspace_bundled = false,
            |m| m.sandboxes[1].source_workspace = "/elsewhere".into(),
        ];
        for edit in cases {
            let tgt = Tgt::new();
            let copy = tgt.dir("in.izba");
            std::fs::copy(&ar, &copy).unwrap();
            edit_manifest(&copy, edit);
            let o = LoadOpts {
                workspace_root: Some(tgt.dir("projects")),
                ..opts(copy, None)
            };
            let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks())
                .unwrap_err()
                .to_string();
            // Refused by the manifest preflight itself, not by a later step.
            assert!(e.contains("takes its workspace from"), "{e}");
            assert!(!tgt.paths.sandbox_dir("b").exists());
        }
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

    // ---- direct tests of the preflight / commit helpers --------------------

    use crate::bundle::manifest::{BlobInfo, SourceOs};
    use crate::bundle::testutil::add_image;

    fn blob(path: &str, allocated: u64) -> BlobInfo {
        BlobInfo {
            path: path.into(),
            logical_len: allocated,
            allocated,
        }
    }

    /// Sandbox entry `name` on image `sha256:aa`, its `rw.img` allocating
    /// 1000 bytes, from source workspace `/src/ws`.
    fn entry(name: &str) -> SandboxEntry {
        SandboxEntry {
            name: name.into(),
            image_digest: "sha256:aa".into(),
            named_volumes: vec![],
            disk_owner: (1000, 1000),
            workspace_bundled: false,
            workspace_from: None,
            source_workspace: "/src/ws".into(),
            source_home: None,
            disks: vec![blob(&format!("sandboxes/{name}/rw.img"), 1000)],
            workspace_bytes: 0,
            locked: false,
        }
    }

    fn manifest(sandboxes: Vec<SandboxEntry>) -> Manifest {
        Manifest {
            format: crate::bundle::FORMAT_VERSION,
            izba_version: "t".into(),
            source_os: SourceOs::current(),
            created_unix_ms: 0,
            tags: Default::default(),
            images: vec!["sha256:aa".into()],
            image_sizes: Default::default(),
            named_volumes: vec![],
            sandboxes,
        }
    }

    fn sel(e: SandboxEntry, ws_target: PathBuf, ws_tree: Option<&str>) -> Sel {
        Sel {
            src: e.name.clone(),
            name: e.name.clone(),
            entry: e,
            ws_target,
            ws_tree: ws_tree.map(Into::into),
            ws_stage: None,
        }
    }

    fn no_staged() -> Staged {
        Staged {
            files: BTreeMap::new(),
            disks: BTreeMap::new(),
            sums: None,
        }
    }

    #[test]
    fn removing_an_absent_file_is_done_not_an_error() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("f");
        remove_file_if_present(&p).unwrap();
        std::fs::write(&p, b"x").unwrap();
        remove_file_if_present(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn valid_digest_is_alg_colon_hex_in_lowercase_alphanumerics() {
        assert!(valid_digest("sha256:ab12"));
        for bad in [
            "",
            "sha256",
            "sha256:",
            ":ab",
            "SHA256:ab",
            "sha256:AB",
            "sha256:a-b",
            "sha256:a/b",
        ] {
            assert!(!valid_digest(bad), "{bad}");
        }
    }

    #[test]
    fn validate_disks_accepts_only_rw_and_numbered_anonymous_volumes() {
        let mut e = entry("a");
        e.disks.push(blob("sandboxes/a/volumes/3.img", 1));
        validate_disks(&e).unwrap();
        for bad in [
            "sandboxes/a/volumes/.img",
            "sandboxes/a/volumes/x.img",
            "sandboxes/a/volumes/1a.img",
            "sandboxes/b/rw.img",
        ] {
            let mut e = entry("a");
            e.disks.push(blob(bad, 1));
            let err = validate_disks(&e).unwrap_err().to_string();
            assert!(err.contains("unexpected disk"), "{bad}: {err}");
        }
    }

    #[test]
    fn workspace_from_must_name_a_matching_bundled_owner() {
        let owner = || SandboxEntry {
            workspace_bundled: true,
            ..entry("a")
        };
        let sharer = || SandboxEntry {
            workspace_bundled: true,
            workspace_from: Some("a".into()),
            ..entry("b")
        };
        validate_workspace_from(&manifest(vec![owner(), sharer()]), &sharer()).unwrap();
        type Case = fn(&mut SandboxEntry, &mut SandboxEntry);
        let cases: [(&str, Case); 6] = [
            ("sharer not bundled", |_, b| b.workspace_bundled = false),
            ("owner not bundled", |a, _| a.workspace_bundled = false),
            ("owner itself a sharer", |a, _| {
                a.workspace_from = Some("c".into())
            }),
            ("different source", |a, _| {
                a.source_workspace = "/other".into()
            }),
            ("self reference", |_, b| b.workspace_from = Some("b".into())),
            ("no such owner", |_, b| {
                b.workspace_from = Some("ghost".into())
            }),
        ];
        for (what, edit) in cases {
            let (mut a, mut b) = (owner(), sharer());
            edit(&mut a, &mut b);
            let e = validate_workspace_from(&manifest(vec![a, b.clone()]), &b)
                .unwrap_err()
                .to_string();
            assert!(e.contains("takes its workspace from"), "{what}: {e}");
        }
    }

    #[test]
    fn a_sandbox_may_only_reference_what_the_archive_carries() {
        let mut m = manifest(vec![]);
        m.named_volumes.push(blob("volumes/data.img", 1));
        let mut e = entry("a");
        e.named_volumes = vec!["data".into()];
        validate_references(&m, &e).unwrap();
        let mut ghost_vol = e.clone();
        ghost_vol.named_volumes = vec!["ghost".into()];
        let err = validate_references(&m, &ghost_vol).unwrap_err().to_string();
        assert!(err.contains("named volume \"ghost\""), "{err}");
        let mut ghost_img = e;
        ghost_img.image_digest = "sha256:bb".into();
        let err = validate_references(&m, &ghost_img).unwrap_err().to_string();
        assert!(err.contains("sha256:bb"), "{err}");
    }

    #[test]
    fn source_basename_is_one_plain_component() {
        assert_eq!(source_basename("/a/b"), Some("b"));
        assert_eq!(source_basename("/a/b/"), Some("b"));
        assert_eq!(source_basename(r"C:\x\y"), Some("y"));
        for bad in ["", "/", "/a/.", "/a/..", "/a/b:c", r"C:\"] {
            assert_eq!(source_basename(bad), None, "{bad}");
        }
    }

    #[test]
    fn two_bundled_trees_never_share_a_target_even_from_one_source() {
        let t = PathBuf::from("/t/ws");
        let sels = vec![sel(entry("a"), t.clone(), Some("a"))];
        // Same source dir, but two separately archived trees: refused.
        let e = check_target_collision(&sels, &entry("b"), "b", &t, Some("b"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("two sandboxes would use workspace"), "{e}");
        // The same tree (a sharer) lands there together with its owner.
        check_target_collision(&sels, &entry("b"), "b", &t, Some("a")).unwrap();
    }

    #[test]
    fn a_repeated_selection_loads_the_sandbox_once() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let o = LoadOpts {
            select: vec!["a".into(), "a".into()],
            ..opts(ar, Some(ws))
        };
        let rep = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap();
        assert_eq!(rep.sandboxes.len(), 1);
    }

    /// `check_space` with `free_root` bytes free on the data root's
    /// filesystem and `free_ws` everywhere else.
    fn space(tgt: &Tgt, m: &Manifest, sels: &[Sel], free_root: u64, free_ws: u64) -> bool {
        let root = nearest_existing(tgt.paths.root()).unwrap();
        let free = move |d: &Path| -> anyhow::Result<u64> {
            Ok(if d == root { free_root } else { free_ws })
        };
        let mut hooks = tgt.hooks();
        hooks.free_bytes = &free;
        match check_space(&tgt.paths, m, sels, &hooks) {
            Ok(()) => true,
            Err(e) => {
                assert!(e.to_string().contains("not enough free space"), "{e}");
                false
            }
        }
    }

    #[test]
    fn space_check_asks_exactly_the_missing_data_plus_five_percent() {
        let tgt = Tgt::new();
        let mut a = entry("a");
        a.named_volumes = vec!["data".into()];
        let mut m = manifest(vec![a.clone()]);
        // `other` is not used by the selection: never counted.
        m.named_volumes = vec![
            blob("volumes/data.img", 1000),
            blob("volumes/other.img", 1 << 30),
        ];
        let sels = [sel(a, tgt.dir("ws/a"), None)];
        // rw.img 1000 + volume 1000 = 2000, +5% = 2100.
        assert!(space(&tgt, &m, &sels, 2100, 0));
        assert!(!space(&tgt, &m, &sels, 2099, 0));
        // A volume already on this host is reused, not counted: 1050.
        crate::bundle::testutil::write_sparse_disk(&tgt.paths.volume_image("data"), 1);
        assert!(space(&tgt, &m, &sels, 1050, 0));
        assert!(!space(&tgt, &m, &sels, 1049, 0));
    }

    #[test]
    fn space_check_counts_a_bundled_tree_once_on_its_target_filesystem() {
        let tgt = Tgt::new();
        let bundled = |name: &str| SandboxEntry {
            workspace_bundled: true,
            workspace_bytes: 500,
            ..entry(name)
        };
        let m = manifest(vec![bundled("a"), bundled("b")]);
        let one = [sel(bundled("a"), tgt.dir("ws/a"), Some("a"))];
        // 500 +5% = 525 on the workspace's filesystem.
        assert!(space(&tgt, &m, &one, u64::MAX, 525));
        assert!(!space(&tgt, &m, &one, u64::MAX, 524));
        // A second sharer of the same tree needs no more room.
        let two = [
            sel(bundled("a"), tgt.dir("ws/a"), Some("a")),
            sel(bundled("b"), tgt.dir("ws/a"), Some("a")),
        ];
        assert!(space(&tgt, &m, &two, u64::MAX, 525));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_stage_dirs_of_dead_processes_are_swept() {
        let t = tempfile::tempdir().unwrap();
        // Above any pid_max: never a live process.
        let dead = t.path().join(".load-4000000000-0");
        let live = t.path().join(format!(".load-{}-0", std::process::id()));
        let other = t.path().join("sandboxes");
        let odd = t.path().join(".load-x-0");
        for d in [&dead, &live, &other, &odd] {
            std::fs::create_dir_all(d.join("sub")).unwrap();
        }
        sweep_stale_stages(t.path());
        assert!(!dead.exists());
        assert!(live.exists() && other.exists() && odd.exists());
    }

    #[test]
    fn read_bounded_takes_up_to_the_cap_and_refuses_one_byte_more() {
        let v = read_bounded(&mut std::io::repeat(b'x').take(MAX_JSON), "m").unwrap();
        assert_eq!(v.len() as u64, MAX_JSON);
        let e = read_bounded(&mut std::io::repeat(b'x').take(MAX_JSON + 1), "m")
            .unwrap_err()
            .to_string();
        assert!(e.contains("implausibly large"), "{e}");
    }

    #[test]
    fn chunk_sizes_and_bounds_are_enforced() {
        use crate::bundle::sparse::chunk_entry_name;
        use crate::bundle::ZERO_BLOCK;
        let tgt = Tgt::new();
        let m = manifest(vec![]);
        let mut st = Stager::new(&tgt.paths, &m, &[], tgt.dir("stage"));
        st.disks
            .insert("d".into(), DiskState::Skip { len: 2 * MAX_CHUNK });
        let feed = |st: &mut Stager<'_>, off: u64, size: u64| {
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(size);
            h.set_mode(0o600);
            h.set_cksum();
            b.append_data(
                &mut h,
                chunk_entry_name("d", off),
                std::io::repeat(0).take(size),
            )
            .unwrap();
            let buf = b.into_inner().unwrap();
            let mut ar = tar::Archive::new(&buf[..]);
            let mut e = ar.entries().unwrap().next().unwrap().unwrap();
            let p = entry_name(&e).unwrap();
            st.chunk(&mut e, &p).map_err(|e| e.to_string())
        };
        feed(&mut st, 0, MAX_CHUNK).unwrap();
        feed(&mut st, MAX_CHUNK, MAX_CHUNK).unwrap(); // ends exactly at len
        for (off, size) in [
            (0, 0),
            (0, MAX_CHUNK + 1),
            (MAX_CHUNK + ZERO_BLOCK, MAX_CHUNK),
        ] {
            let e = feed(&mut st, off, size).unwrap_err();
            assert!(e.contains("exceeds"), "{off}+{size}: {e}");
        }
    }

    #[test]
    fn an_existing_image_config_is_never_replaced() {
        let tgt = Tgt::new();
        add_image(&tgt.paths, "sha256:aa");
        let store = crate::image::ImageStore::new(&tgt.paths);
        let before = std::fs::read(store.config_path("sha256:aa")).unwrap();
        let from = tgt.dir("from");
        std::fs::create_dir_all(&from).unwrap();
        std::fs::write(from.join("config.json"), b"{}").unwrap();
        let mut undo = Vec::new();
        complete_image(&store, "sha256:aa", &from, &mut undo).unwrap();
        assert_eq!(
            std::fs::read(store.config_path("sha256:aa")).unwrap(),
            before
        );
        assert!(undo.is_empty());
    }

    #[test]
    fn a_volume_install_tells_a_concurrent_create_from_an_io_failure() {
        let tgt = Tgt::new();
        let stage = tgt.dir("stage");
        std::fs::create_dir_all(stage.join("volumes")).unwrap();
        let v = BTreeSet::from(["v".to_string()]);
        let mut undo = Vec::new();
        // Nothing staged: the I/O error itself.
        let e = format!(
            "{:#}",
            commit_volumes(&tgt.paths, &v, &stage, &mut undo).unwrap_err()
        );
        assert!(
            e.contains("installing volume 'v'") && !e.contains("appeared"),
            "{e}"
        );
        // A volume that appeared meanwhile: refused, never overwritten.
        std::fs::write(stage.join("volumes/v.img"), b"new").unwrap();
        std::fs::write(tgt.paths.volume_image("v"), b"old").unwrap();
        let e = format!(
            "{:#}",
            commit_volumes(&tgt.paths, &v, &stage, &mut undo).unwrap_err()
        );
        assert!(e.contains("appeared on this host during the load"), "{e}");
        assert_eq!(std::fs::read(tgt.paths.volume_image("v")).unwrap(), b"old");
    }

    #[test]
    fn a_sandbox_install_tells_a_name_clash_from_an_io_failure() {
        let (_t, src) = crate::bundle::testutil::fixture();
        let cfg = add_sandbox(&src, "a", "sha256:aa", &[]);
        let tgt = Tgt::new();
        let s = sel(entry("a"), tgt.dir("ws"), None);
        let install = |cfg: SandboxConfig| {
            let (mut undo, mut rep) = (Vec::new(), LoadReport::default());
            install_sandbox(&tgt.paths, &s, cfg, &no_staged(), &mut undo, &mut rep)
                .map_err(|e| format!("{e:#}"))
        };
        // A sandbox created meanwhile under the same name.
        std::fs::create_dir(tgt.paths.sandbox_dir("a")).unwrap();
        let e = install(cfg.clone()).unwrap_err();
        assert!(e.contains("already exists here"), "{e}");
        // No sandboxes dir at all: the I/O error itself.
        std::fs::remove_dir_all(tgt.paths.sandboxes_dir()).unwrap();
        let e = install(cfg).unwrap_err();
        assert!(
            e.contains("creating") && !e.contains("already exists"),
            "{e}"
        );
    }

    #[test]
    fn claiming_an_already_claimed_run_dir_leaves_nothing_to_undo() {
        let tgt = Tgt::new();
        crate::sandbox::claim_run_dir(&tgt.paths, "a").unwrap();
        let mut undo = Vec::new();
        claim_run_dir(&tgt.paths, "a", &mut undo).unwrap();
        assert!(undo.is_empty());
        assert!(tgt.paths.run_dir("a").join("owner").is_file());
    }

    #[test]
    fn a_failed_tag_step_restores_the_tags_it_already_created() {
        let src = Src::new();
        add_sandbox(&src.paths, "b", "sha256:aa", &[]);
        edit_src_config(&src, "a", |c| c.image_ref = "mine".into());
        edit_src_config(&src, "b", |c| c.image_ref = "Not A Tag".into());
        crate::image::tags::set_tag(&src.paths, "mine", "sha256:aa").unwrap();
        let ar = src.save(&["a", "b"], false);
        edit_manifest(&ar, |m| {
            m.tags.insert("Not A Tag".into(), "sha256:aa".into());
        });
        let tgt = Tgt::new();
        // A tag store already here (so the images dir is not this load's
        // own, which a rollback would remove wholesale).
        crate::image::tags::set_tag(&tgt.paths, "keep", "sha256:ff").unwrap();
        for d in ["ws/a", "ws/b"] {
            std::fs::create_dir_all(tgt.dir(d)).unwrap();
        }
        let o = LoadOpts {
            workspace_root: Some(tgt.dir("ws")),
            ..opts(ar, None)
        };
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &o, &mut |_| {}, &tgt.hooks()).unwrap_err();
        assert!(format!("{e:#}").contains("tag"), "{e:#}");
        assert_eq!(tgt.snapshot(), before);
        assert_eq!(
            crate::image::tags::resolve_tag(&tgt.paths, "mine").unwrap(),
            None
        );
    }

    #[test]
    fn a_config_disagreeing_with_the_manifest_is_refused() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        edit_manifest(&ar, |m| m.sandboxes[0].named_volumes.clear());
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("disagrees with the manifest"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    #[test]
    fn an_archive_missing_an_image_rootfs_is_refused() {
        let src = Src::new();
        let ar = src.save(&["a"], false);
        rewrite_archive(&ar, |n, b| (!n.ends_with("/rootfs.erofs")).then_some(b));
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let before = tgt.snapshot();
        let e = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks())
            .unwrap_err()
            .to_string();
        assert!(e.contains("archive is missing image sha256:aa"), "{e}");
        assert_eq!(tgt.snapshot(), before);
    }

    /// `archive` (no bundled workspace) with `extra` inserted before its trailer.
    fn with_extra_entry(archive: &Path, extra: &str) {
        let mut entries = read_entries(archive);
        let trailer = entries.pop().unwrap();
        entries.push((extra.into(), b"{}".to_vec()));
        entries.push(trailer);
        write_entries(archive, &entries);
    }

    #[test]
    fn stray_sandbox_and_workspace_entries_are_refused() {
        for extra in [
            "sandboxes/ghost/config.json",
            "sandboxes/a/evil",
            // "a" was saved without its workspace.
            "workspaces/a/x",
        ] {
            let src = Src::new();
            let ar = src.save(&["a"], false);
            with_extra_entry(&ar, extra);
            let tgt = Tgt::new();
            let ws = tgt.dir("ws");
            std::fs::create_dir_all(&ws).unwrap();
            let e = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks())
                .unwrap_err()
                .to_string();
            assert!(
                e.contains(&format!("unexpected archive entry {extra}")),
                "{e}"
            );
        }
    }

    #[test]
    fn a_docker_sandbox_loads() {
        let src = Src::new();
        edit_src_config(&src, "a", |c| c.docker = true);
        let ar = src.save(&["a"], false);
        let tgt = Tgt::new();
        let ws = tgt.dir("ws");
        std::fs::create_dir_all(&ws).unwrap();
        load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks()).unwrap();
        let cfg: SandboxConfig = load_json(&tgt.paths.sandbox_dir("a").join(CONFIG_FILE))
            .unwrap()
            .unwrap();
        assert!(cfg.docker);
    }

    #[test]
    fn a_volume_guest_path_the_cmdline_cannot_carry_is_refused() {
        for bad in ["scratch", "/a,b"] {
            let src = Src::new();
            edit_src_config(&src, "a", |c| c.volumes[1].guest_path = bad.into());
            let ar = src.save(&["a"], false);
            let tgt = Tgt::new();
            let ws = tgt.dir("ws");
            std::fs::create_dir_all(&ws).unwrap();
            let e = load_with(&tgt.paths, &opts(ar, Some(ws)), &mut |_| {}, &tgt.hooks())
                .unwrap_err()
                .to_string();
            assert!(e.contains("invalid volume guest path"), "{bad}: {e}");
        }
    }
}
