//! Bundle save: write stopped sandboxes — images, named volumes, per-sandbox
//! files and disks, optionally workspaces — into one `.izba` archive
//! (zstd(tar), spec §2/§4/§10).
//!
//! Every named sandbox's lock — and the lock of every other sandbox that
//! references a saved named volume — is held for the whole write, and
//! liveness is re-checked under the lock, so a concurrent `start` or config
//! edit can never interleave with the copy. The archive is written to a
//! per-run `<out>.<pid>.<seq>.partial` and renamed into place only once it is
//! complete; any failure removes the partial, so `<out>` is either absent or
//! a whole archive.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fsutil::ExactLen;
use super::manifest::{
    BlobInfo, Checksums, Manifest, SandboxEntry, SourceOs, CHECKSUMS_PATH, MANIFEST_PATH,
};
use super::sparse::{chunk_entry_name, data_extents, for_each_chunk, DigestBuilder};
use super::workspace::{append_workspace, git_exec_bits, workspace_bytes};
use super::{Progress, FORMAT_VERSION};
use crate::liveness::Liveness;
use crate::paths::Paths;
use crate::sandbox::Connector;
use crate::state::{load_json, SandboxConfig, CONFIG_FILE};

/// Per-sandbox files carried verbatim when present (host authority, not
/// regenerated on start). Everything else in the sandbox dir — `state.json`,
/// `ports.json`, `lockdown.*`, `ssh/`, `trust/`, `oci/`, `vnc*`, `buildout/`,
/// `run/`, `logs/console.log` — is host-bound and never archived: this is an
/// allow-list, so a new host-bound file can never leak by default.
pub(crate) const SANDBOX_FILES: [&str; 4] = [
    CONFIG_FILE,
    crate::daemon::egress::config::POLICY_FILE,
    crate::manifest::store::MANIFEST_BASE_FILE,
    crate::manifest::store::MANIFEST_REVIEW_FILE,
];
/// The egress audit log, taken from `logs/` and stored beside the files above.
pub(crate) const EGRESS_AUDIT_FILE: &str = "egress-audit.jsonl";
/// Image cache files carried when present (`rootfs.erofs` is mandatory).
pub(crate) const IMAGE_FILES: [&str; 5] =
    ["rootfs.erofs", "config.json", "ref.txt", "passwd", "group"];
/// Progress is reported every this many bytes of disk data.
const PROGRESS_STEP: u64 = 256 << 20;

pub struct SaveOpts {
    pub names: Vec<String>,
    pub out: PathBuf,
    pub with_workspace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SaveReport {
    pub path: PathBuf,
    pub sandboxes: Vec<String>,
    /// Logical bytes archived (disks at their full logical length).
    pub logical_bytes: u64,
    /// Size of the finished `.izba` file.
    pub archive_bytes: u64,
    /// Non-fatal omissions, one line each (e.g. a workspace socket skipped).
    pub warnings: Vec<String>,
}

/// What a save will write, resolved from the sandboxes' configs.
#[derive(Debug)]
pub(crate) struct Plan {
    /// In the order the caller named them, duplicates collapsed.
    pub configs: Vec<(String, SandboxConfig)>,
    pub images: BTreeSet<String>,
    pub named_volumes: BTreeSet<String>,
    /// Local tag -> digest, for each sandbox whose `image_ref` is a local tag
    /// that still resolves to the digest the sandbox runs.
    pub tags: BTreeMap<String, String>,
}

pub(crate) fn plan(paths: &Paths, names: &[String]) -> anyhow::Result<Plan> {
    if names.is_empty() {
        bail!("no sandboxes to save");
    }
    let mut p = Plan {
        configs: Vec::new(),
        images: BTreeSet::new(),
        named_volumes: BTreeSet::new(),
        tags: BTreeMap::new(),
    };
    for name in names {
        crate::sandbox::validate_name(name)?;
        if p.configs.iter().any(|(n, _)| n == name) {
            continue;
        }
        let cfg: SandboxConfig = load_json(&paths.sandbox_dir(name).join(CONFIG_FILE))?
            .with_context(|| format!("no such sandbox '{name}'"))?;
        p.images.insert(cfg.image_digest.clone());
        p.named_volumes
            .extend(cfg.volumes.iter().filter_map(|v| v.name.clone()));
        if crate::image::tags::resolve_tag(paths, &cfg.image_ref)?.as_deref()
            == Some(cfg.image_digest.as_str())
        {
            p.tags
                .insert(cfg.image_ref.clone(), cfg.image_digest.clone());
        }
        p.configs.push((name.clone(), cfg));
    }
    Ok(p)
}

/// Caller guarantees every named sandbox is stopped (daemon stops them first
/// for --stop); a running one — or a named volume held by any other running
/// sandbox — is refused, never stopped here.
pub fn save(
    paths: &Paths,
    connector: Connector,
    opts: &SaveOpts,
    progress: Progress,
) -> anyhow::Result<SaveReport> {
    let plan = plan(paths, &opts.names)?;
    // Held until this function returns: blocks `start` and config edits for
    // the whole copy. Liveness is re-checked under the lock.
    let mut _locks = Vec::new();
    for (name, _) in &plan.configs {
        _locks.push(crate::sandbox::lock_sandbox(paths, name)?);
        if crate::sandbox::liveness_of(paths, name, connector)? != Liveness::Stopped {
            bail!("sandbox '{name}' is running; stop it first (or pass --stop)");
        }
    }
    // Also lock every OTHER sandbox that references a saved named volume, so
    // none can `start` and write the volume mid-copy (a torn image whose
    // checksums would still validate). Held for the whole write, like the
    // saved sandboxes' own locks; a busy one is a loud, retryable refusal.
    let saved: HashSet<&str> = plan.configs.iter().map(|(n, _)| n.as_str()).collect();
    let mut locked: HashSet<String> = HashSet::new();
    for v in &plan.named_volumes {
        for other in crate::sandbox::volume_referrers(paths, v)? {
            if saved.contains(other.as_str()) || !locked.insert(other.clone()) {
                continue;
            }
            match crate::sandbox::lock_sandbox(paths, &other) {
                Ok(l) => _locks.push(l),
                Err(e) => bail!(
                    "named volume '{v}' is also used by sandbox '{other}', which could not be \
                     locked ({e:#}); retry once it is idle"
                ),
            }
        }
    }
    for v in &plan.named_volumes {
        // Exclude nothing: the saved sandboxes were just verified stopped.
        if let Some(h) = crate::sandbox::persistent_volume_holder(paths, v, "", connector)? {
            bail!("named volume '{v}' is in use by running sandbox '{h}'; stop it first");
        }
    }
    let file_name = opts
        .out
        .file_name()
        .context("output path has no file name")?;
    // Unique per run (pid + in-process counter): two concurrent saves to the
    // same --out — possibly two daemon threads — never share a partial.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let partial = opts.out.with_file_name(format!(
        "{}.{}.{seq}.partial",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    match write_archive(paths, &plan, opts, &partial, progress) {
        Ok(mut report) => {
            if let Err(e) = std::fs::rename(&partial, &opts.out) {
                let _ = std::fs::remove_file(&partial);
                return Err(e).with_context(|| format!("renaming to {}", opts.out.display()));
            }
            report.path = opts.out.clone();
            report.archive_bytes = std::fs::metadata(&opts.out)?.len();
            Ok(report)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            Err(e)
        }
    }
}

/// A disk's manifest entry. `allocated` is the sum of its data extents on
/// every host OS — never the file length (a Windows file's metadata carries
/// no block count, so a sparse disk would over-ask the load's space check).
fn disk_blob_info(path: String, src: &Path) -> anyhow::Result<BlobInfo> {
    let f = File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let logical_len = f
        .metadata()
        .with_context(|| format!("stat {}", src.display()))?
        .len();
    let allocated = data_extents(&f, logical_len)
        .with_context(|| format!("mapping extents of {}", src.display()))?
        .iter()
        .map(|(_, l)| l)
        .sum();
    Ok(BlobInfo {
        path,
        logical_len,
        allocated,
    })
}

/// `(archive prefix, host path)` of a sandbox's own disks: `rw.img`, then each
/// anonymous volume by its stable `eph_id`.
fn sandbox_disks(paths: &Paths, name: &str, cfg: &SandboxConfig) -> Vec<(String, PathBuf)> {
    let dir = paths.sandbox_dir(name);
    let mut v = vec![(format!("sandboxes/{name}/rw.img"), dir.join("rw.img"))];
    for vol in cfg.volumes.iter().filter(|v| !v.is_persistent()) {
        let src = vol.image_path(paths, name);
        let file = src.file_name().unwrap_or_default().to_string_lossy();
        v.push((format!("sandboxes/{name}/volumes/{file}"), src));
    }
    v
}

fn build_manifest(paths: &Paths, plan: &Plan, with_workspace: bool) -> anyhow::Result<Manifest> {
    let named_volumes = plan
        .named_volumes
        .iter()
        .map(|v| disk_blob_info(format!("volumes/{v}.img"), &paths.volume_image(v)))
        .collect::<anyhow::Result<_>>()?;
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let source_home = std::env::var_os(home_var).map(|h| h.to_string_lossy().into_owned());
    let mut sandboxes = Vec::new();
    for (name, cfg) in &plan.configs {
        let ws_bytes = if with_workspace {
            if !cfg.workspace.is_dir() {
                bail!(
                    "sandbox '{name}': workspace {} does not exist; save without --with-workspace",
                    cfg.workspace.display()
                );
            }
            workspace_bytes(&cfg.workspace)?
        } else {
            0
        };
        sandboxes.push(SandboxEntry {
            name: name.clone(),
            image_digest: cfg.image_digest.clone(),
            named_volumes: cfg.volumes.iter().filter_map(|v| v.name.clone()).collect(),
            disk_owner: cfg
                .disk_owner
                .unwrap_or_else(|| crate::sandbox::workspace_owner(&cfg.workspace)),
            workspace_bundled: with_workspace,
            source_workspace: cfg.workspace.to_string_lossy().into_owned(),
            source_home: source_home.clone(),
            disks: sandbox_disks(paths, name, cfg)
                .into_iter()
                .map(|(p, src)| disk_blob_info(p, &src))
                .collect::<anyhow::Result<_>>()?,
            workspace_bytes: ws_bytes,
            locked: paths
                .sandbox_dir(name)
                .join(crate::jail_account::state::LOCKDOWN_FILE)
                .exists(),
        });
    }
    Ok(Manifest {
        format: FORMAT_VERSION,
        izba_version: crate::build_info::BuildInfo::current().short(),
        source_os: SourceOs::current(),
        created_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        tags: plan.tags.clone(),
        images: plan.images.iter().cloned().collect(),
        image_sizes: plan
            .images
            .iter()
            .map(|d| (d.clone(), image_allocated(paths, d)))
            .collect(),
        named_volumes,
        sandboxes,
    })
}

/// Allocated bytes of the image files an archive carries for `digest`.
fn image_allocated(paths: &Paths, digest: &str) -> u64 {
    let dir = paths.image_dir(digest);
    IMAGE_FILES
        .iter()
        .filter_map(|f| std::fs::metadata(dir.join(f)).ok())
        .map(|m| crate::sandbox::allocated_bytes(&m))
        .sum()
}

fn write_archive(
    paths: &Paths,
    plan: &Plan,
    opts: &SaveOpts,
    partial: &Path,
    progress: Progress,
) -> anyhow::Result<SaveReport> {
    let manifest = build_manifest(paths, plan, opts.with_workspace)?;
    let file = File::create(partial).with_context(|| format!("creating {}", partial.display()))?;
    let mut enc = zstd::Encoder::new(BufWriter::new(file), 3)?;
    enc.include_checksum(true)?;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get() as u32);
    enc.multithread(threads)?;
    let mut tar = tar::Builder::new(enc);
    tar.mode(tar::HeaderMode::Deterministic);

    let mut sums = Checksums::default();
    let mut logical = 0u64;
    let mut warnings = Vec::new();

    append_bytes(
        &mut tar,
        MANIFEST_PATH,
        &serde_json::to_vec_pretty(&manifest)?,
    )?;

    for digest in &plan.images {
        progress(format!("image {digest}"));
        let dir = paths.image_dir(digest);
        if !dir.join(IMAGE_FILES[0]).is_file() {
            bail!(
                "image {digest} is not in the local image cache ({} missing)",
                IMAGE_FILES[0]
            );
        }
        let dir_name = dir
            .file_name()
            .context("image dir has no name")?
            .to_string_lossy();
        for f in IMAGE_FILES {
            let src = dir.join(f);
            if src.is_file() {
                logical += append_file_hashed(
                    &mut tar,
                    &format!("images/{dir_name}/{f}"),
                    &src,
                    &mut sums,
                )?;
            }
        }
    }

    for v in &plan.named_volumes {
        progress(format!("volume '{v}'"));
        let prefix = format!("volumes/{v}.img");
        logical += append_disk(
            &mut tar,
            &prefix,
            &paths.volume_image(v),
            &mut sums,
            progress,
        )?;
    }

    for (name, cfg) in &plan.configs {
        progress(format!("saving sandbox '{name}'"));
        let dir = paths.sandbox_dir(name);
        let logs = paths.logs_dir(name).join(EGRESS_AUDIT_FILE);
        let files = SANDBOX_FILES
            .iter()
            .map(|f| (*f, dir.join(f)))
            .chain([(EGRESS_AUDIT_FILE, logs)]);
        for (f, src) in files {
            if src.is_file() {
                logical += append_file_hashed(
                    &mut tar,
                    &format!("sandboxes/{name}/{f}"),
                    &src,
                    &mut sums,
                )?;
            }
        }
        for (prefix, src) in sandbox_disks(paths, name, cfg) {
            logical += append_disk(&mut tar, &prefix, &src, &mut sums, progress)?;
        }
    }

    if opts.with_workspace {
        for (name, cfg) in &plan.configs {
            progress(format!("workspace of '{name}'"));
            // NTFS carries no exec bits; git's index is the only record of them.
            let exec_bits = if cfg!(windows) {
                git_exec_bits(&cfg.workspace)
            } else {
                HashSet::new()
            };
            let stats = append_workspace(
                &mut tar,
                &cfg.workspace,
                &format!("workspaces/{name}"),
                &exec_bits,
            )?;
            logical += stats.bytes;
            warnings.extend(stats.skipped.iter().map(|p| {
                format!(
                    "sandbox '{name}': skipped special file {} \
                     (sockets/FIFOs/devices are not archived)",
                    p.display()
                )
            }));
        }
    }

    append_bytes(&mut tar, CHECKSUMS_PATH, &serde_json::to_vec_pretty(&sums)?)?;
    let enc = tar.into_inner().context("finishing archive")?;
    let file = enc
        .finish()
        .context("finishing compression")?
        .into_inner()
        .map_err(|e| e.into_error())
        .context("flushing archive")?;
    file.sync_all().context("syncing archive")?;
    Ok(SaveReport {
        path: partial.to_path_buf(),
        sandboxes: plan.configs.iter().map(|(n, _)| n.clone()).collect(),
        logical_bytes: logical,
        archive_bytes: 0,
        warnings,
    })
}

fn file_header(size: u64) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_size(size);
    h.set_mode(0o600);
    h.set_cksum();
    h
}

fn append_bytes<W: Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
) -> anyhow::Result<()> {
    tar.append_data(&mut file_header(bytes.len() as u64), path, bytes)
        .with_context(|| format!("archiving {path}"))
}

/// `Read` adapter feeding exactly the declared length (see [`ExactLen`])
/// through sha256.
struct HashingReader<R> {
    inner: ExactLen<R>,
    h: Sha256,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.h.update(&buf[..n]);
        Ok(n)
    }
}

/// Plain file entry; its sha256 goes into `sums` under the entry path.
fn append_file_hashed<W: Write>(
    tar: &mut tar::Builder<W>,
    path: &str,
    src: &Path,
    sums: &mut Checksums,
) -> anyhow::Result<u64> {
    let f = File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let len = f.metadata()?.len();
    append_reader_hashed(tar, path, f, len, sums)?;
    Ok(len)
}

/// Exactly `len` bytes of `reader` as entry `path` (header size `len`); a
/// shorter reader fails, a longer one is truncated at `len`.
fn append_reader_hashed<W: Write, R: Read>(
    tar: &mut tar::Builder<W>,
    path: &str,
    reader: R,
    len: u64,
    sums: &mut Checksums,
) -> anyhow::Result<()> {
    let mut r = HashingReader {
        inner: ExactLen::new(reader, len),
        h: Sha256::new(),
    };
    tar.append_data(&mut file_header(len), path, &mut r)
        .with_context(|| format!("archiving {path}"))?;
    sums.files
        .insert(path.to_string(), hex::encode(r.h.finalize()));
    Ok(())
}

/// A disk as `<prefix>.len` (8-byte LE logical length — always written, so an
/// all-zero disk with no chunks still materializes on load) followed by its
/// non-zero `<prefix>.d/<offset>` chunks; the canonical content digest goes
/// into `sums` under `prefix`. Returns the logical length.
fn append_disk<W: Write>(
    tar: &mut tar::Builder<W>,
    prefix: &str,
    src: &Path,
    sums: &mut Checksums,
    progress: Progress,
) -> anyhow::Result<u64> {
    let len = std::fs::metadata(src)
        .with_context(|| format!("stat {}", src.display()))?
        .len();
    append_bytes(tar, &format!("{prefix}.len"), &len.to_le_bytes())?;
    let mut d = DigestBuilder::new(len);
    let mut done = 0u64;
    let read_len = for_each_chunk(src, |c| {
        d.chunk(&c);
        append_bytes(tar, &chunk_entry_name(prefix, c.offset), &c.data)?;
        let before = done;
        done += c.data.len() as u64;
        if done / PROGRESS_STEP != before / PROGRESS_STEP {
            progress(format!("{prefix}: {} MiB", done >> 20));
        }
        Ok(())
    })?;
    if read_len != len {
        bail!("{} changed size while being archived", src.display());
    }
    sums.files.insert(prefix.to_string(), d.finish());
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::manifest::{Checksums, Manifest, CHECKSUMS_PATH, MANIFEST_PATH};
    use crate::bundle::sparse::content_digest;
    use crate::bundle::testutil::{
        add_sandbox, entry_names, fixture, no_conn, read_entries, write_live_state, DATA_OFF,
        DISK_LEN,
    };
    use crate::state::{load_json, save_json, CONFIG_FILE};
    use sha2::{Digest, Sha256};

    fn opts(names: &[&str], out: PathBuf, with_workspace: bool) -> SaveOpts {
        SaveOpts {
            names: names.iter().map(|n| n.to_string()).collect(),
            out,
            with_workspace,
        }
    }

    fn body<'a>(entries: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
        &entries
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no entry {name}"))
            .1
    }

    fn manifest_and_sums(entries: &[(String, Vec<u8>)]) -> (Manifest, Checksums) {
        (
            serde_json::from_slice(body(entries, MANIFEST_PATH)).unwrap(),
            serde_json::from_slice(body(entries, CHECKSUMS_PATH)).unwrap(),
        )
    }

    #[test]
    fn plan_dedups_shared_image_and_collects_named_volumes() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        add_sandbox(&paths, "b", "sha256:aa", &[]);
        let p = plan(&paths, &["a".into(), "b".into()]).unwrap();
        assert_eq!(p.images.len(), 1);
        assert_eq!(p.named_volumes.iter().collect::<Vec<_>>(), vec!["data"]);
        assert_eq!(
            p.configs
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        drop(t);
    }

    #[test]
    fn plan_refuses_unknown_sandbox() {
        let (_t, paths) = fixture();
        assert!(plan(&paths, &["ghost".into()])
            .unwrap_err()
            .to_string()
            .contains("no such sandbox"));
    }

    #[test]
    fn plan_refuses_an_invalid_name_and_an_empty_list() {
        let (_t, paths) = fixture();
        assert!(plan(&paths, &["../etc".into()]).is_err());
        assert!(plan(&paths, &[]).is_err());
    }

    #[test]
    fn plan_collapses_a_repeated_name() {
        let (_t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        let p = plan(&paths, &["a".into(), "a".into()]).unwrap();
        assert_eq!(p.configs.len(), 1);
    }

    #[test]
    fn plan_records_only_local_tags_that_resolve_to_the_sandbox_image() {
        let (_t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        add_sandbox(&paths, "b", "sha256:bb", &[]);
        crate::image::set_tag(&paths, "mine", "sha256:aa").unwrap();
        crate::image::set_tag(&paths, "moved", "sha256:zz").unwrap();
        for (n, r) in [("a", "mine"), ("b", "moved")] {
            let p = paths.sandbox_dir(n).join(CONFIG_FILE);
            let mut c: SandboxConfig = load_json(&p).unwrap().unwrap();
            c.image_ref = r.into();
            save_json(&p, &c).unwrap();
        }
        let p = plan(&paths, &["a".into(), "b".into()]).unwrap();
        assert_eq!(
            p.tags,
            BTreeMap::from([("mine".to_string(), "sha256:aa".to_string())])
        );
    }

    #[test]
    fn save_writes_manifest_first_and_checksums_last_and_skips_host_bound_files() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        let dir = paths.sandbox_dir("a");
        // A stale state.json from the last run (dead VMM): host-bound, not archived.
        crate::testutil::write_state(&paths, "a", crate::testutil::dead_identity());
        for f in [
            "ports.json",
            "lockdown.json",
            "lockdown.cred",
            "vnc.password",
        ] {
            std::fs::write(dir.join(f), b"{}").unwrap();
        }
        for d in ["ssh", "trust", "oci", "vnc", "buildout", "run"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            std::fs::write(dir.join(d).join("x"), b"k").unwrap();
        }
        std::fs::create_dir_all(paths.logs_dir("a")).unwrap();
        std::fs::write(paths.logs_dir("a").join("console.log"), b"boot").unwrap();
        let out = t.path().join("x.izba");
        save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), false),
            &mut |_| {},
        )
        .unwrap();
        let names = entry_names(&out);
        assert_eq!(names.first().unwrap(), "manifest.json");
        assert_eq!(names.last().unwrap(), "checksums.json");
        for bad in [
            "state.json",
            "ports.json",
            "lockdown",
            "ssh/",
            "trust/",
            "oci/",
            "vnc",
            "buildout",
            "run/",
            "console.log",
        ] {
            assert!(
                !names.iter().any(|n| n.contains(bad)),
                "{bad} leaked: {names:?}"
            );
        }
        assert!(names.iter().any(|n| n == "sandboxes/a/rw.img.len"));
        assert!(!names.iter().any(|n| n.starts_with("workspaces/")));
        assert_no_partials(t.path());
    }

    #[test]
    fn save_refuses_a_running_sandbox() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        write_live_state(&paths, "a");
        let out = t.path().join("x.izba");
        let e = save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), false),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.to_string().contains("stop it first"), "{e}");
        assert!(!out.exists());
    }

    #[test]
    fn save_refuses_a_named_volume_held_by_another_running_sandbox() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        add_sandbox(&paths, "b", "sha256:aa", &[("data", "/data")]);
        write_live_state(&paths, "b");
        let e = save(
            &paths,
            &no_conn,
            &opts(&["a"], t.path().join("x.izba"), false),
            &mut |_| {},
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("'data'") && e.contains("'b'"), "{e}");
    }

    fn assert_no_partials(dir: &Path) {
        let left: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".partial"))
            .collect();
        assert!(left.is_empty(), "leftover partials: {left:?}");
    }

    #[test]
    fn save_refuses_when_another_sandbox_sharing_a_named_volume_is_busy() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        add_sandbox(&paths, "b", "sha256:aa", &[("data", "/data")]);
        add_sandbox(&paths, "c", "sha256:aa", &[]);
        // b is stopped but busy (e.g. mid-start): it could write data.img
        // during the copy, so the save must refuse rather than race it.
        let held = crate::sandbox::lock_sandbox(&paths, "b").unwrap();
        let out = t.path().join("x.izba");
        let e = save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), false),
            &mut |_| {},
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("'data'") && e.contains("'b'") && e.contains("busy"),
            "{e}"
        );
        assert!(!out.exists());
        assert_no_partials(t.path());
        // An unrelated busy sandbox (c) does not block; once b is idle it works.
        drop(held);
        let _c = crate::sandbox::lock_sandbox(&paths, "c").unwrap();
        save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), false),
            &mut |_| {},
        )
        .unwrap();
        assert!(out.exists());
    }

    #[test]
    fn save_holds_the_lock_of_a_sandbox_sharing_a_named_volume_during_the_write() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        add_sandbox(&paths, "b", "sha256:aa", &[("data", "/data")]);
        let mut b_busy_mid_write = None;
        save(
            &paths,
            &no_conn,
            &opts(&["a"], t.path().join("x.izba"), false),
            &mut |_| {
                if b_busy_mid_write.is_none() {
                    b_busy_mid_write = Some(crate::sandbox::lock_sandbox(&paths, "b").is_err());
                }
            },
        )
        .unwrap();
        assert_eq!(b_busy_mid_write, Some(true));
        // Released afterwards.
        crate::sandbox::lock_sandbox(&paths, "b").unwrap();
    }

    #[test]
    fn a_reader_shorter_than_its_declared_len_fails() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut sums = Checksums::default();
        let e = append_reader_hashed(&mut tar, "f", &b"abc"[..], 5, &mut sums).unwrap_err();
        assert!(format!("{e:#}").contains("shrank"), "{e:#}");
        assert!(sums.files.is_empty());
    }

    #[test]
    fn a_reader_longer_than_its_declared_len_is_cut_and_the_stream_stays_in_sync() {
        let mut tar = tar::Builder::new(Vec::new());
        let mut sums = Checksums::default();
        append_reader_hashed(&mut tar, "f", &b"hello, grown"[..], 5, &mut sums).unwrap();
        append_reader_hashed(&mut tar, "g", &b"next"[..], 4, &mut sums).unwrap();
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
                ("f".into(), b"hello".to_vec()),
                ("g".into(), b"next".to_vec())
            ]
        );
        assert_eq!(sums.files["f"], hex::encode(Sha256::digest(b"hello")));
    }

    #[test]
    fn concurrent_runs_use_distinct_partials() {
        // Two saves of different sandboxes to the same --out, both succeed
        // (last rename wins) and leave no partial behind.
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        add_sandbox(&paths, "b", "sha256:aa", &[]);
        let out = t.path().join("x.izba");
        std::thread::scope(|s| {
            for n in ["a", "b"] {
                let (paths, out) = (&paths, out.clone());
                s.spawn(move || {
                    save(paths, &no_conn, &opts(&[n], out, false), &mut |_| {}).unwrap();
                });
            }
        });
        assert!(out.exists());
        assert_no_partials(t.path());
    }

    #[test]
    fn save_refuses_a_sandbox_busy_with_another_operation() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        let _held = crate::sandbox::lock_sandbox(&paths, "a").unwrap();
        let e = save(
            &paths,
            &no_conn,
            &opts(&["a"], t.path().join("x.izba"), false),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.to_string().contains("busy"), "{e}");
    }

    #[test]
    fn save_failure_removes_partial() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:missing", &[]);
        std::fs::remove_dir_all(paths.image_dir("sha256:missing")).unwrap();
        let out = t.path().join("x.izba");
        let e = save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), false),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.to_string().contains("sha256:missing"), "{e}");
        assert!(!out.exists());
        assert_no_partials(t.path());
    }

    #[test]
    fn save_archives_every_blob_with_its_checksum() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        let dir = paths.sandbox_dir("a");
        // One anonymous volume (eph_id 3) next to the named one.
        let cp = dir.join(CONFIG_FILE);
        let mut c: SandboxConfig = load_json(&cp).unwrap().unwrap();
        c.volumes.push(crate::volume::VolumeSpec {
            name: None,
            guest_path: "/scratch".into(),
            size_bytes: DISK_LEN,
            eph_id: Some(3),
        });
        save_json(&cp, &c).unwrap();
        crate::bundle::testutil::write_sparse_disk(&dir.join("volumes/3.img"), 0xEF);
        std::fs::write(dir.join("policy.yaml"), b"allow: []\n").unwrap();
        std::fs::write(dir.join("lockdown.json"), b"{}").unwrap();
        std::fs::create_dir_all(paths.logs_dir("a")).unwrap();
        std::fs::write(paths.logs_dir("a").join("egress-audit.jsonl"), b"{}\n").unwrap();

        let out = t.path().join("x.izba");
        let mut msgs = Vec::new();
        let r = save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), false),
            &mut |m| msgs.push(m),
        )
        .unwrap();
        assert_eq!(r.path, out);
        assert_eq!(r.sandboxes, vec!["a".to_string()]);
        assert_eq!(r.archive_bytes, std::fs::metadata(&out).unwrap().len());
        assert!(r.logical_bytes >= 3 * DISK_LEN, "{r:?}");
        assert!(r.warnings.is_empty());
        assert!(!msgs.is_empty());

        let entries = read_entries(&out);
        let (m, sums) = manifest_and_sums(&entries);
        assert_eq!(m.format, crate::bundle::FORMAT_VERSION);
        assert_eq!(m.images, vec!["sha256:aa".to_string()]);
        assert!(m.image_sizes["sha256:aa"] > 0, "{:?}", m.image_sizes);
        assert_eq!(m.sandboxes[0].image_digest, "sha256:aa");
        assert_eq!(m.sandboxes[0].named_volumes, vec!["data".to_string()]);
        assert_eq!(m.named_volumes.len(), 1);
        assert_eq!(m.named_volumes[0].path, "volumes/data.img");
        assert_eq!(m.named_volumes[0].logical_len, DISK_LEN);
        let s = &m.sandboxes[0];
        assert_eq!(s.name, "a");
        assert!(s.locked);
        assert!(!s.workspace_bundled);
        assert_eq!(s.source_workspace, c.workspace.to_string_lossy());
        assert_eq!(
            s.disks.iter().map(|d| d.path.as_str()).collect::<Vec<_>>(),
            vec!["sandboxes/a/rw.img", "sandboxes/a/volumes/3.img"]
        );

        // Disks: `.len` marker + the one data chunk, content digest in checksums.
        for (prefix, src) in [
            ("sandboxes/a/rw.img", dir.join("rw.img")),
            ("sandboxes/a/volumes/3.img", dir.join("volumes/3.img")),
            ("volumes/data.img", paths.volume_image("data")),
        ] {
            assert_eq!(
                body(&entries, &format!("{prefix}.len")),
                DISK_LEN.to_le_bytes()
            );
            let chunk = crate::bundle::sparse::chunk_entry_name(prefix, DATA_OFF);
            assert_eq!(body(&entries, &chunk).len(), 64 * 1024, "{prefix}");
            assert_eq!(
                sums.files[prefix],
                content_digest(&src).unwrap(),
                "{prefix}"
            );
        }
        // Plain files: sha256 of the body.
        let img = paths.image_dir("sha256:aa");
        let img_dir = img.file_name().unwrap().to_string_lossy().into_owned();
        for (name, src) in [
            (
                format!("images/{img_dir}/rootfs.erofs"),
                img.join("rootfs.erofs"),
            ),
            (
                format!("images/{img_dir}/config.json"),
                img.join("config.json"),
            ),
            (format!("images/{img_dir}/ref.txt"), img.join("ref.txt")),
            ("sandboxes/a/config.json".into(), cp.clone()),
            ("sandboxes/a/policy.yaml".into(), dir.join("policy.yaml")),
            (
                "sandboxes/a/egress-audit.jsonl".into(),
                paths.logs_dir("a").join("egress-audit.jsonl"),
            ),
        ] {
            let want = std::fs::read(&src).unwrap();
            assert_eq!(body(&entries, &name), want.as_slice(), "{name}");
            assert_eq!(
                sums.files[&name],
                hex::encode(Sha256::digest(&want)),
                "{name}"
            );
        }
        // Absent optional files leave no entry.
        let names = entry_names(&out);
        assert!(!names.iter().any(|n| n.ends_with("manifest.review")));
        assert!(!names.iter().any(|n| n.ends_with("/passwd")));
    }

    #[test]
    fn a_disk_allocation_is_its_data_extent_sum_on_every_os() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("d.img");
        crate::bundle::testutil::write_sparse_disk(&p, 0x5A);
        let b = disk_blob_info("volumes/d.img".into(), &p).unwrap();
        let f = File::open(&p).unwrap();
        let sum: u64 = crate::bundle::sparse::data_extents(&f, DISK_LEN)
            .unwrap()
            .iter()
            .map(|(_, l)| l)
            .sum();
        assert_eq!(b.logical_len, DISK_LEN);
        assert_eq!(b.allocated, sum);
        assert!(b.allocated <= b.logical_len);
        assert_eq!(b.path, "volumes/d.img");
    }

    #[test]
    fn an_all_zero_disk_still_gets_its_len_marker() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        let rw = paths.sandbox_dir("a").join("rw.img");
        std::fs::File::create(&rw)
            .unwrap()
            .set_len(DISK_LEN)
            .unwrap();
        let out = t.path().join("x.izba");
        save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), false),
            &mut |_| {},
        )
        .unwrap();
        let entries = read_entries(&out);
        assert_eq!(
            body(&entries, "sandboxes/a/rw.img.len"),
            DISK_LEN.to_le_bytes()
        );
        assert!(!entries
            .iter()
            .any(|(n, _)| n.starts_with("sandboxes/a/rw.img.d/")));
        let (_, sums) = manifest_and_sums(&entries);
        assert_eq!(
            sums.files["sandboxes/a/rw.img"],
            content_digest(&rw).unwrap()
        );
    }

    #[test]
    fn a_shared_image_and_volume_are_archived_once() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        add_sandbox(&paths, "b", "sha256:aa", &[("data", "/data")]);
        let out = t.path().join("x.izba");
        save(
            &paths,
            &no_conn,
            &opts(&["a", "b"], out.clone(), false),
            &mut |_| {},
        )
        .unwrap();
        let names = entry_names(&out);
        let count = |s: &str| names.iter().filter(|n| n.ends_with(s)).count();
        assert_eq!(count("/rootfs.erofs"), 1);
        assert_eq!(count("volumes/data.img.len"), 1);
        assert_eq!(count("/rw.img.len"), 2);
    }

    #[test]
    fn save_with_workspace_archives_the_tree() {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[]);
        let out = t.path().join("x.izba");
        save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), true),
            &mut |_| {},
        )
        .unwrap();
        let entries = read_entries(&out);
        assert_eq!(body(&entries, "workspaces/a/README"), b"hello");
        let (m, _) = manifest_and_sums(&entries);
        assert!(m.sandboxes[0].workspace_bundled);
        assert_eq!(m.sandboxes[0].workspace_bytes, 5);
        // Workspace entries sit between the sandbox files and the trailer.
        let names = entry_names(&out);
        let ws = names
            .iter()
            .position(|n| n == "workspaces/a/README")
            .unwrap();
        let rw = names
            .iter()
            .position(|n| n == "sandboxes/a/rw.img.len")
            .unwrap();
        assert!(rw < ws && ws < names.len() - 1);
    }

    #[cfg(unix)]
    #[test]
    fn save_with_workspace_reports_skipped_special_files() {
        use std::os::unix::ffi::OsStrExt;
        let (t, paths) = fixture();
        let cfg = add_sandbox(&paths, "a", "sha256:aa", &[]);
        let fifo = cfg.workspace.join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = t.path().join("x.izba");
        let r = save(&paths, &no_conn, &opts(&["a"], out, true), &mut |_| {}).unwrap();
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
        assert!(r.warnings[0].contains("'a'") && r.warnings[0].contains("fifo"));
    }

    #[test]
    fn save_with_workspace_refuses_a_name_load_could_not_restore() {
        for bad in ["a:b", "CON.txt", "trail.", "back\\slash"] {
            let (t, paths) = fixture();
            let cfg = add_sandbox(&paths, "a", "sha256:aa", &[]);
            std::fs::create_dir_all(cfg.workspace.join("sub")).unwrap();
            std::fs::write(cfg.workspace.join("sub").join(bad), b"x").unwrap();
            let out = t.path().join("x.izba");
            let e = save(
                &paths,
                &no_conn,
                &opts(&["a"], out.clone(), true),
                &mut |_| {},
            )
            .unwrap_err();
            let msg = format!("{e:#}");
            assert!(
                msg.contains(&format!("sub/{bad}")) && msg.contains("cannot be restored portably"),
                "{bad}: {msg}"
            );
            assert!(!out.exists());
            assert_no_partials(t.path());
        }
    }

    #[test]
    fn save_with_workspace_refuses_a_missing_workspace() {
        let (t, paths) = fixture();
        let cfg = add_sandbox(&paths, "a", "sha256:aa", &[]);
        std::fs::remove_dir_all(&cfg.workspace).unwrap();
        let out = t.path().join("x.izba");
        let e = save(
            &paths,
            &no_conn,
            &opts(&["a"], out.clone(), true),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.to_string().contains("without --with-workspace"), "{e}");
        assert!(!out.exists());
        // Without the flag the missing workspace does not matter.
        save(&paths, &no_conn, &opts(&["a"], out, false), &mut |_| {}).unwrap();
    }
}
