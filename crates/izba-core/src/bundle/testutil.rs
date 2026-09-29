//! Shared fixtures for the bundle save/load tests: a data root with stopped
//! sandboxes (config, sparse `rw.img`, workspace), their images and named
//! volumes, plus archive-inspection helpers.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::paths::Paths;
use crate::state::{save_json, SandboxConfig, CONFIG_FILE};
use crate::vmm::IoStream;

/// Logical length of every fixture disk (`rw.img` and volumes).
pub(crate) const DISK_LEN: u64 = 4 << 20;
/// Offset of the one non-zero block written into each fixture disk.
pub(crate) const DATA_OFF: u64 = 1 << 20;

/// An empty data root (no images — `add_sandbox` publishes what it needs).
pub(crate) fn fixture() -> (tempfile::TempDir, Paths) {
    let t = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(t.path().join("izba"));
    std::fs::create_dir_all(paths.sandboxes_dir()).unwrap();
    (t, paths)
}

/// A connector that never reaches a guest: with no `state.json` a sandbox
/// then assesses as Stopped, with a live one as Unhealthy.
pub(crate) fn no_conn(_: &Paths, _: &str) -> anyhow::Result<Box<dyn IoStream>> {
    anyhow::bail!("no guest in unit tests")
}

/// Sparse file of `DISK_LEN` with `tag` repeated over one 64 KiB block at
/// `DATA_OFF`, the rest holes.
pub(crate) fn write_sparse_disk(path: &Path, tag: u8) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = std::fs::File::create(path).unwrap();
    f.set_len(DISK_LEN).unwrap();
    f.seek(SeekFrom::Start(DATA_OFF)).unwrap();
    f.write_all(&vec![tag; 64 * 1024]).unwrap();
}

/// Publish a complete image cache entry for `digest` (rootfs.erofs + config.json).
pub(crate) fn add_image(paths: &Paths, digest: &str) {
    crate::testutil::publish_fixture_image(paths, digest, "fixture:latest");
}

/// Workspace dir used by `add_sandbox` for `name`.
pub(crate) fn workspace_of(paths: &Paths, name: &str) -> PathBuf {
    paths.root().parent().unwrap().join("ws").join(name)
}

/// A stopped sandbox `name` from image `digest` (published), with a sparse
/// `rw.img`, a workspace holding one file, and each `(volume, guest_path)` in
/// `named_volumes` as a persistent volume whose image is created too.
pub(crate) fn add_sandbox(
    paths: &Paths,
    name: &str,
    digest: &str,
    named_volumes: &[(&str, &str)],
) -> SandboxConfig {
    add_image(paths, digest);
    let dir = paths.sandbox_dir(name);
    std::fs::create_dir_all(&dir).unwrap();
    write_sparse_disk(&dir.join("rw.img"), 0xAB);
    let ws = workspace_of(paths, name);
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("README"), b"hello").unwrap();
    let volumes = named_volumes
        .iter()
        .map(|(v, gp)| {
            write_sparse_disk(&paths.volume_image(v), 0xCD);
            crate::volume::VolumeSpec {
                name: Some((*v).to_string()),
                guest_path: PathBuf::from(gp),
                size_bytes: DISK_LEN,
                eph_id: None,
            }
        })
        .collect();
    let cfg = SandboxConfig {
        image_digest: digest.to_string(),
        image_ref: "fixture:latest".to_string(),
        cpus: 1,
        mem_mb: 512,
        workspace: ws,
        ports: vec![],
        volumes,
        builder: false,
        build: None,
        rw_size_gb: 0,
        usb: Default::default(),
        docker: false,
        vnc: false,
        disk_owner: None,
    };
    save_json(&dir.join(CONFIG_FILE), &cfg).unwrap();
    cfg
}

/// A `state.json` naming this test process as the VMM: liveness is then
/// never Stopped.
pub(crate) fn write_live_state(paths: &Paths, name: &str) {
    crate::testutil::write_state(paths, name, crate::testutil::live_identity());
}

/// Every entry path of a `.izba` archive, in stream order.
pub(crate) fn entry_names(archive: &Path) -> Vec<String> {
    read_entries(archive).into_iter().map(|(n, _)| n).collect()
}

/// Every `(path, body)` of a `.izba` archive, in stream order.
pub(crate) fn read_entries(archive: &Path) -> Vec<(String, Vec<u8>)> {
    use std::io::Read;
    let dec = zstd::Decoder::new(std::fs::File::open(archive).unwrap()).unwrap();
    let mut ar = tar::Archive::new(dec);
    ar.entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let name = e.path().unwrap().to_string_lossy().into_owned();
            let mut body = Vec::new();
            e.read_to_end(&mut body).unwrap();
            (name, body)
        })
        .collect()
}

// ---- load fixtures ------------------------------------------------------

/// Write `bytes` at `off` into an existing file (no truncation).
pub(crate) fn write_at(path: &Path, off: u64, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(bytes).unwrap();
}

/// A source data root holding sandbox "a" from image `sha256:aa`: `rw.img`
/// with data at three offsets, an anonymous volume (eph_id 3), the named
/// volume "data", a USB grant with a busid pin, a `policy.yaml`, an egress
/// audit log and a `lockdown.json` (=> `locked` in the manifest).
pub(crate) struct Src {
    pub t: tempfile::TempDir,
    pub paths: Paths,
}

impl Src {
    pub fn new() -> Self {
        let (t, paths) = fixture();
        add_sandbox(&paths, "a", "sha256:aa", &[("data", "/data")]);
        let dir = paths.sandbox_dir("a");
        let rw = dir.join("rw.img");
        write_at(&rw, 0, &[0x11; 4096]);
        write_at(&rw, DISK_LEN - 4096, &[0x22; 4096]);
        let cp = dir.join(CONFIG_FILE);
        let mut c: SandboxConfig = crate::state::load_json(&cp).unwrap().unwrap();
        c.volumes.push(crate::volume::VolumeSpec {
            name: None,
            guest_path: "/scratch".into(),
            size_bytes: DISK_LEN,
            eph_id: Some(3),
        });
        c.usb.devices.push(crate::usb::grants::UsbGrant {
            device: "0403:6001".parse().unwrap(),
            busid_pin: Some("3-2".into()),
            description: String::new(),
            granted_at_unix_ms: 1,
        });
        save_json(&cp, &c).unwrap();
        write_sparse_disk(&dir.join("volumes/3.img"), 0xEF);
        std::fs::write(dir.join("policy.yaml"), b"allow: []\n").unwrap();
        std::fs::write(dir.join("lockdown.json"), b"{}").unwrap();
        std::fs::create_dir_all(paths.logs_dir("a")).unwrap();
        std::fs::write(paths.logs_dir("a").join("egress-audit.jsonl"), b"{}\n").unwrap();
        Self { t, paths }
    }

    /// Save `names` into a fresh archive inside the source tempdir.
    pub fn save(&self, names: &[&str], with_workspace: bool) -> PathBuf {
        let out = self
            .t
            .path()
            .join(format!("{}-{with_workspace}.izba", names.join("+")));
        self.save_to(names, with_workspace, &out);
        out
    }

    pub fn save_to(&self, names: &[&str], with_workspace: bool, out: &Path) {
        crate::bundle::save::save(
            &self.paths,
            &no_conn,
            &crate::bundle::save::SaveOpts {
                names: names.iter().map(|n| n.to_string()).collect(),
                out: out.to_path_buf(),
                with_workspace,
            },
            &mut |_| {},
        )
        .unwrap();
    }

    /// `(source, target)` of every disk of `name` when loaded under `as_name`.
    pub fn disk_pairs(&self, name: &str, as_name: &str, tgt: &Paths) -> Vec<(PathBuf, PathBuf)> {
        let (s, t) = (self.paths.sandbox_dir(name), tgt.sandbox_dir(as_name));
        vec![
            (s.join("rw.img"), t.join("rw.img")),
            (s.join("volumes/3.img"), t.join("volumes/3.img")),
            (self.paths.volume_image("data"), tgt.volume_image("data")),
        ]
    }
}

/// An empty target data root, plus room beside it for workspaces.
pub(crate) struct Tgt {
    pub t: tempfile::TempDir,
    pub paths: Paths,
}

fn plenty(_: &Path) -> anyhow::Result<u64> {
    Ok(u64::MAX / 2)
}

fn never_busy(_: &crate::state::PortRule) -> bool {
    false
}

impl Tgt {
    pub fn new() -> Self {
        let (t, paths) = fixture();
        Self { t, paths }
    }

    pub fn dir(&self, rel: &str) -> PathBuf {
        self.t.path().join(rel)
    }

    /// Hooks that never measure the real disk nor bind a port.
    pub fn hooks(&self) -> crate::bundle::load::LoadHooks<'static> {
        crate::bundle::load::LoadHooks {
            free_bytes: &plenty,
            port_in_use: &never_busy,
            target_home: self.dir("home"),
            fail_at: None,
        }
    }

    /// Every path under the target tempdir (data root, workspaces, the
    /// archive), sorted, each with its file length (`d` for directories).
    pub fn snapshot(&self) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                let m = std::fs::symlink_metadata(&p).unwrap();
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                if m.is_dir() {
                    out.push(format!("{rel} d"));
                    walk(root, &p, out);
                } else {
                    out.push(format!("{rel} {}", m.len()));
                }
            }
        }
        let mut v = Vec::new();
        walk(self.t.path(), self.t.path(), &mut v);
        v.sort();
        v
    }
}

/// Load options for sandbox "a" saved WITH its workspace into
/// `<tgt>/in.izba`, restoring the workspace to the not-yet-existing
/// `<tgt>/ws/a` (whose parent is created by the load too).
pub(crate) fn opts_bundled(tgt: &Tgt) -> crate::bundle::load::LoadOpts {
    let src = Src::new();
    let ar = tgt.dir("in.izba");
    src.save_to(&["a"], true, &ar);
    crate::bundle::load::LoadOpts {
        archive: ar,
        select: vec![],
        rename: None,
        workspace: Some(tgt.dir("ws/a")),
        workspace_root: None,
    }
}

/// Re-encode `archive` in place, passing every `(path, body)` through `f`
/// (`None` drops the entry). Headers (type, mode, link target) are kept.
pub(crate) fn rewrite_archive(archive: &Path, mut f: impl FnMut(&str, Vec<u8>) -> Option<Vec<u8>>) {
    use std::io::Read;
    let dec = zstd::Decoder::new(std::fs::File::open(archive).unwrap()).unwrap();
    let mut ar = tar::Archive::new(dec);
    let mut out = tar::Builder::new(Vec::new());
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        let name = e.path().unwrap().to_string_lossy().into_owned();
        let mut h = e.header().clone();
        let mut body = Vec::new();
        e.read_to_end(&mut body).unwrap();
        if let Some(b) = f(&name, body) {
            h.set_size(b.len() as u64);
            out.append_data(&mut h, &name, &b[..]).unwrap();
        }
    }
    let tar = out.into_inner().unwrap();
    std::fs::write(archive, zstd::encode_all(&tar[..], 3).unwrap()).unwrap();
}
