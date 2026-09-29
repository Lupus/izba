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
