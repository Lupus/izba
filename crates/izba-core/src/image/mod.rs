//! Container image handling: registry pull, OCI layer flattening, erofs
//! build, and the content-addressed cache tying them together.

pub mod erofs;
pub mod flatten;
pub mod pull;
pub mod runtime_config;
pub mod store;

pub use flatten::flatten_layers;
pub use store::ImageStore;

use crate::paths::Paths;
use anyhow::{Context, Result};
use std::fs;
use std::io::Read;

/// Shared tail: flatten the ordered layer readers into one tar, build the
/// erofs, and publish under `digest` along with `config_json` + `image_ref`.
/// Returns the canonical digest (echoes `digest`). Idempotent: if the store
/// already has `digest` cached, it is a no-op returning `digest`.
pub(crate) fn publish_image(
    paths: &Paths,
    digest: &str,
    image_ref: &str,
    config_json: &[u8],
    layers: Vec<Box<dyn Read>>,
) -> Result<String> {
    let store = ImageStore::new(paths);
    if store.is_cached(digest) {
        return Ok(digest.to_string());
    }
    store.publish(digest, |staging| {
        let merged_tar = staging.join("merged.tar");
        let out = fs::File::create(&merged_tar)
            .with_context(|| format!("failed to create {}", merged_tar.display()))?;
        flatten_layers(layers, std::io::BufWriter::new(out))
            .with_context(|| format!("failed to flatten layers of {image_ref}"))?;
        erofs::build_erofs(&merged_tar, &staging.join("rootfs.erofs"))?;
        fs::remove_file(&merged_tar)?;
        fs::write(staging.join("ref.txt"), image_ref)?;
        fs::write(staging.join("config.json"), config_json)?;
        Ok(())
    })?;
    Ok(digest.to_string())
}

/// Ensure `image_ref` is cached locally and return its canonical digest.
///
/// The manifest is always fetched to resolve the digest; layer blobs are
/// pulled, flattened and converted to erofs only on a cache miss.
///
/// `#[mutants::skip]`: every path here performs real registry I/O
/// (`pull::resolve` fetches the manifest; `fetch_layers` downloads blobs), so
/// it cannot run in the unit suite — it is covered by the integration tests.
/// The testable pieces it orchestrates (`ImageStore::{load_config,
/// persist_config,is_cached}`, `flatten_layers`) have their own unit tests.
#[mutants::skip]
pub fn ensure_image(paths: &Paths, image_ref: &str) -> Result<String> {
    let store = ImageStore::new(paths);
    let resolved = pull::resolve(image_ref)?;
    let digest = resolved.digest.clone();
    if store.is_cached(&digest) {
        // Self-heal: images cached by a pre-crun izba have no config.json.
        // resolve() already fetched the config alongside the manifest, so
        // persist it now if missing — cheap, no extra round trip.
        if store.load_config(&digest)?.is_none() {
            store.persist_config(&digest, resolved.config_json.as_bytes())?;
        }
        return Ok(digest);
    }
    let config_json = resolved.config_json.clone();
    let layers = resolved.fetch_layers()?;
    let readers: Vec<Box<dyn Read>> = layers
        .into_iter()
        .map(|f| Box::new(f) as Box<dyn Read>)
        .collect();
    publish_image(paths, &digest, image_ref, config_json.as_bytes(), readers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;

    /// Build a minimal single-file gzip tar layer containing `path` with `content`.
    fn single_file_gzip_tar_layer(path: &str, content: &[u8]) -> impl Read {
        let gz = GzEncoder::new(Vec::new(), Compression::fast());
        let mut b = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, path, content).unwrap();
        let bytes = b.into_inner().unwrap().finish().unwrap();
        Cursor::new(bytes)
    }

    #[test]
    fn publish_image_writes_full_store_entry() {
        if which::which("mkfs.erofs").is_err() {
            eprintln!("SKIP: mkfs.erofs not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let layer = single_file_gzip_tar_layer("hello.txt", b"hi");
        let digest = "sha256:".to_string() + &"a".repeat(64);
        let out = publish_image(
            &paths,
            &digest,
            "oci-archive:/x",
            b"{}",
            vec![Box::new(layer)],
        )
        .unwrap();
        assert_eq!(out, digest);
        let store = ImageStore::new(&paths);
        assert!(store.is_cached(&digest));
        assert!(store.config_path(&digest).exists());
        assert!(store.ref_path(&digest).exists());
    }

    #[test]
    fn publish_image_idempotent_on_cache_hit() {
        if which::which("mkfs.erofs").is_err() {
            eprintln!("SKIP: mkfs.erofs not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let digest = "sha256:".to_string() + &"b".repeat(64);

        // First call populates the cache.
        let layer1 = single_file_gzip_tar_layer("f.txt", b"data");
        publish_image(
            &paths,
            &digest,
            "oci-archive:/x",
            b"{}",
            vec![Box::new(layer1)],
        )
        .unwrap();

        // Second call with empty layers must succeed (cache hit — layers never read).
        let out = publish_image(&paths, &digest, "oci-archive:/x", b"{}", vec![]).unwrap();
        assert_eq!(out, digest);
    }
}
