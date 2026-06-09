//! Container image handling: registry pull, OCI layer flattening, erofs
//! build, and the content-addressed cache tying them together.

pub mod erofs;
pub mod flatten;
pub mod pull;
pub mod store;

pub use flatten::flatten_layers;
pub use store::ImageStore;

use crate::paths::Paths;
use anyhow::{Context, Result};
use std::fs;
use std::io::Read;

/// Ensure `image_ref` is cached locally and return its canonical digest.
///
/// The manifest is always fetched to resolve the digest; layer blobs are
/// pulled, flattened and converted to erofs only on a cache miss.
pub fn ensure_image(paths: &Paths, image_ref: &str) -> Result<String> {
    let store = ImageStore::new(paths);
    let resolved = pull::resolve(image_ref)?;
    let digest = resolved.digest.clone();
    if store.is_cached(&digest) {
        return Ok(digest);
    }
    let layers = resolved.fetch_layers()?;
    store.publish(&digest, |staging| {
        let merged_tar = staging.join("merged.tar");
        let out = fs::File::create(&merged_tar)
            .with_context(|| format!("failed to create {}", merged_tar.display()))?;
        let readers: Vec<Box<dyn Read>> = layers
            .into_iter()
            .map(|f| Box::new(f) as Box<dyn Read>)
            .collect();
        flatten_layers(readers, std::io::BufWriter::new(out))
            .with_context(|| format!("failed to flatten layers of {image_ref}"))?;
        erofs::build_erofs(&merged_tar, &staging.join("rootfs.erofs"))?;
        fs::remove_file(&merged_tar)?;
        fs::write(staging.join("ref.txt"), image_ref)?;
        Ok(())
    })?;
    Ok(digest)
}
