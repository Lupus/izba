//! Anonymous OCI registry pulls: manifest resolution + layer blob download.
//!
//! All async work is confined to a current-thread tokio runtime owned by
//! [`ResolvedImage`], so callers stay synchronous.

use anyhow::{bail, Context, Result};
use futures_util::TryStreamExt;
use oci_client::client::ClientConfig;
use oci_client::manifest::OciImageManifest;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

/// Manifest + layer blobs for one image.
pub struct PulledImage {
    /// Canonical image digest, e.g. `"sha256:..."`.
    pub manifest_digest: String,
    /// Compressed layer blobs in manifest order, each rewound to the start.
    pub layers: Vec<File>,
}

/// An image whose manifest has been fetched; layers can be fetched lazily,
/// which lets callers skip blob downloads on a cache hit.
pub struct ResolvedImage {
    rt: tokio::runtime::Runtime,
    client: Client,
    reference: Reference,
    manifest: OciImageManifest,
    /// Canonical image digest, e.g. `"sha256:..."`.
    pub digest: String,
}

/// Fetch the manifest for `image_ref` (e.g. `"alpine:3.20"`,
/// `"ghcr.io/x/y:tag"`; bare refs default to docker.io) with anonymous auth
/// and resolve its canonical digest. Multi-platform indexes are resolved to
/// the current platform's image manifest.
pub fn resolve(image_ref: &str) -> Result<ResolvedImage> {
    let reference: Reference = image_ref
        .parse()
        .with_context(|| format!("invalid image reference {image_ref:?}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;
    let client = Client::new(ClientConfig::default());
    let (manifest, digest) = rt
        .block_on(client.pull_image_manifest(&reference, &RegistryAuth::Anonymous))
        .with_context(|| format!("failed to pull manifest for {image_ref}"))?;
    Ok(ResolvedImage {
        rt,
        client,
        reference,
        manifest,
        digest,
    })
}

impl ResolvedImage {
    /// Download all layer blobs in manifest order. Each blob is streamed to
    /// an anonymous temp file and its sha256 is verified against the
    /// manifest layer digest while writing.
    pub fn fetch_layers(&self) -> Result<Vec<File>> {
        self.rt.block_on(async {
            let mut layers = Vec::with_capacity(self.manifest.layers.len());
            for descriptor in &self.manifest.layers {
                let expected_hex =
                    descriptor.digest.strip_prefix("sha256:").with_context(|| {
                        format!("unsupported layer digest algorithm: {}", descriptor.digest)
                    })?;
                let mut writer = Sha256Writer {
                    inner: tempfile::tempfile().context("failed to create layer temp file")?,
                    hasher: Sha256::new(),
                };
                let mut stream = self
                    .client
                    .pull_blob_stream(&self.reference, descriptor)
                    .await
                    .with_context(|| format!("failed to pull blob {}", descriptor.digest))?;
                while let Some(chunk) = stream
                    .try_next()
                    .await
                    .with_context(|| format!("failed reading blob {}", descriptor.digest))?
                {
                    writer.write_all(&chunk)?;
                }
                let actual_hex = hex::encode(writer.hasher.finalize());
                if actual_hex != expected_hex {
                    bail!(
                        "layer digest mismatch: expected {}, got sha256:{actual_hex}",
                        descriptor.digest
                    );
                }
                let mut file = writer.inner;
                file.seek(SeekFrom::Start(0))?;
                layers.push(file);
            }
            Ok(layers)
        })
    }
}

/// Pull manifest + all layer blobs for `image_ref` with anonymous auth.
pub fn pull_layers(image_ref: &str) -> Result<PulledImage> {
    let resolved = resolve(image_ref)?;
    let layers = resolved.fetch_layers()?;
    Ok(PulledImage {
        manifest_digest: resolved.digest,
        layers,
    })
}

/// `Write` adapter that feeds everything written into a sha256 hasher.
struct Sha256Writer<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for Sha256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
