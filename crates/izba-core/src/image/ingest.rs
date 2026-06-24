//! OCI image-layout archive ingest: reads an OCI-layout tarball
//! (`oci-layout` + `index.json` + `blobs/sha256/<hex>`) and feeds the
//! ordered layer blobs into [`super::publish_image`].

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::paths::Paths;

/// OCI media types we care about.
const MEDIA_TYPE_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const MEDIA_TYPE_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const MEDIA_TYPE_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";

/// Ingest an OCI-layout archive tarball (the `type=oci` export format).
///
/// Reads `index.json` → the single `application/vnd.oci.image.manifest.v1+json`
/// entry (prefers `linux/amd64` when there are multiple) → config + ordered
/// layer blobs. Each layer blob's sha256 is verified against the manifest
/// descriptor before the reader is handed to `publish_image`. Returns the
/// config digest (the image ID), matching registry-pull semantics.
pub fn ingest_oci_archive(paths: &Paths, archive_path: &Path) -> Result<String> {
    // ── Pass 1: read index.json + the manifest blob ──────────────────────────
    let (manifest_digest, manifest_bytes) = read_manifest(archive_path)
        .with_context(|| format!("failed to read manifest from {}", archive_path.display()))?;
    let _ = manifest_digest; // manifest digest itself is not published; config digest is used

    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).context("failed to parse manifest JSON")?;

    // Config descriptor.
    let config_descriptor = manifest
        .get("config")
        .context("manifest missing 'config' field")?;
    let config_digest = config_descriptor
        .get("digest")
        .and_then(|v| v.as_str())
        .context("manifest config missing 'digest'")?
        .to_string();

    // Layer descriptors.
    let layers_arr = manifest
        .get("layers")
        .and_then(|v| v.as_array())
        .context("manifest missing 'layers' array")?;

    // ── Pass 2: read blobs (config + layers), verify digests, stage layers ───
    let config_bytes = read_verified_blob(archive_path, &config_digest)
        .with_context(|| format!("failed to read config blob {config_digest}"))?;

    let mut layer_readers: Vec<Box<dyn Read>> = Vec::with_capacity(layers_arr.len());
    for (i, layer_desc) in layers_arr.iter().enumerate() {
        let layer_digest = layer_desc
            .get("digest")
            .and_then(|v| v.as_str())
            .with_context(|| format!("layer {i} missing 'digest'"))?;
        let media_type = layer_desc
            .get("mediaType")
            .and_then(|v| v.as_str())
            .unwrap_or(MEDIA_TYPE_LAYER_GZIP);

        // Reject unsupported layer media types before we even read the blob.
        if media_type != MEDIA_TYPE_LAYER_GZIP && media_type != MEDIA_TYPE_LAYER_TAR {
            bail!(
                "layer {i} has unsupported media type {media_type:?}; \
                 only {MEDIA_TYPE_LAYER_GZIP} and {MEDIA_TYPE_LAYER_TAR} are supported"
            );
        }

        let tmp = read_verified_blob_to_tempfile(archive_path, layer_digest)
            .with_context(|| format!("failed to verify layer {i} blob {layer_digest}"))?;
        layer_readers.push(Box::new(tmp));
    }

    super::publish_image(
        paths,
        &config_digest,
        &format!("oci-archive:{}", archive_path.display()),
        &config_bytes,
        layer_readers,
    )
}

/// Open the archive at `archive_path` and return the raw bytes of the single
/// image manifest selected from `index.json`. Returns (manifest_digest,
/// manifest_bytes).
fn read_manifest(archive_path: &Path) -> Result<(String, Vec<u8>)> {
    // ── Step 1: read index.json ───────────────────────────────────────────────
    let index_bytes = find_file_in_tar(archive_path, "index.json")
        .context("failed to locate index.json in archive")?
        .context("archive does not contain index.json")?;

    let index: serde_json::Value =
        serde_json::from_slice(&index_bytes).context("failed to parse index.json")?;

    let manifests = index
        .get("manifests")
        .and_then(|v| v.as_array())
        .context("index.json missing 'manifests' array")?;

    // ── Step 2: select the image manifest ────────────────────────────────────
    let image_manifests: Vec<&serde_json::Value> = manifests
        .iter()
        .filter(|m| {
            m.get("mediaType").and_then(|v| v.as_str()).unwrap_or("") == MEDIA_TYPE_IMAGE_MANIFEST
        })
        .collect();

    let manifest_descriptor = match image_manifests.len() {
        0 => bail!("index.json contains no {MEDIA_TYPE_IMAGE_MANIFEST} manifest entries"),
        1 => image_manifests[0],
        _ => {
            // Multiple entries: prefer linux/amd64.
            let linux_amd64: Vec<&serde_json::Value> = image_manifests
                .iter()
                .filter(|m| {
                    let platform = m.get("platform");
                    let os = platform
                        .and_then(|p| p.get("os"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let arch = platform
                        .and_then(|p| p.get("architecture"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    os == "linux" && arch == "amd64"
                })
                .copied()
                .collect();
            match linux_amd64.len() {
                1 => linux_amd64[0],
                0 => bail!(
                    "index.json has {} image manifest entries but none match linux/amd64; \
                     cannot select unambiguously",
                    image_manifests.len()
                ),
                _ => bail!(
                    "index.json has multiple linux/amd64 image manifest entries; \
                     cannot select unambiguously"
                ),
            }
        }
    };

    let manifest_digest = manifest_descriptor
        .get("digest")
        .and_then(|v| v.as_str())
        .context("manifest entry missing 'digest'")?
        .to_string();

    // ── Step 3: read the manifest blob ───────────────────────────────────────
    let manifest_bytes = read_verified_blob(archive_path, &manifest_digest)
        .with_context(|| format!("failed to read manifest blob {manifest_digest}"))?;

    Ok((manifest_digest, manifest_bytes))
}

/// Parse `digest` (expected format: `sha256:<hex>`) and return the blob path
/// inside the archive (`blobs/sha256/<hex>`).
fn blob_path_from_digest(digest: &str) -> Result<String> {
    let hex = digest.strip_prefix("sha256:").with_context(|| {
        format!("unsupported digest algorithm in {digest:?}; only sha256 supported")
    })?;
    Ok(format!("blobs/sha256/{hex}"))
}

/// Read a blob from the archive, verify its sha256, and return its bytes.
fn read_verified_blob(archive_path: &Path, digest: &str) -> Result<Vec<u8>> {
    let blob_path = blob_path_from_digest(digest)?;
    let bytes = find_file_in_tar(archive_path, &blob_path)
        .with_context(|| format!("failed to search archive for blob {blob_path}"))?
        .with_context(|| format!("blob {blob_path} not found in archive"))?;

    verify_sha256(&bytes, digest).with_context(|| format!("digest mismatch for blob {digest}"))?;

    Ok(bytes)
}

/// Read a blob from the archive into a seekable temp file, verify its sha256,
/// and rewind the file to offset 0. Returns a `BufReader<File>` ready for
/// streaming.
fn read_verified_blob_to_tempfile(archive_path: &Path, digest: &str) -> Result<BufReader<File>> {
    let blob_path = blob_path_from_digest(digest)?;

    let f = File::open(archive_path)
        .with_context(|| format!("failed to open archive {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(BufReader::new(f));

    let mut tmp = tempfile::tempfile().context("failed to create temp file for layer blob")?;
    let mut hasher = Sha256::new();
    let mut found = false;

    for entry in archive
        .entries()
        .context("failed to iterate archive entries")?
    {
        let mut entry = entry.context("failed to read archive entry")?;
        let entry_path = entry.path().context("failed to get entry path")?;
        let entry_str = entry_path.to_string_lossy();

        if matches_blob_path(&entry_str, &blob_path) {
            // Stream through hasher + temp file simultaneously.
            let mut buf = [0u8; 65536];
            loop {
                let n = entry.read(&mut buf).context("failed to read blob data")?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                io::Write::write_all(&mut tmp, &buf[..n])
                    .context("failed to write layer blob to temp file")?;
            }
            found = true;
            break;
        }
    }

    if !found {
        bail!("blob {blob_path} not found in archive");
    }

    let actual_hex = hex::encode(hasher.finalize());
    let expected_hex = digest
        .strip_prefix("sha256:")
        .with_context(|| format!("unsupported digest in {digest:?}"))?;
    if actual_hex != expected_hex {
        bail!(
            "sha256 digest mismatch for {blob_path}: \
             expected sha256:{expected_hex}, got sha256:{actual_hex}"
        );
    }

    tmp.seek(SeekFrom::Start(0))
        .context("failed to rewind layer temp file")?;
    Ok(BufReader::new(tmp))
}

/// Locate a named file inside the tar archive and return its bytes, or `None`
/// if not present. Handles entries with and without a leading `./`.
fn find_file_in_tar(archive_path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let f = File::open(archive_path)
        .with_context(|| format!("failed to open archive {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(BufReader::new(f));

    for entry in archive
        .entries()
        .context("failed to iterate archive entries")?
    {
        let mut entry = entry.context("failed to read archive entry")?;
        let entry_path = entry.path().context("failed to get entry path")?;
        let entry_str = entry_path.to_string_lossy();

        if matches_blob_path(&entry_str, name) {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .with_context(|| format!("failed to read {name} from archive"))?;
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

/// Returns true if `entry` matches `name` allowing an optional leading `./`.
fn matches_blob_path(entry: &str, name: &str) -> bool {
    entry == name || entry.strip_prefix("./").unwrap_or(entry) == name
}

/// Verify that the sha256 of `data` matches `digest` (`sha256:<hex>`).
fn verify_sha256(data: &[u8], digest: &str) -> Result<()> {
    let expected_hex = digest
        .strip_prefix("sha256:")
        .with_context(|| format!("unsupported digest algorithm in {digest:?}"))?;
    let actual_hex = hex::encode(Sha256::digest(data));
    if actual_hex != expected_hex {
        bail!("sha256 digest mismatch: expected sha256:{expected_hex}, got sha256:{actual_hex}");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::image::ImageStore;
    use crate::paths::Paths;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use sha2::{Digest, Sha256};

    /// Build a minimal gzipped single-file tar layer.
    /// `file_path` may be absolute (e.g. `/etc/x`) — we strip the leading `/`
    /// because the tar crate's `Builder::append_data` rejects absolute paths.
    /// Returns the gzip-compressed bytes.
    fn make_gzip_layer(file_path: &str, content: &[u8]) -> Vec<u8> {
        // Strip leading '/' so the tar crate accepts the path.
        let rel_path = file_path.trim_start_matches('/');
        let gz = GzEncoder::new(Vec::new(), Compression::fast());
        let mut b = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(content.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, rel_path, content).unwrap();
        b.into_inner().unwrap().finish().unwrap()
    }

    /// OCI image config JSON with no meaningful content — just structurally valid.
    fn make_config_json() -> Vec<u8> {
        br#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#
            .to_vec()
    }

    /// Build a valid minimal OCI image-layout archive tarball containing one
    /// gzipped layer with a single file at `file_path` with `content`.
    ///
    /// Returns the path to the written archive file.
    pub fn build_oci_archive_fixture(
        tmp_dir: &Path,
        file_path: &str,
        content: &[u8],
    ) -> std::path::PathBuf {
        build_oci_archive_fixture_inner(tmp_dir, file_path, content, false)
    }

    /// Like `build_oci_archive_fixture` but corrupts the layer blob's last byte.
    pub fn build_oci_archive_fixture_corrupted_layer(
        tmp_dir: &Path,
        file_path: &str,
        content: &[u8],
    ) -> std::path::PathBuf {
        build_oci_archive_fixture_inner(tmp_dir, file_path, content, true)
    }

    fn build_oci_archive_fixture_inner(
        tmp_dir: &Path,
        file_path: &str,
        content: &[u8],
        corrupt_layer: bool,
    ) -> std::path::PathBuf {
        let layer_bytes = make_gzip_layer(file_path, content);
        // The manifest always records the digest of the ORIGINAL (correct) blob.
        let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&layer_bytes)));
        let mut layer_blob = layer_bytes.clone();
        if corrupt_layer {
            // Corrupt a byte in the middle of the data to produce a sha256
            // mismatch: the manifest still records the original digest, so
            // ingest must detect the tamper and return an error.
            let mid = layer_blob.len() / 2;
            layer_blob[mid] ^= 0xff;
        }
        let layer_size = layer_blob.len() as u64;

        let config_bytes = make_config_json();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));
        let config_size = config_bytes.len() as u64;

        // Build manifest JSON.
        let manifest_json = format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {{
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "{config_digest}",
    "size": {config_size}
  }},
  "layers": [
    {{
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "{layer_digest}",
      "size": {layer_size}
    }}
  ]
}}"#
        );
        let manifest_bytes = manifest_json.as_bytes();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)));

        // Build index.json.
        let index_json = format!(
            r#"{{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {{
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "{manifest_digest}",
      "size": {},
      "platform": {{"os": "linux", "architecture": "amd64"}}
    }}
  ]
}}"#,
            manifest_bytes.len()
        );

        // Assemble the tarball in memory.
        let archive_path = tmp_dir.join("image.tar");
        let archive_file = std::fs::File::create(&archive_path).unwrap();
        let mut b = tar::Builder::new(archive_file);

        // oci-layout marker.
        let oci_layout = br#"{"imageLayoutVersion":"1.0.0"}"#;
        let mut h = tar::Header::new_gnu();
        h.set_size(oci_layout.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, "oci-layout", &oci_layout[..])
            .unwrap();

        // index.json.
        let index_bytes = index_json.as_bytes();
        let mut h = tar::Header::new_gnu();
        h.set_size(index_bytes.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, "index.json", index_bytes).unwrap();

        // Config blob.
        let config_hex = config_digest.strip_prefix("sha256:").unwrap();
        let config_blob_path = format!("blobs/sha256/{config_hex}");
        let mut h = tar::Header::new_gnu();
        h.set_size(config_size);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, &config_blob_path, &config_bytes[..])
            .unwrap();

        // Manifest blob.
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();
        let manifest_blob_path = format!("blobs/sha256/{manifest_hex}");
        let mut h = tar::Header::new_gnu();
        h.set_size(manifest_bytes.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, &manifest_blob_path, manifest_bytes)
            .unwrap();

        // Layer blob (potentially corrupted).
        let layer_hex = layer_digest.strip_prefix("sha256:").unwrap();
        let layer_blob_path = format!("blobs/sha256/{layer_hex}");
        let mut h = tar::Header::new_gnu();
        h.set_size(layer_blob.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, &layer_blob_path, &layer_blob[..])
            .unwrap();

        b.finish().unwrap();
        archive_path
    }

    #[test]
    fn ingest_oci_archive_publishes_image() {
        if which::which("mkfs.erofs").is_err() {
            eprintln!("SKIP: mkfs.erofs not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let archive = build_oci_archive_fixture(tmp.path(), "/etc/x", b"y");
        let digest = ingest_oci_archive(&paths, &archive).unwrap();
        assert!(
            digest.starts_with("sha256:"),
            "returned digest must start with sha256:"
        );
        assert!(
            ImageStore::new(&paths).is_cached(&digest),
            "image must be cached after ingest"
        );
    }

    #[test]
    fn ingest_rejects_blob_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let archive = build_oci_archive_fixture_corrupted_layer(tmp.path(), "/etc/x", b"y");
        let result = ingest_oci_archive(&paths, &archive);
        assert!(
            result.is_err(),
            "ingest must error on layer blob digest mismatch"
        );
        // The error may surface as a sha256 mismatch (caught by our verifier)
        // or as a gzip-CRC failure (caught by flate2 when the gzip checksum
        // bytes are corrupted). Both are legitimate rejections of a tampered blob.
        let err = result.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("digest mismatch")
                || msg.contains("sha256")
                || msg.contains("checksum")
                || msg.contains("corrupt"),
            "error message should indicate integrity failure; got: {msg}"
        );
    }

    // ── Helper: build an archive with a custom index.json body ───────────────

    /// Write a tar archive that contains exactly `files`: a slice of (path, bytes).
    fn build_raw_tar(tmp_dir: &Path, name: &str, files: &[(&str, &[u8])]) -> std::path::PathBuf {
        let archive_path = tmp_dir.join(name);
        let f = std::fs::File::create(&archive_path).unwrap();
        let mut b = tar::Builder::new(f);
        for (entry_path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, entry_path, *data).unwrap();
        }
        b.finish().unwrap();
        archive_path
    }

    // ── Error-path tests ─────────────────────────────────────────────────────

    /// Lines 92-94: find_file_in_tar returns Ok(None) for missing index.json.
    #[test]
    fn ingest_errors_when_index_json_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        // Archive with no index.json at all.
        let archive = build_raw_tar(tmp.path(), "no_index.tar", &[("oci-layout", b"{}")]);
        let result = ingest_oci_archive(&paths, &archive);
        assert!(result.is_err(), "must error when index.json is absent");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("index.json"),
            "error should mention index.json; got: {msg}"
        );
    }

    /// Line 113: zero image manifests in index.json.
    #[test]
    fn ingest_errors_on_zero_image_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        // index.json with a manifest-list entry (not an image manifest).
        let index = br#"{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:aaaa","size":4}]}"#;
        let archive = build_raw_tar(tmp.path(), "zero_manifests.tar", &[("index.json", index)]);
        let result = ingest_oci_archive(&paths, &archive);
        assert!(result.is_err(), "must error on zero image manifests");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("no") || msg.contains("manifest"),
            "error should mention manifests; got: {msg}"
        );
    }

    /// Lines 135-138: multiple image manifests but none is linux/amd64.
    #[test]
    fn ingest_errors_on_multiple_manifests_no_amd64() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let index = br#"{
          "schemaVersion": 2,
          "manifests": [
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaa","size":4,"platform":{"os":"linux","architecture":"arm64"}},
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbb","size":4,"platform":{"os":"linux","architecture":"s390x"}}
          ]
        }"#;
        let archive = build_raw_tar(tmp.path(), "multi_no_amd64.tar", &[("index.json", index)]);
        let result = ingest_oci_archive(&paths, &archive);
        assert!(
            result.is_err(),
            "must error when no linux/amd64 manifest present"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("linux/amd64") || msg.contains("unambiguous"),
            "error should mention linux/amd64 or ambiguity; got: {msg}"
        );
    }

    /// Lines 140-143: multiple linux/amd64 manifests (ambiguous).
    #[test]
    fn ingest_errors_on_multiple_amd64_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let index = br#"{
          "schemaVersion": 2,
          "manifests": [
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaa","size":4,"platform":{"os":"linux","architecture":"amd64"}},
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bbbb","size":4,"platform":{"os":"linux","architecture":"amd64"}}
          ]
        }"#;
        let archive = build_raw_tar(tmp.path(), "multi_amd64.tar", &[("index.json", index)]);
        let result = ingest_oci_archive(&paths, &archive);
        assert!(
            result.is_err(),
            "must error when multiple linux/amd64 manifests"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("multiple") || msg.contains("linux/amd64"),
            "error should mention multiple amd64 manifests; got: {msg}"
        );
    }

    /// Lines 113-114 (single manifest path) + lines 173-175: manifest blob
    /// referenced from index.json but absent from blobs/.
    #[test]
    fn ingest_errors_when_manifest_blob_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        // A syntactically valid index.json pointing to a non-existent blob.
        let index = br#"{
          "schemaVersion": 2,
          "manifests": [
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","size":99,"platform":{"os":"linux","architecture":"amd64"}}
          ]
        }"#;
        let archive = build_raw_tar(
            tmp.path(),
            "missing_manifest_blob.tar",
            &[("index.json", index)],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(result.is_err(), "must error when manifest blob is missing");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("blob") || msg.contains("not found") || msg.contains("manifest"),
            "error should mention missing blob; got: {msg}"
        );
    }

    /// Lines 177 / 279-283: manifest blob present but sha256 mismatches.
    #[test]
    fn ingest_errors_on_manifest_blob_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));

        // Craft a manifest blob whose content does NOT match the digest we
        // put in index.json.
        let bogus_manifest = b"{}";
        let correct_hex = hex::encode(Sha256::digest(bogus_manifest));
        // Use a wrong digest in the index (flip first nibble).
        let wrong_hex = format!("ff{}", &correct_hex[2..]);
        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{wrong_hex}","size":2,"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#
        );
        let blob_path = format!("blobs/sha256/{wrong_hex}");
        let archive = build_raw_tar(
            tmp.path(),
            "manifest_digest_mismatch.tar",
            &[
                ("index.json", index.as_bytes()),
                (&blob_path, bogus_manifest),
            ],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(
            result.is_err(),
            "must error on manifest blob digest mismatch"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("digest mismatch") || msg.contains("sha256"),
            "error should indicate digest mismatch; got: {msg}"
        );
    }

    /// Lines 51-52: config blob missing from archive.
    #[test]
    fn ingest_errors_when_config_blob_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));

        // Build a real manifest that points to a config blob we won't include.
        let config_bytes = make_config_json();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));
        let layer_bytes = make_gzip_layer("/a", b"a");
        let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&layer_bytes)));

        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
            config_bytes.len(),
            layer_bytes.len()
        );
        let manifest_bytes = manifest_json.as_bytes();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)));
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();

        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{},"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#,
            manifest_bytes.len()
        );

        let manifest_blob_path = format!("blobs/sha256/{manifest_hex}");
        // Deliberately omit the config blob.
        let archive = build_raw_tar(
            tmp.path(),
            "missing_config.tar",
            &[
                ("index.json", index.as_bytes()),
                (&manifest_blob_path, manifest_bytes),
            ],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(result.is_err(), "must error when config blob is missing");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("config") || msg.contains("blob") || msg.contains("not found"),
            "error should mention missing config; got: {msg}"
        );
    }

    /// Lines 177: config blob present but digest mismatches.
    #[test]
    fn ingest_errors_on_config_blob_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));

        let config_bytes = make_config_json();
        let correct_hex = hex::encode(Sha256::digest(&config_bytes));
        // Write the correct blob under a wrong digest reference.
        let wrong_hex = format!("ff{}", &correct_hex[2..]);
        let config_digest_wrong = format!("sha256:{wrong_hex}");

        let layer_bytes = make_gzip_layer("/a", b"a");
        let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&layer_bytes)));

        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest_wrong}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
            config_bytes.len(),
            layer_bytes.len()
        );
        let manifest_bytes = manifest_json.as_bytes();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)));
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();

        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{},"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#,
            manifest_bytes.len()
        );

        let manifest_blob_path = format!("blobs/sha256/{manifest_hex}");
        let config_blob_path = format!("blobs/sha256/{wrong_hex}");
        let archive = build_raw_tar(
            tmp.path(),
            "config_digest_mismatch.tar",
            &[
                ("index.json", index.as_bytes()),
                (&manifest_blob_path, manifest_bytes),
                (&config_blob_path, &config_bytes),
            ],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(result.is_err(), "must error on config blob digest mismatch");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("digest mismatch") || msg.contains("sha256"),
            "error should indicate digest mismatch; got: {msg}"
        );
    }

    /// Lines 66-71: unsupported layer media type.
    #[test]
    fn ingest_errors_on_unsupported_layer_media_type() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));

        let config_bytes = make_config_json();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));

        let layer_bytes = b"fake layer data";
        let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(layer_bytes)));

        // Use a mediaType that is not tar+gzip or tar.
        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+zstd","digest":"{layer_digest}","size":{}}}]}}"#,
            config_bytes.len(),
            layer_bytes.len()
        );
        let manifest_bytes = manifest_json.as_bytes();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)));
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();
        let config_hex = config_digest.strip_prefix("sha256:").unwrap();

        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{},"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#,
            manifest_bytes.len()
        );

        let archive = build_raw_tar(
            tmp.path(),
            "unsupported_media.tar",
            &[
                ("index.json", index.as_bytes()),
                (&format!("blobs/sha256/{manifest_hex}"), manifest_bytes),
                (&format!("blobs/sha256/{config_hex}"), &config_bytes),
            ],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(
            result.is_err(),
            "must error on unsupported layer media type"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("unsupported") || msg.contains("media type") || msg.contains("zstd"),
            "error should mention unsupported media type; got: {msg}"
        );
    }

    /// Lines 221-222: layer blob referenced but absent from blobs/.
    #[test]
    fn ingest_errors_when_layer_blob_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));

        let config_bytes = make_config_json();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));
        let config_hex = config_digest.strip_prefix("sha256:").unwrap();

        // Point to a layer blob we will NOT include.
        let layer_digest =
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":99}}]}}"#,
            config_bytes.len()
        );
        let manifest_bytes = manifest_json.as_bytes();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)));
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();

        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{},"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#,
            manifest_bytes.len()
        );

        let archive = build_raw_tar(
            tmp.path(),
            "missing_layer_blob.tar",
            &[
                ("index.json", index.as_bytes()),
                (&format!("blobs/sha256/{manifest_hex}"), manifest_bytes),
                (&format!("blobs/sha256/{config_hex}"), &config_bytes),
            ],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(result.is_err(), "must error when layer blob is missing");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("blob") || msg.contains("not found"),
            "error should mention missing blob; got: {msg}"
        );
    }

    /// Lines 268-269: matches_blob_path handles dot-slash prefix correctly.
    #[test]
    fn matches_blob_path_handles_dot_slash_prefix() {
        assert!(matches_blob_path("./index.json", "index.json"));
        assert!(matches_blob_path("index.json", "index.json"));
        assert!(matches_blob_path("./blobs/sha256/abc", "blobs/sha256/abc"));
        assert!(!matches_blob_path("blobs/sha256/abc", "blobs/sha256/xyz"));
    }

    /// Lines 164-166 (blob_path_from_digest): non-sha256 digest algorithm.
    #[test]
    fn ingest_errors_on_unsupported_digest_algorithm() {
        // The only way to trigger blob_path_from_digest with a bad algorithm
        // is via verify_sha256 or read_verified_blob called with a non-sha256 digest.
        // We test the internal helper directly since it is private-but-pub-in-tests.
        let result = blob_path_from_digest("sha512:abcd");
        assert!(result.is_err(), "should error on non-sha256 digest");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("sha256") || msg.contains("unsupported"),
            "error should mention sha256; got: {msg}"
        );
    }

    /// Line 148-151 (read_manifest): manifest entry missing 'digest' field.
    #[test]
    fn ingest_errors_when_manifest_entry_missing_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        // An image manifest entry with no 'digest' key.
        let index = br#"{
          "schemaVersion": 2,
          "manifests": [
            {"mediaType":"application/vnd.oci.image.manifest.v1+json","size":4,"platform":{"os":"linux","architecture":"amd64"}}
          ]
        }"#;
        let archive = build_raw_tar(
            tmp.path(),
            "manifest_no_digest.tar",
            &[("index.json", index)],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(
            result.is_err(),
            "must error when manifest entry lacks digest"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("digest") || msg.contains("manifest"),
            "error should mention missing digest; got: {msg}"
        );
    }

    /// Lines 35-48: manifest missing 'config' or 'layers' fields.
    #[test]
    fn ingest_errors_on_manifest_missing_config_field() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));

        // Build an archive with a manifest that has no 'config' field.
        let manifest_json = br#"{"schemaVersion":2,"layers":[]}"#;
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_json)));
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();

        let index = format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{},"platform":{{"os":"linux","architecture":"amd64"}}}}]}}"#,
            manifest_json.len()
        );

        let archive = build_raw_tar(
            tmp.path(),
            "manifest_no_config.tar",
            &[
                ("index.json", index.as_bytes()),
                (&format!("blobs/sha256/{manifest_hex}"), manifest_json),
            ],
        );
        let result = ingest_oci_archive(&paths, &archive);
        assert!(result.is_err(), "must error when manifest lacks 'config'");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("config") || msg.contains("manifest"),
            "error should mention config field; got: {msg}"
        );
    }

    /// Single-manifest path with an explicit linux/amd64 platform: verify the
    /// multi-manifest amd64-selection success path (lines 117-134) is exercised.
    #[test]
    fn ingest_selects_amd64_from_multi_manifest_index() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));

        // Build a real manifest+blobs, then wrap in a multi-manifest index where
        // only the amd64 entry points to real content; the arm64 entry is a stub
        // with a fake digest (we never try to read it since amd64 wins).
        let layer_bytes = make_gzip_layer("/f", b"data");
        let layer_digest = format!("sha256:{}", hex::encode(Sha256::digest(&layer_bytes)));
        let layer_hex = layer_digest.strip_prefix("sha256:").unwrap();

        let config_bytes = make_config_json();
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(&config_bytes)));
        let config_hex = config_digest.strip_prefix("sha256:").unwrap();

        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{layer_digest}","size":{}}}]}}"#,
            config_bytes.len(),
            layer_bytes.len()
        );
        let manifest_bytes = manifest_json.as_bytes();
        let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_bytes)));
        let manifest_hex = manifest_digest.strip_prefix("sha256:").unwrap();

        // The arm64 stub — digest is fake; it must never be fetched.
        let arm64_digest =
            "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

        let index = format!(
            r#"{{
  "schemaVersion": 2,
  "manifests": [
    {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{},"platform":{{"os":"linux","architecture":"amd64"}}}},
    {{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{arm64_digest}","size":4,"platform":{{"os":"linux","architecture":"arm64"}}}}
  ]
}}"#,
            manifest_bytes.len()
        );

        let archive = build_raw_tar(
            tmp.path(),
            "multi_amd64_select.tar",
            &[
                ("index.json", index.as_bytes()),
                (&format!("blobs/sha256/{manifest_hex}"), manifest_bytes),
                (&format!("blobs/sha256/{config_hex}"), &config_bytes),
                (&format!("blobs/sha256/{layer_hex}"), &layer_bytes),
            ],
        );

        // This test exercises the amd64-selection branch but reaches
        // publish_image which needs mkfs.erofs. Skip if unavailable.
        if which::which("mkfs.erofs").is_err() {
            eprintln!("SKIP: mkfs.erofs not installed");
            return;
        }
        let result = ingest_oci_archive(&paths, &archive);
        assert!(
            result.is_ok(),
            "multi-manifest amd64 selection should succeed; err={result:?}"
        );
    }
}
