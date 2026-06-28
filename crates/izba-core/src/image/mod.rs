//! Container image handling: registry pull, OCI layer flattening, erofs
//! build, and the content-addressed cache tying them together.

pub mod erofs;
pub mod flatten;
pub mod ingest;
pub mod pull;
pub mod runtime_config;
pub mod store;
pub mod tags;

pub use flatten::flatten_layers;
pub use ingest::ingest_oci_archive;
pub use store::ImageStore;
pub use tags::{resolve_tag, set_tag, validate_tag};

use crate::paths::Paths;
use anyhow::{Context, Result};
use std::fs;
use std::io::Read;

/// Pull the raw bytes of `etc/passwd` and `etc/group` out of a flattened image
/// tar. Matches the canonical paths regardless of a leading `/` or `./`;
/// last entry wins (the flattened tar is lowest-layer-first, so a higher layer's
/// passwd appears later and overrides). Only regular-file entries are read.
#[allow(clippy::type_complexity)]
fn extract_user_dbs(merged_tar: &std::path::Path) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let f = fs::File::open(merged_tar)
        .with_context(|| format!("failed to open {}", merged_tar.display()))?;
    let mut ar = tar::Archive::new(f);
    let mut passwd = None;
    let mut group = None;
    for entry in ar.entries().context("reading merged tar")? {
        let mut entry = entry.context("reading merged tar entry")?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path().context("entry path")?;
        let norm = path
            .to_string_lossy()
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        let slot = match norm.as_str() {
            "etc/passwd" => &mut passwd,
            "etc/group" => &mut group,
            _ => continue,
        };
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut buf).context("reading user db entry")?;
        *slot = Some(buf); // last-wins
    }
    Ok((passwd, group))
}

/// Shared tail: flatten the ordered layer readers into one tar, build the
/// erofs, and publish under `digest` along with `config_json` + `image_ref`.
/// Returns the canonical digest (echoes `digest`). Idempotent: if the store
/// already has `digest` cached, it is a no-op returning `digest`.
#[mutants::skip] // reason: flatten→erofs→publish; needs mkfs.erofs tooling, exercised by e2e
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
        // Capture the image's user databases for host-side symbolic-USER
        // resolution (issue #96) before the merged tar is discarded.
        let (passwd, group) = extract_user_dbs(&merged_tar)?;
        if let Some(p) = &passwd {
            fs::write(staging.join("passwd"), p)?;
        }
        if let Some(g) = &group {
            fs::write(staging.join("group"), g)?;
        }
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
    if let Some(p) = image_ref.strip_prefix("oci-archive:") {
        return ingest_oci_archive(paths, std::path::Path::new(p));
    }
    // Local tag dispatch: a local tag shadows a registry ref only when the
    // tag resolves AND the digest is cached (prevents a stale evicted tag from
    // silently winning over a fresh registry pull).
    if let Some(digest) = tags::resolve_tag(paths, image_ref)? {
        if ImageStore::new(paths).is_cached(&digest) {
            return Ok(digest);
        }
    }
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

    // ── ensure_image tag dispatch ─────────────────────────────────────────────

    /// Seed a fake cached entry (just the rootfs.erofs sentinel file) for
    /// `digest` without running mkfs.erofs.
    fn seed_cached_entry(paths: &Paths, digest: &str) {
        let dir = paths.image_dir(digest);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("rootfs.erofs"), b"fake erofs").unwrap();
    }

    /// When a local tag resolves AND the digest is cached, `ensure_image`
    /// must return that digest without touching the registry.
    #[test]
    fn ensure_image_returns_tagged_digest_when_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let digest = "sha256:".to_string() + &"c".repeat(64);

        // Seed: tag + cached store entry.
        set_tag(&paths, "myimg", &digest).unwrap();
        seed_cached_entry(&paths, &digest);

        let got = ensure_image(&paths, "myimg").unwrap();
        assert_eq!(got, digest);
    }

    /// When a local tag exists but its digest is NOT cached, `ensure_image`
    /// must fall through to the registry path.  We assert fall-through by
    /// passing an invalid (non-resolvable) tag string that would only fail via
    /// registry resolution (not via local tag lookup).
    ///
    /// Strategy: register a tag pointing at an uncached digest, then call
    /// `ensure_image` with the tag name.  The local tag IS found, but
    /// `is_cached` returns false, so the code falls through to `pull::resolve`.
    /// The registry attempt will fail (no network / invalid ref) — we just
    /// check it does NOT return the tagged digest directly.
    #[test]
    fn ensure_image_falls_through_when_tag_not_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(tmp.path().join("izba"));
        let digest = "sha256:".to_string() + &"d".repeat(64);

        // Tag exists but digest is NOT seeded into the store.
        set_tag(&paths, "notcached", &digest).unwrap();

        // Must NOT return the tagged digest; must attempt registry (and fail).
        let result = ensure_image(&paths, "notcached");
        assert!(
            result.is_err(),
            "expected registry error on fall-through, got: {result:?}"
        );
    }

    #[test]
    fn extract_user_dbs_reads_passwd_handles_paths_and_last_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let tar_path = tmp.path().join("merged.tar");
        {
            let f = fs::File::create(&tar_path).unwrap();
            let mut b = tar::Builder::new(f);
            // `Builder::append_data` rejects absolute paths (tar crate policy),
            // so we set the path bytes directly in the GNU header and use
            // `append` to write raw header bytes without re-validation.
            let add_raw = |b: &mut tar::Builder<fs::File>, path: &str, data: &[u8]| {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(0o644);
                let name_bytes = path.as_bytes();
                let gnu = h.as_gnu_mut().unwrap();
                let len = gnu.name.len().min(name_bytes.len());
                gnu.name[..len].copy_from_slice(&name_bytes[..len]);
                h.set_cksum();
                b.append(&h, std::io::Cursor::new(data)).unwrap();
            };
            add_raw(&mut b, "etc/passwd", b"root:x:0:0::/root:/bin/sh\n");
            // a later, absolute-prefixed entry for the same logical path wins
            add_raw(
                &mut b,
                "/etc/passwd",
                b"node:x:1000:1000::/home/node:/bin/sh\n",
            );
            b.finish().unwrap();
        }
        let (passwd, group) = extract_user_dbs(&tar_path).unwrap();
        let passwd = String::from_utf8(passwd.expect("passwd present")).unwrap();
        assert!(
            passwd.contains("node:x:1000"),
            "last-wins entry must win: {passwd}"
        );
        assert!(group.is_none(), "no /etc/group entry -> None");
    }

    /// `ensure_image("oci-archive:<path>")` must route to `ingest_oci_archive`
    /// and return the same digest as a direct call.
    #[test]
    fn ensure_image_routes_oci_archive_prefix() {
        if which::which("mkfs.erofs").is_err() {
            eprintln!("SKIP: mkfs.erofs not installed");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let archive =
            crate::image::ingest::tests::build_oci_archive_fixture(tmp.path(), "/etc/x", b"hi");

        // Direct ingest into one store.
        let paths_direct = Paths::with_root(tmp.path().join("izba_direct"));
        let digest_direct = ingest_oci_archive(&paths_direct, &archive).unwrap();

        // ensure_image with the oci-archive: prefix into a fresh store.
        let paths_via = Paths::with_root(tmp.path().join("izba_via"));
        let image_ref = format!("oci-archive:{}", archive.display());
        let digest_via = ensure_image(&paths_via, &image_ref).unwrap();

        assert_eq!(
            digest_direct, digest_via,
            "ensure_image(oci-archive:...) must return the same digest as ingest_oci_archive"
        );
    }
}
