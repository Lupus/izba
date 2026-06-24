//! BuildKit builder-image constants and lazy-pull helper.
//!
//! The image ref uses a sha256 digest pin so the content is immutable even when
//! pulled by tag. The pinned digest addresses the **multi-arch OCI index**;
//! `image::ensure_image` → `pull::resolve` always resolves to the linux/amd64
//! manifest from it (izba guests are always linux/amd64 microVMs).
//!
//! ## Re-pinning
//! ```text
//! curl -s -I \
//!   "https://registry-1.docker.io/v2/moby/buildkit/manifests/v0.19.0" \
//!   -H "Authorization: Bearer $(curl -s \
//!     'https://auth.docker.io/token?service=registry.docker.io&scope=repository:moby/buildkit:pull' \
//!     | jq -r .token)" \
//!   -H "Accept: application/vnd.oci.image.index.v1+json" \
//!   | grep -i docker-content-digest
//! ```

use crate::image;
use crate::paths::Paths;
use anyhow::Result;

/// Sha-pinned BuildKit builder image (moby/buildkit v0.19.0).
///
/// The `@sha256:` suffix pins the multi-arch OCI index digest, making this
/// reference content-addressable and immune to tag mutation. `docker.io` is
/// the canonical registry prefix accepted by `oci_client::Reference::parse`.
/// Re-pin with the curl recipe in the module-level doc comment.
pub const BUILDER_IMAGE_REF: &str =
    "docker.io/moby/buildkit@sha256:14aa1b4dd92ea0a4cd03a54d0c6079046ea98cd0c0ae6176bdd7036ba370cbbe";

/// Ensure the BuildKit builder image is in the local store, lazy-pulling on
/// first use. Returns its store (config) digest.
///
/// The live pull needs egress + DNS and runs under the build-network policy
/// when invoked from the build flow. Unit tests must not call this function
/// directly; the e2e suite exercises the full pull path.
///
/// `#[mutants::skip]`: every non-cached path here performs real registry I/O —
/// it delegates entirely to `image::ensure_image` which is itself
/// `#[mutants::skip]` for the same reason.
#[mutants::skip]
pub fn ensure_builder_image(paths: &Paths) -> Result<String> {
    image::ensure_image(paths, BUILDER_IMAGE_REF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_client::Reference;

    /// `BUILDER_IMAGE_REF` must contain a `@sha256:` digest pin with a 64-hex
    /// hash, and the `oci_client` reference parser must accept it cleanly.
    #[test]
    fn builder_ref_is_sha_pinned() {
        // Assert the constant contains the @sha256: pin marker.
        assert!(
            BUILDER_IMAGE_REF.contains("@sha256:"),
            "BUILDER_IMAGE_REF must contain @sha256: pin: {BUILDER_IMAGE_REF}"
        );

        // Extract and validate the 64-hex digest portion.
        let digest_hex = BUILDER_IMAGE_REF
            .split("@sha256:")
            .nth(1)
            .expect("@sha256: present (checked above)");
        assert_eq!(
            digest_hex.len(),
            64,
            "sha256 digest must be exactly 64 hex chars, got {}: {digest_hex:?}",
            digest_hex.len()
        );
        assert!(
            digest_hex.chars().all(|c| c.is_ascii_hexdigit()),
            "digest must be all hex digits: {digest_hex:?}"
        );

        // The oci_client Reference parser must accept the full ref string.
        let reference: Reference = BUILDER_IMAGE_REF
            .parse()
            .expect("BUILDER_IMAGE_REF must parse as a valid OCI reference");

        // Parsed digest must match the pinned sha256:… string.
        let expected_digest = format!("sha256:{digest_hex}");
        assert_eq!(
            reference.digest(),
            Some(expected_digest.as_str()),
            "parsed digest does not match pinned digest"
        );

        // Registry must be docker.io (the canonical docker hub prefix).
        assert_eq!(
            reference.registry(),
            "docker.io",
            "registry should be docker.io"
        );

        // Repository must be moby/buildkit.
        assert_eq!(
            reference.repository(),
            "moby/buildkit",
            "repository should be moby/buildkit"
        );
    }
}
