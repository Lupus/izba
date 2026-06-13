//! Guest trust anchor: bakes the izba root CA into the guest trust store so
//! workload tools (curl/git/node/python) trust izbad's MITM leaf certs.
//!
//! izbad delivers the CA PEM to the guest as a read-only virtiofs share tagged
//! [`TRUST_TAG`], mounted at [`TRUST_MOUNT`]. At boot, init copies the CA into
//! the writable overlay (the guest's real `/etc`) at the canonical paths and
//! exec'd workloads get the CA-bundle env vars pointing there.
//!
//! Only the pure helpers ([`build_combined_bundle`], [`trust_env_pairs`]) live
//! here and are unit-tested; the boot glue that performs filesystem I/O is
//! `write_trust_anchor()` in `main.rs` (per the crate's no-unit-test-on-glue
//! convention), and the per-exec env defaulting is in `exec.rs`.

/// virtiofs tag of the read-only CA share izbad attaches (host side builds it).
pub const TRUST_TAG: &str = "izba-trust";

/// Guest mountpoint of the [`TRUST_TAG`] share, mirroring `workspace`'s fixed
/// mountpoint convention. Mounted under `/rootfs` by the rootfs plan.
pub const TRUST_MOUNT: &str = "/izba-trust";

/// Filename of the CA PEM inside the share. The host side must write this name.
pub const CA_FILE: &str = "ca.pem";

/// Post-chroot guest path of the CA-alone PEM init writes into the overlay.
pub const GUEST_CA_PEM: &str = "/etc/izba/ca.pem";

/// Post-chroot guest path of the combined (CA + system roots) bundle.
pub const GUEST_CA_BUNDLE: &str = "/etc/izba/ca-bundle.pem";

/// Returns `ca_pem` concatenated with the system bundle when present (CA first,
/// newline-separated), or just `ca_pem` when `None`.
///
/// The izba CA goes FIRST so a tool that stops at the first matching anchor
/// still sees it; the system roots follow so existing public TLS keeps working.
pub fn build_combined_bundle(ca_pem: &str, system_pem: Option<&str>) -> String {
    match system_pem {
        Some(system) => {
            let mut out = String::with_capacity(ca_pem.len() + 1 + system.len());
            out.push_str(ca_pem);
            if !ca_pem.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(system);
            out
        }
        None => ca_pem.to_string(),
    }
}

/// The canonical CA-bundle env vars and their post-chroot guest paths.
///
/// `NODE_EXTRA_CA_CERTS`/`DENO_CERT` take the CA alone (they ADD to the runtime's
/// built-in roots); the rest take the combined bundle (they REPLACE the trust
/// set, so they must include the system roots).
pub fn trust_env_pairs() -> [(&'static str, &'static str); 6] {
    [
        ("NODE_EXTRA_CA_CERTS", GUEST_CA_PEM),
        ("DENO_CERT", GUEST_CA_PEM),
        ("SSL_CERT_FILE", GUEST_CA_BUNDLE),
        ("REQUESTS_CA_BUNDLE", GUEST_CA_BUNDLE),
        ("CURL_CA_BUNDLE", GUEST_CA_BUNDLE),
        ("GIT_SSL_CAINFO", GUEST_CA_BUNDLE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_bundle_ca_only_when_no_system() {
        assert_eq!(
            build_combined_bundle("CA-PEM\n", None),
            "CA-PEM\n",
            "with no system bundle the result is the CA verbatim"
        );
    }

    #[test]
    fn combined_bundle_ca_first_then_system() {
        assert_eq!(
            build_combined_bundle("CA-PEM\n", Some("SYS-ROOTS\n")),
            "CA-PEM\nSYS-ROOTS\n",
            "CA precedes the system roots, newline-separated"
        );
    }

    #[test]
    fn combined_bundle_inserts_separator_when_ca_unterminated() {
        // A CA PEM that does not end in a newline must not glue onto the first
        // system cert line.
        assert_eq!(
            build_combined_bundle("CA-PEM", Some("SYS-ROOTS\n")),
            "CA-PEM\nSYS-ROOTS\n"
        );
    }

    #[test]
    fn trust_env_pairs_are_the_canonical_six() {
        assert_eq!(
            trust_env_pairs(),
            [
                ("NODE_EXTRA_CA_CERTS", "/etc/izba/ca.pem"),
                ("DENO_CERT", "/etc/izba/ca.pem"),
                ("SSL_CERT_FILE", "/etc/izba/ca-bundle.pem"),
                ("REQUESTS_CA_BUNDLE", "/etc/izba/ca-bundle.pem"),
                ("CURL_CA_BUNDLE", "/etc/izba/ca-bundle.pem"),
                ("GIT_SSL_CAINFO", "/etc/izba/ca-bundle.pem"),
            ]
        );
    }
}
