//! Guest trust anchor: bakes the izba root CA — and any host-installed extra
//! roots (#283) — into the guest trust store so workload tools trust izbad's
//! MITM leaves AND the operator's private PKI. Delivered for EVERY sandbox,
//! bare or enforcing: a bare sandbox's TLS goes end-to-end, so the guest
//! store is the only place a corporate root can live.
//!
//! izbad delivers the CA PEM to the guest as a read-only virtiofs share tagged
//! [`TRUST_TAG`], mounted at [`TRUST_MOUNT`]. At boot, init copies the CA into
//! the writable overlay (the guest's real `/etc`) at the canonical paths and
//! exec'd workloads get the CA-bundle env vars pointing there.
//!
//! Only the pure helpers ([`build_combined_bundle`], [`build_anchor_pem`],
//! [`trust_env_pairs`]) live here and are unit-tested; the boot glue that
//! performs filesystem I/O is
//! `write_trust_anchor()` in `main.rs` (per the crate's no-unit-test-on-glue
//! convention), and the per-exec env defaulting is in `exec.rs`.

/// virtiofs tag of the read-only CA share izbad attaches (host side builds it).
pub const TRUST_TAG: &str = "izba-trust";

/// Guest mountpoint of the [`TRUST_TAG`] share, mirroring `workspace`'s fixed
/// mountpoint convention. Mounted under `/rootfs` by the rootfs plan.
pub const TRUST_MOUNT: &str = "/izba-trust";

/// Filename of the CA PEM inside the share. The host side must write this name.
pub const CA_FILE: &str = "ca.pem";

/// Filename of the OPTIONAL host-installed extra roots inside the share
/// (`<data>/trust/extra/*.pem` concatenated by `sandbox::start`, #283).
/// Absent when the operator installed none.
pub const EXTRA_FILE: &str = "extra.pem";

/// Post-chroot guest path of the anchors (izba CA + any host extra roots)
/// init writes into the overlay.
pub const GUEST_CA_PEM: &str = "/etc/izba/ca.pem";

/// Post-chroot guest path of the combined (anchors + system roots) bundle.
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

/// The izba-added anchors: the izba CA first, then the host's extra roots
/// (already newline-joined by the host side). This is what lands in
/// `/etc/izba/ca.pem` — `NODE_EXTRA_CA_CERTS`/`DENO_CERT` read THIS file, so
/// the corporate roots must be in it, not only in the combined bundle.
pub fn build_anchor_pem(ca_pem: &str, extra_pem: Option<&str>) -> String {
    build_combined_bundle(ca_pem, extra_pem)
}

/// Marks the start of the izba-managed block this crate rewrites in the
/// canonical system CA bundle (`/etc/ssl/certs/ca-certificates.crt` etc.) on
/// every boot. See [`replace_managed_block`] for why a marked, replaced block
/// — not an append — is required: the canonical bundle lives on the
/// sandbox's PERSISTENT overlay, so an append would (a) never revoke a CA the
/// operator removed from `<data>/trust/extra/` and (b) grow the file with a
/// duplicate copy of the anchors every single boot.
pub const MANAGED_BEGIN: &str =
    "# BEGIN izba-managed trust anchors (rewritten on every boot; do not edit)";

/// Marks the end of the izba-managed block. See [`MANAGED_BEGIN`].
pub const MANAGED_END: &str = "# END izba-managed trust anchors";

/// Returns `existing` with any previous `MANAGED_BEGIN…MANAGED_END` block
/// (inclusive of its trailing newline) removed, then — when `anchors` is
/// non-empty — exactly one fresh block appended (a separating newline first,
/// if the text so far doesn't already end with one).
///
/// Text outside PEM blocks (comment lines, blank lines) is tolerated by every
/// bundle consumer (OpenSSL, curl, Python, Node), which is what makes marker
/// comments a safe way to carve out and replace an izba-owned region of an
/// otherwise foreign file. A truncated previous block (a `MANAGED_BEGIN` with
/// no matching `MANAGED_END`, e.g. from a killed boot mid-write) is treated
/// as running to EOF, so it is fully removed rather than left dangling.
pub fn replace_managed_block(existing: &str, anchors: &str) -> String {
    let (before, tail) = match existing.find(MANAGED_BEGIN) {
        Some(begin_pos) => {
            let before = &existing[..begin_pos];
            match existing[begin_pos..].find(MANAGED_END) {
                Some(end_rel) => {
                    let mut tail_start = begin_pos + end_rel + MANAGED_END.len();
                    if existing.as_bytes().get(tail_start) == Some(&b'\n') {
                        tail_start += 1;
                    }
                    (before, &existing[tail_start..])
                }
                // Truncated: no END, so everything from BEGIN to EOF is the
                // old (broken) block.
                None => (before, ""),
            }
        }
        None => (existing, ""),
    };

    let mut out = String::with_capacity(before.len() + tail.len() + anchors.len() + 64);
    out.push_str(before);
    out.push_str(tail);

    if !anchors.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(MANAGED_BEGIN);
        out.push('\n');
        out.push_str(anchors);
        if !anchors.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(MANAGED_END);
        out.push('\n');
    }
    out
}

/// The canonical CA-bundle env vars and their post-chroot guest paths.
///
/// `NODE_EXTRA_CA_CERTS`/`DENO_CERT` take the anchors — izba CA + any host
/// extra roots — (they ADD to the runtime's built-in roots); the rest take
/// the combined bundle (they REPLACE the trust set, so they must include the
/// system roots).
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

    #[test]
    fn anchor_pem_is_the_ca_alone_without_extras() {
        assert_eq!(build_anchor_pem("CA-PEM\n", None), "CA-PEM\n");
    }

    #[test]
    fn anchor_pem_is_ca_then_extras_newline_separated() {
        assert_eq!(
            build_anchor_pem("CA-PEM", Some("CORP-A\nCORP-B\n")),
            "CA-PEM\nCORP-A\nCORP-B\n",
            "izba CA first, then every extra root in shipped order"
        );
    }

    /// The AC's ordering contract end to end: izba CA, each extra PEM in
    /// order, then the system roots.
    #[test]
    fn combined_bundle_is_ca_then_extras_then_system() {
        let anchors = build_anchor_pem("CA-PEM\n", Some("CORP-A\nCORP-B\n"));
        assert_eq!(
            build_combined_bundle(&anchors, Some("SYS-ROOTS\n")),
            "CA-PEM\nCORP-A\nCORP-B\nSYS-ROOTS\n"
        );
    }

    #[test]
    fn extra_file_name_matches_the_host_contract() {
        assert_eq!(EXTRA_FILE, "extra.pem");
    }

    #[test]
    fn managed_block_appended_once_when_no_prior_block() {
        let existing = "SYSTEM ROOT CERT\n";
        let out = replace_managed_block(existing, "ANCHOR-PEM\n");
        assert_eq!(
            out,
            format!("SYSTEM ROOT CERT\n{MANAGED_BEGIN}\nANCHOR-PEM\n{MANAGED_END}\n")
        );
    }

    #[test]
    fn managed_block_is_idempotent() {
        let existing = "SYSTEM ROOT CERT\n";
        let once = replace_managed_block(existing, "ANCHOR-PEM\n");
        let twice = replace_managed_block(&once, "ANCHOR-PEM\n");
        assert_eq!(once, twice, "reapplying with the same anchors is a no-op");
    }

    #[test]
    fn managed_block_replaced_when_anchors_change_leaves_prefix_untouched() {
        let existing = "SYSTEM ROOT CERT\n";
        let old = replace_managed_block(existing, "OLD-ANCHOR\n");
        let new = replace_managed_block(&old, "NEW-ANCHOR\n");

        assert!(!new.contains("OLD-ANCHOR"), "old anchor content is gone");
        assert_eq!(
            new.matches(MANAGED_BEGIN).count(),
            1,
            "exactly one begin marker"
        );
        assert_eq!(
            new.matches(MANAGED_END).count(),
            1,
            "exactly one end marker"
        );
        assert!(
            new.starts_with(existing),
            "text before the block is untouched byte-for-byte"
        );
        assert_eq!(
            new,
            format!("SYSTEM ROOT CERT\n{MANAGED_BEGIN}\nNEW-ANCHOR\n{MANAGED_END}\n")
        );
    }

    #[test]
    fn managed_block_truncated_begin_without_end_is_removed() {
        // Simulates a killed boot mid-write: BEGIN present, END never written.
        let existing = format!("SYSTEM ROOT CERT\n{MANAGED_BEGIN}\nHALF-WRITTEN-ANCHOR\n");
        let out = replace_managed_block(&existing, "ANCHOR-PEM\n");
        assert!(!out.contains("HALF-WRITTEN-ANCHOR"));
        assert_eq!(
            out,
            format!("SYSTEM ROOT CERT\n{MANAGED_BEGIN}\nANCHOR-PEM\n{MANAGED_END}\n")
        );
    }

    #[test]
    fn managed_block_empty_anchors_removes_prior_block_and_appends_nothing() {
        let existing = "SYSTEM ROOT CERT\n";
        let with_block = replace_managed_block(existing, "ANCHOR-PEM\n");
        let removed = replace_managed_block(&with_block, "");
        assert_eq!(removed, existing);
    }

    #[test]
    fn managed_block_inserts_separator_when_existing_has_no_trailing_newline() {
        let existing = "SYSTEM ROOT CERT (no trailing newline)";
        let out = replace_managed_block(existing, "ANCHOR-PEM\n");
        assert_eq!(
            out,
            format!(
                "SYSTEM ROOT CERT (no trailing newline)\n{MANAGED_BEGIN}\nANCHOR-PEM\n{MANAGED_END}\n"
            )
        );
    }
}
