//! Host-installed extra CA roots (#283):
//! `<data>/trust/extra/*.pem|*.crt|*.cer|*.der` (PEM text or raw DER).
//!
//! One loader, two consumers, so the guest and izbad can never disagree about
//! which roots are trusted:
//! - `sandbox::start` ships the loaded CERTIFICATES to the guest as
//!   `trust/extra.pem` on the read-only `izba-trust` share (guest side: next
//!   sandbox start);
//! - `daemon::server::build_mitm_runtime` adds the same parsed certs to
//!   izbad's upstream verifier on top of webpki-roots (izbad side: daemon
//!   start).
//!
//! The guest text is RE-SERIALIZED from the parsed certificates, never copied
//! from the file: that is what makes "one loader, no disagreement" literal,
//! and it is a security boundary, not a nicety. `pem_slice_iter` silently
//! skips non-CERTIFICATE sections, so a key+cert file (exactly the shape of
//! `~/.mitmproxy/mitmproxy-ca.pem`) used to ship a CA PRIVATE KEY into every
//! hostile guest. Such a file is now refused outright, and even if a new
//! section type appears, only certificates can ever leave this module.
//!
//! The directory is host-only authority, like `policy.yaml` (F-30): it is
//! never shared into a VM — only a per-sandbox copy of the certificates is.

use std::path::Path;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer};

/// File extensions the loader picks up (case-insensitive). `cer`/`der` are
/// there because a Windows "export certificate" produces raw DER under those
/// names by default. Anything else in the directory (README, `.bak`,
/// dotfiles, subdirectories) is ignored.
pub const EXTRA_CA_EXTENSIONS: [&str; 4] = ["pem", "crt", "cer", "der"];

/// One file from the extra-CA directory.
///
/// Deliberately holds NO copy of the file text: the only thing that leaves
/// this module is the parsed certificate list, so nothing else in the file
/// (a private key, a comment, an unknown PEM section) can reach a guest.
#[derive(Debug, Clone)]
pub struct ExtraCaFile {
    /// File name inside the directory — the ordering key and what
    /// `izba daemon status` prints.
    pub name: String,
    /// Every certificate parsed from the file, in file order: what izbad
    /// trusts and what the guest receives.
    pub certs: Vec<CertificateDer<'static>>,
}

/// True when `text` carries any `-----BEGIN … PRIVATE KEY-----` header
/// (`PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`,
/// `ENCRYPTED PRIVATE KEY`, …). Line-oriented so a certificate that merely
/// mentions the phrase in a comment is not misread as one.
fn contains_private_key(text: &str) -> bool {
    text.lines().any(|line| {
        line.trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
            .is_some_and(|label| label.trim_end().ends_with("PRIVATE KEY"))
    })
}

/// One certificate as standard PEM: 64-column base64 between the canonical
/// header/footer, newline-terminated.
fn cert_to_pem(der: &CertificateDer<'_>) -> String {
    use base64ct::{Base64, Encoding};
    let b64 = Base64::encode_string(der.as_ref());
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // `chunk` is a slice of an ASCII base64 string, so it is always UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Parse one extra-CA file's bytes into certificates, or fail naming `path`.
///
/// A leading `0x30` (ASN.1 SEQUENCE) means the whole file is ONE DER
/// certificate; otherwise the bytes must be UTF-8 PEM text carrying at least
/// one CERTIFICATE block and NO private key.
fn parse_extra_ca_file(path: &Path, bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    if bytes.first() == Some(&0x30) {
        let cert = CertificateDer::from(bytes.to_vec());
        validate_anchor(path, &cert)?;
        return Ok(vec![cert]);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        anyhow::anyhow!(
            "extra CA file {}: not PEM text and not a DER certificate \
             (convert with `openssl x509 -inform der -in {} -out {}.pem`)",
            path.display(),
            path.display(),
            path.display()
        )
    })?;
    // Refuse a key+cert bundle rather than half-ingesting it: `pem_slice_iter`
    // would silently skip the key, and the pre-fix guest shipper copied the
    // file text verbatim — leaking the CA private key into every sandbox.
    if contains_private_key(text) {
        bail!(
            "extra CA file {}: contains a private key — install only the certificate \
             (e.g. mitmproxy-ca-cert.pem, or `openssl x509 -in {} -out {}.crt`)",
            path.display(),
            path.display(),
            path.display()
        );
    }
    let mut certs = Vec::new();
    for cert in CertificateDer::pem_slice_iter(text.as_bytes()) {
        let cert = cert
            .map_err(|e| anyhow::anyhow!("extra CA file {}: invalid PEM: {e}", path.display()))?;
        validate_anchor(path, &cert)?;
        certs.push(cert);
    }
    if certs.is_empty() {
        bail!(
            "extra CA file {}: no CERTIFICATE blocks found (expected PEM or DER)",
            path.display()
        );
    }
    Ok(certs)
}

/// PEM framing alone proves nothing about the bytes inside: a well-formed
/// block of garbage base64 parses as a "certificate". Validate it the way
/// izbad will consume it — as a trust anchor — so a corrupt file is refused
/// HERE, with its name, not skipped later at daemon start.
fn validate_anchor(path: &Path, cert: &CertificateDer<'static>) -> Result<()> {
    rustls::RootCertStore::empty()
        .add(cert.clone())
        .map_err(|e| {
            anyhow::anyhow!(
                "extra CA file {}: not a valid X.509 certificate: {e}",
                path.display()
            )
        })?;
    Ok(())
}

/// Load every [`EXTRA_CA_EXTENSIONS`] file under `dir`, sorted by file name.
/// A missing directory is simply "no extra CAs". A file that parses to zero
/// certificates, contains a corrupt block, is neither PEM nor DER, or carries
/// a private key is a HARD error naming the file: a silently skipped
/// corporate CA would reproduce exactly the "my CA doesn't work" confusion
/// this feature exists to remove.
pub fn load_extra_cas(dir: &Path) -> Result<Vec<ExtraCaFile>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading extra CA dir {}", dir.display())),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("listing extra CA dir {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        if ext
            .as_deref()
            .is_some_and(|e| EXTRA_CA_EXTENSIONS.contains(&e))
        {
            names.push(name.to_string());
        }
    }
    names.sort();

    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let path = dir.join(&name);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading extra CA file {}", path.display()))?;
        let certs = parse_extra_ca_file(&path, &bytes)?;
        out.push(ExtraCaFile { name, certs });
    }
    Ok(out)
}

/// The text shipped to the guest as `trust/extra.pem`: every LOADED
/// CERTIFICATE re-serialized as standard PEM, in load order. Built from the
/// parsed certs and never from the file text, so the guest receives exactly
/// the anchors izbad trusts — no private key, no comments, nothing else the
/// operator's file happened to contain. Empty when there are no files (the
/// caller then removes a stale `extra.pem` instead).
pub fn guest_extra_pem(files: &[ExtraCaFile]) -> String {
    let mut out = String::new();
    for f in files {
        for cert in &f.certs {
            out.push_str(&cert_to_pem(cert));
        }
    }
    out
}

/// webpki-roots (the Mozilla bundle production izbad always trusted) PLUS
/// every extra cert, in load order. Only ever widens over the baseline.
pub fn upstream_root_store(extra: &[ExtraCaFile]) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for file in extra {
        for cert in &file.certs {
            // `load_extra_cas` already validated every cert through this
            // same `add`, so the error branch is defensive only — log rather
            // than panic inside the daemon.
            if let Err(e) = roots.add(cert.clone()) {
                eprintln!(
                    "izbad: extra CA file {}: skipping certificate: {e}",
                    file.name
                );
            }
        }
    }
    roots
}

/// izbad's upstream `ClientConfig` (ALPN http/1.1) trusting
/// [`upstream_root_store`]. Built once at daemon start — a changed directory
/// is picked up by restarting the daemon (`izba daemon stop`).
pub fn upstream_client_config(extra: &[ExtraCaFile]) -> std::sync::Arc<rustls::ClientConfig> {
    crate::daemon::egress::mitm::upstream_client_config(upstream_root_store(extra))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA_A: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

    /// A real, parseable CA PEM (rcgen via IzbaCa); tests that only need
    /// ordering use the fake `CA_A` text and never parse it.
    fn real_ca_pem() -> String {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::daemon::egress::mitm::IzbaCa::generate()
            .unwrap()
            .cert_pem()
            .to_string()
    }

    #[test]
    fn missing_dir_loads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let files = load_extra_cas(&dir.path().join("absent")).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn loads_pem_and_crt_sorted_by_name_ignoring_others() {
        let dir = tempfile::tempdir().unwrap();
        let ca = real_ca_pem();
        std::fs::write(dir.path().join("zeta.pem"), &ca).unwrap();
        std::fs::write(dir.path().join("alpha.CRT"), &ca).unwrap();
        std::fs::write(dir.path().join("README.md"), "not a cert").unwrap();
        std::fs::write(dir.path().join(".hidden.pem"), &ca).unwrap();
        std::fs::create_dir(dir.path().join("sub.pem")).unwrap();
        let files = load_extra_cas(dir.path()).unwrap();
        let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["alpha.CRT", "zeta.pem"]);
        assert_eq!(files[0].certs.len(), 1);
    }

    #[test]
    fn counts_every_cert_in_a_multi_cert_file() {
        let dir = tempfile::tempdir().unwrap();
        let ca = real_ca_pem();
        std::fs::write(dir.path().join("chain.pem"), format!("{ca}{ca}")).unwrap();
        let files = load_extra_cas(dir.path()).unwrap();
        assert_eq!(files[0].certs.len(), 2);
    }

    #[test]
    fn a_file_with_no_certificates_is_an_error_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.pem"), "just text\n").unwrap();
        let err = load_extra_cas(dir.path()).unwrap_err().to_string();
        assert!(err.contains("empty.pem"), "{err}");
        assert!(err.contains("no CERTIFICATE"), "{err}");
    }

    #[test]
    fn a_corrupt_block_is_an_error_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.pem"), CA_A).unwrap();
        let err = load_extra_cas(dir.path()).unwrap_err().to_string();
        assert!(err.contains("bad.pem"), "{err}");
    }

    /// Every block is newline-terminated, so two files never glue onto one
    /// line and the guest bundle stays well-formed however the operator's
    /// files were (or were not) terminated.
    #[test]
    fn guest_extra_pem_emits_one_terminated_block_per_cert_in_order() {
        let dir = tempfile::tempdir().unwrap();
        // b.pem is written WITHOUT a trailing newline; a.pem with two.
        std::fs::write(dir.path().join("a.pem"), format!("{}\n", real_ca_pem())).unwrap();
        std::fs::write(dir.path().join("b.pem"), real_ca_pem().trim_end()).unwrap();
        let files = load_extra_cas(dir.path()).unwrap();
        let out = guest_extra_pem(&files);
        assert_eq!(out.matches("-----BEGIN CERTIFICATE-----\n").count(), 2);
        assert_eq!(out.matches("-----END CERTIFICATE-----\n").count(), 2);
        assert!(!out.contains("\n\n"), "no blank lines: {out}");
        assert!(out.ends_with("-----END CERTIFICATE-----\n"), "{out}");
        assert_eq!(guest_extra_pem(&[]), "");
    }

    /// 64-column base64, the canonical width every consumer expects.
    #[test]
    fn guest_extra_pem_wraps_base64_at_64_columns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.pem"), real_ca_pem()).unwrap();
        let out = guest_extra_pem(&load_extra_cas(dir.path()).unwrap());
        let body: Vec<&str> = out.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(body.len() > 1, "{out}");
        for line in &body[..body.len() - 1] {
            assert_eq!(line.len(), 64, "{out}");
        }
        assert!(body[body.len() - 1].len() <= 64, "{out}");
    }

    #[test]
    fn upstream_roots_are_webpki_plus_every_extra_cert() {
        let ca = real_ca_pem();
        let files = vec![ExtraCaFile {
            name: "corp.pem".into(),
            certs: CertificateDer::pem_slice_iter(format!("{ca}{ca}").as_bytes())
                .map(|c| c.unwrap())
                .collect(),
        }];
        let roots = upstream_root_store(&files);
        assert_eq!(
            roots.len(),
            webpki_roots::TLS_SERVER_ROOTS.len() + 2,
            "webpki baseline plus both extra certs"
        );
        assert_eq!(
            upstream_root_store(&[]).len(),
            webpki_roots::TLS_SERVER_ROOTS.len(),
            "no extras ⇒ exactly the webpki baseline"
        );
    }

    /// The property izbad relies on: a leaf minted by an EXTRA CA verifies
    /// under the upstream config, and does NOT verify without that CA.
    #[test]
    fn upstream_config_verifies_a_leaf_signed_by_an_extra_ca_and_only_then() {
        use crate::daemon::egress::mitm::{server_config_with_resolver, CertCache, IzbaCa};
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let corp = IzbaCa::generate().unwrap();
        let corp_pem = corp.cert_pem().to_string();
        let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(Arc::new(
            CertCache::new(corp),
        ))));

        let files = vec![ExtraCaFile {
            name: "corp.pem".into(),
            certs: CertificateDer::pem_slice_iter(corp_pem.as_bytes())
                .map(|c| c.unwrap())
                .collect(),
        }];

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handshake = |cfg: Arc<rustls::ClientConfig>| {
            let acceptor = acceptor.clone();
            rt.block_on(async move {
                let (client, server) = tokio::io::duplex(16 * 1024);
                let srv = tokio::spawn(async move { acceptor.accept(server).await.map(|_| ()) });
                let name = ServerName::try_from("registry.corp.example").unwrap();
                let res = TlsConnector::from(cfg)
                    .connect(name, client)
                    .await
                    .map(|_| ());
                let _ = srv.await;
                res
            })
        };
        handshake(upstream_client_config(&files)).expect("extra CA leaf verifies");
        handshake(upstream_client_config(&[]))
            .expect_err("without the extra CA the leaf is refused");
    }

    // -------------------------------------------------------------- #283 fixes

    /// One real CA as raw DER bytes (what a Windows "export certificate"
    /// produces by default).
    fn real_ca_der() -> Vec<u8> {
        CertificateDer::pem_slice_iter(real_ca_pem().as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec()
    }

    /// A private key must NEVER reach the guest: `~/.mitmproxy/mitmproxy-ca.pem`
    /// is exactly a key+cert file, and `pem_slice_iter` silently SKIPS the key
    /// section, so shipping the file text verbatim leaked the CA private key
    /// into every sandbox. Refuse the file instead, naming it.
    #[test]
    fn a_file_containing_a_private_key_is_refused() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = crate::daemon::egress::mitm::IzbaCa::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("mitmproxy-ca.pem"),
            format!("{}{}", ca.key_pem(), ca.cert_pem()),
        )
        .unwrap();
        let err = load_extra_cas(dir.path()).unwrap_err().to_string();
        assert!(err.contains("mitmproxy-ca.pem"), "{err}");
        assert!(err.contains("private key"), "{err}");
    }

    /// The guest text is built from the PARSED certs, never the file text, so
    /// operator comments (and anything else outside a CERTIFICATE block) are
    /// stripped rather than shipped.
    #[test]
    fn guest_pem_ships_only_certificates_never_surrounding_text() {
        let dir = tempfile::tempdir().unwrap();
        let ca = real_ca_pem();
        std::fs::write(
            dir.path().join("corp.pem"),
            format!("# corp root\nsubject=/CN=corp\n{ca}"),
        )
        .unwrap();
        let out = guest_extra_pem(&load_extra_cas(dir.path()).unwrap());
        assert!(!out.contains('#'), "{out}");
        assert!(!out.contains("subject="), "{out}");
        for line in out.lines() {
            let base64ish = |l: &str| {
                !l.is_empty()
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
            };
            assert!(
                line == "-----BEGIN CERTIFICATE-----"
                    || line == "-----END CERTIFICATE-----"
                    || base64ish(line),
                "line outside a PEM block: {line:?}"
            );
        }
    }

    /// The re-serialized guest text carries EXACTLY the anchors izbad trusts,
    /// in order — that is what makes "one loader, no disagreement" literal.
    #[test]
    fn guest_pem_reparses_to_the_same_der_list_in_order() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.pem"), real_ca_pem()).unwrap();
        std::fs::write(
            dir.path().join("b.pem"),
            format!("{}{}", real_ca_pem(), real_ca_pem()),
        )
        .unwrap();
        let files = load_extra_cas(dir.path()).unwrap();
        let expected: Vec<Vec<u8>> = files
            .iter()
            .flat_map(|f| f.certs.iter().map(|c| c.to_vec()))
            .collect();
        assert_eq!(expected.len(), 3);
        let got: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(guest_extra_pem(&files).as_bytes())
            .map(|c| c.unwrap().to_vec())
            .collect();
        assert_eq!(got, expected);
    }

    /// Windows' default certificate export is DER, named `.cer`/`.crt`/`.der`.
    /// Before the fix that hit `read_to_string` → "stream did not contain
    /// valid UTF-8" and bricked every `izba start`.
    #[test]
    fn a_der_certificate_file_loads() {
        let dir = tempfile::tempdir().unwrap();
        let der = real_ca_der();
        std::fs::write(dir.path().join("corp.cer"), &der).unwrap();
        let files = load_extra_cas(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].certs.len(), 1);
        assert_eq!(files[0].certs[0].to_vec(), der);
    }

    /// `.cer` is also a common PEM extension — the CONTENT decides, not the name.
    #[test]
    fn a_pem_cer_file_loads() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("corp.cer"), real_ca_pem()).unwrap();
        assert_eq!(load_extra_cas(dir.path()).unwrap()[0].certs.len(), 1);
    }

    #[test]
    fn a_binary_non_der_file_is_an_error_naming_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("junk.der"), [0xffu8, 0xfe, 0x00, 0x99]).unwrap();
        let err = load_extra_cas(dir.path()).unwrap_err().to_string();
        assert!(err.contains("junk.der"), "{err}");
        assert!(
            err.contains("not PEM text and not a DER certificate"),
            "{err}"
        );
    }
}
