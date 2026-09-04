//! Host-installed extra CA roots (#283): `<data>/trust/extra/*.pem|*.crt`.
//!
//! One loader, two consumers, so the guest and izbad can never disagree about
//! which roots are trusted:
//! - `sandbox::start` ships the files' text to the guest as `trust/extra.pem`
//!   on the read-only `izba-trust` share (guest side: next sandbox start);
//! - `daemon::server::build_mitm_runtime` adds the parsed certs to izbad's
//!   upstream verifier on top of webpki-roots (izbad side: daemon start).
//!
//! The directory is host-only authority, like `policy.yaml` (F-30): it is
//! never shared into a VM — only a per-sandbox COPY of its text is.

use std::path::Path;

use anyhow::{bail, Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer};

/// File extensions the loader picks up (case-insensitive). Anything else in
/// the directory (README, `.bak`, dotfiles, subdirectories) is ignored.
pub const EXTRA_CA_EXTENSIONS: [&str; 2] = ["pem", "crt"];

/// One file from the extra-CA directory.
#[derive(Debug, Clone)]
pub struct ExtraCaFile {
    /// File name inside the directory — the ordering key and what
    /// `izba daemon status` prints.
    pub name: String,
    /// The file's text verbatim: what the guest receives. Text outside the
    /// PEM blocks (comments) is harmless to every consumer (OpenSSL, curl,
    /// Node, Python) and keeps the operator's annotations.
    pub pem: String,
    /// Every certificate parsed from `pem`, in file order: what izbad trusts.
    pub certs: Vec<CertificateDer<'static>>,
}

/// Load every `*.pem` / `*.crt` under `dir`, sorted by file name. A missing
/// directory is simply "no extra CAs". A file that parses to zero
/// certificates, or contains a corrupt block, is a HARD error naming the file:
/// a silently skipped corporate CA would reproduce exactly the "my CA doesn't
/// work" confusion this feature exists to remove.
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
        let pem = std::fs::read_to_string(&path)
            .with_context(|| format!("reading extra CA file {}", path.display()))?;
        let mut certs = Vec::new();
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|e| {
                anyhow::anyhow!("extra CA file {}: invalid PEM: {e}", path.display())
            })?;
            // PEM framing alone proves nothing about the bytes inside: a
            // well-formed block of garbage base64 parses as a "certificate".
            // Validate it the way izbad will consume it — as a trust anchor —
            // so a corrupt file is refused HERE, with its name, not skipped
            // later at daemon start.
            rustls::RootCertStore::empty()
                .add(cert.clone())
                .map_err(|e| {
                    anyhow::anyhow!(
                        "extra CA file {}: not a valid X.509 certificate: {e}",
                        path.display()
                    )
                })?;
            certs.push(cert);
        }
        if certs.is_empty() {
            bail!(
                "extra CA file {}: no CERTIFICATE blocks found (expected PEM)",
                path.display()
            );
        }
        out.push(ExtraCaFile { name, pem, certs });
    }
    Ok(out)
}

/// The text shipped to the guest as `trust/extra.pem`: every file's text in
/// load order, each trimmed and newline-terminated, so two files never glue
/// onto one line and the guest bundle stays well-formed. Empty when there are
/// no files (the caller then removes a stale `extra.pem` instead).
pub fn guest_extra_pem(files: &[ExtraCaFile]) -> String {
    let mut out = String::new();
    for f in files {
        out.push_str(f.pem.trim());
        out.push('\n');
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
        assert_eq!(files[0].pem, ca);
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

    #[test]
    fn guest_extra_pem_joins_files_in_order_with_single_newlines() {
        let files = vec![
            ExtraCaFile {
                name: "a.pem".into(),
                pem: "A-PEM".into(), // unterminated
                certs: vec![],
            },
            ExtraCaFile {
                name: "b.pem".into(),
                pem: "B-PEM\n\n".into(), // over-terminated
                certs: vec![],
            },
        ];
        assert_eq!(guest_extra_pem(&files), "A-PEM\nB-PEM\n");
        assert_eq!(guest_extra_pem(&[]), "");
    }

    #[test]
    fn upstream_roots_are_webpki_plus_every_extra_cert() {
        let ca = real_ca_pem();
        let files = vec![ExtraCaFile {
            name: "corp.pem".into(),
            pem: format!("{ca}{ca}"),
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
            pem: corp_pem.clone(),
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
}
