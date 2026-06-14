//! The persistent izba root CA. One CA per data root (`<root>/ca/`), minted on
//! first use and reused thereafter: the MITM signs per-host leaves with it and
//! every guest bakes its cert into the trust store, so a leaf izbad mints is
//! trusted inside the sandbox. The private key never leaves the host — only
//! `ca.pem` is shared into a guest (a per-sandbox copy, never the CA dir).

use std::path::Path;

use anyhow::{Context, Result};

use crate::daemon::egress::mitm::IzbaCa;

const CERT_FILE: &str = "ca.pem";
const KEY_FILE: &str = "ca.key";

/// Load the CA from `dir`, minting + persisting it on first use. Idempotent:
/// later calls return the same cert + key. The directory is created `0700` and
/// the key file `0600` (it holds the signing key).
pub fn load_or_create(dir: &Path) -> Result<IzbaCa> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading {}", key_path.display()))?;
        return IzbaCa::from_pem(&cert_pem, &key_pem);
    }

    std::fs::create_dir_all(dir).with_context(|| format!("creating CA dir {}", dir.display()))?;
    harden_dir(dir)?;

    let ca = IzbaCa::generate()?;
    // Key first (0600), then the public cert — so a reader never sees a cert
    // without its key.
    write_private(&key_path, ca.key_pem().as_bytes())?;
    std::fs::write(&cert_path, ca.cert_pem())
        .with_context(|| format!("writing {}", cert_path.display()))?;
    Ok(ca)
}

#[cfg(unix)]
fn harden_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))
}

#[cfg(not(unix))]
fn harden_dir(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_ring() {
        use std::sync::OnceLock;
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn mints_then_persists_a_valid_ca() {
        install_ring();
        let dir = tempfile::tempdir().unwrap();
        let ca = load_or_create(dir.path()).unwrap();
        let pem = ca.cert_pem().to_string();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        // Both artifacts landed.
        assert!(dir.path().join("ca.pem").exists());
        assert!(dir.path().join("ca.key").exists());
    }

    #[test]
    fn load_or_create_is_idempotent() {
        install_ring();
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create(dir.path()).unwrap().cert_pem().to_string();
        let second = load_or_create(dir.path()).unwrap().cert_pem().to_string();
        assert_eq!(first, second, "the persisted cert is reused verbatim");
    }

    /// A reloaded CA still signs leaves that validate against the persisted
    /// cert — the property the guest relies on (it trusts ca.pem; izbad signs
    /// with the reloaded key).
    #[test]
    fn reloaded_ca_signs_leaves_trusted_by_the_persisted_cert() {
        use crate::daemon::egress::mitm::{server_config_with_resolver, CertCache};
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        install_ring();
        let dir = tempfile::tempdir().unwrap();
        // Mint, then reload — the reload is what signs.
        let _ = load_or_create(dir.path()).unwrap();
        let reloaded = load_or_create(dir.path()).unwrap();
        let trusted_pem = reloaded.cert_pem().to_string();

        let cache = Arc::new(CertCache::new(reloaded));
        let acceptor = TlsAcceptor::from(Arc::new(server_config_with_resolver(cache)));

        // A guest that trusts ONLY the persisted ca.pem must accept the leaf.
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut trusted_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let mut gcfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        gcfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (client, server) = tokio::io::duplex(16 * 1024);
            let srv = tokio::spawn(async move { acceptor.accept(server).await.map(|_| ()) });
            let connector = TlsConnector::from(Arc::new(gcfg));
            let name = ServerName::try_from("api.anthropic.com").unwrap();
            let _g = connector
                .connect(name, client)
                .await
                .expect("leaf from the reloaded CA chains to the persisted ca.pem");
            srv.await.unwrap().expect("server accept");
        });
    }
}
