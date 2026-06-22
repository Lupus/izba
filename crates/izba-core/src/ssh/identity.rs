use anyhow::Context;
use ssh_key::{rand_core::OsRng, Algorithm, LineEnding, PrivateKey};
use std::path::{Path, PathBuf};

pub struct SshIdentity {
    pub user_private: PathBuf,
    pub user_public: PathBuf,
    pub host_private: PathBuf,
    pub host_public: PathBuf,
}

const USER_PRIV: &str = "id_ed25519";
const HOST_PRIV: &str = "ssh_host_ed25519_key";

fn ensure_keypair(dir: &Path, stem: &str) -> anyhow::Result<(PathBuf, PathBuf)> {
    let priv_path = dir.join(stem);
    let pub_path = dir.join(format!("{stem}.pub"));
    if !priv_path.exists() {
        let key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).context("generating ed25519 key")?;
        let pem = key
            .to_openssh(LineEnding::LF)
            .context("encoding private key")?;
        write_private(&priv_path, pem.as_bytes())?;
        let pub_openssh = key
            .public_key()
            .to_openssh()
            .context("encoding public key")?;
        std::fs::write(&pub_path, format!("{pub_openssh}\n"))
            .with_context(|| format!("writing {}", pub_path.display()))?;
    }
    Ok((priv_path, pub_path))
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
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
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// reason: trivial Windows file-write variant (no permission logic to assert);
// the behaviorally-meaningful unix variant + its 0600 test carry the coverage,
// and cargo-mutants cannot see the #[cfg] so this would otherwise spuriously
// survive on the Linux leg.
#[mutants::skip]
#[cfg(windows)]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

pub fn ensure_identity(ssh_dir: &Path) -> anyhow::Result<SshIdentity> {
    std::fs::create_dir_all(ssh_dir).with_context(|| format!("creating {}", ssh_dir.display()))?;
    let (user_private, user_public) = ensure_keypair(ssh_dir, USER_PRIV)?;
    let (host_private, host_public) = ensure_keypair(ssh_dir, HOST_PRIV)?;
    Ok(SshIdentity {
        user_private,
        user_public,
        host_private,
        host_public,
    })
}

pub fn user_public_openssh(ssh_dir: &Path) -> anyhow::Result<String> {
    read_pub(&ssh_dir.join(format!("{USER_PRIV}.pub")))
}

pub fn host_public_openssh(ssh_dir: &Path) -> anyhow::Result<String> {
    read_pub(&ssh_dir.join(format!("{HOST_PRIV}.pub")))
}

fn read_pub(p: &Path) -> anyhow::Result<String> {
    Ok(std::fs::read_to_string(p)
        .with_context(|| format!("reading {}", p.display()))?
        .trim()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_identity_is_idempotent_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let id1 = ensure_identity(tmp.path()).unwrap();
        let priv1 = std::fs::read(&id1.user_private).unwrap();
        // second call must not regenerate
        let id2 = ensure_identity(tmp.path()).unwrap();
        let priv2 = std::fs::read(&id2.user_private).unwrap();
        assert_eq!(priv1, priv2, "keypair regenerated on second call");
        assert!(host_public_openssh(tmp.path())
            .unwrap()
            .starts_with("ssh-ed25519 "));
        assert!(user_public_openssh(tmp.path())
            .unwrap()
            .starts_with("ssh-ed25519 "));
    }

    #[cfg(unix)]
    #[test]
    fn private_keys_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let id = ensure_identity(tmp.path()).unwrap();
        for p in [&id.user_private, &id.host_private] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} not 0600", p.display());
        }
    }
}
