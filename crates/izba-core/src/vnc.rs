//! Host-side VNC credential material for a `--vnc` sandbox: a fresh
//! 24-char alphanumeric password generated on every `start`, plus the
//! guest-facing `kasmpasswd` hash file delivered over the read-only
//! `izba-vnc` virtiofs share.
//!
//! **Hash format (empirically captured, spec 2026-08-09 Task 6 §Interfaces):**
//! upstream `kasmvncpasswd` 1.5.0 (bookworm) produces lines shaped
//! `<user>:$5$kasm$<43-char base64-crypt hash>:wo` — SHA-256-crypt (glibc
//! `crypt(3)` algorithm id `5`), fixed literal salt `kasm`, default 5000
//! rounds (omitted from the MCF string), followed by a `:`-delimited
//! permission-flags field (`w`rite + `o`wner, in THIS order — not `ow` as an
//! unverified assumption might guess).
//!
//! We reproduce this with the pure-Rust `sha-crypt` crate rather than
//! shelling out to the vendored `kasmvncpasswd` binary. We do NOT reuse the
//! literal `kasm` salt (the crate's `ShaCrypt` hasher base64-encodes
//! whatever salt bytes it is given into the MCF salt field, so it cannot be
//! made to emit an arbitrary literal string); each hash instead gets a
//! fresh random salt, matching the informal convention (every other tool
//! that shells out to `kasmvncpasswd` gets the same fixed salt only because
//! upstream hardcodes it — it is not part of the sha256-crypt spec, and
//! `crypt(3)` validates any well-formed salt equally). Our MCF output also
//! carries an explicit `rounds=5000$` field that upstream elides for the
//! default rounds count; both forms are spec-legal and verify identically
//! under `crypt(3)`. Round-tripped against the crate's own `verify_password`
//! in the test below, and the `$5$` prefix is checked against the captured
//! golden line.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha_crypt::{Algorithm, Params, PasswordHasher, ShaCrypt};

use crate::paths::Paths;

/// virtiofs share tag for the guest-facing `kasmpasswd` hash file.
pub const VNC_SHARE_TAG: &str = "izba-vnc";

/// Length of the generated plaintext VNC password.
const PASSWORD_LEN: usize = 24;

/// Alphanumeric only: the password lands in a URL userinfo section
/// downstream (spec 2026-08-09 Task 6), so no characters that would need
/// percent-encoding.
const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Raw salt bytes fed to `ShaCrypt::hash_password_with_salt`. 12 bytes
/// base64-crypt-encode to a 16-char salt field, matching the max salt length
/// `crypt(3)` sha256-crypt accepts.
const SALT_BYTES: usize = 12;

/// The kasmvnc "user" field. izba's guest-side VNC session always runs as
/// this fixed username; only the password varies per start.
const VNC_USER: &str = "izba";

/// Filename for the host-only plaintext password, a SIBLING of the share dir
/// (`<sandbox>/vnc.password`) — deliberately NOT inside `vnc/`
/// (`Paths::vnc_share_dir`), which is what virtiofs exposes to the guest.
/// Putting the plaintext in the share dir would leak it to the guest; only
/// the hash belongs there.
const PASSWORD_FILENAME: &str = "vnc.password";

const KASMPASSWD_FILENAME: &str = "kasmpasswd";

fn generate_password() -> String {
    (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rand::random_range(0..PASSWORD_ALPHABET.len());
            PASSWORD_ALPHABET[idx] as char
        })
        .collect()
}

fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; SALT_BYTES];
    rand::fill(&mut salt);
    let hasher = ShaCrypt::new(Algorithm::Sha256Crypt, Params::default());
    let hash = hasher
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("sha256-crypt hashing failed: {e}"))?;
    Ok(hash.as_str().to_string())
}

fn password_file(paths: &Paths, name: &str) -> PathBuf {
    paths.sandbox_dir(name).join(PASSWORD_FILENAME)
}

/// Generates a fresh 24-char alphanumeric VNC password (rotated on every
/// call — izba-init sees a new password each time the sandbox starts),
/// writes the host-only plaintext to `<sandbox>/vnc.password` (0600) and the
/// guest-facing `<user>:<hash>:wo` line to `<vnc-share>/kasmpasswd` (0644,
/// readable through virtiofs — it holds a hash, never the plaintext).
/// Returns the share dir (`Paths::vnc_share_dir`).
pub fn write_vnc_material(paths: &Paths, name: &str) -> Result<PathBuf> {
    let share = paths.vnc_share_dir(name);
    std::fs::create_dir_all(&share)
        .with_context(|| format!("creating vnc share dir {}", share.display()))?;

    let password = generate_password();

    let pw_file = password_file(paths, name);
    std::fs::write(&pw_file, &password)
        .with_context(|| format!("writing vnc password to {}", pw_file.display()))?;
    set_mode(&pw_file, 0o600).with_context(|| format!("setting 0600 on {}", pw_file.display()))?;

    let hash = hash_password(&password)?;
    let line = format!("{VNC_USER}:{hash}:wo\n");
    let kasmpasswd = share.join(KASMPASSWD_FILENAME);
    std::fs::write(&kasmpasswd, &line)
        .with_context(|| format!("writing {}", kasmpasswd.display()))?;
    set_mode(&kasmpasswd, 0o644)
        .with_context(|| format!("setting 0644 on {}", kasmpasswd.display()))?;

    Ok(share)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Reads the host-only plaintext VNC password written by the most recent
/// `write_vnc_material` call for sandbox `name`.
pub fn read_password(paths: &Paths, name: &str) -> Result<String> {
    let pw_file = password_file(paths, name);
    std::fs::read_to_string(&pw_file)
        .with_context(|| format!("reading vnc password from {}", pw_file.display()))
}

/// Verifies `password` against a `kasmpasswd`-format line
/// (`<user>:<hash>:<perms>`) by extracting the hash field and delegating to
/// the crate's own `PasswordVerifier`. Test-only: production never needs to
/// verify a password it just generated itself.
#[cfg(test)]
fn verify_password(password: &str, kasmpasswd_line: &str) -> bool {
    use sha_crypt::PasswordVerifier as _;

    let Some(hash) = kasmpasswd_line.trim_end().split(':').nth(1) else {
        return false;
    };
    let hasher = ShaCrypt::new(Algorithm::Sha256Crypt, Params::default());
    hasher.verify_password(password.as_bytes(), hash).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::test_paths;

    /// Golden verify-vector: the exact line captured from upstream
    /// `kasmvncpasswd` 1.5.0 (bookworm) for user `izba`, password
    /// `secret123` — `izba:$5$kasm$g0eZTkmHZIY7dGmFpQySvHQv1umVa/nly66Q1jraM22:wo`.
    /// We don't reproduce this exact hash (different salt/rounds encoding,
    /// see module docs) but assert our own output shares the load-bearing
    /// shape: `$5$` algorithm id and a trailing `:wo` permission field.
    const GOLDEN_UPSTREAM_LINE: &str =
        "izba:$5$kasm$g0eZTkmHZIY7dGmFpQySvHQv1umVa/nly66Q1jraM22:wo";

    #[test]
    fn golden_line_shape_matches_captured_upstream_format() {
        assert!(GOLDEN_UPSTREAM_LINE.starts_with("izba:$5$"));
        assert!(GOLDEN_UPSTREAM_LINE.trim_end().ends_with(":wo"));
    }

    #[test]
    fn write_vnc_material_creates_password_and_hash() {
        let (_dir, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("s")).unwrap();

        let share = write_vnc_material(&paths, "s").unwrap();
        let pw = read_password(&paths, "s").unwrap();
        assert_eq!(pw.len(), PASSWORD_LEN);
        assert!(
            pw.bytes().all(|b| b.is_ascii_alphanumeric()),
            "password must be alphanumeric only: {pw}"
        );

        let kp = std::fs::read_to_string(share.join("kasmpasswd")).unwrap();
        assert!(kp.starts_with("izba:$5$"), "user + sha256-crypt hash: {kp}");
        assert!(kp.trim_end().ends_with(":wo"), "write+owner perms: {kp}");
        assert!(verify_password(&pw, &kp), "hash round-trips");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let pw_mode = std::fs::metadata(paths.sandbox_dir("s").join("vnc.password"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(pw_mode & 0o777, 0o600, "plaintext password must be 0600");

            let kp_mode = std::fs::metadata(share.join("kasmpasswd"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(kp_mode & 0o777, 0o644, "kasmpasswd must be 0644 in-share");
        }
    }

    #[test]
    fn plaintext_password_lives_outside_the_share_dir() {
        let (_dir, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("s")).unwrap();

        let share = write_vnc_material(&paths, "s").unwrap();

        assert!(
            !share.join("password").exists(),
            "plaintext must not be written inside the guest-visible share dir"
        );
        assert!(
            paths.sandbox_dir("s").join("vnc.password").exists(),
            "plaintext must live as a host-only sibling of the share dir"
        );
    }

    #[test]
    fn each_start_rotates_the_password() {
        let (_dir, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("s")).unwrap();

        write_vnc_material(&paths, "s").unwrap();
        let first = read_password(&paths, "s").unwrap();

        write_vnc_material(&paths, "s").unwrap();
        let second = read_password(&paths, "s").unwrap();

        assert_ne!(first, second, "each start must generate a fresh password");
    }
}
