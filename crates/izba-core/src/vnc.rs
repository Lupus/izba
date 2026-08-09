//! Host-side VNC credential material for a `--vnc` sandbox: a fresh
//! 24-char alphanumeric password generated on every `start`, plus the
//! guest-facing `kasmpasswd` hash file delivered over the `izba-vnc`
//! virtiofs share (mounted read-only by izba-init — Task 10).
//!
//! **Hash format (empirically captured, spec 2026-08-09 Task 6 §Interfaces):**
//! upstream `kasmvncpasswd` 1.5.0 (bookworm) produces lines shaped
//! `<user>:$5$kasm$<43-char base64-crypt hash>:wo` — SHA-256-crypt (glibc
//! `crypt(3)` algorithm id `5`), fixed literal salt `kasm`, default 5000
//! rounds (omitted from the MCF string), followed by a `:`-delimited
//! permission-flags field (`w`rite + `o`wner, in THIS order — not `ow` as an
//! unverified assumption might guess).
//!
//! **This must be byte-for-byte, not merely shape-compatible.** A live probe
//! against the real KasmVNC 1.5.0 server proved it does NOT call
//! `crypt(pw, stored_hash)` (which would accept any well-formed sha256-crypt
//! hash regardless of salt/rounds encoding) — it recomputes
//! `crypt(pw, "$5$kasm$")` itself and does a plain string compare against the
//! stored line. A hash using a random salt, or one carrying an explicit
//! `rounds=5000$` field (both spec-legal sha256-crypt variants, but NOT what
//! `$5$kasm$` recomputes to), is silently rejected — see
//! `docs.../task-6-report.md` "fix report" for the probe matrix.
//!
//! So the salt is hardcoded to the literal `kasm`, matching upstream exactly.
//! `sha-crypt`'s high-level `ShaCrypt`/`PasswordHasher` API cannot produce
//! this: it unconditionally emits a `rounds=` field and base64-encodes
//! whatever salt bytes it is given (so it can never emit the literal string
//! `kasm` as the salt component). Instead we call the crate's low-level
//! `sha256_crypt` function directly with salt `b"kasm"`, apply the
//! algorithm's public transposition table by hand (mirroring the crate's own
//! private `sha256_crypt_core`, which the `password-hash` feature does not
//! expose), and base64-crypt-encode the result ourselves via `base64ct`.
//!
//! **Deliberate consequence of a fixed salt:** two sandboxes with the same
//! plaintext VNC password would hash identically (no per-hash entropy from
//! the salt). This is acceptable ONLY because the salt is not the thing
//! carrying the entropy here — the 24-char password itself is, freshly
//! random on every single `start` (see `generate_password`), so no two
//! passwords (and therefore no two hashes) are expected to collide in
//! practice, and a stale hash is worthless within one boot cycle regardless.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64ct::{Base64ShaCrypt, Encoding};
use sha_crypt::{sha256_crypt, Params};

use crate::paths::Paths;

/// virtiofs share tag for the guest-facing `kasmpasswd` hash file.
pub const VNC_SHARE_TAG: &str = "izba-vnc";

/// The guest-loopback port KasmVNC's websocket/HTTP endpoint listens on
/// (`-websocketPort`, spec 2026-08-09 §4/§7). The host never binds this — it
/// is the `StreamOpen::TcpDial` target of the daemon's ephemeral VNC relay
/// and of the inspect liveness probe. Both ends of the number must move
/// together: the guest side is izba-init's `Xkasmvnc` invocation.
pub const WEBSOCKET_PORT: u16 = 6901;

/// Length of the generated plaintext VNC password.
const PASSWORD_LEN: usize = 24;

/// Alphanumeric only: the password lands in a URL userinfo section
/// downstream (spec 2026-08-09 Task 6), so no characters that would need
/// percent-encoding.
const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The kasmvnc "user" field. izba's guest-side VNC session always runs as
/// this fixed username; only the password varies per start.
const VNC_USER: &str = "izba";

/// The literal salt upstream `kasmvncpasswd` hardcodes. KasmVNC's own
/// auth check recomputes `crypt(pw, "$5$kasm$")` and string-compares — see
/// module docs — so this is NOT a stylistic choice, it is required for the
/// hash to authenticate against a real KasmVNC server.
const KASM_SALT: &[u8] = b"kasm";

/// SHA-256-crypt's algorithm-specific output transposition table (32
/// entries), copied from `sha-crypt`'s private `sha256_crypt_core` (only
/// reachable there under the `password-hash` feature's MCF-wrapping API,
/// which we cannot use — see module docs). Applying this table to the raw
/// `sha256_crypt` digest, then base64-crypt-encoding it, is exactly the
/// public two-step process the MCF encoder performs internally.
const SHA256_CRYPT_TRANSPOSITION: [usize; 32] = [
    20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15, 26, 16, 6, 17, 7, 27, 8, 28,
    18, 29, 19, 9, 30, 31,
];

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

fn transpose_sha256_crypt(digest: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &src_idx) in SHA256_CRYPT_TRANSPOSITION.iter().enumerate() {
        out[i] = digest[src_idx];
    }
    out
}

/// Produces the exact `$5$kasm$<hash>` MCF string upstream `kasmvncpasswd`
/// emits for `password` (empirically verified byte-for-byte against a real
/// KasmVNC probe — see module docs).
fn hash_password(password: &str) -> String {
    let digest = sha256_crypt(password.as_bytes(), KASM_SALT, Params::default());
    let transposed = transpose_sha256_crypt(digest);
    let encoded = Base64ShaCrypt::encode_string(&transposed);
    format!("$5$kasm${encoded}")
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
    // Clear any stale material from a previous start before writing fresh
    // credentials — cheap explicitness, avoids a stale kasmpasswd/other file
    // ever lingering next to the current one.
    if share.exists() {
        std::fs::remove_dir_all(&share)
            .with_context(|| format!("clearing stale vnc share dir {}", share.display()))?;
    }
    std::fs::create_dir_all(&share)
        .with_context(|| format!("creating vnc share dir {}", share.display()))?;

    let password = generate_password();

    let pw_file = password_file(paths, name);
    write_private_0600(&pw_file, password.as_bytes())
        .with_context(|| format!("writing vnc password to {}", pw_file.display()))?;

    let hash = hash_password(&password);
    let line = format!("{VNC_USER}:{hash}:wo\n");
    let kasmpasswd = share.join(KASMPASSWD_FILENAME);
    std::fs::write(&kasmpasswd, &line)
        .with_context(|| format!("writing {}", kasmpasswd.display()))?;
    set_mode_0644(&kasmpasswd)
        .with_context(|| format!("setting 0644 on {}", kasmpasswd.display()))?;

    Ok(share)
}

/// Atomically creates `path` with content `bytes` and mode 0600 in one
/// syscall (mirrors `ssh::identity::write_private`) — no window where the
/// plaintext password is briefly world/group-readable between write and
/// chmod.
#[cfg(unix)]
fn write_private_0600(path: &Path, bytes: &[u8]) -> Result<()> {
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

// reason: trivial Windows file-write variant (no permission logic to
// assert — Windows gets no permission tightening here, consistent with the
// rest of the tree, e.g. ssh::identity::write_private); the
// behaviorally-meaningful unix variant + its 0600 test carry the coverage,
// and cargo-mutants cannot see the #[cfg] so this would otherwise spuriously
// survive on the Linux leg.
#[mutants::skip]
#[cfg(windows)]
fn write_private_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_mode_0644(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

// reason: Windows gets no permission tightening (consistent with the rest of
// the tree); nothing here to assert behaviorally beyond what the unix 0644
// test already carries, and cargo-mutants cannot see the #[cfg] so this
// would otherwise spuriously survive on the Linux leg.
#[mutants::skip]
#[cfg(windows)]
fn set_mode_0644(_path: &Path) -> Result<()> {
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
/// (`<user>:<hash>:<perms>`) by recomputing the hash and comparing —
/// deliberately NOT delegating to `sha-crypt`'s `PasswordVerifier` (that
/// verifier re-derives params/salt generically from the MCF string and would
/// pass for shapes KasmVNC itself rejects; see module docs). Test-only:
/// production never needs to verify a password it just generated itself.
#[cfg(test)]
fn verify_password(password: &str, kasmpasswd_line: &str) -> bool {
    let Some(hash) = kasmpasswd_line.trim_end().split(':').nth(1) else {
        return false;
    };
    hash_password(password) == hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::test_paths;

    /// Golden verify-vector: the exact line captured from upstream
    /// `kasmvncpasswd` 1.5.0 (bookworm) for user `izba`, password
    /// `secret123` — `izba:$5$kasm$g0eZTkmHZIY7dGmFpQySvHQv1umVa/nly66Q1jraM22:wo`.
    const GOLDEN_UPSTREAM_LINE: &str =
        "izba:$5$kasm$g0eZTkmHZIY7dGmFpQySvHQv1umVa/nly66Q1jraM22:wo";
    const GOLDEN_UPSTREAM_HASH: &str = "$5$kasm$g0eZTkmHZIY7dGmFpQySvHQv1umVa/nly66Q1jraM22";
    const GOLDEN_UPSTREAM_PASSWORD: &str = "secret123";

    /// Real oracle, not a shape check: our `hash_password` must reproduce
    /// upstream's captured hash BYTE-FOR-BYTE for the same password — a live
    /// KasmVNC probe proved anything less (rounds= field, random salt) is
    /// rejected at auth time (see module docs / task-6-report.md).
    #[test]
    fn hash_password_matches_upstream_kasmvncpasswd_exactly() {
        assert_eq!(
            hash_password(GOLDEN_UPSTREAM_PASSWORD),
            GOLDEN_UPSTREAM_HASH
        );
        assert_eq!(
            format!("izba:{}:wo", hash_password(GOLDEN_UPSTREAM_PASSWORD)),
            GOLDEN_UPSTREAM_LINE
        );
    }

    /// Drift pin against izba-init, which cannot import these (no izba-core
    /// dependency) and therefore repeats the literals in its own
    /// `vnc::{WEBSOCKET_PORT, VNC_TAG}` with a mirror-image test. The port is
    /// the guest side of the daemon's relay + liveness probe: init's
    /// `Xkasmvnc -websocketPort` must be this number or both silently target
    /// a port nothing listens on.
    #[test]
    fn wire_constants_match_the_izba_init_literals() {
        assert_eq!(WEBSOCKET_PORT, 6901);
        assert_eq!(VNC_SHARE_TAG, "izba-vnc");
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
        assert!(
            kp.starts_with("izba:$5$kasm$"),
            "user + fixed-salt sha256-crypt hash: {kp}"
        );
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

    /// A second `write_vnc_material` call must not leave the previous
    /// kasmpasswd/password lying around alongside the new one — the share
    /// dir is cleared before each write.
    #[test]
    fn second_write_leaves_no_stale_files() {
        let (_dir, paths) = test_paths();
        std::fs::create_dir_all(paths.sandbox_dir("s")).unwrap();

        let share = write_vnc_material(&paths, "s").unwrap();
        // Plant an extra stale file the way a leftover from an old format
        // might look.
        std::fs::write(share.join("stale.txt"), b"leftover").unwrap();

        write_vnc_material(&paths, "s").unwrap();

        assert!(
            !share.join("stale.txt").exists(),
            "stale files must be cleared on each write"
        );
        assert!(share.join(KASMPASSWD_FILENAME).exists());
    }
}
