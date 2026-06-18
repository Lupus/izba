//! DPAPI seal/unseal for the per-sandbox credential.
//!
//! `seal` encrypts an arbitrary byte slice with `CryptProtectData` scoped to
//! the **current user** (no `CRYPTPROTECT_LOCAL_MACHINE`). The ciphertext blob
//! is only decryptable by the same user on the same machine, which is exactly
//! the threat model for persisting the sandbox account password between
//! `izbad` restarts.
//!
//! `unseal` reverses the operation with `CryptUnprotectData`.
//!
//! Both functions pass `CRYPTPROTECT_UI_FORBIDDEN` so they fail cleanly (with
//! an error) rather than popping a UI prompt in a headless daemon context.
//!
//! **Freeing discipline:** `CryptProtect/UnprotectData` allocates the output
//! blob via `LocalAlloc`.  The caller is responsible for freeing it with
//! `LocalFree`.  This module copies the output into a `Vec<u8>` and then calls
//! `LocalFree` — on both the success path *and* the error path (if the API
//! succeeded but a subsequent step failed).
//!
//! On non-Windows this module compiles to stubs that return `Err("windows-only")`.

// ── Windows implementation ───────────────────────────────────────────────────

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    /// Encrypt `plain` bytes with DPAPI (current-user scope).
    ///
    /// Returns the opaque ciphertext blob on success, or an error string.
    pub fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
        // Build the input DATA_BLOB (CRYPT_INTEGER_BLOB in windows-sys 0.60).
        // The API signature takes *const for input, so we construct a local and
        // borrow it as a const pointer.
        let input = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: input/output are valid CRYPT_INTEGER_BLOBs; all optional
        // parameters are null (no entropy, no prompt, no reserved, no description).
        // CryptProtectData reads input.pbData but only writes to output.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(), // szDataDescr: no description
                std::ptr::null(), // pOptionalEntropy: none
                std::ptr::null(), // pvReserved: must be NULL (*const c_void)
                std::ptr::null(), // pPromptStruct: none (UI_FORBIDDEN)
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };

        if ok == 0 {
            // API failed — output.pbData was NOT allocated; nothing to free.
            return Err(format!(
                "CryptProtectData: {}",
                std::io::Error::last_os_error()
            ));
        }

        // API succeeded — copy the blob then unconditionally free the API allocation.
        // SAFETY: output.pbData points to a LocalAlloc'd buffer of output.cbData bytes.
        let blob = unsafe {
            let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
            let v = slice.to_vec();
            LocalFree(output.pbData as _);
            v
        };

        Ok(blob)
    }

    /// Decrypt a DPAPI blob previously produced by [`seal`].
    ///
    /// Returns the plaintext bytes on success, or an error string.
    pub fn unseal(blob: &[u8]) -> Result<Vec<u8>, String> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // SAFETY: same invariants as seal; ppszDataDescr is null_mut (we discard it).
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(), // ppszDataDescr: discard
                std::ptr::null(),     // pOptionalEntropy: none
                std::ptr::null(),     // pvReserved: must be NULL
                std::ptr::null(),     // pPromptStruct: none (UI_FORBIDDEN)
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };

        if ok == 0 {
            return Err(format!(
                "CryptUnprotectData: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: output.pbData points to a LocalAlloc'd buffer of output.cbData bytes.
        let plain = unsafe {
            let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
            let v = slice.to_vec();
            LocalFree(output.pbData as _);
            v
        };

        Ok(plain)
    }
}

// ── Public surface ───────────────────────────────────────────────────────────

/// Encrypt `plain` with DPAPI (current-user scope).
///
/// The returned blob is opaque ciphertext that can only be decrypted by
/// [`unseal`] running as the same Windows user on the same machine.
#[cfg(windows)]
pub fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
    win::seal(plain)
}

/// Encrypt `plain` with DPAPI (current-user scope).
///
/// Returns `Err("windows-only")` on non-Windows platforms.
#[cfg(not(windows))]
pub fn seal(_plain: &[u8]) -> Result<Vec<u8>, String> {
    Err("windows-only".into())
}

/// Decrypt a DPAPI blob previously produced by [`seal`].
#[cfg(windows)]
pub fn unseal(blob: &[u8]) -> Result<Vec<u8>, String> {
    win::unseal(blob)
}

/// Decrypt a DPAPI blob previously produced by [`seal`].
///
/// Returns `Err("windows-only")` on non-Windows platforms.
#[cfg(not(windows))]
pub fn unseal(_blob: &[u8]) -> Result<Vec<u8>, String> {
    Err("windows-only".into())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Non-Windows: the API shape must at least compile and return the expected
    // stub error. The seal/unseal calls below are cfg(windows)-only so these
    // test functions still compile on Linux/musl.

    /// On non-Windows, seal must return the "windows-only" stub error.
    #[cfg(not(windows))]
    #[test]
    fn seal_stub_returns_windows_only() {
        assert_eq!(super::seal(b"test").unwrap_err(), "windows-only");
    }

    /// On non-Windows, unseal must return the "windows-only" stub error.
    #[cfg(not(windows))]
    #[test]
    fn unseal_stub_returns_windows_only() {
        assert_eq!(super::unseal(b"test").unwrap_err(), "windows-only");
    }

    /// Round-trip: unseal(seal(plaintext)) == plaintext.
    ///
    /// Runs only on Windows (DPAPI requires a logged-in user context; it works
    /// without elevation so the Windows-native CI job executes this for real).
    #[cfg(windows)]
    #[test]
    fn roundtrip_seal_unseal() {
        let plaintext = b"s3cret-pw";
        let blob = super::seal(plaintext).expect("seal must succeed");
        let recovered = super::unseal(&blob).expect("unseal must succeed");
        assert_eq!(recovered, plaintext);
    }

    /// The seal output must be non-empty and must differ from the plaintext.
    #[cfg(windows)]
    #[test]
    fn seal_output_is_transformed() {
        let plaintext = b"s3cret-pw";
        let blob = super::seal(plaintext).expect("seal must succeed");
        assert!(!blob.is_empty(), "seal output must be non-empty");
        assert_ne!(
            blob.as_slice(),
            plaintext.as_ref(),
            "seal output must not equal plaintext"
        );
    }
}
