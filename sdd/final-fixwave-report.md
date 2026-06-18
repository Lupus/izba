# Final Fix-Wave Report -- MVP-D lock-down

Branch: `feat/windows-per-sandbox-account`
Date: 2026-06-18

---

## MUST-FIX 1 -- CSPRNG password generator

**File:** `crates/izba-jail-helper/src/account.rs`
**File:** `crates/izba-jail-helper/Cargo.toml`

**What was wrong:** `random_password` used `entropy()` -- a SystemTime-nanos XOR
counter*golden-ratio stream -- as its sole randomness source. This is predictable and
unacceptable for a credential that grants `CreateProcessWithLogonW` access.

**Fix applied:**

1. Added `Win32_Security_Cryptography` and `Win32_System_Threading` (pre-existing
   missing feature) to the `windows-sys` feature list in `Cargo.toml`.

2. Introduced `csprng_fill(buf: &mut [u8]) -> Result<(), String>` (`#[cfg(windows)]`):
   calls `BCryptGenRandom(null, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`, checks
   NTSTATUS == 0, and returns `Err` on failure -- no fallback to the weak source.

3. Replaced `random_password` with a `#[cfg(windows)]` version that:
   - Returns `Result<String, String>` (propagates CSPRNG errors, never silently swallows)
   - Seeds one byte from each of the four complexity classes (upper/lower/digit/symbol)
     via rejection-sampling to avoid modulo bias
   - Fills the remainder from the full alphabet via rejection-sampling
   - Performs a CSPRNG-driven Fisher-Yates shuffle (rejection-sampled index in [0,i])
   - All randomness comes from `BCryptGenRandom`; `entropy()` is NOT called anywhere
     in the password path

4. `entropy()` is retained (with `#[allow(dead_code)]`) for non-credential uses
   (e.g. unique temp-file suffixes). A comment makes the separation explicit.

5. `ALPHABET` is now `#[cfg(windows)]` since only `random_password` uses it.

6. Tests: `meets_complexity` unit tests remain cross-platform. All `random_password`
   generation tests are now `#[cfg(windows)]` and call
   `.expect("BCryptGenRandom should succeed")`. The MIN_PW_LEN import is likewise
   `#[cfg(windows)]` to avoid an unused-import warning on Linux.

7. `win::create_account` propagates the `?` from the now-fallible `random_password`.

**Confirmation:** `grep -n "entropy()" crates/izba-jail-helper/src/account.rs` shows
only the `fn entropy()` definition and a doc-comment -- no call sites in the password
path.

---

## MUST-FIX 2 -- e2e section [11] read-deny assertion

**File:** `hack/spike/validate-izba-windows.ps1`

**What was wrong:** Section [11]'s header claimed "read-deny" but no assertion
verified structural read-confinement. It only checked account existence, firewall
rules, and VMM ownership.

**Fix applied:** Added "Step 6b" between the account-existence check and the unlock
step:

- **Negative control:** creates `$env:TEMP\izba-lk-outside.txt`, asserts
  `izba-spk-lk-validate` is NOT in its ACL via `icacls`.
- **Positive control:** asserts `izba-spk-lk-validate` IS in the ACL of the sandbox
  dir (`$env:LOCALAPPDATA\izba\sandboxes\lk-validate`) via `icacls`.
- Outside file is removed after the checks.
- No code is executed as the account -- ACL inspection via icacls output suffices.
- All new lines are plain ASCII (no em-dashes).

---

## MUST-FIX 3 -- Spec section 5.4 cred_out protection text

**File:** `docs/superpowers/specs/2026-06-18-windows-per-sandbox-account-design.md`

**What was wrong:** Section 5.4 claimed the helper "ACLs to the user" the one-shot
cred file. In reality the helper writes into the per-sandbox directory which inherits
the directory's existing DACL (invoking user + Administrators). No explicit ACL grant
is applied.

**Fix applied:** Replaced the inaccurate sentence with an honest description of what
actually happens: the file inherits the sandbox dir's DACL, izbad reads+seals+deletes
it immediately, the exposure window is brief and within the same trust root.

---

## CHEAP CLEANUPS

### `crates/izba-jail-helper/src/firewall.rs`

- Changed `Command::new("powershell")` to `Command::new("powershell.exe")` in
  `run_ps`. Updated the spawn-failed error string accordingly.
- Added `debug_assert!` injection-invariant checks at the top of `block`:
  - Rule name must be `[a-zA-Z0-9-]` (produced by `rule_name()` in izba-jail-naming)
  - SID must be `S-<digits>-...` form
  - Comment explains these are caller-sanitized invariants caught during development.

### `crates/izba-core/src/jail_account/state.rs`

- Reworded the `#[serde(default)]` doc comment to: "a `lockdown.json` written by an
  older build without this field still deserializes (the field defaults to `None`)".

### `crates/izba-core/src/jail_account/dpapi.rs`

- Fixed copy-paste in the non-Windows `unseal` stub doc-comment: now says
  "Decrypt (unseal)" to distinguish it from the `seal` stub.

### `crates/izba-jail-naming/src/lib.rs`

- Rewrote the `firewall_sddl` doc comment to clarify the SDDL is a **match
  condition** (which user's traffic to match), not an "allow rule". The block action
  comes from `-Action Block` on `New-NetFirewallRule`.

---

## Gate results (all green)

```
cargo test --workspace                                        OK (636 tests, 0 failures)
cargo fmt --check                                             OK
cargo clippy --workspace --all-targets -- -D warnings         OK (0 warnings)
cargo check  --target x86_64-pc-windows-gnu -p ... (5 crates) OK
cargo clippy --target x86_64-pc-windows-gnu -p jail* -D warns OK
cargo build  --target x86_64-pc-windows-gnu -p izba-jail-helper OK
```

Also fixed a pre-existing missing `Win32_System_Threading` feature in Cargo.toml
that caused the Windows clippy gate to fail before this wave.

---

## ASCII-clean check on new PS1 lines

`grep -nP '[^\x00-\x7F]' hack/spike/validate-izba-windows.ps1` shows no non-ASCII
characters in the new Step 6b block (only pre-existing em-dashes in unrelated lines).

---

## Confirmed: no entropy() in the password path

`grep -n "entropy()" crates/izba-jail-helper/src/account.rs` output:
- Line in `csprng_fill` doc-comment: "entropy() is intentionally NOT used here"
- Line: `fn entropy()` definition only

Zero call sites of `entropy()` in `random_password` or any function it calls.
