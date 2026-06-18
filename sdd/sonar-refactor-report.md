# Sonar Refactor Report — Cognitive Complexity Reduction

## Summary

Two functions flagged by SonarCloud (rust:S3776, threshold 15) were refactored as
pure behavior-preserving extractions. All six gates pass green.

---

## Target 1: `crates/izba-core/src/vmm/openvmm.rs` — `OpenVmmDriver::launch`

### Problem

The inline 3-way confinement decision (locked / allow_unconfined / confined) sat
directly in `launch()`, driving it to cognitive complexity 32.

### Extraction

Three private helpers were extracted:

| Helper | Purpose |
|--------|---------|
| `spawn_confined_vmm(spec, inv, vmm_log, policy)` | Top-level dispatcher: routes to locked / unconfined / default-confined branch |
| `spawn_locked_vmm(spec, inv, vmm_log, policy, ll)` | Locked path: Low-labels surfaces, spawns as per-sandbox Windows account |
| `spawn_default_confined_vmm(spec, inv, vmm_log, policy)` | Default confined path: Low-labels surfaces, spawns with restricted token at Low IL |
| `low_label_surfaces(surfaces)` | Shared atomic labelling loop with restore-on-first-failure semantics |

`launch()` now calls `spawn_confined_vmm(...)` and immediately proceeds to
construct `OpenVmmHandle`. The returned `(PidIdentity, ConfinementStatus)` pair
is identical to what the inline code produced.

### Behavior / fail-closed semantics — unchanged

- **Locked path**: still Low-labels `confined_write_surfaces()`, calls
  `spawn_confined_as_account`, maps `ConfinementMode` → `ConfinementStatus`
  identically (Restricted→applied, TokenOnly→token_only, None→degraded), restores
  labels on error, bails with the original message.
- **allow_unconfined path**: still `spawn_detached` (no labelling), status is
  degraded with the original message.
- **Default confined path**: still Low-labels + `spawn_confined` + same mapping +
  restores labels on error, bails with the original message.
- **Precedence** (locked > allow_unconfined > confined) is unchanged.
- `low_label_surfaces` restores all already-labelled paths on the first failure,
  preserving the "never strand a user dir at Low" invariant.

---

## Target 2: `crates/izba-jail-helper/src/provision.rs` — `win_enumerate_accounts`

### Problem

The post-`NetUserEnum` buffer-walk + `izba-spk-` prefix filter loop was inline
in the pagination loop, driving complexity to 21.

### Extraction

One `unsafe` helper was extracted:

| Helper | Purpose |
|--------|---------|
| `unsafe fn collect_izba_accounts(buf, count, out)` | Walk one NetUserEnum page buffer, decode UTF-16 names, filter by `ACCOUNT_PREFIX`, push matches into `out`, then free `buf` via `NetApiBufferFree` |

`win_enumerate_accounts` now calls `collect_izba_accounts` after each successful
`NetUserEnum` page, then sets `buf = std::ptr::null_mut()` so the error path
cannot double-free.

### Behavior / FFI correctness — unchanged

- `NetApiBufferFree` is still called on every exit path: error path in
  `win_enumerate_accounts` (if `NetUserEnum` fails with a non-null buffer) AND
  inside `collect_izba_accounts` after each successful page.
- `ACCOUNT_PREFIX` constant is still used (unchanged filter).
- NUL-terminated UTF-16 decode logic is byte-for-byte identical.
- The `SAFETY` comment on `collect_izba_accounts` documents the caller's
  obligations (valid buffer, count elements, single-use after call).

---

## Gate results (all green)

```
cargo test --workspace                                          OK  (all tests pass)
cargo fmt --check                                              OK  (no diff)
cargo clippy --workspace --all-targets -- -D warnings          OK  (0 warnings)
cargo check --target x86_64-pc-windows-gnu -p izba-core -p izba-jail-helper   OK
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-jail-helper -- -D warnings  OK
cargo build --target x86_64-pc-windows-gnu -p izba-core -p izba-jail-helper   OK
```
