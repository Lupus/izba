# Plan: `izba policy allow --read` — CLI verb for HTTP host read-only access (#84)

Issue: https://github.com/Lupus/izba/issues/84 (type:feature, priority:P2, effort:S, milestone v0.1.0)

## Context

The `access: read` control already exists in the policy model
(`Access::{Read,ReadWrite}` in `crates/izba-core/src/daemon/egress/config.rs`)
and is enforced by the MITM HTTP layer (`policy.rs` rego: "read host denies
POST"), but it is unreachable from the CLI without hand-editing `policy.yaml`.
The git sub-surface already exposes the equivalent split via
`izba policy git allow --write`. This plan adds the symmetric `--read` flag to
`izba policy allow` and makes `izba policy show` display the access verb for
HTTP host entries.

Existing seams (all already on origin/main — no core changes needed):

- `EgressPolicyConfig::allow(host, port)` — adds host/port, preserves an
  existing entry's access verb on rewrite (#147 fix), defaults NEW entries to
  `Access::ReadWrite`.
- `EgressPolicyConfig::set_host_access(host, access)` — sets the access verb,
  preserving ports; adds the entry if absent. Already used by the GUI
  (`app/src-tauri/src/daemon.rs`).
- `edit_policy_file(dir, f)` — load-modify-save closure over `policy.yaml`.
- Rego policy layer already denies non-GET/HEAD methods for `access: read`
  hosts and emits audit (netlog) entries for denials.

## Global Constraints

- Changes live in `crates/izba-cli/src/commands/policy.rs` plus test files
  only. NO changes to `izba-core` public types, NO wire-protocol changes, NO
  `DAEMON_PROTO_VERSION` bump, NO app/src-tauri changes.
- Back-compat: `izba policy allow NAME HOST` without `--read` must continue to
  produce `access: read-write` for NEW entries, and must continue to PRESERVE
  the existing access verb when editing an existing entry (the #147 behavior —
  plain `allow` must NOT widen an existing `read` entry back to `read-write`).
- No `--read-write` flag (out of scope; the default stays implicit).
- No changes to `git allow --write` or any git rule handling.
- TDD: write failing tests first, then the implementation. Conventional
  commits, `Refs #84` in bodies.
- Gates that must stay green: `cargo test --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`.

## Task 1: `--read` flag on `izba policy allow` + `policy show` access annotation

**Files:** `crates/izba-cli/src/commands/policy.rs` (only).

TDD order — tests first (they must fail before the implementation lands):

1. Clap parse test `parse_policy_allow_read`: `izba policy allow web
   api.x.com --read` parses to `PolicyCmd::Allow { name: "web", target:
   "api.x.com", read: true }`; and without the flag `read` is `false`
   (extend the existing parse-test style in the same file).
2. Round-trip test `allow_read_records_read_access` (style of the existing
   `allow_then_block_round_trips_a_policy_file`):
   - fresh dir, allow with read → entry has `access: Access::Read`.
   - fresh dir, allow without read → `access: Access::ReadWrite` (back-compat
     pin, distinct from the existing test so both paths are pinned).
   - allow WITHOUT read on the existing read entry (different port) →
     access STAYS `Access::Read` (no silent widening; #147 behavior through
     the CLI edit path).
   - allow WITH read on an existing read-write entry → access becomes
     `Access::Read` (explicit narrowing).
3. Show-rendering test: `policy show` must display `read` vs `read-write`
   for each HTTP host entry. To make this unit-testable, extract the
   rendering of a loaded config into a pure helper
   `fn render_policy(name: &str, cfg: Option<&EgressPolicyConfig>) -> String`
   that `show()` prints; test asserts the rendered string contains the host
   line with `(read)` for a read entry and `(read-write)` for a read-write
   entry, plus the existing no-policy and empty-allow-list lines stay intact.

Implementation:

- Add `/// Restrict to read-only HTTP access (GET/HEAD only); default is
  read-write` doc-commented `#[arg(long)] read: bool` to `PolicyCmd::Allow`.
- Update `Allow`'s subcommand doc comment (the `--help` text) to mention
  `--read` and its effect (read-only = GET/HEAD).
- Wire in `run()`'s `Allow` arm: one `edit_policy_file` closure doing
  `cfg.allow(&host, port)` then, only when `read`, `cfg.set_host_access(&host,
  Access::Read)`. Keep `apply_edit`'s existing signature usable by other
  callers — check `apply_edit` call sites first; if the manifest/other paths
  use it, leave it intact and route the Allow arm through the closure form
  directly (or extend `apply_edit` with an `Option<Access>` parameter if that
  reads cleaner — implementer's choice, but do not change observable behavior
  of other call sites).
- `show()`: render each HTTP allow entry as
  `    HOST  [PORTS] (ACCESS)` where ACCESS is `read` / `read-write`,
  mirroring the git rules' existing `(access)` annotation style.
- Update the existing `verbs_bail_cleanly_on_unknown_sandbox` test's
  `PolicyCmd::Allow` constructions for the new field.

Commit: `feat(cli): izba policy allow --read for read-only HTTP host access` +
`Refs #84`.

## Task 2: end-to-end verification test — CLI-written config enforces GET-allowed/POST-denied with audit entries

**Files:** `crates/izba-core/tests/egress_mitm.rs` (test only; no product code).

Goal (issue AC4, host-side without KVM): a host added the way the CLI's
`allow --read` path writes it must, through the real MITM enforcement layer,
allow GET, deny POST, and produce audit (netlog) entries for both.

- Study the existing tests in `egress_mitm.rs` (e.g. the allowed-host and
  denied-host request tests around `guest_request`) and follow their harness
  pattern exactly.
- Build the policy the same way the CLI does: construct an
  `EgressPolicyConfig`, apply `cfg.allow("host", port)` +
  `cfg.set_host_access("host", Access::Read)`, set `enforce: true`, then
  `cfg.into_policy("sandbox")` — this pins the CLI-written shape compiling to
  a real enforcing policy (not a hand-written rego data doc).
- Assert: GET through the MITM succeeds (upstream reached); POST is denied
  (blocked response, upstream NOT reached); both produce the expected audit
  records the way neighboring tests assert them (allowed + denied entries).
- If `egress_mitm.rs`'s harness proves unsuitable for driving methods (POST)
  end-to-end, fall back to the policy seam: a test in the same style as
  `config.rs`/`policy.rs` unit tests that runs `into_policy` over the
  CLI-shaped config and checks `Verdict::Allow` for GET and `Verdict::Deny`
  for POST plus the audit/netlog record emission at the enforcement seam that
  neighboring tests use. Prefer the MITM harness if at all workable.

Commit: `test(core): CLI-shaped read-only host config enforces GET/POST split
through MITM` + `Refs #84`.
