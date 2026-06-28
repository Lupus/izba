# Host-side resolution of an image's symbolic `USER`

**Status:** approved design (2026-06-28)
**Issues:** #96 (P1, "Resolve symbolic image USER to a numeric uid/gid in-guest
— Option A userns"), #90 (P2, the older duplicate). Follow-up to PR #95 (Option
A container user-namespace uid mapping) and PR #88 (the loud root-fallback).

## Problem

crun's `config.json` `process.user` is numeric-only per the OCI runtime spec.
izba resolves the image's declared `USER` **host-side** in
`write_oci_bundle`/`resolve_process_user`. Today only a **numeric** `USER`
(`1000`, `1000:1001`) resolves; a **symbolic** one (`node`, `nonroot`, `app`,
`1000:wheel`) falls back to root `(0,0)` with a loud warning (PR #88).

Official images (`node`, `python`, `nginx`, `golang`) and distroless all ship
symbolic `USER` directives, so for the common case izba silently drops the
image's intended privilege-dropping: the workload runs as root, and the Option-A
userns transposition makes **root** (not the image USER) own `/workspace`.

## Goal

- `USER node` (symbolic) runs `exec`/`ssh` as node's real numeric uid.
- That same uid owns `/workspace` inside the container (the Option-A
  transposition is keyed on the resolved uid).
- Numeric `USER` behaviour is unchanged.
- The loud root-fallback fires **only** when the name genuinely cannot be
  resolved.

## Approach: resolve host-side from the image's own `/etc/passwd`

Docker/containerd resolve `USER` against the **image rootfs's** `/etc/passwd` at
container-create time — host-side, not in the running container. izba's flatten
pipeline (`image/flatten.rs`) already walks every file of the merged image, so
the image's `/etc/passwd` + `/etc/group` are available at pull/flatten time.

We **capture** those two files into the content-addressed image store, then
**resolve** the symbolic `USER` host-side at config-build time, feeding the
numeric `(uid, gid)` into both `process.user` and the existing Option-A
transposition (`compute_userns_mappings`). 

This keeps every new line of logic **pure and unit-testable** in `izba-core`
(the codebase's stated preference for the config-merge layer) and requires
**zero guest changes** — no writable-bundle workaround, no JSON handling or
duplicated transposition math in the static-musl `izba-init`. Because `exec`
and `ssh` already pass `--user None` (they inherit the container's configured
`process.user`), baking the resolved uid into `config.json` host-side makes
interactive sessions land as the right uid automatically.

(The alternative — resolving in-guest, as issue #96 originally proposed — was
rejected: the `izba-oci` bundle is mounted read-only in the guest and
`izba-init` deliberately carries no `serde_json`/`izba-core`, so it would need a
writable-bundle copy, in-guest JSON patching, and a second copy of the
transposition arithmetic. Issue #90 explicitly flags the resolution site as
negotiable.)

## Components

### 1. Capture — `image/mod.rs` + a pure extractor

`publish_image` already writes `merged.tar`, builds the erofs from it, then
removes it. Between flatten and removal we read the tar **once** with a new pure
helper:

```rust
/// Pull the raw bytes of `etc/passwd` and `etc/group` out of a flattened
/// image tar. Path-normalized (absolute `/etc/passwd`, `./etc/passwd`,
/// `etc/passwd` all match); last-wins on duplicate entries; regular-file
/// entries only. Returns `(passwd, group)`, each `None` when absent.
fn extract_user_dbs(merged_tar: &Path) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)>
```

`flatten_layers` stays an untouched, already-exhaustively-tested stream merge —
the extra read of a local file is cheap and isolated. The captured bytes are
persisted via the store before `merged.tar` is removed.

### 2. Image store — `image/store.rs`

Mirror the existing `config.json` cache surface:

- `passwd_path(digest)` / `group_path(digest)` → `passwd` / `group` in the
  image dir.
- `load_user_dbs(digest) -> Result<(Option<String>, Option<String>)>` —
  `NotFound` → `None` per file (the legacy-cache shape, like `load_config`).
- `persist_user_dbs(digest, passwd: Option<&[u8]>, group: Option<&[u8]>)` —
  atomic temp-file + rename, like `persist_config`.

### 3. Resolver — `image/runtime_config.rs`

Pure, no I/O:

- `parse_passwd(&str) -> Vec<PasswdEntry { name, uid, gid }>` and
  `parse_group(&str) -> Vec<GroupEntry { name, gid }>` — standard
  colon-separated `/etc/passwd`(7-field) / `/etc/group`(4-field); skip blank /
  `#`-comment / malformed lines.
- `struct UserDb { passwd: Vec<PasswdEntry>, group: Vec<GroupEntry> }` with
  `resolve(spec: &str) -> Option<(u32, u32)>` honouring docker `user[:group]`:
  - `name` → passwd lookup → `(uid, that entry's primary gid)`.
  - numeric `uid` → `(uid, 0)` if no passwd entry (docker's numeric default);
    **numeric specs do not consult passwd** (matches docker — keeps current
    `parse_numeric_user` behaviour).
  - `user:group` → uid from passwd-or-numeric, gid from group-or-numeric; any
    component unresolvable ⇒ `None`.
- `resolve_process_user(declared: Option<&str>, db: &UserDb) -> ((u32,u32), Option<String>)`:
  - `None` / `Some("")` → `((0,0), None)` (silent root — unchanged).
  - fully numeric → resolved pair, no warning (unchanged).
  - symbolic, resolved via `db` → resolved pair, no warning. **(new)**
  - symbolic, unresolvable → `((0,0), Some(msg))` where `msg` names the USER and
    says it could not be resolved against the image's `/etc/passwd`.

`parse_numeric_user` stays as the numeric fast-path. Everything downstream
(`compute_userns_mappings`, the `process.user` build in `generate_spec`) already
keys on the returned `(uid,gid)` — unchanged.

### 4. Wire-up — `sandbox.rs`

`start_with_timeouts` already has `paths` + the image `digest`; it loads the
user dbs from the store (`load_user_dbs`), builds a `UserDb`, and passes it into
`write_oci_bundle`, which calls `resolve_process_user(declared, &db)` instead of
the single-arg form. The existing loud-warning `eprintln!("warning: sandbox
'{name}': …")` convention is reused for the now-rare true fallback.

## Edge cases & decisions

- **Legacy cached images** (published before this change → no `passwd`/`group`
  captured): `load_user_dbs` returns `(None, None)` ⇒ an empty `UserDb` ⇒
  symbolic `USER` falls back to **loud root** until the image is re-pulled (a
  cache miss re-captures). Reading `/etc/passwd` back out of the already-built
  erofs is expensive, so there is **no** re-pull/self-heal here (unlike
  `config.json`, whose blob was already in hand from the manifest fetch).
  Numeric/root paths are unaffected. Documented graceful degradation.
- **`USER` naming a user created at runtime** (by the entrypoint, absent from
  the image's passwd) → unresolvable → loud root. Matches docker exactly.
- **Numeric `USER 1000`** → `(1000, 0)`, no passwd lookup — unchanged, matches
  docker.
- **Image without `/etc/passwd`** (scratch / distroless-static) + symbolic USER
  → loud root. (Distroless `nonroot` ships `/etc/passwd` with uid 65532 → it
  resolves.)
- **Partly-symbolic `1000:wheel`** → uid `1000` numeric, gid from the image's
  `/etc/group` `wheel` entry; `None` (loud root) if `wheel` is absent.

## Testing

**Unit (host, no VM):**
- `parse_passwd`/`parse_group`: well-formed, comments/blank/short lines,
  trailing newline, duplicate names.
- `UserDb::resolve`: name, `name:group`, `uid:group`, `name:gid`, numeric-only,
  unknown name → `None`, unknown group → `None`.
- `resolve_process_user`: symbolic resolved, numeric unchanged, empty/None
  silent root, unresolvable loud root (message names the USER).
- `extract_user_dbs`: absolute vs `./`-prefixed paths, last-wins across layers,
  missing passwd and/or group, non-regular entries ignored.
- store `load_user_dbs`/`persist_user_dbs`: round-trip, `NotFound` → `None`,
  atomic overwrite, corrupt/dir read error propagation.

**Integration (real VM, `IZBA_INTEGRATION=1`):** extend the existing Option-A
userns round-trip harness in `crates/izba-core/tests/integration.rs` with a
fixture image declaring a **named** `USER`; assert the workload runs as the
resolved non-zero uid (`id -u`) and that uid owns `/workspace`. Numeric and
root variants already covered there stay green.

## Out of scope

- `additionalGids` / supplementary groups beyond the primary (separate issue).
- Surfacing a past symbolic→root fallback in `izba status` (issue #114).
- E2E sudo round-trip under a non-root numeric USER (issue #97).
