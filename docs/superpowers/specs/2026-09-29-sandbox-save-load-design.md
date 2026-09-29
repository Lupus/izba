# Sandbox save/load (move sandboxes between hosts) — design

Status: approved in brainstorming 2026-09-29; awaiting written-spec review.

## 1. Goal

Zero-fuss migration of sandboxes between laptops: one command on the old host
produces one file; one command on the new host restores the sandboxes so that
`izba start` just works. Disk contents (rw.img, anonymous + named volumes,
image rootfs.erofs) arrive **byte-identical, and that is verified**, not
assumed. The workspace can optionally travel in the same archive.

### Decisions taken (with the owner)

| Question | Decision |
| --- | --- |
| Platforms | Any ↔ any: Linux↔Linux, Windows↔Windows, Linux↔Windows |
| Archive scope | 1..N named sandboxes (or `--all`) per archive; shared images/named volumes stored once |
| Workspace placement on load | Smart default + override (§3.2) |
| Workspace content | Everything verbatim (`.git`, untracked, ignored, `.env`, symlinks, mode bits) |
| Surfaces | CLI + daemon now; GUI is a follow-up issue |
| Trust | Archives are the user's own: integrity + structural checks, no posture-review gate, no encryption |
| Owner-uid change (non-docker) | Idmapped upper at boot, disks stay byte-identical forever (§5) |

`izba export` already exists (writes `izba.yml` from managed config), so the new
verbs are **`izba save` / `izba load`**.

### Non-goals (follow-up issues)

GUI Save/Load buttons; streaming to/from stdout (`-o -`, `izba load -`);
encryption; incremental/delta archives.

## 2. `izba save`

```
izba save <name…> | --all  -o <file.izba>  [--with-workspace] [--stop]
```

- Refuses a running sandbox ("stop it first or pass --stop"). `--stop`
  stops each gracefully first and **never** restarts it. Each sandbox's
  `lock_sandbox` is held for the whole copy (blocks start and config edits).
  Named volumes are additionally checked with `persistent_volume_holder` so a
  volume held by any other live sandbox is refused.
- Captures per sandbox: `config.json`, `policy.yaml`, `manifest.base.yaml`,
  `manifest.review`, `logs/egress-audit.jsonl` (each if present), `rw.img`,
  anonymous volumes `volumes/<eph_id>.img`; plus each referenced named volume
  and image (once per archive); plus the workspace tree with
  `--with-workspace`.
- Windows source: NTFS has no exec bits, so they are taken from
  `git ls-files -s` (mode `100755`) when the workspace is a git repo and `git`
  is on PATH; otherwise files are 0644, dirs 0755.
- Never captured (host-bound or regenerated on start): `state.json`,
  `ports.json`, `lockdown.json`, `lockdown.cred`, `trust/`, `ssh/`, `oci/`,
  `vnc/`, `vnc.password`, `logs/console.log`, `buildout/`, `run/`, lock files,
  tombstones.
- Writes `<out>.partial`, renames to `<out>` on success; deletes the partial and
  releases all locks on any error or client disconnect.
- Reports progress in bytes; ends with logical vs archive size and a one-line
  note that the archive may contain secrets from disks/workspace.

## 3. `izba load`

```
izba load <file.izba> [<name>…] [--as <new>] [--workspace <dir> | --workspace-root <dir>]
```

`--as` and `--workspace` are only valid when exactly one sandbox is selected.
`--workspace-root <dir>` places each bundled/bound workspace at
`<dir>/<basename(source workspace)>`.

### 3.1 Preflight (before any write)

- `manifest.json` is the first entry; `format` newer than supported → refuse.
- Name collision with an existing sandbox → error pointing at `--as`.
- Free space: sum of allocated bytes + 5% headroom, checked per target
  filesystem (data root vs workspace destination may differ).
- Named volume already present on target: identical sha256 → reuse
  (idempotent re-load); different → hard error naming the volume.

### 3.2 Workspace

- **Bundled:** extract to the source path if it does not exist or is an empty
  dir. Cross-OS, a source path under the source home is translated relative to
  the target home (`/home/u/proj` ↔ `%USERPROFILE%\proj`); a path outside home
  requires `--workspace`/`--workspace-root`. Never extracts over a non-empty
  directory.
- **Not bundled:** bind to the (translated) source path if it exists (e.g. the
  user already cloned the repo); else `--workspace` is required.
- Symlink creation failing on Windows (no Developer Mode / privilege) → load
  fails loudly with that remedy; links are never silently dropped.
- The chosen path gets the same `ensure_confinable` preflight as `create`
  (Windows drive-root rejection etc.) and is canonicalized the same way.

### 3.3 Host-bound fields

- Images: if the digest already exists on the target, the target's copy is
  kept (overlay is path-level; replacing it could disturb the target's other
  sandboxes). Needed tag → digest entries are added to `tags.json` when absent.
- USB: `busid_pin` cleared, grant (`vid:pid`) kept.
- Lockdown: never imported; reported as "re-run `izba lockdown <name>`".
- Ports: rules kept; rules whose host port is currently in use are warned.
- The final report lists everything to redo on this host.

### 3.4 Result

Sandboxes arrive **stopped**, registered (daemon registry rescan) and the
managed ssh config regenerated, exactly as after `create`.

## 4. Archive format

A zstd-compressed (multithreaded, `zstd` crate — new dependency) tar stream,
extension `.izba`. Entry order:

```
manifest.json
images/<digest>/{rootfs.erofs,config.json,ref.txt,passwd?,group?}
volumes/<name>.img.xsp
sandboxes/<name>/{config.json,policy.yaml?,manifest.base.yaml?,manifest.review?,egress-audit.jsonl?}
sandboxes/<name>/rw.img.xsp
sandboxes/<name>/volumes/<eph_id>.img.xsp
workspaces/<name>/…
```

### 4.1 `manifest.json`

- `format: 1`, izba version (`build_info`), source OS, created-at.
- `tags`: tag → digest entries the included sandboxes need.
- Per sandbox: name, `disk_owner` (uid, gid) (§5.1), workspace bundled?,
  source workspace path, source home dir.
- Per blob: archive path, logical length, allocated bytes, **sha256 of the full
  logical content (holes read as zeros)**. Workspace files are covered by one
  aggregate digest over (path, mode, type, link target, content sha) records.

### 4.2 `.xsp` sparse encoding

A tar entry whose body is: magic `IZSPARSE`, version, logical length, extent
count, extent list `[(offset, len)]`, then the extent bytes concatenated.

- Save: extents from `SEEK_DATA`/`SEEK_HOLE` (Linux) or
  `FSCTL_QUERY_ALLOCATED_RANGES` (NTFS), then all-zero 64 KiB blocks inside
  extents are elided too (a fully-allocated file still ships small).
- Load: create, `mark_sparse` (NTFS `FSCTL_SET_SPARSE`), `set_len(logical)`,
  write extents only. The logical sha256 is recomputed while writing.

### 4.3 Structural checks on load

Every tar path must be relative, normalized, without `..` or absolute
components, and inside a known top-level prefix; no device/fifo entries;
workspace symlink *targets* are kept verbatim (they are workspace content) but
extraction never follows a symlink it created (same discipline as `izba cp`'s
`TarExtract`). `config.json` is re-validated with the same rules as `create`
(volume count/paths, sizes, ports, docker⊕builder).

## 5. Disk-owner remapping (non-docker sandboxes)

### 5.1 Problem

Non-docker sandboxes run under the Option-A userns map
`M = transpose_identity_map(W, O)` (W = image `USER`, O = workspace host
owner; identity when W == O or O == 0). Everything the workload writes to the
overlay upper and user volumes is stored as **guest** ids, i.e. depends on O.
Moving to a host with owner O′ (a different uid, or the Windows anchor 0)
would present those files with the wrong owner in-container. Docker-mode
sandboxes are unaffected (idmapped layers store container ids verbatim).

### 5.2 Invariant: preserve the container view

Container id `c` was stored as `M_src(c)`; on the target it must present as
`M_tgt(c)`. The disk idmap is therefore

    P = M_tgt ∘ M_src⁻¹        (per leg: uid, gid)

Both maps are transpositions or identity, so P permutes at most
{0, O, O′, W}. The set of files owned by container-root is unchanged by
construction (e.g. an image with `USER root` stored its files as disk O on
the source; on an `O′ = 0` target P presents them as guest 0 = container 0).
This is **not** a plain O↔O′ swap (that would turn root-owned upper files into
user-owned ones when O′ = 0).

### 5.3 Mechanism

- `SandboxConfig.disk_owner: Option<(u32, u32)>`, `#[serde(default)]`.
  `None` = disks are in the current owner's ids — every existing and every
  newly created sandbox, so today's behavior is unchanged. `load` sets it to
  the source's effective owner: its own `disk_owner` if set, else the
  workspace owner it had at save time (so A→B→C chains stay correct).
- `sandbox::start`, where the owner is already re-derived by stat: if
  `disk_owner` is set, the sandbox is not docker mode, and P ≠ identity, emit
  `izba.diskidmap=<uid extents>;<gid extents>` (full 0..2³² coverage,
  `disk-presented-count` triples as in `layer_idmap_cmdline_value`). One pure
  generation function, one call site.
- `izba-init`: parse `izba.diskidmap`; before overlay assembly, apply an
  idmapped mount of P to `/upper` (vdb) only — the erofs lower stays unmapped,
  so image ids are read under the target's own map exactly like a fresh
  `create` there — and to each user volume. Reuses docker mode's `idmap`
  helpers. **Fail closed:** if the kernel refuses, boot fails with a console
  message; never silently wrong ownership.
- Cmdline chain (CLAUDE.md "Cmdline chain") gains `[izba.diskidmap=…]`.

### 5.4 Spike (first plan task; gates §5.3)

On a real KVM VM (kernel 6.18): overlayfs accepts an idmapped upper over a
non-idmapped erofs lower; copy-up and new writes land on disk as P⁻¹ of the
presented id (moving back is lossless); an idmapped ext4 user volume mounts at
its guest path. If overlayfs rejects a mixed idmap, stop and bring the
fallback (idmap the lower with its own map preserving the container view)
back to the owner before proceeding.

### 5.5 Security

P only permutes among ids already mapped by the source/target maps and
preserves the container view, so no file gains container-root (or any other)
ownership it did not have on the source. Guard test: for every disk id `x` in
{0, O, O′, W, and a few others}, `M_tgt⁻¹(P(x)) == M_src⁻¹(x)`. A short note goes into `docs/security/` (identity
layer change).

## 6. Code structure

New `izba-core/src/bundle/` (pure library, no daemon/CLI assumptions):

| File | Responsibility |
| --- | --- |
| `manifest.rs` | Manifest types, (de)serialization, validation, format gate |
| `sparse.rs` | Per-OS extent enumeration; `.xsp` encoder/decoder |
| `hash.rs` | Logical-content hashing reader/writer |
| `save.rs` | Plan (resolve + dedup images/named volumes), locks, stream entries |
| `load.rs` | Preflight, staged extraction, verify, atomic commit, rollback |
| `workspace.rs` | Workspace tar, git exec bits, cross-OS path translation, symlink policy |
| `diskmap.rs` (or in `image/runtime_config.rs`) | P computation + cmdline value |

Daemon (`daemon/proto.rs`, `daemon/server.rs`):

- `DaemonRequest::Save { names, all, out, with_workspace, stop }` and
  `DaemonRequest::Load { path, select, rename, workspace, workspace_root }`,
  returning `SaveReport` / `LoadReport` (sizes, warnings, redo-on-this-host
  list). Progress via existing `DaemonResponse::Progress` (phase + bytes text).
- `DAEMON_PROTO_VERSION` 6 → 7; CLAUDE.md load-bearing contract updated.
- Load commits via registry rescan + ssh-config regeneration, as `create`.
- The app (`app/src-tauri`) embeds izba-core/izba-proto, so its gate is run
  even though its UI is deferred.

CLI: `izba save`, `izba load` — thin clap wrappers printing progress.

## 7. Error handling

- Save: `<out>.partial` + rename; cleanup and lock release on error or client
  disconnect (detected by a failed progress write). `--stop` failure aborts
  before writing.
- Load: stage in `<data>/.load-<pid>/` (same filesystem → final step is a
  rename); workspaces stage beside their target. Commit order: images →
  named volumes → workspaces → sandbox dirs → registry rescan. Rollback
  removes only what this load created; reused pre-existing images/volumes are
  never touched. Stale `.load-*` dirs whose pid is dead are swept at the next
  load.
- Hash mismatch, truncated stream, bad zstd → hard error naming the entry.
- Every error names the next action (`--as`, `--workspace`, "enable Developer
  Mode", "stop it first or pass --stop").

## 8. Testing

TDD throughout.

- Unit (`bundle/`, no listener binds): `.xsp` round-trips (all-hole,
  all-data, alternating, trailing hole, zero-block elision, non-64K-aligned
  length); manifest validation (future format, traversal, absolute, device
  entries); dedup planning (two sandboxes sharing image + named volume); load
  rollback with a failure injected at each commit step via a seam; collisions
  (name, same-hash volume reuse, different-hash volume refusal); workspace
  path translation (Linux↔Windows, outside-home ⇒ `--workspace`); git
  exec-bit recovery.
- P guard tests: identity ⇒ no flag; O↔O′; O→0 and 0→O (root stays root);
  W==O on either side; uid and gid legs diverging; cmdline golden.
- Proto: serde round-trip of new requests/reports; version == 7.
- KVM e2e (`daemon_e2e`): create non-docker sandbox; write as image USER into
  `$HOME`, a named and an anonymous volume; `save --with-workspace --stop`;
  `rm` + remove the named volume; `load --as` into a fresh data root; start;
  assert disk sha256 == pre-save, contents, and in-container owners. Second
  case: changed `disk_owner` ⇒ container view preserved. Third: docker-mode
  round-trip.
- Windows: `validate-izba-windows.ps1` gains save/load on Windows plus a
  sparseness check. The cross-OS move (WSL → Windows via `/mnt/c`) is
  exercised manually through interop before the PR is reported.
