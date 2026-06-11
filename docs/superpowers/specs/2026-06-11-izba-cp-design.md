# `izba cp` — host↔guest file transfer (tar-stream) — Design

Status: approved 2026-06-11. Companion spec:
[2026-06-11-izba-port-publish-design.md](2026-06-11-izba-port-publish-design.md)
(shares the §2 wire groundwork defined canonically HERE).

sbx parity target: `sbx cp` (host↔guest file transfer over the control plane).
izba v1 design context: docs/superpowers/specs/2026-06-10-izba-v1-design.md.

## 1. Goals and non-goals

**Goals**

- `izba cp <host_path> <NAME>:<guest_path>` and
  `izba cp <NAME>:<guest_path> <host_path>` against a **running** sandbox.
- Recursive by construction (the payload is a tar stream): regular files,
  directories, symlinks; modes and mtimes preserved.
- Works on both host OSes (Linux + Windows) by construction — pure vsock +
  the pure-Rust `tar` crate; no guest-image dependency (the guest side lives
  in `izba-init`, not in the image rootfs).
- Daemonless: one stream-port connection per copy, no new processes.

**Non-goals (v1)**

- uid/gid mapping (extracted entries land root-owned, like `docker cp`).
- Compression, globbing, multiple sources, `-` (stdin/stdout tar), progress UI.
- Hardlink preservation (archived as independent regular files).
- Special files (sockets, fifos, devices): skipped with a warning on either
  side's walk.
- Copying from/to a stopped sandbox (sbx can read stopped sandboxes via the
  daemon; we require a running VM — the guest agent does the work).

## 2. Shared wire groundwork: `StreamOpen` (canonical definition)

This section is the **pre-fork groundwork commit on main** shared with the
port-publish feature. Both ends of the protocol ship together (no deployed
third parties), per the CLAUDE.md load-bearing-contract rule.

Today the first frame on a port-1026 (STREAM_PORT) connection is always a bare
`StreamAttach`. It becomes a tagged enum in `izba-proto`:

```rust
/// First frame on a port-1026 connection, selecting what the connection is.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamOpen {
    /// Attach to an exec's stdio/tty stream (existing semantics, unchanged).
    Attach(StreamAttach),
    /// Port-publish relay: init dials 127.0.0.1:port inside the guest,
    /// replies one Response frame (Ok | Error{ConnectFailed}), then the
    /// connection is a raw bidirectional byte pipe.
    TcpDial { port: u16 },
    /// cp host→guest: a raw tar stream follows; init extracts under `dest`
    /// (workload-root-relative resolution, §4), then replies one trailing
    /// Response frame (Ok | Error).
    TarExtract { dest: String },
    /// cp guest→host: init replies one Response frame first (Ok | Error —
    /// e.g. PathNotFound), then streams a tar of `src` and closes.
    TarCreate { src: String },
}
```

`ErrorKind` gains two variants (serde snake_case like the rest):

```rust
pub enum ErrorKind {
    CommandNotFound,
    ExecNotFound,
    BadRequest,
    Internal,
    PathNotFound,   // cp: guest src/dest missing
    ConnectFailed,  // ports: guest-side dial failed (refused/timeout)
}
```

Groundwork commit contents (all in one commit, six gates green):

1. `izba-proto`: `StreamOpen` enum + `ErrorKind` variants + roundtrip tests.
2. `izba-init` `server.rs::serve_streams`: parse `StreamOpen` instead of
   `StreamAttach`; `Attach` keeps today's behavior verbatim; `TcpDial`,
   `TarExtract`, `TarCreate` answer `Error{BadRequest, "not implemented"}`
   and close (each feature branch fills in its arm).
3. `izba-core` host helpers that send the first frame wrap it in
   `StreamOpen::Attach` (exec path unchanged).
4. `izba-ttytest` `ScriptedGuest`: parse `StreamOpen`, treat `Attach` as
   before, reject the rest.

## 3. CLI surface and semantics

```
izba cp SRC DST
  where exactly one of SRC, DST is NAME:PATH (guest), the other a host path
```

- **Guest-ref detection:** split each operand at the first `:`. The operand is
  a guest ref iff the prefix is a syntactically valid sandbox name
  (`[a-z0-9][a-z0-9_.-]*`, case-sensitive) **and** a sandbox directory with
  that exact name exists. Otherwise it is a host path. Windows drive paths
  (`C:\x`) parse as host paths because `C` (uppercase) is never a valid
  sandbox name. Both operands guest → error; neither guest → error; ambiguity
  is resolvable by prefixing the host path with `./`.
- **Relative guest paths** resolve against `/workspace` (exec's default cwd).
- **Destination rules** (docker-flavored, both directions):
  - dest exists and is a directory → copy *into* it (`cp a NAME:/etc` puts
    `/etc/a`).
  - dest does not exist → the source is renamed to dest (`cp a NAME:/etc/b`
    creates `/etc/b`); for a directory source, dest becomes the new tree root.
    Parent of dest must exist (`PathNotFound` otherwise).
  - dest exists and is a file: file source → overwrite; directory source →
    error ("cannot overwrite non-directory with directory").
- **Top-level source symlink is followed** (docker behavior); symlinks
  *inside* a copied tree are preserved as symlinks.
- The sandbox must be running and healthy; otherwise the CLI errors with the
  same "not running" message family as `exec`.
- Exit codes: 0 success, 1 any failure (message on stderr). No 127/128+n
  mapping here — those are exec-specific.

## 4. Guest side (`izba-init`)

- New module `tarfs.rs` (host-testable, like the rest of init): implements
  the `TarExtract`/`TarCreate` arms over any `Read+Write` stream using the
  `tar` crate (pure Rust; musl-static friendly — the init binary must stay
  static, gate 4).
- **Workload-root resolution (the safety property):** guest paths are
  interpreted exactly as the workload sees them — i.e. under the overlay root
  (`/rootfs` from init's perspective) — and **no tar entry, dest, or symlink
  encountered during resolution may escape that root** into init's initramfs.
  The plan picks the mechanism; acceptable options are `openat2(2)` with
  `RESOLVE_IN_ROOT` (kernel ≥ 5.6; ours is 6.12) or a forked child that
  `chroot`s like the exec engine. The property is tested, not assumed (§7).
- Extraction: root-owned, tar modes + mtimes applied
  (`unpack_in`-equivalent semantics with the root constraint above);
  pre-existing files overwritten; `tar::Archive::set_preserve_permissions(true)`,
  `set_preserve_mtime(true)`, ownership not chowned.
- Creation: walk `src` under the same root rules; append regular files, dirs,
  symlinks; skip other file types with a warning side-channel (a `pax`
  comment is over-engineering — skipped entries are simply absent; the CLI
  documents this).
- After extraction completes (tar EOF blocks read), init writes one
  `Response` frame: `Ok` or `Error{kind, message}`. For creation, init writes
  the leading `Response` frame *before* the tar bytes, then the archive, then
  closes. Tar's two zero-block terminator is the end-of-archive marker in
  both directions, so trailing/leading status frames are unambiguous.

## 5. Host side (`izba-core` + `izba-cli`)

- `izba-core/src/cp.rs`: `pub fn copy_to_guest(sandbox, host_src, guest_dest)`
  and `pub fn copy_from_guest(sandbox, guest_src, host_dest)`. Each opens one
  stream connection (existing `connect_stream` helper → hybrid-vsock
  `CONNECT 1026`), sends the `StreamOpen` first frame, then drives
  `tar::Builder` (to guest) or `tar::Archive` (from guest).
- Host-side dest rules (§3) are applied locally for guest→host copies;
  guest-side dest rules are applied by init for host→guest copies. The
  rename-to-dest rule is implemented by rewriting the top-level path
  component of tar entry names on the *sending* side, so the receiver only
  ever extracts "into a directory" — one code path each end.
- `izba-cli/src/commands/cp.rs`: operand parsing (§3 guest-ref detection),
  clap wiring (`Commands::Cp { src, dst }`).
- New workspace dependency: `tar` (pinned minor; no default features beyond
  what's needed). It must cross-compile for `x86_64-pc-windows-gnu`
  (gates 5–6) and `x86_64-unknown-linux-musl` (gate 4).

## 6. Error handling

| Failure | Behavior |
| --- | --- |
| sandbox missing / not running | CLI error before any connection (same liveness path as `exec`) |
| guest src missing (`TarCreate`) | leading `Error{PathNotFound}` frame → CLI: "NAME:/path: no such file or directory", exit 1 |
| guest dest parent missing (`TarExtract`) | trailing `Error{PathNotFound}` |
| escape attempt via symlink/`..` | trailing `Error{BadRequest, "path escapes workload root"}`; partial extraction may remain (documented; same as an interrupted docker cp) |
| connection death mid-stream | missing tar EOF blocks → "transfer truncated" error, exit 1 |
| disk full in guest | trailing `Error{Internal, <io message>}` |

## 7. Testing

- **Unit (six gates, no listeners — `UnixStream::pair()` / `PairListener`):**
  - proto: `StreamOpen` + new `ErrorKind` roundtrips (groundwork commit).
  - init `tarfs`: extract/create round-trip over a socketpair against a temp
    dir standing in for the workload root; modes/mtimes/symlinks preserved;
    **escape tests**: tar entries with `../` names and a symlinked parent dir
    must fail with `BadRequest`, nothing written outside the root.
  - core `cp`: dest-rule matrix (dir-exists / rename / overwrite / dir-onto-
    file error) against a fake guest on a socketpair; truncated-stream error.
  - cli: operand parsing matrix incl. `C:\x` and `./a:b` cases.
- **Integration (KVM, `IZBA_INTEGRATION=1`, ubuntu:24.04):** copy a small
  tree into `NAME:/etc/izba-cp-test` and back out; assert byte-equality,
  exec bit, symlink survival; copy from a missing guest path → exit 1.
- **Windows:** by construction; folded into the `validate-izba-windows.ps1`
  manual gate (precedent: erofs spec §3.4).

## 8. Out of scope, recorded for later

- `cp` against stopped sandboxes (needs host-side erofs/ext4 mounting or a
  daemon — v2 territory).
- An `--archive`/ownership-mapping flag, progress reporting, `-` streams.
