# Automatic SSH access to sandboxes (v0.1.0 / MVP)

**Status:** approved design — ready for implementation plan
**Date:** 2026-06-22
**Scope:** v0.1.0 MVP, cross-platform (Linux + Windows hosts) from day one

## 1. Goal & motivation

When a user starts a sandbox, they should be able to `ssh izba-<sandbox_name>`
and land in a root shell inside the sandbox — with **zero per-sandbox setup**.
This unlocks the developer experiences that `izba exec` cannot:

- **VS Code Remote-SSH** (the headline use case) — edit/build/debug inside the
  microVM from the desktop editor.
- `scp` / `sftp` file transfer.
- `tmux`, long-lived interactive sessions, terminal multiplexers, `rsync`, etc.

The end-state the user asked for: an entry "appears" in `~/.ssh/config`
(izba-managed) so that `ssh izba-<name>` Just Works, conveniently and reliably.

## 2. The core constraint

The guest is a **NIC-less vsock island** — there is no IP path into the guest.
All host↔guest traffic rides Cloud Hypervisor / OpenVMM **hybrid-vsock**. SSH,
which expects a TCP socket, must be bridged over that vsock channel. The existing
**port-relay path already does exactly this**: `StreamOpen::TcpDial{port}` dials
a guest-local TCP port and splices bytes host↔guest over vsock 1026. SSH access
is therefore "a port relay to guest `127.0.0.1:22`, fronted by a stdio
`ProxyCommand`" — **no new wire protocol is required.**

There is no SSH server in the guest today (the initramfs is just static
`izba-init`; the rootfs is the user's OCI image). izba must provide one.

## 3. Approved decisions (from brainstorming)

| # | Decision | Rationale |
| - | -------- | --------- |
| Server | **izba vendors a static OpenSSH `sshd`**, embedded in the initramfs (like `nft`/`mke2fs`), launched by `izba-init`. | Works for *any* OCI image with zero image burden; OpenSSH (not Dropbear) for maximal VS Code / sftp compatibility. |
| Isolation | sshd binary + `sshd_config` + host key + `authorized_keys` live under an **izba-controlled path outside the overlay rootfs**; the **login session** is `ChrootDirectory /rootfs` so the user gets their real image. | Reliable regardless of how minimal/weird the user image is; session still has full image parity with `izba exec`. |
| Config mgmt | **Hybrid**: one `Host izba-*` wildcard block holds all behavior; **cheap per-sandbox stubs** (`Host izba-<name>`, no body) regenerated for tab-completion. Written to a **dedicated managed file** pulled in via a single `Include` line. | Centralized behavior + name completion, with no risk of corrupting the user's hand-maintained config. |
| Proxy stream | Reuse **`StreamOpen::TcpDial{port:22}`**. | Zero new protocol / no `DAEMON_PROTO_VERSION` bump; the daemon splice already does this. |
| Session entry | **`ChrootDirectory /rootfs`** (not `ForceCommand`). | ForceCommand would break VS Code Remote-SSH and scp (they run their own commands). |
| Auth | izba-managed **ed25519 user keypair**, pubkey injected into the guest at boot; `IdentityFile` set in the wildcard. | Frictionless — no "which key?" prompt, no agent questions. |
| Login user | **`root`** (`User root` in the wildcard). | Matches `izba exec`; fine for a throwaway sandbox. |
| Host key | **Single shared izba host key**, persisted in the data dir, injected into every guest; pinned into an izba-managed `known_hosts` with `StrictHostKeyChecking accept-new`. | No TOFU prompts, **no "host key changed" warnings ever** (even after `rm` + recreate) — required for VS Code's non-interactive flow. The real trust boundary is daemon+vsock access (local, single-user). |
| Always-on | sshd runs in **every** running sandbox (no per-sandbox flag). | Consistent with the "egress stub is always-on" philosophy. |
| Opt-out | A global setting `ssh.config_management` (default **on**). When off, izba writes nothing to `~/.ssh`; `izba ssh <name>` still works directly. | Some users are protective of `~/.ssh/config`. |

**Deferred (not built now):** SSH agent forwarding; non-root / multiple users;
using the user's own key instead of izba's; per-sandbox host keys; X11/advanced
forwarding; landing interactive ssh in `/workspace` instead of `$HOME` (a
nice-to-have profile drop-in, later).

## 4. Architecture

```
  ssh izba-foo                                         guest microVM (NIC-less)
      │ reads ~/.ssh/config → Include → Host izba-*   ┌──────────────────────────┐
      ▼                                               │  izba-init (PID 1)        │
  ProxyCommand: izba ssh-proxy foo                    │   └─ launches vendored    │
      │ stdio                                         │      static sshd          │
      ▼                                               │      bound 127.0.0.1:22   │
  DaemonClient.open_guest_stream("foo",               │      (config+keys from    │
        StreamOpen::TcpDial{port:22})                 │       initramfs, NOT the  │
      │ AF_UNIX → izbad                               │       OCI overlay)        │
      ▼                                               │                           │
  daemon splice ──── vsock 1026 ───────────────────►  │   session: ChrootDirectory│
                    (hybrid-vsock, CH/OpenVMM)        │   /rootfs, root, sftp     │
                                                      └──────────────────────────┘
```

## 5. Components

### (a) Vendored static sshd — guest side
- `hack/build-sshd.sh`: build/fetch a **static OpenSSH `sshd`** (sha-pinned,
  mirroring `hack/build-nft.sh`'s alpine-digest + source-tarball-sha pattern).
  Output embedded into the initramfs via a new `IZBA_SSHD` env hook in
  `hack/build-initramfs.sh`; lands at `/sbin/sshd` (izba-controlled, **not** the
  overlay).
- A static `sshd_config` shipped alongside it, with every sshd-owned path
  pointed at izba-controlled locations outside `/rootfs`:
  `HostKey`, `AuthorizedKeysFile`, `PidFile`, and `Subsystem sftp internal-sftp`
  (so sftp/scp + VS Code need nothing inside the user image). `ChrootDirectory
  /rootfs`. `PermitRootLogin prohibit-password` (key-only). Loopback-only listen.
- The new artifact is also produced + sha-pinned in CI (`artifacts.yml`,
  mirroring the nft job) and embedded by both initramfs build paths.

### (b) `izba-init` launch + session entry — `crates/izba-init/src/ssh.rs` (new)
- At boot (always-on, after net + rootfs are up): materialize the injected host
  key + `authorized_keys` to the izba paths with correct perms, then spawn
  `sshd -D` bound to `127.0.0.1:22`.
- `ChrootDirectory /rootfs` gives the session the user's image (shell, `$HOME`,
  tools, volumes). `/rootfs` already has `/dev`,`/proc`,`/etc/passwd` set up for
  `izba exec`, so we inherit that environment for free.
- Everything except process spawn is host-testable (keeps `main.rs` the only
  non-testable file, per the crate's test convention).

### (c) Host-side keys & identity — `crates/izba-core/src/ssh/identity.rs` (new)
- Lazily generate + persist under the data dir:
  - user keypair `~/.local/share/izba/ssh/id_ed25519`(`.pub`)
  - shared host key `~/.local/share/izba/ssh/ssh_host_ed25519_key`(`.pub`)
- Inject the user **public** key + the host **private** key into each guest at
  boot via the existing config/cmdline channel (the same channel that already
  ships the trust CA into the guest).
- Persisted with `0600` perms; generation is idempotent + concurrency-safe.

### (d) `~/.ssh/config` manager — `crates/izba-core/src/ssh/config.rs` (new)
- **Bootstrap (idempotent):** ensure an `Include` line at the top of
  `~/.ssh/config` (resp. `%USERPROFILE%\.ssh\config`); create the file if absent.
- **Managed file** contains:
  - the `Host izba-*` wildcard block: `ProxyCommand izba ssh-proxy %h` (with the
    `izba-` prefix stripped by the subcommand), `IdentityFile`, `User root`,
    `UserKnownHostsFile` (izba-managed), `StrictHostKeyChecking accept-new`,
    `IdentitiesOnly yes`.
  - cheap per-sandbox stubs: `Host izba-<name>` lines (no body) for each
    **running** sandbox, purely for `ssh izba-<TAB>` completion. (Stubs track
    the running set — `izba` can only SSH into a running sandbox, so a stub for
    a stopped one would only fail at connect.)
- **Regeneration:** enumerate the running sandbox set (daemon registry) and
  **atomically rewrite the whole managed file** (write temp + rename). No
  surgical edits. Pinned `known_hosts` written the same way.
- Gated by `ssh.config_management`.

### (e) CLI — `crates/izba-cli`
- `izba ssh-proxy <name>` (**hidden**): the `ProxyCommand` target. Opens a daemon
  guest-stream with `TcpDial{22}` and splices it to its own stdio. Cross-platform
  (same `DaemonClient`). Exits non-zero with a one-line message if the sandbox
  isn't running (so `ssh` reports a clean proxy failure, never hangs).
- `izba ssh <name> [-- args...]` (**user-facing**): execs the system `ssh` client
  with the right host alias/args. Works even when `ssh.config_management` is off
  (it passes the `ProxyCommand`/identity inline).

### (f) Daemon lifecycle hooks — `crates/izba-core/src/daemon/server.rs`
- In `handle_start` / `handle_stop` / `handle_rm`, after the existing
  relays/egress work, call the config-manager regeneration. **Best-effort**: a
  failure logs a warning and **never fails the sandbox lifecycle** (same posture
  as relays/egress).

## 6. Data flow (one `ssh izba-foo`)

1. `ssh` reads `~/.ssh/config` → `Include` → wildcard `Host izba-*` → runs
   `ProxyCommand izba ssh-proxy foo`.
2. `izba ssh-proxy foo` connects to `izbad` over AF_UNIX, sends
   `OpenStream{sandbox:"foo", StreamOpen::TcpDial{port:22}}`.
3. Daemon verifies `foo` is live, dials vsock `STREAM_PORT` (1026), splices ↔ the
   proxy's stdio.
4. Guest init's stream dispatch handles `TcpDial{22}` → dials `127.0.0.1:22` →
   sshd.
5. sshd authenticates the izba key (pinned host key ⇒ no prompts) →
   `ChrootDirectory /rootfs` → root shell in the user's image. VS Code/scp/sftp
   ride the same channel.

## 7. Error handling (fail honest, never break `~/.ssh`)

- **Sandbox not running:** daemon returns a clean error; `ssh-proxy` exits
  non-zero with `izba: sandbox '<name>' is not running`. No hang.
- **Config-management failure** (perms, read-only `$HOME`): log a warning, never
  fail the lifecycle.
- **Never corrupt user config:** only ever (a) add one idempotent `Include` line,
  (b) atomically rewrite *our own* managed file. Never edit inside the user's
  blocks.
- **sshd fails to start in guest:** logged to the captured `logs/console.log`;
  `ssh` falls back to honest connection-refused. Sandbox still boots — ssh is
  non-fatal to lifecycle.
- **Opt-out:** with `ssh.config_management = false`, izba writes nothing to
  `~/.ssh`; `izba ssh <name>` still works.

## 8. Security considerations

- sshd binds **loopback only**; the only path to it is a daemon-mediated
  `TcpDial` over vsock — same capability surface as `izba exec` / port relays. A
  caller that can splice to vsock 1026 can already reach any guest port, so SSH
  adds no new host→guest authority.
- Guest-is-hostile model: sshd's keys/config are sourced from the izba-controlled
  initramfs, never the (hostile) overlay; the host **private** host key shipped
  into the guest is acceptable because the guest is the SSH *server* and the
  trust boundary is the local vsock channel, not the network.
- Host keypair files are `0600` under the data dir; `IdentitiesOnly yes` keeps
  the user's other keys/agent out of izba sessions.
- The managed `~/.ssh/config` edit is the single new host-side dotfile mutation;
  it is additive (one `Include`) and otherwise confined to izba's own file.

## 9. Testing

- **Host-unit (`izba-core`):** config-manager bootstrap idempotency, atomic stub
  regen, opt-out, `Include` injection, Windows path handling; identity key
  gen/persist/perms/concurrency; `ssh-proxy` stdio↔stream splice via the
  `UnixStream::pair()` fake (no real listeners — per the bind-EPERM test
  constraint).
- **Init-unit (`izba-init`):** `ssh.rs` key/config materialization + launch-arg
  construction, host-testable.
- **KVM integration (`IZBA_INTEGRATION=1`, `izba-core`/`izba-cli`):** boot a
  sandbox; `ssh izba-<name> true` ⇒ exit 0; `scp` a file round-trip; assert the
  session chroot lands in the image (e.g. a marker file from the OCI image is
  visible, the izba sshd config is **not**).
- **Windows WHP validation:** the same `ssh izba-<name> true` over the OpenVMM
  bridge in `hack/spike/validate-izba-windows.ps1`.
- **Gates:** new `izba-core`/`izba-proto` surface keeps the
  `x86_64-pc-windows-gnu` cross checks + the app gate green; SonarCloud
  coverage/security on new code.

## 10. Open implementation questions (resolve during planning, not blocking)

- Exact static-sshd build recipe (alpine `openssh` package extraction vs. from
  source) — must yield a self-contained static `sshd` + `sftp-server`/internal
  needs. Mirror `build-nft.sh`; pick whichever yields a clean static binary.
- Channel for injecting host key + authorized_keys: reuse the trust-CA injection
  mechanism vs. a small dedicated file in the per-sandbox run dir mounted/*passed*
  to the guest. Prefer reusing the CA injection path for consistency.
