# izba

> *izba* — a small self-contained log cabin; cozy, isolated, ownable.

Open-source per-project microVM sandboxes for AI coding agents, inspired by
Docker Desktop's agent sandboxes (`sbx`). Each sandbox is a lightweight KVM
virtual machine: your project directory is shared in live, the guest
environment is any OCI image, and everything outside that boundary is isolated.
Background on izba's architecture and where each piece comes from: [`docs/design-lineage.md`](docs/design-lineage.md).

## Status

v1 in active development. Linux/KVM (including WSL2 nested virtualization)
works end-to-end (gated integration suite green). Windows/WHP via OpenVMM
works end-to-end as well (experimental): a natively cross-built `izba.exe`
pulls, builds erofs with the bundled native `mkfs.erofs.exe`, and boots
sandboxes under OpenVMM — full CLI parity is script-validated on Windows 11
24H2. See the
[Windows-port design + bring-up findings](docs/superpowers/specs/2026-06-10-izba-windows-port-design.md)
and the staging runbook in [hack/README.md](hack/README.md); there is no
installer yet (binaries are staged by script).

## How it works

```
 izba CLI ──spawns──► cloud-hypervisor (per sandbox)     ┌─ microVM ──────────────┐
          ──spawns──► virtiofsd  (workspace share)  ◄────┤ izba-init (PID 1)      │
          ──connects─► vsock port 1025 (control RPC) ◄───┤  ├ overlay rootfs      │
                       vsock port 1026 (stdio streams)◄──┤  ├ /workspace virtiofs │
       izbad ◄─dials── vsock port 1027 (egress: TCP/DNS) ┤  └ spawns workloads    │
                                                         └────────────────────────┘
```

Key properties:

- **Daemon-first, daemonless soul.** Every `izba` command auto-starts `izbad`
  (the same binary, via `izba daemon run`, socket
  `~/.local/share/izba/daemon/izbad.sock`) — no install or service step
  required. The daemon rebuilds all state from disk at startup, so you can kill
  or upgrade it at any time without harming running sandboxes.
- **Disk-state as source of truth.** `state.json` records every PID with its
  `starttime` field from `/proc/<pid>/stat` to defeat PID reuse.
- **Three vsock ports.** Port 1025 carries length-prefixed JSON control RPCs
  (Health, Exec, Wait, Resize, Shutdown). Port 1026 carries raw stdio/tty
  streams. Port 1027 carries **guest egress** — the guest dials out and `izbad`
  bridges it.
- **One network story: all egress through izbad.** The guest is a NIC-less
  vsock island — no `passt`, no `consomme`, no host-side user-mode NAT. The
  in-guest stub redirects all outbound TCP (nftables + `SO_ORIGINAL_DST`) and
  DNS to `izbad` over vsock 1027; `izbad` is the single point that dials the
  outside world. The **agent firewall** (`--policy policy.yaml`,
  `izba netlog`) enforces a per-sandbox egress allow-list and logs every
  connection.

  **Off by default; opt in to enforce.** A bare sandbox does **not** restrict
  egress — everything is allowed and merely logged. The firewall starts
  *enforcing* a default-deny allow-list only once you turn it on, either by
  creating with `--policy policy.yaml` or by running
  `izba policy enforce NAME on`. While enforcing, anything not on the allow-list
  is blocked; an **empty** allow-list under enforcement denies all egress. Turn
  it back off with `izba policy enforce NAME off`, and check the current posture
  with `izba policy show NAME` (prints `enforce: on|off`).

  A `policy.yaml` allow entry is a bare host (web ports 80/443 only) or an
  explicit host+ports pair, and the file carries the enforce posture plus
  optional per-host access and git rules:

  ```yaml
  enforce: true                  # false (or omitted) = log-only, allow everything
  allow:
    - api.anthropic.com          # web ports only: 80 and 443
    - host: db.internal
      ports: [5432]              # exactly 5432 — explicit ports replace the default
    - host: docs.internal
      access: read               # HTTP GET/HEAD only; writes (POST/PUT/…) blocked
  git:
    - repo: github.com/myorg/myrepo    # clone/fetch; read-only (no push) by default
    - repo: github.com/myorg/deploy
      access: read-write               # also allow git push
    - host: github.com                 # or scope a whole host instead of a repo
  ```

  A bare host authorizes ports 80 and 443 only. To reach any other port,
  list it explicitly with `ports:` — explicit ports replace, not extend, the
  web default. (Before M2.1 a bare allow-list host reached every TCP port;
  that loophole is now closed.) `access:` defaults to `read-write` for HTTP
  hosts; `git:` rules are vendor-neutral (keyed on the git wire protocol, not a
  hostname) and read-only unless `access: read-write`.

  **HTTPS under enforce is intercepted (MITM) — the izba CA is auto-trusted.**
  To apply the allow-list and the `access:`/`git:` rules to *encrypted* traffic,
  an enforcing sandbox terminates TLS at `izbad`: it mints a per-host leaf
  certificate for the connection's SNI/Host, signed by a stable **izba egress
  CA**, applies the policy to the decrypted request, then re-originates TLS to
  the real host. izba writes that CA into the guest (`/etc/izba/ca.pem`, plus a
  combined system+izba bundle at `/etc/izba/ca-bundle.pem`) and, for every
  `izba exec`, defaults the standard trust-env vars so common tools trust it
  with no setup: `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
  `GIT_SSL_CAINFO` (→ the bundle) and `NODE_EXTRA_CA_CERTS`, `DENO_CERT`
  (→ `ca.pem`). So `curl`, `git`, Python `requests`, Node, and Deno verify
  successfully out of the box; a tool that reads only the OS trust store should
  be pointed at `/etc/izba/ca.pem` (e.g. copy it into
  `/usr/local/share/ca-certificates/` and run `update-ca-certificates`). A
  **bare** (non-enforcing) sandbox does NOT intercept TLS and ships no CA —
  connections dial straight through.

  **Working under enforce: allow-list what your tooling needs.** Default-deny
  means a fresh enforcing sandbox can reach *nothing* — including your package
  mirror — so installs and fetches fail until you grant the hosts. Add them
  first (e.g. `izba policy allow NAME archive.ubuntu.com` for apt on Ubuntu,
  plus whatever package index or registry you use), or pre-seed them in
  `policy.yaml`. `izba netlog NAME` lists exactly which endpoints were denied,
  so the log tells you what to allow next.
- **OCI → erofs + overlay rootfs.** Images are pulled, flattened to a single
  erofs image (read-only), and combined with a sparse ext4 rw disk via
  overlayfs inside the guest. The erofs is content-addressed and shared across
  sandboxes.

## Quickstart

**1. Install runtime dependencies**

```sh
hack/fetch-artifacts.sh
```

This fetches `cloud-hypervisor` and `virtiofsd` static binaries into
`~/.local/bin` and checks for `mkfs.erofs` (install via your distro package
manager if missing). No `passt` — egress is izbad-owned over vsock.

**2. Build the kernel and initramfs**

```sh
hack/build-kernel.sh
hack/build-initramfs.sh
```

**3. Run a sandbox**

```sh
izba run --image alpine:3.20 .
```

This creates (if needed), starts, and drops you into a shell inside the
sandbox, with your current directory shared at `/workspace`.

See [`docs/testing.md`](docs/testing.md) for the full runbook and the
integration test suite.

## Commands

```
izba create [--image IMG] [--cpus N] [--mem MiB] [--rw-size-gb G] [-p [BIND:]HOST:GUEST]... [--volume [NAME:]GUEST_PATH:SIZE]... [--policy PATH] [DIR]
izba run    [--image IMG] [NAME_OR_DIR] [-- CMD...]
izba exec   NAME [-it] [-- CMD...]
izba ssh    NAME [-- CMD...]            # ssh into a running sandbox (root shell in the workspace)
izba cp     HOST_PATH NAME:GUEST_PATH   # or NAME:GUEST_PATH HOST_PATH; recursive
izba port   publish|unpublish|ls NAME [RULE]   # TCP, runtime or create-time -p
izba volume prune [-f]                  # remove persistent volumes no sandbox uses
izba ls
izba stop   NAME
izba rm     [--force] NAME
izba daemon run                         # run the daemon in the foreground (auto-started on demand otherwise)
izba daemon status                      # daemon health + supervised sandboxes
izba daemon stop                        # stop the daemon; sandboxes keep running, published ports pause
izba netlog  NAME [--summary] [--follow]   # egress audit log; --summary aggregates per endpoint
izba policy  show NAME                    # print the effective allow-list + enforce posture (on/off)
izba policy  enforce NAME on|off          # turn the firewall on (default-deny) or off (log-only)
izba policy  allow NAME HOST[:PORT]       # allow a destination (port defaults to 443); live-reloads
izba policy  block NAME HOST[:PORT]       # remove a destination (port defaults to 443); live-reloads
izba policy  git allow NAME TARGET [--write]  # allow git on a repo/host (clone/fetch; --write adds push)
izba policy  git block NAME TARGET        # remove a git rule
izba policy  enable NAME                  # seed the allow-list from observed allowed traffic; live-reloads
izba policy  reload NAME                  # re-read policy.yaml and apply to new connections (no restart)
```

Volume `SIZE` takes a `g` or `m` suffix (e.g. `10g`, `512m`). A named volume is
persistent (lives under `<data>/volumes`, survives `rm`, single-writer); an
anonymous volume (no `NAME:`) is ephemeral. `izba volume rm`/`prune` ask for
confirmation on a terminal and otherwise need `-f/--force`.

## SSH access (VS Code Remote-SSH, tmux, scp)

Every running sandbox is reachable over SSH with zero setup. izba keeps a small
managed block in your `~/.ssh/config` (via a single `Include`), so as soon as a
sandbox is up you can:

```
ssh izba-<name>          # root shell in the sandbox, landing in /workspace
```

This rides the same NIC-less vsock transport as `izba exec` — there is no open
network port — through an izba-managed `ProxyCommand`. A vendored static OpenSSH
`sshd` runs inside the guest, isolated from your project image; the session is
chrooted into your image so you get its shell, tools, `$HOME`, and volumes.
Authentication uses an izba-managed key, so there are no prompts.

Because it's real SSH, the editor and CLI ecosystem just works:

- **VS Code Remote-SSH** — open host `izba-<name>` and edit/build/debug inside the microVM.
- `scp` / `sftp`, `rsync`, `tmux`, long-lived interactive sessions.

`izba ssh <name>` does the same thing as a one-shot command (and works even if
config management is disabled). To keep izba out of your `~/.ssh/config`
entirely, set `config_management: false` in `<data>/ssh/settings.json` — `izba
ssh <name>` still works directly.

## Project layout

```
crates/
  izba-core/   # sandbox lifecycle, VMM driver trait + Cloud Hypervisor driver,
               #   OCI image → rootfs pipeline, guest control-plane client
  izba-cli/    # `izba` binary — thin wrapper over izba-core; auto-starts izbad
  izba-init/   # guest PID 1 agent (static musl x86_64); boots, mounts,
               #   and serves the control + stream ports
  izba-proto/  # host↔guest protocol types shared by core and init
  izba-ttytest/ # dev-support: PTY/ConPTY harness driving the real izba binary
               #   through a pseudo-terminal for automated exec -it tests
hack/          # scripts to fetch binaries and build the kernel/initramfs
docs/          # architecture notes, design spec, testing runbook
```

## Documentation

| Doc | Read it for |
| --- | --- |
| [docs/superpowers/specs/2026-06-10-izba-v1-design.md](docs/superpowers/specs/2026-06-10-izba-v1-design.md) | The v1 design: every decision with its rationale, deferred scope, open spikes |
| [docs/design-lineage.md](docs/design-lineage.md) | Design lineage & prior art — how each subsystem maps to its public OSS building blocks |
| [docs/testing.md](docs/testing.md) | End-to-end testing runbook (WSL2/KVM setup, integration suite) |
| [hack/README.md](hack/README.md) | Building the kernel/initramfs and fetching runtime binaries |
| [CLAUDE.md](CLAUDE.md) | Contributor/agent crash course: build gates, crate map, load-bearing contracts |

## License

[Apache-2.0](LICENSE).
