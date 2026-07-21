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
and the staging runbook in [hack/README.md](hack/README.md). Self-contained
installers ship on `v*` tags from the [GitHub Releases](../../releases) page: a
Linux `izba_*_amd64.deb` (bundling the CLI, cloud-hypervisor, virtiofsd, the
kernel, and the initramfs) and a Windows `izba-setup-*.exe` (Inno Setup).

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
    - "*.mydomain.com"           # one subdomain label (api.mydomain.com; quote it — YAML)
    - "**.mydomain.com"          # any depth (a.b.mydomain.com); apex needs its own entry
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

  Unknown keys anywhere in `policy.yaml` are rejected with an error naming the
  key and its valid alternatives — a typo can never silently widen egress scope.

  A bare host authorizes ports 80 and 443 only. To reach any other port,
  list it explicitly with `ports:` — explicit ports replace, not extend, the
  web default. (Before M2.1 a bare allow-list host reached every TCP port;
  that loophole is now closed.) `access:` defaults to `read-write` for HTTP
  hosts; `git:` rules are vendor-neutral (keyed on the git wire protocol, not a
  hostname) and read-only unless `access: read-write`.

  Host entries may be wildcards: `*.mydomain.com` matches exactly one
  subdomain label (`api.mydomain.com`, not `a.b.mydomain.com`), and
  `**.mydomain.com` matches any depth. The apex (`mydomain.com`) never
  matches a wildcard — list it explicitly alongside. Patterns apply on both
  enforcement paths (decrypted SNI/Host and the DNS-snooped connect gate),
  and a malformed pattern (`foo.*.com`) is rejected loudly when the policy
  loads. Quote wildcard entries in YAML — a bare `*` is YAML syntax.

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

  **Verifying enforcement: test with a real request, not a bare TCP connect.**
  Because the allow/deny verdict is rendered per request/SNI at the interception
  layer, `izbad` accepts the TCP connection *first* and decides *after* — so a
  bare `nc host 443` or bash `/dev/tcp/host/443` prints OPEN even for a denied
  host. Denial surfaces as the fetch failing, not as a refused connect. Probe
  with an actual request (e.g. `curl https://host/`): an allowed host returns a
  response, a denied one fails the TLS/HTTP exchange, and `izba netlog NAME`
  records the verdict either way.

  **Working under enforce: allow-list what your tooling needs.** Default-deny
  means a fresh enforcing sandbox can reach *nothing* — including your package
  mirror — so installs and fetches fail until you grant the hosts. Add them
  first (e.g. `izba policy allow NAME archive.ubuntu.com` and
  `izba policy allow NAME security.ubuntu.com` for apt on Ubuntu, plus
  whatever package index or registry you use), or pre-seed them in
  `policy.yaml`. A bare host opens the web ports 80 + 443 — the same meaning
  it has in `policy.yaml` — while `HOST:PORT` opens exactly that one port.
  `izba netlog NAME` lists exactly which endpoints were denied, so the log
  tells you what to allow next.
- **OCI → erofs + overlay rootfs.** Images are pulled, flattened to a single
  erofs image (read-only), and combined with a sparse ext4 rw disk via
  overlayfs inside the guest. The erofs is content-addressed and shared across
  sandboxes.

## Quickstart

**Installed from a release?** Installers (`izba_*_amd64.deb` for Linux/WSL2,
`izba-setup-*.exe` for Windows) are cut on `v*` tags; the
[Releases](../../releases) page currently carries **validation prereleases** —
the first stable tag lands when the MVP milestone completes (see
[docs/roadmap.md](docs/roadmap.md)). A prerelease package is self-contained
(CLI + cloud-hypervisor + virtiofsd + kernel + initramfs), so it lets you
**skip the artifact-staging steps below**, which are for building from source.
With one installed, jump straight to **3. Run a sandbox**.

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

Your tooling comes from the image: minimal bases (`alpine:3.20`, the default
`ubuntu:24.04`) ship without `curl`, `python3`, `sudo`, and friends, so a first
task like "fetch a URL" or "run a server" hits command-not-found. Install what
you need via the image's package manager (`apk add …`, `apt-get install …`) or
pick a fuller image. Under an **enforcing** egress policy the sandbox reaches
nothing by default, so allow-list your package mirror first (see "Working under
enforce" above) or the install itself fails.

See [`docs/testing.md`](docs/testing.md) for the full runbook and the
integration test suite.

## Commands

```
izba create [--image IMG] [--cpus N] [--mem MiB] [--rw-size-gb G] [-p [BIND:]HOST:GUEST]... [--volume [NAME:]GUEST_PATH:SIZE]... [--policy PATH] [DIR]
izba run    [--image IMG] [--rm|-d] [NAME_OR_DIR] [-- CMD...]   # create+start+exec; --rm reaps on exit, -d/--detach leaves it running
izba exec   NAME [-it] [-- CMD...]
izba ssh    NAME [-- CMD...]            # ssh into a running sandbox (root shell in the workspace)
izba cp     HOST_PATH NAME:GUEST_PATH   # or NAME:GUEST_PATH HOST_PATH; recursive
izba port   publish|unpublish|ls NAME [RULE]   # TCP, runtime or create-time -p
izba volume prune [-f]                  # remove persistent volumes no sandbox uses
izba ls
izba start  [NAME_OR_DIR]               # boot a stopped sandbox (no exec; symmetric with stop)
izba stop   [NAME_OR_DIR]
izba rm     [--force] [NAME_OR_DIR]
izba daemon run                         # run the daemon in the foreground (auto-started on demand otherwise)
izba daemon status                      # daemon health + supervised sandboxes
izba daemon stop                        # stop the daemon; sandboxes keep running, published ports pause
izba netlog  NAME [--summary] [--follow]   # egress audit log; --summary aggregates per endpoint
izba policy  show NAME                    # print the effective allow-list + enforce posture (on/off)
izba policy  enforce NAME on|off          # turn the firewall on (default-deny) or off (log-only)
izba policy  allow NAME HOST[:PORT]       # allow a destination (bare host = web ports 80+443); live-reloads
izba policy  block NAME HOST[:PORT]       # remove a destination (bare host = web ports 80+443); live-reloads
izba policy  git allow NAME TARGET [--write]  # allow git on a repo/host (clone/fetch; --write adds push)
izba policy  git block NAME TARGET        # remove a git rule
izba policy  enable NAME                  # seed the allow-list from observed allowed traffic; live-reloads
izba policy  reload NAME                  # re-read policy.yaml and apply to new connections (no restart)
izba diff    [NAME_OR_DIR] [--name NAME]  # show drift between izba.yml and managed truth
izba promote [NAME_OR_DIR] [--name NAME] [--force] [--restart] [--reset-scratch=BOOL]
                                          # apply manifest → managed truth (human-gated)
izba export  [NAME_OR_DIR] [--name NAME]  # write managed truth → izba.yml
```

### Referring to sandboxes

`status`, `start`, `stop`, `rm`, `diff`, `export`, and `promote` all take
`NAME_OR_DIR`: a **path-looking
argument** (`.`, `./proj`, `/abs/path`) always means a workspace directory; a
**bare word** means a sandbox name first (falling back to `./word` if that
directory holds an `izba.yml`); **no argument** means the sandbox of the
current directory — so `izba status`, `izba stop`, `izba diff` all "just work"
from a project root, git-style. If a bare word matches both a sandbox and a
directory that resolves to a *different* sandbox, izba refuses and asks for
the explicit `./word` or the exact name.

Volume `SIZE` takes a `g` or `m` suffix (e.g. `10g`, `512m`). A named volume is
persistent (lives under `<data>/volumes`, survives `rm`, single-writer); an
anonymous volume (no `NAME:`) is ephemeral. `izba volume rm`/`prune` ask for
confirmation on a terminal and otherwise need `-f/--force`.

**Lifecycle.** `izba run` does create + start + exec in one step (docker-parity)
and the sandbox **persists** after the command exits — stop it with `izba stop`,
restart it with `izba start` (or `izba run NAME` to start and exec again), and
delete it with `izba rm`. For a throwaway run, `izba run --rm -- <cmd>` removes
the sandbox (and its ephemeral resources; named volumes survive) once the
command exits, propagating its exit code — but only when that run *created* the
sandbox; `--rm` against a pre-existing sandbox leaves it in place. When
`NAME_OR_DIR` is omitted the sandbox is named after the current directory's
basename.

To **start a sandbox and leave it running in the background** — without
attaching a foreground shell — use the detached run (docker's `run -d`), then
reach it over `exec`/`ssh`/ports:

```sh
izba run -d ./myproj      # create + start, return immediately (prints the name)
izba ssh myproj           # …now SSH in (see below)
izba exec -it myproj      # …or open an interactive shell
```

The two-step form does the same thing: `izba create ./myproj` then `izba start
myproj`. (Don't reach for `izba run -- sleep infinity` to keep a sandbox alive —
a foreground `run` blocks until the command exits; `-d` is the right tool.)

## Project manifest (`izba.yml`)

An `izba.yml` at your project root declares a sandbox's desired configuration —
image or build recipe, resources, volumes, ports, and egress policy — in a
version-controllable file. `izba create` and `izba run` honor it automatically:
running bare `izba run .` picks it up with no flags.

```yaml
apiVersion: izba.dev/v1alpha1
kind: Sandbox
metadata:
  name: myapp                 # optional; defaults to workspace basename
spec:
  image: ubuntu:24.04         # an OCI ref
  # build:                    # OR a build recipe (requires build-in-VM)
  #   context: .
  #   dockerfile: Dockerfile
  resources:
    cpus: 2
    memory: 4Gi               # k8s quantity string (Mi/Gi)
  rootDisk:
    size: 8Gi                 # writable overlay (scratch) over the RO image
  volumes:
    - name: data              # named → persistent (survives rm); omit name → ephemeral
      mountPath: /data
      size: 8Gi
  ports:
    - guest: 80
      host: 8080
      bind: 127.0.0.1         # optional; defaults to 127.0.0.1
  egress:
    enforce: true
    allow:
      - host: github.com      # bare host → ports 80 and 443
      - host: api.example.com
        ports: [443]
        access: read          # read | read-write
    git:
      - repo: github.com/me/*
        access: read-write
```

`spec.resources` and `spec.rootDisk` are optional — when omitted they default
to **2 cpus / 4Gi memory / 8Gi root disk**, the same defaults as a bare
`izba run`, so a minimal manifest is just `apiVersion` + `kind` + `spec.image`.

**Trust model.** `izba.yml` lives in the project workspace, mounted at
`/workspace` inside the guest, so the in-guest agent can edit it. It is
therefore an **untrusted proposal**, not authority. The **managed truth** lives
host-only at `~/.local/share/izba/sandboxes/<name>/` (`config.json` +
`policy.yaml`) — outside the overlay, unreachable by the guest — and is the
only record that matters for a running sandbox. `izba promote` is the
**human-gated bridge**: you review the diff, approve it, and only then does
the manifest's intent become authoritative.

**The review loop: `izba diff` → `izba promote` → `izba export`**

```sh
izba diff    myapp    # show structural drift between izba.yml and managed truth
izba promote myapp    # apply the reviewed changes to the managed truth
izba export  myapp    # write managed truth → izba.yml ("save the truth back to the repo")
```

`izba diff` categorizes each changed field by blast radius:

- **Live** — `egress`, `ports`, `volumes`: applied immediately, no interruption.
- **Restart** — `resources`, `image`/`build`: written to managed truth, take
  effect on next start. `izba status` shows a `pending restart: cpus 2→4`
  delta. Use `izba promote --restart` to stop and restart now.
- **Image change** — when `image` or `build` changes, `promote` also governs
  the overlay scratch disk via `--reset-scratch` (default **true**):
  - `--reset-scratch=true` *(default)*: a fresh overlay on the new image base —
    correct semantics; discards un-volumed writes to the root filesystem.
  - `--reset-scratch=false`: keep the existing overlay (expert-only, loud
    warning; old overlay layers may be ABI-incompatible with the new base).

Any change that **weakens** the egress jail — adding `allow` entries, flipping
`enforce: true → false`, widening `access:` scope — is marked `⚠ weakens egress`
in `diff` and `promote` output. You cannot miss a loosened firewall.

**Review gate.** `izba diff` writes a host-only review token (`manifest.review`)
that covers the exact `izba.yml` (and any referenced `Dockerfile`) it just
showed. `izba promote` requires that token to match the current file — a TOCTOU
guard: if the manifest changes after `diff` but before `promote`, the promote
fails with ``izba.yml changed since `izba diff` — re-run it``. Use `--force`
to bypass (with a loud warning naming exactly what is being promoted unreviewed).
The token is host-only, so the in-guest agent cannot fabricate a reviewed state.

No secrets cross into the repo: `export` renders only declarative config; CA
keys, SSH host keys, and other host-only material are never written to `izba.yml`.

## SSH access (VS Code Remote-SSH, tmux, scp)

Every running sandbox is reachable over SSH with zero setup. First get a sandbox
running in the background (see **Lifecycle** above) — the one-step way is the
detached run:

```sh
izba run -d ./myproj     # create + start, return immediately (sandbox stays up)
```

izba keeps a small managed block in your `~/.ssh/config` (via a single
`Include`), so as soon as a sandbox is up you can:

```
ssh izba-<name>          # root shell in the sandbox, landing in /workspace
```

This rides the same NIC-less vsock transport as `izba exec` — there is no open
network port — through an izba-managed `ProxyCommand`. A vendored static OpenSSH
`sshd` runs inside the guest, isolated from your project image; the session is
chrooted into your image so you get its shell, tools, `$HOME`, and volumes.
Authentication uses an izba-managed key, so there are no prompts.

Because it's real SSH, the editor and CLI ecosystem just works against the
`izba-<name>` alias — including file transfer, which needs no extra setup (a
native `sftp-server` runs inside the guest):

```
scp ./local.txt izba-<name>:/workspace/      # copy a file in
scp izba-<name>:/workspace/out.txt ./        # …and back out
sftp izba-<name>                             # interactive sftp on the workspace
rsync -a ./src/ izba-<name>:/workspace/src/  # mirror a tree
code --remote ssh-remote+izba-<name> /workspace   # VS Code Remote-SSH
```

`scp`/`sftp`/`rsync` and VS Code Remote-SSH all rely on the managed
`izba-<name>` alias in `~/.ssh/config`, so they need config management **on**
(the default). `izba ssh <name>` does the same thing as a one-shot command (and works even if
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
