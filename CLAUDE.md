# CLAUDE.md

izba: open-source per-project microVM sandboxes for AI coding agents — an
independent reimplementation of the per-project-microVM agent-sandbox model
popularized by Docker Desktop's `sbx`, built from public OSS building blocks.
Daemon-first Rust CLI on top of Cloud Hypervisor/KVM, with a Windows/WHP-via-
OpenVMM driver (M0 done).

## Documentation map

| Doc | What it holds |
| --- | --- |
| [README.md](README.md) | Product overview, quickstart, command surface |
| [docs/vision.md](docs/vision.md) | **Product North Star** — what izba is becoming (compose-for-microVMs + service mesh + credential vault) and the locked steering decisions. Read before product-direction changes. |
| [docs/superpowers/specs/2026-06-12-izba-mesh-networking-design.md](docs/superpowers/specs/2026-06-12-izba-mesh-networking-design.md) | v2 networking + multi-sandbox mesh design (decisions + rationale; `izbad` as vsock policy hub). The technical "how" for the vision. |
| [docs/roadmap.md](docs/roadmap.md) | **Roadmap** — current-state assessment, milestones M0–M5 + adoption track, risk register, open product decisions. Read before picking the next work item. |
| [docs/superpowers/specs/2026-06-10-izba-v1-design.md](docs/superpowers/specs/2026-06-10-izba-v1-design.md) | **The approved v1 design** — decisions + rationale, §8 spikes, §9 v2 horizon. Read before architectural changes. |
| [docs/superpowers/plans/2026-06-10-izba-v1.md](docs/superpowers/plans/2026-06-10-izba-v1.md) | The executed v1 implementation plan (historical; useful for "why is X built this way") |
| [docs/design-lineage.md](docs/design-lineage.md) | **Design lineage & prior art** — how each izba subsystem maps to its public OSS building blocks (Cloud Hypervisor, OpenVMM, rust-vmm, virtiofs, containerd erofs, NVIDIA OpenShell). Read before architectural changes or external comparisons. |
| [docs/security/README.md](docs/security/README.md) | **Security program** — threat model (guest-is-hostile microVM model), audit methodology (classical + LLM-driven SOTA + spec-first/TDD assurance), and the findings register. Read before any change that touches a trust boundary. |
| [docs/egress-firewall-building-blocks.md](docs/egress-firewall-building-blocks.md) | OSS building-block survey + decisions for the **egress firewall** (M2 allow-list + MITM, M5 credential vault): regorus, DNS-snoop, NVIDIA OpenShell salvage map. Read before M2/M5 work. |
| [docs/testing.md](docs/testing.md) | KVM integration-suite runbook (WSL2 setup, deps, troubleshooting) |
| [hack/README.md](hack/README.md) | Artifact tooling: kernel config/build, initramfs, binary fetching |

## Build & test

```sh
[ -f .cargo-env ] && source .cargo-env   # sandbox-local toolchain, if present
cargo test --workspace                    # all unit/mock tests; integration tests self-skip
cargo clippy --workspace --all-targets -- -D warnings   # gate: zero warnings
cargo fmt --check
cargo build -p izba-init --target x86_64-unknown-linux-musl --release  # must stay static
cargo check  --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli
cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings
```

All six must be green before any commit (the cross gates need `rustup target
add x86_64-pc-windows-gnu` and the `gcc-mingw-w64-x86-64` toolchain). Real-VM integration tests need KVM +
artifacts and are env-gated: `IZBA_INTEGRATION=1 cargo test -p izba-core --test
integration -- --test-threads=1` (full setup in [docs/testing.md](docs/testing.md)).
Daemon e2e (also KVM-gated): `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1`.

Both KVM suites + the Windows WHP validation also run in CI:
`.github/workflows/e2e.yml` (main pushes, weekly cron, manual dispatch).

Coverage (report-only, not a gate): `hack/coverage.sh --html` runs the host
suite under `cargo-llvm-cov` and writes `target/coverage/coverage-gaps.md` (a
QA gap report ranked by uncovered-line impact) + lcov + html. Same run in CI
via `.github/workflows/coverage.yml` (every PR + main push). Separate real-VM
coverage jobs (`linux-kvm-coverage` + `windows-whp-coverage` in `e2e.yml`,
weekly cron + dispatch, isolated from the gates) boot actual microVMs under
instrumentation: Linux emits a merged host+e2e report, Windows its own platform
report (OpenVMM/WHP driver paths, not cross-merged). `IZBA_INTEGRATION=1
hack/coverage.sh` does the Linux part locally. Needs `cargo install
cargo-llvm-cov` + `rustup component add llvm-tools-preview`.

**Agent environment reality check (do NOT re-derive this wrong):** this WSL2
instance has nested virtualization — `/dev/kvm` exists and works; it is merely
INVISIBLE inside Claude's sandboxed Bash. Run the KVM suites with the sandbox
disabled and they work right here. Likewise the Windows host is reachable via
WSL interop: `powershell.exe -NoProfile ...` (also unsandboxed) runs the
Windows validation suite (`hack/spike/validate-izba-windows.ps1`) on the host
directly. Neither requires a different machine.

**Test design constraint:** unit tests never bind unix/vsock listeners — some
sandboxes deny `bind` with EPERM. Use `UnixStream::pair()` fakes (see the
`PairListener` pattern in `crates/izba-init/src/server.rs` tests); tests that
genuinely need a listener must runtime-skip on `PermissionDenied` (see
`full_connect_via_listener` in `crates/izba-core/src/vsock.rs`).

## Crate map

- `izba-proto` — host↔guest wire protocol: u32-LE length-prefixed JSON frames
  + `Request`/`Response`/`StreamOpen` types. Shared verbatim by both sides.
- `izba-core` — the product library, zero CLI assumptions. `sandbox.rs` is the
  lifecycle heart; `vmm/` driver trait + Cloud Hypervisor impl; `image/`
  OCI→erofs pipeline; `procmgr.rs` detached spawning; `vsock.rs`
  hybrid-vsock client; `daemon/` izbad server+client (framed JSON over AF_UNIX);
  `daemon/egress/` the guest-initiated vsock-1027 plane (policy/dns/router/
  manager seams — M1 AllowAll policy + raw-UDP DNS forwarder, M2+ fill in);
  `build_info.rs` compile-time build metadata (git describe/sha/date, rustc,
  target, profile) via a `vergen-gitcl` `build.rs` — the single source of truth
  for `izba --version` / `izba version`, the daemon hello/status, and the app.
- `izba-init` — guest PID 1 (static musl): mounts, exec engine (PTY + pipes),
  vsock servers, NIC-less net bring-up (`net.rs`) + egress stub (`egress.rs`:
  DNS UDP:53→vsock `Dns` half and TCP nft-REDIRECT→`TcpConnect` half).
  Everything except `main.rs` is host-testable.
- `izba-cli` — thin clap binary over izba-core.
- `izba-ttytest` — dev/test-support: drives the real `izba` binary through a
  PTY/ConPTY (portable-pty + vt100) against a scripted fake guest or a real
  sandbox; the automated `exec -it` checklist. Tests live in `crates/izba-cli/
  tests/{tty_scripted,tty_e2e}.rs` behind the `ttytests` feature.
- `app/src-tauri` (Tauri 2 GUI) — **OUT of the workspace, separate gate.** It is
  `exclude`d from the root workspace (`Cargo.toml`) but embeds `izba-core` +
  `izba-proto` by path. The six workspace gates above do NOT compile it, so a
  wire/type change in core (a new field on `DaemonRequest`, a changed enum
  variant, a struct built by field shorthand) can stay green across `cargo
  {test,clippy} --workspace` while silently breaking the GUI build. When you
  touch `izba-core`/`izba-proto` public types, also run the app gate locally:
  `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
  (The App CI **linux** job also runs `cargo fmt --check` on `app/src-tauri` — it
  is easy to forget since the workspace gate uses a separate `cargo fmt --check`.)
  CI mirrors this as the **App CI** workflow (`.github/workflows/app.yml`, jobs
  `app frontend + backend (linux)` / `(windows)`); both are branch-protection
  required checks on `main`, alongside the four `ci.yml` gates.

## Load-bearing contracts (change all ends or none)

- **Disk-state invariant (daemon-first):** a sandbox = its dir under
  `~/.local/share/izba/sandboxes/<name>/` + live processes; liveness is
  always re-verified via pid + `/proc/<pid>/stat` starttime identity — never
  trusted from `state.json` alone. `izbad` (auto-started `izba daemon run`,
  socket `<data>/daemon/izbad.sock`, framed-JSON `daemon::proto`) holds NO
  authoritative state: it adopts everything from disk at startup, so
  killing/upgrading it never harms sandboxes. Port relays are daemon
  threads; rules persist in `ports.json` (plain `Vec<PortRule>`).
  VMs/sidecars are never auto-restarted — death ⇒ honest unhealthy reason.
  The CLI↔daemon hello exchanges `DAEMON_PROTO_VERSION` (the COMPATIBILITY gate
  — bump on any wire-breaking frame change; a stale-proto daemon is auto
  shut-down + respawned) plus a display-only `BuildInfoOwned` (git sha/date).
  Both `proto` and `build` are `#[serde(default)]` so a pre-change daemon
  deserializes to proto 0 and self-heals via one restart.
- **vsock ports:** 1025 control RPC, 1026 streams, 1027 egress
  (`CONTROL_PORT`/`STREAM_PORT`/`EGRESS_PORT` in izba-proto). Stream conns send
  ONE `StreamOpen` frame (`Attach` exec streams / `TcpDial` port relays /
  `TarExtract`+`TarCreate` for cp), then bytes per the variant's framing. Host
  reaches them via Cloud Hypervisor hybrid-vsock: `CONNECT <port>\n` on
  `run/vsock.sock`, response read byte-by-byte (buffering eats stream data). CH
  does NOT propagate vsock half-close guest→host: teardown must be full
  `SHUT_RDWR` once TX is done. CLI streams now reach the guest through izbad's
  `OpenStream` splice (client sends the guest `StreamOpen` in-band after the
  daemon replies Ok); the framing after the splice is unchanged.
  **Egress is INVERTED (guest-initiated):** the guest dials CID 2:1027; the
  VMM bridges that to izbad's `run/vsock.sock_1027` unix listener (Firecracker
  hybrid-vsock convention, shared by CH and OpenVMM). The guest sends one
  `StreamOpen::TcpConnect{addr,port}` (TcpDial's reply contract inverted:
  izbad dials out + replies `Ok`/`Error`, then raw byte pipe) or
  `StreamOpen::Dns` (RFC 1035 2-byte-BE length framing per `izba_proto::dns`,
  request/response alternating). TCP `:53` routes to the same resolver.
- **Disk order:** `sandbox::start()` builds
  `[rootfs.erofs (RO)=vda, rw.img (RW)=vdb, vol₀=vdc, vol₁=vdd, …]`
  (`build_vm_disks`) → CH enumerates `--disk` in that order, OpenVMM gives each
  disk its own PCIe root port via `disk_port(i)` (vda, vdb, vdc, …) → init
  mounts `/dev/vda` erofs lower + `/dev/vdb` ext4 upper into an overlay at
  `/rootfs`, then formats-if-blank + mounts each user volume `/dev/vd{c…}` at
  its declared guest path under `/rootfs` (after the overlay + virtiofs).
  User volumes append after `rw.img` in declaration order; the binding between
  a volume and its `vd{c…}` slot is purely positional, carried on `izba.volumes`
  (see Cmdline chain). Max 24 volumes (26 virtio-blk slots − vda − vdb).
  Named volumes are persistent (`<data>/volumes/<name>.img`, survive `rm`,
  single-writer); anonymous are ephemeral (in the sandbox dir).
- **Cmdline chain:** `console=ttyS0 izba.hostname=<name> izba.egress=1
  [izba.volumes=<p0>,<p1>,…]` ↔
  `hack/kernel.config` (`SERIAL_8250_CONSOLE`; netfilter/nftables —
  `NF_TABLES`/`NFT_NAT`/`NFT_REDIR`/`NF_CONNTRACK` — + `CONFIG_DUMMY`) ↔ init
  reads `izba.hostname` for sethostname and `izba.volumes` (ordered,
  comma-separated guest mountpoints, one per user volume in `vd{c…}` order) for
  the volume format+mount pass. NO `ip=dhcp`: the guest is a NIC-less
  vsock island. `izba.egress=1` is vestigial — init no longer reads it; the
  egress stub is always-on. init brings up `lo` + `dummy0`
  (`192.168.127.2/24`, alias `192.168.127.1` as the default-route gateway via
  `net.rs`): `dummy0` is the structural deny — anything the stub does not
  intercept has nowhere to go. resolv.conf = `nameserver 127.0.0.1`
  (loopback is REQUIRED, not cosmetic: 127/8 hits the nft `return` rule and is
  never REDIRECTed; a REDIRECTed UDP reply is DROPPED — the stub answers from
  an unconnected wildcard socket so the source mismatches and conntrack never
  un-NATs it; see `egress.rs` NFT_RULESET doc). `/sbin/nft` is vendored into
  the initramfs via `IZBA_NFT` (`hack/build-nft.sh`) and applies the nat-output
  REDIRECT ruleset at boot. (passt/consomme/`izba.ipv4only` are GONE from the
  datapath as of M1 — all egress flows through izbad over vsock 1027.)
- **Linux VMM confinement (MVP-C):** on Linux, cloud-hypervisor and virtiofsd
  launch **confined by default** — explicit `--seccomp true`, `--landlock`
  (Landlock v5+), virtiofsd `--sandbox namespace` (fallback `--sandbox chroot`),
  and per-VM file ACLs. **No `setrlimit` is applied** — per-uid/per-process
  rlimits break a confined launch (RLIMIT_NPROC EAGAINs virtiofsd's sandbox
  fork; RLIMIT_AS OOM-kills CH); per-sandbox resource bounding is deferred to a
  cgroup follow-up (F-28). See `ResourceLimits::for_vmm`.
  Launch **fails closed** if the floor (seccomp + Landlock + virtiofsd sandbox)
  cannot be met, unless `--allow-unconfined` is passed (loud CLI/status warning).
  Achieved confinement mode is recorded in `state.json` and surfaced by
  `izba status`. See `crates/izba-core/src/procmgr/jail_linux.rs` and
  `docs/superpowers/specs/2026-06-18-linux-vmm-confinement-design.md`.
- **virtiofs tag** `workspace` (driver `FsShare` ↔ init mount plan) →
  `/workspace` inside the guest, which is also exec's default cwd.
- **SSH access (`ssh izba-<name>`):** a vendored static OpenSSH `sshd`
  (sha-pinned `hack/build-sshd.sh`, OpenSSH 9.9p2) is launched by `izba-init`
  (`ssh.rs`) bound to `127.0.0.1:22`. The initramfs ships, all izba-controlled:
  `/sbin/sshd` + the 9.8-split re-exec worker `/usr/libexec/sshd-session`
  (both `IZBA_SSHD`-embedded), the static `/etc/ssh/sshd_config`, and a minimal
  `/etc/passwd`+`/etc/group` (sshd fatally needs the `sshd` privsep user + a
  `root` login user). The initramfs cpio is packed `--owner=0:0` and init
  force-roots `/run`,`/run/izba/ssh`,`/run/sshd` — sshd's StrictModes rejects a
  non-root path up to `/`, and the build runs unprivileged. Its host key + `authorized_keys` are
  delivered host→guest through the **optional `izba-ssh` virtiofs share**
  (`<sandbox>/ssh/` ↔ `/rootfs/izba-ssh`, mirroring the `izba-trust` channel),
  then copied by init to **init-root `/run/izba/ssh/` (0600), OUTSIDE the
  `/rootfs` overlay** — so izba's sshd material is fully isolated from the OCI
  image. The session runs `ChrootDirectory /rootfs` (exec-parity environment).
  The host reaches `:22` by **reusing `StreamOpen::TcpDial{port:22}`** through
  the daemon splice — **no new wire variant / no `DAEMON_PROTO_VERSION` bump**;
  the `izba __ssh-proxy <alias>` (hidden) is the `ProxyCommand` stdio bridge.
  izba owns a single `Include` line in `~/.ssh/config` pointing at a managed
  file (`<data>/ssh/config`: a `Host izba-*` wildcard block + cheap per-sandbox
  completion stubs), **atomically regenerated by the daemon on
  start/stop/rm** (best-effort, never fails the lifecycle); gated by
  `<data>/ssh/settings.json` `config_management` (default on). Keys are an
  izba-managed ed25519 user keypair + a shared host key under `<data>/ssh/`.
- **Exit-code mapping:** guest `CommandNotFound` → CLI exit 127;
  `Signal(n)` → 128+n. The guest serial console is ALWAYS captured to
  `logs/console.log` — boot failures print its tail.

## Conventions & state

- Conventional commits (`feat(core): ...`); TDD (tests first) was used
  throughout and reviews expect it.
- Known v1 trade-offs are doc-commented at the site: PAX xattrs dropped in
  `image/flatten.rs`, exec-entry retention + orphan-zombie policy in
  `izba-init`, no mount namespace for workloads (chroot only).
- Deferred scope (don't build casually — see spec §8/§9): credential
  injection/vault (M5, branches off the `daemon/egress/router.rs` dispatch
  point — the egress MITM proxy itself already shipped in M2), erofs layer
  dedup, snapshot/resume, CI-published kernel artifacts.

## Agent autonomy & delivery workflow (repo owner authorization)

The repo owner (lupus@oxnull.net) authorizes the agent to act on their behalf in
**this repository**, overriding the global "hand me the git/gh command to run"
preference for this repo only:

- **Push feature branches** to `origin` (`git push`, `--force-with-lease` after a
  rebase). Never push to `main` directly.
- **Open and update pull requests** (`gh pr create` / `gh pr edit`). PR bodies
  end with the Claude Code attribution trailer.
- **Trigger and watch CI** (`gh workflow run`, `gh run watch`, `gh pr checks`).

These need the Bash sandbox disabled and a `gh` token with `repo`+`workflow`
scope; the Windows-host build path (`powershell.exe`, `/mnt/c`, `~/.cache`) is
likewise unsandboxed.

**CI not starting ⇒ it's a MERGE CONFLICT, never an Actions quota.** izba is a
public OSS repo with **no GitHub Actions minutes/spending limits**. If a PR's
required checks won't start — `gh pr checks` shows only "Greptile Review" (a
GitHub App, not Actions), `mergeStateStatus` is `DIRTY`, and no new Actions runs
appear repo-wide after a push — GitHub is holding them under "Checks awaiting
conflict resolution" until the conflict is fixed. Do NOT diagnose this as a
billing/quota issue. Check `gh pr view <n> --json mergeStateStatus,mergeable`,
then rebase on `origin/main`, resolve, and `git push --force-with-lease` to clear
the hold.

**Standard delivery loop for a feature branch:**

1. Push the branch, open/refresh its PR, and start CI.
2. **While CI runs, dispatch the CI installer build** for manual testing:
   `bash hack/devbuild.sh` (run unsandboxed — it needs `gh`; see
   [the script](hack/devbuild.sh) and
   [its design](docs/superpowers/specs/2026-06-16-ci-dev-installer-artifacts-design.md)).
   It dispatches `.github/workflows/devbuild.yml` on the branch, watches the run,
   and downloads the finished `izba_*.deb` + `izba-app_*.deb` + `izba-setup-*.exe`
   — **the build runs entirely in CI, in parallel with the PR checks; nothing
   heavy builds on the laptop or the Windows host** (only ~150 MB of installers
   is downloaded). It needs the branch **pushed** first (CI builds the pushed
   tip), and `devbuild.yml` must already be on `main` (GitHub registers
   `workflow_dispatch` only from the default branch; branches cut from `main`
   inherit it). It prints the exact output dir
   `dist/local/<UTC-ts>-<sha>/`. **Record and report that exact path — never
   `dist/local/latest`**, which a parallel run can repoint out from under you.
   - **When run from a worktree it auto-copies that dir into the MAIN checkout's
     `dist/local/`** (a worktree's `dist/` is a separate working tree) and reports
     the main-checkout path as canonical — a plain copy that survives the worktree
     being removed.
3. When **all** CI checks are green, report to the owner: a concise summary of
   the work completed; the PR link to review; and pointers to the local
   artifacts for manual testing — the exact main-checkout `dist/local/<ts>-<sha>/`
   path **plus ready-to-paste install commands**:
   - Linux CLI/daemon: `sudo dpkg -i <dir>/izba_*.deb` (and the app:
     `sudo dpkg -i <dir>/izba-app_*.deb`).
   - Windows installer via WSL interop — the Inno installer runs the
     `\\wsl.localhost\…` UNC path fine, BUT the zsh→`powershell.exe` hop eats
     backslashes, so DOUBLE every backslash of the `wslpath -w` output (its
     leading `\\` becomes `\\\\`):
     `powershell.exe -NoProfile -Command "Start-Process -Wait '\\\\wsl.localhost\\<distro>\\<abs\\path>\\izba-setup-*.exe'"`.
     If it still rejects the UNC path, copy the `.exe` to a Windows-local dir
     (`cp <dir>/izba-setup-*.exe /mnt/c/Users/<user>/Downloads/`) and
     `Start-Process` that path instead.
