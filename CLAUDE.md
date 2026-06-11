# CLAUDE.md

izba: open-source per-project microVM sandboxes for AI coding agents (a
independent reimplementation of Docker Desktop's `sbx`). Daemonless Rust CLI on top of
Cloud Hypervisor/KVM; Windows/WHP via OpenVMM is planned but not started.

## Documentation map

| Doc | What it holds |
| --- | --- |
| [README.md](README.md) | Product overview, quickstart, command surface |
| [docs/superpowers/specs/2026-06-10-izba-v1-design.md](docs/superpowers/specs/2026-06-10-izba-v1-design.md) | **The approved v1 design** — decisions + rationale, §8 spikes, §9 v2 horizon. Read before architectural changes. |
| [docs/superpowers/plans/2026-06-10-izba-v1.md](docs/superpowers/plans/2026-06-10-izba-v1.md) | The executed v1 implementation plan (historical; useful for "why is X built this way") |
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

**Test design constraint:** unit tests never bind unix/vsock listeners — some
sandboxes deny `bind` with EPERM. Use `UnixStream::pair()` fakes (see the
`PairListener` pattern in `crates/izba-init/src/server.rs` tests); tests that
genuinely need a listener must runtime-skip on `PermissionDenied` (see
`full_connect_via_listener` in `crates/izba-core/src/vsock.rs`).

## Crate map

- `izba-proto` — host↔guest wire protocol: u32-LE length-prefixed JSON frames
  + `Request`/`Response`/`StreamAttach` types. Shared verbatim by both sides.
- `izba-core` — the product library, zero CLI assumptions (a future `izbad`
  daemon wraps the same core). `sandbox.rs` is the lifecycle heart;
  `vmm/` driver trait + Cloud Hypervisor impl; `image/` OCI→erofs pipeline;
  `procmgr.rs` detached spawning; `vsock.rs` hybrid-vsock client.
- `izba-init` — guest PID 1 (static musl): mounts, exec engine (PTY + pipes),
  vsock servers. Everything except `main.rs` is host-testable.
- `izba-cli` — thin clap binary over izba-core.
- `izba-ttytest` — dev/test-support: drives the real `izba` binary through a
  PTY/ConPTY (portable-pty + vt100) against a scripted fake guest or a real
  sandbox; the automated `exec -it` checklist. Tests live in `crates/izba-cli/
  tests/{tty_scripted,tty_e2e}.rs` behind the `ttytests` feature.

## Load-bearing contracts (change all ends or none)

- **Daemonless invariant:** a sandbox = its dir under
  `~/.local/share/izba/sandboxes/<name>/` + live processes. Liveness is always
  re-verified via pid + `/proc/<pid>/stat` starttime identity (PID-reuse-safe;
  zombies count as dead) — never trusted from `state.json` alone.
- **vsock ports:** 1025 control RPC, 1026 streams (`CONTROL_PORT`/`STREAM_PORT`
  in izba-proto). Stream conns send ONE `StreamAttach` frame, then raw bytes.
  Host reaches them via Cloud Hypervisor hybrid-vsock: `CONNECT <port>\n` on
  `run/vsock.sock`, response read byte-by-byte (buffering eats stream data).
- **Disk order:** `sandbox::start()` builds `[rootfs.erofs (RO), rw.img (RW)]`
  → CH enumerates `--disk` order as vda, vdb → init mounts `/dev/vda` erofs
  lower + `/dev/vdb` ext4 upper into an overlay at `/rootfs`.
- **Cmdline chain:** `console=ttyS0 ip=dhcp izba.hostname=<name>` ↔
  `hack/kernel.config` (`SERIAL_8250_CONSOLE`, `IP_PNP_DHCP`) ↔ init reads
  `/proc/net/pnp` for resolv.conf and `izba.hostname` for sethostname.
- **virtiofs tag** `workspace` (driver `FsShare` ↔ init mount plan) →
  `/workspace` inside the guest, which is also exec's default cwd.
- **Exit-code mapping:** guest `CommandNotFound` → CLI exit 127;
  `Signal(n)` → 128+n. The guest serial console is ALWAYS captured to
  `logs/console.log` — boot failures print its tail.

## Conventions & state

- Conventional commits (`feat(core): ...`); TDD (tests first) was used
  throughout and reviews expect it.
- Known v1 trade-offs are doc-commented at the site: PAX xattrs dropped in
  `image/flatten.rs`, exec-entry retention + orphan-zombie policy in
  `izba-init`, no mount namespace for workloads (chroot only).
- Deferred scope (don't build casually — see spec §8/§9): OpenVMM/Windows
  driver (spike S1 first), egress MITM proxy + credential injection (v2 with
  `izbad`), erofs layer dedup, snapshot/resume, CI-published kernel artifacts.
