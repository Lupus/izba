# izba on Windows: platform layer + OpenVmmDriver — design

**Date:** 2026-06-10
**Status:** approved, in implementation
**Builds on:** [2026-06-10-openvmm-spike-s1-findings.md](2026-06-10-openvmm-spike-s1-findings.md)
(spike S1+ verdict GO, all rungs 0–7 PASS) and
[2026-06-10-mkfs-erofs-windows-design.md](2026-06-10-mkfs-erofs-windows-design.md)
(native `mkfs.erofs.exe`, merged).

## 1. Problem

izba v1 runs only on Linux (Cloud Hypervisor/KVM). The spike proved every
piece of the Windows/WHP story works under OpenVMM — boot, virtio-fs, vsock,
consomme networking, headless serial, the full izba guest stack — and the
erofs tooling now exists as a native Windows binary. What's missing is the
host side: `izba.exe` itself. The host-side crates are Unix-coupled in six
places (verified by `cargo check --target x86_64-pc-windows-gnu`, 11 errors):

| Coupling | Where | Windows answer |
| --- | --- | --- |
| `nix` Flock + errno | `sandbox.rs` lock | cross-platform `fd-lock` crate |
| `setsid`/`pre_exec`, signal kill, `/proc` starttime | `procmgr.rs` | `CREATE_NO_WINDOW` flags, `TerminateProcess`, `GetProcessTimes` |
| `std::os::unix::net::UnixStream` | `vsock.rs`, `vmm/mod.rs`, CLI `exec.rs` | `uds_windows` crate (Windows 10 1803+ AF_UNIX) |
| `$HOME/.local/share/izba` | `paths.rs` | `%LOCALAPPDATA%\izba` |
| termios raw mode, `TIOCGWINSZ`, `isatty`, SIGWINCH | CLI `terminal.rs`, `exec.rs` | console modes, `GetConsoleScreenBufferInfo`, `IsTerminal`, size-poll thread |
| driver hardcoded to Cloud Hypervisor | CLI `run.rs` | per-OS default driver |

The image pipeline is already portable: `oci-client` is rustls-based, flatten
is tar-to-tar, `mkfs.erofs` discovery is Windows-aware (merged), and the guest
formats `rw.img` itself (`rwdisk::ensure_formatted`), so the host's optional
`mkfs.ext4` being absent on Windows is a no-op. `izba-init` is untouched — the
guest side stays Linux/musl.

## 2. Decisions

- **Success bar: full CLI parity.** Every izba command works on the Windows
  spike host — `run` (OCI pull → erofs → boot), `exec` including interactive
  `-it`, `list`/`status`, `logs`, `stop`, `rm` — and the daemonless liveness
  invariant holds across CLI invocations.
- **Architecture: cfg-gated platform splits in place** (Approach A). The crate
  map and every public API stay as they are; Unix-coupled modules grow Windows
  bodies behind `#[cfg]`. No `Platform` trait injection (izba already mocks at
  the `VmmDriver`/`Probes` seams; `PidIdentity` is persisted data, not
  behavior), no new platform crate (izba-core is the only consumer).
- **Toolchain: MinGW cross from WSL** — `cargo build --target
  x86_64-pc-windows-gnu` (rust target installed; the mingw-w64 gcc from the
  erofs work is the linker). Unit tests stay on Linux; design every platform
  decision as a pure, host-testable core function with a thin cfg wrapper
  (the `find_mkfs_erofs_from` pattern). Windows code is compile-gated by
  `cargo check`/`clippy --target x86_64-pc-windows-gnu` and
  integration-validated on the spike host.
- **OpenVMM binary: discovery shim + fetch helper.** The driver finds
  `openvmm.exe` via `$IZBA_OPENVMM` → exe-adjacent `libexec\` → `PATH` (same
  probe order as `mkfs.erofs`). A `hack/` helper fetches the pinned CI
  artifact via `gh` (upstream ships no releases; GitHub artifacts expire, so
  the pin is a run id + documented re-pin procedure). Bundling/installer is
  out of scope.
- **Two ordered plans.** Plan 1: everything buildable and testable from Linux
  (platform layer, driver, CLI, gates, cross-built `izba.exe`). Plan 2:
  bring-up on the Windows spike host (artifact staging, the inherited
  deferred erofs gate, full-CLI-parity validation).

## 3. Design

### 3.1 Sandbox lock: `fd-lock` (both platforms)

Replace `nix::fcntl::Flock` in `sandbox.rs` with the `fd-lock` crate
(`flock` on Unix, `LockFileEx` on Windows). One code path on both platforms —
this *deletes* platform-specific code. `try_write()` failure with
`WouldBlock` maps to today's "another start is in flight" handling. The
existing `flock_serializes_start` test keeps the behavior honest.

### 3.2 procmgr: platform split, same API

`procmgr.rs` becomes `procmgr/mod.rs` (shared API + docs) with `unix.rs`
(today's code, moved) and `windows.rs`. Signatures are unchanged:
`spawn_detached(&CommandSpec, log) -> Result<PidIdentity>`,
`kill_pid(&PidIdentity)`, `pid_alive(&PidIdentity) -> bool`.

**`PidIdentity { pid, starttime }` keeps its shape.** On Windows `starttime`
is the process creation `FILETIME` (100 ns units since 1601) from
`GetProcessTimes`, converted to `u64`. Same PID-reuse-defeating semantics as
`/proc/<pid>/stat` field 22; the value is only ever compared for equality,
and `state.json` is per-host so the differing unit is invisible.

- `spawn_detached` (windows): `std::process::Command` +
  `creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)`, stdout and
  stderr redirected to the log file (append), stdin null. No `setsid`
  analog is needed — Windows children survive parent exit by default (spike
  rung 6 confirmed openvmm outlives its launcher). Deliberately **no job
  object**: the daemonless design requires the VMM to outlive the CLI.
  After spawn, read back the creation time via
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessTimes` to
  build the identity.
- `pid_alive` (windows): `OpenProcess` fails → dead; creation time ≠ stored
  starttime → dead (PID reuse); `GetExitCodeProcess` ≠ `STILL_ACTIVE` →
  dead (exited but a handle keeps the object alive — the zombie analog).
- `kill_pid` (windows): `OpenProcess(PROCESS_TERMINATE)` +
  `TerminateProcess`. "No such process" maps to `Ok(())` exactly like the
  Unix `ESRCH` arm.

Windows API access via **`windows-sys`** (declaration-only bindings, fast to
compile), as a `[target.'cfg(windows)'.dependencies]` entry. `nix` moves to
`[target.'cfg(unix)'.dependencies]`.

### 3.3 UDS client: one alias, two backings

`izba-core` exports a platform alias:

```rust
#[cfg(unix)]
pub type UdsStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type UdsStream = uds_windows::UnixStream;
```

`uds_windows` mirrors std's API (`connect`, `try_clone`, `shutdown`,
`set_read_timeout`/`set_write_timeout` — verify timeout support during
implementation; fallback is a small `WSAPoll` wrapper). The `IoStream` impl
in `vmm/mod.rs` and the concrete-stream connector in `sandbox.rs` move to
the alias; CLI `exec.rs` imports it instead of `std::os::unix::net`. The
hybrid-vsock CONNECT/OK protocol in `vsock.rs` is byte-identical on both
platforms (spike rung 4: OpenVMM answers `OK <vmbus-channel-id>`, which
`hybrid_handshake` already accepts).

### 3.4 paths: `%LOCALAPPDATA%\izba`

`Paths::from_env_or_default` gains a Windows default root:
`%LOCALAPPDATA%\izba`, falling back to `%USERPROFILE%\AppData\Local\izba` if
`LOCALAPPDATA` is unset. The
layout below the root is unchanged. The default-root logic becomes a pure
function over an env-lookup closure so both platforms' rules are unit-tested
on Linux.

### 3.5 CLI terminal: console modes behind the same interface

`terminal.rs` keeps its public surface (`RawGuard`, `winsize() -> (u16, u16)`,
tty detection) and splits internally:

- tty detection: replace `libc::isatty` with std's `IsTerminal` trait —
  cross-platform, deletes code.
- `RawGuard` (windows): save/restore console modes; stdin gets
  `ENABLE_VIRTUAL_TERMINAL_INPUT` and drops
  `ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT`; stdout
  gets `ENABLE_VIRTUAL_TERMINAL_PROCESSING`. Restore on drop, as today.
- `winsize` (windows): `GetConsoleScreenBufferInfo` window rect, same 80×24
  fallback.
- Resize events: `exec.rs`'s SIGWINCH thread is Unix-only; the Windows
  variant polls `winsize()` (200 ms) and sends `Resize` on change. Same
  `resize(&control, exec_id)` plumbing, cfg-gated spawn.

### 3.6 OpenVmmDriver

New `vmm/openvmm.rs` beside `cloud_hypervisor.rs`, same shape: a pure
`build_invocation(&VmSpec, openvmm_exe) -> CommandSpec` unit-tested on Linux,
plus an `OpenVmmDriver`/`OpenVmmHandle` pair. **No sidecars at all** — virtiofs
serving and consomme are in-process in openvmm.exe (spike finding (c)), so
`pids()` is just `[("vmm", id)]` and there is no socket-wait choreography.
The module compiles on both targets (everything it uses — procmgr, vsock,
discovery — is platform-split underneath); only its real launch is
Windows-functional. `VmSpec` needs no changes.

Flag mapping (every line is rung-7-validated unless marked):

| VmSpec field | openvmm argv |
| --- | --- |
| `kernel` | `--kernel <path>` |
| `initramfs` | `--initrd <path>` |
| `cmdline` | `-c <cmdline>` (single argv element; `CreateProcess` quoting via std, no PowerShell hazards) |
| `cpus` | `--processors <n>` (**verify flag name at bring-up**) |
| `mem_mb` | `--memory <n>MB` (**verify flag syntax at bring-up**) |
| always | `--hv` (mandatory: VPCI vsock + netvsp need it) |
| `console_log` | `--com1 file=<path>` |
| topology | `--pcie-root-complex rc0`, one `--pcie-root-port rc0:<name>` per disk and per share |
| `disks[i]` | `--virtio-blk file:<path>[,ro],pcie_port=vd<x>` — PCIe-routed to dodge the VPCI device-ID collision (spike finding (f)); port names `vda`, `vdb`, … in disk order, preserving the vda/vdb guest contract |
| `shares[tag]` | `--virtio-fs pcie_port=fs-<tag>:<tag>,<host_path>` |
| `net` | `--net consomme` when true (netvsp NIC; finding (b)) |
| `run_dir` | `--virtio-vsock-path <run_dir>\vsock.sock` |

Launch: create `run_dir`/log dir, remove a stale `vsock.sock` (Windows
AF_UNIX socket files persist across crashes, same hazard the CH driver
handles), spawn detached, return the handle. Boot health-polling stays where
it lives today (`sandbox::start`); console.log tail-on-failure already works
because `--com1 file=` flushes promptly (rung 6).

**Discovery:** `find_openvmm()` with probe order `$IZBA_OPENVMM` →
`<exe dir>/libexec/openvmm.exe` → `PATH`. The probe logic is shared with
`mkfs.erofs` by extracting the existing pattern from `image/erofs.rs` into a
small `discover` module (env override → libexec → PATH, not-found error
lists all probed locations) — one implementation, two thin callers.

### 3.7 Driver selection

`run.rs` picks the default driver by target OS: Cloud Hypervisor on Unix,
OpenVMM on Windows. `cloud_hypervisor.rs` stays compiled on both targets
(after the splits it is portable source; keeping it un-cfg'd means fewer
gates and unchanged tests) — it is simply never selected on Windows.

### 3.8 rw.img on NTFS: mark sparse

`File::set_len` on NTFS allocates real clusters (no sparse-by-default like
ext4), so each sandbox would physically reserve the full `rw_size_gb`. The
rw.img creation in `sandbox.rs` gains a cfg(windows) step: mark the file
sparse via `DeviceIoControl(FSCTL_SET_SPARSE)` before `set_len`. No-op on
Unix; correctness is unaffected either way (it's a disk-space fix).

## 4. Build & gates

New always-on gates (CI-compatible, appended to the CLAUDE.md gate list):

```sh
cargo check  --target x86_64-pc-windows-gnu -p izba-core -p izba-cli -p izba-proto
cargo clippy --target x86_64-pc-windows-gnu -p izba-core -p izba-cli -- -D warnings
```

(`izba-init` is excluded — it is guest-side Linux/musl by design.)

Release artifact: `cargo build --release --target x86_64-pc-windows-gnu -p
izba-cli` → `izba.exe` (rustc's default linker for the target is the
installed `x86_64-w64-mingw32-gcc`). Running Windows-target unit tests under
wine is possible (`CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine`) but is
**best-effort only**, not a gate — wine's AF_UNIX and console-API fidelity is
unproven and a wine failure must not block.

## 5. Plan split

**Plan 1 — Linux-side (no Windows host needed):** fd-lock swap; paths;
procmgr split; UDS alias; `discover` extraction; OpenVmmDriver + tests;
CLI terminal/exec/run cfg work; gates wired and green; cross-built
`izba.exe`. Every task lands with the four existing Linux gates plus the two
new cross-target gates green.

**Plan 2 — Windows bring-up (spike host, user present):** fetch-openvmm
helper + pinned artifact; stage kernel/initramfs/mkfs.erofs.exe/openvmm.exe
into the `libexec` layout next to `izba.exe`; **verify `--processors`/
`--memory` flag names against `openvmm.exe --help` and fix the builder if
needed**; run the inherited deferred erofs gate
(`hack/spike/verify-mkfs-erofs-parity.ps1` on real Windows, then a boot with
a Windows-built rootfs.erofs); a CI-compatible PowerShell validation script
exercising the full CLI surface (run/exec/exec -it/list/status/logs/stop/rm +
liveness across invocations); record results in a findings addendum and
promote artifacts.

## 6. Out of scope

- Installer/packaging, code signing, bundling openvmm.exe (needs a
  distribution story first; the libexec convention is installer-ready).
- Windows CI (repo has no CI; everything ships as CI-compatible scripts).
- egress MITM proxy, credential injection (v2, with `izbad`).
- Snapshot/resume, erofs layer dedup (deferred per v1 spec).
- Any guest-side change — `izba-init`, kernel config, and initramfs are
  already OpenVMM-validated (rungs 2–7 + post-delta KVM 11/11).

## 7. Risks

| Risk | Mitigation |
| --- | --- |
| `--processors`/`--memory` flag names unverified (spike used defaults) | explicit Plan 2 verify step before first boot; argv builder + tests adjust in one place |
| `uds_windows` timeout support gaps | verified during Plan 1 implementation; fallback is a small WSAPoll wrapper behind `IoStream` |
| OpenVMM CI artifact expiry breaks the pin | fetch helper documents the re-pin procedure; building from a pinned source tag is the recorded fallback |
| Windows console raw mode quirks (VT input on older terminals) | spike host is Win11 24H2 (VT-capable); `ENABLE_VIRTUAL_TERMINAL_*` failure surfaces as a clear error, non-tty exec paths unaffected |
| `GetProcessTimes` on other users' processes denied | not applicable — izba only inspects processes it spawned as the same user |
| wine fidelity for Windows-target tests | wine runs are best-effort, never a gate; real validation is Plan 2 on the spike host |
