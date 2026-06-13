# izba hack/ scripts

This directory contains the tooling needed to build and fetch the runtime
dependencies of izba.  None of these scripts are required to build the Rust
code; they are for bootstrapping the host environment.

Once the artifacts are in place, [../docs/testing.md](../docs/testing.md) is
the runbook for actually booting sandboxes and running the integration suite.

---

## Scripts

### `kernel.config`

A kernel configuration **fragment** (not a complete `.config`).  It is merged
on top of `x86_64_defconfig` by `build-kernel.sh` using the kernel's own
`merge_config.sh` helper, then `make olddefconfig` fills in any new symbols.
All selected options are built-in (`=y`); no modules are produced.

### `build-initramfs.sh`

Builds the izba initramfs:

1. Compiles `izba-init` as a static musl binary
   (`x86_64-unknown-linux-musl` target, release profile).
2. Assembles a minimal root tree (`init`, `sbin/`, `proc/`, `sys/`, `dev/`,
   `tmp/`, `lower/`, `upper/`, `rootfs/`).
3. Packs it into a gzip-compressed newc cpio archive.

**Optional:** set `IZBA_MKE2FS=/path/to/static/mke2fs` to embed a static
`mke2fs` binary in `/sbin/mke2fs`.  This enables the guest to format the
blank `rw.img` on first boot when no host-side `mkfs.ext4` is available.

**Optional:** set `IZBA_NFT=/path/to/static/nft` to embed a static `nft`
binary in `/sbin/nft`.  This is required for the M1 izbad-egress TCP REDIRECT
stub (see `build-nft.sh`).

Output defaults to `dist/initramfs.cpio.gz`.

### `build-nft.sh`

Builds a static `nft` (nftables CLI) for the initramfs, via a throwaway
Alpine container (musl).  It compiles `libmnl 1.0.5`, `libnftnl 1.2.9`, and
`nftables 1.1.3` from the netfilter.org source tarballs, configures nftables
with mini-gmp (no external GMP), no interactive CLI, and no JSON, links it
fully static (`-all-static`), strips it, and writes it to `dist/nft`.

```sh
hack/build-nft.sh            # writes dist/nft (~1.1 MB, statically linked)
./dist/nft --version         # smoke-test: static linux binary, runs on WSL
```

Embed it via `IZBA_NFT=dist/nft hack/build-initramfs.sh`.  Requires Docker.

### `build-kernel.sh`

Downloads a Linux kernel source tarball (default: **6.12.30 LTS**), applies
the `kernel.config` fragment, and builds `vmlinux`.

Requires a C toolchain:
```
sudo apt-get install -y build-essential flex bison bc libelf-dev
```

The tarball is cached in `${XDG_CACHE_HOME:-$HOME/.cache}/izba/kernel/` so
subsequent runs skip the download.

Output defaults to `dist/vmlinux`.

**Tarball integrity:** known versions have a pinned sha256 (currently `6.12.30`).
Building an unlisted version requires `IZBA_KERNEL_SHA256=<hash>` — there is no
unverified path.  Set `IZBA_KERNEL_VERIFY_ONLY=1` to hash-check the cached
tarball and exit without building (useful for CI preflight).

### `build-mke2fs.sh`

Builds a statically-linked `mke2fs` from pinned e2fsprogs sources
(**1.47.2**, sha256-verified tarball) using `musl-gcc` (`musl-tools` package).
Only the `mke2fs` binary is produced; no other e2fsprogs utilities are built.

Output defaults to `dist/mke2fs-1.47.2-static-x86_64`.

Pass the result to `build-initramfs.sh` via `IZBA_MKE2FS` so the guest can
format a blank `rw.img` on first boot.  The source tarball is cached in
`${XDG_CACHE_HOME:-$HOME/.cache}/izba/e2fsprogs/`.

### `ci/ttystorm-gate.sh` / `ci/ttystorm-gate.ps1`

The scripted M0 vsock-churn gate used by `.github/workflows/e2e.yml`: boots a
throwaway sandbox, runs `ttystorm floodfast 20 2048` + `chop 30 256` through
izbad, and asserts the VM is still alive afterwards. Env: `IZBA_EXE`,
`TTYSTORM_EXE` (paths to the binaries), `IZBA_IMAGE` (default `alpine:3.20`).

### `fetch-artifacts.sh`

Idempotent dependency checker / downloader.  Manages:

| Artifact | Source |
|---|---|
| `cloud-hypervisor` | GitHub releases (static binary) |
| `virtiofsd` | virtio-fs GitLab (static binary) |
| `mkfs.erofs` | `sudo apt-get install -y erofs-utils` |
| `vmlinux` + `initramfs.cpio.gz` | built locally (see above) |

Binaries are installed to `${IZBA_BIN_DIR:-$HOME/.local/bin}`.
Boot artifacts are expected at
`${IZBA_DATA_DIR:-$HOME/.local/share/izba}/artifacts/`.

Use `--check` for report-only mode (prints what is present/missing, exits 1
if anything is missing, installs nothing).

Downloads are sha256-pinned: cloud-hypervisor and virtiofsd are verified
after download and deleted on mismatch.

---

## Full bring-up on a fresh Ubuntu WSL2

### 0. Enable nested virtualisation

In `%USERPROFILE%\.wslconfig` on the Windows host:

```ini
[wsl2]
nestedVirtualization=true
```

Restart WSL (`wsl --shutdown` from PowerShell, then reopen the terminal).
Confirm KVM is accessible:

```bash
ls -l /dev/kvm          # must exist
sudo chmod 666 /dev/kvm # if your user cannot access it
```

### 1. Install distro packages

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential flex bison bc libelf-dev \
    erofs-utils cpio musl-tools
```

The static `nft` for the egress stub is built in a container (`build-nft.sh`),
so Docker is the only extra requirement for that step.

`musl-tools` provides `x86_64-linux-musl-gcc`, needed by the musl Rust target.

### 2. Install the Rust toolchain (if not already present)

The repo ships a `rust-toolchain.toml` pinning the exact version; `rustup`
picks it up automatically.  Also add the musl target:

```bash
rustup target add x86_64-unknown-linux-musl
```

### 3. Fetch binary dependencies and verify

```bash
hack/fetch-artifacts.sh --check   # see what is missing
hack/fetch-artifacts.sh           # download cloud-hypervisor + virtiofsd
```

Add the bin dir to your PATH if it is not already there:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 4. Build izba-init + initramfs

```bash
hack/build-initramfs.sh
# output: dist/initramfs.cpio.gz
```

### 5. Build the kernel  *(skip if you already have a compatible vmlinux)*

```bash
hack/build-kernel.sh
# output: dist/vmlinux   (~20 min first run, cached after that)
```

### 6. Install boot artifacts

```bash
mkdir -p "$HOME/.local/share/izba/artifacts"
cp dist/vmlinux          "$HOME/.local/share/izba/artifacts/vmlinux"
cp dist/initramfs.cpio.gz "$HOME/.local/share/izba/artifacts/initramfs.cpio.gz"
```

Or point izba at them directly (useful during development):

```bash
export IZBA_KERNEL="$(pwd)/dist/vmlinux"
export IZBA_INITRAMFS="$(pwd)/dist/initramfs.cpio.gz"
```

### 7. Build izba and run

```bash
source .cargo-env
cargo build --release -p izba-cli
./target/release/izba --help
```

---

## Environment-variable overrides

| Variable | Description |
|---|---|
| `IZBA_KERNEL` | Absolute path to a `vmlinux` to use instead of the default artifacts location. Must be set together with `IZBA_INITRAMFS`. |
| `IZBA_INITRAMFS` | Absolute path to an `initramfs.cpio.gz`. Must be set together with `IZBA_KERNEL`. |
| `IZBA_BIN_DIR` | Directory where `fetch-artifacts.sh` installs host binaries. Defaults to `$HOME/.local/bin`. |
| `IZBA_DATA_DIR` | Root data directory. Defaults to `$HOME/.local/share/izba`. |
| `IZBA_MKE2FS` | Optional path to a static `mke2fs` binary to embed in the initramfs at `/sbin/mke2fs` (enables in-guest first-boot rw formatting). |
| `IZBA_KERNEL_SHA256` | sha256 of the kernel source tarball when building an unlisted version; required when the version has no entry in `build-kernel.sh`'s `KNOWN_SHA256` table. |
| `IZBA_KERNEL_VERIFY_ONLY` | Set to `1` to hash-check the cached kernel tarball and exit without building (CI preflight mode). |
| `IZBA_NFT` | Optional path to a static `nft` binary to embed in the initramfs at `/sbin/nft` (required for the M1 izbad-egress TCP REDIRECT stub; built by `build-nft.sh`). |
| `VIRTIOFSD_VERSION` | virtiofsd release tag for `fetch-artifacts.sh`. Defaults to a pinned known-good version. |
| `IZBA_MKFS_EROFS` | Absolute path to `mkfs.erofs` (or `mkfs.erofs.exe` on Windows). Overrides the bundled libexec copy and `$PATH`. |

---

## mkfs.erofs for Windows

```sh
hack/build-mkfs-erofs-windows.sh
# produces dist/mkfs.erofs.exe (Windows PE) + Linux reference binary under ~/.cache/izba/erofs-utils/
```

`build-mkfs-erofs-windows.sh` cross-compiles pinned erofs-utils into a
native, tar-mode-only `dist/mkfs.erofs.exe` (imports: kernel32+msvcrt — no
Cygwin, no WSL2) plus a same-source Linux reference binary. Compat shims
live in `mingw-compat/`; forced in-tree edits in `patches/erofs-utils/`.
POSIX dir-walk APIs are stubbed to abort with exit 70 — the binary is only
valid for `mkfs.erofs --tar=f ...` invocations (which is all izba uses).

`verify-mkfs-erofs-parity.sh` proves the .exe byte-identical to the Linux
reference (under wine when present; otherwise it emits
`dist/erofs-parity-bundle/` for `spike/verify-mkfs-erofs-parity.ps1` on a
real Windows host — exit 2 means "run the Windows leg").

izba-core finds the binary via `$IZBA_MKFS_EROFS` → `<exe dir>/libexec/`
(the directory containing the izba binary) → `$PATH` (see
`crates/izba-core/src/image/erofs.rs`).

Design: [../docs/superpowers/specs/2026-06-10-mkfs-erofs-windows-design.md](../docs/superpowers/specs/2026-06-10-mkfs-erofs-windows-design.md).

## izba.exe (Windows host CLI)

Cross-built from WSL with the same MinGW toolchain as `mkfs.erofs.exe`:

```sh
rustup target add x86_64-pc-windows-gnu   # once
cargo build --release --target x86_64-pc-windows-gnu -p izba-cli
# → target/x86_64-pc-windows-gnu/release/izba.exe
```

The Windows binary discovers its tools via `$IZBA_MKFS_EROFS` /
`$IZBA_OPENVMM`, an exe-adjacent `libexec\` directory, then `PATH` — see
[the Windows-port design](../docs/superpowers/specs/2026-06-10-izba-windows-port-design.md).
