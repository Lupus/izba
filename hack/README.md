# izba hack/ scripts

This directory contains the tooling needed to build and fetch the runtime
dependencies of izba.  None of these scripts are required to build the Rust
code; they are for bootstrapping the host environment.

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

Output defaults to `dist/initramfs.cpio.gz`.

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

### `fetch-artifacts.sh`

Idempotent dependency checker / downloader.  Manages:

| Artifact | Source |
|---|---|
| `cloud-hypervisor` | GitHub releases (static binary) |
| `virtiofsd` | virtio-fs GitLab (static binary) |
| `passt` | `sudo apt-get install -y passt` |
| `mkfs.erofs` | `sudo apt-get install -y erofs-utils` |
| `vmlinux` + `initramfs.cpio.gz` | built locally (see above) |

Binaries are installed to `${IZBA_BIN_DIR:-$HOME/.local/bin}`.
Boot artifacts are expected at
`${IZBA_DATA_DIR:-$HOME/.local/share/izba}/artifacts/`.

Use `--check` for report-only mode (prints what is present/missing, exits 1
if anything is missing, installs nothing).

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
    passt erofs-utils cpio musl-tools
```

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
