#!/usr/bin/env bash
# Ensure all runtime dependencies for izba are present.
#
# Usage:
#   hack/fetch-artifacts.sh [--check]
#
#   --check   Report-only mode: print what is present and what is missing,
#             then exit 0 (all present) or 1 (something missing).
#             Nothing is downloaded or installed.
#
# What this script manages:
#   1. cloud-hypervisor   (static binary, GitHub releases)
#   2. virtiofsd          (static binary, virtio-fs GitLab)
#   3. passt              (distro package — no static build available)
#   4. mkfs.erofs         (distro package — no static build available)
#   5. Boot artifacts     (kernel vmlinux + initramfs.cpio.gz)
#              → must be built locally; see hack/build-kernel.sh and
#                hack/build-initramfs.sh.  No pre-built downloads exist yet.
#
# Binaries 1-2 are installed to ${IZBA_BIN_DIR:-$HOME/.local/bin}.
# Skip each download if the binary is already on PATH.
#
# Data directory for boot artifacts:
#   ${IZBA_DATA_DIR:-$HOME/.local/share/izba}/artifacts/
set -euo pipefail

CHECK_ONLY=0
if [ "${1:-}" = "--check" ]; then
    CHECK_ONLY=1
fi

BIN_DIR="${IZBA_BIN_DIR:-$HOME/.local/bin}"
DATA_DIR="${IZBA_DATA_DIR:-$HOME/.local/share/izba}"
ARTIFACTS_DIR="$DATA_DIR/artifacts"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
OK=""       # names of things that are present
MISSING=""  # names of things that are missing

mark_ok()      { OK="$OK $1"; }
mark_missing() { MISSING="$MISSING $1"; }

need_install() {
    local name="$1"; shift
    mark_missing "$name"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        echo "  → $*"
    fi
}

need_build() {
    local name="$1"; shift
    mark_missing "$name"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        echo "  → $*"
    fi
}

# Download a URL to a destination path, making it executable.
download_bin() {
    local url="$1"
    local dest="$2"
    local name="$3"
    echo "Downloading $name..."
    mkdir -p "$(dirname "$dest")"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --progress-bar -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "$dest" "$url"
    else
        echo "  error: neither curl nor wget found; cannot download $name" >&2
        return 1
    fi
    chmod +x "$dest"
    echo "  installed to $dest"
}

# ---------------------------------------------------------------------------
# 1. cloud-hypervisor
# ---------------------------------------------------------------------------
echo "=== cloud-hypervisor ==="
CH_VERSION="42.0"
CH_RELEASE_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v${CH_VERSION}/cloud-hypervisor-static"

if command -v cloud-hypervisor >/dev/null 2>&1; then
    echo "  present: $(command -v cloud-hypervisor)"
    mark_ok "cloud-hypervisor"
elif [ -x "$BIN_DIR/cloud-hypervisor" ]; then
    echo "  present: $BIN_DIR/cloud-hypervisor (not on PATH — add $BIN_DIR to PATH)"
    mark_ok "cloud-hypervisor"
else
    echo "  missing"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        download_bin "$CH_RELEASE_URL" "$BIN_DIR/cloud-hypervisor" "cloud-hypervisor"
        mark_ok "cloud-hypervisor"
    else
        mark_missing "cloud-hypervisor"
    fi
fi

# ---------------------------------------------------------------------------
# 2. virtiofsd
# ---------------------------------------------------------------------------
echo "=== virtiofsd ==="
# Permalink to the latest static amd64 build from the upstream GitLab CI.
VIRTIOFSD_URL="https://gitlab.com/virtio-fs/virtiofsd/-/releases/permalink/latest/downloads/virtiofsd-x86_64"

if command -v virtiofsd >/dev/null 2>&1; then
    echo "  present: $(command -v virtiofsd)"
    mark_ok "virtiofsd"
elif [ -x "$BIN_DIR/virtiofsd" ]; then
    echo "  present: $BIN_DIR/virtiofsd (not on PATH — add $BIN_DIR to PATH)"
    mark_ok "virtiofsd"
else
    echo "  missing"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        download_bin "$VIRTIOFSD_URL" "$BIN_DIR/virtiofsd" "virtiofsd"
        mark_ok "virtiofsd"
    else
        mark_missing "virtiofsd"
    fi
fi

# ---------------------------------------------------------------------------
# 3. passt
# ---------------------------------------------------------------------------
echo "=== passt ==="
if command -v passt >/dev/null 2>&1; then
    echo "  present: $(command -v passt)"
    mark_ok "passt"
else
    echo "  missing"
    need_install "passt" "sudo apt-get install -y passt"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        echo "  Install with:  sudo apt-get install -y passt"
    fi
fi

# ---------------------------------------------------------------------------
# 4. mkfs.erofs
# ---------------------------------------------------------------------------
echo "=== mkfs.erofs ==="
if command -v mkfs.erofs >/dev/null 2>&1; then
    echo "  present: $(command -v mkfs.erofs)"
    mark_ok "mkfs.erofs"
else
    echo "  missing"
    need_install "mkfs.erofs" "sudo apt-get install -y erofs-utils"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        echo "  Install with:  sudo apt-get install -y erofs-utils"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Boot artifacts (kernel + initramfs)
# ---------------------------------------------------------------------------
echo "=== boot artifacts ==="
KERNEL="$ARTIFACTS_DIR/vmlinux"
INITRAMFS="$ARTIFACTS_DIR/initramfs.cpio.gz"

KERNEL_OK=0
INITRAMFS_OK=0

if [ -f "$KERNEL" ]; then
    echo "  kernel:     $KERNEL  (present)"
    KERNEL_OK=1
    mark_ok "vmlinux"
else
    echo "  kernel:     $KERNEL  (MISSING)"
    mark_missing "vmlinux"
fi

if [ -f "$INITRAMFS" ]; then
    echo "  initramfs:  $INITRAMFS  (present)"
    INITRAMFS_OK=1
    mark_ok "initramfs.cpio.gz"
else
    echo "  initramfs:  $INITRAMFS  (MISSING)"
    mark_missing "initramfs.cpio.gz"
fi

if [ "$KERNEL_OK" -eq 0 ] || [ "$INITRAMFS_OK" -eq 0 ]; then
    if [ "$CHECK_ONLY" -eq 0 ]; then
        echo ""
        echo "NOTE: No pre-built kernel or initramfs downloads exist yet."
        echo "      Build them locally, then copy into place:"
        echo ""
        if [ "$KERNEL_OK" -eq 0 ]; then
            echo "  # Build kernel (requires gcc toolchain — see above for deps):"
            echo "  hack/build-kernel.sh"
            echo "  mkdir -p '$ARTIFACTS_DIR'"
            echo "  cp dist/vmlinux '$KERNEL'"
        fi
        if [ "$INITRAMFS_OK" -eq 0 ]; then
            echo ""
            echo "  # Build initramfs:"
            echo "  hack/build-initramfs.sh"
            echo "  mkdir -p '$ARTIFACTS_DIR'"
            echo "  cp dist/initramfs.cpio.gz '$INITRAMFS'"
        fi
        echo ""
        echo "  Or use the env-var overrides to point at the files directly:"
        echo "    export IZBA_KERNEL=/path/to/vmlinux"
        echo "    export IZBA_INITRAMFS=/path/to/initramfs.cpio.gz"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== summary ==="
if [ -n "$OK" ]; then
    echo "  present: $OK"
fi
if [ -n "$MISSING" ]; then
    echo "  missing: $MISSING"
    exit 1
fi
echo "  all dependencies satisfied"
