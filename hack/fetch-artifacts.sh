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
#   3. passt              (distro package; must support --vhost-user. If the
#                          distro build is too old, install the upstream static
#                          build — see the passt section below.)
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

# Verify a file against an expected sha256; delete it and fail on mismatch.
verify_sha256() {
    local path="$1" want="$2" name="$3"
    local got
    got=$(sha256sum "$path" | cut -d' ' -f1)
    if [ "$got" != "$want" ]; then
        rm -f "$path"
        echo "  error: $name sha256 mismatch" >&2
        echo "    got:  $got" >&2
        echo "    want: $want" >&2
        return 1
    fi
    echo "  sha256 verified: $got"
}

# ---------------------------------------------------------------------------
# 1. cloud-hypervisor
# ---------------------------------------------------------------------------
echo "=== cloud-hypervisor ==="
CH_VERSION="42.0"
CH_RELEASE_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v${CH_VERSION}/cloud-hypervisor-static"
CH_SHA256="537d1cbc1d4d3646099618f3b6f2b711116ad1ed8c8bc909a1a689417c7430aa"

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
        verify_sha256 "$BIN_DIR/cloud-hypervisor" "$CH_SHA256" "cloud-hypervisor"
        mark_ok "cloud-hypervisor"
    else
        mark_missing "cloud-hypervisor"
    fi
fi

# ---------------------------------------------------------------------------
# 2. virtiofsd
# ---------------------------------------------------------------------------
# As of ~v1.13.x the project no longer publishes a direct `virtiofsd-x86_64`
# release permalink (that path now 404s). Each release instead attaches a
# `virtiofsd-vX.Y.Z.zip` as a GitLab *project upload*, linked from the release
# description, e.g. `[virtiofsd-v1.13.3.zip](/uploads/<hash>/virtiofsd-...zip)`.
# The zip contains the static musl binary at
# `target/x86_64-unknown-linux-musl/release/virtiofsd`. We resolve the upload
# link via the API so this keeps working across version bumps.
# Releases: https://gitlab.com/virtio-fs/virtiofsd/-/releases
VIRTIOFSD_VERSION="${VIRTIOFSD_VERSION:-v1.13.3}"  # override with VIRTIOFSD_VERSION env var
# sha256 of the v1.13.3 release zip and of the static binary inside it.
# Bumping VIRTIOFSD_VERSION via env skips pin checks ONLY if you also
# override these (empty disables — intended for local experiments, never CI).
VIRTIOFSD_ZIP_SHA256="${VIRTIOFSD_ZIP_SHA256-c79055af8189dcd3d942a16e5c165aa336aabbc47ea8e015c3a6cf9980ff73ab}"
VIRTIOFSD_BIN_SHA256="${VIRTIOFSD_BIN_SHA256-b3f7d24d7a530515b1a44b035f426c700553cb4f0cd14189051d54c0e6b6ef78}"
VIRTIOFSD_API="https://gitlab.com/api/v4/projects/virtio-fs%2Fvirtiofsd"

# Resolve + download + extract the virtiofsd release zip into $1 (dest binary).
download_virtiofsd() {
    local dest="$1"
    echo "Resolving virtiofsd ${VIRTIOFSD_VERSION} release asset..."
    local rel upload_path pid url tmpd bin
    rel=$(curl -fLs "$VIRTIOFSD_API/releases/${VIRTIOFSD_VERSION}") || {
        echo "  error: cannot fetch release ${VIRTIOFSD_VERSION}" >&2; return 1; }
    upload_path=$(printf '%s' "$rel" | grep -oE '/uploads/[a-f0-9]+/[^")]+\.zip' | head -1)
    if [ -z "$upload_path" ]; then
        echo "  error: no upload .zip link in release ${VIRTIOFSD_VERSION} description" >&2; return 1
    fi
    pid=$(curl -fLs "$VIRTIOFSD_API" | grep -oE '"id":[0-9]+' | head -1 | grep -oE '[0-9]+')
    if [ -z "$pid" ]; then echo "  error: cannot resolve project id" >&2; return 1; fi
    # Project uploads are served under the /-/project/<id>/ scope.
    url="https://gitlab.com/-/project/${pid}${upload_path}"
    tmpd=$(mktemp -d)
    echo "Downloading virtiofsd from ${url}..."
    if ! curl -fL --progress-bar -o "$tmpd/virtiofsd.zip" "$url"; then
        rm -rf "$tmpd"; echo "  error: download failed" >&2; return 1
    fi
    if [ -n "$VIRTIOFSD_ZIP_SHA256" ]; then
        verify_sha256 "$tmpd/virtiofsd.zip" "$VIRTIOFSD_ZIP_SHA256" "virtiofsd.zip" \
            || { rm -rf "$tmpd"; return 1; }
    fi
    if ! ( cd "$tmpd" && unzip -oq virtiofsd.zip ); then
        rm -rf "$tmpd"; echo "  error: unzip failed (is 'unzip' installed?)" >&2; return 1
    fi
    bin=$(find "$tmpd" -type f -name virtiofsd -path '*release*' | head -1)
    [ -z "$bin" ] && bin=$(find "$tmpd" -type f -name 'virtiofsd' ! -name '*.zip' | head -1)
    if [ -z "$bin" ]; then
        rm -rf "$tmpd"; echo "  error: virtiofsd binary not found inside zip" >&2; return 1
    fi
    if [ -n "$VIRTIOFSD_BIN_SHA256" ]; then
        verify_sha256 "$bin" "$VIRTIOFSD_BIN_SHA256" "virtiofsd" \
            || { rm -rf "$tmpd"; return 1; }
    fi
    mkdir -p "$(dirname "$dest")"
    install -m755 "$bin" "$dest"
    rm -rf "$tmpd"
    echo "  installed to $dest"
}

echo "=== virtiofsd ==="
if command -v virtiofsd >/dev/null 2>&1; then
    echo "  present: $(command -v virtiofsd)"
    mark_ok "virtiofsd"
elif [ -x "$BIN_DIR/virtiofsd" ]; then
    echo "  present: $BIN_DIR/virtiofsd (not on PATH — add $BIN_DIR to PATH)"
    mark_ok "virtiofsd"
else
    echo "  missing"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        download_virtiofsd "$BIN_DIR/virtiofsd"
        mark_ok "virtiofsd"
    else
        mark_missing "virtiofsd"
    fi
fi

# ---------------------------------------------------------------------------
# 3. passt
# ---------------------------------------------------------------------------
echo "=== passt ==="
# izba runs passt in vhost-user mode: cloud-hypervisor consumes the network
# device over a vhost-user socket (see vmm/cloud_hypervisor.rs — passt is
# invoked with `--vhost-user --socket-path .../net.sock`). That mode was added
# upstream around 2024_03_20; older builds — including the one Ubuntu 24.04
# ships (0.0~git20240220) — reject --vhost-user, exit immediately, and never
# create net.sock, so every boot fails with "passt did not create ... net.sock
# within 3s". Presence alone is therefore NOT enough — we probe the capability.
passt_ok=0
if command -v passt >/dev/null 2>&1; then
    if passt --help 2>&1 | grep -q vhost-user; then
        echo "  present: $(command -v passt) (supports --vhost-user)"
        mark_ok "passt"
        passt_ok=1
    else
        echo "  present but TOO OLD: $(command -v passt) lacks --vhost-user"
    fi
else
    echo "  missing"
fi
if [ "$passt_ok" -eq 0 ]; then
    mark_missing "passt"
    if [ "$CHECK_ONLY" -eq 0 ]; then
        # Distro apt has no newer passt on Ubuntu 24.04, but upstream publishes
        # an official static build. Install it to /usr/local/bin so it shadows
        # any older /usr/bin/passt (izba resolves `passt` via PATH, and
        # /usr/local/bin precedes /usr/bin). ~/.local/bin would NOT shadow a
        # system passt, so this one genuinely needs the system location.
        echo "  → Build the pinned passt and install it (needs sudo):"
        echo "      hack/build-passt.sh"
        echo "      sudo install -m755 dist/passt-2026_05_26-static-x86_64 /usr/local/bin/passt"
        echo "      hash -r && passt --help | grep vhost-user   # verify"
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
