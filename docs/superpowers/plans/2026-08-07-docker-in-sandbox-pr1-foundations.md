# Docker-in-sandbox PR 1 — Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the behavior-neutral foundations for docker mode (#198): guest-kernel networking symbols, a vendored static iproute2 `ip`, the image supplementary-groups fix, and the wildcard `:15001` redirect bind.

**Architecture:** Four independent slices, each shippable alone, per spec §9 (`docs/superpowers/specs/2026-08-07-docker-in-sandbox-design.md`). Nothing here is gated on a docker flag; the supplementary-groups fix is a user-visible improvement for all sandboxes, the rest is inert until PR 2.

**Tech Stack:** Rust (izba-core/izba-init), kernel Kconfig fragment (`merge_config.sh`), bash + pinned-Alpine-container builds (`hack/build-*.sh` pattern), GitHub Actions.

## Global Constraints

- All six workspace gates green before EVERY commit: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --check`; `cargo build -p izba-init --target x86_64-unknown-linux-musl --release`; `cargo check --target x86_64-pc-windows-gnu -p izba-proto -p izba-core -p izba-cli`; `cargo clippy --target x86_64-pc-windows-gnu --all-targets -p izba-proto -p izba-core -p izba-cli -- -D warnings`. Run `[ -f .cargo-env ] && source .cargo-env` first.
- SpecParams is an izba-core public type → also run the app gate before the final push: `cd app && npm ci && npm run build && (cd src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)`.
- Unit tests never bind unix/vsock listeners unconditionally; TCP listener tests must runtime-skip on `PermissionDenied` (see `full_connect_via_listener` in `crates/izba-core/src/vsock.rs`).
- Every new function gets a killing test or `#[mutants::skip]` + reason comment (mutation gate; the "call site without a test" defect class).
- Conventional commits. TDD: write the failing test first, watch it fail, then implement.
- KVM suites and kernel/initramfs builds need the Bash sandbox disabled (this WSL2 host has working `/dev/kvm`; never conclude "no KVM").
- Vendored-binary inputs are sha256-pinned (builder image by digest, tarballs by published hash) — `hack/build-nft.sh` is the reference posture.

---

### Task 1: Kernel fragment — docker networking + cgroup symbols

**Files:**
- Modify: `hack/kernel.config` (append a new section after the M1 egress block, line ~146)

**Interfaces:**
- Consumes: nothing.
- Produces: base `vmlinux` with `VETH`/`BRIDGE`/xtables/masquerade/cgroup symbols; PR 2's veth datapath and dockerd depend on it. No Rust surface.

- [ ] **Step 1: Append the fragment section**

Add to `hack/kernel.config` after the `CONFIG_DUMMY=y` line:

```
# Docker-in-sandbox (#198, spec 2026-08-07-docker-in-sandbox-design.md §7):
# the docker-mode workload runs dockerd in its OWN netns (owned by its userns)
# behind an init-owned veth; dockerd needs bridge/veth + its iptables surface
# (iptables-nft => NFT_COMPAT xtables shim; MASQUERADE for inner-container
# SNAT; the xt matches docker's rules use), and the cgroup controllers nested
# runc drives. Base fragment, NOT a variant: no D4-style structural-deny
# argument, variants combine multiplicatively (usb+docker), and the shipped
# .deb's vmlinux must carry it (e2e runs the shipped artifact). Enumerated
# against docker's check-config.sh "Generally Necessary" + network sections.
CONFIG_VETH=y
CONFIG_BRIDGE=y
CONFIG_BRIDGE_NETFILTER=y
CONFIG_NETFILTER_XTABLES=y
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
CONFIG_NETFILTER_XT_MATCH_MULTIPORT=y
CONFIG_NETFILTER_XT_MARK=y
CONFIG_NETFILTER_XT_NAT=y
CONFIG_NETFILTER_XT_TARGET_MASQUERADE=y
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_FILTER=y
CONFIG_IP_NF_NAT=y
CONFIG_IP_NF_TARGET_MASQUERADE=y
CONFIG_IP_NF_MANGLE=y
CONFIG_NFT_COMPAT=y
CONFIG_NFT_MASQ=y
CONFIG_NF_NAT_MASQUERADE=y
# cgroup controllers for nested container limits (x86_64_defconfig leaves
# several off; dockerd warns and runc degrades without them).
CONFIG_MEMCG=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CFS_BANDWIDTH=y
CONFIG_BLK_CGROUP=y
```

- [ ] **Step 2: Build the kernel and verify fragment survival** (sandbox disabled; ~20-60 min, cached source tree helps)

Run: `hack/build-kernel.sh 6.12.30 dist/vmlinux`
Expected: the "Verifying fragment symbols survived olddefconfig" block passes. If a symbol is reported dropped, its dependency is missing — add the parent symbol with a comment rather than deleting the child (e.g. `NETFILTER_XT_TARGET_MASQUERADE` needs `NF_NAT` — already `=y`). If `CONFIG_NETFILTER_XT_TARGET_MASQUERADE` vs `CONFIG_NETFILTER_XT_NAT` naming differs on 6.12, keep whichever the verification accepts and delete the other, noting it in the fragment comment.

- [ ] **Step 3: Cross-check against docker's check-config.sh**

Run: `curl -fsSL https://raw.githubusercontent.com/moby/moby/master/contrib/check-config.sh -o "$TMPDIR/check-config.sh" && bash "$TMPDIR/check-config.sh" <kernel-build-dir>/.config | grep -v missing.*optional` (the kernel build dir is printed by build-kernel.sh; the script reads any .config path).
Expected: every "Generally Necessary" line green except `CONFIG_NAMESPACES` sub-items already `=y`; note which "Optional Features" stay red (acceptable: IPVS, IPv6, AUFS/btrfs/zfs storage, SECCOMP_FILTER is present via defconfig). Record the residual red list in the commit message body.

- [ ] **Step 4: Regression-boot the existing KVM integration suite against the new kernel** (sandbox disabled)

Run: `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1` with `IZBA_KERNEL=dist/vmlinux IZBA_INITRAMFS=<existing initramfs>` per docs/testing.md.
Expected: PASS — the added symbols must not regress boot/egress (BRIDGE_NETFILTER in particular changes packet paths only when bridges exist; none do in non-docker sandboxes).

- [ ] **Step 5: Commit**

```bash
git add hack/kernel.config
git commit -m "feat(kernel): add bridge/veth/xtables/cgroup symbols for docker mode (#198)"
```

---

### Task 2: Vendored static iproute2 `ip` (`hack/build-ip.sh` + initramfs + CI)

**Files:**
- Create: `hack/build-ip.sh`
- Modify: `hack/build-initramfs.sh` (new `IZBA_IP` optional-embed block after the `IZBA_NFT` block at line ~83-92)
- Modify: `.github/workflows/_artifacts.yml` (new `ip` job mirroring the `nft` job at lines 52-64; add to the `initramfs` job's `needs`/download/env at lines 101-142; add to the summary `needs` at line 234)
- Modify: `.github/workflows/e2e.yml` (mirror its inline nft build at line ~96-98 and the initramfs env at line ~180)

**Interfaces:**
- Consumes: nothing.
- Produces: `/sbin/ip` inside the initramfs (static, musl). PR 2's init veth setup shells out to it. `IZBA_IP` env var contract: optional; absent ⇒ no `/sbin/ip` (PR 2's veth path then fails loudly at runtime — acceptable until PR 2 makes it load-bearing).

- [ ] **Step 1: Write `hack/build-ip.sh`**

Model on `hack/build-nft.sh` verbatim (same pinned-Alpine posture, same static verification). Pin the iproute2 tarball hash from kernel.org's published `sha256sums.asc` (fetch `https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/sha256sums.asc` and copy the value for the chosen tarball — do NOT compute it from the downloaded artifact alone):

```bash
#!/usr/bin/env bash
# Build a static /sbin/ip for the izba initramfs (musl, via Alpine).
# Output: dist/ip  (use: IZBA_IP=dist/ip hack/build-initramfs.sh)
#
# Docker mode (#198) gives the workload container its own netns; izba-init
# wires it to the init netns with a veth pair, and veth creation requires
# netlink (RTM_NEWLINK) — init's net.rs is ioctl-only by design. A vendored
# static `ip` performs the link/addr/route setup in both namespaces.
#
# Same sha256-pinned posture as build-nft.sh: Alpine builder by digest,
# source tarball by the hash kernel.org publishes in sha256sums.asc.
set -euo pipefail
cd "$(dirname "$0")/.."

ALPINE="alpine@sha256:310c62b5e7ca5b08167e4384c68db0fd2905dd9c7493756d356e893909057601"

IPROUTE2_VER=6.12.0
IPROUTE2_SHA=<value from kernel.org sha256sums.asc>

OUT="dist/ip"
mkdir -p dist

command -v docker >/dev/null 2>&1 || {
    echo "error: docker not found (build-ip.sh builds in an Alpine container)" >&2
    exit 1
}

docker run --rm \
    -e IPROUTE2_VER="$IPROUTE2_VER" -e IPROUTE2_SHA="$IPROUTE2_SHA" \
    -v "$PWD/dist:/out" "$ALPINE" sh -euc '
  apk add --no-cache build-base bison flex linux-headers pkgconf wget xz \
      libmnl-dev libmnl-static
  wget -qO ip.tar.xz "https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-${IPROUTE2_VER}.tar.xz"
  echo "$IPROUTE2_SHA  ip.tar.xz" | sha256sum -c -
  tar xJf ip.tar.xz
  cd "iproute2-${IPROUTE2_VER}"
  # configure probes optional libs (elf/bpf/cap/selinux); none are installed,
  # so the probes disable them — exactly what a minimal static ip wants.
  ./configure
  # Only lib + ip are needed (no tc/ss/bridge binaries in the initramfs).
  make -j"$(nproc)" SUBDIRS="lib ip" LDFLAGS="-static"
  strip ip/ip && cp ip/ip /out/ip
'
file "$OUT" | grep -q "statically linked" || { echo "error: $OUT is not static" >&2; exit 1; }
echo "wrote $OUT ($(du -sh "$OUT" | cut -f1), static, sha256 $(sha256sum "$OUT" | cut -d' ' -f1))"
```

If `SUBDIRS="lib ip"` is not honored by that iproute2 version's Makefile, fall back to `make -C lib && make -C ip LDFLAGS="-static"`. If the static link drags in a missing `libmnl.a` symbol set, add `LIBS="-lmnl"`.

- [ ] **Step 2: Run it and sanity-check the binary** (needs docker; sandbox disabled)

Run: `bash hack/build-ip.sh && ./dist/ip -V && ./dist/ip link help 2>&1 | grep -q veth && echo OK`
Expected: version prints, `veth` listed as a link type, `OK`.

- [ ] **Step 3: Add the `IZBA_IP` embed block to `hack/build-initramfs.sh`**

Copy the `IZBA_NFT` block shape exactly (lines 83-92), inserted right after it:

```bash
# Optional static iproute2 ip (docker-mode veth setup; see hack/build-ip.sh).
if [[ -n "${IZBA_IP:-}" ]]; then
    if [[ ! -f "$IZBA_IP" ]]; then
        echo "error: IZBA_IP='$IZBA_IP' does not exist" >&2
        exit 1
    fi
    cp "$IZBA_IP" "$WORK/sbin/ip"
    chmod 755 "$WORK/sbin/ip"
    echo "  embedded ip from $IZBA_IP"
fi
```

Also update the usage comment block at the top of the script (the `IZBA_NFT=` line ~12 has siblings — add `IZBA_IP=/path/to/static/ip  (optional, see hack/build-ip.sh)`).

- [ ] **Step 4: Rebuild the initramfs locally and verify**

Run: `IZBA_IP=dist/ip IZBA_NFT=<existing> ... hack/build-initramfs.sh` (reuse whatever embed set the local dev initramfs already uses), then `zcat dist/initramfs.cpio.gz | cpio -t 2>/dev/null | grep -x sbin/ip` (adjust to the script's actual output path/compression).
Expected: `sbin/ip` listed.

- [ ] **Step 5: Wire CI**

In `.github/workflows/_artifacts.yml`: add an `ip` job cloned from the `nft` job (lines 52-64: `run: hack/build-ip.sh`, upload artifact `ip` from `dist/ip`); add `ip` to the `initramfs` job `needs`, download it, add the existence check + `chmod 755 dist/ip` + `IZBA_IP=dist/ip` to the build-initramfs invocation (lines 136-142); add `ip` to the summary job `needs` (line 234) and its version line (`iproute2: 6.12.0`). In `.github/workflows/e2e.yml`: add `- run: hack/build-ip.sh` next to the nft build (line ~96-98) and `IZBA_IP=dist/ip` to its initramfs invocation (line ~180). Check `.github/workflows/dogfood.yml` for a third copy of the initramfs recipe and mirror there too if present.

- [ ] **Step 6: Commit**

```bash
git add hack/build-ip.sh hack/build-initramfs.sh .github/workflows/_artifacts.yml .github/workflows/e2e.yml
git commit -m "feat(hack): vendor a static iproute2 ip into the initramfs (#198)"
```

(Include dogfood.yml in the add if touched.)

---

### Task 3: Supplementary groups from the image's /etc/group

**Files:**
- Modify: `crates/izba-core/src/image/runtime_config.rs` (GroupEntry at 229, `parse_group` at 264, `UserDb` impl at 297, `SpecParams` at 511, `generate_spec` at 587; tests module)
- Modify: `crates/izba-core/src/sandbox.rs` (the `resolve_process_user` call site at ~668 and the `SpecParams` literal at ~697)

**Interfaces:**
- Consumes: existing `UserDb`, `SpecParams`, `generate_spec`.
- Produces: `GroupEntry.members: Vec<String>`; `UserDb::supplementary_gids(&self, declared: Option<&str>) -> Vec<u32>` (first-occurrence order, deduped); `SpecParams.additional_gids: &'a [u32]`; spec `process.user.additionalGids` populated when non-empty, absent when empty. PR 2 relies on this for the `docker` group; every sandbox benefits now.

- [ ] **Step 1: Write the failing tests** (in `runtime_config.rs` tests module)

```rust
#[test]
fn parse_group_reads_member_list() {
    let g = parse_group("docker:x:999:agent,deploy\nnogroup:x:65534:\n");
    assert_eq!(g[0].members, vec!["agent".to_string(), "deploy".to_string()]);
    assert_eq!(g[1].members, Vec::<String>::new());
}

#[test]
fn supplementary_gids_symbolic_user_collects_memberships() {
    let db = UserDb::from_files(
        Some("agent:x:1000:1000::/home/agent:/bin/bash\n"),
        Some("agent:x:1000:\ndocker:x:999:agent\naudio:x:29:pulse,agent\nother:x:5:pulse\n"),
    );
    // Member-of groups only, group-file order; the primary gid (1000) is NOT
    // repeated here.
    assert_eq!(db.supplementary_gids(Some("agent")), vec![999, 29]);
}

#[test]
fn supplementary_gids_numeric_user_reverse_resolves_via_passwd() {
    let db = UserDb::from_files(
        Some("agent:x:1000:1000::/home/agent:/bin/bash\n"),
        Some("docker:x:999:agent\n"),
    );
    // USER 1000: uid reverse-looked-up to "agent", memberships apply
    // (docker-faithful); USER 1000:0 strips the :group part first.
    assert_eq!(db.supplementary_gids(Some("1000")), vec![999]);
    assert_eq!(db.supplementary_gids(Some("1000:0")), vec![999]);
}

#[test]
fn supplementary_gids_unknown_or_absent_user_is_empty() {
    let db = UserDb::from_files(None, Some("docker:x:999:agent\n"));
    assert_eq!(db.supplementary_gids(Some("ghost")), Vec::<u32>::new());
    assert_eq!(db.supplementary_gids(None), Vec::<u32>::new());
    assert_eq!(db.supplementary_gids(Some("")), Vec::<u32>::new());
    // Numeric uid with no passwd row: no name to match members against.
    assert_eq!(db.supplementary_gids(Some("4242")), Vec::<u32>::new());
}

#[test]
fn supplementary_gids_dedupes_repeated_membership() {
    let db = UserDb::from_files(
        Some("agent:x:1000:1000::/h:/bin/sh\n"),
        Some("docker:x:999:agent\ndup:x:999:agent\n"),
    );
    assert_eq!(db.supplementary_gids(Some("agent")), vec![999]);
}

#[test]
fn generate_spec_populates_additional_gids() {
    let params = SpecParams { additional_gids: &[999, 29], ../* copy the existing minimal-params helper used by neighboring generate_spec tests */ };
    let spec = generate_spec(&params).unwrap();
    let user = spec.process().as_ref().unwrap().user().clone();
    assert_eq!(user.additional_gids().clone().unwrap(), vec![999, 29]);
    assert_eq!(user.uid(), params.user.0);
}

#[test]
fn additional_gids_are_always_inside_the_gid_map() {
    // transpose_identity_map is a bijection over 0..USERNS_RANGE_END, so any
    // gid the image's /etc/group can name (u32 < u32::MAX) is mapped; this
    // pins that invariant so a future map change can't silently strand
    // additionalGids outside the userns (setgroups would then fail).
    let (_uids, gids) = compute_userns_mappings((1000, 1000), (0, 0));
    let covered: u64 = gids.iter().map(|m| m.size() as u64).sum();
    assert_eq!(covered, USERNS_RANGE_END as u64);
}
```

Note: `generate_spec_populates_additional_gids` — look at the existing `generate_spec` tests around line 1100+ for how they build minimal `SpecParams` (there is a helper or repeated literal; extend it with `additional_gids: &[]` everywhere it appears).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p izba-core parse_group_reads_member_list supplementary_gids generate_spec_populates_additional_gids`
Expected: compile FAILURE (no `members` field, no `supplementary_gids`, no `additional_gids` param) — that is the failing state for structural TDD; fix compile by implementing in Step 3.

- [ ] **Step 3: Implement**

In `GroupEntry` (line 229) add `pub members: Vec<String>`. In `parse_group` (line 264) read the 4th field:

```rust
let members = f
    .next()
    .map(|m| {
        m.split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default();
```

(and add `members` to the struct literal; fix the existing `parse_group_basic_and_skips_junk` test at line ~1757 to include the new field expectation).

In `impl UserDb` add:

```rust
/// Supplementary gids for the image `USER`: the gids of every `/etc/group`
/// entry listing the user as a member — group-file order, deduped. The
/// primary gid is excluded by construction (membership lists carry
/// secondary groups). A numeric USER is reverse-resolved to a name via
/// passwd first (docker-faithful); no passwd match, no declared USER, or an
/// unresolvable name ⇒ empty (the direction that never invents privilege).
pub fn supplementary_gids(&self, declared: Option<&str>) -> Vec<u32> {
    let user_part = match declared {
        None | Some("") => return Vec::new(),
        Some(u) => u.split_once(':').map_or(u, |(user, _)| user),
    };
    let name: &str = match user_part.parse::<u32>() {
        Ok(n) => match self.passwd.iter().find(|e| e.uid == n) {
            Some(e) => &e.name,
            None => return Vec::new(),
        },
        Err(_) => user_part,
    };
    let mut seen = std::collections::HashSet::new();
    self.group
        .iter()
        .filter(|g| g.members.iter().any(|m| m == name))
        .map(|g| g.gid)
        .filter(|gid| seen.insert(*gid))
        .collect()
}
```

In `SpecParams` (line 511) add:

```rust
/// Supplementary gids for the container process user (the image USER's
/// /etc/group memberships — e.g. `docker`). Empty when none resolve.
pub additional_gids: &'a [u32],
```

In `generate_spec` (line 614):

```rust
let mut user_builder = UserBuilder::default().uid(params.user.0).gid(params.user.1);
if !params.additional_gids.is_empty() {
    user_builder = user_builder.additional_gids(params.additional_gids.to_vec());
}
let user = user_builder.build()?;
```

In `crates/izba-core/src/sandbox.rs`: at the `resolve_process_user` call site (~668), compute `let additional_gids = user_db.supplementary_gids(image_config.and_then(|c| c.user.as_deref()));` and pass `additional_gids: &additional_gids` in the `SpecParams` literal (~697). Grep for every other `SpecParams {` literal in the workspace (tests included) and add `additional_gids: &[]` there.

- [ ] **Step 4: Run the full izba-core test suite**

Run: `cargo test -p izba-core`
Expected: PASS, including all pre-existing `generate_spec`/`parse_group` tests you updated.

- [ ] **Step 5: Mutation-check the new code** (sandbox disabled if cargo-mutants needs it)

Run: `cargo mutants -p izba-core -f crates/izba-core/src/image/runtime_config.rs --no-shuffle 2>&1 | tail -20`
Expected: no MISSED mutants in `supplementary_gids`/`parse_group`/the `generate_spec` gid branch. Add tests for any survivor (e.g. the `is_empty()` guard mutant needs the "empty ⇒ additionalGids absent in JSON" assertion: extend `generate_spec_populates_additional_gids` with a `&[]` case asserting `user.additional_gids().is_none()`).

- [ ] **Step 6: Commit**

```bash
git add crates/izba-core/src/image/runtime_config.rs crates/izba-core/src/sandbox.rs
git commit -m "fix(core): apply the image USER's supplementary groups to the workload (#198)"
```

---

### Task 4: Wildcard bind for the TCP redirect listener

**Files:**
- Modify: `crates/izba-init/src/egress.rs` (`bind_tcp_redirect` at line 375, its doc comment, tests)

**Interfaces:**
- Consumes: nothing new.
- Produces: `:15001` listener on `0.0.0.0` — PR 2's prerouting REDIRECT (which rewrites the destination to the veth address `192.168.127.1`) can reach it. Behavior-neutral today: the guest is a NIC-less island; the only sources are in-guest.

- [ ] **Step 1: Write the failing test** (in `egress.rs` tests)

```rust
#[test]
fn tcp_redirect_listener_binds_wildcard() {
    // Prerouting REDIRECT (docker mode, spec §3) rewrites the destination to
    // the ingress interface's address (192.168.127.1), not loopback — the
    // listener must accept on any local address. Wildcard is harmless on the
    // NIC-less island. Runtime-skip where the sandbox denies bind (repo test
    // constraint).
    let l = match bind_tcp_redirect() {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return, // parallel test run owns :15001
        Err(e) => panic!("bind: {e}"),
    };
    assert!(l.local_addr().unwrap().ip().is_unspecified());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p izba-init tcp_redirect_listener_binds_wildcard`
Expected: FAIL on the `is_unspecified` assertion (binds 127.0.0.1 today) — or skip-pass in a bind-denied sandbox; if it skips locally, verify the failure by inspection and rely on CI's run.

- [ ] **Step 3: Change the bind + doc comment**

In `bind_tcp_redirect` (line 375): `TcpListener::bind(("0.0.0.0", REDIRECT_PORT))`, and extend the function's doc comment: wildcard because prerouting REDIRECT (docker mode) delivers to the veth address, while output-hook REDIRECT delivers to loopback — one listener serves both datapaths.

- [ ] **Step 4: Run the izba-init suite**

Run: `cargo test -p izba-init`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/izba-init/src/egress.rs
git commit -m "feat(init): bind the TCP redirect stub on the wildcard address (#198)"
```

---

### Task 5: Gates, delivery, CI iteration

**Files:**
- No new files; the branch `worktree-docker-in-sandbox` as committed by Tasks 1-4.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: PR open and iterated to CLEAN per the repo's delivery loop.

- [ ] **Step 1: Run all six workspace gates + the app gate** (Global Constraints, verbatim)

Expected: all green. Fix anything red before proceeding.

- [ ] **Step 2: Run the KVM integration + daemon e2e suites locally** (sandbox disabled)

Run: `IZBA_INTEGRATION=1 cargo test -p izba-core --test integration -- --test-threads=1` and `IZBA_INTEGRATION=1 cargo test -p izba-cli --test daemon_e2e -- --test-threads=1`, against the Task-1 kernel + Task-2 initramfs.
Expected: PASS — proves the foundations regress nothing on real VMs before CI does the same.

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin worktree-docker-in-sandbox
gh pr create -R Lupus/izba --title "Docker-in-sandbox foundations: kernel symbols, static ip, supplementary groups, wildcard redirect bind (#198)" --body "$(cat <<'EOF'
Part 1 of 2 for #198 (spec: docs/superpowers/specs/2026-08-07-docker-in-sandbox-design.md, §9 PR 1).

Behavior-neutral foundations for docker mode:
- kernel fragment: bridge/veth/xtables/masquerade + cgroup controllers (base, not a variant — §7 rationale in the spec)
- vendored static iproute2 `ip` (hack/build-ip.sh, sha-pinned, IZBA_IP initramfs embed + CI wiring)
- image /etc/group supplementary groups applied to the workload user (all sandboxes; the `docker`-group half of #198)
- TCP redirect stub binds wildcard (prerouting REDIRECT readiness)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

(NOT draft — repo rule.)

- [ ] **Step 4: Dispatch the devbuild while CI runs**

Run: `bash hack/devbuild.sh` (unsandboxed). Record the exact `dist/local/<ts>-<sha>/` path it reports (main-checkout copy).

- [ ] **Step 5: Iterate CI to CLEAN**

Watch `gh pr checks`; fix real failures (fresh commits or amend+force-with-lease per repo habit), rerun known-infra flakes (Windows install-action hang, windows vitest containerStatus flake). Done means: all required checks green, Sonar quality gate passed, Greptile 5/5 with no unresolved actionable comments (use the greploop skill), `mergeStateStatus: CLEAN`. If checks won't start: it's a merge conflict, never quota — rebase on origin/main and force-push.

- [ ] **Step 6: Report**

Summary + PR link + devbuild path + install command, per the repo delivery loop. Then write the PR 2 plan (separate document) informed by what landed.
