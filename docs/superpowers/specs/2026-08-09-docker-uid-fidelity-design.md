# Docker-mode uid fidelity — shifted userns + idmapped layers — design

**Status:** approved for implementation (sprint 2026-08-09)
**Issue anchors:** the claude-code-docker breakage (Windows ownership scramble /
Linux fail-closed start); follows up `2026-08-07-docker-in-sandbox-design.md`
(#198) and the F-32 rootless invariant (`docs/security/`).

## 1. Problem

Two field failures, one root cause — `transpose_identity_map(workload, owner)`
(Option A) collides with non-root-`USER` images:

- **Windows (observed):** `workspace_owner()` is a `(0,0)` stub on
  `cfg(not(unix))` — semantically right (OpenVMM virtiofs presents workspace
  files as guest-0, mode 0777), but the transpose then swaps guest-0↔guest-1000
  for a `USER agent` (uid 1000) image: every root-owned image file (`/etc`,
  setuid `sudo`) appears in-container as uid 1000, and agent's `$HOME` appears
  as root. Claude Code gets EACCES on its own settings; `sudo` refuses to run.
  Verified against the live `docker-claude-test` sandbox's generated OCI spec.
- **Linux (code-pinned):** owner (host uid 1000) == image `USER` (1000)
  degenerates the map to identity, `docker_userns_isolates_root` correctly
  says the F-32 invariant would not hold, and the docker-mode start **fails
  closed** ("use a non-root-owned workspace"). The flagship
  `docker/sandbox-templates:claude-code-docker` image cannot start at all.

Structural conflict: F-32 requires container-0 ≠ guest-0 in docker mode, while
image fidelity requires image-root files (stored as guest-0 in the erofs) to
appear as container-0. **No userns map alone can satisfy both** over a rootfs
that stores raw image uids.

## 2. Decision — the rootless-container playbook

Docker mode adopts the same two-piece answer rootless Docker/Podman use:
a shifted userns map, plus an **idmapped mount** of the container's storage so
on-disk image uids present shifted — making the container's view of its own
files exactly the image's uids.

### 2.1 The map (`docker_shifted_map`)

One function `guest_of(c)` used for BOTH the container userns mapping and the
layer idmap (uid and gid independently, same shape):

- `guest_of(c) = BASE + c` for `c ∈ [0, RANGE)`, **except**
- `guest_of(workload) = owner` **iff `owner != 0`** (the workspace carve-out).

Constants: `RANGE = 1 << 20` (1,048,576 ids — covers real-world image uids),
`BASE = 1 << 21`; if `owner ∈ [BASE, BASE+RANGE)` (exotic host uid), bump
`BASE += RANGE` (the two windows cannot both contain `owner`).

Properties:
- **F-32 strictly stronger:** container-0 → guest `BASE` (or `owner` when the
  image `USER` is root) — never guest-0; moreover guest-0 is now *entirely
  unmapped* (the old transpose mapped it to the workload id, leaving
  CAP_DAC_OVERRIDE theoretically in reach; now `capable_wrt_inode_uidgid`
  fails outright for every guest-root-owned inode).
- **No fail-closed hole:** the invariant holds by construction for every
  `(owner, workload)`, so the "use a non-root-owned workspace" start error
  disappears. `docker_userns_isolates_root` stays as a post-construction
  assertion (regression tripwire), not a user-facing gate.
- **Workspace UX kept (Linux):** container-`workload` maps to guest-`owner`,
  so the virtiofs `/workspace` (guest driver forces `default_permissions`) is
  owned and writable by the image `USER`, as today.
- **Windows:** `owner == 0` ⇒ pure shift, no carve-out (mapping any container
  id to guest-0 would hand the workload guest-root's euid for sysctl DAC —
  forbidden). `/workspace` presents guest-0 0777 → writable via other-bits;
  it lists as `nobody` in-container. Cosmetic; noted in §6.

### 2.2 Idmapped layers (init, docker mode only)

Overlayfs itself cannot be the target of an idmapped mount on 6.12 (no
`FS_ALLOW_IDMAP`), but **erofs and ext4 both allow it** (verified in v6.12
sources), and overlay-over-idmapped-layers is supported since 5.19. So init,
in docker mode:

1. mounts `/lower` (erofs) + `/upper` (ext4) plain, creates
   `/upper/{data,work}` as today;
2. builds a helper userns whose uid/gid maps are the `guest_of` extents
   (delivered via cmdline, §2.3), then for each of `/lower`, `/upper`:
   `open_tree(OPEN_TREE_CLONE)` → `mount_setattr(MOUNT_ATTR_IDMAP)` →
   `move_mount` back over the same path;
3. assembles the overlay at `/rootfs` from the (now idmapped) paths —
   the overlay mount options string is unchanged;
4. mounts each user volume (ext4) through the same clone→idmap→move sequence.

Result: a file stored with image uid `D` presents guest-side as
`guest_of(D)`, and through the container userns as `D` again — **verbatim
image ownership in-container for every id in `[0, RANGE)`**, including the
`/var/lib/docker` volume (fresh ext4 root, disk-uid 0 → container-0 →
dockerd owns it with no chown pass).

### 2.3 Wire: `izba.uidmap=` / `izba.gidmap=` cmdline params

`sandbox::start()` (docker mode only) appends
`izba.uidmap=<disk>-<presented>-<n>[,…] izba.gidmap=…` — the OCI spec's
`linux.{uid,gid}Mappings` extents **verbatim** (real-VM-verified orientation:
an idmapped mount computes `presented = make_kuid(mnt_userns, disk_uid)`, so
the on-disk uid is the namespace-INNER id and a `uid_map` line reads
`<disk> <presented> <n>`; the OCI extent `(container, guest, n)` has
disk==container==image-uid and presented==guest — same columns), emitted by
`layer_idmap_cmdline_value` from the very Spec object `write_oci_bundle` just
wrote (single generation site; mirrors the `izba.volumes` pattern;
host-authoritative; never emitted apart from `izba.docker=1`). One extra
**fsuid-0 anchor extent** closes each list: `<RANGE>-0-1` (disk
`DOCKER_IDMAP_FSUID0_DISK_ID` = `RANGE` → presented 0).
Kernel background: overlayfs creates whiteouts/copy-ups with the MOUNTER's
creds (init, fsuid 0) and crun mkdirs missing mount targets as guest-root; a
fsuid with no reverse mapping in the mount idmap fails `EOVERFLOW`, so
without the anchor `rm` of any lower file would break. Anchored writes land
on a disk id no image uses and present in-container as `nobody` (guest-0
stays unmapped in the container userns — F-32 intact). init parses the params
in `cmdline.rs` and **fails a docker-mode boot loudly** when they are absent
or malformed.

### 2.4 Init writes through the idmapped rootfs — `setfsuid` write-through

Init's *meaningful* writes should not land on the anchor (`nobody`-owned):
every init write into `/rootfs` in docker mode goes through
`idmap::with_fs_ids((presented_of_disk_zero(uid), …), || …)`, which
temporarily sets per-thread `setfsuid`/`setfsgid` to presented-of-disk-0 —
attribution then lands as **disk uid 0**, i.e. container-root-owned, exactly
like a normal system. Call sites (audited): `/etc/resolv.conf`, `/etc/hosts`,
`/etc/izba/ca*.pem` (trust anchor), `izba cp` tar extraction (per-connection
thread). Volume mountpoint `create_dir_all` deliberately relies on the anchor
(the dir is mounted over). Invariant (documented at the helper): any future
init write under `/rootfs` must use the helper in docker mode.

## 3. Non-docker mode — kill the owner-0 transpose

`transpose_identity_map` returns the **identity map when `owner == 0` and
`workload != 0`**. Rationale: an owner anchor of 0 means either Windows
(guest-visible virtiofs owner is 0, mode 0777 — transpose buys nothing, and
scrambles the image) or a root-owned workspace on Linux (`sudo izba` — the old
transpose gave the workload write access by scrambling the image; identity is
honest: root's 0755 files are not the workload's to write). Linux flows with a
non-root owner are byte-for-byte unchanged.

## 4. Out of scope / follow-ups

- Nested userns remap inside the workload (dockerd `--userns-remap`,
  rootless-in-rootless): ids beyond `RANGE` stay unmapped; revisit on demand.
- ~~Idmapped virtiofs (kernel ≥ 6.15) would let Windows `/workspace` present a
  real owner; revisit when the pinned kernel moves.~~ **Re-diagnosed
  2026-08-09:** the "≥ 6.15" premise was wrong — virtiofs has carried
  `FS_ALLOW_IDMAP` + implicit `default_permissions` since 6.12, and virtiofsd
  has advertised `FUSE_ALLOW_IDMAP` since v1.13.0 (izba pins 1.13.3). The June
  spike failed on an inverted mount-map orientation (the same bug class §2.3
  documents), not missing kernel plumbing; re-run with the corrected columns
  it passes on the 6.12.30 pins. The guest side now stacks an idmapped mount
  over the workspace share when the host asks (`izba.wsidmap=1`, emitted for
  docker sandboxes whose owner leg is 0), fail-soft on backends without
  `FUSE_ALLOW_IDMAP`. **The remaining Windows blocker is OpenVMM**: its
  bundled virtiofs server does not advertise `FUSE_ALLOW_IDMAP` (verified
  upstream, zero hits), so the idmap degrades to the §6 cosmetic there until
  upstream gains the flag.
- Unifying non-docker mode onto the shifted+idmap scheme (#200 territory).

## 5. Testing

- **Host units:** map shapes for `(owner,workload)` ∈ {(1000,1000), (1000,0),
  (0,1000), (0,0), owner-in-window bump, owner>window}; extents bijective and
  non-overlapping; cmdline round-trip (emit → parse); `generate_spec` docker
  branch uses the shifted map and never errors; transpose owner-0 identity;
  fsuid helper attribution logic (seamed).
- **KVM e2e (docker mode):** (a) existing dind journey still green (root
  `USER`, carve-out at container-0→owner); (b) **new**: a pinned non-root
  `USER` image starts (Bug-2 regression gate), `stat` fidelity in-container
  (`/etc/hostname` owner 0, `$HOME` owner = USER uid), workspace write as the
  USER, engine boots, `sudo`-shaped setuid escalation works where the image
  ships it.
- **Windows validation:** devbuild installer, recreate the claude-code-docker
  sandbox, check `/home/agent` ownership, settings write, `sudo -v`,
  `docker run hello-world`.

## 6. Known cosmetic residue (accepted)

On Windows (owner=0), `/workspace` lists as `nobody` (docker mode) or root
(non-docker) inside the container; writable either way via 0777. Git may need
`safe.directory` there — the templates already run in `/workspace` as the
repo user on Linux, and the Windows share never had a real owner to begin
with.

**Update 2026-08-09:** the guest-side fix ships (`izba.wsidmap=1` → init
stacks an idmapped mount over the share with the same layer extents, so
disk-0 presents as container-root and every mapped container id writes
through). On Linux it takes effect for root-owned workspaces (`sudo izba`
docker sandboxes). On Windows the residue REMAINS for now: OpenVMM's virtiofs
does not advertise `FUSE_ALLOW_IDMAP`, init's mount_setattr is refused, and
the share keeps the 0777/`nobody` presentation — it lights up automatically
once OpenVMM gains the flag (§4).
