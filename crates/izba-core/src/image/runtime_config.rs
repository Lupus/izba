//! Host-side generation of the OCI runtime `config.json` for the guest's
//! single workload container (Pillar A2).
//!
//! Pure transforms over the captured image config ([`oci_client::config`]) plus
//! izba's per-sandbox overrides, producing an [`oci_spec::runtime::Spec`] that
//! crun consumes inside the guest. Kept free of I/O so the merge semantics —
//! the part docker users notice — are exhaustively unit-tested.

use anyhow::{bail, Result};
use oci_client::config::Config;
use oci_spec::runtime::{
    Capability, LinuxCapabilitiesBuilder, LinuxDeviceCgroupBuilder, LinuxDeviceType,
    LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder, ProcessBuilder, RootBuilder, Spec,
    UserBuilder,
};
use std::collections::HashSet;
use std::path::PathBuf;

/// The docker-default capability set for the container's root process.
///
/// `Spec::default()` ships only the OCI minimal example set (AuditWrite, Kill,
/// NetBindService), which lacks `CAP_DAC_OVERRIDE` etc. — so container-root
/// cannot even write the host-owned virtiofs `/workspace`. We instead grant the
/// same set Docker grants by default: enough for a normal root workload (chown,
/// dac-override, setuid/gid, mknod, …) while still dropping the dangerous caps
/// (SYS_ADMIN, SYS_PTRACE, …). The in-guest container is HARDENING/least-
/// privilege, not the security boundary (the VM is) — this matches that stance.
fn docker_default_caps() -> Result<oci_spec::runtime::LinuxCapabilities> {
    let set: HashSet<Capability> = [
        Capability::AuditWrite,
        Capability::Chown,
        Capability::DacOverride,
        Capability::Fowner,
        Capability::Fsetid,
        Capability::Kill,
        Capability::Mknod,
        Capability::NetBindService,
        Capability::NetRaw,
        Capability::Setfcap,
        Capability::Setgid,
        Capability::Setpcap,
        Capability::Setuid,
        Capability::SysChroot,
    ]
    .into_iter()
    .collect();
    Ok(LinuxCapabilitiesBuilder::default()
        .bounding(set.clone())
        .effective(set.clone())
        .permitted(set)
        .inheritable(HashSet::new())
        .ambient(HashSet::new())
        .build()?)
}

/// Docker-mode capability set (spec §2): the docker-default least-privilege
/// set plus the admin caps dockerd + nested runc need — ALL scoped inside
/// the container's user namespace (a userns `CAP_SYS_ADMIN` cannot mount real
/// block devices or touch init's namespaces). Strictly weaker than the
/// privileged builder profile ([`all_caps`]), which drops the userns entirely.
pub fn docker_mode_caps() -> Result<oci_spec::runtime::LinuxCapabilities> {
    let base = docker_default_caps()?;
    let mut set: HashSet<Capability> = base.bounding().clone().unwrap_or_default();
    set.extend([
        Capability::SysAdmin,
        Capability::NetAdmin,
        Capability::SysPtrace,
    ]);
    Ok(LinuxCapabilitiesBuilder::default()
        .bounding(set.clone())
        .effective(set.clone())
        .permitted(set)
        .inheritable(HashSet::new())
        .ambient(HashSet::new())
        .build()?)
}

/// The FULL capability set, for **privileged builder VMs only** (see
/// [`SpecParams::privileged`]).
///
/// Rootful BuildKit's overlayfs snapshotter performs bind/overlay `mount(2)`s
/// inside the container, which require `CAP_SYS_ADMIN` (and friends) — exactly
/// what [`docker_default_caps`] drops. Granting every capability (effective /
/// bounding / permitted / inheritable / ambient) is the in-VM equivalent of
/// `docker run --privileged`. This is acceptable ONLY because the throwaway
/// builder microVM is itself the security boundary (gated egress + host-side
/// VMM jail); normal sandboxes never use this.
fn all_caps() -> Result<oci_spec::runtime::LinuxCapabilities> {
    // `oci_spec::runtime::Capability` does not derive `EnumIter`, so the full
    // set is enumerated explicitly (kept exhaustive — a new variant should be
    // added here too; the unit test asserts SysAdmin presence as the canary).
    let set: HashSet<Capability> = [
        Capability::AuditControl,
        Capability::AuditRead,
        Capability::AuditWrite,
        Capability::BlockSuspend,
        Capability::Bpf,
        Capability::CheckpointRestore,
        Capability::Chown,
        Capability::DacOverride,
        Capability::DacReadSearch,
        Capability::Fowner,
        Capability::Fsetid,
        Capability::IpcLock,
        Capability::IpcOwner,
        Capability::Kill,
        Capability::Lease,
        Capability::LinuxImmutable,
        Capability::MacAdmin,
        Capability::MacOverride,
        Capability::Mknod,
        Capability::NetAdmin,
        Capability::NetBindService,
        Capability::NetBroadcast,
        Capability::NetRaw,
        Capability::Perfmon,
        Capability::Setgid,
        Capability::Setfcap,
        Capability::Setpcap,
        Capability::Setuid,
        Capability::SysAdmin,
        Capability::SysBoot,
        Capability::SysChroot,
        Capability::SysModule,
        Capability::SysNice,
        Capability::SysPacct,
        Capability::SysPtrace,
        Capability::SysRawio,
        Capability::SysResource,
        Capability::SysTime,
        Capability::SysTtyConfig,
        Capability::Syslog,
        Capability::WakeAlarm,
    ]
    .into_iter()
    .collect();
    Ok(LinuxCapabilitiesBuilder::default()
        .bounding(set.clone())
        .effective(set.clone())
        .permitted(set.clone())
        .inheritable(set.clone())
        .ambient(set)
        .build()?)
}

/// The container rootfs inside the guest — the overlay init mounts at `/rootfs`
/// (erofs lower + ext4 upper). Workspace and user volumes are submounts under
/// it, so they ride along in the container's rootfs subtree.
pub const CONTAINER_ROOTFS: &str = "/rootfs";

/// Resolve the container's process argv exactly as `docker run` does.
///
/// Faithful port of moby's `daemon/commit.go::merge` followed by
/// `daemon/create.go::mergeAndVerifyConfig` (the `[""]` reset + "no command"
/// check). The non-obvious rules this captures:
///
/// - An explicit entrypoint override (`--entrypoint X`) **clears the image
///   CMD** — image `Cmd`/`Entrypoint` are inherited *only* when no entrypoint
///   override was given. So `--entrypoint X` alone runs just `[X]`.
/// - `--entrypoint ""` clears the entrypoint and likewise does **not** inherit
///   the image CMD; with no command args it is an error.
/// - Image `Cmd` is inherited only when neither an entrypoint override nor
///   command args were supplied.
///
/// Inputs mirror moby's `containertypes.Config` fields:
/// - `image_entrypoint`/`image_cmd`: the image's `Entrypoint`/`Cmd`.
/// - `user_entrypoint`: `None` = `--entrypoint` not passed; `Some(["X"])` =
///   `--entrypoint X`; `Some([""])` = `--entrypoint ""` (the CLI never yields an
///   empty vec).
/// - `user_cmd`: `None` = no positional command args; `Some(args)` = the
///   positional command override.
pub fn resolve_process_args(
    image_entrypoint: &[String],
    image_cmd: &[String],
    user_entrypoint: Option<&[String]>,
    user_cmd: Option<&[String]>,
) -> Result<Vec<String>> {
    // moby daemon/commit.go::merge — image Cmd/Entrypoint are inherited only
    // when no entrypoint override was supplied (the outer `len(Entrypoint)==0`
    // gate uses the user value, before the [""] reset below).
    let mut entrypoint: Vec<String> = user_entrypoint.map(<[_]>::to_vec).unwrap_or_default();
    let mut cmd: Vec<String> = user_cmd.map(<[_]>::to_vec).unwrap_or_default();
    if entrypoint.is_empty() {
        if cmd.is_empty() {
            cmd = image_cmd.to_vec();
        }
        // moby's `userConf.Entrypoint == nil`: only inherit when the override
        // was absent entirely (not an explicit empty value).
        if user_entrypoint.is_none() {
            entrypoint = image_entrypoint.to_vec();
        }
    }
    // moby create.go: reset the entrypoint if it is exactly [""].
    if entrypoint.len() == 1 && entrypoint[0].is_empty() {
        entrypoint.clear();
    }
    if entrypoint.is_empty() && cmd.is_empty() {
        bail!("no command specified: image has no Entrypoint/Cmd and none was provided");
    }
    entrypoint.extend(cmd);
    Ok(entrypoint)
}

/// Merge environment layers the way `docker run` resolves them: the image's
/// `Env` is the base, izba's trust-env defaults (CA bundle etc.) layer on top,
/// and `-e` user overrides win last. Later definitions of the same `KEY`
/// replace earlier ones (docker last-wins) while preserving first-appearance
/// order, yielding a deduped `KEY=VALUE` list for the OCI spec.
///
/// The "only when a CA bundle is present" gate is the caller's job — it passes
/// an empty `trust_env` when the gate is closed.
pub fn merge_env(image_env: &[String], trust_env: &[String], user_env: &[String]) -> Vec<String> {
    // Ordered last-wins-by-key: track first-appearance index per key so a later
    // layer updates the value in place rather than appending a duplicate.
    let mut order: Vec<String> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for entry in image_env.iter().chain(trust_env).chain(user_env) {
        let key = entry.split_once('=').map_or(entry.as_str(), |(k, _)| k);
        match index.get(key) {
            Some(&i) => order[i] = entry.clone(),
            None => {
                index.insert(key.to_string(), order.len());
                order.push(entry.clone());
            }
        }
    }
    order
}

/// Resolve the container's working directory: an explicit override wins (e.g.
/// `/workspace` for interactive sandboxes), else the image's `WorkingDir`, else
/// the OCI default `/`.
pub fn resolve_cwd(image_working_dir: Option<&str>, cwd_override: Option<&str>) -> String {
    cwd_override
        .or(image_working_dir)
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

/// One `/etc/passwd` row reduced to the fields izba's USER resolution needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

/// One `/etc/group` row: `(name, gid)` plus the member list (field 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// Parse `/etc/passwd` content into entries. Standard 7-field colon format;
/// blank lines, `#` comments, and rows whose name/uid/gid don't parse are
/// skipped (a malformed image passwd never aborts a launch).
pub fn parse_passwd(content: &str) -> Vec<PasswdEntry> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut f = line.split(':');
            let name = f.next()?;
            let _passwd = f.next()?;
            let uid = f.next()?.parse().ok()?;
            let gid = f.next()?.parse().ok()?;
            if name.is_empty() {
                return None;
            }
            Some(PasswdEntry {
                name: name.to_string(),
                uid,
                gid,
            })
        })
        .collect()
}

/// Parse `/etc/group` content into `(name, gid)` entries (4-field colon
/// format; same skip rules as [`parse_passwd`]).
pub fn parse_group(content: &str) -> Vec<GroupEntry> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut f = line.split(':');
            let name = f.next()?;
            let _passwd = f.next()?;
            let gid = f.next()?.parse().ok()?;
            if name.is_empty() {
                return None;
            }
            let members = f
                .next()
                .map(|m| {
                    m.split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            Some(GroupEntry {
                name: name.to_string(),
                gid,
                members,
            })
        })
        .collect()
}

/// The image's user databases (`/etc/passwd` + `/etc/group`), used to resolve a
/// symbolic `USER` host-side exactly as docker/containerd do (against the image
/// rootfs at create time). An empty db (legacy cache / image without passwd)
/// resolves no names, so symbolic users fall back to the loud root path.
#[derive(Debug, Clone, Default)]
pub struct UserDb {
    pub passwd: Vec<PasswdEntry>,
    pub group: Vec<GroupEntry>,
}

impl UserDb {
    /// Build from raw file contents (each `None` when the image lacked it).
    pub fn from_files(passwd: Option<&str>, group: Option<&str>) -> Self {
        UserDb {
            passwd: passwd.map(parse_passwd).unwrap_or_default(),
            group: group.map(parse_group).unwrap_or_default(),
        }
    }

    /// Resolve a docker `user[:group]` spec to `(uid, gid)`, or `None` when any
    /// component is a name absent from the db.
    ///
    /// **Intentional divergence:** a pure-numeric `uid` (e.g. `"1000"`) does NOT
    /// consult passwd and defaults gid to 0 — docker-faithful for the numeric form
    /// and matches izba's prior behaviour. A symbolic name (e.g. `"node"`) adopts
    /// the passwd entry's primary gid. So `USER 1000` → `(1000, 0)` while
    /// `USER node` (node=1000:1000 in passwd) → `(1000, 1000)` — on the record.
    pub fn resolve(&self, spec: &str) -> Option<(u32, u32)> {
        let (user_part, group_part) = match spec.split_once(':') {
            Some((u, g)) => (u, Some(g)),
            None => (spec, None),
        };
        // uid + the user's primary gid (used when no explicit group is given).
        let (uid, primary_gid) = match user_part.parse::<u32>() {
            Ok(uid) => (uid, 0), // numeric: docker default gid 0, no passwd lookup
            Err(_) => {
                let e = self.passwd.iter().find(|e| e.name == user_part)?;
                (e.uid, e.gid)
            }
        };
        let gid = match group_part {
            None => primary_gid,
            Some(g) => match g.parse::<u32>() {
                Ok(gid) => gid,
                Err(_) => self.group.iter().find(|e| e.name == g)?.gid,
            },
        };
        Some((uid, gid))
    }

    /// Supplementary gids for the image `USER`: the gids of every `/etc/group`
    /// entry listing the user as a member — group-file order, deduped. The
    /// primary gid is normally absent because `/etc/group` membership lists
    /// conventionally carry only secondary groups; an image that lists a user
    /// in their own primary group produces a redundant entry, which is harmless
    /// to setgroups. A numeric USER is reverse-resolved to a name via
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
        let mut seen = HashSet::new();
        self.group
            .iter()
            .filter(|g| g.members.iter().any(|m| m == name))
            .map(|g| g.gid)
            .filter(|gid| seen.insert(*gid))
            .collect()
    }
}

/// Resolve an image's declared `USER` to a numeric `(uid, gid)` for config.json,
/// plus an optional loud warning.
///
/// - `None` / `Some("")` -> `((0,0), None)` (silent root).
/// - fully numeric (`"1000"`, `"1000:1001"`) -> resolved pair, no warning.
/// - symbolic (`"node"`, `"1000:wheel"`) resolved against `db` (the image's
///   `/etc/passwd`+`/etc/group`) -> resolved pair, no warning.
/// - symbolic but unresolvable (name absent from the image's passwd/group, or a
///   legacy cache with no captured db) -> `((0,0), Some(fallback))` naming the
///   USER. izba never silently downgrades security, so the fallback is loud.
pub fn resolve_process_user(
    declared: Option<&str>,
    db: &UserDb,
) -> ((u32, u32), Option<crate::state::UserFallback>) {
    match declared {
        None | Some("") => ((0, 0), None),
        Some(u) => match db.resolve(u) {
            Some(ids) => (ids, None),
            None => ((0, 0), Some(crate::state::UserFallback::new(u))),
        },
    }
}

/// Default cwd for an interactive sandbox — the virtiofs `workspace` mount,
/// also exec's default cwd today.
pub const INTERACTIVE_CWD: &str = "/workspace";

// ──────────────────────────────────────────────────────────────────────────────
// Option A — container user-namespace uid/gid mapping (spike recommendation #1)
// ──────────────────────────────────────────────────────────────────────────────

/// Exclusive upper bound of the mapped id range. The kernel treats
/// `(uid_t)-1` == 4294967295 as the "invalid"/overflow id, so a full identity
/// map is conventionally `0 0 4294967295` — covering ids `0..=4294967294`. Our
/// transposition keeps that coverage so any id an image uses (root, the USER,
/// service accounts, `nobody`) stays mapped and never appears as overflow.
pub const USERNS_RANGE_END: u32 = u32::MAX; // 4294967295, exclusive

/// Build the container's user-namespace id map for **Option A** (single-uid
/// arithmetic, VMM-independent — the spike's recommended primary strategy).
///
/// izba's virtiofsd runs **unprivileged** (as the host user) and applies **no**
/// uid translation, so the guest sees workspace files owned by the host uid
/// that owns them, and every container write squashes back to that host uid on
/// disk regardless of the in-guest uid. The container user namespace therefore
/// exists to make ownership *correct and writable inside the guest*, not to pick
/// the on-disk owner (that is always the host user).
///
/// The map is the **identity** over the full id range **except it transposes**
/// the workload id (`workload_id`, the image `USER`'s uid/gid — 0 when the image
/// declares no USER) with the workspace-owner id (`owner_id`, the host uid/gid
/// that owns the virtiofs `workspace`). This single swap delivers the whole UX:
///
/// - Workspace files (seen in-guest as `owner_id`) map to container `workload_id`
///   → the image's USER **owns** `/workspace` and can write it, whatever the host
///   uid happens to be.
/// - Image-root files (host id 0) keep mapping to container 0 whenever the
///   workload is non-root (`workload_id != 0`), so **setuid binaries like `sudo`
///   still work** and passwordless-sudo-to-root is seamless.
/// - When the workload *is* root (`workload_id == 0`, izba's default interactive
///   sandbox), container-root maps to the workspace owner so root owns
///   `/workspace`; image-root files then read as a non-root id, but the binaries
///   are world-rx and the workload is already root, so nothing breaks.
/// - When `workload_id == owner_id` (e.g. host uid 1000 running an image whose
///   USER is uid 1000) the map degenerates to pure identity.
/// - When `owner_id == 0` (the Windows OpenVMM anchor — shares present as
///   guest-0 mode 0777 — or a root-owned Linux workspace) the map is ALSO
///   identity: transposing 0↔workload would scramble every root-owned image
///   file for nothing (see the in-function comment).
///
/// The returned extents are a bijection over `0..USERNS_RANGE_END` with no
/// overlapping host ranges (the kernel rejects overlaps), using at most five
/// extents (well under the kernel's 340-extent limit). The guest init is real
/// root in the initial (full-range) user namespace, so crun can write any of
/// these extents directly.
pub fn transpose_identity_map(
    workload_id: u32,
    owner_id: u32,
) -> Vec<oci_spec::runtime::LinuxIdMapping> {
    use oci_spec::runtime::LinuxIdMappingBuilder;
    // Build one extent; `size == 0` extents are skipped (an empty span).
    let extent = |container: u32, host: u32, size: u32| {
        LinuxIdMappingBuilder::default()
            .container_id(container)
            .host_id(host)
            .size(size)
            .build()
            .expect("LinuxIdMapping build is infallible for u32 fields")
    };

    // workload == owner ⇒ the swap is a no-op ⇒ a single full-range identity map.
    //
    // owner == 0 (workload non-root) ⇒ ALSO identity. A zero owner anchor means
    // the guest-visible workspace owner is root: the Windows OpenVMM virtiofs
    // backend (which presents every share as guest-0 with mode 0777), or a
    // root-owned Linux workspace (`sudo izba`). Transposing 0↔workload there
    // scrambles every root-owned image file — setuid `sudo` becomes owned by
    // the workload uid and the workload's own $HOME becomes root's (the
    // claude-code-on-Windows breakage) — while buying nothing: on Windows the
    // 0777 share mode already grants the workload write access, and on a
    // root-owned Linux workspace the honest answer is that root's files are
    // not the workload's to own.
    if workload_id == owner_id || owner_id == 0 {
        return vec![extent(0, 0, USERNS_RANGE_END)];
    }

    let (lo, hi) = (workload_id.min(owner_id), workload_id.max(owner_id));
    let mut maps = Vec::with_capacity(5);
    // [0, lo): identity.
    if lo > 0 {
        maps.push(extent(0, 0, lo));
    }
    // lo -> hi  (the transposition's first half).
    maps.push(extent(lo, hi, 1));
    // (lo, hi): identity.
    if hi - lo > 1 {
        maps.push(extent(lo + 1, lo + 1, hi - lo - 1));
    }
    // hi -> lo  (the transposition's second half; consumes host id `lo` once).
    maps.push(extent(hi, lo, 1));
    // (hi, USERNS_RANGE_END): identity (skip when hi is the last mapped id).
    if hi < USERNS_RANGE_END - 1 {
        maps.push(extent(hi + 1, hi + 1, USERNS_RANGE_END - (hi + 1)));
    }
    maps
}

/// Compute the container user-namespace `(uidMappings, gidMappings)` for
/// Option A from the workspace-owner ids and the workload (image `USER`) ids.
/// Thin wrapper over [`transpose_identity_map`] applied to uid and gid.
///
/// `owner` is `(host_uid, host_gid)` owning the virtiofs `workspace`; `workload`
/// is the resolved image-`USER` `(uid, gid)` (see [`resolve_process_user`]).
pub fn compute_userns_mappings(
    owner: (u32, u32),
    workload: (u32, u32),
) -> (
    Vec<oci_spec::runtime::LinuxIdMapping>,
    Vec<oci_spec::runtime::LinuxIdMapping>,
) {
    (
        transpose_identity_map(workload.0, owner.0),
        transpose_identity_map(workload.1, owner.1),
    )
}

/// True iff `mappings` map container id 0 to guest (host) id 0 — i.e. the
/// container's root IS the guest's real root. Because a userns map's extents
/// are non-overlapping and 0 is the minimum id, the extent covering container
/// id 0 always starts at `container_id == 0` and maps it linearly to its
/// `host_id`; so this is exactly "some extent has container_id 0 and host_id 0".
fn maps_root_to_host_root(mappings: &[oci_spec::runtime::LinuxIdMapping]) -> bool {
    mappings
        .iter()
        .any(|m| m.container_id() == 0 && m.host_id() == 0)
}

/// Docker mode's **durable** container→guest-root barrier (spec §3, the
/// rootless-container invariant). Returns `true` when the container user
/// namespace maps container-root to a **non-zero** guest id for BOTH uid and
/// gid — the property that actually contains a `CAP_SYS_ADMIN`-holding
/// workload, exactly as rootless Docker/Podman rely on.
///
/// Why this, and not the `/proc/sys` read-only binds: those binds are
/// defense-in-depth only. A docker-mode workload holds userns `CAP_SYS_ADMIN`
/// (dockerd needs it) and seccomp is off, so it can `mount -o remount,rw` any
/// bind izba installed in its own mount namespace — crun creates them after the
/// userns, so they are not `MNT_LOCKED` (verified on a real VM, Task 7).
/// What it CANNOT change is the id map. A sysctl write goes through
/// `sysctl_perm`/`test_perm`, a plain `current_euid() == GLOBAL_ROOT_UID` DAC
/// check against the 0644 file owned by guest-uid-0: when container-root maps
/// to a NON-zero guest id, the acting euid is not guest-0 and the write is
/// denied. `CAP_DAC_OVERRIDE` cannot rescue it either, because
/// `capable_wrt_inode_uidgid` (torvalds/linux `23adbe12`) additionally requires
/// the file's owner uid to be MAPPED into the acting userns. The
/// [`docker_shifted_map`] leaves guest-uid-0 entirely unmapped, so the write is
/// denied **regardless of any remount**. This is the same design as rootless
/// containers (rootlesscontaine.rs, docker.com/engine/security/rootless).
///
/// The shifted map satisfies this **by construction** (container-0 → `BASE` or
/// → the non-zero owner), so since the shifted-map change this is a regression
/// TRIPWIRE over the actual mappings — asserted by [`generate_spec`] — rather
/// than a user-facing fail-closed gate. (The old transpose could violate it,
/// which is why non-root-`USER` images used to be refused in docker mode.)
pub fn docker_userns_isolates_root(
    uid_maps: &[oci_spec::runtime::LinuxIdMapping],
    gid_maps: &[oci_spec::runtime::LinuxIdMapping],
) -> bool {
    !maps_root_to_host_root(uid_maps) && !maps_root_to_host_root(gid_maps)
}

// ──────────────────────────────────────────────────────────────────────────────
// Docker mode — shifted userns map + idmapped layers (uid-fidelity design)
// ──────────────────────────────────────────────────────────────────────────────

/// Number of ids the docker-mode map covers, starting at container id 0.
/// 2^20 comfortably covers real-world image uids (system accounts, `nobody`,
/// the occasional 100000-range rpm ghost) while keeping the guest window far
/// below any plausible collision.
pub const DOCKER_IDMAP_RANGE: u32 = 1 << 20;

/// Default first guest id of the shifted window (`container 0 → guest BASE`).
/// Bumped by one RANGE when the workspace-owner id happens to fall inside the
/// window (see [`docker_shifted_map`]).
pub const DOCKER_IDMAP_BASE: u32 = 1 << 21;

/// Build the docker-mode container id map — the rootless-container playbook
/// (uid-fidelity design §2.1). One function `guest_of(c)` shapes BOTH this
/// userns map and the layer idmap izba-init applies to the erofs/ext4 layers
/// (delivered via `izba.uidmap=`/`izba.gidmap=`, same extents):
///
/// - `guest_of(c) = BASE + c` for `c ∈ [0, RANGE)`, **except**
/// - `guest_of(workload) = owner` iff `owner != 0` — the workspace carve-out
///   that keeps the image `USER` owning the virtiofs `/workspace` (whose
///   guest-visible owner is `owner`, and whose FUSE driver forces
///   `default_permissions`, so ownership is what grants the write).
///
/// With the layers idmapped by the same function, a file stored with image
/// uid `D` presents in-container as `D` again — verbatim image ownership —
/// while guest-0 stays **unmapped** (the F-32 barrier, strictly stronger than
/// the old transpose which mapped guest-0 to the workload id).
///
/// `owner == 0` (the Windows anchor, or a root-owned workspace) ⇒ **no
/// carve-out**: mapping any container id to guest-0 would hand the workload
/// guest-root's euid for the sysctl DAC check. The Windows share is 0777, so
/// writability survives without ownership.
pub fn docker_shifted_map(
    workload_id: u32,
    owner_id: u32,
) -> Result<Vec<oci_spec::runtime::LinuxIdMapping>> {
    use oci_spec::runtime::LinuxIdMappingBuilder;
    anyhow::ensure!(
        workload_id < DOCKER_IDMAP_RANGE,
        "docker mode: the image USER id {workload_id} is outside the mapped id range \
         (0..{DOCKER_IDMAP_RANGE}); such an image cannot run in docker mode"
    );
    let extent = |container: u32, host: u32, size: u32| {
        LinuxIdMappingBuilder::default()
            .container_id(container)
            .host_id(host)
            .size(size)
            .build()
            .expect("LinuxIdMapping build is infallible for u32 fields")
    };
    // Keep the guest window clear of the owner id so the carve-out extent can
    // never overlap the shift extents (the kernel rejects overlapping maps).
    // The two candidate windows are disjoint, so the owner is inside at most
    // one of them.
    let base = if (DOCKER_IDMAP_BASE..DOCKER_IDMAP_BASE + DOCKER_IDMAP_RANGE).contains(&owner_id) {
        DOCKER_IDMAP_BASE + DOCKER_IDMAP_RANGE
    } else {
        DOCKER_IDMAP_BASE
    };
    if owner_id == 0 {
        return Ok(vec![extent(0, base, DOCKER_IDMAP_RANGE)]);
    }
    let mut maps = Vec::with_capacity(3);
    if workload_id > 0 {
        maps.push(extent(0, base, workload_id));
    }
    maps.push(extent(workload_id, owner_id, 1));
    if workload_id < DOCKER_IDMAP_RANGE - 1 {
        maps.push(extent(
            workload_id + 1,
            base + workload_id + 1,
            DOCKER_IDMAP_RANGE - workload_id - 1,
        ));
    }
    Ok(maps)
}

/// Docker-mode `(uidMappings, gidMappings)` — [`docker_shifted_map`] applied
/// to the uid and gid dimensions independently (same shape as
/// [`compute_userns_mappings`] for the transpose).
pub fn compute_docker_userns_mappings(
    owner: (u32, u32),
    workload: (u32, u32),
) -> Result<(
    Vec<oci_spec::runtime::LinuxIdMapping>,
    Vec<oci_spec::runtime::LinuxIdMapping>,
)> {
    Ok((
        docker_shifted_map(workload.0, owner.0)?,
        docker_shifted_map(workload.1, owner.1)?,
    ))
}

/// Disk id that fsuid-0 writers land on through the idmapped layers — the
/// [`layer_idmap_cmdline_value`] anchor extent (`disk RANGE → presented 0`).
///
/// Kernel background: a write through an idmapped mount reverse-maps the
/// writer's fsuid; a fsuid with NO reverse mapping fails `EOVERFLOW`. Guest
/// fsuid-0 writers are unavoidable — overlayfs creates whiteouts/copy-ups
/// with the MOUNTER's creds (izba-init, fsuid 0), and crun mkdirs missing
/// mount targets — so the layer map must give presented-0 a disk id. It is
/// `DOCKER_IDMAP_RANGE` itself: one past every image uid the map covers, so
/// it collides with nothing and such files present in-container as `nobody`
/// (guest-0 is unmapped in the container userns — F-32). izba-init's OWN
/// writes (resolv.conf, trust CA, `izba cp`) instead run under
/// `setfsuid(presented-of-disk-0)` so they land as disk-0 = container-root.
pub const DOCKER_IDMAP_FSUID0_DISK_ID: u32 = DOCKER_IDMAP_RANGE;

/// Serialize a container userns map as the **layer idmap** `izba.uidmap=`/
/// `izba.gidmap=` kernel-cmdline value: comma-separated `disk-presented-size`
/// triples, plus the fsuid-0 anchor extent
/// (see [`DOCKER_IDMAP_FSUID0_DISK_ID`]).
///
/// Orientation (VERIFIED on a real VM — an inverted first cut presented
/// every image-root file as `nobody`): an idmapped mount computes
/// `presented = make_kuid(mnt_userns, disk_uid)`, i.e. the DISK uid is the
/// namespace-INNER id and the presented uid is the OUTER id, so a userns
/// `uid_map` line reads `<disk> <presented> <n>`. The OCI userns extent
/// `(container, guest, n)` has disk==container==image-uid and
/// presented==guest, which makes the layer triples the OCI extents
/// **verbatim** — same columns, no swap. Host-authoritative, same
/// channel-shape as `izba.volumes`; parsed by izba-init's `idmap.rs` and
/// written verbatim as the layer-idmap userns map lines.
pub fn layer_idmap_cmdline_value(userns_map: &[oci_spec::runtime::LinuxIdMapping]) -> String {
    userns_map
        .iter()
        .map(|m| format!("{}-{}-{}", m.container_id(), m.host_id(), m.size()))
        .chain(std::iter::once(format!(
            "{DOCKER_IDMAP_FSUID0_DISK_ID}-0-1"
        )))
        .collect::<Vec<_>>()
        .join(",")
}

/// Whether the workspace virtiofs share needs a guest-side idmapped mount in
/// docker mode (`izba.wsidmap=1`).
///
/// The share presents its files with the HOST owner's ids (virtiofsd
/// passthrough on Linux; guest-0 on OpenVMM, whose stub `workspace_owner()`
/// reports `(0, 0)`). When an owner leg is non-zero the shifted map's owner
/// carve-out already presents `/workspace` as the workload USER in-container
/// — the common Linux case, no idmap needed. When a leg is 0, guest-0 is
/// deliberately UNMAPPED (F-32: the rootless invariant), so the share would
/// list as `nobody`/`nogroup` and be writable only through the 0777 mode
/// bits. For exactly that case izba-init stacks an idmapped mount over the
/// share using the SAME layer extents as `/lower`/`/upper`, which presents
/// disk-0 as container-root and gives every mapped container id a write-through
/// reverse mapping. Fail-soft in the guest: a virtiofs backend that does not
/// advertise `FUSE_ALLOW_IDMAP` (OpenVMM today) rejects the idmap and init
/// keeps the un-idmapped share (the documented §6 cosmetic) rather than
/// failing the boot.
pub fn workspace_idmap_needed(host_owner: (u32, u32)) -> bool {
    host_owner.0 == 0 || host_owner.1 == 0
}

/// Render the 6 canonical CA-bundle env pairs as `"KEY=VALUE"` strings for
/// the OCI spec's process environment.
///
/// Keep in sync with `izba-init trust.rs::trust_env_pairs()`:
/// - `NODE_EXTRA_CA_CERTS`/`DENO_CERT` → `/etc/izba/ca.pem` (add to built-in roots)
/// - `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`/`GIT_SSL_CAINFO`
///   → `/etc/izba/ca-bundle.pem` (replace trust set, so must include system roots)
///
/// `izba-core` cannot depend on `izba-init`, so the pairs are duplicated here.
pub fn trust_env_strings() -> Vec<String> {
    const CA_PEM: &str = "/etc/izba/ca.pem";
    const CA_BUNDLE: &str = "/etc/izba/ca-bundle.pem";
    [
        ("NODE_EXTRA_CA_CERTS", CA_PEM),
        ("DENO_CERT", CA_PEM),
        ("SSL_CERT_FILE", CA_BUNDLE),
        ("REQUESTS_CA_BUNDLE", CA_BUNDLE),
        ("CURL_CA_BUNDLE", CA_BUNDLE),
        ("GIT_SSL_CAINFO", CA_BUNDLE),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={v}"))
    .collect()
}

/// Which process runs as the container's PID 1 (decision **D4**).
pub enum ContainerMode<'a> {
    /// Interactive dev sandbox (izba's default): a pause process holds the
    /// container's namespaces open as PID 1; the user's shell arrives later via
    /// `crun exec`. The image `Entrypoint`/`Cmd` are **not** run — this
    /// preserves today's boot-to-idle-then-`exec` UX (a bare image whose CMD is
    /// a shell would otherwise read EOF and exit, killing the sandbox).
    /// `pause_argv` is the argv of the vendored pause binary (bind-mounted into
    /// the container by the caller).
    Interactive { pause_argv: &'a [String] },
    /// Service member: the image entrypoint/cmd (merged with overrides) run as
    /// PID 1; its death is honest-unhealthy (no auto-restart).
    Service,
}

/// Inputs for [`generate_spec`]. Borrows so the generator stays a pure
/// transform with no ownership of izba's sandbox state.
pub struct SpecParams<'a> {
    /// PID-1 mode for the container (interactive pause vs image entrypoint).
    pub mode: ContainerMode<'a>,
    /// The image's runtime config (`oci_client`), if any was captured.
    pub image: Option<&'a Config>,
    /// `--entrypoint` override (Service mode): `None` = not passed; see
    /// [`resolve_process_args`]. Ignored in Interactive mode.
    pub entrypoint_override: Option<&'a [String]>,
    /// Positional command override (Service mode; `None` = none given).
    pub cmd_override: Option<&'a [String]>,
    /// `-e` user env overrides (last-wins).
    pub env_overrides: &'a [String],
    /// izba trust-env defaults; empty when the CA gate is closed (caller's job).
    pub trust_env: &'a [String],
    /// Working-dir override; else image WD (Service) / [`INTERACTIVE_CWD`].
    pub cwd_override: Option<&'a str>,
    /// Already-resolved process user `(uid, gid)` (see [`UserDb::resolve`]).
    pub user: (u32, u32),
    /// The host `(uid, gid)` that owns the virtiofs `workspace` share — the
    /// anchor of the Option A user-namespace transposition (see
    /// [`compute_userns_mappings`]). Workspace files are seen in-guest as this
    /// owner; the container userns maps it to the workload's [`SpecParams::user`]
    /// so the image USER owns `/workspace`.
    pub host_owner: (u32, u32),
    /// Guest hostname (the sandbox name).
    pub hostname: &'a str,
    /// Allocate a terminal for the container process (interactive shells).
    pub terminal: bool,
    /// Builder/privileged mode — full capabilities and NO user namespace, for
    /// rootful buildkit-in-VM. The VM is the boundary. When true, the container
    /// gets every capability ([`all_caps`], incl. `CAP_SYS_ADMIN` for buildkit's
    /// overlayfs bind/overlay mounts) and the Option-A user namespace + uid/gid
    /// mappings are skipped so container-root == guest-root (real root, which
    /// rootful buildkit requires). The network namespace is still dropped (D1).
    /// Normal (non-builder) sandboxes leave this `false` and are UNCHANGED.
    pub privileged: bool,
    /// This sandbox holds USB device grants, so the workload gets a
    /// [`USB_SHARED_DIR`] bind at `/dev/izba` and permission to open the serial
    /// char majors. False for every sandbox without grants, which then has no
    /// device directory and no device allowances at all.
    pub usb: bool,
    /// Docker mode (spec §2-§3): fresh userns-owned network namespace instead
    /// of sharing init's, the docker-mode capability set, and the rw cgroupfs
    /// treatment.
    ///
    /// Mutually exclusive with `privileged` — this is a CALLER-SIDE invariant
    /// `generate_spec` ASSUMES rather than one it enforces or makes safe. The
    /// caps `if/else` below picks `privileged`'s `all_caps()` before ever
    /// looking at `docker`, but the netns block further down is gated on
    /// `docker` independently of that same `if/else`; a caller that violates
    /// the invariant (both `true`) would therefore get `all_caps()` (incl.
    /// `CAP_SYS_ADMIN`) PLUS a fresh container-owned network namespace and no
    /// user namespace — strictly MORE dangerous than either mode alone, not a
    /// safe fallback. Callers (`sandbox.rs`) must guarantee exclusivity
    /// themselves; see `docker: config.docker && !config.builder` there.
    pub docker: bool,
    /// Supplementary gids for the container process user (the image USER's
    /// /etc/group memberships — e.g. `docker`). Empty when none resolve.
    pub additional_gids: &'a [u32],
    /// This sandbox has a VNC display enabled: bind the KasmVNC bundle
    /// ([`VNC_BUNDLE_SHARED_DIR`]) and its `xkbcomp` binary
    /// (hardcoded server path, see [`add_vnc_mounts`]) and secrets
    /// ([`VNC_SECRETS_SHARED_DIR`]) into the container, and grow `/dev/shm`
    /// to [`DEV_SHM_VNC_SIZE`] (the X server + browser client both need real
    /// shared-memory headroom). False for every sandbox without a display,
    /// which then gets none of these mounts and the stock 64M `/dev/shm`.
    pub vnc: bool,
}

/// Guest path izba-init mirrors attached device nodes into, bind-mounted to
/// `/dev/izba` in the container.
///
/// It lives in init-root `/run`, OUTSIDE the `/rootfs` overlay — mirroring how
/// the ssh material is kept out of the OCI image — and izba-init creates it
/// before crun starts, because a bind mount needs its source to exist. It is a
/// *directory* bind rather than per-device binds because attach happens long
/// after the container starts: new files inside a bind mount are visible
/// immediately (same superblock), new mounts would not be.
///
/// Must stay in step with `izba_init::usb::SHARED_DEV_DIR`.
pub const USB_SHARED_DIR: &str = "/run/izba/usb";

/// Where the shared directory appears inside the container.
pub const USB_CONTAINER_DIR: &str = "/dev/izba";

/// Char-device majors izba will let a workload open: 166 (CDC-ACM, `ttyACM*`)
/// and 188 (USB serial, `ttyUSB*`).
///
/// v1 is serial-class only (design D5), and encoding that as a cgroup device
/// rule makes it structural rather than a naming convention: a node of any
/// other class that somehow reached `/dev/izba` still cannot be opened. It is
/// the same restriction the guest applies when it decides which node to mirror,
/// enforced independently on the other side.
const SERIAL_MAJORS: [i64; 2] = [166, 188];

/// Host-mirrored guest path holding the vendored KasmVNC bundle (X server,
/// window manager, VNC/websockify, and the `xkbcomp` binary at
/// `bin/xkbcomp` — see [`add_vnc_mounts`]), bind-mounted read-only into the
/// container at [`VNC_BUNDLE_CONTAINER_DIR`].
///
/// Lives in init-root `/run`, OUTSIDE the `/rootfs` overlay — mirroring the
/// USB and ssh material — so the VNC bundle is never part of the OCI image
/// and can't be shadowed by anything the workload writes.
pub const VNC_BUNDLE_SHARED_DIR: &str = "/run/izba/vnc";

/// Where the VNC bundle appears inside the container.
pub const VNC_BUNDLE_CONTAINER_DIR: &str = "/opt/izba-vnc";

/// Host-mirrored guest path holding VNC session secrets (password, TLS
/// material), bind-mounted read-only into the container. Source and
/// destination are the same path by convention (mirrors how the guest's own
/// tooling expects to find it), so container tooling needs no izba-specific
/// path translation.
pub const VNC_SECRETS_SHARED_DIR: &str = "/run/izba/vnc-secrets";

/// Container-side mount point for the VNC secrets — identical to
/// [`VNC_SECRETS_SHARED_DIR`] (see its doc comment).
pub const VNC_SECRETS_CONTAINER_DIR: &str = "/run/izba/vnc-secrets";

/// `/dev/shm` size for a VNC-enabled sandbox, replacing the OCI default
/// spec's stock `size=65536k` (64 MiB). The X server and the browser-based
/// VNC client both keep real shared-memory segments (framebuffer/SHM
/// extension), and 64 MiB is too tight for a modern desktop session — 512
/// MiB gives real headroom.
pub const DEV_SHM_VNC_SIZE: &str = "size=524288k";

/// Generate the OCI runtime [`Spec`] for the guest's single workload container.
///
/// Starts from the standard rootful Linux spec ([`Spec::default`] — standard
/// mounts + namespaces) and applies izba's policy: process argv/env/cwd/user
/// from the docker-faithful merges, rootfs at [`CONTAINER_ROOTFS`], and — the
/// load-bearing decision **D1** — drops the network namespace so the container
/// shares izba-init's netns (egress/port-relay/ssh all live there).
pub fn generate_spec(params: &SpecParams) -> Result<Spec> {
    let cfg = params.image;
    let image_ep: Vec<String> = cfg.and_then(|c| c.entrypoint.clone()).unwrap_or_default();
    let image_cmd: Vec<String> = cfg.and_then(|c| c.cmd.clone()).unwrap_or_default();
    let image_env: Vec<String> = cfg.and_then(|c| c.env.clone()).unwrap_or_default();
    let image_wd: Option<String> = cfg.and_then(|c| c.working_dir.clone());

    let (args, cwd) = match params.mode {
        ContainerMode::Interactive { pause_argv } => {
            // Image entrypoint/cmd are NOT run; the pause holds the namespaces.
            (
                pause_argv.to_vec(),
                params.cwd_override.unwrap_or(INTERACTIVE_CWD).to_string(),
            )
        }
        ContainerMode::Service => (
            resolve_process_args(
                &image_ep,
                &image_cmd,
                params.entrypoint_override,
                params.cmd_override,
            )?,
            resolve_cwd(image_wd.as_deref(), params.cwd_override),
        ),
    };
    let env = merge_env(&image_env, params.trust_env, params.env_overrides);

    let mut user_builder = UserBuilder::default().uid(params.user.0).gid(params.user.1);
    if !params.additional_gids.is_empty() {
        user_builder = user_builder.additional_gids(params.additional_gids.to_vec());
    }
    let user = user_builder.build()?;
    // Privileged builder VMs get the full capability set (rootful buildkit needs
    // CAP_SYS_ADMIN for its overlayfs bind/overlay mounts); docker-mode sandboxes
    // get the docker-default set plus the userns-scoped admin caps a nested
    // dockerd + runc need ([`docker_mode_caps`]); normal sandboxes get the
    // least-privilege docker-default set. `privileged` is checked first, but
    // that ordering is NOT what keeps `privileged && docker` safe — see
    // [`SpecParams::docker`] for why that combination (a caller-side invariant
    // this function assumes, never enforces) is strictly more dangerous than
    // either mode alone, not a safe fallback.
    let caps = if params.privileged {
        all_caps()?
    } else if params.docker {
        docker_mode_caps()?
    } else {
        docker_default_caps()?
    };
    let process = ProcessBuilder::default()
        .terminal(params.terminal)
        .args(args)
        .env(env)
        .cwd(cwd)
        .user(user)
        .capabilities(caps)
        .build()?;
    let root = RootBuilder::default()
        .path(CONTAINER_ROOTFS)
        .readonly(false)
        .build()?;

    // Start from the standard rootful Linux spec (default mounts + namespaces),
    // then apply izba policy on top.
    let mut spec = Spec::default();
    spec.set_process(Some(process));
    spec.set_root(Some(root));
    spec.set_hostname(Some(params.hostname.to_string()));

    // D1: the container shares izba-init's network namespace — drop `network`
    // from the namespace set so crun does not unshare a fresh (routeless) one.
    //
    // EXCEPTION (docker mode, spec §3): a nested dockerd needs its OWN network
    // namespace to run its bridge/NAT plumbing without fighting init's egress
    // stub for the same netns, so docker-mode sandboxes keep the default
    // (pathless) `network` namespace entry instead of dropping it — crun then
    // creates a fresh one that the nested dockerd owns exclusively.
    //
    // Option A: add a `user` namespace and the uid/gid transposition so the
    // image USER owns the host-owned virtiofs `/workspace` (and image-root files
    // keep mapping to container-root, so setuid `sudo` works). VMM-independent —
    // the same guest-userns mechanism normalizes ownership on both the
    // virtiofsd (Linux) and OpenVMM (Windows) backends, which both present host
    // uids untranslated.
    //
    // Privileged builder VMs (`params.privileged`) SKIP the user namespace and
    // its uid/gid mappings entirely: rootful buildkit requires real container-
    // root == guest-root (no userns), and the throwaway builder VM is itself the
    // boundary. The network namespace is still dropped (D1 applies to builders
    // too — they share init's netns for gated egress).
    if let Some(linux) = spec.linux_mut().as_mut() {
        if let Some(mut nss) = linux.namespaces().clone() {
            // Docker mode keeps the default set's `network` entry (see the D1
            // EXCEPTION above); every other mode drops it.
            if !params.docker {
                nss.retain(|n| n.typ() != LinuxNamespaceType::Network);
            }
            if !params.privileged && !nss.iter().any(|n| n.typ() == LinuxNamespaceType::User) {
                // Idempotent: only add the user namespace if the default set lacks it.
                nss.push(
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::User)
                        .build()?,
                );
            }
            linux.set_namespaces(Some(nss));
        }
        if !params.privileged {
            let (uid_maps, gid_maps) = if params.docker {
                // Docker mode (uid-fidelity design §2): the shifted map. The
                // matching layer idmap (same extents, applied by izba-init to
                // the erofs/ext4 layers via izba.uidmap=/izba.gidmap=) is what
                // makes image uids present verbatim in-container; this userns
                // half is what keeps guest-root unmapped — the F-32 barrier,
                // now satisfied for EVERY (owner, USER) shape, so the old
                // fail-closed refusal of non-root-USER images is gone.
                let (u, g) = compute_docker_userns_mappings(params.host_owner, params.user)?;
                // Regression tripwire, never a user-facing gate: the shifted
                // map isolates container-root by construction.
                debug_assert!(
                    docker_userns_isolates_root(&u, &g),
                    "docker_shifted_map must never map container-root to guest-root"
                );
                (u, g)
            } else {
                compute_userns_mappings(params.host_owner, params.user)
            };
            linux.set_uid_mappings(Some(uid_maps));
            linux.set_gid_mappings(Some(gid_maps));
        }
    }

    // Present `/sys` as a recursive bind of the host `/sys`, not a fresh `sysfs`
    // mount. The container runs in the Option-A user namespace (above) while
    // still SHARING izba-init's network namespace (D1, `network` dropped —
    // except docker mode, which owns a fresh netns of its own; the bind stays
    // correct there too since a recursive bind needs no netns ownership). The
    // Linux kernel refuses to mount a NEW `sysfs` instance from a user namespace
    // that does not OWN the network namespace that sysfs would expose, so crun's
    // default `type:sysfs` `/sys` mount fails with `mount sysfs: Operation not
    // permitted`. crun ships a sysfs->/sys bind fallback, but it is conditional
    // (read-only mount, in-userns probe) and VMM-dependent — it rescues the
    // CH/virtiofsd guest yet NOT the OpenVMM/WHP guest, where every container
    // then fails to start. Authoring the bind ourselves makes container start
    // deterministic on every backend: a recursive bind of an already-visible
    // mount needs no netns ownership. This is the canonical rootless /
    // `--net=host`+userns layout (cf. oci-spec `get_rootless_mounts`, runc,
    // podman); `/sys/fs/cgroup` stays a separate mount that crun layers on top.
    rebind_sys_mount(&mut spec);

    // USB passthrough: give the workload somewhere for attached devices to
    // appear, and permission to open them. Both halves are skipped entirely for
    // a sandbox without grants — no directory, no device rules.
    if params.usb {
        add_usb_device_access(&mut spec)?;
    }

    // VNC display: bind in the vendored bundle + secrets, and grow
    // /dev/shm for the X server and browser VNC client. Both halves are
    // skipped entirely for a sandbox without a display — no bundle, no
    // secrets, no bigger /dev/shm.
    if params.vnc {
        add_vnc_mounts(&mut spec)?;
        resize_dev_shm(&mut spec);
    }

    // Privileged builders AND docker-mode sandboxes: mount `/sys/fs/cgroup`
    // read-WRITE. The OCI default mounts cgroupfs read-only, but both
    // consumers run a nested runc that must create its own cgroup subtree
    // (`mkdir /sys/fs/cgroup/<id>`) — rootful BuildKit's OCI worker for the
    // former, dockerd's own containerd-shim+runc for the latter — and
    // read-only cgroupfs fails that with "unable to apply cgroup
    // configuration: ... read-only file system". The throwaway builder VM is
    // the trust boundary for `privileged`; the userns-scoped `docker` caps
    // ([`docker_mode_caps`]) are the equivalent boundary here. Normal
    // sandboxes keep the read-only default.
    if params.privileged || params.docker {
        if let Some(mounts) = spec.mounts_mut().as_mut() {
            for m in mounts.iter_mut() {
                if m.destination().to_string_lossy() == "/sys/fs/cgroup" {
                    // Drop any `ro`, then guarantee `rw` is present.
                    let mut opts: Vec<String> = m
                        .options()
                        .clone()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|o| o != "ro")
                        .collect();
                    if !opts.iter().any(|o| o == "rw") {
                        opts.push("rw".to_string());
                    }
                    m.set_options(Some(opts));
                }
            }
        }
    }

    // Docker mode only: narrow the OCI default `/proc/sys` read-only remount
    // down to its non-`net` children (see [`DOCKER_READONLY_PROC_SYS`]).
    //
    // dockerd cannot create its default `bridge` network without writing
    // `/proc/sys/net/ipv4/ip_forward` (plus a handful of per-interface
    // `net.ipv6.*` knobs). The OCI default read-only-remounts ALL of
    // `/proc/sys`, so on a real boot dockerd died at startup with
    //   failed to start daemon: Error initializing network controller: ...
    //   failed to set IP forwarding '/proc/sys/net/ipv4/ip_forward' = '1':
    //   open ...: read-only file system
    // (observed in Task 7's first green-veth boot). Docker's own dind image
    // solves this with `--privileged`, which clears readonlyPaths AND
    // maskedPaths AND all capability limits; izba unlocks exactly one sysctl
    // subtree, and only for docker-mode sandboxes.
    //
    // **Why the whole subtree is NOT unlocked, and what actually enforces it.**
    // `net.*` writes are gated by the kernel on the owning user namespace
    // (`net_ctl_permissions` ⇒ `ns_capable(net->user_ns, CAP_NET_ADMIN)`), and
    // this netns belongs to the container's userns (spec §3) — so those writes
    // are legitimately the container's own. Keeping the OTHER `/proc/sys`
    // children read-only is **defense-in-depth, NOT the durable barrier**: a
    // docker-mode workload holds userns `CAP_SYS_ADMIN` (dockerd needs it) with
    // seccomp off, and these binds live in the container's own mount namespace,
    // so it can `mount -o remount,rw` them (crun does not `MNT_LOCK` mounts it
    // creates after the userns — proven on a real VM, Task 7 [5c]). Narrowing
    // the list therefore only shrinks the attack surface; it does not close it.
    //
    // The DURABLE barrier is the container-0 ≠ guest-0 uid invariant enforced at
    // the top of this function ([`docker_userns_isolates_root`]): a non-`net`
    // sysctl write (file owned by guest-uid-0) is gated by `test_perm`'s plain
    // euid==guest-0 check, with `capable_wrt_inode_uidgid` blocking any
    // `CAP_DAC_OVERRIDE` bypass while the owner uid stays unmapped — so a
    // workload whose container-root maps to a NON-zero guest id is denied the
    // write even after it remounts the path rw — exactly as in rootless
    // Docker/Podman. That is why generate_spec fails a violating docker-mode
    // start closed rather than relying on these binds.
    //
    // The other default read-only paths (`/proc/bus`, `/proc/fs`, `/proc/irq`,
    // `/proc/sysrq-trigger`) and ALL `maskedPaths` stay untouched.
    if params.docker {
        if let Some(linux) = spec.linux_mut().as_mut() {
            if let Some(mut ro) = linux.readonly_paths().clone() {
                ro.retain(|p| p != "/proc/sys");
                for child in DOCKER_READONLY_PROC_SYS {
                    if !ro.iter().any(|p| p == child) {
                        ro.push((*child).to_string());
                    }
                }
                linux.set_readonly_paths(Some(ro));
            }
        }
    }

    Ok(spec)
}

/// The `/proc/sys` children that stay read-only in docker mode: every top-level
/// sysctl subtree izba's guest kernel registers EXCEPT `net`, which dockerd
/// must write (see the `params.docker` block in [`generate_spec`]).
///
/// A path that does not exist in the guest kernel is harmless: per the OCI
/// runtime spec a runtime ignores a `readonlyPaths` entry it cannot resolve
/// (crun releases the `ENOENT` and continues), so over-listing is free while
/// UNDER-listing silently leaves a subtree writable. Erring towards
/// over-listing is therefore deliberate.
///
/// The authority is the guest kernel, not this list, and the enforcement is
/// real: `docker_mode_engine_runs_containers` phase [5b] enumerates the ACTUAL
/// `/proc/sys` in a booted docker-mode guest and fails naming any non-`net`
/// child that is not remounted read-only. That oracle is not theoretical — it
/// is what caught `sunrpc` (registered by `CONFIG_SUNRPC` in izba's kernel and
/// absent from the canonical "abi/debug/dev/fs/kernel/net/user/vm" set) on the
/// first real boot after this narrowing landed. A future kernel option adding
/// another subtree fails that test rather than slipping through.
const DOCKER_READONLY_PROC_SYS: &[&str] = &[
    "/proc/sys/abi",
    "/proc/sys/debug",
    "/proc/sys/dev",
    "/proc/sys/fs",
    "/proc/sys/kernel",
    // CONFIG_SUNRPC (the guest kernel carries NFS/SUNRPC); not part of the
    // canonical set, found by the phase-[5b] guest enumeration.
    "/proc/sys/sunrpc",
    "/proc/sys/user",
    "/proc/sys/vm",
];

/// Bind the shared device directory into the container and authorise the serial
/// char majors.
///
/// Two independent things, both required. The **bind mount** is how a node that
/// izba-init creates *after* the container started becomes visible at all: the
/// container has its own mount namespace and a fresh tmpfs `/dev` from the OCI
/// default spec, so nothing izba does to the guest's `/dev` reaches the
/// workload — but a bind mount shares the source directory's superblock, so
/// files appearing in it later show up immediately.
///
/// The **device cgroup rules** are what make the node openable. Under cgroup v2
/// crun compiles `linux.resources.devices` into an eBPF device filter, and a
/// major that is not listed is refused with `EPERM` on `open()`. Only the two
/// serial majors are listed, and only for read/write — never `m` (mknod), so
/// the workload can use a device izba attached but cannot conjure one of its
/// own.
fn add_usb_device_access(spec: &mut Spec) -> Result<()> {
    if let Some(mounts) = spec.mounts_mut().as_mut() {
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from(USB_CONTAINER_DIR))
                .typ("bind")
                .source(PathBuf::from(USB_SHARED_DIR))
                .options(vec![
                    "rbind".to_string(),
                    "rw".to_string(),
                    // A device directory has no business carrying setuid bits or
                    // executables, and the workload never needs to traverse it
                    // as code.
                    "nosuid".to_string(),
                    "noexec".to_string(),
                ])
                .build()?,
        );
    }
    if let Some(linux) = spec.linux_mut().as_mut() {
        let mut resources = linux.resources().clone().unwrap_or_default();
        let mut devices = resources.devices().clone().unwrap_or_default();
        for major in SERIAL_MAJORS {
            devices.push(
                LinuxDeviceCgroupBuilder::default()
                    .allow(true)
                    .typ(LinuxDeviceType::C)
                    .major(major)
                    .access("rw")
                    .build()?,
            );
        }
        resources.set_devices(Some(devices));
        linux.set_resources(Some(resources));
    }
    Ok(())
}

/// Bind the vendored KasmVNC bundle and its session secrets into the
/// container.
///
/// Ten binds:
/// - **Bundle** ([`VNC_BUNDLE_SHARED_DIR`] → [`VNC_BUNDLE_CONTAINER_DIR`]):
///   the whole vendored tree (X server, window manager, VNC/websockify),
///   `rbind,ro` — read-only because the workload never needs to modify its
///   own display stack, but withOUT `noexec`: the binaries inside it are
///   what actually runs.
/// - **`xkbcomp`** (`VNC_BUNDLE_SHARED_DIR/bin/xkbcomp` →
///   `/usr/bin/xkbcomp`): a single-file bind at the X server's HARDCODED
///   lookup path. The server shells out to `/usr/bin/xkbcomp` directly and
///   ignores any environment override for that path (proven in the spike),
///   so the only way to make our vendored `xkbcomp` reachable is to occupy
///   that exact guest path — the workload's own `/usr/bin` (if any) is
///   shadowed at this one file, nothing else.
/// - **`menu-cached` + `menu-cache-gen`** (`VNC_BUNDLE_SHARED_DIR/bin/…` →
///   `/usr/lib/menu-cache/…`): same class as `xkbcomp`. libmenu-cache
///   spawns its Applications-menu cache daemon from a COMPILED-IN path with
///   no environment override, and that daemon in turn spawns the generator
///   from a second one, so both vendored binaries must occupy those exact
///   guest paths. The literals are the ones baked into `libmenu-cache.so.3`
///   and `menu-cached` (Debian's `libmenu-cache-bin` layout) — **not**
///   `libexec` paths. Each half fails differently and neither failure is
///   loud: without `menu-cached`, `lxpanel` treats the missing daemon as a
///   fatal `g_error` and aborts, so the desktop has no panel at all;
///   without `menu-cache-gen` the panel is fine but its Applications menu
///   is permanently EMPTY, with nothing logged anywhere. Both were found
///   only by booting a real VM and looking.
/// - **Module + data trees** — the same hardcoded-path class once more, for
///   `dlopen` and `open` rather than `exec`. Five directories, none of them
///   overridable by any environment variable:
///   - `lib/lxpanel/plugins` → `/usr/lib/x86_64-linux-gnu/lxpanel/plugins`
///     and `lib/libfm` → `/usr/lib/x86_64-linux-gnu/libfm/modules`:
///     `liblxpanel.so.0` and `libfm.so.4` each scan a compiled-in multiarch
///     directory, so without these binds every panel plugin (the
///     Applications menu, taskbar, pager, clock) and every libfm module is
///     simply absent — the panel process lives but is empty.
///   - `share/lxpanel` → `/usr/share/lxpanel`, `share/libfm` →
///     `/usr/share/libfm`, and `share/pcmanfm` → `/usr/share/pcmanfm`: the
///     compiled-in `PACKAGE_DATA_DIR` of each app, holding its images and
///     its GtkBuilder `.ui` files. Without lxpanel's, the panel comes up
///     with a broken-image Applications button. Without libfm's and
///     pcmanfm's, the desktop right-click menu still renders but the
///     dialogs behind its entries — Desktop Preferences
///     (`pcmanfm/ui/desktop-pref.ui`), Create New, Properties, Rename
///     (`libfm/ui/*.ui`) — cannot be built, and libfm's terminal database
///     (`libfm/terminals.list`) is missing.
///
///   `ro` but never `noexec`: the module trees are shared objects that must
///   be mappable executable.
///
///   NOTE the literal `x86_64-linux-gnu` in the two module paths. Debian's
///   multiarch directory name is part of the compiled-in path, so these
///   binds are correct only for an x86_64 bundle — which is what
///   `hack/build-kasmvnc-erofs.sh` builds (it copies from
///   `/usr/lib/x86_64-linux-gnu` and vendors an x86_64 dynamic loader).
///   Porting the bundle to another architecture must change both ends.
/// - **Secrets** ([`VNC_SECRETS_SHARED_DIR`] → [`VNC_SECRETS_CONTAINER_DIR`]):
///   `rbind,ro,nosuid,noexec` — session password/TLS material, never
///   executable and never writable from inside the container.
fn add_vnc_mounts(spec: &mut Spec) -> Result<()> {
    if let Some(mounts) = spec.mounts_mut().as_mut() {
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from(VNC_BUNDLE_CONTAINER_DIR))
                .typ("bind")
                .source(PathBuf::from(VNC_BUNDLE_SHARED_DIR))
                .options(vec![
                    "rbind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    // NOT noexec: the bundle's binaries execute from here.
                ])
                .build()?,
        );
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from("/usr/bin/xkbcomp"))
                .typ("bind")
                .source(PathBuf::from(format!(
                    "{VNC_BUNDLE_SHARED_DIR}/bin/xkbcomp"
                )))
                .options(vec![
                    "bind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                ])
                .build()?,
        );
        for bin in ["menu-cached", "menu-cache-gen"] {
            mounts.push(
                MountBuilder::default()
                    .destination(PathBuf::from(format!("/usr/lib/menu-cache/{bin}")))
                    .typ("bind")
                    .source(PathBuf::from(format!("{VNC_BUNDLE_SHARED_DIR}/bin/{bin}")))
                    .options(vec![
                        "bind".to_string(),
                        "ro".to_string(),
                        "nosuid".to_string(),
                    ])
                    .build()?,
            );
        }
        for (dest, src) in [
            (
                "/usr/lib/x86_64-linux-gnu/lxpanel/plugins",
                format!("{VNC_BUNDLE_SHARED_DIR}/lib/lxpanel/plugins"),
            ),
            (
                "/usr/lib/x86_64-linux-gnu/libfm/modules",
                format!("{VNC_BUNDLE_SHARED_DIR}/lib/libfm"),
            ),
            (
                "/usr/share/lxpanel",
                format!("{VNC_BUNDLE_SHARED_DIR}/share/lxpanel"),
            ),
            (
                "/usr/share/libfm",
                format!("{VNC_BUNDLE_SHARED_DIR}/share/libfm"),
            ),
            (
                "/usr/share/pcmanfm",
                format!("{VNC_BUNDLE_SHARED_DIR}/share/pcmanfm"),
            ),
        ] {
            mounts.push(
                MountBuilder::default()
                    .destination(PathBuf::from(dest))
                    .typ("bind")
                    .source(PathBuf::from(src))
                    .options(vec![
                        "rbind".to_string(),
                        "ro".to_string(),
                        "nosuid".to_string(),
                        // NOT noexec: these trees are dlopened.
                    ])
                    .build()?,
            );
        }
        mounts.push(
            MountBuilder::default()
                .destination(PathBuf::from(VNC_SECRETS_CONTAINER_DIR))
                .typ("bind")
                .source(PathBuf::from(VNC_SECRETS_SHARED_DIR))
                .options(vec![
                    "rbind".to_string(),
                    "ro".to_string(),
                    "nosuid".to_string(),
                    "noexec".to_string(),
                ])
                .build()?,
        );
    }
    Ok(())
}

/// Grow the spec's `/dev/shm` mount to [`DEV_SHM_VNC_SIZE`], in place —
/// dropping any existing `size=…` option rather than appending a second one
/// (tmpfs only honors the last `size=` remount option it sees, so a
/// duplicate would silently mean "whichever one crun/mount parses last").
/// Idempotent and a no-op if there is no `/dev/shm` mount.
fn resize_dev_shm(spec: &mut Spec) {
    let Some(mounts) = spec.mounts_mut().as_mut() else {
        return;
    };
    let Some(shm) = mounts
        .iter_mut()
        .find(|m| m.destination().to_string_lossy() == "/dev/shm")
    else {
        return;
    };
    let mut opts: Vec<String> = shm
        .options()
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|o| !o.starts_with("size="))
        .collect();
    opts.push(DEV_SHM_VNC_SIZE.to_string());
    shm.set_options(Some(opts));
}

/// Rewrite the spec's `/sys` mount from a fresh `sysfs` mount into a recursive
/// read-only bind of the host `/sys` (see the call site in [`generate_spec`]
/// for why). Idempotent and a no-op if there is no `/sys` mount.
fn rebind_sys_mount(spec: &mut Spec) {
    let Some(mounts) = spec.mounts_mut().as_mut() else {
        return;
    };
    let Some(sys) = mounts
        .iter_mut()
        .find(|m| m.destination().to_string_lossy() == "/sys")
    else {
        return;
    };
    // A bind mount: `type:none`, `source:/sys`, with `rbind` added to the
    // existing hardening options (nosuid/noexec/nodev/ro carry over).
    sys.set_typ(Some("none".to_string()));
    sys.set_source(Some(std::path::PathBuf::from("/sys")));
    let mut opts = sys.options().clone().unwrap_or_default();
    if !opts.iter().any(|o| o == "rbind") {
        opts.push("rbind".to_string());
    }
    sys.set_options(Some(opts));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ---- Table from moby daemon/commit.go::merge + create.go ----

    #[test]
    fn no_override_concatenates_entrypoint_and_cmd() {
        let args = resolve_process_args(&v(&["/ep"]), &v(&["a", "b"]), None, None).unwrap();
        assert_eq!(args, v(&["/ep", "a", "b"]));
    }

    #[test]
    fn no_override_only_entrypoint() {
        let args = resolve_process_args(&v(&["/ep"]), &[], None, None).unwrap();
        assert_eq!(args, v(&["/ep"]));
    }

    #[test]
    fn no_override_only_cmd() {
        let args = resolve_process_args(&[], &v(&["/cmd"]), None, None).unwrap();
        assert_eq!(args, v(&["/cmd"]));
    }

    #[test]
    fn no_override_both_empty_is_error() {
        assert!(resolve_process_args(&[], &[], None, None).is_err());
    }

    #[test]
    fn cmd_override_keeps_image_entrypoint() {
        // docker run IMAGE x  (image has ENTRYPOINT /ep, CMD a) -> /ep x
        let args = resolve_process_args(&v(&["/ep"]), &v(&["a"]), None, Some(&v(&["x"]))).unwrap();
        assert_eq!(args, v(&["/ep", "x"]));
    }

    #[test]
    fn entrypoint_override_clears_image_cmd() {
        // docker run --entrypoint /new IMAGE  (image CMD a) -> /new  (NOT /new a)
        let args =
            resolve_process_args(&v(&["/ep"]), &v(&["a"]), Some(&v(&["/new"])), None).unwrap();
        assert_eq!(args, v(&["/new"]));
    }

    #[test]
    fn entrypoint_override_plus_cmd_override() {
        let args = resolve_process_args(
            &v(&["/ep"]),
            &v(&["a"]),
            Some(&v(&["/new"])),
            Some(&v(&["y"])),
        )
        .unwrap();
        assert_eq!(args, v(&["/new", "y"]));
    }

    #[test]
    fn empty_entrypoint_override_with_cmd_runs_cmd_only() {
        // docker run --entrypoint "" IMAGE z -> z  (entrypoint cleared)
        let args =
            resolve_process_args(&v(&["/ep"]), &v(&["a"]), Some(&v(&[""])), Some(&v(&["z"])))
                .unwrap();
        assert_eq!(args, v(&["z"]));
    }

    #[test]
    fn empty_entrypoint_override_without_cmd_is_error() {
        // docker run --entrypoint "" alpine  -> "no command specified"
        // (image CMD is NOT inherited because Entrypoint was non-empty at merge)
        assert!(resolve_process_args(&v(&["/ep"]), &v(&["a"]), Some(&v(&[""])), None).is_err());
    }

    // ---- env merge ----

    #[test]
    fn env_image_only_passes_through() {
        let env = merge_env(&v(&["PATH=/usr/bin", "LANG=C"]), &[], &[]);
        assert_eq!(env, v(&["PATH=/usr/bin", "LANG=C"]));
    }

    #[test]
    fn env_user_override_wins_last_and_keeps_position() {
        let env = merge_env(
            &v(&["PATH=/usr/bin", "LANG=C"]),
            &[],
            &v(&["PATH=/opt/bin"]),
        );
        assert_eq!(env, v(&["PATH=/opt/bin", "LANG=C"]));
    }

    #[test]
    fn env_new_keys_append_in_override_order() {
        let env = merge_env(&v(&["LANG=C"]), &[], &v(&["FOO=1", "BAR=2"]));
        assert_eq!(env, v(&["LANG=C", "FOO=1", "BAR=2"]));
    }

    #[test]
    fn env_trust_layers_between_image_and_user() {
        // trust-env adds CA path; a later -e of the same key still wins.
        let env = merge_env(
            &v(&["PATH=/usr/bin"]),
            &v(&["SSL_CERT_FILE=/etc/izba/ca.pem", "PATH=/trust/bin"]),
            &v(&["PATH=/opt/bin"]),
        );
        assert_eq!(env, v(&["PATH=/opt/bin", "SSL_CERT_FILE=/etc/izba/ca.pem"]));
    }

    #[test]
    fn env_entry_without_equals_treated_as_key() {
        // `-e VAR` (bare) overrides image VAR=... as the whole-string key.
        let env = merge_env(&v(&["VAR=old"]), &[], &v(&["VAR"]));
        assert_eq!(env, v(&["VAR"]));
    }

    // ---- cwd ----

    #[test]
    fn cwd_override_wins() {
        assert_eq!(resolve_cwd(Some("/img"), Some("/workspace")), "/workspace");
    }

    #[test]
    fn cwd_falls_back_to_image_working_dir() {
        assert_eq!(resolve_cwd(Some("/img"), None), "/img");
    }

    #[test]
    fn cwd_defaults_to_root() {
        assert_eq!(resolve_cwd(None, None), "/");
        assert_eq!(resolve_cwd(Some(""), None), "/");
    }

    // ---- Option A userns transposition map ----

    /// Resolve a container id to its host id through a set of extents, using u64
    /// arithmetic so a full-range extent can't overflow. `None` ⇒ unmapped.
    fn map_c2h(maps: &[oci_spec::runtime::LinuxIdMapping], cid: u32) -> Option<u32> {
        for m in maps {
            let lo = m.container_id() as u64;
            let hi = lo + m.size() as u64;
            if (cid as u64) >= lo && (cid as u64) < hi {
                return Some((m.host_id() as u64 + (cid as u64 - lo)) as u32);
            }
        }
        None
    }

    /// Assert the extents are a clean bijection over `0..USERNS_RANGE_END`: no
    /// two extents share a host id, and every container id maps to a distinct
    /// host id (spot-checked at the boundaries plus a sample). Also asserts NO
    /// zero-size extents (a relaxed `>`→`>=` guard would emit empty extents,
    /// which the kernel/crun may reject — and which would otherwise be invisible
    /// to the value assertions, since `map_c2h` skips them).
    fn assert_no_host_overlap(maps: &[oci_spec::runtime::LinuxIdMapping]) {
        for m in maps {
            assert!(
                m.size() > 0,
                "zero-size extent (container_id={}, host_id={})",
                m.container_id(),
                m.host_id()
            );
        }
        let mut ranges: Vec<(u64, u64)> = maps
            .iter()
            .map(|m| (m.host_id() as u64, m.host_id() as u64 + m.size() as u64))
            .collect();
        ranges.sort();
        for w in ranges.windows(2) {
            assert!(w[0].1 <= w[1].0, "host ranges overlap: {ranges:?}");
        }
    }

    #[test]
    fn userns_identity_when_workload_equals_owner() {
        // host uid 1000 running an image whose USER is 1000 → pure identity.
        let m = transpose_identity_map(1000, 1000);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].container_id(), 0);
        assert_eq!(m[0].host_id(), 0);
        assert_eq!(m[0].size(), USERNS_RANGE_END);
        assert_eq!(map_c2h(&m, 0), Some(0));
        assert_eq!(map_c2h(&m, 1000), Some(1000));
        assert_eq!(map_c2h(&m, 65534), Some(65534));
    }

    #[test]
    fn userns_root_workload_swaps_zero_and_owner() {
        // Default interactive sandbox: workload is root (0), workspace owner 1000.
        let m = transpose_identity_map(0, 1000);
        // container-root owns the workspace (maps to host 1000).
        assert_eq!(map_c2h(&m, 0), Some(1000));
        // the workspace-owner id is consumed exactly once (by container 1000).
        assert_eq!(map_c2h(&m, 1000), Some(0));
        // everything else is identity.
        assert_eq!(map_c2h(&m, 1), Some(1));
        assert_eq!(map_c2h(&m, 999), Some(999));
        assert_eq!(map_c2h(&m, 1001), Some(1001));
        assert_eq!(map_c2h(&m, 65534), Some(65534));
        assert_no_host_overlap(&m);
    }

    #[test]
    fn userns_named_user_keeps_root_for_sudo() {
        // Image USER=node(1000), host owner uid 1001 (host uid != image uid).
        let m = transpose_identity_map(1000, 1001);
        // the USER owns the workspace.
        assert_eq!(map_c2h(&m, 1000), Some(1001));
        // CRITICAL: container-root still maps to host-root → setuid sudo works.
        assert_eq!(map_c2h(&m, 0), Some(0));
        // the owner id is consumed exactly once (by container 1001).
        assert_eq!(map_c2h(&m, 1001), Some(1000));
        assert_eq!(map_c2h(&m, 65534), Some(65534));
        assert_no_host_overlap(&m);
    }

    #[test]
    fn userns_multi_uid_nobody_image() {
        // Real multi-uid image whose USER resolves to a high id (nobody=65534),
        // host workspace owner 1000.
        let m = transpose_identity_map(65534, 1000);
        assert_eq!(map_c2h(&m, 65534), Some(1000)); // nobody owns the workspace
        assert_eq!(map_c2h(&m, 0), Some(0)); // root preserved (sudo)
        assert_eq!(map_c2h(&m, 1000), Some(65534)); // owner id consumed once
        assert_eq!(map_c2h(&m, 33), Some(33)); // www-data etc. identity
        assert_no_host_overlap(&m);
    }

    #[test]
    fn userns_covers_full_range_no_overflow_id() {
        // Highest mapped id is RANGE_END-1; the (uid_t)-1 overflow id is excluded.
        let m = transpose_identity_map(1000, 2000);
        assert_eq!(
            map_c2h(&m, USERNS_RANGE_END - 1),
            Some(USERNS_RANGE_END - 1)
        );
        // total coverage equals the full range (sum of sizes).
        let total: u64 = m.iter().map(|e| e.size() as u64).sum();
        assert_eq!(total, USERNS_RANGE_END as u64);
        // at most five extents.
        assert!(m.len() <= 5, "too many extents: {}", m.len());
    }

    #[test]
    fn userns_owner_is_root_degenerate() {
        // Pathological: virtiofsd somehow runs as root (owner 0) and workload 0.
        // workload==owner==0 → identity (no swap needed; root already owns it).
        let m = transpose_identity_map(0, 0);
        assert_eq!(m.len(), 1);
        assert_eq!(map_c2h(&m, 0), Some(0));
    }

    #[test]
    fn userns_owner_zero_nonroot_workload_is_identity() {
        // owner 0 with a non-root workload = the Windows anchor stub (OpenVMM
        // virtiofs presents guest-0 0777) or a root-owned Linux workspace
        // (`sudo izba`). Transposing 0↔workload scrambles EVERY root-owned
        // image file (setuid sudo → uid workload, workload's $HOME → root) —
        // the claude-code-on-Windows breakage. Identity keeps the image
        // faithful; workspace writability comes from the share's own mode
        // (0777 on Windows), not from ownership games.
        let m = transpose_identity_map(1000, 0);
        assert_eq!(m.len(), 1);
        assert_eq!(map_c2h(&m, 0), Some(0));
        assert_eq!(map_c2h(&m, 1000), Some(1000));
        assert_eq!(map_c2h(&m, 65534), Some(65534));
    }

    // ---- docker-mode shifted map (docker_shifted_map) ----

    /// Sum of extent sizes == the mapped id count; extents must not overlap on
    /// either side.
    fn assert_shifted_invariants(m: &[oci_spec::runtime::LinuxIdMapping]) {
        assert_no_host_overlap(m);
        let mut cranges: Vec<(u64, u64)> = m
            .iter()
            .map(|e| {
                (
                    e.container_id() as u64,
                    e.container_id() as u64 + e.size() as u64,
                )
            })
            .collect();
        cranges.sort();
        for w in cranges.windows(2) {
            assert!(w[0].1 <= w[1].0, "container ranges overlap: {cranges:?}");
        }
    }

    #[test]
    fn docker_shifted_map_common_linux_flow_owner_equals_workload() {
        // THE claude-code-docker case that used to fail closed: image USER
        // agent (1000) on a workspace owned by host uid 1000.
        let m = docker_shifted_map(1000, 1000).expect("map builds");
        // container-root → BASE, never guest-0 (F-32, by construction).
        assert_eq!(map_c2h(&m, 0), Some(DOCKER_IDMAP_BASE));
        // the workload owns the workspace (carve-out to guest-owner).
        assert_eq!(map_c2h(&m, 1000), Some(1000));
        // linear shift around the carve-out.
        assert_eq!(map_c2h(&m, 999), Some(DOCKER_IDMAP_BASE + 999));
        assert_eq!(map_c2h(&m, 1001), Some(DOCKER_IDMAP_BASE + 1001));
        // guest-0 is entirely unmapped (strictly stronger than the transpose):
        // a host range contains 0 iff it STARTS at 0 (ranges are ascending).
        assert!(!m.iter().any(|e| e.host_id() == 0 && e.size() > 0));
        assert_shifted_invariants(&m);
    }

    #[test]
    fn docker_shifted_map_root_image_on_user_workspace() {
        // docker:dind (USER root) on a uid-1000 workspace: container-root gets
        // the carve-out → owns /workspace, exactly like the shipped dind e2e.
        let m = docker_shifted_map(0, 1000).expect("map builds");
        assert_eq!(map_c2h(&m, 0), Some(1000));
        assert_eq!(map_c2h(&m, 1), Some(DOCKER_IDMAP_BASE + 1));
        assert_eq!(
            map_c2h(&m, DOCKER_IDMAP_RANGE - 1),
            Some(DOCKER_IDMAP_BASE + DOCKER_IDMAP_RANGE - 1)
        );
        assert_shifted_invariants(&m);
    }

    #[test]
    fn docker_shifted_map_owner_zero_is_pure_shift() {
        // Windows (owner anchor 0): NO carve-out — mapping any container id to
        // guest-0 would hand the workload guest-root's euid for sysctl DAC.
        for workload in [0u32, 1000] {
            let m = docker_shifted_map(workload, 0).expect("map builds");
            assert_eq!(m.len(), 1);
            assert_eq!(map_c2h(&m, 0), Some(DOCKER_IDMAP_BASE));
            assert_eq!(map_c2h(&m, 1000), Some(DOCKER_IDMAP_BASE + 1000));
            assert_shifted_invariants(&m);
        }
    }

    #[test]
    fn docker_shifted_map_owner_inside_window_bumps_base() {
        // An owner uid that lands inside the default guest window would
        // overlap the shift extents; the window moves up by one RANGE.
        let owner = DOCKER_IDMAP_BASE + 5;
        let m = docker_shifted_map(1000, owner).expect("map builds");
        let base = DOCKER_IDMAP_BASE + DOCKER_IDMAP_RANGE;
        assert_eq!(map_c2h(&m, 0), Some(base));
        assert_eq!(map_c2h(&m, 1000), Some(owner));
        assert_shifted_invariants(&m);
    }

    #[test]
    fn docker_shifted_map_huge_owner_outside_window_is_fine() {
        // A big (LDAP-style) owner uid far above the window: no bump needed,
        // carve-out points straight at it.
        let owner = 10_000_000;
        let m = docker_shifted_map(1000, owner).expect("map builds");
        assert_eq!(map_c2h(&m, 0), Some(DOCKER_IDMAP_BASE));
        assert_eq!(map_c2h(&m, 1000), Some(owner));
        assert_shifted_invariants(&m);
    }

    #[test]
    fn docker_shifted_map_workload_above_range_is_refused() {
        let err = docker_shifted_map(DOCKER_IDMAP_RANGE, 1000)
            .expect_err("workload beyond the mapped range must be refused");
        let msg = format!("{err:#}");
        assert!(msg.contains("USER"), "actionable message, got: {msg}");
    }

    #[test]
    fn docker_shifted_map_workload_at_top_of_range_omits_zero_size_tail() {
        // workload == RANGE-1: the tail extent would be zero-size and must be
        // omitted (the kernel rejects zero-size extents; a relaxed `<`→`<=`
        // or broken `RANGE - 1` arithmetic in the guard would emit it).
        let m = docker_shifted_map(DOCKER_IDMAP_RANGE - 1, 1000).expect("map builds");
        assert!(
            m.iter().all(|e| e.size() > 0),
            "no zero-size extents allowed: {m:?}"
        );
        assert_eq!(map_c2h(&m, DOCKER_IDMAP_RANGE - 1), Some(1000));
        let total: u64 = m.iter().map(|e| e.size() as u64).sum();
        assert_eq!(total, DOCKER_IDMAP_RANGE as u64);
        assert_shifted_invariants(&m);
    }

    #[test]
    fn docker_userns_isolates_root_checks_both_legs_independently() {
        // A safe uid map with a gid map that puts container-0 on guest-0 (and
        // vice versa) must fail the predicate — `&&` of the two negated legs,
        // not `||`.
        let safe = docker_shifted_map(0, 1000).expect("map builds");
        let violating = transpose_identity_map(1000, 1000); // identity: 0 → 0
        assert!(!docker_userns_isolates_root(&safe, &violating));
        assert!(!docker_userns_isolates_root(&violating, &safe));
        assert!(docker_userns_isolates_root(&safe, &safe));
    }

    #[test]
    fn docker_shifted_map_workload_zero_boundary_extents() {
        // workload 0 with non-zero owner: the carve-out IS container-0; no
        // leading extent, and the tail covers [1, RANGE).
        let m = docker_shifted_map(0, 7).expect("map builds");
        assert_eq!(map_c2h(&m, 0), Some(7));
        assert_eq!(map_c2h(&m, 1), Some(DOCKER_IDMAP_BASE + 1));
        let total: u64 = m.iter().map(|e| e.size() as u64).sum();
        assert_eq!(total, DOCKER_IDMAP_RANGE as u64);
        assert_shifted_invariants(&m);
    }

    #[test]
    fn compute_docker_userns_mappings_maps_uid_and_gid_independently() {
        let (uid_maps, gid_maps) =
            compute_docker_userns_mappings((1000, 2000), (10, 20)).expect("maps build");
        assert_eq!(map_c2h(&uid_maps, 10), Some(1000));
        assert_eq!(map_c2h(&gid_maps, 20), Some(2000));
        // the OTHER dimension's ids follow the shift, not the carve-out.
        assert_eq!(map_c2h(&uid_maps, 20), Some(DOCKER_IDMAP_BASE + 20));
        assert_eq!(map_c2h(&gid_maps, 10), Some(DOCKER_IDMAP_BASE + 10));
    }

    #[test]
    fn layer_idmap_cmdline_value_keeps_oci_columns_and_appends_fsuid0_anchor() {
        // The cmdline fragment mirrors izba.volumes: comma-separated
        // `disk-presented-n` triples — the OCI extents VERBATIM (disk uid is
        // the mount userns's inner id; see layer_idmap_cmdline_value's
        // orientation doc, verified on a real VM) — closed by the fsuid-0
        // anchor so guest-root writers (overlay whiteouts, crun mkdirs)
        // never EOVERFLOW.
        let m = docker_shifted_map(1000, 1000).expect("map builds");
        let s = layer_idmap_cmdline_value(&m);
        let b = DOCKER_IDMAP_BASE;
        let r = DOCKER_IDMAP_RANGE;
        assert_eq!(
            s,
            format!(
                "0-{b}-1000,1000-1000-1,1001-{}-{},{r}-0-1",
                b + 1001,
                r - 1001
            )
        );
    }

    #[test]
    fn workspace_idmap_needed_exactly_when_an_owner_leg_is_zero() {
        // Zero leg(s) ⇒ the share would present through the shifted map as
        // nobody/nogroup (guest-0 unmapped, F-32) ⇒ idmap it. Non-zero owner
        // (the common Linux case) ⇒ the owner carve-out already presents the
        // share as the workload USER ⇒ leave it alone.
        assert!(workspace_idmap_needed((0, 0)));
        assert!(workspace_idmap_needed((0, 1000)));
        assert!(workspace_idmap_needed((1000, 0)));
        assert!(!workspace_idmap_needed((1000, 1000)));
        assert!(!workspace_idmap_needed((1, 1)));
    }

    #[test]
    fn compute_userns_mappings_maps_uid_and_gid_independently() {
        // Asymmetric across all four ids so a swapped uid/gid field OR a swapped
        // owner/workload arg would change an assertion (the transposition itself
        // is symmetric in its two args, so the distinguishing power comes from
        // uid != gid AND owner != workload with distinct values).
        let (uid_maps, gid_maps) = compute_userns_mappings((1000, 2000), (10, 20));
        // uid map transposes workload-uid 10 <-> owner-uid 1000.
        assert_eq!(map_c2h(&uid_maps, 10), Some(1000));
        assert_eq!(map_c2h(&uid_maps, 1000), Some(10));
        assert_eq!(map_c2h(&uid_maps, 20), Some(20)); // gid value is identity in the uid map
                                                      // gid map transposes workload-gid 20 <-> owner-gid 2000.
        assert_eq!(map_c2h(&gid_maps, 20), Some(2000));
        assert_eq!(map_c2h(&gid_maps, 2000), Some(20));
        assert_eq!(map_c2h(&gid_maps, 10), Some(10)); // uid value is identity in the gid map

        // owner == workload → identity both.
        let (uid_maps, gid_maps) = compute_userns_mappings((1000, 50), (1000, 50));
        assert_eq!(uid_maps.len(), 1);
        assert_eq!(gid_maps.len(), 1);
    }

    #[test]
    fn userns_top_boundary_no_trailing_zero_extent() {
        // workload at the very top mapped id (RANGE_END-1): the trailing
        // identity extent must be omitted (a relaxed `<`→`<=` guard would emit a
        // zero-size extent at the top). assert_no_host_overlap rejects that.
        let m = transpose_identity_map(USERNS_RANGE_END - 1, 1000);
        assert_eq!(map_c2h(&m, USERNS_RANGE_END - 1), Some(1000));
        assert_eq!(map_c2h(&m, 1000), Some(USERNS_RANGE_END - 1));
        assert_eq!(map_c2h(&m, 0), Some(0));
        assert_no_host_overlap(&m);
        let total: u64 = m.iter().map(|e| e.size() as u64).sum();
        assert_eq!(total, USERNS_RANGE_END as u64);
    }

    // ---- resolve_process_user (config.json USER -> (uid,gid) + loud warning) ----

    fn db_with_node() -> UserDb {
        UserDb::from_files(
            Some("root:x:0:0::/root:/bin/sh\nnode:x:1000:1000::/home/node:/bin/sh\n"),
            Some("node:x:1000:\nwheel:x:10:\n"),
        )
    }

    #[test]
    fn resolve_process_user_none_is_silent_root() {
        assert_eq!(
            resolve_process_user(None, &UserDb::default()),
            ((0, 0), None)
        );
    }

    #[test]
    fn resolve_process_user_empty_is_silent_root() {
        assert_eq!(
            resolve_process_user(Some(""), &UserDb::default()),
            ((0, 0), None)
        );
    }

    #[test]
    fn resolve_process_user_numeric_is_silent() {
        assert_eq!(
            resolve_process_user(Some("1000"), &UserDb::default()),
            ((1000, 0), None)
        );
        assert_eq!(
            resolve_process_user(Some("1000:1001"), &UserDb::default()),
            ((1000, 1001), None)
        );
    }

    #[test]
    fn resolve_process_user_symbolic_resolves_from_db() {
        assert_eq!(
            resolve_process_user(Some("node"), &db_with_node()),
            ((1000, 1000), None)
        );
    }

    #[test]
    fn resolve_process_user_partly_symbolic_resolves_group() {
        assert_eq!(
            resolve_process_user(Some("1000:wheel"), &db_with_node()),
            ((1000, 10), None)
        );
    }

    #[test]
    fn resolve_process_user_unresolvable_is_loud_root() {
        let ((uid, gid), fb) = resolve_process_user(Some("ghost"), &db_with_node());
        assert_eq!((uid, gid), (0, 0));
        let fb = fb.expect("unresolvable symbolic USER produces a fallback");
        assert_eq!(fb.declared, "ghost");
        assert!(fb.reason.contains("USER 'ghost'"), "got: {}", fb.reason);
    }

    // ---- full spec assembly ----

    fn image_config(json: serde_json::Value) -> Config {
        serde_json::from_value(json).unwrap()
    }

    fn base_params<'a>(image: &'a Config) -> SpecParams<'a> {
        SpecParams {
            mode: ContainerMode::Service,
            image: Some(image),
            entrypoint_override: None,
            cmd_override: None,
            env_overrides: &[],
            trust_env: &[],
            cwd_override: None,
            user: (0, 0),
            host_owner: (1000, 1000),
            hostname: "web",
            terminal: false,
            privileged: false,
            usb: false,
            docker: false,
            additional_gids: &[],
            vnc: false,
        }
    }

    #[test]
    fn generate_spec_populates_additional_gids() {
        let img = image_config(serde_json::json!({"Cmd": ["/bin/sh"]}));
        let spec = generate_spec(&SpecParams {
            additional_gids: &[999, 29],
            ..base_params(&img)
        })
        .unwrap();
        let user = spec.process().as_ref().unwrap().user().clone();
        assert_eq!(user.additional_gids().clone().unwrap(), vec![999, 29]);
        assert_eq!(user.uid(), base_params(&img).user.0);

        // Empty ⇒ additionalGids absent from the spec entirely (never an
        // empty-array field), matching every pre-existing sandbox with no
        // supplementary groups.
        let spec_empty = generate_spec(&base_params(&img)).unwrap();
        let user_empty = spec_empty.process().as_ref().unwrap().user().clone();
        assert!(user_empty.additional_gids().is_none());
    }

    #[test]
    fn a_usb_sandbox_gets_the_shared_device_directory_bound_in() {
        // The bind is how a node created AFTER the container started becomes
        // visible: the container has its own mount namespace and a fresh tmpfs
        // /dev, but a bind mount shares the source's superblock.
        let img = image_config(serde_json::json!({"Cmd": ["/bin/sh"]}));
        let spec = generate_spec(&SpecParams {
            usb: true,
            ..base_params(&img)
        })
        .unwrap();
        let m = spec
            .mounts()
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.destination() == std::path::Path::new(USB_CONTAINER_DIR))
            .expect("no /dev/izba mount");
        assert_eq!(m.typ().as_deref(), Some("bind"));
        assert_eq!(
            m.source().as_deref(),
            Some(std::path::Path::new(USB_SHARED_DIR))
        );
        let opts = m.options().clone().unwrap_or_default();
        for want in ["rbind", "rw", "nosuid", "noexec"] {
            assert!(opts.iter().any(|o| o == want), "missing {want}: {opts:?}");
        }
    }

    #[test]
    fn a_sandbox_without_usb_has_no_device_directory_and_no_device_rules() {
        // The structural half of "disabled USB adds no attack surface": not a
        // directory that stays empty, but no directory and no allowance at all.
        let img = image_config(serde_json::json!({"Cmd": ["/bin/sh"]}));
        let spec = generate_spec(&base_params(&img)).unwrap();
        assert!(
            !spec
                .mounts()
                .as_ref()
                .unwrap()
                .iter()
                .any(|m| m.destination() == std::path::Path::new(USB_CONTAINER_DIR)),
            "no USB grants must mean no /dev/izba"
        );
        let devices = spec
            .linux()
            .as_ref()
            .unwrap()
            .resources()
            .clone()
            .unwrap_or_default()
            .devices()
            .clone()
            .unwrap_or_default();
        assert!(devices.is_empty(), "no USB ⇒ no device rules: {devices:?}");
    }

    #[test]
    fn only_the_serial_char_majors_are_authorised_and_never_for_mknod() {
        // The cgroup rules are what make "serial class only" structural: a node
        // of any other class that somehow reached /dev/izba still cannot be
        // opened, and the workload can never create one of its own.
        let img = image_config(serde_json::json!({"Cmd": ["/bin/sh"]}));
        let spec = generate_spec(&SpecParams {
            usb: true,
            ..base_params(&img)
        })
        .unwrap();
        let devices = spec
            .linux()
            .as_ref()
            .unwrap()
            .resources()
            .clone()
            .unwrap()
            .devices()
            .clone()
            .unwrap();
        let majors: Vec<i64> = devices.iter().filter_map(|d| d.major()).collect();
        assert_eq!(majors, vec![166, 188], "ttyACM and ttyUSB, nothing else");
        assert!(devices.iter().all(|d| d.allow()));
        assert!(devices.iter().all(|d| d.typ() == Some(LinuxDeviceType::C)));
        for d in &devices {
            let access = d.access().clone().unwrap_or_default();
            assert!(
                !access.contains('m'),
                "mknod must never be granted: {access}"
            );
            assert!(access.contains('r') && access.contains('w'), "{access}");
        }
    }

    #[test]
    fn the_shared_directory_path_matches_the_one_izba_init_writes_to() {
        // Host and guest agree on this path by convention, not by a shared
        // constant (izba-core does not depend on izba-init). A drift here would
        // bind an empty directory and the device would simply never appear.
        assert_eq!(USB_SHARED_DIR, "/run/izba/usb");
    }

    #[test]
    fn usb_does_not_disturb_the_rest_of_the_spec() {
        // The USB additions are additive: the /sys rebind, the dropped network
        // namespace and the user namespace must all survive.
        let img = image_config(serde_json::json!({"Cmd": ["/bin/sh"]}));
        let with = generate_spec(&SpecParams {
            usb: true,
            ..base_params(&img)
        })
        .unwrap();
        let without = generate_spec(&base_params(&img)).unwrap();
        let nss = |s: &Spec| {
            s.linux()
                .as_ref()
                .unwrap()
                .namespaces()
                .clone()
                .unwrap()
                .iter()
                .map(|n| format!("{:?}", n.typ()))
                .collect::<Vec<_>>()
        };
        assert_eq!(nss(&with), nss(&without));
        let sys = |s: &Spec| {
            s.mounts()
                .as_ref()
                .unwrap()
                .iter()
                .find(|m| m.destination() == std::path::Path::new("/sys"))
                .map(|m| format!("{:?}", m.typ()))
        };
        assert_eq!(sys(&with), sys(&without));
    }

    // ---- VNC ----

    #[test]
    fn a_vnc_sandbox_gets_bundle_xkbcomp_and_secrets_bound_in() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&SpecParams {
            vnc: true,
            ..base_params(&img)
        })
        .unwrap();
        let m = |dest: &str| {
            spec.mounts()
                .as_ref()
                .unwrap()
                .iter()
                .find(|m| m.destination().to_str() == Some(dest))
                .cloned()
        };
        let bundle = m(VNC_BUNDLE_CONTAINER_DIR).expect("bundle bind");
        assert_eq!(
            bundle.source().as_ref().unwrap().to_str(),
            Some(VNC_BUNDLE_SHARED_DIR)
        );
        let bundle_opts = bundle.options().clone().unwrap_or_default();
        assert!(bundle_opts.contains(&"ro".to_string()));
        assert!(
            !bundle_opts.iter().any(|o| o == "noexec"),
            "bundle binaries must stay executable: {bundle_opts:?}"
        );

        let xkb = m("/usr/bin/xkbcomp").expect("xkbcomp file bind (server path is hardcoded)");
        assert_eq!(
            xkb.source().as_ref().unwrap().to_str(),
            Some("/run/izba/vnc/bin/xkbcomp")
        );

        // libmenu-cache (lxpanel's Applications menu backend) spawns its
        // daemon from a COMPILED-IN path — same class as xkbcomp: occupy
        // the hardcoded path with a bundle file-bind. The literal is
        // `/usr/lib/menu-cache/menu-cached` (Debian's `libmenu-cache-bin`
        // layout, and the string compiled into `libmenu-cache.so.3`); a
        // bind anywhere else leaves lxpanel to `g_error`/abort at startup
        // with "failed to find menu-cached" — the desktop then has no
        // panel at all, which a real-VM boot proved.
        // BOTH halves: `menu-cached` is the daemon lxpanel talks to, and
        // `menu-cache-gen` is the generator that daemon spawns from its own
        // hardcoded `/usr/lib/menu-cache` path. Binding only the daemon
        // yields a menu that opens but is permanently EMPTY, with nothing
        // logged anywhere — proven on a real VM.
        for bin in ["menu-cached", "menu-cache-gen"] {
            let mc = m(&format!("/usr/lib/menu-cache/{bin}"))
                .unwrap_or_else(|| panic!("{bin} file bind"));
            assert_eq!(
                mc.source().as_ref().and_then(|p| p.to_str()),
                Some(format!("/run/izba/vnc/bin/{bin}").as_str())
            );
            assert!(mc.options().as_ref().unwrap().iter().any(|o| o == "ro"));
        }

        // The two dlopened MODULE TREES, same class again: `liblxpanel.so.0`
        // and `libfm.so.4` each dlopen from a compiled-in multiarch dir with
        // no environment override, so the bundle's copies must occupy those
        // exact guest paths or every panel plugin (taskbar, clock, menu) and
        // every libfm module is silently missing.
        for (dest, src) in [
            (
                "/usr/lib/x86_64-linux-gnu/lxpanel/plugins",
                "/run/izba/vnc/lib/lxpanel/plugins",
            ),
            (
                "/usr/lib/x86_64-linux-gnu/libfm/modules",
                "/run/izba/vnc/lib/libfm",
            ),
            ("/usr/share/lxpanel", "/run/izba/vnc/share/lxpanel"),
            // libfm's and pcmanfm's PACKAGE_DATA_DIRs carry the GtkBuilder
            // .ui files behind the desktop right-click menu's entries
            // (Desktop Preferences, Create New, Properties, Rename); an
            // image that does not ship pcmanfm has none of them.
            ("/usr/share/libfm", "/run/izba/vnc/share/libfm"),
            ("/usr/share/pcmanfm", "/run/izba/vnc/share/pcmanfm"),
        ] {
            let md = m(dest).unwrap_or_else(|| panic!("module-dir bind for {dest}"));
            assert_eq!(md.source().as_ref().and_then(|p| p.to_str()), Some(src));
            let opts = md.options().clone().unwrap_or_default();
            assert!(opts.iter().any(|o| o == "ro"), "{dest}: {opts:?}");
            assert!(
                !opts.iter().any(|o| o == "noexec"),
                "module trees are dlopened — noexec would defeat the bind: {opts:?}"
            );
        }

        let sec = m(VNC_SECRETS_CONTAINER_DIR).expect("secrets bind");
        assert_eq!(
            sec.source().as_ref().unwrap().to_str(),
            Some(VNC_SECRETS_SHARED_DIR)
        );
        let sec_opts = sec.options().clone().unwrap_or_default();
        for want in ["ro", "nosuid", "noexec"] {
            assert!(
                sec_opts.iter().any(|o| o == want),
                "missing {want}: {sec_opts:?}"
            );
        }

        let shm = m("/dev/shm").unwrap();
        let opts = shm.options().clone().unwrap_or_default();
        assert!(opts.contains(&DEV_SHM_VNC_SIZE.to_string()));
        assert!(
            !opts.iter().any(|o| o == "size=65536k"),
            "old size replaced, not duplicated: {opts:?}"
        );
    }

    /// The VNC bind SOURCES are guest paths izba-init creates/mounts, agreed
    /// by convention rather than a shared constant (izba-core does not depend
    /// on izba-init). izba-init pins the same literals in its `vnc` module. A
    /// drift here would fail the container start outright — crun refuses a
    /// bind whose source does not exist.
    #[test]
    fn the_vnc_guest_paths_match_the_ones_izba_init_provides() {
        assert_eq!(VNC_BUNDLE_SHARED_DIR, "/run/izba/vnc");
        assert_eq!(VNC_BUNDLE_CONTAINER_DIR, "/opt/izba-vnc");
        assert_eq!(VNC_SECRETS_SHARED_DIR, "/run/izba/vnc-secrets");
        // Source and destination are deliberately the same path so
        // `-KasmPasswordFile` reads identically on both sides.
        assert_eq!(VNC_SECRETS_CONTAINER_DIR, VNC_SECRETS_SHARED_DIR);
    }

    #[test]
    fn a_sandbox_without_vnc_has_stock_shm_and_no_vnc_mounts() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let mounts = spec.mounts().as_ref().unwrap();
        assert!(
            !mounts
                .iter()
                .any(|m| m.destination().to_str() == Some(VNC_BUNDLE_CONTAINER_DIR)),
            "no vnc ⇒ no bundle bind"
        );
        for dest in [
            "/usr/bin/xkbcomp",
            "/usr/lib/menu-cache/menu-cached",
            "/usr/lib/menu-cache/menu-cache-gen",
            "/usr/lib/x86_64-linux-gnu/lxpanel/plugins",
            "/usr/lib/x86_64-linux-gnu/libfm/modules",
            "/usr/share/lxpanel",
            "/usr/share/libfm",
            "/usr/share/pcmanfm",
        ] {
            assert!(
                !mounts
                    .iter()
                    .any(|m| m.destination().to_str() == Some(dest)),
                "no vnc ⇒ no {dest} bind"
            );
        }
        assert!(
            !mounts
                .iter()
                .any(|m| m.destination().to_str() == Some(VNC_SECRETS_CONTAINER_DIR)),
            "no vnc ⇒ no secrets bind"
        );
        let shm = mounts
            .iter()
            .find(|m| m.destination().to_str() == Some("/dev/shm"))
            .expect("stock /dev/shm mount");
        let opts = shm.options().clone().unwrap_or_default();
        // Pin the actual OCI-default stock value so drift in the vendored
        // spec (e.g. a version bump changing the default size) is caught
        // here rather than silently changing what "stock" means.
        assert!(
            opts.contains(&"size=65536k".to_string()),
            "stock /dev/shm size must be untouched without vnc: {opts:?}"
        );
        assert!(!opts.iter().any(|o| o == DEV_SHM_VNC_SIZE));
    }

    #[test]
    fn vnc_does_not_disturb_the_rest_of_the_spec() {
        // Mirrors usb_does_not_disturb_the_rest_of_the_spec: the VNC
        // additions are additive — the /sys rebind, the dropped network
        // namespace, the user namespace, and the readonly paths must all
        // survive untouched.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let with = generate_spec(&SpecParams {
            vnc: true,
            ..base_params(&img)
        })
        .unwrap();
        let without = generate_spec(&base_params(&img)).unwrap();
        let nss = |s: &Spec| {
            s.linux()
                .as_ref()
                .unwrap()
                .namespaces()
                .clone()
                .unwrap()
                .iter()
                .map(|n| format!("{:?}", n.typ()))
                .collect::<Vec<_>>()
        };
        assert_eq!(nss(&with), nss(&without));
        let sys = |s: &Spec| {
            s.mounts()
                .as_ref()
                .unwrap()
                .iter()
                .find(|m| m.destination() == std::path::Path::new("/sys"))
                .map(|m| format!("{:?}", m.typ()))
        };
        assert_eq!(sys(&with), sys(&without));
        let ro = |s: &Spec| s.linux().as_ref().unwrap().readonly_paths().clone();
        assert_eq!(ro(&with), ro(&without));
    }

    #[test]
    fn spec_process_reflects_merges_and_user() {
        let img = image_config(serde_json::json!({
            "Entrypoint": ["/bin/server"],
            "Cmd": ["--port", "80"],
            "Env": ["PATH=/usr/bin"],
            "WorkingDir": "/srv",
        }));
        let mut p = base_params(&img);
        p.env_overrides = &[];
        p.user = (1000, 1000);
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().as_ref().expect("process");
        assert_eq!(
            proc.args().clone().unwrap(),
            v(&["/bin/server", "--port", "80"])
        );
        assert_eq!(proc.env().clone().unwrap(), v(&["PATH=/usr/bin"]));
        assert_eq!(proc.cwd().to_string_lossy(), "/srv");
        assert_eq!(proc.user().uid(), 1000);
        assert_eq!(proc.user().gid(), 1000);
        assert!(!proc.terminal().unwrap_or(false));
    }

    #[test]
    fn spec_root_is_rootfs_writable() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let root = spec.root().as_ref().expect("root");
        assert_eq!(root.path().to_string_lossy(), CONTAINER_ROOTFS);
        assert_eq!(root.readonly(), Some(false));
    }

    #[test]
    fn spec_hostname_and_terminal_applied() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.hostname = "myhost";
        p.terminal = true;
        let spec = generate_spec(&p).unwrap();
        assert_eq!(spec.hostname().as_deref(), Some("myhost"));
        assert!(spec.process().as_ref().unwrap().terminal().unwrap());
    }

    #[test]
    fn spec_omits_network_namespace_keeps_others() {
        // D1: container shares izba-init's netns -> no network ns in the spec.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let nss = spec.linux().as_ref().unwrap().namespaces().clone().unwrap();
        let types: Vec<LinuxNamespaceType> = nss.iter().map(|n| n.typ()).collect();
        assert!(
            !types.contains(&LinuxNamespaceType::Network),
            "network namespace must be omitted (D1)"
        );
        assert!(types.contains(&LinuxNamespaceType::Pid));
        assert!(types.contains(&LinuxNamespaceType::Mount));
        assert!(types.contains(&LinuxNamespaceType::Ipc));
        assert!(types.contains(&LinuxNamespaceType::Uts));
    }

    #[test]
    fn spec_adds_user_namespace_with_transposed_mappings() {
        // Option A: generate_spec must add a User namespace and the uid/gid
        // transposition mapping (workload USER <-> workspace owner).
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.user = (0, 0); // root workload
        p.host_owner = (1000, 1000); // host owns the workspace
        let spec = generate_spec(&p).unwrap();
        let linux = spec.linux().as_ref().unwrap();

        // A User namespace is present.
        let nss = linux.namespaces().clone().unwrap();
        assert!(
            nss.iter().any(|n| n.typ() == LinuxNamespaceType::User),
            "User namespace must be added (Option A)"
        );

        // uid/gid mappings are the transposition (container-0 -> host-1000).
        let uid_maps = linux.uid_mappings().clone().expect("uid mappings set");
        let gid_maps = linux.gid_mappings().clone().expect("gid mappings set");
        assert_eq!(map_c2h(&uid_maps, 0), Some(1000));
        assert_eq!(map_c2h(&gid_maps, 0), Some(1000));
        assert_eq!(map_c2h(&uid_maps, 1000), Some(0));
    }

    #[test]
    fn spec_userns_named_user_preserves_root_mapping() {
        // Image USER=1000 with host owner 1001: the USER owns the workspace and
        // container-root stays host-root (sudo works).
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"], "User": "1000" }));
        let mut p = base_params(&img);
        p.user = (1000, 1000);
        p.host_owner = (1001, 1001);
        let spec = generate_spec(&p).unwrap();
        let linux = spec.linux().as_ref().unwrap();
        let uid_maps = linux.uid_mappings().clone().expect("uid mappings set");
        assert_eq!(map_c2h(&uid_maps, 1000), Some(1001)); // USER -> owner
        assert_eq!(map_c2h(&uid_maps, 0), Some(0)); // root preserved
    }

    #[test]
    fn spec_userns_mappings_serialize_to_json() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.host_owner = (1000, 1000);
        let spec = generate_spec(&p).unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        // OCI serializes these as camelCase keys.
        assert!(json.contains("uidMappings"), "uidMappings in JSON: {json}");
        assert!(json.contains("gidMappings"), "gidMappings in JSON");
        assert!(json.contains("\"user\""), "user namespace type in JSON");
    }

    #[test]
    fn spec_sys_mount_is_a_recursive_bind_not_fresh_sysfs() {
        // Option A adds a user namespace while the container still SHARES
        // izba-init's (host) network namespace (D1). The kernel forbids mounting
        // a fresh `sysfs` instance from a user namespace that does not own the
        // network namespace it would expose, so a `type:sysfs` `/sys` mount fails
        // `mount sysfs: EPERM` under crun (seen on the OpenVMM/WHP backend). The
        // spec must instead present `/sys` as a recursive bind of the already-
        // mounted host `/sys` — the canonical rootless / `--net=host`+userns
        // layout. A bind clone of a visible mount needs no netns ownership, so it
        // is deterministic on every VMM.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let p = base_params(&img);
        let spec = generate_spec(&p).unwrap();
        let mounts = spec.mounts().clone().expect("mounts set");
        let sys = mounts
            .iter()
            .find(|m| m.destination().to_string_lossy() == "/sys")
            .expect("/sys mount present");

        // NOT a fresh sysfs — a bind of the host /sys.
        assert_ne!(
            sys.typ().as_deref(),
            Some("sysfs"),
            "/sys must not be a fresh sysfs mount under a userns sharing the host netns"
        );
        assert_eq!(
            sys.source()
                .as_ref()
                .map(|s| s.to_string_lossy().into_owned()),
            Some("/sys".to_string()),
            "/sys bind source must be the host /sys"
        );
        let opts = sys.options().clone().unwrap_or_default();
        assert!(
            opts.iter().any(|o| o == "rbind"),
            "/sys mount must be a recursive bind (rbind): {opts:?}"
        );
        // The hardening options carry over (read-only, no suid/dev/exec).
        assert!(opts.iter().any(|o| o == "ro"), "/sys must stay read-only");
    }

    #[test]
    fn spec_interactive_cwd_override_and_cmd_override() {
        let img = image_config(serde_json::json!({
            "Entrypoint": ["/bin/server"],
            "Cmd": ["--port", "80"],
            "WorkingDir": "/srv",
        }));
        let mut p = base_params(&img);
        p.cwd_override = Some("/workspace");
        let shell = v(&["/bin/bash"]);
        p.entrypoint_override = Some(&shell);
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().as_ref().unwrap();
        // entrypoint override clears image cmd -> just the shell
        assert_eq!(proc.args().clone().unwrap(), v(&["/bin/bash"]));
        assert_eq!(proc.cwd().to_string_lossy(), "/workspace");
    }

    #[test]
    fn spec_interactive_runs_pause_ignores_image_entrypoint() {
        // D4: interactive mode runs the pause as PID 1, NOT the image cmd.
        let img = image_config(serde_json::json!({
            "Entrypoint": ["/bin/server"],
            "Cmd": ["--port", "80"],
            "WorkingDir": "/srv",
        }));
        let pause = v(&["/sbin/izba-pause"]);
        let mut p = base_params(&img);
        p.mode = ContainerMode::Interactive { pause_argv: &pause };
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().as_ref().unwrap();
        assert_eq!(proc.args().clone().unwrap(), v(&["/sbin/izba-pause"]));
        // interactive default cwd is /workspace, not the image WorkingDir
        assert_eq!(proc.cwd().to_string_lossy(), INTERACTIVE_CWD);
    }

    #[test]
    fn spec_interactive_honors_cwd_override() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let pause = v(&["/sbin/izba-pause"]);
        let mut p = base_params(&img);
        p.mode = ContainerMode::Interactive { pause_argv: &pause };
        p.cwd_override = Some("/data");
        let spec = generate_spec(&p).unwrap();
        assert_eq!(
            spec.process().as_ref().unwrap().cwd().to_string_lossy(),
            "/data"
        );
    }

    #[test]
    fn spec_serializes_to_json() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("\"ociVersion\""));
        assert!(json.contains("/rootfs"));
    }

    #[test]
    fn trust_env_strings_are_the_canonical_six() {
        // Must stay byte-for-byte in sync with izba-init trust.rs::trust_env_pairs.
        assert_eq!(
            trust_env_strings(),
            vec![
                "NODE_EXTRA_CA_CERTS=/etc/izba/ca.pem".to_string(),
                "DENO_CERT=/etc/izba/ca.pem".to_string(),
                "SSL_CERT_FILE=/etc/izba/ca-bundle.pem".to_string(),
                "REQUESTS_CA_BUNDLE=/etc/izba/ca-bundle.pem".to_string(),
                "CURL_CA_BUNDLE=/etc/izba/ca-bundle.pem".to_string(),
                "GIT_SSL_CAINFO=/etc/izba/ca-bundle.pem".to_string(),
            ]
        );
    }

    #[test]
    fn spec_trust_env_layered_when_present() {
        let img = image_config(serde_json::json!({
            "Cmd": ["/bin/sh"],
            "Env": ["PATH=/usr/bin"],
        }));
        let mut p = base_params(&img);
        let trust = v(&["SSL_CERT_FILE=/etc/izba/ca.pem"]);
        p.trust_env = &trust;
        let spec = generate_spec(&p).unwrap();
        let env = spec.process().as_ref().unwrap().env().clone().unwrap();
        assert!(env.contains(&"SSL_CERT_FILE=/etc/izba/ca.pem".to_string()));
        assert!(env.contains(&"PATH=/usr/bin".to_string()));
    }

    #[test]
    fn spec_grants_docker_default_caps_incl_dac_override() {
        // Without DAC_OVERRIDE the container root cannot write the host-owned
        // virtiofs /workspace (verified on a real boot). The minimal OCI default
        // set lacks it, so generate_spec must grant the docker-default set.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let proc = spec.process().clone().unwrap();
        let caps = proc.capabilities().clone().expect("capabilities set");
        for set in [caps.bounding(), caps.effective(), caps.permitted()] {
            let set = set.as_ref().expect("cap set present");
            assert!(
                set.contains(&Capability::DacOverride),
                "DAC_OVERRIDE must be granted (workspace writes)"
            );
            assert!(set.contains(&Capability::Chown));
            assert!(set.contains(&Capability::Setuid));
            // dangerous caps stay dropped — the VM is the boundary.
            assert!(!set.contains(&Capability::SysAdmin));
        }
    }

    // ---- docker mode spec ----

    #[test]
    fn docker_mode_caps_is_default_plus_admin_set() {
        let caps = docker_mode_caps().unwrap();
        let bounding = caps.bounding().clone().unwrap();
        for c in [
            Capability::SysAdmin,
            Capability::NetAdmin,
            Capability::SysPtrace,
        ] {
            assert!(
                bounding.contains(&c),
                "{c:?} missing from docker-mode bounding set"
            );
        }
        // Strictly weaker than privileged: docker mode must NOT be all_caps.
        let all = all_caps().unwrap();
        assert!(bounding.len() < all.bounding().clone().unwrap().len());
        // And a superset of the docker-default set.
        let dflt = docker_default_caps().unwrap();
        for c in dflt.bounding().clone().unwrap() {
            assert!(bounding.contains(&c), "{c:?} from default set missing");
        }
    }

    #[test]
    fn docker_mode_spec_keeps_fresh_network_namespace() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut params = base_params(&img);
        params.docker = true;
        let spec = generate_spec(&params).unwrap();
        let nss = spec.linux().as_ref().unwrap().namespaces().clone().unwrap();
        let net = nss
            .iter()
            .find(|n| n.typ() == LinuxNamespaceType::Network)
            .expect("docker mode must keep a network namespace");
        assert!(net.path().is_none(), "fresh netns, not a joined one");
        // The userns + mappings must still be present (docker mode is NOT privileged).
        assert!(nss.iter().any(|n| n.typ() == LinuxNamespaceType::User));
        assert!(spec.linux().as_ref().unwrap().uid_mappings().is_some());
    }

    #[test]
    fn non_docker_spec_still_drops_network_namespace() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let nss = spec.linux().as_ref().unwrap().namespaces().clone().unwrap();
        assert!(!nss.iter().any(|n| n.typ() == LinuxNamespaceType::Network));
    }

    #[test]
    fn docker_mode_gets_rw_cgroup_mount() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut params = base_params(&img);
        params.docker = true;
        let spec = generate_spec(&params).unwrap();
        let m = spec
            .mounts()
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.destination().to_string_lossy() == "/sys/fs/cgroup")
            .unwrap();
        let opts = m.options().clone().unwrap();
        assert!(opts.iter().any(|o| o == "rw") && !opts.iter().any(|o| o == "ro"));
    }

    #[test]
    fn docker_mode_unlocks_only_proc_sys_net_and_keeps_every_other_readonly_path() {
        // dockerd cannot bring up its default bridge without writing
        // /proc/sys/net/ipv4/ip_forward (real-boot failure, Task 7). ONLY the
        // net subtree is unlocked: the blanket /proc/sys entry is replaced by
        // its non-net children, because non-net sysctls are gated by a plain
        // euid check with no namespace component — container root maps to
        // guest root in common id maps, so an unlocked /proc/sys/kernel would
        // be a real escape hatch.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut params = base_params(&img);
        params.docker = true;
        let spec = generate_spec(&params).unwrap();
        let ro = spec
            .linux()
            .as_ref()
            .unwrap()
            .readonly_paths()
            .clone()
            .expect("readonlyPaths present");
        assert!(
            !ro.iter().any(|p| p == "/proc/sys"),
            "the blanket /proc/sys entry must be gone (it would keep net RO), got {ro:?}"
        );
        // Every non-net sysctl subtree is pinned read-only, one entry each.
        for keep in DOCKER_READONLY_PROC_SYS {
            assert!(
                ro.iter().any(|p| p == keep),
                "{keep} must stay read-only in docker mode, got {ro:?}"
            );
        }
        // The escape-hatch subtrees specifically (belt and braces: this list is
        // what a future edit of DOCKER_READONLY_PROC_SYS must not lose).
        for critical in ["/proc/sys/kernel", "/proc/sys/vm", "/proc/sys/fs"] {
            assert!(ro.iter().any(|p| p == critical), "{critical} must be RO");
        }
        // ...and net is NOT read-only, under any prefix spelling.
        assert!(
            !ro.iter().any(|p| p.starts_with("/proc/sys/net")),
            "/proc/sys/net must stay writable for dockerd, got {ro:?}"
        );
        // The non-/proc/sys defaults survive.
        for keep in ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sysrq-trigger"] {
            assert!(
                ro.iter().any(|p| p == keep),
                "{keep} must stay read-only in docker mode, got {ro:?}"
            );
        }
        // maskedPaths are untouched — this is NOT `--privileged`.
        let masked = spec
            .linux()
            .as_ref()
            .unwrap()
            .masked_paths()
            .clone()
            .expect("maskedPaths present");
        assert!(masked.iter().any(|p| p == "/proc/kcore"));
    }

    #[test]
    fn non_docker_spec_gets_no_proc_sys_children() {
        // The narrowing is docker-mode-only: a normal sandbox keeps the single
        // blanket entry and gains none of the per-child ones.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let ro = spec
            .linux()
            .as_ref()
            .unwrap()
            .readonly_paths()
            .clone()
            .expect("readonlyPaths present");
        for child in DOCKER_READONLY_PROC_SYS {
            assert!(
                !ro.iter().any(|p| p == child),
                "non-docker spec must not carry {child}, got {ro:?}"
            );
        }
    }

    // ---- docker-mode rootless container-0 ≠ guest-0 invariant ----

    #[test]
    fn docker_userns_isolates_root_holds_for_every_shifted_shape() {
        // F-32 holds BY CONSTRUCTION for the shifted map: container-root maps
        // to BASE (owner 0 / workload≠0 shapes) or to the non-zero owner
        // (workload 0). The predicate stays as a regression tripwire over the
        // actual mappings, exercised across every shape — including the ones
        // the old transpose could not satisfy (owner==workload, both-zero).
        for (owner, workload) in [
            ((1000, 1000), (0, 0)),
            ((0, 0), (101, 101)),
            ((0, 0), (0, 0)),
            ((1000, 1000), (1000, 1000)),
            ((1000, 1000), (101, 101)),
            ((1000, 0), (0, 0)),
            ((0, 1000), (0, 0)),
        ] {
            let (uid_maps, gid_maps) =
                compute_docker_userns_mappings(owner, workload).expect("maps build");
            assert!(
                docker_userns_isolates_root(&uid_maps, &gid_maps),
                "shifted map must isolate container-root for owner={owner:?} workload={workload:?}"
            );
        }
        // And the tripwire still bites on a genuinely violating map (the old
        // transpose identity shape).
        let (u, g) = compute_userns_mappings((1000, 1000), (1000, 1000));
        assert!(!docker_userns_isolates_root(&u, &g));
    }

    #[test]
    fn docker_start_succeeds_for_non_root_user_image_on_same_uid_workspace() {
        // THE claude-code-docker regression gate: image USER 1000 on a
        // uid-1000-owned workspace USED to fail closed; the shifted map makes
        // it start, with container-root isolated and the USER owning the
        // workspace-owner id.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"], "User": "1000:1000" }));
        let mut p = base_params(&img);
        p.docker = true;
        p.host_owner = (1000, 1000);
        p.user = (1000, 1000);
        let spec = generate_spec(&p).expect("non-root USER docker sandbox must start");
        let linux = spec.linux().as_ref().unwrap();
        let uid_maps = linux.uid_mappings().clone().expect("uid mappings present");
        assert_eq!(map_c2h(&uid_maps, 0), Some(DOCKER_IDMAP_BASE));
        assert_eq!(map_c2h(&uid_maps, 1000), Some(1000));

        // Non-docker mode keeps the transpose (identity here) untouched.
        let mut ok = base_params(&img);
        ok.docker = false;
        ok.host_owner = (1000, 1000);
        ok.user = (1000, 1000);
        let spec = generate_spec(&ok).expect("non-docker flow unchanged");
        let uid_maps = spec
            .linux()
            .as_ref()
            .unwrap()
            .uid_mappings()
            .clone()
            .expect("uid mappings present");
        assert_eq!(map_c2h(&uid_maps, 0), Some(0));
    }

    #[test]
    fn docker_start_succeeds_on_the_common_non_root_workspace_flow() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.docker = true;
        // base_params already models it: workspace owned by 1000/1000, image
        // USER root. Assert the produced map really isolates container-root.
        assert_eq!(p.host_owner, (1000, 1000));
        assert_eq!(p.user, (0, 0));
        let spec = generate_spec(&p).expect("common docker flow must start");
        let uid_maps = spec
            .linux()
            .as_ref()
            .unwrap()
            .uid_mappings()
            .clone()
            .expect("uid mappings present");
        // container-root gets the carve-out: it owns the workspace (guest
        // 1000), and is never guest-root.
        assert_eq!(map_c2h(&uid_maps, 0), Some(1000));
        // image system uids follow the shift (fidelity comes from the layer
        // idmap presenting disk uids shifted the same way).
        assert_eq!(map_c2h(&uid_maps, 33), Some(DOCKER_IDMAP_BASE + 33));
    }

    #[test]
    fn docker_start_refuses_workload_beyond_mapped_range() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.docker = true;
        p.user = (DOCKER_IDMAP_RANGE + 1, 0);
        let err = generate_spec(&p).expect_err("out-of-range USER must be refused");
        assert!(format!("{err:#}").contains("USER"));
    }

    #[test]
    fn non_docker_spec_keeps_proc_sys_readonly() {
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let spec = generate_spec(&base_params(&img)).unwrap();
        let ro = spec
            .linux()
            .as_ref()
            .unwrap()
            .readonly_paths()
            .clone()
            .expect("readonlyPaths present");
        assert!(
            ro.iter().any(|p| p == "/proc/sys"),
            "a normal sandbox keeps the OCI default /proc/sys read-only remount"
        );
    }

    // ---- privileged builder spec ----

    #[test]
    fn spec_privileged_grants_full_caps_including_sysadmin() {
        // Builder VMs run the in-guest container privileged: rootful buildkit's
        // overlayfs snapshotter needs CAP_SYS_ADMIN for its bind/overlay mounts.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.privileged = true;
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().clone().unwrap();
        let caps = proc.capabilities().clone().expect("capabilities set");
        // The full set: effective/bounding/permitted/inheritable/ambient all
        // contain SysAdmin (and equal the docker-default plus the dropped ones).
        for set in [
            caps.bounding(),
            caps.effective(),
            caps.permitted(),
            caps.inheritable(),
            caps.ambient(),
        ] {
            let set = set.as_ref().expect("cap set present");
            assert!(
                set.contains(&Capability::SysAdmin),
                "privileged spec must grant CAP_SYS_ADMIN"
            );
            // sanity: also still has the everyday ones.
            assert!(set.contains(&Capability::DacOverride));
            assert!(set.contains(&Capability::SysPtrace));
        }
    }

    #[test]
    fn spec_privileged_omits_user_namespace_and_mappings() {
        // Privileged = real container-root == guest-root: NO user namespace and
        // NO uid/gid mappings (rootful buildkit requires real root, not a userns).
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.privileged = true;
        let spec = generate_spec(&p).unwrap();
        let linux = spec.linux().as_ref().unwrap();
        let nss = linux.namespaces().clone().unwrap();
        let types: Vec<LinuxNamespaceType> = nss.iter().map(|n| n.typ()).collect();
        assert!(
            !types.contains(&LinuxNamespaceType::User),
            "privileged spec must NOT add a User namespace"
        );
        // D1 still applies: the builder shares init's netns.
        assert!(
            !types.contains(&LinuxNamespaceType::Network),
            "network namespace must still be dropped for builders (D1)"
        );
        assert!(
            linux.uid_mappings().is_none(),
            "privileged spec must not set uid mappings"
        );
        assert!(
            linux.gid_mappings().is_none(),
            "privileged spec must not set gid mappings"
        );
    }

    /// Helper: the options of the `/sys/fs/cgroup` mount in a generated spec.
    fn cgroup_mount_opts(spec: &Spec) -> Vec<String> {
        spec.mounts()
            .clone()
            .unwrap_or_default()
            .into_iter()
            .find(|m| m.destination().to_string_lossy() == "/sys/fs/cgroup")
            .and_then(|m| m.options().clone())
            .unwrap_or_default()
    }

    #[test]
    fn spec_privileged_mounts_cgroup_writable() {
        // Rootful BuildKit's OCI worker runs each `RUN` step via a nested runc,
        // which must create its own cgroup subtree (`mkdir /sys/fs/cgroup/...`).
        // The OCI default mounts cgroupfs read-only, so the nested runc fails
        // with "read-only file system". Privileged builders mount it rw.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let mut p = base_params(&img);
        p.privileged = true;
        let spec = generate_spec(&p).unwrap();
        let opts = cgroup_mount_opts(&spec);
        assert!(
            opts.iter().any(|o| o == "rw"),
            "privileged builder must mount /sys/fs/cgroup rw; got {opts:?}"
        );
        assert!(
            !opts.iter().any(|o| o == "ro"),
            "privileged builder cgroup mount must not be read-only; got {opts:?}"
        );
    }

    #[test]
    fn spec_non_privileged_keeps_cgroup_readonly() {
        // Regression guard: normal sandboxes keep the OCI-default read-only
        // cgroup mount — only the throwaway builder VM gets the writable one.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let p = base_params(&img); // privileged: false
        let spec = generate_spec(&p).unwrap();
        let opts = cgroup_mount_opts(&spec);
        assert!(
            opts.iter().any(|o| o == "ro"),
            "non-privileged cgroup mount must stay read-only; got {opts:?}"
        );
    }

    #[test]
    fn spec_non_privileged_unchanged_caps_and_userns() {
        // Belt-and-braces: privileged:false (the default) is byte-identical to
        // the established behavior — docker-default caps (no SysAdmin) and a User
        // namespace with mappings.
        let img = image_config(serde_json::json!({ "Cmd": ["/bin/sh"] }));
        let p = base_params(&img); // privileged: false
        let spec = generate_spec(&p).unwrap();
        let proc = spec.process().clone().unwrap();
        let caps = proc.capabilities().clone().unwrap();
        let eff = caps.effective().as_ref().unwrap();
        assert!(!eff.contains(&Capability::SysAdmin));
        assert!(eff.contains(&Capability::DacOverride));
        let linux = spec.linux().as_ref().unwrap();
        let types: Vec<LinuxNamespaceType> = linux
            .namespaces()
            .clone()
            .unwrap()
            .iter()
            .map(|n| n.typ())
            .collect();
        assert!(types.contains(&LinuxNamespaceType::User));
        assert!(!types.contains(&LinuxNamespaceType::Network));
        assert!(linux.uid_mappings().is_some());
        assert!(linux.gid_mappings().is_some());
    }

    // ---- passwd/group parsing + UserDb::resolve ----

    #[test]
    fn parse_passwd_basic_and_skips_junk() {
        let p = parse_passwd(
            "root:x:0:0:root:/root:/bin/sh\n\
             # a comment\n\
             \n\
             node:x:1000:1000:Node:/home/node:/bin/sh\n\
             short:x:1\n\
             #commented:x:999:999::/c:/bin/sh\n",
        );
        // The trailing line is a comment that is ALSO a structurally-valid passwd
        // row: it must be dropped by the leading-`#` skip, NOT parsed (this makes
        // the `is_empty() || starts_with('#')` guard load-bearing — without the
        // `#` arm it would yield a bogus "#commented" uid-999 entry).
        assert_eq!(p.len(), 2);
        assert!(
            p.iter().all(|e| e.uid != 999),
            "a #-commented row must never be parsed as an entry: {p:?}"
        );
        assert_eq!(p[0].name, "root");
        assert_eq!(
            (p[1].name.as_str(), p[1].uid, p[1].gid),
            ("node", 1000, 1000)
        );
    }

    #[test]
    fn parse_group_basic_and_skips_junk() {
        // `#fake:x:777:` is a comment that is also a structurally-valid group row;
        // it must be skipped (not parsed as gid 777), keeping the `#` skip arm
        // load-bearing.
        let g = parse_group("root:x:0:\nwheel:x:10:node\n#c\n\nbad:x\n#fake:x:777:\n");
        assert_eq!(g.len(), 2);
        assert!(
            g.iter().all(|e| e.gid != 777),
            "a #-commented row must never be parsed as a group: {g:?}"
        );
        assert_eq!((g[1].name.as_str(), g[1].gid), ("wheel", 10));
        assert_eq!(g[0].members, Vec::<String>::new());
        assert_eq!(g[1].members, vec!["node".to_string()]);
    }

    #[test]
    fn parse_group_reads_member_list() {
        let g = parse_group("docker:x:999:agent,deploy\nnogroup:x:65534:\n");
        assert_eq!(
            g[0].members,
            vec!["agent".to_string(), "deploy".to_string()]
        );
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
    fn additional_gids_are_always_inside_the_gid_map() {
        // transpose_identity_map is a bijection over 0..USERNS_RANGE_END, so any
        // gid the image's /etc/group can name (u32 < u32::MAX) is mapped; this
        // pins that invariant so a future map change can't silently strand
        // additionalGids outside the userns (setgroups would then fail).
        let (_uids, gids) = compute_userns_mappings((1000, 1000), (0, 0));
        let covered: u64 = gids.iter().map(|m| m.size() as u64).sum();
        assert_eq!(covered, USERNS_RANGE_END as u64);
    }

    #[test]
    fn userdb_resolves_name_to_uid_and_primary_gid() {
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), None);
        assert_eq!(db.resolve("node"), Some((1000, 1000)));
    }

    #[test]
    fn userdb_resolves_name_colon_group_name() {
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), Some("wheel:x:10:\n"));
        assert_eq!(db.resolve("node:wheel"), Some((1000, 10)));
    }

    #[test]
    fn userdb_numeric_uid_does_not_consult_passwd() {
        // Pure-numeric spec keeps docker's default gid 0 even if passwd has 1000.
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), None);
        assert_eq!(db.resolve("1000"), Some((1000, 0)));
        assert_eq!(db.resolve("1000:1001"), Some((1000, 1001)));
    }

    #[test]
    fn userdb_unknown_name_or_group_is_none() {
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), Some("wheel:x:10:\n"));
        assert_eq!(db.resolve("ghost"), None);
        assert_eq!(db.resolve("node:ghostgroup"), None);
    }

    #[test]
    fn userdb_name_colon_numeric_gid() {
        let db = UserDb::from_files(Some("node:x:1000:1000::/:/bin/sh\n"), None);
        assert_eq!(db.resolve("node:42"), Some((1000, 42)));
    }
}
