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
    Capability, LinuxCapabilitiesBuilder, LinuxNamespaceBuilder, LinuxNamespaceType,
    ProcessBuilder, RootBuilder, Spec, UserBuilder,
};
use std::collections::HashSet;

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

/// Parse a numeric OCI/docker `User` spec into `(uid, gid)`.
///
/// `"1000:1000"` → `(1000, 1000)`; `"1000"` → `(1000, 0)` (docker's gid default
/// for a numeric uid without a passwd lookup); `""` → `(0, 0)`. Returns `None`
/// when either component is a non-numeric *name* — that requires resolving
/// against the container's `/etc/passwd`, which is deferred to the guest side
/// (Phase 4), not guessed host-side.
pub fn parse_numeric_user(user: &str) -> Option<(u32, u32)> {
    if user.is_empty() {
        return Some((0, 0));
    }
    match user.split_once(':') {
        Some((u, g)) => Some((u.parse().ok()?, g.parse().ok()?)),
        None => Some((user.parse().ok()?, 0)),
    }
}

/// Resolve an image's declared `USER` to a numeric `(uid, gid)` for config.json,
/// plus an optional loud warning.
///
/// crun's `config.json` `process.user` is numeric-only per the OCI runtime spec,
/// so a symbolic username cannot be passed through and resolving it would require
/// reading the image's `/etc/passwd` out of the overlay (not available here);
/// proper symbolic→numeric resolution is a deferred follow-up. Until then a
/// non-empty symbolic/unparseable USER falls back to root `(0, 0)` — but **loudly**
/// (izba never silently downgrades security), via the returned `Some(msg)`.
///
/// - `None` (no declared USER) / `Some("")` (explicit root) → `((0, 0), None)`.
/// - numeric (`"1000"`, `"1000:1001"`) → resolved pair, `None` warning.
/// - symbolic / partly-symbolic (`"node"`, `"1000:wheel"`) → `((0, 0), Some(msg))`,
///   `msg` naming the offending USER string.
pub fn resolve_process_user(declared: Option<&str>) -> ((u32, u32), Option<String>) {
    match declared {
        None | Some("") => ((0, 0), None),
        Some(u) => match parse_numeric_user(u) {
            Some(ids) => (ids, None),
            None => (
                (0, 0),
                Some(format!(
                    "image USER '{u}' is not numeric; izba cannot resolve symbolic users yet \
                     — running the workload as root (uid 0)"
                )),
            ),
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
    if workload_id == owner_id {
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
    /// Already-resolved process user `(uid, gid)` (see [`parse_numeric_user`]).
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
}

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

    let user = UserBuilder::default()
        .uid(params.user.0)
        .gid(params.user.1)
        .build()?;
    // Privileged builder VMs get the full capability set (rootful buildkit needs
    // CAP_SYS_ADMIN for its overlayfs bind/overlay mounts); normal sandboxes get
    // the least-privilege docker-default set.
    let caps = if params.privileged {
        all_caps()?
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
            nss.retain(|n| n.typ() != LinuxNamespaceType::Network);
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
            let (uid_maps, gid_maps) = compute_userns_mappings(params.host_owner, params.user);
            linux.set_uid_mappings(Some(uid_maps));
            linux.set_gid_mappings(Some(gid_maps));
        }
    }

    // Present `/sys` as a recursive bind of the host `/sys`, not a fresh `sysfs`
    // mount. The container runs in the Option-A user namespace (above) while
    // still SHARING izba-init's network namespace (D1, `network` dropped). The
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

    // Privileged builders: mount `/sys/fs/cgroup` read-WRITE. The OCI default
    // mounts cgroupfs read-only, but rootful BuildKit's OCI worker runs each
    // `RUN` step via a nested runc that must create its own cgroup subtree
    // (`mkdir /sys/fs/cgroup/<id>`) — read-only cgroupfs fails it with
    // "unable to apply cgroup configuration: ... read-only file system". The
    // throwaway builder VM is the trust boundary, so a writable cgroupfs is
    // acceptable. Normal sandboxes keep the read-only default.
    if params.privileged {
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

    Ok(spec)
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

    // ---- numeric user ----

    #[test]
    fn user_uid_and_gid() {
        assert_eq!(parse_numeric_user("1000:1001"), Some((1000, 1001)));
    }

    #[test]
    fn user_uid_only_defaults_gid_zero() {
        assert_eq!(parse_numeric_user("1000"), Some((1000, 0)));
    }

    #[test]
    fn user_empty_is_root() {
        assert_eq!(parse_numeric_user(""), Some((0, 0)));
    }

    #[test]
    fn user_name_needs_passwd_resolution() {
        assert_eq!(parse_numeric_user("node"), None);
        assert_eq!(parse_numeric_user("node:1000"), None);
        assert_eq!(parse_numeric_user("1000:wheel"), None);
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

    // ---- resolve_process_user (config.json USER → (uid,gid) + loud warning) ----

    #[test]
    fn resolve_process_user_none_is_silent_root() {
        assert_eq!(resolve_process_user(None), ((0, 0), None));
    }

    #[test]
    fn resolve_process_user_empty_is_silent_root() {
        assert_eq!(resolve_process_user(Some("")), ((0, 0), None));
    }

    #[test]
    fn resolve_process_user_numeric_uid_only_silent() {
        assert_eq!(resolve_process_user(Some("1000")), ((1000, 0), None));
    }

    #[test]
    fn resolve_process_user_numeric_uid_gid_silent() {
        assert_eq!(
            resolve_process_user(Some("1000:1001")),
            ((1000, 1001), None)
        );
    }

    #[test]
    fn resolve_process_user_symbolic_name_is_loud_root() {
        let ((uid, gid), warn) = resolve_process_user(Some("node"));
        assert_eq!((uid, gid), (0, 0));
        let msg = warn.expect("symbolic USER must produce a warning");
        assert!(msg.contains("node"), "warning must name the user: {msg}");
    }

    #[test]
    fn resolve_process_user_partly_symbolic_is_loud_root() {
        let ((uid, gid), warn) = resolve_process_user(Some("1000:wheel"));
        assert_eq!((uid, gid), (0, 0));
        let msg = warn.expect("partly-symbolic USER must produce a warning");
        assert!(
            msg.contains("1000:wheel"),
            "warning must name the user: {msg}"
        );
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
        }
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
}
