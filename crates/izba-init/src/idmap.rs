//! Docker-mode layer idmap (uid-fidelity design §2.2): present the erofs
//! lower + ext4 upper (and each user volume) through an idmapped mount whose
//! mapping mirrors the container userns map, so image uids appear verbatim
//! inside the container while guest-0 stays unmapped (the F-32 barrier).
//!
//! The mapping arrives host-authoritatively on the kernel cmdline
//! (`izba.uidmap=`/`izba.gidmap=`, written by izba-core's
//! `layer_idmap_cmdline_value`) as comma-separated `disk-presented-size`
//! triples — ALREADY in mount-idmap orientation: an idmapped mount computes
//! `presented = make_kuid(mnt_userns, disk_uid)`, i.e. the disk uid is the
//! namespace-INNER id, so a `uid_map` line reads `<disk> <presented> <n>`
//! (verified on a real VM; an inverted first cut presented every image-root
//! file as `nobody`). The final triple is the fsuid-0 anchor
//! (`<RANGE>-0-1`): guest-root writers with no other reverse mapping —
//! overlayfs whiteouts/copy-ups run with the MOUNTER's creds, crun mkdirs
//! missing mount targets — land on a disk id no image uses instead of
//! failing `EOVERFLOW`.
//!
//! izba-init's own meaningful writes into `/rootfs` (resolv.conf, the trust
//! CA, `izba cp` extraction) run under [`with_fs_ids`] using
//! [`presented_of_disk_zero`] so they land as disk-0 = container-root-owned,
//! exactly like a normal system. **Invariant: any future init write under
//! `/rootfs` must do the same in docker mode.**
//!
//! Pure logic (parsing, map-line rendering, reverse lookup) is host-tested;
//! the syscall glue (userns helper child + open_tree/mount_setattr/
//! move_mount) only runs in the guest and is exercised by the docker-mode
//! KVM e2e.

use std::path::Path;

/// One layer-idmap extent, in mount-idmap orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdExtent {
    /// Id as stored on disk (the image/upper/volume filesystem) — the mount
    /// userns's INNER id.
    pub disk: u32,
    /// Id the guest (and the mount) presents — the OUTER id.
    pub presented: u32,
    /// Number of consecutive ids covered.
    pub size: u32,
}

/// Parse an `izba.uidmap=`/`izba.gidmap=` value: comma-separated
/// `disk-presented-size` triples. Rejects empty lists, malformed triples and
/// zero sizes — a docker-mode boot without a valid layer map must fail
/// loudly, never proceed to a scrambled rootfs.
pub fn parse_cmdline_map(s: &str) -> Result<Vec<IdExtent>, String> {
    let mut out = Vec::new();
    for triple in s.split(',') {
        let parts: Vec<&str> = triple.split('-').collect();
        let [d, p, n] = parts.as_slice() else {
            return Err(format!("malformed idmap triple '{triple}' in '{s}'"));
        };
        let parse = |v: &str, what: &str| {
            v.parse::<u32>()
                .map_err(|_| format!("bad {what} '{v}' in idmap triple '{triple}'"))
        };
        let ext = IdExtent {
            disk: parse(d, "disk id")?,
            presented: parse(p, "presented id")?,
            size: parse(n, "size")?,
        };
        if ext.size == 0 {
            return Err(format!("zero-size idmap triple '{triple}'"));
        }
        out.push(ext);
    }
    if out.is_empty() {
        return Err("empty idmap".to_string());
    }
    Ok(out)
}

/// Render extents as the helper userns's `uid_map`/`gid_map` file content:
/// one `<disk> <presented> <n>` line per extent (`<inner> <outer> <count>`
/// in kernel terms — an idmapped mount treats the on-disk id as the INNER
/// id: `presented = make_kuid(mnt_userns, disk_uid)`).
pub fn map_file_content(extents: &[IdExtent]) -> String {
    let mut s = String::new();
    for e in extents {
        s.push_str(&format!("{} {} {}\n", e.disk, e.presented, e.size));
    }
    s
}

/// The presented id that disk id 0 maps to — the fs id init must adopt (via
/// [`with_fs_ids`]) so its writes through the idmapped rootfs land as disk-0,
/// i.e. container-root-owned. `None` when disk-0 is unmapped (a host bug: the
/// shifted map always covers disk 0; callers fall back to writing as-is,
/// which then lands on the fsuid-0 anchor instead).
pub fn presented_of_disk_zero(extents: &[IdExtent]) -> Option<u32> {
    extents
        .iter()
        .find(|e| e.disk == 0 && e.size > 0)
        .map(|e| e.presented)
}

/// Run `f` with the calling THREAD's fsuid/fsgid switched to `ids`, restoring
/// the previous values afterwards. `setfsuid`/`setfsgid` are per-thread and
/// cannot fail for a privileged caller (they return the previous value), so
/// the guard is infallible; on the host (unprivileged tests) a denied switch
/// silently leaves the fs ids unchanged, which is also the correct no-op.
pub fn with_fs_ids<R>(ids: (u32, u32), f: impl FnOnce() -> R) -> R {
    // SAFETY: setfsuid/setfsgid have no memory-safety concerns; they always
    // return the PREVIOUS id (the only way to query them).
    let prev_uid = unsafe { libc::setfsuid(ids.0 as libc::uid_t) } as u32;
    let prev_gid = unsafe { libc::setfsgid(ids.1 as libc::gid_t) } as u32;
    let r = f();
    unsafe {
        libc::setfsuid(prev_uid as libc::uid_t);
        libc::setfsgid(prev_gid as libc::gid_t);
    }
    r
}

// ── syscall glue (guest-only) ────────────────────────────────────────────────

const OPEN_TREE_CLONE: libc::c_uint = 0x1;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

/// `struct mount_attr` for `mount_setattr(2)` (kernel ≥ 5.12).
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Fork a helper child that unshares a fresh user namespace, write the layer
/// maps into it from the (privileged) parent, grab its ns fd, and reap the
/// child. The returned fd is the mapping vehicle for `mount_setattr`.
// reason: fork/unshare/procfs plumbing — guest-only (init is single-threaded
// at the call point; sandboxed host tests may not even unshare). The pure map
// content it writes is unit-tested via map_file_content.
#[mutants::skip]
fn layer_userns_fd(
    uid_map: &[IdExtent],
    gid_map: &[IdExtent],
) -> anyhow::Result<std::os::fd::OwnedFd> {
    use anyhow::Context as _;
    use nix::sys::signal::{kill, Signal};
    use nix::sys::wait::waitpid;
    use nix::unistd::{fork, ForkResult};
    use std::io::Read as _;

    let (mut r, mut w) = std::io::pipe().context("creating idmap helper pipe")?;
    // SAFETY: called during single-threaded early boot (before any server
    // threads spawn); the child only performs async-signal-safe syscalls.
    match unsafe { fork() }.context("forking idmap helper")? {
        ForkResult::Child => {
            drop(r);
            // SAFETY: plain syscalls, no allocation.
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            if rc == 0 {
                use std::io::Write as _;
                let _ = w.write_all(&[1]);
            }
            // Park until the parent harvests the ns and kills us. Exit on any
            // stray wakeup if the parent died first.
            loop {
                // SAFETY: pause has no preconditions.
                unsafe { libc::pause() };
            }
        }
        ForkResult::Parent { child } => {
            drop(w);
            let mut byte = [0u8; 1];
            r.read_exact(&mut byte)
                .context("idmap helper failed to unshare a user namespace")?;
            let write_map = |file: &str, extents: &[IdExtent]| -> anyhow::Result<()> {
                let path = format!("/proc/{}/{file}", child.as_raw());
                std::fs::write(&path, map_file_content(extents))
                    .with_context(|| format!("writing {path}"))
            };
            let res = (|| -> anyhow::Result<std::os::fd::OwnedFd> {
                write_map("uid_map", uid_map)?;
                write_map("gid_map", gid_map)?;
                // An open ns fd pins the namespace beyond the (soon-reaped)
                // helper child's lifetime.
                let ns = std::fs::File::open(format!("/proc/{}/ns/user", child.as_raw()))
                    .context("opening idmap helper ns/user")?;
                Ok(ns.into())
            })();
            let _ = kill(child, Signal::SIGKILL);
            let _ = waitpid(child, None);
            res
        }
    }
}

/// Replace the mount at each of `paths` with an idmapped clone of itself
/// (mapping = `uid_map`/`gid_map`): `open_tree(OPEN_TREE_CLONE)` →
/// `mount_setattr(MOUNT_ATTR_IDMAP)` → `move_mount` back over the same path.
/// The clone stacks on top of the original, so later path resolution (the
/// overlay's `lowerdir=`/`upperdir=`, the container rootfs) sees the idmapped
/// view. Docker-mode only; failure must abort the boot (a plain-view fallback
/// would scramble every uid the way the old transpose did).
// reason: raw new-mount-API syscalls against live mounts — guest-only;
// exercised end-to-end by the docker-mode KVM e2e (ownership-fidelity
// assertions). Pure inputs (extent lists) are unit-tested separately.
#[mutants::skip]
pub fn apply_layer_idmaps(
    paths: &[&Path],
    uid_map: &[IdExtent],
    gid_map: &[IdExtent],
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    let userns = layer_userns_fd(uid_map, gid_map)?;
    for path in paths {
        let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("path {} contains NUL", path.display()))?;
        // SAFETY: plain syscalls over owned buffers/fds.
        let tree = unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                libc::AT_FDCWD,
                cpath.as_ptr(),
                OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint,
            )
        };
        if tree < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("open_tree({})", path.display()));
        }
        let tree = unsafe { std::os::fd::OwnedFd::from_raw_fd(tree as std::os::fd::RawFd) };
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: userns.as_raw_fd() as u64,
        };
        let empty = std::ffi::CString::new("").expect("static");
        // SAFETY: attr is a valid mount_attr; AT_EMPTY_PATH targets the tree fd.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                tree.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH,
                &attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("mount_setattr(idmap) on {}", path.display()));
        }
        // SAFETY: moves the detached idmapped clone onto its original path.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                tree.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_FDCWD,
                cpath.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("move_mount(idmapped clone) onto {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cmdline_map_accepts_the_layer_shape() {
        // The exact shape izba-core emits for USER 1000 / owner 1000 + anchor.
        let m = parse_cmdline_map("0-2097152-1000,1000-1000-1,1001-2098153-1047575,1048576-0-1")
            .expect("parses");
        assert_eq!(m.len(), 4);
        assert_eq!(
            m[0],
            IdExtent {
                disk: 0,
                presented: 2097152,
                size: 1000
            }
        );
        assert_eq!(
            m[3],
            IdExtent {
                disk: 1048576,
                presented: 0,
                size: 1
            }
        );
    }

    #[test]
    fn parse_cmdline_map_rejects_garbage() {
        assert!(parse_cmdline_map("").is_err());
        assert!(parse_cmdline_map("1-2").is_err());
        assert!(parse_cmdline_map("1-2-3-4").is_err());
        assert!(parse_cmdline_map("a-2-3").is_err());
        assert!(parse_cmdline_map("1-2-0").is_err());
        assert!(parse_cmdline_map("1-2-3,").is_err());
    }

    #[test]
    fn map_file_content_renders_kernel_lines() {
        // Lines are `<disk> <presented> <n>` = `<inner> <outer> <n>`: the
        // on-disk uid is the mount userns's inner id (real-VM verified).
        let m = vec![
            IdExtent {
                disk: 0,
                presented: 2097152,
                size: 1000,
            },
            IdExtent {
                disk: 1048576,
                presented: 0,
                size: 1,
            },
        ];
        assert_eq!(map_file_content(&m), "0 2097152 1000\n1048576 0 1\n");
    }

    #[test]
    fn presented_of_disk_zero_finds_the_shift_extent() {
        let m = parse_cmdline_map("0-2097152-1000,1000-1000-1,1048576-0-1").expect("parses");
        assert_eq!(presented_of_disk_zero(&m), Some(2097152));
        // The anchor (disk RANGE → presented 0) must NOT be confused for it.
        let only_anchor = parse_cmdline_map("1048576-0-1").expect("parses");
        assert_eq!(presented_of_disk_zero(&only_anchor), None);
    }

    #[test]
    fn with_fs_ids_runs_the_closure_and_returns_its_value() {
        // Unprivileged host: the switch is silently denied, which is the
        // correct no-op; the guard must still run the closure transparently.
        let v = with_fs_ids((1234, 1234), || 42);
        assert_eq!(v, 42);
    }
}
