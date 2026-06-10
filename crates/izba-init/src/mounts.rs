//! Mount planning and execution for the guest boot sequence.
//!
//! Plans are pure data so they can be unit-tested on any host; only
//! [`apply`] performs syscalls (guest-only).

use anyhow::Context;
use nix::mount::MsFlags;
use std::path::PathBuf;

/// One mount(2) invocation, expressed as plain data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountOp {
    pub source: String,
    pub target: PathBuf,
    pub fstype: String,
    pub flags: Vec<String>,
    pub data: String,
}

impl MountOp {
    fn new(source: &str, target: &str, fstype: &str, flags: &[&str], data: &str) -> Self {
        Self {
            source: source.to_string(),
            target: PathBuf::from(target),
            fstype: fstype.to_string(),
            flags: flags.iter().map(|f| f.to_string()).collect(),
            data: data.to_string(),
        }
    }
}

/// Pseudo-filesystems needed immediately after the kernel hands over to init.
pub fn boot_mount_plan() -> Vec<MountOp> {
    vec![
        MountOp::new("proc", "/proc", "proc", &["nosuid", "nodev", "noexec"], ""),
        MountOp::new("sysfs", "/sys", "sysfs", &["nosuid", "nodev", "noexec"], ""),
        MountOp::new("devtmpfs", "/dev", "devtmpfs", &["nosuid"], ""),
        // devpts in init's OWN root, not just under /rootfs. The exec engine
        // calls openpty() for tty jobs (exec.rs) from init's context, before
        // the child chroots into /rootfs. openpty opens /dev/ptmx, and the
        // kernel's ptmx_open → devpts_acquire → path_pts requires /dev/ptmx's
        // sibling /dev/pts to be a devpts mount; without it openpty fails with
        // ENODEV. The child inherits the already-opened slave fd (dup2'd by
        // std before chroot), so it never reopens by path — only init needs a
        // working /dev/ptmx here. /rootfs/dev/pts (rootfs_mount_plan) is still
        // mounted separately for workloads that allocate their own ptys.
        MountOp::new(
            "devpts",
            "/dev/pts",
            "devpts",
            &["nosuid", "noexec"],
            "gid=5,mode=620,ptmxmode=666",
        ),
        MountOp::new("tmpfs", "/tmp", "tmpfs", &["nosuid", "nodev"], ""),
    ]
}

/// Mounts the image (ro lower), the rw disk (upper), then the overlay and
/// everything the workload chroot needs.
///
/// NOTE: [`upper_prep_dirs`] must be created between op 2 (/upper) and op 3
/// (the overlay): overlayfs requires upperdir/workdir to exist. Callers split
/// the plan at the overlay op for that interlude.
pub fn rootfs_mount_plan() -> Vec<MountOp> {
    vec![
        MountOp::new("/dev/vda", "/lower", "erofs", &["ro"], ""),
        MountOp::new("/dev/vdb", "/upper", "ext4", &[], ""),
        MountOp::new(
            "overlay",
            "/rootfs",
            "overlay",
            &[],
            "lowerdir=/lower,upperdir=/upper/data,workdir=/upper/work",
        ),
        MountOp::new("workspace", "/rootfs/workspace", "virtiofs", &[], ""),
        MountOp::new(
            "proc",
            "/rootfs/proc",
            "proc",
            &["nosuid", "nodev", "noexec"],
            "",
        ),
        MountOp::new(
            "sysfs",
            "/rootfs/sys",
            "sysfs",
            &["nosuid", "nodev", "noexec"],
            "",
        ),
        MountOp::new("devtmpfs", "/rootfs/dev", "devtmpfs", &["nosuid"], ""),
        MountOp::new("tmpfs", "/rootfs/tmp", "tmpfs", &["nosuid", "nodev"], ""),
        MountOp::new(
            "devpts",
            "/rootfs/dev/pts",
            "devpts",
            &["nosuid", "noexec"],
            "gid=5,mode=620,ptmxmode=666",
        ),
    ]
}

/// Directories that must exist on the freshly mounted rw disk before the
/// overlay mount (upperdir and workdir).
pub fn upper_prep_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from("/upper/data"), PathBuf::from("/upper/work")]
}

fn flags_to_ms(flags: &[String]) -> anyhow::Result<MsFlags> {
    let mut ms = MsFlags::empty();
    for f in flags {
        ms |= match f.as_str() {
            "ro" => MsFlags::MS_RDONLY,
            "nosuid" => MsFlags::MS_NOSUID,
            "nodev" => MsFlags::MS_NODEV,
            "noexec" => MsFlags::MS_NOEXEC,
            "relatime" => MsFlags::MS_RELATIME,
            "noatime" => MsFlags::MS_NOATIME,
            other => anyhow::bail!("unknown mount flag {other:?}"),
        };
    }
    Ok(ms)
}

/// Pause required before mounting `op`, if any.
///
/// OpenVMM runs all in-process virtio device workers on a single shared host
/// thread, and the virtiofs worker only arms its queue-notification wait on
/// its first poll. If the guest never yields the CPU between DRIVER_OK and
/// FUSE_INIT (this mount loop runs back-to-back), that thread may not have
/// been scheduled yet and the guest blocks indefinitely in
/// `mount(virtiofs, ...)`. Any guest pause — experimentally as little as a
/// silent 20 ms sleep — lets the host schedule the worker, which then services
/// the already-enqueued (never lost) FUSE_INIT. Cloud Hypervisor's external
/// virtiofsd is polling before the guest boots, so it is unaffected by the
/// extra 50 ms. Full analysis + upstream-issue draft:
/// docs/superpowers/specs/2026-06-10-openvmm-virtiofs-hang-rca.md
pub fn pre_mount_pause(op: &MountOp) -> Option<std::time::Duration> {
    (op.fstype == "virtiofs").then(|| std::time::Duration::from_millis(50))
}

/// Executes a mount plan in order, creating target directories first.
/// Guest-only: requires CAP_SYS_ADMIN.
///
/// The per-mount `eprintln!` lines are boot diagnostics on the serial console;
/// the OpenVMM-readiness accommodation is [`pre_mount_pause`], not the prints.
pub fn apply(ops: &[MountOp]) -> anyhow::Result<()> {
    for op in ops {
        std::fs::create_dir_all(&op.target)
            .with_context(|| format!("creating mount target {}", op.target.display()))?;
        let flags = flags_to_ms(&op.flags)?;
        let data = if op.data.is_empty() {
            None
        } else {
            Some(op.data.as_str())
        };
        eprintln!(
            "izba-init: mounting {} ({}) on {}",
            op.source,
            op.fstype,
            op.target.display()
        );
        if let Some(pause) = pre_mount_pause(op) {
            std::thread::sleep(pause);
        }
        nix::mount::mount(
            Some(op.source.as_str()),
            &op.target,
            Some(op.fstype.as_str()),
            flags,
            data,
        )
        .with_context(|| {
            format!(
                "mounting {} ({}) on {}",
                op.source,
                op.fstype,
                op.target.display()
            )
        })?;
        eprintln!(
            "izba-init: mounted {} ({}) on {} OK",
            op.source,
            op.fstype,
            op.target.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(v: &[MountOp], i: usize) -> (&str, &str, &str, Vec<&str>, &str) {
        let o = &v[i];
        (
            o.source.as_str(),
            o.target.to_str().unwrap(),
            o.fstype.as_str(),
            o.flags.iter().map(|s| s.as_str()).collect(),
            o.data.as_str(),
        )
    }

    #[test]
    fn boot_plan_sequence() {
        let p = boot_mount_plan();
        assert_eq!(p.len(), 5);
        assert_eq!(
            op(&p, 0),
            (
                "proc",
                "/proc",
                "proc",
                vec!["nosuid", "nodev", "noexec"],
                ""
            )
        );
        assert_eq!(
            op(&p, 1),
            (
                "sysfs",
                "/sys",
                "sysfs",
                vec!["nosuid", "nodev", "noexec"],
                ""
            )
        );
        assert_eq!(
            op(&p, 2),
            ("devtmpfs", "/dev", "devtmpfs", vec!["nosuid"], "")
        );
        assert_eq!(
            op(&p, 3),
            (
                "devpts",
                "/dev/pts",
                "devpts",
                vec!["nosuid", "noexec"],
                "gid=5,mode=620,ptmxmode=666"
            )
        );
        assert_eq!(
            op(&p, 4),
            ("tmpfs", "/tmp", "tmpfs", vec!["nosuid", "nodev"], "")
        );
    }

    #[test]
    fn rootfs_plan_sequence() {
        let p = rootfs_mount_plan();
        assert_eq!(p.len(), 9);
        assert_eq!(op(&p, 0), ("/dev/vda", "/lower", "erofs", vec!["ro"], ""));
        assert_eq!(op(&p, 1), ("/dev/vdb", "/upper", "ext4", vec![], ""));
        assert_eq!(
            op(&p, 2),
            (
                "overlay",
                "/rootfs",
                "overlay",
                vec![],
                "lowerdir=/lower,upperdir=/upper/data,workdir=/upper/work"
            )
        );
        assert_eq!(
            op(&p, 3),
            ("workspace", "/rootfs/workspace", "virtiofs", vec![], "")
        );
        assert_eq!(
            op(&p, 4),
            (
                "proc",
                "/rootfs/proc",
                "proc",
                vec!["nosuid", "nodev", "noexec"],
                ""
            )
        );
        assert_eq!(
            op(&p, 5),
            (
                "sysfs",
                "/rootfs/sys",
                "sysfs",
                vec!["nosuid", "nodev", "noexec"],
                ""
            )
        );
        assert_eq!(
            op(&p, 6),
            ("devtmpfs", "/rootfs/dev", "devtmpfs", vec!["nosuid"], "")
        );
        assert_eq!(
            op(&p, 7),
            ("tmpfs", "/rootfs/tmp", "tmpfs", vec!["nosuid", "nodev"], "")
        );
        assert_eq!(
            op(&p, 8),
            (
                "devpts",
                "/rootfs/dev/pts",
                "devpts",
                vec!["nosuid", "noexec"],
                "gid=5,mode=620,ptmxmode=666"
            )
        );
    }

    #[test]
    fn upper_prep_dirs_precede_overlay() {
        assert_eq!(
            upper_prep_dirs(),
            vec![PathBuf::from("/upper/data"), PathBuf::from("/upper/work")]
        );
        // The overlay op must reference exactly these dirs.
        let overlay = &rootfs_mount_plan()[2];
        assert!(overlay.data.contains("upperdir=/upper/data"));
        assert!(overlay.data.contains("workdir=/upper/work"));
    }

    #[test]
    fn virtiofs_gets_pre_mount_pause() {
        let plan = rootfs_mount_plan();
        for op in &plan {
            let pause = pre_mount_pause(op);
            if op.fstype == "virtiofs" {
                assert!(
                    pause.is_some_and(|d| d >= std::time::Duration::from_millis(20)),
                    "virtiofs mounts need >= 20ms pause (OpenVMM scheduling lag)"
                );
            } else {
                assert_eq!(pause, None, "{} must not pause", op.fstype);
            }
        }
    }

    #[test]
    fn unknown_flag_rejected() {
        assert!(flags_to_ms(&["bogus".to_string()]).is_err());
    }

    #[test]
    fn known_flags_map() {
        let ms = flags_to_ms(&[
            "ro".into(),
            "nosuid".into(),
            "nodev".into(),
            "noexec".into(),
        ])
        .unwrap();
        assert!(ms.contains(MsFlags::MS_RDONLY));
        assert!(ms.contains(MsFlags::MS_NOSUID));
        assert!(ms.contains(MsFlags::MS_NODEV));
        assert!(ms.contains(MsFlags::MS_NOEXEC));
    }
}
