//! OpenVMM backend (Windows/WHP): pure argv construction plus the
//! [`OpenVmmDriver`] that spawns `openvmm.exe`. Unlike Cloud Hypervisor
//! there are NO sidecars — the virtiofs server and consomme networking run
//! in-process inside openvmm (spike S1+ finding (c)), so launch is a single
//! detached spawn and `pids()` is just `[("vmm", id)]`.
//!
//! Flag shapes are pinned by the rung-7 canonical invocation in
//! docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md:
//! `--hv` is mandatory (VPCI vsock + netvsp need it); virtio-blk must be
//! routed via per-disk PCIe root ports (VPCI auto-routing collides device
//! IDs); networking is `--net consomme` (netvsp NIC), not virtio-net.
//! `--processors`/`--memory` are spike-unverified (defaults were used) and
//! get confirmed against `openvmm.exe --help` during Plan 2 bring-up.

use super::spec::{CommandSpec, VmSpec};
use super::{IoStream, VmHandle, VmmDriver};
use crate::procmgr::{kill_pid, pid_alive, spawn_detached};
use crate::state::PidIdentity;
use crate::vsock::hybrid_connect;
use anyhow::Context;
use std::path::{Path, PathBuf};

#[cfg(windows)]
const OPENVMM_EXE: &str = "openvmm.exe";
#[cfg(not(windows))]
const OPENVMM_EXE: &str = "openvmm";

/// Locate `openvmm`: explicit `$IZBA_OPENVMM` override, then a copy bundled
/// next to the running executable (`<exe dir>/libexec/`), then `$PATH`.
pub fn find_openvmm() -> anyhow::Result<PathBuf> {
    crate::discover::find_tool("IZBA_OPENVMM", OPENVMM_EXE)
}

/// PCIe root-port name for disk `i`: vda, vdb, … — mirrors the guest's
/// virtio-blk device names so the disk-order contract (rootfs = vda,
/// rw = vdb) stays legible end to end.
fn disk_port(i: usize) -> String {
    assert!(i < 26, "more than 26 disks is not a supported VmSpec");
    format!("vd{}", (b'a' + i as u8) as char)
}

/// OpenVMM device flags are comma-separated values (`file:<path>,ro,...`,
/// `pcie_port=<port>:<tag>,<path>`); a comma inside an embedded path would
/// silently truncate it into a bogus option list. Reject early with a clear
/// error instead.
fn reject_commas(spec: &VmSpec) -> anyhow::Result<()> {
    for disk in &spec.disks {
        if disk.path.display().to_string().contains(',') {
            anyhow::bail!(
                "disk path {} contains a comma, which the openvmm --virtio-blk \
                 syntax cannot carry — move the izba data root to a comma-free path",
                disk.path.display()
            );
        }
    }
    for share in &spec.shares {
        if share.host_path.display().to_string().contains(',') {
            anyhow::bail!(
                "workspace path {} contains a comma, which the openvmm --virtio-fs \
                 syntax cannot carry — use a comma-free workspace directory",
                share.host_path.display()
            );
        }
    }
    Ok(())
}

pub fn build_invocation(spec: &VmSpec, openvmm: &Path) -> CommandSpec {
    let vsock_sock = spec.run_dir.join("vsock.sock");
    let mut argv = vec![
        openvmm.display().to_string(),
        "--kernel".to_string(),
        spec.kernel.display().to_string(),
        "--initrd".to_string(),
        spec.initramfs.display().to_string(),
        "-c".to_string(),
        spec.cmdline.clone(),
        "--hv".to_string(),
        "--processors".to_string(),
        spec.cpus.to_string(),
        "--memory".to_string(),
        format!("{}MB", spec.mem_mb),
        "--com1".to_string(),
        format!("file={}", spec.console_log.display()),
        "--pcie-root-complex".to_string(),
        "rc0".to_string(),
    ];
    for i in 0..spec.disks.len() {
        argv.push("--pcie-root-port".to_string());
        argv.push(format!("rc0:{}", disk_port(i)));
    }
    for share in &spec.shares {
        argv.push("--pcie-root-port".to_string());
        argv.push(format!("rc0:fs-{}", share.tag));
    }
    for (i, disk) in spec.disks.iter().enumerate() {
        let ro = if disk.readonly { ",ro" } else { "" };
        argv.push("--virtio-blk".to_string());
        argv.push(format!(
            "file:{}{ro},pcie_port={}",
            disk.path.display(),
            disk_port(i)
        ));
    }
    for share in &spec.shares {
        argv.push("--virtio-fs".to_string());
        argv.push(format!(
            "pcie_port=fs-{}:{},{}",
            share.tag,
            share.tag,
            share.host_path.display()
        ));
    }
    if spec.net {
        argv.push("--net".to_string());
        argv.push("consomme".to_string());
    }
    argv.push("--virtio-vsock-path".to_string());
    argv.push(vsock_sock.display().to_string());
    CommandSpec { argv }
}

/// Spawns openvmm as a single detached process.
///
/// Integration-tested on the Windows spike host (Plan 2); not unit-tested —
/// `build_invocation` carries the testable logic.
pub struct OpenVmmDriver;

impl VmmDriver for OpenVmmDriver {
    fn launch(&self, spec: &VmSpec) -> anyhow::Result<Box<dyn VmHandle>> {
        reject_commas(spec)?;
        std::fs::create_dir_all(&spec.run_dir)
            .with_context(|| format!("creating {}", spec.run_dir.display()))?;
        let log_dir = spec
            .console_log
            .parent()
            .context("console_log has no parent directory")?;
        std::fs::create_dir_all(log_dir)
            .with_context(|| format!("creating {}", log_dir.display()))?;

        let openvmm = find_openvmm()?;
        let inv = build_invocation(spec, &openvmm);

        // A crashed previous run leaves the AF_UNIX socket file behind;
        // openvmm must be able to re-bind it.
        let vsock_sock = spec.run_dir.join("vsock.sock");
        match std::fs::remove_file(&vsock_sock) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("removing stale {}", vsock_sock.display()))
            }
        }

        // Guest serial goes to spec.console_log via --com1 file=; openvmm's
        // own stdout/stderr go to a sibling vmm.log.
        let vmm_id = spawn_detached(&inv, &log_dir.join("vmm.log")).context("spawning openvmm")?;

        Ok(Box::new(OpenVmmHandle {
            vsock_sock,
            vmm: ("vmm".to_string(), vmm_id),
        }))
    }
}

/// Handle to a launched openvmm VM — exactly one process, no sidecars.
struct OpenVmmHandle {
    vsock_sock: PathBuf,
    vmm: (String, PidIdentity),
}

impl VmHandle for OpenVmmHandle {
    fn connect(&self, port: u32) -> anyhow::Result<Box<dyn IoStream>> {
        let s = hybrid_connect(&self.vsock_sock, port)?;
        Ok(Box::new(s))
    }

    fn pids(&self) -> Vec<(String, PidIdentity)> {
        vec![self.vmm.clone()]
    }

    fn is_alive(&self) -> bool {
        pid_alive(&self.vmm.1)
    }

    fn kill(&mut self) -> anyhow::Result<()> {
        kill_pid(&self.vmm.1).context("killing vmm")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::spec::{BlockDisk, FsShare, VmSpec};
    use std::path::PathBuf;

    fn base_spec() -> VmSpec {
        VmSpec {
            kernel: PathBuf::from("/img/vmlinux"),
            initramfs: PathBuf::from("/img/initramfs.img"),
            cmdline: "console=ttyS0 ip=dhcp izba.hostname=box".to_string(),
            cpus: 2,
            mem_mb: 4096,
            disks: vec![
                BlockDisk {
                    path: PathBuf::from("/img/rootfs.erofs"),
                    readonly: true,
                },
                BlockDisk {
                    path: PathBuf::from("/sbx/rw.img"),
                    readonly: false,
                },
            ],
            shares: vec![FsShare {
                tag: "workspace".to_string(),
                host_path: PathBuf::from("/home/user/project"),
            }],
            net: true,
            console_log: PathBuf::from("/sbx/console.log"),
            run_dir: PathBuf::from("/sbx/run"),
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn openvmm_invocation() {
        let inv = build_invocation(&base_spec(), &PathBuf::from("/opt/openvmm"));
        assert_eq!(
            inv.argv,
            argv(&[
                "/opt/openvmm",
                "--kernel",
                "/img/vmlinux",
                "--initrd",
                "/img/initramfs.img",
                "-c",
                "console=ttyS0 ip=dhcp izba.hostname=box",
                "--hv",
                "--processors",
                "2",
                "--memory",
                "4096MB",
                "--com1",
                "file=/sbx/console.log",
                "--pcie-root-complex",
                "rc0",
                "--pcie-root-port",
                "rc0:vda",
                "--pcie-root-port",
                "rc0:vdb",
                "--pcie-root-port",
                "rc0:fs-workspace",
                "--virtio-blk",
                "file:/img/rootfs.erofs,ro,pcie_port=vda",
                "--virtio-blk",
                "file:/sbx/rw.img,pcie_port=vdb",
                "--virtio-fs",
                "pcie_port=fs-workspace:workspace,/home/user/project",
                "--net",
                "consomme",
                "--virtio-vsock-path",
                "/sbx/run/vsock.sock",
            ])
        );
    }

    #[test]
    fn openvmm_invocation_no_net() {
        let mut spec = base_spec();
        spec.net = false;
        let inv = build_invocation(&spec, &PathBuf::from("/opt/openvmm"));
        assert!(!inv.argv.contains(&"--net".to_string()));
        assert!(!inv.argv.contains(&"consomme".to_string()));
        // vsock stays:
        assert!(inv.argv.contains(&"--virtio-vsock-path".to_string()));
    }

    #[test]
    fn openvmm_invocation_multi_share() {
        let mut spec = base_spec();
        spec.shares.push(FsShare {
            tag: "cache".to_string(),
            host_path: PathBuf::from("/home/user/.cache/izba"),
        });
        let inv = build_invocation(&spec, &PathBuf::from("/opt/openvmm"));
        let joined = inv.argv.join(" ");
        assert!(joined.contains("--pcie-root-port rc0:fs-workspace"));
        assert!(joined.contains("--pcie-root-port rc0:fs-cache"));
        assert!(joined.contains("pcie_port=fs-cache:cache,/home/user/.cache/izba"));
    }

    #[test]
    fn disk_ports_follow_disk_order() {
        // The vda/vdb naming is a contract with the guest mount plan: disk 0
        // (rootfs.erofs) must enumerate first. Three disks → vda vdb vdc.
        let mut spec = base_spec();
        spec.disks.push(BlockDisk {
            path: PathBuf::from("/x/extra.img"),
            readonly: false,
        });
        let inv = build_invocation(&spec, &PathBuf::from("/opt/openvmm"));
        let joined = inv.argv.join(" ");
        assert!(joined.contains("file:/img/rootfs.erofs,ro,pcie_port=vda"));
        assert!(joined.contains("file:/sbx/rw.img,pcie_port=vdb"));
        assert!(joined.contains("file:/x/extra.img,pcie_port=vdc"));
    }

    #[test]
    fn comma_in_share_path_rejected() {
        let mut spec = base_spec();
        spec.shares[0].host_path = PathBuf::from("/home/user/a,b");
        let err = reject_commas(&spec).unwrap_err();
        assert!(err.to_string().contains("comma"), "got: {err:#}");
    }

    #[test]
    fn comma_free_spec_accepted() {
        assert!(reject_commas(&base_spec()).is_ok());
    }
}
