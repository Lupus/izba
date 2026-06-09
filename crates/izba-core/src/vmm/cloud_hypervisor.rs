//! Cloud-hypervisor backend: pure argv construction for a microVM plus its
//! sidecars (one virtiofsd per shared dir, optional passt for user-mode
//! networking), and the [`CloudHypervisorDriver`] that spawns them.

use super::spec::{CommandSpec, VmSpec};
use super::{IoStream, VmHandle, VmmDriver};
use crate::procmgr::{kill_pid, pid_alive, spawn_detached};
use crate::state::PidIdentity;
use crate::vsock::hybrid_connect;
use anyhow::{bail, Context};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The set of commands needed to boot one VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocations {
    /// One per share, order matches `spec.shares`.
    pub virtiofsd: Vec<CommandSpec>,
    pub passt: Option<CommandSpec>,
    pub vmm: CommandSpec,
}

pub fn build_invocations(spec: &VmSpec) -> Invocations {
    let run = &spec.run_dir;
    let fs_sock = |tag: &str| run.join(format!("fs-{tag}.sock"));
    let net_sock = run.join("net.sock");
    let vsock_sock = run.join("vsock.sock");
    let api_sock = run.join("ch-api.sock");

    let virtiofsd = spec
        .shares
        .iter()
        .map(|share| CommandSpec {
            argv: vec![
                "virtiofsd".to_string(),
                "--socket-path".to_string(),
                fs_sock(&share.tag).display().to_string(),
                "--shared-dir".to_string(),
                share.host_path.display().to_string(),
                "--cache".to_string(),
                "auto".to_string(),
                "--sandbox".to_string(),
                "none".to_string(),
            ],
        })
        .collect();

    let passt = spec.net.then(|| CommandSpec {
        argv: vec![
            "passt".to_string(),
            "--vhost-user".to_string(),
            "--socket-path".to_string(),
            net_sock.display().to_string(),
            "--foreground".to_string(),
            "--pid".to_string(),
            run.join("passt.pid").display().to_string(),
        ],
    });

    let mut vmm = vec![
        "cloud-hypervisor".to_string(),
        "--kernel".to_string(),
        spec.kernel.display().to_string(),
        "--initramfs".to_string(),
        spec.initramfs.display().to_string(),
        "--cmdline".to_string(),
        spec.cmdline.clone(),
        "--cpus".to_string(),
        format!("boot={}", spec.cpus),
        "--memory".to_string(),
        format!("size={}M,shared=on", spec.mem_mb),
    ];

    if !spec.disks.is_empty() {
        vmm.push("--disk".to_string());
        for disk in &spec.disks {
            let mut value = format!("path={}", disk.path.display());
            if disk.readonly {
                value.push_str(",readonly=on");
            }
            vmm.push(value);
        }
    }

    if !spec.shares.is_empty() {
        vmm.push("--fs".to_string());
        for share in &spec.shares {
            vmm.push(format!(
                "tag={},socket={}",
                share.tag,
                fs_sock(&share.tag).display()
            ));
        }
    }

    if spec.net {
        vmm.push("--net".to_string());
        vmm.push(format!("vhost_user=true,socket={}", net_sock.display()));
    }

    vmm.extend([
        "--vsock".to_string(),
        format!("cid=3,socket={}", vsock_sock.display()),
        "--serial".to_string(),
        format!("file={}", spec.console_log.display()),
        "--console".to_string(),
        "off".to_string(),
        "--api-socket".to_string(),
        api_sock.display().to_string(),
    ]);

    Invocations {
        virtiofsd,
        passt,
        vmm: CommandSpec { argv: vmm },
    }
}

/// Spawns cloud-hypervisor and its sidecars as detached processes.
///
/// Integration-tested on real hosts (requires the cloud-hypervisor, virtiofsd
/// and passt binaries); not unit-tested.
pub struct CloudHypervisorDriver;

const SOCKET_WAIT: Duration = Duration::from_secs(3);
const SOCKET_POLL: Duration = Duration::from_millis(50);

impl VmmDriver for CloudHypervisorDriver {
    fn launch(&self, spec: &VmSpec) -> anyhow::Result<Box<dyn VmHandle>> {
        std::fs::create_dir_all(&spec.run_dir)
            .with_context(|| format!("creating {}", spec.run_dir.display()))?;
        let log_dir = spec
            .console_log
            .parent()
            .context("console_log has no parent directory")?;
        std::fs::create_dir_all(log_dir)
            .with_context(|| format!("creating {}", log_dir.display()))?;

        let inv = build_invocations(spec);

        // Sidecars first: cloud-hypervisor connects to their sockets at boot.
        let mut sidecars: Vec<(String, PidIdentity)> = Vec::new();
        // (role, socket the sidecar must create before CH may start)
        let mut expected_socks: Vec<(String, PathBuf)> = Vec::new();

        let kill_all = |pids: &[(String, PidIdentity)]| {
            for (_, id) in pids {
                let _ = kill_pid(id);
            }
        };

        for (share, cmd) in spec.shares.iter().zip(&inv.virtiofsd) {
            let role = format!("virtiofsd:{}", share.tag);
            let log = log_dir.join(format!("virtiofsd-{}.log", share.tag));
            let id = match spawn_detached(cmd, &log) {
                Ok(id) => id,
                Err(e) => {
                    kill_all(&sidecars);
                    return Err(e).with_context(|| format!("spawning {role}"));
                }
            };
            sidecars.push((role.clone(), id));
            expected_socks.push((role, spec.run_dir.join(format!("fs-{}.sock", share.tag))));
        }

        if let Some(cmd) = &inv.passt {
            let id = match spawn_detached(cmd, &log_dir.join("passt.log")) {
                Ok(id) => id,
                Err(e) => {
                    kill_all(&sidecars);
                    return Err(e).context("spawning passt");
                }
            };
            sidecars.push(("passt".to_string(), id));
            expected_socks.push(("passt".to_string(), spec.run_dir.join("net.sock")));
        }

        // Each sidecar must create its listening socket before CH starts.
        for (role, sock) in &expected_socks {
            let deadline = Instant::now() + SOCKET_WAIT;
            while !sock.exists() {
                if Instant::now() >= deadline {
                    kill_all(&sidecars);
                    bail!(
                        "{role} did not create {} within {SOCKET_WAIT:?}",
                        sock.display()
                    );
                }
                std::thread::sleep(SOCKET_POLL);
            }
        }

        // The guest serial console goes to spec.console_log (--serial file=);
        // the CH process's own stdout/stderr go to a sibling vmm.log.
        let vmm_id = match spawn_detached(&inv.vmm, &log_dir.join("vmm.log")) {
            Ok(id) => id,
            Err(e) => {
                kill_all(&sidecars);
                return Err(e).context("spawning cloud-hypervisor");
            }
        };

        let mut pids = vec![("vmm".to_string(), vmm_id)];
        pids.extend(sidecars);
        Ok(Box::new(ChHandle {
            vsock_sock: spec.run_dir.join("vsock.sock"),
            pids,
        }))
    }
}

/// Handle to a launched cloud-hypervisor VM. `pids[0]` is always `"vmm"`.
struct ChHandle {
    vsock_sock: PathBuf,
    pids: Vec<(String, PidIdentity)>,
}

impl ChHandle {
    fn vmm_pid(&self) -> &PidIdentity {
        &self.pids[0].1
    }
}

impl VmHandle for ChHandle {
    fn connect(&self, port: u32) -> anyhow::Result<Box<dyn IoStream>> {
        let s = hybrid_connect(&self.vsock_sock, port)?;
        Ok(Box::new(s))
    }

    fn pids(&self) -> Vec<(String, PidIdentity)> {
        self.pids.clone()
    }

    fn is_alive(&self) -> bool {
        pid_alive(self.vmm_pid())
    }

    fn kill(&mut self) -> anyhow::Result<()> {
        // In order: vmm first (it is pids[0]), then sidecars — killing the
        // backends first would leave the VMM running on dead devices.
        let mut last_err = None;
        for (role, id) in &self.pids {
            if let Err(e) = kill_pid(id) {
                last_err = Some(e.context(format!("killing {role}")));
            }
        }
        match last_err {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::spec::{BlockDisk, FsShare};
    use std::path::PathBuf;

    fn base_spec() -> VmSpec {
        VmSpec {
            kernel: PathBuf::from("/img/vmlinux"),
            initramfs: PathBuf::from("/img/initramfs.img"),
            cmdline: "console=ttyS0 init=/init".to_string(),
            cpus: 2,
            mem_mb: 4096,
            disks: vec![
                BlockDisk {
                    path: PathBuf::from("/img/rootfs.img"),
                    readonly: true,
                },
                BlockDisk {
                    path: PathBuf::from("/sbx/scratch.img"),
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
    fn ch_invocations() {
        let inv = build_invocations(&base_spec());

        assert_eq!(inv.virtiofsd.len(), 1);
        assert_eq!(
            inv.virtiofsd[0].argv,
            argv(&[
                "virtiofsd",
                "--socket-path",
                "/sbx/run/fs-workspace.sock",
                "--shared-dir",
                "/home/user/project",
                "--cache",
                "auto",
                "--sandbox",
                "none",
            ])
        );

        assert_eq!(
            inv.passt
                .as_ref()
                .expect("passt expected when net=true")
                .argv,
            argv(&[
                "passt",
                "--vhost-user",
                "--socket-path",
                "/sbx/run/net.sock",
                "--foreground",
                "--pid",
                "/sbx/run/passt.pid",
            ])
        );

        assert_eq!(
            inv.vmm.argv,
            argv(&[
                "cloud-hypervisor",
                "--kernel",
                "/img/vmlinux",
                "--initramfs",
                "/img/initramfs.img",
                "--cmdline",
                "console=ttyS0 init=/init",
                "--cpus",
                "boot=2",
                "--memory",
                "size=4096M,shared=on",
                "--disk",
                "path=/img/rootfs.img,readonly=on",
                "path=/sbx/scratch.img",
                "--fs",
                "tag=workspace,socket=/sbx/run/fs-workspace.sock",
                "--net",
                "vhost_user=true,socket=/sbx/run/net.sock",
                "--vsock",
                "cid=3,socket=/sbx/run/vsock.sock",
                "--serial",
                "file=/sbx/console.log",
                "--console",
                "off",
                "--api-socket",
                "/sbx/run/ch-api.sock",
            ])
        );
    }

    #[test]
    fn ch_invocations_no_net() {
        let mut spec = base_spec();
        spec.net = false;
        let inv = build_invocations(&spec);

        assert!(inv.passt.is_none());
        assert_eq!(
            inv.vmm.argv,
            argv(&[
                "cloud-hypervisor",
                "--kernel",
                "/img/vmlinux",
                "--initramfs",
                "/img/initramfs.img",
                "--cmdline",
                "console=ttyS0 init=/init",
                "--cpus",
                "boot=2",
                "--memory",
                "size=4096M,shared=on",
                "--disk",
                "path=/img/rootfs.img,readonly=on",
                "path=/sbx/scratch.img",
                "--fs",
                "tag=workspace,socket=/sbx/run/fs-workspace.sock",
                "--vsock",
                "cid=3,socket=/sbx/run/vsock.sock",
                "--serial",
                "file=/sbx/console.log",
                "--console",
                "off",
                "--api-socket",
                "/sbx/run/ch-api.sock",
            ])
        );
    }

    #[test]
    fn ch_invocations_multi_share() {
        let mut spec = base_spec();
        spec.shares = vec![
            FsShare {
                tag: "workspace".to_string(),
                host_path: PathBuf::from("/home/user/project"),
            },
            FsShare {
                tag: "cache".to_string(),
                host_path: PathBuf::from("/home/user/.cache/izba"),
            },
        ];
        let inv = build_invocations(&spec);

        assert_eq!(inv.virtiofsd.len(), 2);
        assert_eq!(
            inv.virtiofsd[0].argv,
            argv(&[
                "virtiofsd",
                "--socket-path",
                "/sbx/run/fs-workspace.sock",
                "--shared-dir",
                "/home/user/project",
                "--cache",
                "auto",
                "--sandbox",
                "none",
            ])
        );
        assert_eq!(
            inv.virtiofsd[1].argv,
            argv(&[
                "virtiofsd",
                "--socket-path",
                "/sbx/run/fs-cache.sock",
                "--shared-dir",
                "/home/user/.cache/izba",
                "--cache",
                "auto",
                "--sandbox",
                "none",
            ])
        );

        assert_eq!(
            inv.vmm.argv,
            argv(&[
                "cloud-hypervisor",
                "--kernel",
                "/img/vmlinux",
                "--initramfs",
                "/img/initramfs.img",
                "--cmdline",
                "console=ttyS0 init=/init",
                "--cpus",
                "boot=2",
                "--memory",
                "size=4096M,shared=on",
                "--disk",
                "path=/img/rootfs.img,readonly=on",
                "path=/sbx/scratch.img",
                "--fs",
                "tag=workspace,socket=/sbx/run/fs-workspace.sock",
                "tag=cache,socket=/sbx/run/fs-cache.sock",
                "--net",
                "vhost_user=true,socket=/sbx/run/net.sock",
                "--vsock",
                "cid=3,socket=/sbx/run/vsock.sock",
                "--serial",
                "file=/sbx/console.log",
                "--console",
                "off",
                "--api-socket",
                "/sbx/run/ch-api.sock",
            ])
        );
    }
}
