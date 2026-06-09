//! Pure argv construction for a cloud-hypervisor microVM plus its sidecars
//! (one virtiofsd per shared dir, optional passt for user-mode networking).
//! No process is spawned here; see the launch driver for that.

use super::spec::{CommandSpec, VmSpec};

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
        assert!(!inv.vmm.argv.iter().any(|a| a == "--net"));
        assert!(!inv.vmm.argv.iter().any(|a| a.contains("net.sock")));
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

        let fs_values: Vec<&String> = inv
            .vmm
            .argv
            .iter()
            .skip_while(|a| *a != "--fs")
            .skip(1)
            .take_while(|a| !a.starts_with("--"))
            .collect();
        assert_eq!(
            fs_values,
            vec![
                "tag=workspace,socket=/sbx/run/fs-workspace.sock",
                "tag=cache,socket=/sbx/run/fs-cache.sock",
            ]
        );
        assert_eq!(inv.vmm.argv.iter().filter(|a| *a == "--fs").count(), 1);
    }
}
