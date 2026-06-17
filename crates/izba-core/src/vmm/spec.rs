use std::path::PathBuf;

/// A block device backed by a host file or device node.
#[derive(Debug, Clone)]
pub struct BlockDisk {
    pub path: PathBuf,
    pub readonly: bool,
}

/// A host directory shared into the guest via virtiofs.
#[derive(Debug, Clone)]
pub struct FsShare {
    pub tag: String,
    pub host_path: PathBuf,
}

/// Full description of a microVM to launch.
#[derive(Debug, Clone)]
pub struct VmSpec {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub cmdline: String,
    pub cpus: u32,
    pub mem_mb: u32,
    pub disks: Vec<BlockDisk>,
    pub shares: Vec<FsShare>,
    pub console_log: PathBuf,
    /// Per-sandbox dir where control sockets live.
    pub run_dir: PathBuf,
    /// User opt-out of host-side VMM confinement. DEFAULT false: the driver
    /// confines the VMM and FAILS CLOSED if it cannot. When true the VMM is
    /// launched unconfined and the degraded status is recorded loudly. Only the
    /// Windows OpenVMM driver consults this; the Linux jailer is a separate
    /// milestone.
    pub allow_unconfined: bool,
}

impl VmSpec {
    /// Host paths the confined (Low-IL) VMM must be able to WRITE — hence the
    /// set that must be Low-labelled before a confined launch and restored to
    /// Medium on teardown (MIC no-write-up otherwise blocks every write):
    ///
    ///   - the per-sandbox **scratch dir** (`run_dir`'s parent) — `run/` (vsock
    ///     socket), `logs/` (console.log + vmm.log), `rw.img`, and any anonymous
    ///     volume images all live under it; one inheritable label covers them;
    ///   - each **virtiofs share**'s host dir (the user's workspace) — the guest
    ///     writes it through the in-process virtiofs running inside the VMM;
    ///   - every **writable disk** backing file — notably NAMED persistent
    ///     volumes under `<data>/volumes`, which live OUTSIDE the scratch dir.
    ///     (`rw.img` / anon volumes are under the scratch dir already, so they
    ///     are covered twice — harmless.)
    ///
    /// The read-only rootfs (erofs) is omitted: a Low-IL process may read UP to
    /// a Medium object (no-read-up is not part of MIC's default policy), so the
    /// RO image needs no label.
    pub fn confined_write_surfaces(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(scratch) = self.run_dir.parent() {
            out.push(scratch.to_path_buf());
        }
        for s in &self.shares {
            out.push(s.host_path.clone());
        }
        for d in &self.disks {
            if !d.readonly {
                out.push(d.path.clone());
            }
        }
        out
    }
}

/// A fully-resolved command line: `argv[0]` is the program name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub argv: Vec<String>,
}

/// Both VMM backends format host paths into comma-delimited device-option
/// grammar — cloud-hypervisor's `--disk path=<p>,readonly=on` /
/// `--fs tag=...,socket=<p>` and openvmm's `--virtio-blk file:<p>,ro,...` /
/// `--virtio-fs pcie_port=...,<p>`. A comma embedded in a disk or workspace
/// path would silently split into bogus extra options (option-injection /
/// misconfiguration; not shell injection — argv is passed directly). Reject
/// such paths early with a clear error, before any invocation is built.
pub fn reject_commas(spec: &VmSpec) -> anyhow::Result<()> {
    for disk in &spec.disks {
        if disk.path.display().to_string().contains(',') {
            anyhow::bail!(
                "disk path {} contains a comma, which the VMM device-option \
                 syntax cannot carry — move the izba data root to a comma-free path",
                disk.path.display()
            );
        }
    }
    for share in &spec.shares {
        if share.host_path.display().to_string().contains(',') {
            anyhow::bail!(
                "workspace path {} contains a comma, which the VMM device-option \
                 syntax cannot carry — use a comma-free workspace directory",
                share.host_path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with(disks: Vec<BlockDisk>, shares: Vec<FsShare>) -> VmSpec {
        VmSpec {
            kernel: PathBuf::from("/k"),
            initramfs: PathBuf::from("/i"),
            cmdline: String::new(),
            cpus: 1,
            mem_mb: 256,
            disks,
            shares,
            console_log: PathBuf::from("/sbx/web/logs/console.log"),
            run_dir: PathBuf::from("/sbx/web/run"),
            allow_unconfined: false,
        }
    }

    #[test]
    fn confined_write_surfaces_covers_scratch_shares_and_writable_disks_only() {
        let spec = spec_with(
            vec![
                BlockDisk {
                    path: PathBuf::from("/img/rootfs.erofs"),
                    readonly: true,
                },
                BlockDisk {
                    path: PathBuf::from("/sbx/web/rw.img"),
                    readonly: false,
                },
                BlockDisk {
                    path: PathBuf::from("/data/volumes/cache.img"),
                    readonly: false,
                },
            ],
            vec![FsShare {
                tag: "workspace".to_string(),
                host_path: PathBuf::from("/home/user/project"),
            }],
        );
        let s = spec.confined_write_surfaces();
        // scratch dir (run_dir's parent)
        assert!(s.contains(&PathBuf::from("/sbx/web")));
        // virtiofs share host dir
        assert!(s.contains(&PathBuf::from("/home/user/project")));
        // writable disks (rw.img + the named volume OUTSIDE the scratch dir)
        assert!(s.contains(&PathBuf::from("/sbx/web/rw.img")));
        assert!(s.contains(&PathBuf::from("/data/volumes/cache.img")));
        // the read-only rootfs must NOT be labelled (read-up is allowed)
        assert!(!s.contains(&PathBuf::from("/img/rootfs.erofs")));
    }
}
