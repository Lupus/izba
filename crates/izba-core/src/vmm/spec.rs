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
