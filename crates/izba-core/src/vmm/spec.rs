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
    pub net: bool,
    pub console_log: PathBuf,
    /// Per-sandbox dir where control sockets live.
    pub run_dir: PathBuf,
}

/// A fully-resolved command line: `argv[0]` is the program name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub argv: Vec<String>,
}
