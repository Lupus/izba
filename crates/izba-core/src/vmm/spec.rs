use std::path::PathBuf;

/// Carries the per-sandbox Windows account credentials needed to launch the
/// VMM as that account (MVP-D locked-down path).
///
/// The password field is intentionally excluded from `Debug` output to prevent
/// it leaking into logs — `VmSpec` is sometimes logged as `{:?}` and the
/// password must never appear there.
///
/// [`LockdownLaunch`] is `Clone` so it can be embedded in the cloneable
/// `VmSpec`.
#[derive(Clone)]
pub struct LockdownLaunch {
    account: String,
    password: String,
}

impl LockdownLaunch {
    /// Create a new launch-credential carrier.
    pub fn new(account: String, password: String) -> Self {
        Self { account, password }
    }

    /// The Windows local account name (e.g. `izba-sb-mybox`).
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The account password — **never put this in a log string**.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for LockdownLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockdownLaunch")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .finish()
    }
}

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
    /// If set, the VMM is launched as this per-sandbox Windows account
    /// (MVP-D locked-down path). `None` means: use the normal confined or
    /// unconfined launch based on `allow_unconfined`.
    pub lockdown: Option<LockdownLaunch>,
}

impl VmSpec {
    /// Host paths the confined (Low-IL) VMM must be able to WRITE — hence the
    /// set that must be Low-labelled before a confined launch and restored to
    /// Medium on teardown (MIC no-write-up otherwise blocks every write).
    ///
    /// Since #85 (the hashed-runtime-dir move), `run_dir` is
    /// `<root>/run/<hex8(sha256(name))>` — a per-sandbox dir, but its
    /// **parent is the SHARED `<root>/run` tree**, holding every sibling
    /// sandbox's own hashed dir. That parent must NEVER be labelled: Low-
    /// labelling it would flip the inheritable integrity label of every
    /// sibling sandbox's run dir in one shot, and teardown's restore-to-
    /// Medium would then corrupt any sibling still confined and running.
    /// So write coverage is now split into two independent surfaces instead
    /// of the old single "scratch dir" (pre-#85, `run_dir`'s parent WAS the
    /// per-sandbox scratch dir covering everything below):
    ///
    ///   - **`run_dir` itself** — the hashed per-sandbox dir where the vsock
    ///     control socket is created; labelled directly (not via its parent);
    ///   - **`console_log`'s parent** — the per-sandbox `logs/` dir, opened
    ///     for write by the Low-IL VMM via `--com1 file=`; without this,
    ///     `console.log` is unreachable and every default confined Windows
    ///     boot fails at MIC's no-write-up check;
    ///   - each **virtiofs share**'s host dir (the user's workspace) — the
    ///     guest writes it through the in-process virtiofs running inside the
    ///     VMM;
    ///   - every **writable disk** backing file — `rw.img`, anonymous volume
    ///     images, and NAMED persistent volumes under `<data>/volumes` (which
    ///     live outside the per-sandbox dir entirely).
    ///
    /// The read-only rootfs (erofs) is omitted: a Low-IL process may read UP to
    /// a Medium object (no-read-up is not part of MIC's default policy), so the
    /// RO image needs no label.
    pub fn confined_write_surfaces(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        out.push(self.run_dir.clone());
        if let Some(logs) = self.console_log.parent() {
            out.push(logs.to_path_buf());
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

    /// Realistic post-#85 layout: `run_dir` is the hashed dir directly under
    /// the SHARED `<root>/run` (its parent is NOT per-sandbox), while
    /// `console_log` lives under the per-sandbox `sandboxes/<name>/logs`
    /// dir. A test that instead hand-builds `run_dir: "/sbx/web/run"` (old
    /// pre-#85 layout, where `run_dir.parent()` WAS the per-sandbox scratch
    /// dir) would mask a regression where `confined_write_surfaces` still
    /// labels `run_dir.parent()` — see
    /// `confined_write_surfaces_covers_scratch_shares_and_writable_disks_only`.
    fn spec_with(disks: Vec<BlockDisk>, shares: Vec<FsShare>) -> VmSpec {
        VmSpec {
            kernel: PathBuf::from("/k"),
            initramfs: PathBuf::from("/i"),
            cmdline: String::new(),
            cpus: 1,
            mem_mb: 256,
            disks,
            shares,
            console_log: PathBuf::from("/data/sandboxes/web/logs/console.log"),
            run_dir: PathBuf::from("/data/run/aabbccdd"),
            allow_unconfined: false,
            lockdown: None,
        }
    }

    /// The password embedded in `LockdownLaunch` must never appear in `{:?}`
    /// output — `VmSpec` is sometimes logged and the credential must not leak.
    #[test]
    fn lockdown_launch_debug_redacts_password() {
        let ll = LockdownLaunch::new("izba-sb-mybox".into(), "s3cret".into());
        let s = format!("{ll:?}");
        assert!(
            !s.contains("s3cret"),
            "password must NOT appear in Debug output, got: {s}"
        );
        assert!(
            s.contains("<redacted>"),
            "Debug output must contain <redacted>, got: {s}"
        );
        assert!(
            s.contains("izba-sb-mybox"),
            "account must appear in Debug output, got: {s}"
        );
    }

    /// The same password-redaction guarantee holds when `LockdownLaunch` is
    /// embedded inside a `VmSpec` and the spec is formatted as `{:?}`.
    #[test]
    fn vmspec_debug_with_lockdown_redacts_password() {
        let spec = VmSpec {
            kernel: PathBuf::from("/k"),
            initramfs: PathBuf::from("/i"),
            cmdline: String::new(),
            cpus: 1,
            mem_mb: 256,
            disks: vec![],
            shares: vec![],
            console_log: PathBuf::from("/sbx/web/logs/console.log"),
            run_dir: PathBuf::from("/sbx/web/run"),
            allow_unconfined: false,
            lockdown: Some(LockdownLaunch::new("acct".into(), "s3cret".into())),
        };
        let s = format!("{spec:?}");
        assert!(
            !s.contains("s3cret"),
            "password must NOT appear in VmSpec Debug output, got: {s}"
        );
        assert!(
            s.contains("<redacted>"),
            "VmSpec Debug output must contain <redacted>, got: {s}"
        );
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
        // the per-sandbox hashed run dir itself (needed for socket creation)
        assert!(s.contains(&PathBuf::from("/data/run/aabbccdd")));
        // the logs dir (console_log's parent) — covers console.log, opened
        // for write by the Low-IL VMM via `--com1 file=`
        assert!(s.contains(&PathBuf::from("/data/sandboxes/web/logs")));
        // virtiofs share host dir
        assert!(s.contains(&PathBuf::from("/home/user/project")));
        // writable disks (rw.img + the named volume OUTSIDE the scratch dir)
        assert!(s.contains(&PathBuf::from("/sbx/web/rw.img")));
        assert!(s.contains(&PathBuf::from("/data/volumes/cache.img")));
        // the read-only rootfs must NOT be labelled (read-up is allowed)
        assert!(!s.contains(&PathBuf::from("/img/rootfs.erofs")));
        // the SHARED `<root>/run` parent must NEVER be labelled — it holds
        // every sibling sandbox's hashed run dir; Low-labelling it would
        // flip every sibling's inheritable integrity label, and teardown
        // restore would corrupt concurrently-running confined siblings.
        assert!(!s.contains(&PathBuf::from("/data/run")));
        // the sandbox dir must NOT be labelled wholesale — under the new
        // layout it is not a single scratch dir covering run/, only logs/
        // (+ rw.img, covered separately via the writable-disks loop).
        assert!(!s.contains(&PathBuf::from("/data/sandboxes/web")));
    }
}
