//! OpenVMM backend (Windows/WHP): pure argv construction plus the
//! [`OpenVmmDriver`] that spawns `openvmm.exe`. Unlike Cloud Hypervisor
//! there are NO sidecars — the virtiofs server runs in-process inside
//! openvmm (spike S1+ finding (c)), so launch is a single detached spawn
//! and `pids()` is just `[("vmm", id)]`. There is no host NIC: guest egress
//! rides the izbad-owned vsock 1027 plane (see `daemon::egress`), so openvmm
//! is launched without `--net`.
//!
//! Flag shapes are pinned by the rung-7 canonical invocation in
//! docs/superpowers/specs/2026-06-10-openvmm-spike-s1-findings.md:
//! `--hv` is mandatory (VPCI vsock needs it); virtio-blk must be routed via
//! per-disk PCIe root ports (VPCI auto-routing collides device IDs).
//! `--processors`/`--memory` are spike-unverified (defaults were used) and
//! get confirmed against `openvmm.exe --help` during Plan 2 bring-up.

use super::spec::{reject_commas, CommandSpec, LockdownLaunch, VmSpec};
use super::{IoStream, VmHandle, VmmDriver};
use crate::procmgr::{
    ensure_confinable, kill_pid, pid_alive, restore_integrity_recursive,
    set_low_integrity_recursive, spawn_confined, spawn_confined_as_account, spawn_detached,
    ConfinementMode, ConfinementPolicy, ConfinementStatus,
};
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
    push_disk_root_ports(&mut argv, spec);
    push_share_root_ports(&mut argv, spec);
    push_virtio_blk(&mut argv, spec);
    push_virtio_fs(&mut argv, spec);
    argv.push("--virtio-vsock-path".to_string());
    argv.push(vsock_sock.display().to_string());
    CommandSpec { argv }
}

/// One `--pcie-root-port rc0:vd{a..}` per disk, in disk order.
fn push_disk_root_ports(argv: &mut Vec<String>, spec: &VmSpec) {
    for i in 0..spec.disks.len() {
        argv.push("--pcie-root-port".to_string());
        argv.push(format!("rc0:{}", disk_port(i)));
    }
}

/// One `--pcie-root-port rc0:fs-<tag>` per virtiofs share, in share order.
fn push_share_root_ports(argv: &mut Vec<String>, spec: &VmSpec) {
    for share in &spec.shares {
        argv.push("--pcie-root-port".to_string());
        argv.push(format!("rc0:fs-{}", share.tag));
    }
}

/// One `--virtio-blk file:<path>[,ro],pcie_port=vd{a..}` per disk, in order.
fn push_virtio_blk(argv: &mut Vec<String>, spec: &VmSpec) {
    for (i, disk) in spec.disks.iter().enumerate() {
        let ro = if disk.readonly { ",ro" } else { "" };
        argv.push("--virtio-blk".to_string());
        argv.push(format!(
            "file:{}{ro},pcie_port={}",
            disk.path.display(),
            disk_port(i)
        ));
    }
}

/// One `--virtio-fs pcie_port=fs-<tag>:<tag>,<host_path>` per share, in order.
fn push_virtio_fs(argv: &mut Vec<String>, spec: &VmSpec) {
    for share in &spec.shares {
        argv.push("--virtio-fs".to_string());
        argv.push(format!(
            "pcie_port=fs-{}:{},{}",
            share.tag,
            share.tag,
            share.host_path.display()
        ));
    }
}

/// Applies the three-way confinement decision for the VMM process and returns
/// the resulting `(PidIdentity, ConfinementStatus)`.
///
/// Precedence (highest to lowest):
/// 1. **Locked** (`spec.lockdown` is `Some`) — launch as the per-sandbox
///    Windows account; Low-label write surfaces first; fail-closed on error.
/// 2. **allow_unconfined** — user explicitly opted out; spawn detached with no
///    labelling; status recorded as degraded.
/// 3. **Confined** (default) — Low-label write surfaces, spawn with a
///    restricted token at Low IL; fail-closed on error and restores labels.
///
/// FAIL CLOSED: on any labelling or spawn error the surfaces that were
/// already Low-labelled are restored to Medium before the error is propagated.
/// The caller never receives a `ConfinementStatus` that claims more than was
/// actually achieved.
fn spawn_confined_vmm(
    spec: &VmSpec,
    inv: &CommandSpec,
    vmm_log: &Path,
    policy: &ConfinementPolicy,
) -> anyhow::Result<(PidIdentity, ConfinementStatus)> {
    if let Some(ll) = &spec.lockdown {
        spawn_locked_vmm(spec, inv, vmm_log, policy, ll)
    } else if spec.allow_unconfined {
        // User EXPLICITLY opted out: run unconfined, record it loudly so
        // status never silently claims confinement that was waived.
        let id = spawn_detached(inv, vmm_log).context("spawning openvmm")?;
        Ok((
            id,
            ConfinementStatus::degraded(
                "--allow-unconfined: host-side VMM confinement disabled by user",
            ),
        ))
    } else {
        spawn_default_confined_vmm(spec, inv, vmm_log, policy)
    }
}

/// Low-label surfaces then spawn as the per-sandbox Windows account (locked path).
///
/// The account-launched VMM also runs at Low IL (the inner launcher calls
/// `spawn_confined` on the account's behalf), so we must Low-label every host
/// path the VMM needs to write — the same set as the normal confined branch.
/// The account already has DACL access from provisioning, but without the Low
/// IL label MIC would block writes.
fn spawn_locked_vmm(
    spec: &VmSpec,
    inv: &CommandSpec,
    vmm_log: &Path,
    policy: &ConfinementPolicy,
    ll: &LockdownLaunch,
) -> anyhow::Result<(PidIdentity, ConfinementStatus)> {
    let surfaces = spec.confined_write_surfaces();
    low_label_surfaces(&surfaces).with_context(|| {
        "Low-labelling confined write surface so the per-account VMM \
         (and its in-process virtiofs) can write it"
    })?;
    let pidfile = spec.run_dir.join("vmm-pid.json");
    match spawn_confined_as_account(ll.account(), ll.password(), inv, vmm_log, &pidfile) {
        Ok((id, ConfinementMode::Restricted)) => Ok((id, ConfinementStatus::applied(policy))),
        Ok((id, ConfinementMode::TokenOnly)) => Ok((id, ConfinementStatus::token_only(policy))),
        Ok((id, ConfinementMode::None)) => Ok((
            id,
            ConfinementStatus::degraded("confinement unavailable on this platform"),
        )),
        Err(e) => {
            // Undo Low labels — same fail-closed guarantee as the
            // normal confined branch.
            for p in &surfaces {
                let _ = restore_integrity_recursive(p);
            }
            anyhow::bail!(
                "failed to launch VMM as per-sandbox account {}: {e}. \
                 Consider removing the lock-down or using --allow-unconfined.",
                ll.account()
            )
        }
    }
}

/// Low-label surfaces then spawn with a restricted token at Low IL (default confined path).
///
/// The confined VMM runs at Low integrity, but izbad created the sandbox's
/// writable host files at Medium — and MIC forbids a Low-IL process from
/// writing UP to Medium-IL objects, so the VM would never boot (empty
/// console.log) and the guest could not write /workspace.  Low-label EVERY
/// host path the confined VMM must write (`VmSpec::confined_write_surfaces`:
/// the hashed run dir, the logs dir, the virtiofs shares, and writable disk
/// backing files incl. named volumes outside the per-sandbox dir). Lowering
/// is a write-DOWN for izbad (Medium → Low), so izbad keeps full control; the
/// labels are restored to Medium on teardown
/// (sandbox::restore_confined_workspace). Inheritance is
/// robust for plain creates; documented residuals (atomic-rename-in,
/// post-teardown Low files) live in the design spec / F-06 finding.
///
/// FAIL CLOSED: if labelling ANY surface OR the confined spawn fails, restore
/// every surface we touched before propagating the error.
fn spawn_default_confined_vmm(
    spec: &VmSpec,
    inv: &CommandSpec,
    vmm_log: &Path,
    policy: &ConfinementPolicy,
) -> anyhow::Result<(PidIdentity, ConfinementStatus)> {
    let surfaces = spec.confined_write_surfaces();
    low_label_surfaces(&surfaces).with_context(|| {
        "Low-labelling confined write surface so the VMM \
         (and its in-process virtiofs) can write it"
    })?;
    match spawn_confined(inv, vmm_log, policy) {
        // Honest mapping: the resource job is best-effort, so report
        // TokenOnly when it could not be applied even though token+IL
        // (the real boundary) succeeded.
        Ok((id, ConfinementMode::Restricted)) => Ok((id, ConfinementStatus::applied(policy))),
        Ok((id, ConfinementMode::TokenOnly)) => Ok((id, ConfinementStatus::token_only(policy))),
        // Unreachable on the confined path (the Windows jailer never
        // returns None and the Unix stub is not hit here), but map it
        // defensively rather than silently claiming confinement.
        Ok((id, ConfinementMode::None)) => Ok((
            id,
            ConfinementStatus::degraded("confinement unavailable on this platform"),
        )),
        Err(e) => {
            // The VMM never launched; undo the Low labels so a failed
            // confined start does not strand any user dir at Low.
            for p in &surfaces {
                let _ = restore_integrity_recursive(p);
            }
            anyhow::bail!(
                "failed to apply host-side confinement to the VMM: {e}. \
                 Re-run with --allow-unconfined to start the VMM WITHOUT host-side \
                 confinement (NOT recommended)."
            )
        }
    }
}

/// Low-label each surface in order, restoring all already-labelled surfaces on
/// the first failure.
///
/// Returns `Ok(())` when all surfaces are successfully labelled, or the first
/// labelling error (with all previously labelled surfaces restored).
fn low_label_surfaces(surfaces: &[PathBuf]) -> anyhow::Result<()> {
    let mut labelled: Vec<&PathBuf> = Vec::new();
    for p in surfaces {
        // Preflight then relabel: `ensure_confinable` fails fast with an
        // actionable message when a surface (e.g. a workspace at a drive root)
        // cannot be relabelled at all, instead of the opaque `WIN32_ERROR 5` the
        // relabel itself would bail with. No-op off Windows.
        if let Err(e) = ensure_confinable(p).and_then(|()| set_low_integrity_recursive(p)) {
            for done in &labelled {
                let _ = restore_integrity_recursive(done);
            }
            return Err(e).with_context(|| format!("{}", p.display()));
        }
        labelled.push(p);
    }
    Ok(())
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
        let vmm_log = log_dir.join("vmm.log");

        // Confined-by-default with a HARD fail-closed contract. The DEFAULT
        // (no --allow-unconfined) path confines the VMM or errors — it NEVER
        // falls back to an unconfined spawn. spawn_confined itself builds the
        // restricted token before spawning anything, so a confinement failure
        // never leaves a running unconfined VMM.
        let mut policy = ConfinementPolicy::vmm_default();
        // Size the best-effort resource job from the guest's RAM plus VMM
        // overhead; the job is caps-only and never kill-on-close.
        policy.job_memory_max_mb = Some(spec.mem_mb as u64 + 512);

        let (vmm_id, confinement) = spawn_confined_vmm(spec, &inv, &vmm_log, &policy)?;

        Ok(Box::new(OpenVmmHandle {
            vsock_sock,
            vmm: ("vmm".to_string(), vmm_id),
            confinement,
        }))
    }
}

/// Handle to a launched openvmm VM — exactly one process, no sidecars.
struct OpenVmmHandle {
    vsock_sock: PathBuf,
    vmm: (String, PidIdentity),
    /// Host-side confinement achieved at launch (see `VmHandle::confinement`).
    confinement: ConfinementStatus,
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

    fn confinement(&self) -> ConfinementStatus {
        self.confinement.clone()
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

    /// The handle accessors (`pids`/`is_alive`/`confinement`) are otherwise only
    /// reachable via a real `launch()` (VM-gated). Construct a handle directly to
    /// exercise them: a fabricated dead pid reads as not-alive, and the recorded
    /// confinement is surfaced verbatim.
    #[test]
    fn handle_accessors_report_pids_liveness_and_confinement() {
        let h = OpenVmmHandle {
            vsock_sock: PathBuf::from("/run/izba/vsock.sock"),
            vmm: (
                "vmm".to_string(),
                PidIdentity {
                    pid: u32::MAX, // a pid that does not exist -> not alive
                    starttime: 0,
                },
            ),
            confinement: ConfinementStatus::applied(&ConfinementPolicy::vmm_default()),
        };
        let pids = h.pids();
        assert_eq!(pids.len(), 1);
        assert_eq!(pids[0].0, "vmm");
        assert!(!h.is_alive(), "a fabricated pid must not read as alive");
        assert_eq!(h.confinement().mode, ConfinementMode::Restricted);
    }

    fn base_spec() -> VmSpec {
        VmSpec {
            kernel: PathBuf::from("/img/vmlinux"),
            initramfs: PathBuf::from("/img/initramfs.img"),
            cmdline: "console=ttyS0 izba.hostname=box".to_string(),
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
            console_log: PathBuf::from("/sbx/console.log"),
            run_dir: PathBuf::from("/sbx/run"),
            allow_unconfined: false,
            lockdown: None,
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    /// Compute a path under a directory the same way production code does, so
    /// on Windows PathBuf::join produces the native separator and display()
    /// matches what build_invocation() emits.
    fn dir_join(dir: &Path, name: &str) -> String {
        dir.join(name).display().to_string()
    }

    #[test]
    fn openvmm_invocation() {
        let spec = base_spec();
        let run = &spec.run_dir;
        let inv = build_invocation(&spec, &PathBuf::from("/opt/openvmm"));
        assert_eq!(
            inv.argv,
            argv(&[
                "/opt/openvmm",
                "--kernel",
                "/img/vmlinux",
                "--initrd",
                "/img/initramfs.img",
                "-c",
                "console=ttyS0 izba.hostname=box",
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
                "--virtio-vsock-path",
                &dir_join(run, "vsock.sock"),
            ])
        );
    }

    #[test]
    fn openvmm_invocation_has_no_net() {
        // No host NIC: guest egress rides the vsock 1027 plane. The cmdline
        // passes through unmodified (no izba.ipv4only append).
        let inv = build_invocation(&base_spec(), &PathBuf::from("/opt/openvmm"));
        assert!(!inv.argv.contains(&"--net".to_string()));
        assert!(!inv.argv.contains(&"consomme".to_string()));
        assert!(inv.argv.iter().all(|a| !a.contains("izba.ipv4only")));
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
