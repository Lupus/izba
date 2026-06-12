//! izba-init: PID 1 inside the microVM.
//!
//! Boot sequence: pseudo-filesystems → hostname → rw-disk format (first
//! boot) → overlay rootfs assembly → vsock control/stream servers. On
//! Shutdown: kill all workloads, sync, power off.

mod cmdline;
mod egress;
mod exec;
mod mounts;
mod net;
mod rwdisk;
mod server;
mod tarfs;

use anyhow::Context;
use exec::ExecEngine;
use izba_proto::{ExitStatus, CONTROL_PORT, STREAM_PORT};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct VsockPortListener(vsock::VsockListener);

impl server::Listener for VsockPortListener {
    type Conn = vsock::VsockStream;
    fn accept(&self) -> std::io::Result<Self::Conn> {
        self.0.accept().map(|(stream, _addr)| stream)
    }
}

fn main() {
    if std::env::args().any(|a| a == "--self-check") {
        self_check();
        return;
    }
    if std::process::id() != 1 {
        eprintln!("izba-init: not PID 1; nothing to do (try --self-check)");
        std::process::exit(1);
    }
    if let Err(e) = run_pid1() {
        // PID 1 must never exit (kernel panic); report and power off so the
        // host sees a dead VM rather than a wedged one.
        eprintln!("izba-init: fatal: {e:#}");
        power_off();
    }
}

/// Host-side smoke test used during image bring-up.
fn self_check() {
    let parsed = cmdline::parse("izba.hostname=web quiet");
    assert_eq!(parsed.get("izba.hostname").map(String::as_str), Some("web"));
    assert_eq!(parsed.get("quiet").map(String::as_str), Some(""));

    let engine = ExecEngine::new(None);
    let req = izba_proto::ExecRequest {
        argv: vec!["true".into()],
        env: vec![],
        cwd: "/".into(),
        tty: false,
        uid: nix::unistd::geteuid().as_raw(),
        gid: nix::unistd::getegid().as_raw(),
    };
    let id = engine.exec(&req).expect("self-check: exec true");
    let status = engine.wait(id).expect("self-check: wait");
    assert_eq!(status, ExitStatus::Code(0), "self-check: true must exit 0");
    println!("self-check OK");
}

fn run_pid1() -> anyhow::Result<()> {
    // Pin the uptime origin (server::START is lazy) to boot time.
    let _ = *server::START;

    mounts::apply(&mounts::boot_mount_plan()).context("boot mounts")?;

    let params = cmdline::parse(&std::fs::read_to_string("/proc/cmdline").unwrap_or_default());
    if let Some(hostname) = params.get("izba.hostname").filter(|h| !h.is_empty()) {
        if let Err(e) = nix::unistd::sethostname(hostname) {
            eprintln!("izba-init: sethostname {hostname:?}: {e}");
        }
    }
    if params.get("izba.ipv4only").map(String::as_str) == Some("1") {
        // Best-effort: a missing eth0 (net=false VM) is not fatal.
        if let Err(e) = net::apply_ipv4only(Path::new("/proc/sys/net/ipv6/conf")) {
            eprintln!("izba-init: izba.ipv4only: {e}");
        }
    }
    let egress_on = params.get("izba.egress").map(String::as_str) == Some("1");

    rwdisk::ensure_formatted(Path::new("/dev/vdb")).context("rw disk")?;

    // The overlay (op 2) needs upperdir/workdir to exist on the freshly
    // mounted rw disk, so the plan is applied in two halves.
    let rootfs_plan = mounts::rootfs_mount_plan();
    mounts::apply(&rootfs_plan[..2]).context("lower/upper mounts")?;
    for dir in mounts::upper_prep_dirs() {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    mounts::apply(&rootfs_plan[2..]).context("rootfs mounts")?;

    write_resolv_conf(egress_on);

    let engine = Arc::new(ExecEngine::new(Some("/rootfs".into())));
    let shutdown = Arc::new(AtomicBool::new(false));

    let control = VsockPortListener(
        vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, CONTROL_PORT)
            .context("binding vsock control port")?,
    );
    let streams = VsockPortListener(
        vsock::VsockListener::bind_with_cid_port(libc::VMADDR_CID_ANY, STREAM_PORT)
            .context("binding vsock stream port")?,
    );
    {
        let (e, s) = (Arc::clone(&engine), Arc::clone(&shutdown));
        std::thread::spawn(move || server::serve_control(control, e, s));
    }
    {
        let e = Arc::clone(&engine);
        std::thread::spawn(move || server::serve_streams(streams, e));
    }
    if egress_on {
        std::thread::spawn(|| {
            if let Err(e) = egress::serve_dns_udp() {
                eprintln!("izba-init: dns stub: {e}");
            }
        });
    }

    // Zombie policy (v1): every engine exec is reaped by its dedicated
    // waitpid thread. We deliberately do NOT waitpid(-1) here — that would
    // race those targeted waiters and steal their statuses. Orphans
    // reparented to PID 1 (daemonized grandchildren) therefore linger as
    // zombies until poweroff, when the kernel discards them.
    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    engine.kill_all();
    nix::unistd::sync();
    power_off();
}

/// With izbad egress, the resolver is the local stub (interim: loopback;
/// the dummy0-carried 192.168.127.1 arrives with the phase-C cutover).
/// Otherwise: kernel `ip=dhcp` autoconfig result from /proc/net/pnp.
fn write_resolv_conf(egress_on: bool) {
    let conf = if egress_on {
        "nameserver 127.0.0.1\n".to_string()
    } else {
        let Ok(pnp) = std::fs::read_to_string("/proc/net/pnp") else {
            return;
        };
        pnp.lines()
            .filter(|l| l.starts_with("nameserver") || l.starts_with("domain"))
            .map(|l| format!("{l}\n"))
            .collect()
    };
    let _ = std::fs::create_dir_all("/rootfs/etc");
    if let Err(e) = std::fs::write("/rootfs/etc/resolv.conf", conf) {
        eprintln!("izba-init: writing resolv.conf: {e}");
    }
}

fn power_off() -> ! {
    let _ = nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF);
    // reboot(2) only fails without CAP_SYS_BOOT (i.e. not really PID 1 in a
    // VM); nothing sensible left to do.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
