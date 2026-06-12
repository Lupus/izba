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
    rwdisk::ensure_formatted(Path::new("/dev/vdb")).context("rw disk")?;

    // The overlay (op 2) needs upperdir/workdir to exist on the freshly
    // mounted rw disk, so the plan is applied in two halves.
    let rootfs_plan = mounts::rootfs_mount_plan();
    mounts::apply(&rootfs_plan[..2]).context("lower/upper mounts")?;
    for dir in mounts::upper_prep_dirs() {
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    mounts::apply(&rootfs_plan[2..]).context("rootfs mounts")?;

    // Static guest networking: lo + dummy0 with the izba subnet. Log and
    // continue on error — exec/cp/vsock still work without IP networking.
    if let Err(e) = net::configure() {
        eprintln!("izba-init: network configure: {e}");
    }
    write_resolv_conf();

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
    {
        // Egress is unconditional: the guest is a pure vsock island, so the
        // stub IS the only way out. Order matters: listeners first, rules
        // second — once REDIRECT is in, every guest TCP connect lands on the
        // stub. The binds happen HERE on the main thread (not inside the
        // spawned serve loops) so they strictly happen-before apply_nft; the
        // accept/recv loops then move into threads.
        let dns_sock = match egress::bind_dns_udp() {
            Ok(s) => Some(s),
            Err(e) => {
                // Bind failed: the udp :53 redirect now blackholes DNS until
                // fixed, but TCP egress is unaffected — we still apply nft.
                eprintln!("izba-init: binding dns :53: {e}");
                None
            }
        };
        let tcp_listener = match egress::bind_tcp_redirect() {
            Ok(l) => Some(l),
            Err(e) => {
                // Bind failed: the TCP REDIRECT now blackholes ALL guest TCP
                // (loopback RST) — the honest deny posture; DNS is unaffected.
                // We still apply nft so the deny is enforced, not bypassed.
                eprintln!(
                    "izba-init: binding tcp redirect :{}: {e}",
                    egress::REDIRECT_PORT
                );
                None
            }
        };
        if let Some(sock) = dns_sock {
            std::thread::spawn(move || {
                if let Err(e) = egress::serve_dns_udp(sock) {
                    eprintln!("izba-init: dns stub: {e}");
                }
            });
        }
        if let Some(listener) = tcp_listener {
            std::thread::spawn(move || {
                if let Err(e) = egress::serve_tcp_redirect(listener) {
                    eprintln!("izba-init: tcp redirect stub: {e}");
                }
            });
        }
        if let Err(e) = egress::apply_nft() {
            // Loud but not fatal: DNS still works via resolv.conf; TCP
            // egress is dead until fixed. The console log is captured.
            eprintln!("izba-init: applying nft ruleset: {e}");
        }
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

/// The resolver is the egress stub, reached over loopback at 127.0.0.1:53
/// (the stub binds 0.0.0.0:53, so loopback hits it). It MUST be a loopback
/// address, not the dummy0-carried 192.168.127.1: the guest is NIC-less and
/// `dummy0` black-holes everything it transmits, so a DNS reply addressed to
/// the guest's own 192.168.127.x would be routed out dummy0 and dropped. A
/// query/reply pair on `lo` is the only path that actually returns. (Apps
/// that hardcode an external resolver are still caught by the nft
/// `udp dport 53 redirect to :53` rule; the resolv.conf path is the common
/// one and is what must work.) There is no NIC and no DHCP, so there is
/// nothing to discover from /proc/net/pnp.
fn write_resolv_conf() {
    let _ = std::fs::create_dir_all("/rootfs/etc");
    let conf = format!("nameserver {}\n", net::DNS_LOOPBACK);
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
