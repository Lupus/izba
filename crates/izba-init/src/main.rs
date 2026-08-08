//! izba-init: PID 1 inside the microVM.
//!
//! Boot sequence: pseudo-filesystems → hostname → rw-disk format (first
//! boot) → overlay rootfs assembly → vsock control/stream servers. On
//! Shutdown: kill all workloads, sync, power off.

mod cmdline;
mod docker;
mod egress;
mod exec;
mod hosts;
mod mounts;
mod net;
mod oci;
mod pause;
mod rwdisk;
mod server;
mod ssh;
mod trust;
mod veth;

use anyhow::Context;
use exec::ExecEngine;
use izba_proto::{CONTROL_PORT, STREAM_PORT};
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

// `#[mutants::skip]`: PID-1 entry point — it branches on argv and the live
// process id, then dispatches into `self_check`/`pause::run`/`run_pid1`/
// `power_off`, none of which return in a unit test. The decision logic it
// contains is extracted into testable helpers (`is_pause_invocation`,
// `spawn_serve`), which are unit-tested directly.
#[mutants::skip]
fn main() {
    if std::env::args().any(|a| a == "--self-check") {
        self_check();
        return;
    }
    // Hidden subcommand: `izba-init __pause` — minimal reaping PID-1 for an
    // interactive OCI container. Must be checked before the PID-1 guard so it
    // works when invoked as PID 1 of a container PID namespace (not VM PID 1).
    if is_pause_invocation(std::env::args().nth(1).as_deref()) {
        pause::run();
    }
    // sshd invokes root's login shell (`/init`) in two ways (OpenSSH contract):
    //   interactive login  (`ssh host`):       argv[0] = "-init" (dash-prefixed), no `-c`
    //   remote command     (`ssh host <cmd>`): argv = ["/init", "-c", "<cmd>"]
    // Both routes enter the running `izba` crun container via `crun exec`.
    // Check before the PID-1 guard because the session process is not PID 1.
    let args: Vec<String> = std::env::args().collect();
    if let Some(cmd) = login_shell_command(&args) {
        ssh::ssh_session(Some(cmd));
    }
    if is_interactive_login_shell(&args) {
        ssh::ssh_session(None);
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

/// Whether `first_arg` (argv[1]) selects the hidden `__pause` PID-1 mode.
///
/// Extracted as a pure predicate so the dispatch condition is unit-testable
/// (the live `main` path runs `pause::run()`, which never returns).
fn is_pause_invocation(first_arg: Option<&str>) -> bool {
    first_arg == Some("__pause")
}

/// The remote command when sshd invoked izba-init as `init -c "<cmd>"`
/// (`ssh host <cmd>`); `None` if there is no `-c`.
fn login_shell_command(args: &[String]) -> Option<&str> {
    // Look for "-c" and return the argument immediately following it.
    args.windows(2)
        .find(|w| w[0] == "-c")
        .map(|w| w[1].as_str())
}

/// Whether sshd invoked izba-init as an INTERACTIVE login shell: argv[0] is
/// dash-prefixed (OpenSSH's login-shell convention, e.g. "-init").
fn is_interactive_login_shell(args: &[String]) -> bool {
    args.first().map(|a| a.starts_with('-')).unwrap_or(false)
}

/// Host-side smoke test used during image bring-up.
///
/// Validates the parts of init's logic that run on a bare host — cmdline
/// parsing, `ExecEngine` construction, and the crun argv wiring. It deliberately
/// does NOT perform a live exec: under Stance B `exec()` teleports into the
/// running workload via `crun exec`, and crun (plus the `izba` container) exists
/// only inside a booted guest. A build host has no `/sbin/crun` — the previous
/// version spawned it and panicked here. Even where crun is present there is no
/// running container to enter, so a real round-trip is impossible in this mode.
///
/// `#[mutants::skip]`: a manual `--self-check` smoke entry whose only observable
/// effect is internal assertions + a stdout line, so a unit test cannot tell the
/// `replace with ()` mutant from real success. Every builder it exercises
/// (`cmdline::parse`, `oci::crun_run_argv`, `oci::crun_exec_argv`) is unit-tested
/// directly.
#[mutants::skip]
fn self_check() {
    let parsed = cmdline::parse("izba.hostname=web quiet");
    assert_eq!(parsed.get("izba.hostname").map(String::as_str), Some("web"));
    assert_eq!(parsed.get("quiet").map(String::as_str), Some(""));

    // ExecEngine constructs without a live container (cgroup detection is
    // best-effort), exercising the boot-time construction path.
    let _engine = ExecEngine::new(None);

    // The crun run/exec argv wiring is the Stance B substitute for the old
    // direct spawn; validate both build the expected, well-formed argv.
    let run = oci::crun_run_argv(oci::CgroupManager::Disabled);
    assert_eq!(run.first().map(String::as_str), Some(oci::CRUN_PATH));
    assert!(
        run.iter().any(|a| a == "--no-pivot"),
        "self-check: crun run argv must carry --no-pivot"
    );
    assert_eq!(run.last().map(String::as_str), Some(oci::CONTAINER_ID));

    let exec = oci::crun_exec_argv(
        oci::CgroupManager::Disabled,
        false,
        "/workspace",
        &[],
        None,
        &["true".into()],
    );
    assert_eq!(exec.first().map(String::as_str), Some(oci::CRUN_PATH));
    assert!(
        exec.iter().any(|a| a == "exec"),
        "self-check: crun exec argv must carry the exec subcommand"
    );
    assert_eq!(exec.last().map(String::as_str), Some("true"));

    println!("self-check OK");
}

// reason: PID 1 boot sequence — mounts, overlay, vsock servers, sshd/egress
// launch. Runs only inside a real microVM; exercised by the KVM/WHP e2e, never
// by host unit tests (main.rs is the crate's one non-host-testable file).
#[mutants::skip]
fn run_pid1() -> anyhow::Result<()> {
    // Pin the uptime origin (server::START is lazy) to boot time.
    let _ = *server::START;

    // Record the guest-side build in the serial console (logs/console.log on the
    // host) so a boot capture identifies exactly which init binary booted.
    println!(
        "izba-init {} {} (built {})",
        env!("CARGO_PKG_VERSION"),
        option_env!("VERGEN_GIT_DESCRIBE").unwrap_or("unknown"),
        option_env!("VERGEN_BUILD_TIMESTAMP").unwrap_or("unknown"),
    );

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

    // User volumes (vdc, vdd, …): format-if-blank then mount under /rootfs,
    // in the order the host declared them on the izba.volumes cmdline list.
    let vols: Vec<&str> = params
        .get("izba.volumes")
        .map(|s| s.split(',').filter(|p| !p.is_empty()).collect())
        .unwrap_or_default();
    setup_user_volumes(&vols)?;

    // Builder output share: when the host attached the `izba-buildout` virtiofs
    // share (signalled by `izba.buildout=1` on the cmdline), mount it at
    // /rootfs/out so BuildKit can write img.tar there.
    if params
        .get("izba.buildout")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        mounts::apply(&[mounts::buildout_mount_op()]).context("buildout mount")?;
    }

    // USB passthrough, decided by the host: the flag rides the kernel cmdline,
    // which only izbad writes. Its absence is the guest's refusal to attach
    // anything, and it is also why the shared device directory exists only for
    // a sandbox that may actually use it — the container's /dev/izba bind mount
    // needs a source before crun starts.
    let usb_enabled = params.get("izba.usb").map(|v| v == "1").unwrap_or(false);
    if usb_enabled {
        if let Err(e) = std::fs::create_dir_all(izba_init::usb::SHARED_DEV_DIR) {
            eprintln!(
                "izba-init: creating {}: {e}",
                izba_init::usb::SHARED_DEV_DIR
            );
        }
    }
    let usb = Arc::new(izba_init::usb::UsbState::new(usb_enabled));

    // Docker mode, decided by the host: same host-authoritative cmdline
    // channel as izba.usb (see sandbox.rs). Drives the network topology
    // (net::configure), the resolv.conf nameserver (write_resolv_conf), the
    // nft chain (bring_up_egress/apply_nft), and — once the container is
    // running — the veth datapath wired up below.
    let docker = params.get("izba.docker").map(|v| v == "1").unwrap_or(false);

    // Guest networking: shared-netns dummy0, or (docker mode) just loopback
    // — see net::configure's doc for the split. Log and continue on error —
    // exec/cp/vsock still work without IP networking.
    if let Err(e) = net::configure(docker) {
        eprintln!("izba-init: network configure: {e}");
    }
    write_resolv_conf(docker);
    write_etc_hosts(
        params
            .get("izba.hostname")
            .map(String::as_str)
            .filter(|h| !h.is_empty()),
    );
    write_trust_anchor();
    ssh::launch();

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
    bring_up_egress(docker);

    // Start the OCI workload container via crun BEFORE the vsock control/stream
    // servers begin answering.  Placement rationale:
    //   * after egress is up — the container shares init's netns and needs the
    //     egress stub active;
    //   * before serving control/streams — `launch_container()` blocks until the
    //     container actually reaches `running` (crun --detach returns once the
    //     monitor is forked, BEFORE the detached child finishes creating the
    //     `user` namespace + writing its uid/gid map and exec'ing PID 1).  The
    //     host marks a sandbox healthy via a `Health` RPC answered by
    //     `serve_control`; gating that behind the container being up means a
    //     freshly-booted sandbox never reports ready while exec/ssh would still
    //     race the container into existence ("container does not exist").
    // The listeners are already bound above, so connections that arrive during
    // this window queue in the kernel backlog rather than being refused.
    // Fail-honest: launch_container() logs errors but never panics or exits PID 1.
    oci::launch_container();

    // Docker mode only: the workload runs in its OWN netns (image/
    // runtime_config.rs's docker-mode OCI profile), so — unlike the shared-
    // netns default, where the container just inherits init's dummy0 — it
    // needs the veth pair wired up now that crun has actually created that
    // netns (launch_container() blocked until `running`, so container_pid
    // should be available; a race would mean the container died between
    // "running" and here, which container_pid's None branch reports
    // honestly rather than wiring a stale/wrong pid). Placed before serving
    // control/streams, mirroring launch_container's own placement rationale
    // above: a sandbox should not be usable before its network is.
    if docker {
        match oci::container_pid(oci::CONTAINER_ID) {
            Some(pid) => {
                if let Err(e) = veth::apply(pid) {
                    eprintln!(
                        "izba-init: *** DOCKER-MODE VETH SETUP FAILED *** {e}; the container has no network"
                    );
                }
                // Cgroup delegation: dockerd running inside the container
                // needs `+controller` entries in every ancestor's
                // cgroup.subtree_control to create its own nested cgroups.
                // Best-effort (loud, non-fatal) — a kernel/controller gap
                // degrades nested resource limits but must not block the
                // engine from starting at all.
                match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
                    Ok(s) => match docker::parse_cgroup_path(&s) {
                        Some(cg) => {
                            if let Err(e) = docker::apply_delegation(
                                std::path::Path::new("/sys/fs/cgroup"),
                                &cg,
                            ) {
                                eprintln!(
                                    "izba-init: docker-mode cgroup delegation incomplete: {e} (nested container limits degraded)"
                                );
                            }
                        }
                        // Distinct from the read failure below: the file was
                        // read fine, but had no `0::<path>` unified-hierarchy
                        // line (unexpected content, not a raced-away pid).
                        None => eprintln!(
                            "izba-init: docker-mode cgroup delegation skipped: /proc/{pid}/cgroup had no parseable unified-hierarchy line"
                        ),
                    },
                    // The pid raced away (container died between container_pid()
                    // returning it and this read) or /proc is otherwise unreadable.
                    Err(e) => eprintln!(
                        "izba-init: docker-mode cgroup delegation skipped: reading /proc/{pid}/cgroup: {e}"
                    ),
                }
                // Auto-start the engine regardless of delegation outcome —
                // dockerd still runs (with degraded nested limits) rather
                // than never starting at all.
                docker::start_engine();
            }
            None => eprintln!(
                "izba-init: *** DOCKER-MODE VETH SETUP SKIPPED *** container pid unavailable (container not running?)"
            ),
        }
    }

    {
        let (e, u, s) = (Arc::clone(&engine), Arc::clone(&usb), Arc::clone(&shutdown));
        std::thread::spawn(move || server::serve_control(control, e, u, s));
    }
    {
        let e = Arc::clone(&engine);
        std::thread::spawn(move || server::serve_streams(streams, e));
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

/// Format-if-blank then mount each user volume (vdc, vdd, …) under /rootfs,
/// in the host-declared `izba.volumes` order.
fn setup_user_volumes(vols: &[&str]) -> anyhow::Result<()> {
    for i in 0..vols.len() {
        let dev = mounts::volume_device(i);
        rwdisk::ensure_formatted(Path::new(&dev))
            .with_context(|| format!("formatting volume {dev}"))?;
    }
    mounts::apply(&mounts::volume_mount_plan(vols)).context("volume mounts")
}

/// Bring up the always-on egress stub.
///
/// Egress is unconditional: the guest is a pure vsock island, so the stub IS
/// the only way out. Order matters: listeners first, rules second — once
/// REDIRECT is in, every guest TCP connect lands on the stub. The binds happen
/// HERE on the main thread (not inside the spawned serve loops) so they
/// strictly happen-before apply_nft; the accept/recv loops then move into
/// threads. `docker` selects the nft ruleset variant (`egress::ruleset`): the
/// same output chain always applies (init's own outbound egress dial), plus
/// the prerouting chain in docker mode (the workload's own-netns traffic,
/// delivered over the veth — see `egress::NFT_DOCKER_PREROUTING`).
///
/// `#[mutants::skip]`: orchestrates real socket binds, thread spawns, and the
/// nft apply against a live guest; none of that is reachable from a host unit
/// test. Its constituent pieces (`egress::bind_dns_udp`/`bind_dns_tcp`/
/// `bind_tcp_redirect`, `spawn_serve`, `egress::ruleset`) are unit-tested
/// directly.
#[mutants::skip]
fn bring_up_egress(docker: bool) {
    let dns_sock = match egress::bind_dns_udp() {
        Ok(s) => Some(s),
        Err(e) => {
            // Bind failed: the udp :53 redirect now blackholes DNS until
            // fixed, but TCP egress is unaffected — we still apply nft.
            eprintln!("izba-init: binding dns :53: {e}");
            None
        }
    };
    // DNS-over-TCP: the loopback retry path a resolver takes after a TC=1
    // (truncated) UDP answer. Bind before apply_nft like the others; a bind
    // failure only loses TCP DNS (large/split-horizon answers), not UDP DNS.
    let dns_tcp_listener = match egress::bind_dns_tcp() {
        Ok(l) => Some(l),
        Err(e) => {
            eprintln!("izba-init: binding dns tcp :53: {e}");
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
    spawn_serve(dns_sock, "dns stub", egress::serve_dns_udp);
    spawn_serve(dns_tcp_listener, "dns tcp stub", egress::serve_dns_tcp);
    spawn_serve(
        tcp_listener,
        "tcp redirect stub",
        egress::serve_tcp_redirect,
    );
    if let Err(e) = egress::apply_nft(docker) {
        // Loud but not fatal: DNS still works via resolv.conf; TCP
        // egress is dead until fixed. The console log is captured.
        eprintln!("izba-init: applying nft ruleset: {e}");
    }
}

/// Spawn a serve loop for a bound egress listener, logging a `label`led error if
/// the loop ever exits with one. No-op when the bind failed (`None`) — the nft
/// REDIRECT/DROP still enforces the deny, so a missing stub blackholes rather
/// than leaks.
fn spawn_serve<T: Send + 'static>(
    listener: Option<T>,
    label: &'static str,
    serve: fn(T) -> std::io::Result<()>,
) {
    let Some(l) = listener else {
        return;
    };
    std::thread::spawn(move || {
        if let Err(e) = serve(l) {
            eprintln!("izba-init: {label}: {e}");
        }
    });
}

/// The resolver MUST be a loopback address (127.0.0.1) in shared-netns mode
/// because 127.0.0.0/8 hits the `return` rule in the nft output-hook REDIRECT
/// chain and is never redirected. Any query sent to a non-loopback address IS
/// redirected to :53, but the stub answers from an unconnected wildcard
/// socket — the reply's source address does not match the address the client
/// queried, so conntrack's reverse-NAT never finds the tuple and the reply
/// never reaches the client (the transparent-UDP-proxy reply problem; see
/// NFT_RULESET's doc in egress.rs). Apps that hardcode an external UDP
/// resolver (e.g. 8.8.8.8) currently get no DNS — a known M1 gap, pending an
/// IP_ORIGDSTADDR transparent-reply fix in the stub. There is no NIC and no
/// DHCP, so there is nothing to discover from /proc/net/pnp.
///
/// **Docker-mode exception:** the workload runs in its OWN netns, reached
/// only over the veth pair — 127.0.0.1 there is the CONTAINER's own
/// loopback, not init's, so it can't reach the stub at all. RESOLVER_IP (the
/// veth gateway address, intercepted by the docker-mode prerouting chain
/// instead of the output chain) is used as the nameserver there, exactly as
/// non-loopback DNS servers are handled in shared-netns mode, but for
/// prerouting REDIRECT rather than output REDIRECT — see
/// `egress::NFT_DOCKER_PREROUTING`.
///
/// `#[mutants::skip]`: writes a real file under `/rootfs/etc`, only
/// meaningful inside a booted guest with the overlay assembled; the unit
/// suite has no `/rootfs`. The content it writes (`resolv_conf_content`) is
/// the pure, unit-tested part.
#[mutants::skip]
fn write_resolv_conf(docker: bool) {
    let _ = std::fs::create_dir_all("/rootfs/etc");
    if let Err(e) = std::fs::write("/rootfs/etc/resolv.conf", resolv_conf_content(docker)) {
        eprintln!("izba-init: writing resolv.conf: {e}");
    }
}

/// Pure: the resolv.conf content for either mode (nameserver line only). See
/// [`write_resolv_conf`]'s doc for why the nameserver differs by mode.
fn resolv_conf_content(docker: bool) -> String {
    if docker {
        format!("nameserver {}\n", net::RESOLVER_IP)
    } else {
        format!("nameserver {}\n", net::DNS_LOOPBACK)
    }
}

/// Ensures `localhost` and the sandbox hostname resolve in the workload's
/// `/etc/hosts` (see `hosts::ensure_entries` for the why). Best-effort: a
/// failure costs only the cosmetic per-invocation warnings this fixes.
// reason: PID-1-only glue — the read-modify-write logic lives in
// `hosts::sync_file` (unit-tested); only the fixed overlay path and the
// best-effort console log remain here, exercised by the KVM e2e boot.
#[mutants::skip]
fn write_etc_hosts(hostname: Option<&str>) {
    if let Err(e) = hosts::sync_file(Path::new("/rootfs/etc/hosts"), hostname) {
        eprintln!("izba-init: writing /etc/hosts: {e}");
    }
}

/// Bakes izbad's root CA (delivered via the read-only `izba-trust` virtiofs
/// share) into the guest trust store so workload tools trust the MITM leaves.
///
/// Best-effort and no-op when the share has no `ca.pem` — a sandbox without
/// HTTPS MITM ships no CA, and the trust-env defaulting in `exec.rs` is gated
/// on `ca-bundle.pem` existing, so absence here cleanly disables the feature.
///
/// Writes into the overlay (the guest's real, writable `/etc`):
/// `/etc/izba/ca.pem` (the CA alone, for runtimes that ADD a root) and
/// `/etc/izba/ca-bundle.pem` (CA + system roots, for tools that REPLACE the
/// trust set). If a distro CA bundle exists it also appends the CA to it
/// (best-effort, so tools that read the canonical system path also trust it).
/// We do NOT run update-ca-certificates: this is a static-musl, distro-agnostic
/// init.
fn write_trust_anchor() {
    // The share is mounted under /rootfs at the fixed trust mountpoint.
    let share_ca = format!("/rootfs{}/{}", trust::TRUST_MOUNT, trust::CA_FILE);
    let ca_pem = match std::fs::read_to_string(&share_ca) {
        Ok(p) => p,
        Err(e) => {
            // ENOENT is the normal "no MITM for this sandbox" path; anything
            // else is logged but still non-fatal.
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("izba-init: reading trust anchor {share_ca}: {e}");
            }
            return;
        }
    };

    if let Err(e) = std::fs::create_dir_all("/rootfs/etc/izba") {
        eprintln!("izba-init: creating /etc/izba: {e}");
        return;
    }
    if let Err(e) = std::fs::write("/rootfs/etc/izba/ca.pem", &ca_pem) {
        eprintln!("izba-init: writing /etc/izba/ca.pem: {e}");
        return;
    }

    // First existing distro CA bundle, if any (Debian/Alpine vs RHEL paths).
    const SYSTEM_BUNDLES: [&str; 2] = [
        "/rootfs/etc/ssl/certs/ca-certificates.crt",
        "/rootfs/etc/pki/tls/certs/ca-bundle.crt",
    ];
    let system_pem = SYSTEM_BUNDLES
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok());
    let bundle = trust::build_combined_bundle(&ca_pem, system_pem.as_deref());
    if let Err(e) = std::fs::write("/rootfs/etc/izba/ca-bundle.pem", bundle) {
        eprintln!("izba-init: writing /etc/izba/ca-bundle.pem: {e}");
    }

    // Best-effort: append the CA to the canonical Debian/Alpine bundle so tools
    // that hardcode that path also trust the MITM. Ignore all errors (path may
    // not exist; read-only/odd distros are fine — the env vars are the source
    // of truth).
    let canonical = "/rootfs/etc/ssl/certs/ca-certificates.crt";
    if std::path::Path::new(canonical).exists() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(canonical) {
            let _ = writeln!(f);
            let _ = f.write_all(ca_pem.as_bytes());
        }
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

#[cfg(test)]
mod tests {
    use super::{
        is_interactive_login_shell, is_pause_invocation, login_shell_command, resolv_conf_content,
        spawn_serve,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pause_invocation_only_for_exact_pause_arg() {
        assert!(is_pause_invocation(Some("__pause")));
        assert!(!is_pause_invocation(Some("--self-check")));
        assert!(!is_pause_invocation(Some("__pause__")));
        assert!(!is_pause_invocation(Some("")));
        assert!(!is_pause_invocation(None));
    }

    #[test]
    fn login_shell_command_extracts_c_operand() {
        // sshd's remote-command form: argv = [<shell>, "-c", "<cmd>"]
        assert_eq!(
            login_shell_command(&args(&["init", "-c", "ls -l"])),
            Some("ls -l")
        );
        // interactive login form: no "-c"
        assert_eq!(login_shell_command(&args(&["-init"])), None);
        // bare init invocation (PID-1)
        assert_eq!(login_shell_command(&args(&["init"])), None);
        // empty args
        assert_eq!(login_shell_command(&[]), None);
        // -c without a following arg (malformed) → None (windows(2) won't match last elem alone)
        assert_eq!(login_shell_command(&args(&["init", "-c"])), None);
    }

    #[test]
    fn is_interactive_login_shell_detects_dash_prefix() {
        // OpenSSH login-shell convention: argv[0] starts with '-'
        assert!(is_interactive_login_shell(&args(&["-init"])));
        assert!(is_interactive_login_shell(&args(&["-/init"])));
        // PID-1 form — not a login shell
        assert!(!is_interactive_login_shell(&args(&["/init"])));
        // remote command form — not a login shell (dash is not argv[0])
        assert!(!is_interactive_login_shell(&args(&["init", "-c", "x"])));
        // empty args
        assert!(!is_interactive_login_shell(&[]));
    }

    // `spawn_serve` is generic over the listener type, so these tests use `()` as
    // a stand-in listener: no socket is bound (some sandboxes deny `bind`), yet
    // every branch — the None no-op, the spawned serve call, and the error log —
    // is exercised. Each test owns a distinct counter so the parallel test runner
    // cannot race them.
    fn spin_until_nonzero(counter: &AtomicUsize) -> usize {
        for _ in 0..400 {
            let n = counter.load(Ordering::SeqCst);
            if n > 0 {
                return n;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        counter.load(Ordering::SeqCst)
    }

    static NONE_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn none_serve(_: ()) -> std::io::Result<()> {
        NONE_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    #[test]
    fn spawn_serve_is_noop_when_listener_is_none() {
        // A failed bind (`None`) must never spawn a thread or invoke `serve`.
        spawn_serve(None::<()>, "none", none_serve);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(NONE_CALLS.load(Ordering::SeqCst), 0);
    }

    static OK_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn ok_serve(_: ()) -> std::io::Result<()> {
        OK_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    #[test]
    fn spawn_serve_runs_serve_for_a_bound_listener() {
        spawn_serve(Some(()), "ok", ok_serve);
        assert_eq!(spin_until_nonzero(&OK_CALLS), 1);
    }

    static ERR_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn err_serve(_: ()) -> std::io::Result<()> {
        ERR_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("simulated serve-loop exit"))
    }

    #[test]
    fn spawn_serve_logs_and_survives_a_serve_error() {
        // A serve loop returning Err is logged inside the thread, not propagated.
        spawn_serve(Some(()), "err", err_serve);
        assert_eq!(spin_until_nonzero(&ERR_CALLS), 1);
    }

    #[test]
    fn resolv_conf_content_selects_nameserver_by_mode() {
        assert_eq!(
            resolv_conf_content(false),
            format!("nameserver {}\n", crate::net::DNS_LOOPBACK)
        );
        assert_eq!(
            resolv_conf_content(true),
            format!("nameserver {}\n", crate::net::RESOLVER_IP)
        );
    }
}
