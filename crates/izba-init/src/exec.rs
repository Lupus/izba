//! Workload execution engine: spawns, signals, resizes and streams processes.
//!
//! Every exec gets its own session (`setsid` in `pre_exec`, both tty and
//! pipe modes) so signals are delivered with `killpg` to the whole job, and
//! a dedicated waiter thread that reaps it exactly once with `waitpid`.

use izba_proto::{ErrorKind, ExecRequest, ExitStatus, StreamKind};
use nix::sys::signal::{killpg, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const DEFAULT_TERM: &str = "xterm-256color";

type ExecError = (ErrorKind, String);

fn internal(msg: impl std::fmt::Display) -> ExecError {
    (ErrorKind::Internal, msg.to_string())
}

/// Shared exit-status slot: waiter thread fills it, `wait()` blocks on it.
type StatusCell = Arc<(Mutex<Option<ExitStatus>>, Condvar)>;

/// Parent-side stream fds; each takeable exactly once.
/// Tty mode populates only `tty`; pipe mode only stdin/stdout/stderr.
#[derive(Default)]
struct Streams {
    stdin: Option<OwnedFd>,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
    tty: Option<OwnedFd>,
}

struct ExecProc {
    pid: Pid,
    status: StatusCell,
    tty_mode: bool,
    streams: Streams,
    /// PTY master kept for TIOCSWINSZ; `None` for pipe mode.
    pty_master: Option<OwnedFd>,
}

/// Execution engine: spawns, signals, streams and waits on guest workloads.
///
/// # Entry retention (v1 trade-off)
///
/// Entries in `procs` are **never pruned**. This is intentional: `wait()` must
/// remain callable any number of times after an exec exits (idempotent status
/// reads), so removing the entry on first wait would break repeated callers.
///
/// Downside: a long-lived guest that starts many short-lived execs accumulates
/// one `ExecProc` per exec, each holding the reaper thread's resources and any
/// un-taken `OwnedFd`s until the engine is dropped. For v1 workloads (bounded
/// number of execs per guest lifetime) this is fine. A v2 protocol extension
/// can introduce an explicit `Release` RPC to let the host signal that it will
/// never call `Wait` again, at which point the entry can be removed safely.
pub struct ExecEngine {
    /// The overlay root: `Some("/rootfs")` in the guest, `None` in tests. Used
    /// to (a) validate an exec's cwd against `<root>/<cwd>` and (b) confine the
    /// cp tar arms' path resolution. Exec no longer chroots here — `crun exec`
    /// enters the container's namespaces instead (Stance B).
    root: Option<PathBuf>,
    /// Test-only: when set, `exec()` spawns the request's argv DIRECTLY instead
    /// of wrapping it in `crun exec`. Production always wraps in crun (this is
    /// `false`); the direct path lets the host unit tests exercise the control/
    /// stream RPC wiring and the lifecycle machinery without a live crun + a
    /// running container. See `spawn_direct`.
    #[cfg(test)]
    direct: bool,
    procs: Mutex<HashMap<u32, ExecProc>>,
    next_id: AtomicU32,
}

impl ExecEngine {
    pub fn new(root: Option<PathBuf>) -> Self {
        Self {
            root,
            #[cfg(test)]
            direct: false,
            procs: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        }
    }

    /// Test-only constructor whose `exec()` spawns the request argv directly
    /// (no crun wrapping). Used by the server RPC-wiring tests, which need a
    /// real spawnable workload but run on a host without crun or a container.
    #[cfg(test)]
    pub fn new_direct(root: Option<PathBuf>) -> Self {
        Self {
            direct: true,
            ..Self::new(root)
        }
    }

    /// The overlay root, if any (`Some("/rootfs")` in the guest, `None` in
    /// tests). Used by the cp tar arms to confine path resolution.
    pub fn root(&self) -> Option<&std::path::Path> {
        self.root.as_deref()
    }

    /// Whether the izba combined CA bundle exists in the guest, resolved
    /// against the chroot root (`<root>/etc/izba/ca-bundle.pem` in the guest,
    /// the bare guest path in tests). Gates the trust-env defaulting so only
    /// MITM-enabled sandboxes advertise the CA-bundle vars.
    fn trust_bundle_present(&self) -> bool {
        let guest_path = crate::trust::GUEST_CA_BUNDLE.trim_start_matches('/');
        let resolved = match &self.root {
            Some(r) => r.join(guest_path),
            None => PathBuf::from(crate::trust::GUEST_CA_BUNDLE),
        };
        resolved.is_file()
    }

    pub fn exec(&self, req: &ExecRequest) -> Result<u32, ExecError> {
        let argv0 = req
            .argv
            .first()
            .ok_or((ErrorKind::BadRequest, "empty argv".to_string()))?
            .clone();

        // Pre-validate the working directory so a nonexistent cwd surfaces as
        // BadRequest rather than being misclassified later. The container roots
        // at the overlay (`<root>` = `/rootfs` in the guest), so the cwd inside
        // the container resolves to `<root>/<cwd>` from init's view.
        let host_cwd = match &self.root {
            Some(r) => r.join(req.cwd.trim_start_matches('/')),
            None => PathBuf::from(&req.cwd),
        };
        if !host_cwd.is_dir() {
            return Err((
                ErrorKind::BadRequest,
                format!("cwd {} does not exist in the sandbox", req.cwd),
            ));
        }

        // Test-only: spawn the request argv directly (no crun) so the server
        // RPC-wiring/lifecycle tests run on a crun-less host. A missing argv0 is
        // classified CommandNotFound here (the direct binary IS the workload),
        // mirroring the pre-Stance-B contract those tests pin.
        #[cfg(test)]
        if self.direct {
            return self.spawn_direct(&req.argv, req.tty, &argv0);
        }

        // Build the per-exec environment overlay: the caller's env plus izba's
        // trust-env defaults (only when the CA bundle is present and the key was
        // not already supplied). crun applies the container's image env as the
        // base; these `--env K=V` pairs layer on top. izba-init's OWN process
        // env is NOT propagated (crun sets the container env from its config).
        let env_overlay = self.build_env_overlay(req);

        // crun enters the container and applies the user via `--user`; only pass
        // it when the request asks for a specific uid/gid (uid==gid==0 means run
        // as the container's configured user, so we omit --user there).
        let user = crun_user_arg(req.uid, req.gid);

        let argv = crate::oci::crun_exec_argv(
            crate::oci::detect_cgroup_manager(),
            req.tty,
            &req.cwd,
            &env_overlay,
            user.as_deref(),
            &req.argv,
        );

        self.spawn_argv(&argv, req.tty, &argv0)
    }

    /// Spawn `argv` (argv[0] is the binary to exec), wire its stdio per `tty`,
    /// attach the reaper, and register the resulting [`ExecProc`]. This holds
    /// the lifecycle machinery shared by every exec; `exec()` is the thin layer
    /// that turns an [`ExecRequest`] into a `crun exec` argv first.
    ///
    /// `user_argv0` is only used for diagnostics (the user's command name) so a
    /// spawn failure reports something meaningful.
    fn spawn_argv(&self, argv: &[String], tty: bool, user_argv0: &str) -> Result<u32, ExecError> {
        // argv[0] is the binary to exec (CRUN_PATH in production); the rest are
        // its args. The container's command is carried as crun-exec's trailing
        // positionals (already folded into `argv` by the caller).
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);

        let (pty_master, mut streams) = self.configure_stdio(&mut cmd, tty)?;

        // SAFETY: pre_exec runs in the forked child before exec; only
        // async-signal-safe calls (setsid/ioctl). No chroot/setuid here — crun
        // joins the container's namespaces and applies the user itself.
        unsafe {
            cmd.pre_exec(move || child_pre_exec(tty));
        }

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                // The binary itself (crun in production) is missing — NOT the
                // user's command, which is resolved inside the container and
                // surfaces as crun rc 127.
                (
                    ErrorKind::Internal,
                    format!("exec binary {} not found: {e}", argv[0]),
                )
            } else {
                internal(format!("spawn {} for {user_argv0}: {e}", argv[0]))
            }
        })?;

        if !tty {
            streams.stdin = Some(OwnedFd::from(child.stdin.take().expect("piped stdin")));
            streams.stdout = Some(OwnedFd::from(child.stdout.take().expect("piped stdout")));
            streams.stderr = Some(OwnedFd::from(child.stderr.take().expect("piped stderr")));
        }

        let pid = Pid::from_raw(child.id() as i32);
        let status: StatusCell = Arc::new((Mutex::new(None), Condvar::new()));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        spawn_reaper(child, pid, Arc::clone(&status));

        self.procs.lock().unwrap().insert(
            id,
            ExecProc {
                pid,
                status,
                tty_mode: tty,
                streams,
                pty_master,
            },
        );
        Ok(id)
    }

    /// Test-only direct spawn: like `spawn_argv` but classifies a missing
    /// `argv[0]` as `CommandNotFound` (in the direct path the binary IS the
    /// user's workload). Production never takes this path — crun is always the
    /// binary, and a missing user command surfaces as crun rc 127.
    #[cfg(test)]
    fn spawn_direct(&self, argv: &[String], tty: bool, user_argv0: &str) -> Result<u32, ExecError> {
        self.spawn_argv(argv, tty, user_argv0)
            .map_err(|(kind, msg)| {
                if kind == ErrorKind::Internal && msg.contains("not found") {
                    (ErrorKind::CommandNotFound, msg)
                } else {
                    (kind, msg)
                }
            })
    }

    /// Build the per-exec `--env` overlay passed to `crun exec`.
    ///
    /// Starts from the caller's `req.env`, then appends izba's defaults for any
    /// key the caller did not set:
    /// - `TERM` (tty execs only) — the container image rarely sets it;
    /// - the MITM CA-bundle vars, but ONLY when the combined bundle exists in
    ///   the guest (`write_trust_anchor` wrote it), so non-MITM sandboxes don't
    ///   point tools at a missing file. The values are guest paths valid inside
    ///   the container (it shares the overlay rootfs).
    ///
    /// `PATH` is intentionally NOT defaulted here: crun applies the container
    /// image's `PATH` (the right value for the image), and overriding it with
    /// izba's generic default would mask the image's bin dirs. A caller may
    /// still pass `PATH` explicitly to override.
    fn build_env_overlay(&self, req: &ExecRequest) -> Vec<(String, String)> {
        let mut env = req.env.clone();
        let has = |env: &[(String, String)], key: &str| env.iter().any(|(k, _)| k == key);
        if req.tty && !has(&env, "TERM") {
            env.push(("TERM".to_string(), DEFAULT_TERM.to_string()));
        }
        if self.trust_bundle_present() {
            for (k, v) in crate::trust::trust_env_pairs() {
                if !has(&env, k) {
                    env.push((k.to_string(), v.to_string()));
                }
            }
        }
        env
    }

    /// Wire up the child's stdio. Tty mode allocates a pre-sized pty and returns
    /// the master (kept for resize) + a `Streams` carrying a master dup; pipe
    /// mode just requests piped stdio (taken from the child after spawn).
    fn configure_stdio(
        &self,
        cmd: &mut Command,
        tty: bool,
    ) -> Result<(Option<OwnedFd>, Streams), ExecError> {
        if !tty {
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            return Ok((None, Streams::default()));
        }
        // Pre-size the pty so a client's first Resize cannot race the
        // child's first size query.
        let ws = nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = nix::pty::openpty(Some(&ws), None).map_err(|e| {
            if e == nix::errno::Errno::EPERM || e == nix::errno::Errno::EACCES {
                internal(format!("openpty denied: {e}"))
            } else {
                internal(format!("openpty: {e}"))
            }
        })?;
        // Keep the master out of the child (fork inherits it; exec must
        // close it or master EOF never arrives after the child exits).
        set_cloexec(&pty.master).map_err(internal)?;
        // Set CLOEXEC on the slave immediately: without it the slave fd is
        // inherited by every child spawned concurrently from this process.
        // Those children hold the slave open across their own exec, keeping
        // the pty alive beyond this tty job and preventing master EOF.
        // std's child-side dup2(slave, 0/1/2) clears CLOEXEC on the dup'd
        // descriptors, so the actual tty child is unaffected.
        set_cloexec(&pty.slave).map_err(internal)?;
        let slave_in = pty.slave.try_clone().map_err(internal)?;
        let slave_out = pty.slave.try_clone().map_err(internal)?;
        cmd.stdin(Stdio::from(slave_in));
        cmd.stdout(Stdio::from(slave_out));
        cmd.stderr(Stdio::from(pty.slave));
        let master_dup = pty.master.try_clone().map_err(internal)?;
        Ok((
            Some(pty.master),
            Streams {
                tty: Some(master_dup),
                ..Streams::default()
            },
        ))
    }

    /// Blocks until the exec exits; repeatable (returns the same status).
    pub fn wait(&self, id: u32) -> Result<ExitStatus, ExecError> {
        let status = {
            let procs = self.procs.lock().unwrap();
            let proc = procs.get(&id).ok_or_else(|| not_found(id))?;
            Arc::clone(&proc.status)
        };
        let (lock, cvar) = &*status;
        let mut guard = lock.lock().unwrap();
        loop {
            if let Some(st) = *guard {
                return Ok(st);
            }
            guard = cvar.wait(guard).unwrap();
        }
    }

    /// Signals the exec's whole process group. ESRCH (already gone) is Ok.
    pub fn kill(&self, id: u32, sig: i32) -> Result<(), ExecError> {
        let pid = {
            let procs = self.procs.lock().unwrap();
            let proc = procs.get(&id).ok_or_else(|| not_found(id))?;
            // If the process has already been reaped, return Ok immediately.
            // Sending a signal to a reaped pgid risks hitting a recycled pid.
            if proc.status.0.lock().unwrap().is_some() {
                return Ok(());
            }
            proc.pid
        };
        let signal = Signal::try_from(sig)
            .map_err(|e| (ErrorKind::BadRequest, format!("bad signal {sig}: {e}")))?;
        match killpg(pid, signal) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
            Err(e) => Err(internal(format!("killpg {pid}: {e}"))),
        }
    }

    pub fn resize(&self, id: u32, cols: u16, rows: u16) -> Result<(), ExecError> {
        let procs = self.procs.lock().unwrap();
        let proc = procs.get(&id).ok_or_else(|| not_found(id))?;
        let master = proc
            .pty_master
            .as_ref()
            .ok_or((ErrorKind::BadRequest, format!("exec {id} has no tty")))?;
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: valid fd, valid winsize pointer.
        let rc = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        if rc < 0 {
            return Err(internal(format!(
                "TIOCSWINSZ: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Hands out the parent-side fd for a stream; each is takeable once.
    pub fn take_stream(&self, id: u32, kind: StreamKind) -> Result<OwnedFd, ExecError> {
        let mut procs = self.procs.lock().unwrap();
        let proc = procs.get_mut(&id).ok_or_else(|| not_found(id))?;
        let applicable = matches!(kind, StreamKind::Tty) == proc.tty_mode;
        if !applicable {
            return Err((
                ErrorKind::BadRequest,
                format!("exec {id} has no {kind:?} stream"),
            ));
        }
        let slot = match kind {
            StreamKind::Stdin => &mut proc.streams.stdin,
            StreamKind::Stdout => &mut proc.streams.stdout,
            StreamKind::Stderr => &mut proc.streams.stderr,
            StreamKind::Tty => &mut proc.streams.tty,
        };
        slot.take().ok_or((
            ErrorKind::BadRequest,
            format!("{kind:?} stream of exec {id} already taken"),
        ))
    }

    /// SIGKILLs every exec that has not been reaped yet (shutdown path).
    pub fn kill_all(&self) {
        let procs = self.procs.lock().unwrap();
        for proc in procs.values() {
            if proc.status.0.lock().unwrap().is_none() {
                let _ = killpg(proc.pid, Signal::SIGKILL);
            }
        }
    }
}

fn not_found(id: u32) -> ExecError {
    (ErrorKind::ExecNotFound, format!("no exec with id {id}"))
}

/// The `--user uid:gid` argument for `crun exec`, or `None` when the request
/// wants the container's configured user (uid==gid==0). Passing `--user 0:0`
/// would force root even if the image declares a non-root USER, so we omit it
/// in the default case and only set it for an explicit non-zero id.
fn crun_user_arg(uid: u32, gid: u32) -> Option<String> {
    (uid != 0 || gid != 0).then(|| format!("{uid}:{gid}"))
}

fn set_cloexec(fd: &OwnedFd) -> std::io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    let flags = fcntl(fd.as_raw_fd(), FcntlArg::F_GETFD)?;
    let mut flags = FdFlag::from_bits_retain(flags);
    flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(flags))?;
    Ok(())
}

/// Child-side setup run in the forked process before exec.
///
/// In Stance B the child execs `crun exec`, which itself joins the container's
/// namespaces, chdirs to `--cwd`, and applies the user (`--user`). So this
/// pre_exec does NOT chroot or drop privileges any more — it only establishes
/// the session (so `killpg` reaches the whole crun-exec job) and, for tty
/// execs, adopts the pre-allocated pty slave as the controlling terminal.
///
/// # Safety
/// Runs in the forked child before exec; only async-signal-safe calls
/// (setsid/ioctl).
fn child_pre_exec(tty: bool) -> std::io::Result<()> {
    // Own session per exec → killpg targets the whole job.
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if tty {
        // Stdio fds were already dup2'ed by std; fd 0 is the pty slave.
        // Adopt it as the controlling terminal.
        if unsafe { libc::ioctl(0, libc::TIOCSCTTY, 0) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Dedicated reaper: exactly one waitpid per child, so the engine never races
/// itself over exit statuses. Fills `status` and notifies waiters on exit.
fn spawn_reaper(child: std::process::Child, pid: Pid, status: StatusCell) {
    std::thread::spawn(move || {
        // `child` is moved in (but never `wait()`ed) so its Drop
        // runs here, not in exec(); only this waitpid reaps.
        let _keep = child;
        let st = decode_wait_status(waitpid(pid, None));
        let (lock, cvar) = &*status;
        *lock.lock().unwrap() = Some(st);
        cvar.notify_all();
    });
}

/// Decode the reaped `crun exec` process status into an `ExitStatus`.
///
/// **No double-add.** `crun exec` PROPAGATES the workload command's exit status
/// as crun's OWN exit code: a normal exit `N` → crun exits `N`; a signal-killed
/// command → crun exits `128+n`; a missing executable → crun exits `127`. So we
/// pass crun's `Exited(code)` straight through as `Code(code)` — re-encoding a
/// 128+n exit as `Signal(n)` here would double-apply the host CLI's `128+n`
/// mapping and produce the wrong number.
///
/// `Signaled` only happens when the crun-exec PROCESS ITSELF is signaled (e.g.
/// via our `kill`/`kill_all`), and maps to `Signal(n)` — the host CLI then
/// renders `128+n`, the right contract for "the exec was killed".
fn decode_wait_status(res: nix::Result<WaitStatus>) -> ExitStatus {
    match res {
        Ok(WaitStatus::Exited(_, code)) => ExitStatus::Code(code),
        Ok(WaitStatus::Signaled(_, sig, _)) => ExitStatus::Signal(sig as i32),
        // Anything else (or waitpid error) is reported as a
        // wedge-proof synthetic failure rather than wedging wait().
        _ => ExitStatus::Code(-1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};

    fn req(argv: &[&str]) -> ExecRequest {
        ExecRequest {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: vec![],
            cwd: "/".into(),
            tty: false,
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
        }
    }

    fn engine() -> ExecEngine {
        ExecEngine::new(None)
    }

    /// Resolve a real binary in the test host for the lifecycle tests.
    ///
    /// In Stance B `exec()` always shells out to `crun`, which is NOT present in
    /// the unit-test host (and there is no live container), so the lifecycle
    /// machinery (spawn/reaper/wait/kill/streams/resize) is exercised by calling
    /// the private `spawn_argv()` directly with an ordinary binary. That tests
    /// the same code path crun would drive at runtime, minus the crun process.
    fn bin(name: &str) -> String {
        for prefix in ["/bin/", "/usr/bin/"] {
            let p = format!("{prefix}{name}");
            if std::path::Path::new(&p).exists() {
                return p;
            }
        }
        panic!("test host is missing /bin/{name} (or /usr/bin/{name})");
    }

    /// Spawn an ordinary binary through the engine's lifecycle machinery,
    /// bypassing crun-argv construction. `argv[0]` must be an absolute binary
    /// path (use [`bin`]).
    fn spawn(e: &ExecEngine, argv: &[&str], tty: bool) -> Result<u32, ExecError> {
        let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        e.spawn_argv(&owned, tty, &owned[0])
    }

    // ── Lifecycle machinery (spawn_argv → reaper/wait/kill/streams/resize) ────
    // These drive a real binary directly because the production `exec()` now
    // shells out to crun, which is absent in the unit-test host.

    #[test]
    fn exit_code_zero() {
        let e = engine();
        let id = spawn(&e, &[&bin("true")], false).unwrap();
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Code(0));
    }

    #[test]
    fn exit_code_one() {
        let e = engine();
        let id = spawn(&e, &[&bin("false")], false).unwrap();
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Code(1));
    }

    #[test]
    fn missing_binary_is_internal_error() {
        // spawn_argv's argv[0] is the binary to exec (crun in production). A
        // missing argv[0] is an Internal error (crun absent), NOT
        // CommandNotFound — the user's command is resolved *inside* the
        // container by crun and surfaces as crun rc 127, not a spawn failure.
        let e = engine();
        let (kind, msg) = spawn(&e, &["/nonexistent/zzz"], false).unwrap_err();
        assert_eq!(kind, ErrorKind::Internal, "{msg}");
    }

    #[test]
    fn empty_argv_is_bad_request() {
        let e = engine();
        let (kind, _) = e.exec(&req(&[])).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
    }

    #[test]
    fn stdout_pipe() {
        let e = engine();
        let id = spawn(&e, &[&bin("sh"), "-c", "echo out"], false).unwrap();
        let mut out = String::new();
        File::from(e.take_stream(id, StreamKind::Stdout).unwrap())
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "out\n");
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Code(0));
    }

    #[test]
    fn stdin_roundtrip() {
        let e = engine();
        let id = spawn(&e, &[&bin("cat")], false).unwrap();
        {
            let mut stdin = File::from(e.take_stream(id, StreamKind::Stdin).unwrap());
            stdin.write_all(b"hi").unwrap();
            // drop closes the write end → cat sees EOF
        }
        let mut out = String::new();
        File::from(e.take_stream(id, StreamKind::Stdout).unwrap())
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, "hi");
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Code(0));
    }

    #[test]
    fn kill_term() {
        let e = engine();
        let id = spawn(&e, &[&bin("sleep"), "30"], false).unwrap();
        e.kill(id, 15).unwrap();
        // The spawned process ITSELF is signaled → Signal(15). (At runtime this
        // is the crun-exec process; see decode_wait_status.)
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Signal(15));
    }

    #[test]
    fn double_wait_same() {
        let e = engine();
        let id = spawn(&e, &[&bin("false")], false).unwrap();
        let first = e.wait(id).unwrap();
        let second = e.wait(id).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, ExitStatus::Code(1));
    }

    #[test]
    fn unknown_exec_id() {
        let e = engine();
        let (kind, _) = e.wait(999).unwrap_err();
        assert_eq!(kind, ErrorKind::ExecNotFound);
        let (kind, _) = e.kill(999, 15).unwrap_err();
        assert_eq!(kind, ErrorKind::ExecNotFound);
        let (kind, _) = e.take_stream(999, StreamKind::Stdout).unwrap_err();
        assert_eq!(kind, ErrorKind::ExecNotFound);
    }

    #[test]
    fn stream_takeable_once() {
        let e = engine();
        let id = spawn(&e, &[&bin("true")], false).unwrap();
        e.take_stream(id, StreamKind::Stdout).unwrap();
        let (kind, _) = e.take_stream(id, StreamKind::Stdout).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        // Tty stream does not exist in pipe mode.
        let (kind, _) = e.take_stream(id, StreamKind::Tty).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        e.wait(id).unwrap();
    }

    #[test]
    fn resize_without_tty_is_bad_request() {
        let e = engine();
        let id = spawn(&e, &[&bin("true")], false).unwrap();
        let (kind, _) = e.resize(id, 80, 24).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        e.wait(id).unwrap();
    }

    #[test]
    fn tty_size() {
        let e = engine();
        let id = match spawn(&e, &[&bin("sh"), "-c", "stty size"], true) {
            Ok(id) => id,
            Err((_, msg)) if msg.contains("openpty denied") => {
                eprintln!("SKIP: sandbox denies pty allocation: {msg}");
                return;
            }
            Err((k, m)) => panic!("spawn failed: {k:?} {m}"),
        };
        // openpty pre-sizes to 24x80; this exercises TIOCSWINSZ with the
        // same geometry so there is no race with stty.
        e.resize(id, 80, 24).unwrap();
        let mut tty = File::from(e.take_stream(id, StreamKind::Tty).unwrap());
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tty.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                // EIO on the master means all slave fds are closed → EOF.
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(e) => panic!("tty read: {e}"),
            }
        }
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("24 80"), "tty output: {out:?}");
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Code(0));
    }

    #[test]
    fn bad_cwd_is_bad_request() {
        let e = engine();
        let mut r = req(&["true"]);
        r.cwd = "/nonexistent-dir-xyz".into();
        let (kind, _msg) = e.exec(&r).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
    }

    #[test]
    fn kill_after_exit_is_ok() {
        let e = engine();
        let id = spawn(&e, &[&bin("true")], false).unwrap();
        e.wait(id).unwrap();
        // Process has been reaped; kill should return Ok without signaling.
        e.kill(id, 15).unwrap();
    }

    #[test]
    fn kill_with_invalid_signal_is_bad_request() {
        let e = engine();
        let id = spawn(&e, &[&bin("sleep"), "30"], false).unwrap();
        // 9999 is not a valid signal number → BadRequest before any signal.
        let (kind, _) = e.kill(id, 9999).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        // The job is still running; reap it so the test leaves nothing behind.
        e.kill(id, libc::SIGKILL).unwrap();
        e.wait(id).unwrap();
    }

    #[test]
    fn kill_all_sigkills_unreaped() {
        let e = engine();
        let running = spawn(&e, &[&bin("sleep"), "30"], false).unwrap();
        let done = spawn(&e, &[&bin("true")], false).unwrap();
        // Reap the short-lived one so kill_all must skip it (status present)
        // and only signal the still-running job.
        assert_eq!(e.wait(done).unwrap(), ExitStatus::Code(0));
        e.kill_all();
        assert_eq!(e.wait(running).unwrap(), ExitStatus::Signal(libc::SIGKILL));
    }

    // ── exec() → crun-argv contract (the part exec() now owns) ────────────────

    #[test]
    fn exec_cwd_is_validated_against_root() {
        // exec() pre-validates the cwd against <root>/<cwd> BEFORE shelling out
        // to crun, so a nonexistent cwd is a clean BadRequest. With root=None a
        // real, existing absolute cwd passes that gate; the subsequent crun
        // spawn fails (no crun on the host) with an Internal error — proving the
        // cwd gate ran and passed.
        let e = engine();
        let mut r = req(&[&bin("true")]);
        r.cwd = "/".into();
        // /  exists → cwd gate passes → crun spawn fails Internal (crun absent).
        let err = e.exec(&r);
        match err {
            Err((ErrorKind::Internal, _)) => {} // crun absent — expected here.
            Err((ErrorKind::BadRequest, m)) => panic!("cwd / wrongly rejected: {m}"),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn build_env_overlay_defaults_term_only_for_tty() {
        let e = engine(); // root=None → no trust bundle.
        let mut r = req(&["x"]);
        r.tty = false;
        assert!(
            !e.build_env_overlay(&r).iter().any(|(k, _)| k == "TERM"),
            "pipe exec must not inject TERM"
        );
        r.tty = true;
        let env = e.build_env_overlay(&r);
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "TERM")
                .map(|(_, v)| v.as_str()),
            Some(DEFAULT_TERM),
            "tty exec defaults TERM"
        );
    }

    #[test]
    fn build_env_overlay_preserves_caller_env_and_term_override() {
        let e = engine();
        let mut r = req(&["x"]);
        r.tty = true;
        r.env = vec![
            ("FOO".into(), "bar".into()),
            ("TERM".into(), "vt100".into()),
        ];
        let env = e.build_env_overlay(&r);
        // Caller env is preserved verbatim.
        assert!(env.contains(&("FOO".to_string(), "bar".to_string())));
        // Caller-supplied TERM wins (no duplicate default appended).
        assert_eq!(env.iter().filter(|(k, _)| k == "TERM").count(), 1);
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "TERM")
                .map(|(_, v)| v.as_str()),
            Some("vt100")
        );
    }

    #[test]
    fn build_env_overlay_no_path_default() {
        // PATH is left to the container image; izba must NOT inject a default
        // (that would mask the image's bin dirs).
        let e = engine();
        let r = req(&["x"]);
        assert!(!e.build_env_overlay(&r).iter().any(|(k, _)| k == "PATH"));
    }

    #[test]
    fn trust_bundle_present_tracks_the_guest_file() {
        let dir = tempfile::tempdir().unwrap();
        let e = ExecEngine::new(Some(dir.path().to_path_buf()));
        // No bundle yet → not present → trust env defaulting is suppressed.
        assert!(!e.trust_bundle_present());
        // Materialize <root>/etc/izba/ca-bundle.pem.
        let bundle = dir.path().join("etc/izba/ca-bundle.pem");
        std::fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        std::fs::write(&bundle, "CA\n").unwrap();
        assert!(e.trust_bundle_present());
    }

    #[test]
    fn build_env_overlay_injects_trust_vars_when_bundle_present() {
        let dir = tempfile::tempdir().unwrap();
        let e = ExecEngine::new(Some(dir.path().to_path_buf()));
        let bundle = dir.path().join("etc/izba/ca-bundle.pem");
        std::fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        std::fs::write(&bundle, "CA\n").unwrap();

        // Caller supplies one of the trust keys; it must win, the rest default.
        let mut r = req(&["x"]);
        r.env = vec![("CURL_CA_BUNDLE".into(), "/custom/ca.pem".into())];
        let env = e.build_env_overlay(&r);
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "CURL_CA_BUNDLE")
                .map(|(_, v)| v.as_str()),
            Some("/custom/ca.pem"),
            "caller CURL_CA_BUNDLE must not be overwritten"
        );
        // All six trust keys present (the supplied one + five defaulted).
        for (k, _) in crate::trust::trust_env_pairs() {
            assert!(
                env.iter().any(|(ek, _)| ek == k),
                "trust var {k} must be present"
            );
        }
    }

    #[test]
    fn build_env_overlay_suppresses_trust_vars_without_bundle() {
        // root=None → no bundle → no trust vars injected.
        let e = engine();
        let r = req(&["x"]);
        let env = e.build_env_overlay(&r);
        for (k, _) in crate::trust::trust_env_pairs() {
            assert!(
                !env.iter().any(|(ek, _)| ek == k),
                "trust var {k} must NOT be injected when no bundle"
            );
        }
    }

    // ── exit-status decode table (crun rc → ExitStatus; NO double-add) ────────

    #[test]
    fn decode_wait_status_table() {
        use nix::sys::wait::WaitStatus as W;
        let pid = Pid::from_raw(1);
        // crun exec propagates the command's rc verbatim → straight passthrough.
        assert_eq!(
            decode_wait_status(Ok(W::Exited(pid, 0))),
            ExitStatus::Code(0)
        );
        // 127 = crun's "executable file not found" → CLI renders exit 127.
        assert_eq!(
            decode_wait_status(Ok(W::Exited(pid, 127))),
            ExitStatus::Code(127)
        );
        // 137 = a signal-killed command (crun already encoded 128+9). We MUST
        // pass it through as Code(137), NOT re-encode as Signal(9), or the host
        // CLI's 128+n mapping would double-add to 265.
        assert_eq!(
            decode_wait_status(Ok(W::Exited(pid, 137))),
            ExitStatus::Code(137)
        );
        // crun-exec PROCESS itself signaled (our kill/kill_all) → Signal.
        assert_eq!(
            decode_wait_status(Ok(W::Signaled(pid, Signal::SIGKILL, false))),
            ExitStatus::Signal(libc::SIGKILL)
        );
        // waitpid error / unexpected status → wedge-proof synthetic failure.
        assert_eq!(
            decode_wait_status(Err(nix::errno::Errno::ECHILD)),
            ExitStatus::Code(-1)
        );
    }

    // ── exec() end-to-end crun argv (overlay + user + crun_exec_argv) ─────────

    #[test]
    fn exec_builds_crun_exec_argv_with_user_and_env() {
        // Verify the argv exec() hands to spawn_argv by reconstructing it from
        // the same pure pieces. This pins exec()'s composition: user mapping,
        // env overlay, and crun_exec_argv ordering.
        let e = engine();
        let mut r = req(&["sh", "-c", "echo hi"]);
        r.tty = false;
        r.cwd = "/workspace".into();
        r.uid = 1000;
        r.gid = 1000;
        r.env = vec![("FOO".into(), "bar".into())];

        let overlay = e.build_env_overlay(&r);
        let user = crun_user_arg(r.uid, r.gid);
        assert_eq!(user.as_deref(), Some("1000:1000"));
        let argv = crate::oci::crun_exec_argv(
            crate::oci::CgroupManager::Disabled,
            r.tty,
            &r.cwd,
            &overlay,
            user.as_deref(),
            &r.argv,
        );
        // crun binary, exec subcommand, cwd, env, user, id, then user argv.
        assert_eq!(argv[0], crate::oci::CRUN_PATH);
        assert!(argv.iter().any(|a| a == "exec"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--cwd" && w[1] == "/workspace"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--env" && w[1] == "FOO=bar"));
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--user" && w[1] == "1000:1000"));
        let id_pos = argv
            .iter()
            .position(|a| a == crate::oci::CONTAINER_ID)
            .unwrap();
        assert_eq!(&argv[id_pos + 1..], &["sh", "-c", "echo hi"]);
    }

    #[test]
    fn crun_user_arg_table() {
        // uid==gid==0 → None (container's configured USER applies).
        assert_eq!(crun_user_arg(0, 0), None);
        // any non-zero id → "uid:gid".
        assert_eq!(crun_user_arg(1000, 1000).as_deref(), Some("1000:1000"));
        assert_eq!(crun_user_arg(0, 1000).as_deref(), Some("0:1000"));
        assert_eq!(crun_user_arg(1000, 0).as_deref(), Some("1000:0"));
    }
}
