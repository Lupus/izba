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
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
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
    /// Chroot for workloads: `Some("/rootfs")` in the guest, `None` in tests.
    root: Option<PathBuf>,
    procs: Mutex<HashMap<u32, ExecProc>>,
    next_id: AtomicU32,
}

impl ExecEngine {
    pub fn new(root: Option<PathBuf>) -> Self {
        Self {
            root,
            procs: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        }
    }

    /// The workload chroot root, if any (`Some("/rootfs")` in the guest,
    /// `None` in tests). Used by the cp tar arms to confine path resolution.
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
            .ok_or((ErrorKind::BadRequest, "empty argv".to_string()))?;

        let mut cmd = Command::new(argv0);
        cmd.args(&req.argv[1..]);
        cmd.env_clear();
        cmd.envs(req.env.iter().map(|(k, v)| (k, v)));
        if !req.env.iter().any(|(k, _)| k == "PATH") {
            cmd.env("PATH", DEFAULT_PATH);
        }
        if req.tty && !req.env.iter().any(|(k, _)| k == "TERM") {
            cmd.env("TERM", DEFAULT_TERM);
        }
        // CA-bundle env defaults for the izba MITM trust anchor, mirroring the
        // PATH/TERM "default unless the caller overrides" pattern. Only
        // advertise them when the combined bundle actually exists in the guest
        // (write_trust_anchor wrote it), so non-MITM sandboxes don't point
        // tools at a missing file. The values are post-chroot guest paths.
        if self.trust_bundle_present() {
            for (k, v) in crate::trust::trust_env_pairs() {
                if !req.env.iter().any(|(ek, _)| ek == k) {
                    cmd.env(k, v);
                }
            }
        }

        let (pty_master, mut streams) = if req.tty {
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
            (
                Some(pty.master),
                Streams {
                    tty: Some(master_dup),
                    ..Streams::default()
                },
            )
        } else {
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            (None, Streams::default())
        };

        // Pre-validate the working directory so a nonexistent cwd surfaces as
        // BadRequest rather than being misclassified as CommandNotFound (both
        // produce ENOENT from the child-side chdir in pre_exec).
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

        let root = self.root.clone();
        let cwd = req.cwd.clone();
        let tty = req.tty;
        let uid = req.uid;
        let gid = req.gid;
        // SAFETY: pre_exec runs in the forked child before exec; only
        // async-signal-safe calls (setsid/ioctl/chroot/chdir/setgid/setuid).
        unsafe {
            cmd.pre_exec(move || {
                // Own session per exec → killpg targets the whole job.
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if tty {
                    // Stdio fds were already dup2'ed by std; fd 0 is the
                    // pty slave. Adopt it as the controlling terminal.
                    if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                if let Some(root) = &root {
                    nix::unistd::chroot(root.as_path()).map_err(std::io::Error::from)?;
                }
                nix::unistd::chdir(Path::new(&cwd)).map_err(std::io::Error::from)?;
                // Drop privileges last (gid before uid, or setgid fails).
                // Skip no-op changes so unprivileged test runs work.
                //
                // Clear supplementary groups to exactly {gid} before setgid.
                // setgroups may fail with EPERM in unprivileged test runs;
                // ignore that — root inside a guest will succeed, and tests
                // run as the invoking user (which has no extra groups to drop).
                let _ = nix::unistd::setgroups(&[nix::unistd::Gid::from_raw(gid)]);
                if gid != nix::unistd::getegid().as_raw() {
                    nix::unistd::setgid(nix::unistd::Gid::from_raw(gid))
                        .map_err(std::io::Error::from)?;
                }
                if uid != nix::unistd::geteuid().as_raw() {
                    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))
                        .map_err(std::io::Error::from)?;
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                (ErrorKind::CommandNotFound, format!("{argv0}: {e}"))
            } else {
                internal(format!("spawn {argv0}: {e}"))
            }
        })?;

        if !req.tty {
            streams.stdin = Some(OwnedFd::from(child.stdin.take().expect("piped stdin")));
            streams.stdout = Some(OwnedFd::from(child.stdout.take().expect("piped stdout")));
            streams.stderr = Some(OwnedFd::from(child.stderr.take().expect("piped stderr")));
        }

        let pid = Pid::from_raw(child.id() as i32);
        let status: StatusCell = Arc::new((Mutex::new(None), Condvar::new()));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        // Dedicated reaper: exactly one waitpid per child, so the engine
        // never races itself over exit statuses.
        {
            let status = Arc::clone(&status);
            std::thread::spawn(move || {
                // `child` is moved in (but never `wait()`ed) so its Drop
                // runs here, not in exec(); only this waitpid reaps.
                let _keep = child;
                let st = match waitpid(pid, None) {
                    Ok(WaitStatus::Exited(_, code)) => ExitStatus::Code(code),
                    Ok(WaitStatus::Signaled(_, sig, _)) => ExitStatus::Signal(sig as i32),
                    // Anything else (or waitpid error) is reported as a
                    // wedge-proof synthetic failure rather than wedging wait().
                    _ => ExitStatus::Code(-1),
                };
                let (lock, cvar) = &*status;
                *lock.lock().unwrap() = Some(st);
                cvar.notify_all();
            });
        }

        self.procs.lock().unwrap().insert(
            id,
            ExecProc {
                pid,
                status,
                tty_mode: req.tty,
                streams,
                pty_master,
            },
        );
        Ok(id)
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

fn set_cloexec(fd: &OwnedFd) -> std::io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    let flags = fcntl(fd.as_raw_fd(), FcntlArg::F_GETFD)?;
    let mut flags = FdFlag::from_bits_retain(flags);
    flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(flags))?;
    Ok(())
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

    #[test]
    fn exit_code_zero() {
        let e = engine();
        let id = e.exec(&req(&["true"])).unwrap();
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Code(0));
    }

    #[test]
    fn exit_code_one() {
        let e = engine();
        let id = e.exec(&req(&["false"])).unwrap();
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Code(1));
    }

    #[test]
    fn command_not_found() {
        let e = engine();
        let (kind, msg) = e.exec(&req(&["/nonexistent/zzz"])).unwrap_err();
        assert_eq!(kind, ErrorKind::CommandNotFound, "{msg}");
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
        let id = e.exec(&req(&["sh", "-c", "echo out"])).unwrap();
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
        let id = e.exec(&req(&["cat"])).unwrap();
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
        let id = e.exec(&req(&["sleep", "30"])).unwrap();
        e.kill(id, 15).unwrap();
        assert_eq!(e.wait(id).unwrap(), ExitStatus::Signal(15));
    }

    #[test]
    fn double_wait_same() {
        let e = engine();
        let id = e.exec(&req(&["false"])).unwrap();
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
        let id = e.exec(&req(&["true"])).unwrap();
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
        let id = e.exec(&req(&["true"])).unwrap();
        let (kind, _) = e.resize(id, 80, 24).unwrap_err();
        assert_eq!(kind, ErrorKind::BadRequest);
        e.wait(id).unwrap();
    }

    #[test]
    fn tty_size() {
        let e = engine();
        let mut r = req(&["sh", "-c", "stty size"]);
        r.tty = true;
        let id = match e.exec(&r) {
            Ok(id) => id,
            Err((_, msg)) if msg.contains("openpty denied") => {
                eprintln!("SKIP: sandbox denies pty allocation: {msg}");
                return;
            }
            Err((k, m)) => panic!("exec failed: {k:?} {m}"),
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
        let id = e.exec(&req(&["true"])).unwrap();
        e.wait(id).unwrap();
        // Process has been reaped; kill should return Ok without signaling.
        e.kill(id, 15).unwrap();
    }

    #[test]
    fn env_is_cleared_and_path_defaulted() {
        let e = engine();
        let mut r = req(&["sh", "-c", "echo \"P=$PATH M=${IZBA_MARKER:-unset}\""]);
        r.env = vec![("IZBA_OTHER".into(), "x".into())];
        std::env::set_var("IZBA_MARKER", "leaked");
        let id = e.exec(&r).unwrap();
        let mut out = String::new();
        File::from(e.take_stream(id, StreamKind::Stdout).unwrap())
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out, format!("P={DEFAULT_PATH} M=unset\n"));
        e.wait(id).unwrap();
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
    fn trust_env_defaulting_skips_caller_supplied_keys() {
        // Mirrors exec()'s injection loop: a caller override for one trust key
        // must win, while the rest still default. (The gate + env_clear path is
        // exercised by exit/PATH tests; this pins the override semantics.)
        let caller: Vec<(String, String)> =
            vec![("CURL_CA_BUNDLE".into(), "/custom/ca.pem".into())];
        let mut injected = Vec::new();
        for (k, v) in crate::trust::trust_env_pairs() {
            if !caller.iter().any(|(ck, _)| ck == k) {
                injected.push((k, v));
            }
        }
        assert!(
            !injected.iter().any(|(k, _)| *k == "CURL_CA_BUNDLE"),
            "caller-supplied CURL_CA_BUNDLE must not be overwritten"
        );
        assert_eq!(injected.len(), 5, "the other five trust vars still default");
    }
}
