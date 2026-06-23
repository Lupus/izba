//! `izba-init __pause` — minimal PID-1 for an interactive OCI container.
//!
//! When a crun container is started in interactive (non-ephemeral) mode, its
//! PID 1 must be a long-lived process that never exits. If the user's container
//! entrypoint crashes or exits, exec must still be able to attach — which
//! requires PID 1 to still be alive. This module provides that pause process.
//!
//! The pause process is PID 1 of the container's PID namespace, so any exec'd
//! processes that outlive their parent get reparented to it. Those reparented
//! processes MUST be reaped or they become permanent zombies. `reap_zombies`
//! handles this: it loops `waitpid(-1, WNOHANG)` to reap all available exited
//! children and returns the count (treating `ECHILD` as "nothing to reap").
//!
//! The main loop (`run`) blocks on `SIGCHLD` via `signalfd` and calls
//! `reap_zombies` on each wake — it never busy-spins.

use nix::sys::signal::{self, SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

/// Reap all currently-available zombie children without blocking.
///
/// Calls `waitpid(-1, WNOHANG)` in a loop until either:
/// - `ECHILD`: no children exist → returns accumulated count (may be 0).
/// - `WouldBlock`: no children are ready yet → returns accumulated count.
///
/// Returns the number of children successfully reaped.
pub fn reap_zombies() -> usize {
    let mut count = 0usize;
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            // A child exited or was killed — reap it and keep going.
            Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => {
                count += 1;
            }
            // Job-control notifications: not a zombie reap, don't count.
            Ok(WaitStatus::Stopped(_, _)) | Ok(WaitStatus::Continued(_)) => {}
            // No more children ready right now.
            Ok(WaitStatus::StillAlive) => break,
            // No children at all — normal when there's nothing to reap.
            Err(nix::errno::Errno::ECHILD) => break,
            // Any other error: stop looping to avoid a tight error-spin.
            Ok(_) | Err(_) => break,
        }
    }
    count
}

/// Block-on-SIGCHLD pause loop. Runs forever — never returns under normal
/// operation.
///
/// The loop uses `signalfd` so it sleeps in the kernel until a signal arrives,
/// then calls `reap_zombies` to drain any zombie children.
pub fn run() -> ! {
    // Block SIGCHLD in the normal signal delivery path so signalfd gets it.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    signal::sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&mask), None)
        .expect("pause: sigprocmask SIG_BLOCK SIGCHLD");

    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC).expect("pause: signalfd creation");

    loop {
        // Blocks until SIGCHLD arrives (or signalfd is readable).
        let _ = sfd.read_signal();
        reap_zombies();
    }
}

#[cfg(test)]
mod tests {
    use super::reap_zombies;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    use std::os::fd::AsRawFd;

    /// Single byte the isolated subprocess writes to the result pipe IFF every
    /// `reap_zombies` check passed. Its ABSENCE is the failure signal.
    const OK_SENTINEL: u8 = b'K';

    /// Exercises both `reap_zombies` outcomes inside a FORKED SUBPROCESS, with
    /// the verdict carried over a pipe rather than the subprocess exit code.
    ///
    /// `reap_zombies` calls `waitpid(-1, WNOHANG)`, which reaps *any* child of
    /// the calling process. Running it in the shared test-binary process would
    /// (a) let it steal children spawned by other parallel tests — breaking
    /// their own `wait()` with `ECHILD` — and (b) let those children inflate its
    /// reap count. That cross-test race is real: it surfaced under the coverage
    /// run's timing. Forking confines `waitpid(-1)` to children WE create here.
    ///
    /// **Verdict via a sentinel pipe, not the exit code.** A failed check — or a
    /// usize-underflow panic from a mutated `count += 1` → `-= 1` inside the
    /// forked child, whose unwinding through the test harness yields an
    /// unreliable exit code — simply never writes `OK_SENTINEL`. The parent
    /// treats a missing sentinel (EOF on the read end) as failure, so the result
    /// is deterministic regardless of how the child ends. The subprocess uses
    /// only async-signal-safe calls (fork / waitpid / nanosleep / write /
    /// `_exit`, never `malloc`/`eprintln`) — mandatory after `fork()` in a
    /// multi-threaded harness where another thread may hold the allocator lock.
    #[test]
    fn reap_zombies_reaps_then_returns_zero() {
        let (read_end, write_end) = nix::unistd::pipe().expect("pipe");

        let subproc = match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                // Child: keep only the write end; signal success via the pipe.
                drop(read_end);
                if run_isolated_reaper_checks() {
                    let b = [OK_SENTINEL];
                    // async-signal-safe write; ignore the (irrelevant) result.
                    unsafe { libc::write(write_end.as_raw_fd(), b.as_ptr().cast(), 1) };
                }
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => child,
        };

        // Parent: drop the write end so the read sees EOF once the child is gone.
        drop(write_end);
        let mut buf = [0u8; 1];
        let got = loop {
            match nix::unistd::read(read_end.as_raw_fd(), &mut buf) {
                Ok(n) => break n,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => break 0,
            }
        };
        // Reap the subprocess by its specific pid (never `-1`), so this test
        // leaves no zombie and never disturbs another test's children.
        let _ = waitpid(subproc, None);

        assert!(
            got == 1 && buf[0] == OK_SENTINEL,
            "isolated reap_zombies checks failed: no success sentinel \
             (read {got} byte(s)) — see the checks in run_isolated_reaper_checks"
        );
    }

    /// Runs in the forked subprocess. Returns `true` iff every check passed.
    ///
    /// Async-signal-safe only (no allocation, no stdio locks): after `fork()` in
    /// the multi-threaded harness, `malloc`/`eprintln` could deadlock on a lock
    /// held by a now-absent thread.
    fn run_isolated_reaper_checks() -> bool {
        // Part 1: reap_zombies() reaps a forked quick-exiting child, and the
        // specific child then becomes unwaitable (already reaped).
        let child = match unsafe { fork() } {
            Ok(ForkResult::Child) => unsafe { libc::_exit(0) },
            Ok(ForkResult::Parent { child }) => child,
            Err(_) => return false,
        };
        let mut count = 0;
        for _ in 0..2000 {
            count = reap_zombies();
            if count > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Exactly one child was forked, so the reaping call must report exactly
        // one — asserting `== 1` (not just `> 0`) pins the `count += 1`
        // accumulator: a `*=` mutant leaves it 0 and a `-=` mutant wraps it.
        if count != 1 {
            return false;
        }
        if let Ok(WaitStatus::StillAlive) = waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            return false; // any already-reaped status (or ECHILD) is fine
        }

        // Part 2: with no children left, reap_zombies() must return 0 (the
        // ECHILD/StillAlive path, no spin). Reliable HERE because this isolated
        // subprocess has no other children — exactly what the outer fork buys.
        reap_zombies() == 0
    }
}
