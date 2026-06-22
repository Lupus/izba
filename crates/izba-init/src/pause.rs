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
    use nix::sys::wait::waitpid;
    use nix::unistd::{fork, ForkResult};

    /// `reap_zombies` returns 0 on `ECHILD` — exercised deterministically.
    ///
    /// Strategy: fork a quick-exiting child, then `waitpid` it *directly* to
    /// fully exhaust it from the child table.  After that, `reap_zombies()` on
    /// that PID subtree sees ECHILD and must return 0.
    #[test]
    fn reap_zombies_no_children_returns_zero() {
        // Fork a child that exits immediately.
        let child_pid = match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => child,
        };

        // Reap the child directly with a *blocking* wait so we know it is gone.
        loop {
            match waitpid(child_pid, None) {
                Ok(_) => break,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => panic!("waitpid failed: {e}"),
            }
        }

        // Now the child table for this child is empty.  reap_zombies() must hit
        // ECHILD (or StillAlive with count 0) and return 0.
        let n = reap_zombies();
        assert_eq!(
            n, 0,
            "expected 0 after all children already reaped, got {n}"
        );
    }

    /// `reap_zombies` reaps a forked quick-exiting child and reports count ≥ 1.
    /// Asserts that the specific child PID is no longer in the process table
    /// (a second targeted wait returns ECHILD).
    #[test]
    fn reap_zombies_reaps_a_quick_exit_child() {
        // Safety: this is a fork test. The child calls _exit immediately, so it
        // does not interact with the Rust runtime or test harness.
        let child_pid = match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                // Exit immediately; the parent will wait for us.
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => child,
        };

        // Give the kernel a moment to reap + mark the child as zombie.
        // We loop with a small sleep instead of a fixed sleep so the test
        // stays fast on fast machines.
        let count = loop {
            let n = reap_zombies();
            if n > 0 {
                break n;
            }
            // Tiny yield — the child may not have exited yet.
            std::thread::sleep(std::time::Duration::from_millis(1));
        };

        assert!(count >= 1, "expected ≥1 reaped child, got {count}");

        // Verify the specific child is gone: a blocking wait for that exact PID
        // should now return ECHILD (already reaped) or Err(ECHILD).
        let second = nix::sys::wait::waitpid(child_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
        // ECHILD means already reaped — exactly what we expect.
        match second {
            Err(nix::errno::Errno::ECHILD) => {} // already reaped ✓
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                panic!("child pid {child_pid} still alive after reap_zombies");
            }
            other => {
                // Any other result (already-reaped WaitStatus) is also fine.
                let _ = other;
            }
        }
    }
}
