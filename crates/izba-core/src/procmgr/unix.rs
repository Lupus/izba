use crate::state::PidIdentity;
use crate::vmm::CommandSpec;
use anyhow::Context;
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Spawn a process detached from the current session.
///
/// The child runs in its own session (setsid), with stdin=/dev/null and
/// stdout+stderr appended to `log`. The `std::process::Child` handle is
/// intentionally forgotten (via `std::mem::forget`) so that the spawning
/// process — a daemonless CLI — can exit without waiting for or killing the
/// child. Orphaned children are reparented to PID 1 and reaped when they
/// eventually die.
///
/// **Zombie handling**: after SIGKILL the child becomes a zombie (`Z` state)
/// because we never call `wait(2)`. Zombies still have a `/proc/<pid>/stat`
/// entry with the same `starttime`, so a naive starttime-only check would
/// report the process as alive forever. `pid_alive` therefore also checks the
/// process state field and treats `Z` as dead.
pub fn spawn_detached(cmd: &CommandSpec, log: &Path) -> anyhow::Result<PidIdentity> {
    let logf = File::options()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening log {}", log.display()))?;
    let mut c = Command::new(&cmd.argv[0]);
    c.args(&cmd.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(logf.try_clone()?))
        .stderr(Stdio::from(logf));
    // SAFETY: setsid(2) is async-signal-safe; no allocation in pre_exec.
    unsafe {
        c.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    let child = c
        .spawn()
        .with_context(|| format!("spawning {:?}", cmd.argv))?;
    let pid = child.id();
    let starttime = proc_starttime(pid)?;
    std::mem::forget(child); // intentional: do not reap; see doc comment above
    Ok(PidIdentity { pid, starttime })
}

/// Parse `/proc/<pid>/stat` and return `(state, starttime)`.
///
/// The `comm` field (field 2) is wrapped in parens and can itself contain
/// spaces or parens, so we locate the LAST `)` to find where the fixed-format
/// fields begin. After that closing paren and a space:
///   index 0 → state (field 3 overall)
///   index 19 → starttime (field 22 overall)
fn proc_stat_fields(pid: u32) -> anyhow::Result<(char, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after = s
        .rfind(')')
        .context("malformed /proc stat: no closing paren")?
        + 2;
    let fields: Vec<&str> = s[after..].split(' ').collect();
    let state = fields
        .first()
        .and_then(|f| f.chars().next())
        .context("malformed /proc stat: missing state field")?;
    let starttime: u64 = fields
        .get(19)
        .context("malformed /proc stat: missing starttime field")?
        .trim()
        .parse()
        .context("malformed /proc stat: non-numeric starttime")?;
    Ok((state, starttime))
}

pub(crate) fn proc_starttime(pid: u32) -> anyhow::Result<u64> {
    proc_stat_fields(pid).map(|(_, starttime)| starttime)
}

/// Returns `true` iff the process identified by `id` is currently alive
/// (not a zombie, and has the same starttime as recorded at spawn).
///
/// Zombie processes (`state == 'Z'`) retain their `/proc/<pid>/stat` entry
/// with the original starttime but are effectively dead — treating them as
/// alive would make `pid_alive` return `true` forever after SIGKILL when the
/// child is never reaped. We therefore report zombies as dead.
pub fn pid_alive(id: &PidIdentity) -> bool {
    match proc_stat_fields(id.pid) {
        Ok((state, starttime)) => state != 'Z' && starttime == id.starttime,
        Err(_) => false,
    }
}

/// Send SIGKILL to the process identified by `id`, if it is still alive.
///
/// This is idempotent: if the process has already exited (or is a zombie),
/// `Ok(())` is returned.
pub fn kill_pid(id: &PidIdentity) -> anyhow::Result<()> {
    if !pid_alive(id) {
        return Ok(());
    }
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    match kill(Pid::from_raw(id.pid as i32), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_and_identity() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("out.log");
        let id = spawn_detached(
            &CommandSpec {
                argv: vec!["sleep".into(), "30".into()],
            },
            &log,
        )
        .unwrap();
        assert!(pid_alive(&id));
        kill_pid(&id).unwrap();
        // SIGKILL is asynchronous; poll up to 2 s.
        // pid_alive treats zombies as dead (see module doc), so this converges
        // even though we never reap the child.
        let dead = (0..40).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            !pid_alive(&id)
        });
        assert!(dead, "process should be dead or zombie after SIGKILL");
    }

    #[test]
    fn identity_defeats_pid_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let id = spawn_detached(
            &CommandSpec {
                argv: vec!["sleep".into(), "30".into()],
            },
            &dir.path().join("l"),
        )
        .unwrap();
        // Forge an identity with a wrong starttime.
        let forged = PidIdentity {
            pid: id.pid,
            starttime: id.starttime + 1,
        };
        assert!(!pid_alive(&forged));
        kill_pid(&id).unwrap();
    }

    #[test]
    fn stdout_to_log() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("echo.log");
        spawn_detached(
            &CommandSpec {
                argv: vec!["sh".into(), "-c".into(), "echo hi".into()],
            },
            &log,
        )
        .unwrap();
        let ok = (0..40).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::fs::read_to_string(&log)
                .map(|s| s.contains("hi"))
                .unwrap_or(false)
        });
        assert!(ok, "log should contain 'hi'");
    }

    #[test]
    fn kill_dead_pid_is_ok() {
        // A PidIdentity that refers to a non-existent PID should not error.
        let dead = PidIdentity {
            pid: 99999,
            starttime: 0,
        };
        assert!(kill_pid(&dead).is_ok());
    }
}
