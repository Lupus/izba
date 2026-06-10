//! Detached process management with PID-reuse-safe identity.
//!
//! The API is platform-independent; each platform supplies the same three
//! functions. `PidIdentity.starttime` is an opaque equality token: Linux uses
//! `/proc/<pid>/stat` field 22 (clock ticks since boot), Windows uses the
//! process creation `FILETIME`. `state.json` is per-host, so the differing
//! unit never crosses platforms.

#[cfg(unix)]
mod unix;
// Consumed only by `sandbox.rs` unit tests (forging identities for liveness
// checks), hence the `test` gate — an unconditional re-export trips
// `unused_imports` in non-test builds.
#[cfg(all(unix, test))]
pub(crate) use unix::proc_starttime;
#[cfg(unix)]
pub use unix::{kill_pid, pid_alive, spawn_detached};

#[cfg(windows)]
mod windows;
// Same test-only re-export rationale as the unix one above.
#[cfg(all(windows, test))]
pub(crate) use windows::proc_starttime;
#[cfg(windows)]
pub use windows::{kill_pid, pid_alive, spawn_detached};
