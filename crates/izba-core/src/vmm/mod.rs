pub mod cloud_hypervisor;
pub mod openvmm;
pub mod spec;
pub use spec::*;

use crate::procmgr::ConfinementStatus;
use crate::state::PidIdentity;
use std::io::{Read, Write};
use std::time::Duration;

/// A bidirectional byte stream to the guest that supports bounded I/O.
///
/// Control-plane RPCs must never block forever on a wedged-but-accepting
/// guest, so every stream must be able to enforce a read/write deadline.
pub trait IoStream: Read + Write + Send {
    /// Apply (or clear, with `None`) a timeout to subsequent reads and writes.
    fn set_io_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()>;
}

/// Platform alias for a connected AF_UNIX stream socket. Windows 10 1803+
/// supports AF_UNIX natively, but Rust std only exposes it on Unix — the
/// Windows side uses the `uds_windows` crate (same API surface: `connect`,
/// `pair`, `try_clone`, `shutdown`, read/write timeouts).
#[cfg(unix)]
pub type UdsStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type UdsStream = uds_windows::UnixStream;

impl IoStream for UdsStream {
    fn set_io_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(t)?;
        self.set_write_timeout(t)
    }
}

pub trait VmHandle: Send {
    /// Open a byte stream to the given guest vsock port.
    fn connect(&self, port: u32) -> anyhow::Result<Box<dyn IoStream>>;
    /// All processes backing this VM: `("vmm", id)`, `("virtiofsd:<tag>", id)`.
    fn pids(&self) -> Vec<(String, PidIdentity)>;
    fn is_alive(&self) -> bool;
    /// Hard stop (SIGKILL all). Graceful shutdown goes through the guest RPC instead.
    fn kill(&mut self) -> anyhow::Result<()>;
    /// The host-side confinement actually achieved for this VM's VMM process,
    /// captured at launch. Surfaced in status and persisted into `state.json`
    /// so liveness reporting is honest about whether a VM escape would be
    /// contained.
    fn confinement(&self) -> ConfinementStatus;
}

pub trait VmmDriver {
    fn launch(&self, spec: &VmSpec) -> anyhow::Result<Box<dyn VmHandle>>;
}
