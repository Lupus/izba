pub mod cloud_hypervisor;
pub mod spec;
pub use spec::*;

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

impl IoStream for std::os::unix::net::UnixStream {
    fn set_io_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(t)?;
        self.set_write_timeout(t)
    }
}

pub trait VmHandle: Send {
    /// Open a byte stream to the given guest vsock port.
    fn connect(&self, port: u32) -> anyhow::Result<Box<dyn IoStream>>;
    /// All processes backing this VM: `("vmm", id)`, `("virtiofsd:<tag>", id)`, `("passt", id)`.
    fn pids(&self) -> Vec<(String, PidIdentity)>;
    fn is_alive(&self) -> bool;
    /// Hard stop (SIGKILL all). Graceful shutdown goes through the guest RPC instead.
    fn kill(&mut self) -> anyhow::Result<()>;
}

pub trait VmmDriver {
    fn launch(&self, spec: &VmSpec) -> anyhow::Result<Box<dyn VmHandle>>;
}
