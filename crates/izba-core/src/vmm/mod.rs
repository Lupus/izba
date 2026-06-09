pub mod cloud_hypervisor;
pub mod spec;
pub use spec::*;

use crate::state::PidIdentity;
use std::io::{Read, Write};

pub trait IoStream: Read + Write + Send {}
impl<T: Read + Write + Send> IoStream for T {}

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
