pub mod cloud_hypervisor;
pub mod openvmm;
pub mod spec;
pub use spec::*;

use crate::procmgr::ConfinementStatus;
use crate::state::PidIdentity;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

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

impl<T: IoStream + ?Sized> IoStream for Box<T> {
    fn set_io_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        (**self).set_io_timeout(t)
    }
}

/// An [`IoStream`] whose every read and write is bounded by ONE overall
/// deadline, fixed at construction.
///
/// A per-syscall timeout ([`IoStream::set_io_timeout`]) restarts on every
/// partial read, so a hostile guest that dribbles a legal-length frame one
/// byte just inside that timeout can hold the reader for as long as the frame
/// lasts (up to `MAX_FRAME`, i.e. effectively forever — #205). Before each
/// operation this wrapper hands the inner stream only the time REMAINING until
/// the deadline (or the caller's own per-op timeout, if tighter), and once the
/// deadline has passed it fails `TimedOut` without touching the inner stream.
pub struct DeadlineStream<S> {
    inner: S,
    deadline: Instant,
    /// The caller's own per-op timeout; the deadline can only tighten it.
    per_op: Option<Duration>,
}

impl<S: IoStream> DeadlineStream<S> {
    pub fn new(inner: S, deadline: Instant) -> Self {
        Self {
            inner,
            deadline,
            per_op: None,
        }
    }

    /// The wrapped stream, for operations outside Read/Write (`shutdown`).
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Arm the inner stream with what is left of the budget, or refuse.
    fn arm(&mut self) -> std::io::Result<()> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "overall I/O deadline exceeded",
            ));
        }
        let t = self.per_op.map_or(remaining, |p| p.min(remaining));
        self.inner.set_io_timeout(Some(t))
    }
}

impl<S: IoStream> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.inner.read(buf)
    }
}

impl<S: IoStream> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<S: IoStream> IoStream for DeadlineStream<S> {
    /// Recorded, not applied: it is re-applied per op, capped by the deadline.
    fn set_io_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.per_op = t;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// What a [`RecordingStream`] saw: every timeout applied, and how many
    /// reads/writes/flushes actually reached it.
    #[derive(Default)]
    struct Seen {
        timeouts: Vec<Option<Duration>>,
        reads: usize,
        writes: usize,
        flushes: usize,
    }

    /// Fake inner stream: always has a byte to read, accepts every write, and
    /// records what the wrapper did to it.
    struct RecordingStream(Arc<Mutex<Seen>>);

    impl Read for RecordingStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().reads += 1;
            buf[0] = 7;
            Ok(1)
        }
    }
    impl Write for RecordingStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().writes += 1;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.lock().unwrap().flushes += 1;
            Ok(())
        }
    }
    impl IoStream for RecordingStream {
        fn set_io_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
            self.0.lock().unwrap().timeouts.push(t);
            Ok(())
        }
    }

    fn recording(deadline: Instant) -> (DeadlineStream<Box<dyn IoStream>>, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let inner: Box<dyn IoStream> = Box::new(RecordingStream(Arc::clone(&seen)));
        (DeadlineStream::new(inner, deadline), seen)
    }

    #[test]
    fn expired_deadline_times_out_without_touching_the_inner_stream() {
        let (mut s, seen) = recording(Instant::now());
        let mut buf = [0u8; 4];
        assert_eq!(s.read(&mut buf).unwrap_err().kind(), ErrorKind::TimedOut);
        assert_eq!(s.write(b"x").unwrap_err().kind(), ErrorKind::TimedOut);
        let seen = seen.lock().unwrap();
        assert_eq!((seen.reads, seen.writes), (0, 0), "inner stream was used");
        assert!(seen.timeouts.is_empty(), "inner timeout was touched");
    }

    #[test]
    fn each_op_gets_only_the_remaining_budget_which_shrinks() {
        let budget = Duration::from_secs(10);
        let (mut s, seen) = recording(Instant::now() + budget);
        let mut buf = [0u8; 1];
        assert_eq!(s.read(&mut buf).unwrap(), 1);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(s.write(b"x").unwrap(), 1);
        let seen = seen.lock().unwrap();
        assert_eq!((seen.reads, seen.writes), (1, 1));
        let [Some(first), Some(second)] = seen.timeouts[..] else {
            panic!("expected two bounded timeouts, got {:?}", seen.timeouts);
        };
        assert!(first <= budget && first > budget - Duration::from_secs(1));
        assert!(
            second < first,
            "the budget must shrink: {first:?} then {second:?}"
        );
    }

    #[test]
    fn a_tighter_caller_timeout_is_kept_and_a_looser_one_is_capped() {
        let budget = Duration::from_secs(10);
        let (mut s, seen) = recording(Instant::now() + budget);
        let mut buf = [0u8; 1];
        s.set_io_timeout(Some(Duration::from_millis(5))).unwrap();
        s.read_exact(&mut buf).unwrap();
        s.set_io_timeout(Some(Duration::from_secs(60))).unwrap();
        s.read_exact(&mut buf).unwrap();
        s.set_io_timeout(None).unwrap();
        s.read_exact(&mut buf).unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.timeouts.len(), 3, "{:?}", seen.timeouts);
        assert_eq!(seen.timeouts[0], Some(Duration::from_millis(5)));
        for t in &seen.timeouts[1..] {
            assert!(
                t.is_some_and(|t| t <= budget),
                "the deadline must cap the per-op timeout: {t:?}"
            );
        }
    }

    #[test]
    fn flush_reaches_the_inner_stream() {
        let (mut s, seen) = recording(Instant::now() + Duration::from_secs(10));
        s.flush().unwrap();
        assert_eq!(seen.lock().unwrap().flushes, 1);
    }

    #[test]
    fn a_prompt_exchange_within_the_deadline_succeeds() {
        let (a, mut b) = UdsStream::pair().unwrap();
        let mut s = DeadlineStream::new(a, Instant::now() + Duration::from_secs(5));
        s.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        b.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
        b.write_all(b"pong").unwrap();
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"pong");
        // The inner stream stays reachable (the VNC probe shuts it down).
        s.inner().shutdown(std::net::Shutdown::Both).unwrap();
    }
}
