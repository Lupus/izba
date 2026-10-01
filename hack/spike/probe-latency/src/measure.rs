//! One timed `Health` exchange, and the JSON line that reports it.
//!
//! Both measurements are the same three steps — open a control-port stream,
//! write `Request::Health`, read one `Response` — and differ only in how the
//! stream is opened:
//!
//! * **probe**: `sandbox::control`, exactly what `probe_container_state` calls.
//!   It runs the liveness assessment (pid identity checks plus a `Health`
//!   exchange of its own on a separate connection) and then dials again.
//! * **direct**: the bare connector. One dial, one guest round trip.
//!
//! The daemon wraps its stream in a `DeadlineStream` bounded by
//! `CONTAINER_PROBE_TIMEOUT`; this tool deliberately does not, so a phase that
//! would have been cut off at the bound is measured at its real length.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use izba_core::paths::Paths;
use izba_core::sandbox::Connector;
use izba_core::vmm::IoStream;
use izba_proto::{read_frame, write_frame, Request, Response};
use serde::ser::SerializeMap as _;
use serde::{Serialize, Serializer};

use crate::classify::inspect_container;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Probe,
    Direct,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Probe => "probe",
            Kind::Direct => "direct",
        }
    }

    /// The phase that opens the stream.
    pub fn open_phase(self) -> Phase {
        match self {
            Kind::Probe => Phase::Control,
            Kind::Direct => Phase::Dial,
        }
    }

    /// JSON key of the open-phase duration.
    pub fn open_field(self) -> &'static str {
        match self {
            Kind::Probe => "control_us",
            Kind::Direct => "dial_us",
        }
    }

    /// JSON key of the write+read duration.
    pub fn rpc_field(self) -> &'static str {
        match self {
            Kind::Probe => "health_us",
            Kind::Direct => "rpc_us",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Control,
    Dial,
    Write,
    Read,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Control => "control",
            Phase::Dial => "dial",
            Phase::Write => "write",
            Phase::Read => "read",
        }
    }
}

/// The outcome of one exchange. A duration is `Some` only when its phase
/// COMPLETED; a failed exchange instead carries `failed_after_us`, the time
/// from start to the failure, so a time-to-failure is never mistaken for a
/// latency sample.
#[derive(Debug, Clone)]
pub struct Measured {
    pub open_us: Option<u64>,
    pub rpc_us: Option<u64>,
    pub total_us: Option<u64>,
    pub failed_after_us: Option<u64>,
    pub phase_failed: Option<Phase>,
    /// The full anyhow chain (`{:#}`) of the failed step.
    pub error: Option<String>,
    pub response: Option<Response>,
    /// See [`crate::classify::inspect_container`].
    pub inspect_container: String,
}

impl Measured {
    /// Every step completed. NOT the same as "the workload is running": a
    /// well-formed non-`Health` reply is `ok` and still classifies as `none`.
    pub fn ok(&self) -> bool {
        self.phase_failed.is_none()
    }
}

/// Per-syscall read/write timeout put on the stream so a wedged guest ends the
/// iteration as a `read` failure instead of hanging the tool. It is a safety
/// net, not the bound under test: at least 30 s and at least twice the bound,
/// so every latency up to 2x the bound is still observed in full.
pub fn io_cap(bound_ms: u64) -> Duration {
    Duration::from_millis(bound_ms.saturating_mul(2)).max(Duration::from_secs(30))
}

/// Open a stream with `open`, then do one `Health` exchange on it, timing the
/// open and the exchange separately.
pub fn exchange(
    kind: Kind,
    io_cap: Duration,
    open: impl FnOnce() -> anyhow::Result<Box<dyn IoStream>>,
) -> Measured {
    let t0 = Instant::now();
    let mut conn = match open() {
        Ok(conn) => conn,
        Err(e) => return failed(kind.open_phase(), None, t0, e),
    };
    let t1 = Instant::now();
    let open_us = Some(micros(t0, t1));

    let sent = conn
        .set_io_timeout(Some(io_cap))
        .context("setting the safety I/O timeout")
        .and_then(|()| {
            write_frame(&mut conn, &Request::Health).context("writing the Health request")
        });
    if let Err(e) = sent {
        return failed(Phase::Write, open_us, t0, e);
    }
    let response = match read_frame::<_, Response>(&mut conn) {
        Ok(response) => response,
        Err(e) => {
            let e = anyhow::Error::new(e).context("reading the Health response");
            return failed(Phase::Read, open_us, t0, e);
        }
    };
    let t2 = Instant::now();

    let outcome: anyhow::Result<Response> = Ok(response);
    Measured {
        open_us,
        rpc_us: Some(micros(t1, t2)),
        total_us: Some(micros(t0, t2)),
        failed_after_us: None,
        phase_failed: None,
        error: None,
        inspect_container: inspect_container(&outcome),
        response: outcome.ok(),
    }
}

fn failed(phase: Phase, open_us: Option<u64>, t0: Instant, e: anyhow::Error) -> Measured {
    let failed_after_us = Some(micros(t0, Instant::now()));
    let error = Some(format!("{e:#}"));
    let outcome: anyhow::Result<Response> = Err(e);
    Measured {
        open_us,
        rpc_us: None,
        total_us: None,
        failed_after_us,
        phase_failed: Some(phase),
        error,
        response: None,
        inspect_container: inspect_container(&outcome),
    }
}

/// The probe replica: `sandbox::control` (liveness assessment + dial), then
/// the `Health` exchange — `probe_container_state` minus its `DeadlineStream`.
pub fn measure_probe(
    paths: &Paths,
    name: &str,
    connector: Connector,
    io_cap: Duration,
) -> Measured {
    exchange(Kind::Probe, io_cap, || {
        izba_core::sandbox::control(paths, name, connector)
    })
}

/// One bare dial and one guest round trip.
pub fn measure_direct(
    paths: &Paths,
    name: &str,
    connector: Connector,
    io_cap: Duration,
) -> Measured {
    exchange(Kind::Direct, io_cap, || connector(paths, name))
}

/// One output line: a [`Measured`] plus where and when it was taken.
#[derive(Debug, Clone)]
pub struct Sample {
    pub worker: u32,
    pub iteration: u32,
    /// Milliseconds from tool start to this measurement's start, for lining
    /// up overlapping workers.
    pub started_ms: u64,
    pub kind: Kind,
    pub m: Measured,
}

/// Serialized by hand so the two duration keys can be named per measurement
/// (`control_us`/`health_us` vs `dial_us`/`rpc_us`) and the keys keep a
/// readable order.
impl Serialize for Sample {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let m = &self.m;
        let mut map = s.serialize_map(Some(13))?;
        map.serialize_entry("worker", &self.worker)?;
        map.serialize_entry("iteration", &self.iteration)?;
        map.serialize_entry("measurement", self.kind.name())?;
        map.serialize_entry("started_ms", &self.started_ms)?;
        map.serialize_entry(self.kind.open_field(), &m.open_us)?;
        map.serialize_entry(self.kind.rpc_field(), &m.rpc_us)?;
        map.serialize_entry("total_us", &m.total_us)?;
        map.serialize_entry("ok", &m.ok())?;
        map.serialize_entry("inspect_container", &m.inspect_container)?;
        map.serialize_entry("phase_failed", &m.phase_failed.map(Phase::as_str))?;
        map.serialize_entry("failed_after_us", &m.failed_after_us)?;
        map.serialize_entry("error", &m.error)?;
        map.serialize_entry("response", &m.response)?;
        map.end()
    }
}

/// Elapsed microseconds, saturating.
pub(crate) fn micros(from: Instant, to: Instant) -> u64 {
    u64::try_from(to.saturating_duration_since(from).as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_core::vmm::UdsStream;
    use izba_proto::{read_frame, write_frame, ContainerState, HealthInfo, Request};
    use std::thread::JoinHandle;

    const CAP: Duration = Duration::from_secs(10);

    fn health(container: Option<ContainerState>) -> Response {
        Response::Health(HealthInfo {
            version: "test".into(),
            uptime_ms: 7,
            container,
        })
    }

    /// A socketpair standing in for the guest (no listener: some sandboxes
    /// deny `bind`). The fake reads one request and answers with `reply`, or
    /// hangs up without answering when `reply` is `None`. Joining it yields
    /// the request it saw.
    fn fake_guest(reply: Option<Response>) -> (Box<dyn IoStream>, JoinHandle<Request>) {
        let (host, mut guest) = UdsStream::pair().expect("socketpair");
        let handle = std::thread::spawn(move || {
            let req: Request = read_frame(&mut guest).expect("guest reads the request");
            if let Some(reply) = reply {
                write_frame(&mut guest, &reply).expect("guest writes the reply");
            }
            req
        });
        (Box::new(host), handle)
    }

    fn sample(kind: Kind, m: Measured) -> Sample {
        Sample {
            worker: 2,
            iteration: 5,
            started_ms: 1234,
            kind,
            m,
        }
    }

    fn json(s: &Sample) -> serde_json::Value {
        serde_json::from_str(&serde_json::to_string(s).unwrap()).unwrap()
    }

    #[test]
    fn running_guest_is_ok_with_all_three_durations() {
        let (host, guest) = fake_guest(Some(health(Some(ContainerState::Running))));
        let m = exchange(Kind::Direct, CAP, move || Ok(host));
        // It sent exactly the request the daemon's probe sends.
        assert!(matches!(guest.join().unwrap(), Request::Health));
        assert!(m.ok());
        assert_eq!(m.phase_failed, None);
        assert_eq!(m.error, None);
        assert_eq!(m.failed_after_us, None);
        assert_eq!(m.inspect_container, "some:running");
        let (open, rpc, total) = (m.open_us.unwrap(), m.rpc_us.unwrap(), m.total_us.unwrap());
        // total spans both phases (each figure truncates to whole µs).
        assert!(total >= open && total >= rpc, "{open} {rpc} {total}");
        assert!(total <= open + rpc + 1, "{open} {rpc} {total}");
        assert!(matches!(m.response, Some(Response::Health(_))));
    }

    #[test]
    fn guest_reported_unknown_is_ok_and_some_unknown() {
        let (host, guest) = fake_guest(Some(health(Some(ContainerState::Unknown))));
        let m = exchange(Kind::Probe, CAP, move || Ok(host));
        guest.join().unwrap();
        assert!(m.ok());
        assert_eq!(m.inspect_container, "some:unknown");
    }

    #[test]
    fn non_health_reply_is_ok_but_none() {
        let (host, guest) = fake_guest(Some(Response::Ok));
        let m = exchange(Kind::Probe, CAP, move || Ok(host));
        guest.join().unwrap();
        assert!(m.ok(), "every step completed");
        assert_eq!(m.inspect_container, "none");
        assert!(matches!(m.response, Some(Response::Ok)));
    }

    #[test]
    fn failed_open_is_blamed_on_the_open_phase_of_that_measurement() {
        for (kind, phase) in [(Kind::Probe, Phase::Control), (Kind::Direct, Phase::Dial)] {
            let m = exchange(kind, CAP, || {
                Err(anyhow::anyhow!("connection refused").context("connecting to vsock.sock"))
            });
            assert!(!m.ok());
            assert_eq!(m.phase_failed, Some(phase));
            // The whole chain, outermost first.
            assert_eq!(
                m.error.as_deref(),
                Some("connecting to vsock.sock: connection refused")
            );
            assert_eq!((m.open_us, m.rpc_us, m.total_us), (None, None, None));
            assert!(m.failed_after_us.is_some());
            assert_eq!(m.inspect_container, "none");
            assert!(m.response.is_none());
        }
    }

    #[test]
    fn guest_hanging_up_without_answering_fails_the_read() {
        let (host, guest) = fake_guest(None);
        let m = exchange(Kind::Direct, CAP, move || Ok(host));
        guest.join().unwrap();
        assert_eq!(m.phase_failed, Some(Phase::Read));
        // The open completed and keeps its duration; nothing after it does.
        assert!(m.open_us.is_some());
        assert_eq!((m.rpc_us, m.total_us), (None, None));
        assert!(m.failed_after_us.unwrap() >= m.open_us.unwrap());
        assert!(m.error.is_some());
        assert_eq!(m.inspect_container, "none");
    }

    /// Unix only: writing to a socketpair whose peer is gone is EPIPE there.
    #[cfg(unix)]
    #[test]
    fn peer_gone_before_the_request_fails_the_write() {
        let (host, guest) = UdsStream::pair().expect("socketpair");
        drop(guest);
        let m = exchange(Kind::Probe, CAP, move || {
            Ok(Box::new(host) as Box<dyn IoStream>)
        });
        assert_eq!(m.phase_failed, Some(Phase::Write));
        assert!(m.open_us.is_some());
        assert_eq!((m.rpc_us, m.total_us), (None, None));
        assert_eq!(m.inspect_container, "none");
    }

    #[test]
    fn silent_guest_is_cut_off_by_the_io_cap_as_a_read_failure() {
        // Keep the peer open and silent; only the cap can end this.
        let (host, _guest) = UdsStream::pair().expect("socketpair");
        let started = Instant::now();
        let m = exchange(Kind::Direct, Duration::from_millis(100), move || {
            Ok(Box::new(host) as Box<dyn IoStream>)
        });
        assert_eq!(m.phase_failed, Some(Phase::Read));
        assert!(m.failed_after_us.unwrap() >= 100_000);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn io_cap_is_a_safety_net_well_above_the_bound() {
        assert_eq!(io_cap(5000), Duration::from_secs(30));
        assert_eq!(io_cap(1), Duration::from_secs(30));
        assert_eq!(io_cap(15_000), Duration::from_secs(30));
        assert_eq!(io_cap(60_000), Duration::from_secs(120));
    }

    #[test]
    fn micros_saturates_instead_of_panicking() {
        let a = Instant::now();
        let b = a + Duration::from_micros(1500);
        assert_eq!(micros(a, b), 1500);
        assert_eq!(micros(b, a), 0);
    }

    #[test]
    fn probe_line_uses_the_probe_key_names() {
        let (host, guest) = fake_guest(Some(health(Some(ContainerState::Running))));
        let m = exchange(Kind::Probe, CAP, move || Ok(host));
        guest.join().unwrap();
        let v = json(&sample(Kind::Probe, m));
        assert_eq!(v["measurement"], "probe");
        assert_eq!(v["worker"], 2);
        assert_eq!(v["iteration"], 5);
        assert_eq!(v["started_ms"], 1234);
        assert!(v["control_us"].is_u64());
        assert!(v["health_us"].is_u64());
        assert!(v["total_us"].is_u64());
        assert!(v.get("dial_us").is_none() && v.get("rpc_us").is_none());
        assert_eq!(v["ok"], true);
        assert!(v["error"].is_null());
        assert!(v["phase_failed"].is_null());
        assert!(v["failed_after_us"].is_null());
        assert_eq!(v["inspect_container"], "some:running");
        // The raw reply, re-serialized exactly as it travels on the wire.
        assert_eq!(
            v["response"],
            serde_json::json!({
                "type": "health",
                "version": "test",
                "uptime_ms": 7,
                "container": "running",
            })
        );
    }

    #[test]
    fn direct_line_uses_the_direct_key_names() {
        let (host, guest) = fake_guest(Some(health(Some(ContainerState::Unknown))));
        let m = exchange(Kind::Direct, CAP, move || Ok(host));
        guest.join().unwrap();
        let v = json(&sample(Kind::Direct, m));
        assert_eq!(v["measurement"], "direct");
        assert!(v["dial_us"].is_u64());
        assert!(v["rpc_us"].is_u64());
        assert!(v.get("control_us").is_none() && v.get("health_us").is_none());
        assert_eq!(v["inspect_container"], "some:unknown");
        assert_eq!(v["response"]["container"], "unknown");
    }

    #[test]
    fn failed_line_carries_error_phase_and_nulls() {
        let m = exchange(Kind::Probe, CAP, || {
            Err(anyhow::anyhow!("sandbox 'x' is not running"))
        });
        let v = json(&sample(Kind::Probe, m));
        assert_eq!(v["ok"], false);
        assert_eq!(v["phase_failed"], "control");
        assert_eq!(v["error"], "sandbox 'x' is not running");
        assert!(v["control_us"].is_null());
        assert!(v["health_us"].is_null());
        assert!(v["total_us"].is_null());
        assert!(v["failed_after_us"].is_u64());
        assert!(v["response"].is_null());
        assert_eq!(v["inspect_container"], "none");
    }

    #[test]
    fn a_line_is_one_line() {
        let m = exchange(Kind::Probe, CAP, || Err(anyhow::anyhow!("multi\nline")));
        let line = serde_json::to_string(&sample(Kind::Probe, m)).unwrap();
        assert!(!line.contains('\n'), "{line}");
    }
}
