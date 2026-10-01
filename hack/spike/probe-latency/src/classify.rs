//! What the product's container line would be built from, for one probe
//! outcome.
//!
//! Each request mirrors the tail of its probe in
//! `crates/izba-core/src/daemon/server.rs` exactly.
//!
//! `health` — `probe_container_state`, which feeds `SandboxDetail.container`
//! (`izba status` / Inspect):
//!
//! ```text
//! match read_frame::<_, Response>(&mut conn).ok()? {
//!     Response::Health(h) => h.container,
//!     _ => None,
//! }
//! ```
//!
//! `stats` — `probe_guest_stats`, whose result's `container` field is
//! `stats.guest.container`, read by the desktop app's Overview:
//!
//! ```text
//! match read_frame::<_, Response>(&mut conn).ok()? {
//!     Response::Stats(g) => Some(g),
//!     _ => None,
//! }
//! ```
//!
//! The product prints "unknown" for BOTH `None` and
//! `Some(ContainerState::Unknown)`. The strings here keep them apart.

use izba_proto::Response;

use crate::request::RequestKind;

/// The probe yielded no container state: a step failed, the guest answered
/// with something other than the reply this request expects, or that reply
/// carried no `container`.
pub const NONE: &str = "none";

/// The one outcome the tool's exit status treats as healthy.
pub const RUNNING: &str = "some:running";

/// `"none"`, or `"some:<state>"` using [`izba_proto::ContainerState::as_str`]
/// — so a guest-reported `Unknown` is `"some:unknown"`, never `"none"`.
///
/// Only the reply type `request` expects counts: a `Health` reply to a
/// `Stats` request is `"none"`, as it is in the daemon, and vice versa.
pub fn inspect_container<E>(request: RequestKind, outcome: &Result<Response, E>) -> String {
    let container = match (request, outcome) {
        (RequestKind::Health, Ok(Response::Health(h))) => h.container,
        (RequestKind::Stats, Ok(Response::Stats(g))) => g.container,
        (_, Ok(_) | Err(_)) => None,
    };
    match container {
        Some(state) => format!("some:{}", state.as_str()),
        None => NONE.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::{ContainerState, ErrorKind, GuestStats, HealthInfo};

    const ALL_STATES: [ContainerState; 6] = [
        ContainerState::Creating,
        ContainerState::Created,
        ContainerState::Running,
        ContainerState::Stopped,
        ContainerState::Paused,
        ContainerState::Unknown,
    ];

    fn health(container: Option<ContainerState>) -> Result<Response, String> {
        Ok(Response::Health(HealthInfo {
            version: "test".into(),
            uptime_ms: 1,
            container,
        }))
    }

    fn stats(container: Option<ContainerState>) -> Result<Response, String> {
        Ok(Response::Stats(GuestStats {
            processes: vec![],
            process_count: 7,
            load1_centi: 1,
            load5_centi: 2,
            load15_centi: 3,
            mem_total_kb: 4096,
            mem_available_kb: 2048,
            mounts: vec![],
            docker: None,
            container,
        }))
    }

    /// `inspect_container` for a `Health` request.
    fn on_health<E>(outcome: &Result<Response, E>) -> String {
        inspect_container(RequestKind::Health, outcome)
    }

    /// `inspect_container` for a `Stats` request.
    fn on_stats<E>(outcome: &Result<Response, E>) -> String {
        inspect_container(RequestKind::Stats, outcome)
    }

    /// The daemon's own mapping, copied from `probe_container_state`, so the
    /// tests below compare against the thing being mirrored rather than
    /// against a second hand-written table.
    fn daemon_probe<E>(outcome: Result<Response, E>) -> Option<ContainerState> {
        match outcome.ok()? {
            Response::Health(h) => h.container,
            _ => None,
        }
    }

    /// Likewise `probe_guest_stats`, followed by the `.container` the app
    /// reads off its result.
    fn daemon_stats_probe<E>(outcome: Result<Response, E>) -> Option<ContainerState> {
        let guest = match outcome.ok()? {
            Response::Stats(g) => Some(g),
            _ => None,
        };
        guest?.container
    }

    fn render(v: Option<ContainerState>) -> String {
        match v {
            None => "none".to_string(),
            Some(s) => format!("some:{}", s.as_str()),
        }
    }

    #[test]
    fn running_workload() {
        assert_eq!(
            on_health(&health(Some(ContainerState::Running))),
            "some:running"
        );
        assert_eq!(RUNNING, "some:running");
    }

    #[test]
    fn guest_reported_unknown_is_some_unknown() {
        assert_eq!(
            on_health(&health(Some(ContainerState::Unknown))),
            "some:unknown"
        );
    }

    #[test]
    fn health_without_a_container_field_is_none() {
        assert_eq!(on_health(&health(None)), "none");
    }

    #[test]
    fn non_health_response_is_none() {
        let ok: Result<Response, String> = Ok(Response::Ok);
        assert_eq!(on_health(&ok), "none");
        let error: Result<Response, String> = Ok(Response::Error {
            kind: ErrorKind::BadRequest,
            message: "no".into(),
        });
        assert_eq!(on_health(&error), "none");
    }

    #[test]
    fn a_failed_step_is_none() {
        let failed: Result<Response, String> = Err("timed out".into());
        assert_eq!(on_health(&failed), "none");
    }

    /// The whole point of the tool: `izba status` shows "unknown" for both of
    /// these, and they are different outcomes with different causes.
    #[test]
    fn some_unknown_and_none_are_different_outcomes() {
        let guest_said_unknown = on_health(&health(Some(ContainerState::Unknown)));
        let probe_gave_up: Result<Response, String> = Err("timed out".into());
        let probe_gave_up = on_health(&probe_gave_up);
        assert_ne!(guest_said_unknown, probe_gave_up);
        assert_ne!(guest_said_unknown, on_health(&health(None)));
    }

    #[test]
    fn mirrors_the_daemon_for_every_state() {
        for state in ALL_STATES {
            assert_eq!(
                on_health(&health(Some(state))),
                render(daemon_probe(health(Some(state)))),
            );
        }
        assert_eq!(on_health(&health(None)), render(daemon_probe(health(None))));
        let ok: Result<Response, String> = Ok(Response::Ok);
        assert_eq!(on_health(&ok), render(daemon_probe(ok)));
        let failed: Result<Response, String> = Err("x".into());
        assert_eq!(on_health(&failed), render(daemon_probe(failed)));
    }

    /// Straight off the wire: an old guest's frame has no `container` key
    /// (`#[serde(default)]`), a current guest whose `crun state` failed sends
    /// `"unknown"`.
    #[test]
    fn classifies_real_wire_frames() {
        let parse =
            |json: &str| -> Result<Response, serde_json::Error> { serde_json::from_str(json) };
        assert_eq!(
            on_health(&parse(r#"{"type":"health","version":"v","uptime_ms":5}"#)),
            "none"
        );
        assert_eq!(
            on_health(&parse(
                r#"{"type":"health","version":"v","uptime_ms":5,"container":"unknown"}"#
            )),
            "some:unknown"
        );
        assert_eq!(
            on_health(&parse(
                r#"{"type":"health","version":"v","uptime_ms":5,"container":"running"}"#
            )),
            "some:running"
        );
        assert_eq!(on_health(&parse("not json")), "none");
    }

    // ---- `--request stats` -------------------------------------------------

    #[test]
    fn stats_running_workload() {
        assert_eq!(
            on_stats(&stats(Some(ContainerState::Running))),
            "some:running"
        );
    }

    #[test]
    fn stats_guest_reported_unknown_is_some_unknown() {
        assert_eq!(
            on_stats(&stats(Some(ContainerState::Unknown))),
            "some:unknown"
        );
    }

    #[test]
    fn stats_without_a_container_is_none() {
        assert_eq!(on_stats(&stats(None)), "none");
    }

    #[test]
    fn stats_some_unknown_and_none_are_different_outcomes() {
        let guest_said_unknown = on_stats(&stats(Some(ContainerState::Unknown)));
        let probe_gave_up: Result<Response, String> = Err("timed out".into());
        assert_ne!(guest_said_unknown, on_stats(&probe_gave_up));
        assert_ne!(guest_said_unknown, on_stats(&stats(None)));
    }

    #[test]
    fn stats_request_non_stats_response_or_failure_is_none() {
        let ok: Result<Response, String> = Ok(Response::Ok);
        assert_eq!(on_stats(&ok), "none");
        // The kind of reply a guest that predates `Request::Stats` gives.
        let error: Result<Response, String> = Ok(Response::Error {
            kind: ErrorKind::BadRequest,
            message: "unknown variant `stats`".into(),
        });
        assert_eq!(on_stats(&error), "none");
        let failed: Result<Response, String> = Err("timed out".into());
        assert_eq!(on_stats(&failed), "none");
    }

    /// Only the reply the request expects counts — `probe_guest_stats` drops a
    /// `Health`, and `probe_container_state` drops a `Stats`, even though
    /// each carries a perfectly good container state.
    #[test]
    fn the_other_requests_reply_is_none() {
        assert_eq!(on_stats(&health(Some(ContainerState::Running))), "none");
        assert_eq!(on_health(&stats(Some(ContainerState::Running))), "none");
    }

    #[test]
    fn stats_mirrors_the_daemon_for_every_state() {
        for state in ALL_STATES {
            assert_eq!(
                on_stats(&stats(Some(state))),
                render(daemon_stats_probe(stats(Some(state)))),
            );
            assert_eq!(
                on_stats(&health(Some(state))),
                render(daemon_stats_probe(health(Some(state)))),
            );
        }
        assert_eq!(
            on_stats(&stats(None)),
            render(daemon_stats_probe(stats(None)))
        );
        let ok: Result<Response, String> = Ok(Response::Ok);
        assert_eq!(on_stats(&ok), render(daemon_stats_probe(ok)));
        let failed: Result<Response, String> = Err("x".into());
        assert_eq!(on_stats(&failed), render(daemon_stats_probe(failed)));
    }

    #[test]
    fn stats_classifies_real_wire_frames() {
        let parse =
            |json: &str| -> Result<Response, serde_json::Error> { serde_json::from_str(json) };
        let frame = |container: &str| {
            format!(
                r#"{{"type":"stats","processes":[],"process_count":3,"load1_centi":0,"load5_centi":0,"load15_centi":0,"mem_total_kb":1,"mem_available_kb":1,"mounts":[],"docker":null{container}}}"#
            )
        };
        assert_eq!(
            on_stats(&parse(&frame(r#","container":"running""#))),
            "some:running"
        );
        assert_eq!(
            on_stats(&parse(&frame(r#","container":"unknown""#))),
            "some:unknown"
        );
        assert_eq!(on_stats(&parse(&frame(r#","container":null"#))), "none");
        // An absent key deserializes to `None` as well.
        assert_eq!(on_stats(&parse(&frame(""))), "none");
    }
}
