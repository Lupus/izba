//! What `SandboxDetail.container` would be for one probe outcome.
//!
//! This mirrors the tail of `probe_container_state` in
//! `crates/izba-core/src/daemon/server.rs` exactly:
//!
//! ```text
//! match read_frame::<_, Response>(&mut conn).ok()? {
//!     Response::Health(h) => h.container,
//!     _ => None,
//! }
//! ```
//!
//! `izba status` prints "unknown" for BOTH `None` and
//! `Some(ContainerState::Unknown)`. The strings here keep them apart.

use izba_proto::Response;

/// The probe returned `None`: a step failed, the guest answered something
/// other than `Health`, or its `Health` carried no `container` field.
pub const NONE: &str = "none";

/// The one outcome the tool's exit status treats as healthy.
pub const RUNNING: &str = "some:running";

/// `"none"`, or `"some:<state>"` using [`izba_proto::ContainerState::as_str`]
/// — so a guest-reported `Unknown` is `"some:unknown"`, never `"none"`.
pub fn inspect_container<E>(outcome: &Result<Response, E>) -> String {
    match outcome {
        Ok(Response::Health(h)) => match h.container {
            Some(state) => format!("some:{}", state.as_str()),
            None => NONE.to_string(),
        },
        Ok(_) | Err(_) => NONE.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use izba_proto::{ContainerState, ErrorKind, HealthInfo};

    fn health(container: Option<ContainerState>) -> Result<Response, String> {
        Ok(Response::Health(HealthInfo {
            version: "test".into(),
            uptime_ms: 1,
            container,
        }))
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

    fn render(v: Option<ContainerState>) -> String {
        match v {
            None => "none".to_string(),
            Some(s) => format!("some:{}", s.as_str()),
        }
    }

    #[test]
    fn running_workload() {
        assert_eq!(
            inspect_container(&health(Some(ContainerState::Running))),
            "some:running"
        );
        assert_eq!(RUNNING, "some:running");
    }

    #[test]
    fn guest_reported_unknown_is_some_unknown() {
        assert_eq!(
            inspect_container(&health(Some(ContainerState::Unknown))),
            "some:unknown"
        );
    }

    #[test]
    fn health_without_a_container_field_is_none() {
        assert_eq!(inspect_container(&health(None)), "none");
    }

    #[test]
    fn non_health_response_is_none() {
        let ok: Result<Response, String> = Ok(Response::Ok);
        assert_eq!(inspect_container(&ok), "none");
        let error: Result<Response, String> = Ok(Response::Error {
            kind: ErrorKind::BadRequest,
            message: "no".into(),
        });
        assert_eq!(inspect_container(&error), "none");
    }

    #[test]
    fn a_failed_step_is_none() {
        let failed: Result<Response, String> = Err("timed out".into());
        assert_eq!(inspect_container(&failed), "none");
    }

    /// The whole point of the tool: `izba status` shows "unknown" for both of
    /// these, and they are different outcomes with different causes.
    #[test]
    fn some_unknown_and_none_are_different_outcomes() {
        let guest_said_unknown = inspect_container(&health(Some(ContainerState::Unknown)));
        let probe_gave_up: Result<Response, String> = Err("timed out".into());
        let probe_gave_up = inspect_container(&probe_gave_up);
        assert_ne!(guest_said_unknown, probe_gave_up);
        assert_ne!(guest_said_unknown, inspect_container(&health(None)));
    }

    #[test]
    fn mirrors_the_daemon_for_every_state() {
        for state in [
            ContainerState::Creating,
            ContainerState::Created,
            ContainerState::Running,
            ContainerState::Stopped,
            ContainerState::Paused,
            ContainerState::Unknown,
        ] {
            assert_eq!(
                inspect_container(&health(Some(state))),
                render(daemon_probe(health(Some(state)))),
            );
        }
        assert_eq!(
            inspect_container(&health(None)),
            render(daemon_probe(health(None)))
        );
        let ok: Result<Response, String> = Ok(Response::Ok);
        assert_eq!(inspect_container(&ok), render(daemon_probe(ok)));
        let failed: Result<Response, String> = Err("x".into());
        assert_eq!(inspect_container(&failed), render(daemon_probe(failed)));
    }

    /// Straight off the wire: an old guest's frame has no `container` key
    /// (`#[serde(default)]`), a current guest whose `crun state` failed sends
    /// `"unknown"`.
    #[test]
    fn classifies_real_wire_frames() {
        let parse =
            |json: &str| -> Result<Response, serde_json::Error> { serde_json::from_str(json) };
        assert_eq!(
            inspect_container(&parse(r#"{"type":"health","version":"v","uptime_ms":5}"#)),
            "none"
        );
        assert_eq!(
            inspect_container(&parse(
                r#"{"type":"health","version":"v","uptime_ms":5,"container":"unknown"}"#
            )),
            "some:unknown"
        );
        assert_eq!(
            inspect_container(&parse(
                r#"{"type":"health","version":"v","uptime_ms":5,"container":"running"}"#
            )),
            "some:running"
        );
        assert_eq!(inspect_container(&parse("not json")), "none");
    }
}
