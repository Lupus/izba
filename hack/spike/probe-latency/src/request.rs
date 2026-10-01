//! Which guest RPC is being measured.
//!
//! izbad has two probe-shaped fetches of the workload's container state, both
//! over the same `probe_control` dial and both bounded at 5 s:
//!
//! * `probe_container_state` sends `Request::Health` — it feeds
//!   `SandboxDetail.container`, i.e. `izba status` / Inspect.
//! * `probe_guest_stats` sends `Request::Stats` — it feeds
//!   `stats.guest.container`, which is what the desktop app's Overview reads.
//!   The guest samples CPU for ~250 ms inside that call, so it is much slower.

use izba_proto::Request;
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestKind {
    #[default]
    Health,
    Stats,
}

impl RequestKind {
    /// The `--request` value and the `"request"` field in the output.
    pub fn name(self) -> &'static str {
        match self {
            RequestKind::Health => "health",
            RequestKind::Stats => "stats",
        }
    }

    /// The wire variant's name, for error messages.
    pub fn label(self) -> &'static str {
        match self {
            RequestKind::Health => "Health",
            RequestKind::Stats => "Stats",
        }
    }

    /// Exactly `health` or `stats`; anything else is `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "health" => Some(RequestKind::Health),
            "stats" => Some(RequestKind::Stats),
            _ => None,
        }
    }

    /// The frame to send.
    pub fn request(self) -> Request {
        match self {
            RequestKind::Health => Request::Health,
            RequestKind::Stats => Request::Stats,
        }
    }
}

impl Serialize for RequestKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_health() {
        assert_eq!(RequestKind::default(), RequestKind::Health);
    }

    #[test]
    fn parses_exactly_the_two_names() {
        assert_eq!(RequestKind::parse("health"), Some(RequestKind::Health));
        assert_eq!(RequestKind::parse("stats"), Some(RequestKind::Stats));
        for bad in ["", "Health", "STATS", "stat", "health ", "inspect"] {
            assert_eq!(RequestKind::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn name_round_trips_through_parse() {
        for kind in [RequestKind::Health, RequestKind::Stats] {
            assert_eq!(RequestKind::parse(kind.name()), Some(kind));
        }
    }

    #[test]
    fn sends_the_matching_wire_request() {
        assert!(matches!(RequestKind::Health.request(), Request::Health));
        assert!(matches!(RequestKind::Stats.request(), Request::Stats));
    }

    #[test]
    fn serializes_as_its_name() {
        assert_eq!(
            serde_json::to_string(&RequestKind::Stats).unwrap(),
            r#""stats""#
        );
        assert_eq!(
            serde_json::to_string(&RequestKind::Health).unwrap(),
            r#""health""#
        );
    }
}
