//! The final `{"summary": …}` line and the exit status.

use std::collections::BTreeMap;

use serde::ser::SerializeMap as _;
use serde::{Serialize, Serializer};

use crate::args::Args;
use crate::classify::RUNNING;
use crate::measure::{io_cap, Kind, Sample};
use crate::request::RequestKind;
use crate::stats::{field_stats, fraction_of_bound, FieldStats};

/// Everything about one measurement (`probe` or `direct`) across all workers.
#[derive(Debug, Clone, PartialEq)]
pub struct MeasurementSummary {
    pub kind: Kind,
    /// Names the probe replica's round-trip key (`health_us` / `stats_us`).
    pub request: RequestKind,
    pub iterations: usize,
    /// Iterations in which a step failed.
    pub failures: usize,
    pub open: FieldStats,
    pub rpc: FieldStats,
    pub total: FieldStats,
    /// Longest time-to-failure among failed iterations.
    pub max_failed_after_us: Option<u64>,
    /// Slowest COMPLETED exchange over the configured bound (1.0 = at the
    /// bound). Failed iterations are not in it — see `max_failed_after_us`.
    pub max_total_as_fraction_of_bound: Option<f64>,
    /// How many iterations produced each distinct `inspect_container` value.
    pub inspect_container: BTreeMap<String, usize>,
}

/// By hand for the same reason as `Sample`: per-measurement key names.
impl Serialize for MeasurementSummary {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(8))?;
        map.serialize_entry("iterations", &self.iterations)?;
        map.serialize_entry("failures", &self.failures)?;
        map.serialize_entry(self.kind.open_field(), &self.open)?;
        map.serialize_entry(self.kind.rpc_field(self.request), &self.rpc)?;
        map.serialize_entry("total_us", &self.total)?;
        map.serialize_entry("max_failed_after_us", &self.max_failed_after_us)?;
        map.serialize_entry(
            "max_total_as_fraction_of_bound",
            &self.max_total_as_fraction_of_bound,
        )?;
        map.serialize_entry("inspect_container", &self.inspect_container)?;
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    pub sandbox: String,
    /// The guest RPC that was measured (`health` / `stats`).
    pub request: RequestKind,
    pub data_root: String,
    pub iterations: u32,
    pub parallel: u32,
    pub interval_ms: u64,
    pub bound_ms: u64,
    pub io_cap_ms: u64,
    /// Every measurement of every iteration saw `some:running` (exit 0).
    pub all_running: bool,
    pub probe: MeasurementSummary,
    pub direct: MeasurementSummary,
}

/// The wrapper that puts the summary under a `"summary"` key, so a consumer
/// can tell the last line from a measurement line.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SummaryLine {
    pub summary: Summary,
}

pub fn summarize_kind(
    kind: Kind,
    request: RequestKind,
    samples: &[Sample],
    bound_ms: u64,
) -> MeasurementSummary {
    let own: Vec<&Sample> = samples.iter().filter(|s| s.kind == kind).collect();
    let field = |pick: fn(&Sample) -> Option<u64>| -> FieldStats {
        field_stats(&own.iter().map(|s| pick(s)).collect::<Vec<_>>())
    };
    let total = field(|s| s.m.total_us);
    let mut inspect_container = BTreeMap::new();
    for s in &own {
        *inspect_container
            .entry(s.m.inspect_container.clone())
            .or_insert(0) += 1;
    }
    MeasurementSummary {
        kind,
        request,
        iterations: own.len(),
        failures: own.iter().filter(|s| !s.m.ok()).count(),
        open: field(|s| s.m.open_us),
        rpc: field(|s| s.m.rpc_us),
        max_failed_after_us: own.iter().filter_map(|s| s.m.failed_after_us).max(),
        max_total_as_fraction_of_bound: fraction_of_bound(total.max, bound_ms),
        total,
        inspect_container,
    }
}

pub fn summarize(args: &Args, data_root: &str, samples: &[Sample]) -> SummaryLine {
    SummaryLine {
        summary: Summary {
            sandbox: args.sandbox.clone(),
            request: args.request,
            data_root: data_root.to_string(),
            iterations: args.iterations,
            parallel: args.parallel,
            interval_ms: args.interval_ms,
            bound_ms: args.bound_ms,
            io_cap_ms: u64::try_from(io_cap(args.bound_ms).as_millis()).unwrap_or(u64::MAX),
            all_running: all_running(samples),
            probe: summarize_kind(Kind::Probe, args.request, samples, args.bound_ms),
            direct: summarize_kind(Kind::Direct, args.request, samples, args.bound_ms),
        },
    }
}

/// True when there is at least one sample and every one is `some:running`.
pub fn all_running(samples: &[Sample]) -> bool {
    !samples.is_empty() && samples.iter().all(|s| s.m.inspect_container == RUNNING)
}

/// 0 when [`all_running`], 1 otherwise.
pub fn exit_code(samples: &[Sample]) -> u8 {
    if all_running(samples) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measure::{Measured, Phase};

    const HEALTH: RequestKind = RequestKind::Health;

    fn ok(kind: Kind, open: u64, rpc: u64, inspect: &str) -> Sample {
        Sample {
            worker: 0,
            iteration: 0,
            started_ms: 0,
            kind,
            m: Measured {
                request: HEALTH,
                open_us: Some(open),
                rpc_us: Some(rpc),
                total_us: Some(open + rpc),
                failed_after_us: None,
                phase_failed: None,
                error: None,
                response: None,
                inspect_container: inspect.into(),
            },
        }
    }

    fn failed(kind: Kind, phase: Phase, open: Option<u64>, after: u64) -> Sample {
        Sample {
            worker: 0,
            iteration: 0,
            started_ms: 0,
            kind,
            m: Measured {
                request: HEALTH,
                open_us: open,
                rpc_us: None,
                total_us: None,
                failed_after_us: Some(after),
                phase_failed: Some(phase),
                error: Some("boom".into()),
                response: None,
                inspect_container: "none".into(),
            },
        }
    }

    fn args() -> Args {
        Args {
            sandbox: "box".into(),
            iterations: 4,
            interval_ms: 250,
            parallel: 1,
            bound_ms: 1,
            request: HEALTH,
        }
    }

    fn mixed() -> Vec<Sample> {
        vec![
            ok(Kind::Probe, 60, 40, "some:running"),
            ok(Kind::Direct, 10, 20, "some:running"),
            ok(Kind::Probe, 120, 80, "some:running"),
            ok(Kind::Direct, 10, 30, "some:unknown"),
            ok(Kind::Probe, 200, 100, "some:running"),
            // Open completed, the read did not.
            failed(Kind::Probe, Phase::Read, Some(90), 4000),
            // Nothing completed.
            failed(Kind::Probe, Phase::Control, None, 700),
        ]
    }

    #[test]
    fn a_measurement_only_counts_its_own_samples() {
        let s = summarize_kind(Kind::Probe, HEALTH, &mixed(), 1);
        assert_eq!(s.kind, Kind::Probe);
        assert_eq!(s.iterations, 5);
        assert_eq!(s.failures, 2);
        let d = summarize_kind(Kind::Direct, HEALTH, &mixed(), 1);
        assert_eq!((d.iterations, d.failures), (2, 0));
    }

    #[test]
    fn a_completed_open_counts_even_when_a_later_phase_failed() {
        let s = summarize_kind(Kind::Probe, HEALTH, &mixed(), 1);
        // 60, 90, 120, 200 completed; one iteration never opened.
        assert_eq!((s.open.count, s.open.failures), (4, 1));
        assert_eq!((s.open.min, s.open.max), (Some(60), Some(200)));
        // Only the three fully-completed exchanges have an rpc and a total.
        assert_eq!((s.rpc.count, s.rpc.failures), (3, 2));
        assert_eq!((s.total.count, s.total.failures), (3, 2));
        assert_eq!(
            (s.total.min, s.total.p50, s.total.p95, s.total.max),
            (Some(100), Some(200), Some(300), Some(300))
        );
        assert_eq!(s.max_failed_after_us, Some(4000));
    }

    #[test]
    fn fraction_of_bound_uses_the_slowest_completed_total() {
        // bound 1 ms = 1000 µs; slowest completed probe total is 300 µs.
        assert_eq!(
            summarize_kind(Kind::Probe, HEALTH, &mixed(), 1).max_total_as_fraction_of_bound,
            Some(0.3)
        );
        assert_eq!(
            summarize_kind(Kind::Direct, HEALTH, &mixed(), 1).max_total_as_fraction_of_bound,
            Some(0.04)
        );
        let none = [failed(Kind::Probe, Phase::Control, None, 5)];
        let s = summarize_kind(Kind::Probe, HEALTH, &none, 1);
        assert_eq!(s.max_total_as_fraction_of_bound, None);
        assert_eq!(s.max_failed_after_us, Some(5));
    }

    #[test]
    fn tally_counts_each_distinct_value() {
        let s = summarize_kind(Kind::Probe, HEALTH, &mixed(), 1);
        assert_eq!(
            s.inspect_container,
            BTreeMap::from([("none".to_string(), 2), ("some:running".to_string(), 3)])
        );
        let d = summarize_kind(Kind::Direct, HEALTH, &mixed(), 1);
        assert_eq!(
            d.inspect_container,
            BTreeMap::from([
                ("some:running".to_string(), 1),
                ("some:unknown".to_string(), 1)
            ])
        );
    }

    #[test]
    fn exit_status_is_zero_only_when_everything_was_running() {
        let good = vec![
            ok(Kind::Probe, 1, 1, "some:running"),
            ok(Kind::Direct, 1, 1, "some:running"),
        ];
        assert!(all_running(&good));
        assert_eq!(exit_code(&good), 0);

        // One guest-reported unknown on either measurement is enough.
        let mut one_unknown = good.clone();
        one_unknown.push(ok(Kind::Direct, 1, 1, "some:unknown"));
        assert_eq!(exit_code(&one_unknown), 1);

        let mut one_failure = good.clone();
        one_failure.push(failed(Kind::Probe, Phase::Control, None, 1));
        assert_eq!(exit_code(&one_failure), 1);

        // "Stopped" is a real answer, and not a running workload.
        let stopped = vec![ok(Kind::Probe, 1, 1, "some:stopped")];
        assert_eq!(exit_code(&stopped), 1);

        // No evidence is not a pass.
        assert!(!all_running(&[]));
        assert_eq!(exit_code(&[]), 1);
    }

    #[test]
    fn summary_line_shape() {
        let line = summarize(&args(), "/data/izba", &mixed());
        let text = serde_json::to_string(&line).unwrap();
        assert!(!text.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let s = &v["summary"];
        assert_eq!(s["sandbox"], "box");
        assert_eq!(s["request"], "health");
        assert_eq!(s["data_root"], "/data/izba");
        assert_eq!(s["iterations"], 4);
        assert_eq!(s["parallel"], 1);
        assert_eq!(s["interval_ms"], 250);
        assert_eq!(s["bound_ms"], 1);
        assert_eq!(s["io_cap_ms"], 30_000);
        assert_eq!(s["all_running"], false);

        let p = &s["probe"];
        assert_eq!(p["iterations"], 5);
        assert_eq!(p["failures"], 2);
        assert_eq!(
            p["control_us"],
            serde_json::json!({"count": 4, "failures": 1, "min": 60, "p50": 90, "p95": 200, "max": 200})
        );
        assert_eq!(p["health_us"]["count"], 3);
        assert_eq!(p["total_us"]["max"], 300);
        assert_eq!(p["max_failed_after_us"], 4000);
        assert_eq!(p["max_total_as_fraction_of_bound"], 0.3);
        assert_eq!(
            p["inspect_container"],
            serde_json::json!({"none": 2, "some:running": 3})
        );
        assert!(p.get("dial_us").is_none() && p.get("rpc_us").is_none());

        let d = &s["direct"];
        assert_eq!(d["dial_us"]["count"], 2);
        assert_eq!(d["rpc_us"]["max"], 30);
        assert_eq!(d["total_us"]["max"], 40);
        assert!(d["max_failed_after_us"].is_null());
        assert!(d.get("control_us").is_none() && d.get("health_us").is_none());
    }

    /// A stats run says so, and its probe round trip is `stats_us` — the
    /// same key its lines use — never `health_us`.
    #[test]
    fn stats_summary_names_the_request_and_the_stats_round_trip() {
        let stats_args = Args {
            request: RequestKind::Stats,
            ..args()
        };
        let line = summarize(&stats_args, "/data/izba", &mixed());
        let v = serde_json::to_value(&line).unwrap();
        let s = &v["summary"];
        assert_eq!(s["request"], "stats");
        let p = &s["probe"];
        assert_eq!(p["stats_us"]["count"], 3);
        assert_eq!(p["control_us"]["count"], 4);
        assert!(p.get("health_us").is_none());
        let d = &s["direct"];
        assert_eq!(d["rpc_us"]["max"], 30);
        assert!(d.get("stats_us").is_none() && d.get("health_us").is_none());
    }

    #[test]
    fn summary_of_an_all_running_run_says_so() {
        let good = vec![
            ok(Kind::Probe, 1, 1, "some:running"),
            ok(Kind::Direct, 1, 1, "some:running"),
        ];
        assert!(summarize(&args(), "/d", &good).summary.all_running);
    }
}
