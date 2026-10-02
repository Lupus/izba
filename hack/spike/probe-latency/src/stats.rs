//! Order statistics over microsecond samples.

use serde::Serialize;

/// Nearest-rank percentile of an ASCENDING slice: the sample at 1-based rank
/// `ceil(p/100 * n)`, clamped to `1..=n`. Always an observed value — never an
/// interpolation — so p95 is the largest sample for every `n < 20`, and the
/// second largest at the default `n == 20`. `None` when there are no samples.
pub fn percentile(sorted: &[u64], p: u32) -> Option<u64> {
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    // ceil(p * n / 100) in integers; u128 so no sample count can overflow it.
    let rank = (u128::from(p) * n as u128).div_ceil(100);
    let rank = usize::try_from(rank).unwrap_or(n).clamp(1, n);
    Some(sorted[rank - 1])
}

/// Summary of one timing field across all iterations of one measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldStats {
    /// Iterations in which this phase completed, i.e. samples in the figures.
    pub count: usize,
    /// Iterations in which it did not (it failed, or an earlier phase did).
    pub failures: usize,
    pub min: Option<u64>,
    pub p50: Option<u64>,
    pub p95: Option<u64>,
    pub max: Option<u64>,
}

/// One entry per iteration; `None` = the phase did not complete. Input order
/// does not matter.
pub fn field_stats(samples: &[Option<u64>]) -> FieldStats {
    let mut completed: Vec<u64> = samples.iter().flatten().copied().collect();
    completed.sort_unstable();
    FieldStats {
        count: completed.len(),
        failures: samples.len() - completed.len(),
        min: completed.first().copied(),
        p50: percentile(&completed, 50),
        p95: percentile(&completed, 95),
        max: completed.last().copied(),
    }
}

/// `max_us` as a fraction of a bound given in milliseconds (1.0 = exactly at
/// the bound). `None` when there is no sample.
pub fn fraction_of_bound(max_us: Option<u64>, bound_ms: u64) -> Option<f64> {
    max_us.map(|us| us as f64 / (bound_ms as f64 * 1000.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_of_nothing_is_none() {
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile(&[], 95), None);
    }

    #[test]
    fn percentile_of_one_sample_is_that_sample() {
        assert_eq!(percentile(&[42], 50), Some(42));
        assert_eq!(percentile(&[42], 95), Some(42));
    }

    #[test]
    fn median_is_nearest_rank_not_interpolated() {
        // Even count: rank ceil(0.5 * 4) = 2 — the LOWER middle sample, not 25.
        assert_eq!(percentile(&[10, 20, 30, 40], 50), Some(20));
        // Odd count: rank ceil(0.5 * 5) = 3 — the middle sample.
        assert_eq!(percentile(&[10, 20, 30, 40, 50], 50), Some(30));
    }

    #[test]
    fn p95_on_small_n_is_the_largest_sample() {
        // rank ceil(0.95 * 5) = 5
        assert_eq!(percentile(&[10, 20, 30, 40, 50], 95), Some(50));
        // rank ceil(0.95 * 19) = ceil(18.05) = 19
        let n19: Vec<u64> = (1..=19).collect();
        assert_eq!(percentile(&n19, 95), Some(19));
    }

    #[test]
    fn p95_pinned_around_the_default_iteration_count() {
        // The default run is 20 iterations: rank ceil(19.0) = 19, so exactly
        // one sample (the max) sits above p95.
        let n20: Vec<u64> = (1..=20).collect();
        assert_eq!(percentile(&n20, 95), Some(19));
        // rank ceil(19.95) = 20
        let n21: Vec<u64> = (1..=21).collect();
        assert_eq!(percentile(&n21, 95), Some(20));
        let n100: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&n100, 95), Some(95));
        assert_eq!(percentile(&n100, 50), Some(50));
    }

    #[test]
    fn percentile_extremes_clamp_to_observed_samples() {
        assert_eq!(percentile(&[10, 20, 30], 0), Some(10));
        assert_eq!(percentile(&[10, 20, 30], 100), Some(30));
    }

    #[test]
    fn field_stats_sorts_and_counts_failures() {
        let s = field_stats(&[Some(300), None, Some(100), Some(200), None]);
        assert_eq!(
            s,
            FieldStats {
                count: 3,
                failures: 2,
                min: Some(100),
                p50: Some(200),
                p95: Some(300),
                max: Some(300),
            }
        );
    }

    #[test]
    fn field_stats_of_no_iterations() {
        assert_eq!(
            field_stats(&[]),
            FieldStats {
                count: 0,
                failures: 0,
                min: None,
                p50: None,
                p95: None,
                max: None,
            }
        );
    }

    #[test]
    fn field_stats_when_every_iteration_failed() {
        let s = field_stats(&[None, None, None]);
        assert_eq!(s.count, 0);
        assert_eq!(s.failures, 3);
        assert_eq!((s.min, s.p50, s.p95, s.max), (None, None, None, None));
    }

    #[test]
    fn field_stats_single_sample() {
        let s = field_stats(&[Some(7)]);
        assert_eq!((s.count, s.failures), (1, 0));
        assert_eq!(
            (s.min, s.p50, s.p95, s.max),
            (Some(7), Some(7), Some(7), Some(7))
        );
    }

    #[test]
    fn fraction_of_bound_is_in_units_of_the_bound() {
        assert_eq!(fraction_of_bound(Some(2_500_000), 5000), Some(0.5));
        assert_eq!(fraction_of_bound(Some(5_000_000), 5000), Some(1.0));
        assert_eq!(fraction_of_bound(Some(7_500_000), 5000), Some(1.5));
        assert_eq!(fraction_of_bound(Some(300), 1), Some(0.3));
        assert_eq!(fraction_of_bound(None, 5000), None);
    }
}
