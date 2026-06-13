//! A fixed-bucket latency histogram with bounded memory.
//!
//! Storing every observed latency would be unbounded; instead we keep one
//! counter per configured bucket plus a running sum/count. Percentiles are
//! computed by linear interpolation inside the bucket that contains the rank —
//! the same approach as Prometheus `histogram_quantile`.

use std::sync::Arc;

/// A latency histogram over a shared set of upper bounds (in milliseconds).
#[derive(Debug, Clone)]
pub(crate) struct Histogram {
    /// Upper bounds (ms), ascending. Shared across all per-tool histograms.
    bounds: Arc<Vec<f64>>,
    /// Per-bucket counts. Length is `bounds.len() + 1`; the last slot is the
    /// `+Inf` overflow bucket for observations larger than every bound.
    counts: Vec<u64>,
    /// Sum of all observed values (ms) — used for the mean.
    sum_ms: f64,
    /// Total number of observations.
    count: u64,
}

impl Histogram {
    pub(crate) fn new(bounds: Arc<Vec<f64>>) -> Self {
        let len = bounds.len() + 1;
        Self {
            bounds,
            counts: vec![0; len],
            sum_ms: 0.0,
            count: 0,
        }
    }

    /// Record one observation.
    pub(crate) fn observe(&mut self, ms: f64) {
        let idx = self
            .bounds
            .iter()
            .position(|&b| ms <= b)
            .unwrap_or(self.bounds.len());
        self.counts[idx] += 1;
        self.sum_ms += ms;
        self.count += 1;
    }

    pub(crate) fn count(&self) -> u64 {
        self.count
    }

    pub(crate) fn sum_ms(&self) -> f64 {
        self.sum_ms
    }

    /// Mean latency in ms (0 when no observations).
    pub(crate) fn mean_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum_ms / self.count as f64
        }
    }

    /// Approximate quantile (`q` in `0.0..=1.0`) in ms via linear interpolation
    /// within the containing bucket. Returns 0 when there are no observations.
    pub(crate) fn quantile(&self, q: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let rank = q * self.count as f64;
        let mut cumulative = 0u64;
        for (i, &bucket_count) in self.counts.iter().enumerate() {
            let next = cumulative + bucket_count;
            if (next as f64) >= rank && bucket_count > 0 {
                let lower = if i == 0 { 0.0 } else { self.bounds[i - 1] };
                // Overflow bucket has no finite upper bound: report its lower edge.
                let Some(&upper) = self.bounds.get(i) else {
                    return lower;
                };
                let pos_in_bucket = rank - cumulative as f64;
                let frac = pos_in_bucket / bucket_count as f64;
                return lower + frac * (upper - lower);
            }
            cumulative = next;
        }
        // Fallback: last finite bound.
        self.bounds.last().copied().unwrap_or(0.0)
    }

    /// Cumulative bucket counts paired with their finite upper bound, for
    /// Prometheus exposition. Does not include the `+Inf` bucket (the caller
    /// emits that using [`count`](Self::count)).
    pub(crate) fn cumulative_buckets(&self) -> Vec<(f64, u64)> {
        let mut out = Vec::with_capacity(self.bounds.len());
        let mut cumulative = 0u64;
        for (i, &bound) in self.bounds.iter().enumerate() {
            cumulative += self.counts[i];
            out.push((bound, cumulative));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> Arc<Vec<f64>> {
        Arc::new(vec![10.0, 50.0, 100.0, 500.0])
    }

    #[test]
    fn empty_quantiles_are_zero() {
        let h = Histogram::new(bounds());
        assert_eq!(h.quantile(0.5), 0.0);
        assert_eq!(h.mean_ms(), 0.0);
        assert_eq!(h.count(), 0);
    }

    #[test]
    fn mean_and_count_track_observations() {
        let mut h = Histogram::new(bounds());
        h.observe(10.0);
        h.observe(30.0);
        assert_eq!(h.count(), 2);
        assert!((h.mean_ms() - 20.0).abs() < 1e-9);
    }

    #[test]
    fn quantile_lands_in_expected_bucket() {
        let mut h = Histogram::new(bounds());
        // 100 observations all in (10, 50] bucket.
        for _ in 0..100 {
            h.observe(30.0);
        }
        let p50 = h.quantile(0.5);
        assert!(p50 > 10.0 && p50 <= 50.0, "p50 = {p50}");
        let p99 = h.quantile(0.99);
        assert!(p99 > 10.0 && p99 <= 50.0, "p99 = {p99}");
    }

    #[test]
    fn overflow_bucket_reports_last_bound() {
        let mut h = Histogram::new(bounds());
        h.observe(10_000.0);
        // Single huge observation → quantile resolves to the overflow bucket,
        // whose lower edge is the last finite bound.
        assert_eq!(h.quantile(0.99), 500.0);
    }

    #[test]
    fn cumulative_buckets_are_monotonic() {
        let mut h = Histogram::new(bounds());
        h.observe(5.0);
        h.observe(40.0);
        h.observe(80.0);
        let buckets = h.cumulative_buckets();
        assert_eq!(buckets, vec![(10.0, 1), (50.0, 2), (100.0, 3), (500.0, 3)]);
    }
}
