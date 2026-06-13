//! Configuration for the metrics collector.

use crate::constants::{
    DEFAULT_METRICS_LATENCY_BUCKETS_MS, DEFAULT_METRICS_MAX_SESSIONS, DEFAULT_METRICS_MAX_TOOLS,
    DEFAULT_METRICS_NAMESPACE, DEFAULT_METRICS_PATH,
};

/// Configuration for a [`MetricsCollector`](super::MetricsCollector).
///
/// Use [`MetricsConfig::default`] for sensible defaults or
/// [`MetricsConfig::from_env`] to read overrides from environment variables.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Histogram bucket upper bounds in milliseconds, ascending.
    ///
    /// Latency percentiles (p50/p95/p99) are interpolated from these buckets,
    /// so pick bounds that bracket your expected tool latencies.
    pub latency_buckets_ms: Vec<f64>,
    /// Track per-session metrics in [`MetricsSnapshot`](super::MetricsSnapshot).
    ///
    /// Per-session data is only ever exposed via the JSON snapshot, never as
    /// Prometheus labels (sessions are unbounded-cardinality). Default: `true`.
    pub track_sessions: bool,
    /// Maximum number of distinct sessions to retain. Once reached, metrics for
    /// new sessions are dropped (tool-level metrics are unaffected). Guards
    /// against unbounded memory growth.
    pub max_sessions: usize,
    /// Maximum number of distinct tools to retain. A safety cap; tool
    /// cardinality is normally bounded by the server design.
    pub max_tools: usize,
    /// HTTP path for the Prometheus/JSON metrics endpoint in HTTP mode.
    ///
    /// `None` disables the endpoint (metrics remain queryable in-process via
    /// [`MetricsCollector::snapshot`](super::MetricsCollector::snapshot)).
    pub endpoint_path: Option<String>,
    /// Prefix for Prometheus metric names (e.g. `mcp` → `mcp_tool_calls_total`).
    pub namespace: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            latency_buckets_ms: DEFAULT_METRICS_LATENCY_BUCKETS_MS.to_vec(),
            track_sessions: true,
            max_sessions: DEFAULT_METRICS_MAX_SESSIONS,
            max_tools: DEFAULT_METRICS_MAX_TOOLS,
            endpoint_path: Some(DEFAULT_METRICS_PATH.to_string()),
            namespace: DEFAULT_METRICS_NAMESPACE.to_string(),
        }
    }
}

impl MetricsConfig {
    /// Build a config from environment variables, falling back to defaults.
    ///
    /// | Variable | Effect |
    /// |---|---|
    /// | `MCP_METRICS_PATH` | endpoint path (`""` / `off` disables the endpoint) |
    /// | `MCP_METRICS_NAMESPACE` | Prometheus metric name prefix |
    /// | `MCP_METRICS_TRACK_SESSIONS` | `false`/`0`/`off` disables per-session tracking |
    /// | `MCP_METRICS_MAX_SESSIONS` | max retained sessions |
    /// | `MCP_METRICS_BUCKETS_MS` | comma-separated latency bucket bounds |
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        if let Ok(path) = std::env::var("MCP_METRICS_PATH") {
            let trimmed = path.trim();
            cfg.endpoint_path = if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("off") {
                None
            } else {
                Some(trimmed.to_string())
            };
        }

        if let Ok(ns) = std::env::var("MCP_METRICS_NAMESPACE")
            && !ns.trim().is_empty()
        {
            cfg.namespace = ns.trim().to_string();
        }

        if let Ok(track) = std::env::var("MCP_METRICS_TRACK_SESSIONS") {
            cfg.track_sessions = !matches!(
                track.trim().to_ascii_lowercase().as_str(),
                "false" | "0" | "off" | "no"
            );
        }

        if let Ok(max) = std::env::var("MCP_METRICS_MAX_SESSIONS")
            && let Ok(n) = max.trim().parse::<usize>()
        {
            cfg.max_sessions = n;
        }

        if let Ok(buckets) = std::env::var("MCP_METRICS_BUCKETS_MS") {
            let parsed: Vec<f64> = buckets
                .split(',')
                .filter_map(|s| s.trim().parse::<f64>().ok())
                .filter(|v| v.is_finite() && *v > 0.0)
                .collect();
            if !parsed.is_empty() {
                cfg.latency_buckets_ms = parsed;
            }
        }

        cfg
    }

    /// Return the latency bounds sorted ascending and deduplicated, ready to
    /// hand to a histogram.
    pub(crate) fn sorted_bounds(&self) -> Vec<f64> {
        let mut bounds = self.latency_buckets_ms.clone();
        bounds.retain(|v| v.is_finite() && *v > 0.0);
        bounds.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        bounds.dedup();
        if bounds.is_empty() {
            bounds = DEFAULT_METRICS_LATENCY_BUCKETS_MS.to_vec();
        }
        bounds
    }
}
