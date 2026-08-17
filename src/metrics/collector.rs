//! The metrics collector: a [`ToolCallLogger`] that aggregates tool call
//! statistics and exposes them as a queryable snapshot or Prometheus text.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;

use crate::audit::{ToolCallLogger, ToolCallOutcome, ToolCallRecord};
use crate::newtypes::{SessionId, ToolName};

use super::config::MetricsConfig;
use super::histogram::Histogram;

/// Per-tool aggregated counters and latency distribution.
struct ToolStats {
    success: u64,
    tool_error: u64,
    mcp_error: u64,
    latency: Histogram,
}

impl ToolStats {
    fn new(bounds: Arc<Vec<f64>>) -> Self {
        Self {
            success: 0,
            tool_error: 0,
            mcp_error: 0,
            latency: Histogram::new(bounds),
        }
    }

    fn calls(&self) -> u64 {
        self.success + self.tool_error + self.mcp_error
    }

    fn errors(&self) -> u64 {
        self.tool_error + self.mcp_error
    }
}

/// Classification of a tool call outcome into the three counted buckets.
#[derive(Clone, Copy)]
enum Outcome {
    Success,
    ToolError,
    McpError,
}

impl Outcome {
    fn classify(outcome: &ToolCallOutcome) -> Self {
        match outcome {
            ToolCallOutcome::Success {
                is_error: false, ..
            } => Outcome::Success,
            ToolCallOutcome::Success { is_error: true, .. } => Outcome::ToolError,
            ToolCallOutcome::McpError { .. } => Outcome::McpError,
        }
    }
}

/// Per-session aggregated counters.
#[derive(Default)]
struct SessionStats {
    success: u64,
    errors: u64,
    per_tool: HashMap<ToolName, u64>,
}

impl SessionStats {
    fn calls(&self) -> u64 {
        self.success + self.errors
    }
}

/// Mutable inner state guarded by a single mutex.
struct Inner {
    tools: HashMap<ToolName, ToolStats>,
    sessions: HashMap<SessionId, SessionStats>,
}

/// Aggregates tool call metrics in memory.
///
/// `MetricsCollector` implements [`ToolCallLogger`], so it plugs into the same
/// fire-and-forget hook as audit logging — there is no extra interception point
/// and no impact on tool call latency. Wire it via
/// [`McpAppBuilder::metrics`](crate::McpAppBuilder::metrics), which also mounts
/// the HTTP endpoint and composes with any existing logger.
///
/// Metrics are cumulative since process start. Query them in-process with
/// [`snapshot`](Self::snapshot) or scrape them over HTTP (Prometheus text, or
/// JSON via `?format=json`).
///
/// # Example
///
/// ```rust,ignore
/// use mcp_framework::prelude::*;
///
/// let metrics = MetricsCollector::new(MetricsConfig::default());
///
/// McpAppBuilder::new("my-server")
///     .metrics(metrics.clone())
///     .server(|| MyServer::new())
///     .run()
///     .await?;
///
/// // elsewhere:
/// let snap = metrics.snapshot();
/// println!("total calls: {}", snap.total_calls);
/// ```
pub struct MetricsCollector {
    config: MetricsConfig,
    bounds: Arc<Vec<f64>>,
    started_at: Instant,
    inner: Mutex<Inner>,
}

impl MetricsCollector {
    /// Create a collector wrapped in an `Arc`, ready to share between the
    /// builder and your own code.
    pub fn new(config: MetricsConfig) -> Arc<Self> {
        let bounds = Arc::new(config.sorted_bounds());
        Arc::new(Self {
            config,
            bounds,
            started_at: Instant::now(),
            inner: Mutex::new(Inner {
                tools: HashMap::new(),
                sessions: HashMap::new(),
            }),
        })
    }

    /// The configured endpoint path, if the HTTP endpoint is enabled.
    pub fn endpoint_path(&self) -> Option<&str> {
        self.config.endpoint_path.as_deref()
    }

    /// Record one tool call. Public for testing and custom wiring; normally
    /// invoked via the [`ToolCallLogger`] hook.
    pub fn record(&self, record: &ToolCallRecord) {
        let ms = record.duration.as_secs_f64() * 1000.0;
        let outcome = Outcome::classify(&record.outcome);
        let tool = &record.tool_name;
        let session = &record.session_id;

        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // ── per-tool ──────────────────────────────────────────────
        // `get_mut` on the warm path avoids cloning the tool name on every
        // call — a key is only allocated when a tool is first seen.
        let known = inner.tools.contains_key(tool);
        if known || inner.tools.len() < self.config.max_tools {
            if !known {
                inner
                    .tools
                    .insert(tool.clone(), ToolStats::new(self.bounds.clone()));
            }
            if let Some(stats) = inner.tools.get_mut(tool) {
                match outcome {
                    Outcome::Success => stats.success += 1,
                    Outcome::ToolError => stats.tool_error += 1,
                    Outcome::McpError => stats.mcp_error += 1,
                }
                stats.latency.observe(ms);
            }
        }

        // ── per-session ───────────────────────────────────────────
        if self.config.track_sessions {
            let known = inner.sessions.contains_key(session);
            if known || inner.sessions.len() < self.config.max_sessions {
                if !known {
                    inner
                        .sessions
                        .insert(session.clone(), SessionStats::default());
                }
                if let Some(stats) = inner.sessions.get_mut(session) {
                    match outcome {
                        Outcome::Success => stats.success += 1,
                        Outcome::ToolError | Outcome::McpError => stats.errors += 1,
                    }
                    if let Some(count) = stats.per_tool.get_mut(tool) {
                        *count += 1;
                    } else {
                        stats.per_tool.insert(tool.clone(), 1);
                    }
                }
            }
        }
    }

    /// Take a consistent snapshot of all aggregated metrics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut tools: Vec<ToolMetrics> = inner
            .tools
            .iter()
            .map(|(name, s)| {
                let calls = s.calls();
                let denom = calls.max(1) as f64;
                ToolMetrics {
                    tool: name.to_string(),
                    calls,
                    success: s.success,
                    tool_error: s.tool_error,
                    mcp_error: s.mcp_error,
                    success_rate: s.success as f64 / denom,
                    error_rate: s.errors() as f64 / denom,
                    avg_ms: s.latency.mean_ms(),
                    p50_ms: s.latency.quantile(0.50),
                    p95_ms: s.latency.quantile(0.95),
                    p99_ms: s.latency.quantile(0.99),
                }
            })
            .collect();
        tools.sort_by(|a, b| b.calls.cmp(&a.calls).then_with(|| a.tool.cmp(&b.tool)));

        let mut sessions: Vec<SessionMetrics> = inner
            .sessions
            .iter()
            .map(|(id, s)| {
                let calls = s.calls();
                let denom = calls.max(1) as f64;
                SessionMetrics {
                    session_id: id.to_string(),
                    calls,
                    errors: s.errors,
                    error_rate: s.errors as f64 / denom,
                    tools: s
                        .per_tool
                        .iter()
                        .map(|(t, c)| (t.to_string(), *c))
                        .collect(),
                }
            })
            .collect();
        sessions.sort_by(|a, b| {
            b.calls
                .cmp(&a.calls)
                .then_with(|| a.session_id.cmp(&b.session_id))
        });

        let total_calls = tools.iter().map(|t| t.calls).sum();

        MetricsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            total_calls,
            tools,
            sessions,
        }
    }

    /// Render metrics in Prometheus text exposition format (v0.0.4).
    ///
    /// Only tool-level series are emitted — session identifiers would explode
    /// label cardinality, so per-session data lives in [`snapshot`](Self::snapshot).
    pub fn render_prometheus(&self) -> String {
        let ns = &self.config.namespace;
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut out = String::new();

        // counter: tool calls by outcome
        out.push_str(&format!(
            "# HELP {ns}_tool_calls_total Total tool calls by outcome.\n# TYPE {ns}_tool_calls_total counter\n"
        ));
        for (name, s) in &inner.tools {
            let tool = escape_label(name.as_str());
            out.push_str(&format!(
                "{ns}_tool_calls_total{{tool=\"{tool}\",outcome=\"success\"}} {}\n",
                s.success
            ));
            out.push_str(&format!(
                "{ns}_tool_calls_total{{tool=\"{tool}\",outcome=\"tool_error\"}} {}\n",
                s.tool_error
            ));
            out.push_str(&format!(
                "{ns}_tool_calls_total{{tool=\"{tool}\",outcome=\"mcp_error\"}} {}\n",
                s.mcp_error
            ));
        }

        // histogram: tool call latency
        out.push_str(&format!(
            "# HELP {ns}_tool_call_duration_ms Tool call latency in milliseconds.\n# TYPE {ns}_tool_call_duration_ms histogram\n"
        ));
        for (name, s) in &inner.tools {
            let tool = escape_label(name.as_str());
            for (bound, cumulative) in s.latency.cumulative_buckets() {
                out.push_str(&format!(
                    "{ns}_tool_call_duration_ms_bucket{{tool=\"{tool}\",le=\"{}\"}} {cumulative}\n",
                    format_float(bound)
                ));
            }
            out.push_str(&format!(
                "{ns}_tool_call_duration_ms_bucket{{tool=\"{tool}\",le=\"+Inf\"}} {}\n",
                s.latency.count()
            ));
            out.push_str(&format!(
                "{ns}_tool_call_duration_ms_sum{{tool=\"{tool}\"}} {}\n",
                format_float(s.latency.sum_ms())
            ));
            out.push_str(&format!(
                "{ns}_tool_call_duration_ms_count{{tool=\"{tool}\"}} {}\n",
                s.latency.count()
            ));
        }

        // gauge: active tracked sessions
        out.push_str(&format!(
            "# HELP {ns}_active_sessions Number of sessions currently tracked.\n# TYPE {ns}_active_sessions gauge\n"
        ));
        out.push_str(&format!("{ns}_active_sessions {}\n", inner.sessions.len()));

        out
    }
}

impl ToolCallLogger for MetricsCollector {
    fn log_sync(&self, record: ToolCallRecord) {
        self.record(&record);
    }
}

/// Escape a Prometheus label value (`\`, `"`, and newline).
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Format a float without a trailing `.0` for integral values, so bucket bounds
/// render as `10` rather than `10.0`.
fn format_float(v: f64) -> String {
    if v.fract() == 0.0 && v.is_finite() {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// A point-in-time view of all aggregated metrics. Serializable to JSON.
#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    /// Seconds since the collector was created.
    pub uptime_secs: u64,
    /// Total tool calls across all tools.
    pub total_calls: u64,
    /// Per-tool metrics, sorted by call count descending.
    pub tools: Vec<ToolMetrics>,
    /// Per-session metrics, sorted by call count descending. Empty when
    /// session tracking is disabled.
    pub sessions: Vec<SessionMetrics>,
}

/// Aggregated metrics for a single tool.
#[derive(Debug, Clone, Serialize)]
pub struct ToolMetrics {
    pub tool: String,
    /// Total calls (success + tool_error + mcp_error).
    pub calls: u64,
    pub success: u64,
    /// Calls where the tool reported a tool-level error (`is_error = true`).
    pub tool_error: u64,
    /// Calls that failed at the MCP protocol level.
    pub mcp_error: u64,
    /// `success / calls`.
    pub success_rate: f64,
    /// `(tool_error + mcp_error) / calls`.
    pub error_rate: f64,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Aggregated metrics for a single session.
#[derive(Debug, Clone, Serialize)]
pub struct SessionMetrics {
    pub session_id: String,
    /// Total tool calls in this session.
    pub calls: u64,
    /// Calls that errored (tool-level or MCP-level).
    pub errors: u64,
    /// `errors / calls`.
    pub error_rate: f64,
    /// Distribution of calls across tools.
    pub tools: HashMap<String, u64>,
}

#[cfg(test)]
#[path = "collector_tests.rs"]
mod tests;
