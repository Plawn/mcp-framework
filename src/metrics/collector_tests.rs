use std::time::{Duration, SystemTime};

use super::*;
use crate::audit::{ToolCallLogger, ToolCallOutcome, ToolCallRecord, ToolCallSource};
use crate::metrics::MetricsConfig;
use crate::newtypes::{SessionId, ToolName};

fn record(tool: &str, session: &str, ms: u64, outcome: ToolCallOutcome) -> ToolCallRecord {
    ToolCallRecord {
        tool_name: ToolName::new(tool),
        arguments: None,
        session_id: SessionId::new(session),
        timestamp: SystemTime::now(),
        duration: Duration::from_millis(ms),
        source: ToolCallSource::Inner,
        outcome,
    }
}

fn success() -> ToolCallOutcome {
    ToolCallOutcome::Success {
        is_error: false,
        content_summary: None,
    }
}

fn tool_error() -> ToolCallOutcome {
    ToolCallOutcome::Success {
        is_error: true,
        content_summary: None,
    }
}

fn mcp_error() -> ToolCallOutcome {
    ToolCallOutcome::McpError {
        code: -32000,
        message: "boom".into(),
    }
}

#[test]
fn aggregates_per_tool_outcomes() {
    let c = MetricsCollector::new(MetricsConfig::default());
    c.record(&record("a", "s1", 10, success()));
    c.record(&record("a", "s1", 20, success()));
    c.record(&record("a", "s1", 30, tool_error()));
    c.record(&record("a", "s1", 40, mcp_error()));

    let snap = c.snapshot();
    assert_eq!(snap.total_calls, 4);
    let t = snap.tools.iter().find(|t| t.tool == "a").unwrap();
    assert_eq!(t.calls, 4);
    assert_eq!(t.success, 2);
    assert_eq!(t.tool_error, 1);
    assert_eq!(t.mcp_error, 1);
    assert!((t.success_rate - 0.5).abs() < 1e-9);
    assert!((t.error_rate - 0.5).abs() < 1e-9);
    assert!(t.avg_ms > 0.0);
    assert!(t.p99_ms >= t.p50_ms);
}

#[test]
fn aggregates_per_session() {
    let c = MetricsCollector::new(MetricsConfig::default());
    c.record(&record("a", "s1", 10, success()));
    c.record(&record("b", "s1", 10, mcp_error()));
    c.record(&record("a", "s2", 10, success()));

    let snap = c.snapshot();
    let s1 = snap.sessions.iter().find(|s| s.session_id == "s1").unwrap();
    assert_eq!(s1.calls, 2);
    assert_eq!(s1.errors, 1);
    assert!((s1.error_rate - 0.5).abs() < 1e-9);
    assert_eq!(s1.tools.get("a"), Some(&1));
    assert_eq!(s1.tools.get("b"), Some(&1));

    let s2 = snap.sessions.iter().find(|s| s.session_id == "s2").unwrap();
    assert_eq!(s2.calls, 1);
    assert_eq!(s2.errors, 0);
}

#[test]
fn track_sessions_can_be_disabled() {
    let cfg = MetricsConfig {
        track_sessions: false,
        ..Default::default()
    };
    let c = MetricsCollector::new(cfg);
    c.record(&record("a", "s1", 10, success()));

    let snap = c.snapshot();
    assert_eq!(snap.tools.len(), 1);
    assert!(snap.sessions.is_empty());
}

#[test]
fn max_sessions_caps_cardinality() {
    let cfg = MetricsConfig {
        max_sessions: 2,
        ..Default::default()
    };
    let c = MetricsCollector::new(cfg);
    c.record(&record("a", "s1", 10, success()));
    c.record(&record("a", "s2", 10, success()));
    c.record(&record("a", "s3", 10, success())); // dropped

    let snap = c.snapshot();
    assert_eq!(snap.sessions.len(), 2);
    // tool metrics are unaffected by the session cap
    assert_eq!(snap.total_calls, 3);
}

#[test]
fn works_through_logger_trait() {
    let c = MetricsCollector::new(MetricsConfig::default());
    let logger: &dyn ToolCallLogger = c.as_ref();
    logger.log_sync(record("a", "s1", 10, success()));

    assert_eq!(c.snapshot().total_calls, 1);
}

#[test]
fn prometheus_output_contains_expected_series() {
    let c = MetricsCollector::new(MetricsConfig::default());
    c.record(&record("get_nps", "s1", 10, success()));
    c.record(&record("get_nps", "s1", 200, mcp_error()));

    let text = c.render_prometheus();
    assert!(text.contains("mcp_tool_calls_total{tool=\"get_nps\",outcome=\"success\"} 1"));
    assert!(text.contains("mcp_tool_calls_total{tool=\"get_nps\",outcome=\"mcp_error\"} 1"));
    assert!(text.contains("# TYPE mcp_tool_call_duration_ms histogram"));
    assert!(text.contains("mcp_tool_call_duration_ms_count{tool=\"get_nps\"} 2"));
    assert!(text.contains("le=\"+Inf\""));
    assert!(text.contains("mcp_active_sessions 1"));
}

#[test]
fn custom_namespace_is_applied() {
    let cfg = MetricsConfig {
        namespace: "blumana".into(),
        ..Default::default()
    };
    let c = MetricsCollector::new(cfg);
    c.record(&record("a", "s1", 10, success()));
    let text = c.render_prometheus();
    assert!(text.contains("blumana_tool_calls_total"));
    assert!(!text.contains("mcp_tool_calls_total"));
}

#[test]
fn label_values_are_escaped() {
    let c = MetricsCollector::new(MetricsConfig::default());
    c.record(&record("we\"ird", "s1", 10, success()));
    let text = c.render_prometheus();
    assert!(text.contains("tool=\"we\\\"ird\""));
}
