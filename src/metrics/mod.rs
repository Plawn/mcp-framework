//! Effectiveness metrics for MCP tool calls (feature `metrics`).
//!
//! Aggregates per-tool and per-session statistics from the same
//! [`ToolCallRecord`](crate::audit::ToolCallRecord) stream that audit logging
//! uses, then exposes them as a queryable [`MetricsSnapshot`] or over HTTP in
//! Prometheus / JSON format.
//!
//! Measured per tool: call frequency, success rate, error rate (split into
//! `tool_error` vs `mcp_error`), and latency percentiles (p50/p95/p99) via a
//! bounded-memory histogram. Measured per session: call count, tool
//! distribution, and error rate.
//!
//! # Wiring
//!
//! ```rust,ignore
//! use mcp_framework::prelude::*;
//!
//! let metrics = MetricsCollector::new(MetricsConfig::default());
//!
//! McpAppBuilder::new("my-server")
//!     .metrics(metrics.clone())   // logs records + mounts the endpoint
//!     .server(|| MyServer::new())
//!     .run()
//!     .await?;
//! ```
//!
//! `.metrics()` composes with any logger set via
//! [`tool_call_logger`](crate::McpAppBuilder::tool_call_logger) — both run.
//! In HTTP mode the endpoint is served (unauthenticated) at the configured
//! path; in stdio mode metrics are still collected and queryable in-process.

mod collector;
mod config;
mod endpoint;
mod histogram;

pub use collector::{MetricsCollector, MetricsSnapshot, SessionMetrics, ToolMetrics};
pub use config::MetricsConfig;

pub(crate) use endpoint::metrics_router;
