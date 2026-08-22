# Audit logging & metrics

The `ToolCallLogger` stream and the feature-gated metrics collector built on it.
Overview and defaults: [CLAUDE.md](../CLAUDE.md).

## Audit logging (`src/audit/`)

Pluggable tool call audit logging. Every `call_tool` invocation can be logged via a `ToolCallLogger` trait implementation. The framework ships two built-in loggers:
- `NoopLogger` — discards all records
- `TracingLogger` — emits structured `tracing::info!` events

Key types:
- `ToolCallRecord` — captures tool name, arguments (`Option<Map<String, Value>>`), session ID, timestamp (`SystemTime`), duration (`Duration`), dispatch source (registry vs inner handler), and outcome
- `ToolCallOutcome` — `Success { is_error, content_summary }` or `McpError { code, message }`. `is_error: true` means the tool reported a tool-level error (e.g. bad LLM input) but the MCP protocol call itself succeeded
- `ToolCallSource` — `Registry` (dynamic tools from `CapabilityRegistry`) or `Inner` (static tools from `ServerHandler`)

Logging is fire-and-forget via `tokio::spawn` — zero impact on tool call latency. When no logger is configured, the hot path has zero overhead (no clones, no allocations).

The interception point is `DynamicHandler::call_tool` in `src/capability/handler.rs`.

### Using a built-in logger

```rust
McpAppBuilder::new("my-server")
    .tool_call_logger(Arc::new(TracingLogger))
    .server(|| MyServer::new())
    .run()
    .await?;
```

### Implementing a custom storage backend

Implement the `ToolCallLogger` trait. The `log` method returns `Pin<Box<dyn Future<Output = ()> + Send>>` — this allows async I/O (database writes, HTTP calls). Handle errors internally; the framework cannot act on them since logging is fire-and-forget.

```rust
use mcp_framework::audit::{ToolCallLogger, ToolCallRecord, ToolCallOutcome};
use std::future::Future;
use std::pin::Pin;

struct FileLogger { path: std::path::PathBuf }

impl ToolCallLogger for FileLogger {
    fn log(&self, record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let path = self.path.clone();
        Box::pin(async move {
            let line = format!(
                "{} tool={} session={} duration={}ms outcome={}\n",
                humantime::format_rfc3339(record.timestamp),
                record.tool_name,
                record.session_id,
                record.duration.as_millis(),
                match &record.outcome {
                    ToolCallOutcome::Success { is_error, .. } =>
                        if *is_error { "tool_error" } else { "success" },
                    ToolCallOutcome::McpError { code, .. } =>
                        &format!("mcp_error({code})"),
                },
            );
            if let Err(e) = tokio::fs::OpenOptions::new()
                .create(true).append(true).open(&path).await
                .and_then(|mut f| {
                    use tokio::io::AsyncWriteExt;
                    // write_all requires a mutable borrow in an async block
                    Box::pin(async move { f.write_all(line.as_bytes()).await })
                }).await
            {
                tracing::warn!("audit log write failed: {e}");
            }
        })
    }
}
```

Then wire it via the builder: `.tool_call_logger(Arc::new(FileLogger { path: "audit.log".into() }))`

## Effectiveness metrics (`src/metrics/`, feature `metrics`)

Opt-in, feature-gated aggregation of tool call effectiveness. Compiled out entirely unless the `metrics` cargo feature is enabled — zero cost (no module, no fields populated) otherwise.

The `MetricsCollector` **is** a `ToolCallLogger`: it consumes the same `ToolCallRecord` stream as audit logging, so there is no new interception point and no added tool-call latency. `.metrics(collector)` composes with any logger already set via `.tool_call_logger()` (both receive every record, via `CompositeLogger`).

What's measured (cumulative since process start):
- **Per tool**: call frequency, success / `tool_error` / `mcp_error` counts, success & error rates, latency p50/p95/p99 + mean. Percentiles come from a bounded-memory bucketed histogram (`histogram.rs`), interpolated like Prometheus `histogram_quantile` — no per-call sample retention.
- **Per session**: call count, error rate, per-tool distribution. Cardinality-capped (`max_sessions`).

Exposure (both, answering the ticket's open question):
- **In-process**: `collector.snapshot() -> MetricsSnapshot` (serde-serializable; per-tool + per-session). Works in stdio mode too.
- **HTTP endpoint**: served *outside* the auth layer (so a Prometheus scraper needs no credentials) at `MetricsConfig::endpoint_path` (default `/metrics`). Prometheus text by default; `?format=json` returns the snapshot. Per-session data is JSON-only — session ids would explode Prometheus label cardinality, so the exposition emits per-tool series + an `mcp_active_sessions` gauge.

Key types: `MetricsCollector`, `MetricsConfig` (with `Default` and `from_env`), `MetricsSnapshot` / `ToolMetrics` / `SessionMetrics`. The endpoint is mounted via the general `public_routes: Option<Router>` field (the un-authed counterpart to `extra_routes`, threaded through `McpApp` → `HttpAppConfig`); `.metrics()` merges its router there. `public_routes` is a feature-independent type, so there's no `cfg` churn on struct literals, and it doubles as the mounting point for health checks / probes via `McpAppBuilder::public_routes`.

```rust
use mcp_framework::prelude::*;

let metrics = MetricsCollector::new(MetricsConfig::default());

McpAppBuilder::new("my-server")
    .metrics(metrics.clone())     // logs records + mounts /metrics
    .server(|| MyServer::new())
    .run()
    .await?;

// query in-process anytime:
let snap = metrics.snapshot();
println!("{} calls, p95 of busiest tool: {:?}ms",
    snap.total_calls, snap.tools.first().map(|t| t.p95_ms));
```

Enable the feature in `Cargo.toml`: `mcp-framework = { version = "0.1", features = ["metrics"] }`.
