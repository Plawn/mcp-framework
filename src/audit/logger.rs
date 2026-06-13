use std::future::Future;
use std::pin::Pin;

use super::record::{ToolCallOutcome, ToolCallRecord, ToolCallSource};

/// Trait for pluggable tool call audit logging.
///
/// Implement this to log tool call records to any storage backend (database,
/// file, HTTP endpoint, etc.). The framework spawns `log()` via `tokio::spawn`
/// so it never blocks tool call responses.
///
/// Implementations should handle their own errors internally (e.g. log a
/// warning via `tracing::warn!` on failure).
///
/// # Example
///
/// ```rust,ignore
/// use mcp_framework::audit::{ToolCallLogger, ToolCallRecord};
/// use std::future::Future;
/// use std::pin::Pin;
///
/// struct MyDbLogger { pool: sqlx::PgPool }
///
/// impl ToolCallLogger for MyDbLogger {
///     fn log(&self, record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>> {
///         let pool = self.pool.clone();
///         Box::pin(async move {
///             if let Err(e) = sqlx::query("INSERT INTO audit_log ...").execute(&pool).await {
///                 tracing::warn!("Failed to log tool call: {e}");
///             }
///         })
///     }
/// }
/// ```
pub trait ToolCallLogger: Send + Sync + 'static {
    /// Log a tool call record asynchronously.
    ///
    /// Called via `tokio::spawn` — must not panic. Errors should be
    /// handled internally.
    ///
    /// The default implementation delegates to [`log_sync`](Self::log_sync)
    /// and wraps the result in a ready future, avoiding the `Pin<Box<Future>>`
    /// allocation for synchronous loggers.
    ///
    /// Override this method for async loggers (database, HTTP, etc.).
    fn log(&self, record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.log_sync(record);
        Box::pin(std::future::ready(()))
    }

    /// Log a tool call record synchronously.
    ///
    /// Override this for loggers that do no async I/O (e.g. tracing, stdout).
    /// The default is a no-op; the default [`log`](Self::log) delegates here,
    /// so overriding only `log_sync` is sufficient for sync loggers.
    fn log_sync(&self, _record: ToolCallRecord) {}
}

/// A no-op logger that discards all records.
///
/// Uses the default trait methods — `log_sync` is a no-op by default,
/// and `log` delegates to it.
pub struct NoopLogger;

impl ToolCallLogger for NoopLogger {}

/// A logger that fans every record out to several inner loggers.
///
/// Useful for running audit logging and metrics collection side by side: each
/// inner logger receives a clone of the record. The framework uses this to
/// compose [`McpAppBuilder::metrics`](crate::McpAppBuilder::metrics) with any
/// logger already set via
/// [`tool_call_logger`](crate::McpAppBuilder::tool_call_logger).
pub struct CompositeLogger {
    loggers: Vec<std::sync::Arc<dyn ToolCallLogger>>,
}

impl CompositeLogger {
    /// Create a composite from the given loggers.
    pub fn new(loggers: Vec<std::sync::Arc<dyn ToolCallLogger>>) -> Self {
        Self { loggers }
    }
}

impl ToolCallLogger for CompositeLogger {
    fn log(&self, record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        // Drive every inner logger; await them all together so async backends
        // run concurrently while sync ones complete inline. The last logger
        // takes the owned record, so we clone only `len - 1` times.
        let Some((last, rest)) = self.loggers.split_last() else {
            return Box::pin(std::future::ready(()));
        };
        let mut futures: Vec<_> = rest.iter().map(|l| l.log(record.clone())).collect();
        futures.push(last.log(record));
        Box::pin(async move {
            for fut in futures {
                fut.await;
            }
        })
    }
}

/// A logger that emits structured `tracing` events at INFO level.
///
/// Each tool call produces a single `tracing::info!` event with fields:
/// `tool`, `session_id`, `duration_ms`, `source`, `outcome`, and `detail`.
pub struct TracingLogger;

impl ToolCallLogger for TracingLogger {
    fn log_sync(&self, record: ToolCallRecord) {
        let source = match record.source {
            ToolCallSource::Registry => "registry",
            ToolCallSource::Inner => "inner",
        };
        let (outcome, detail) = match &record.outcome {
            ToolCallOutcome::Success {
                is_error,
                content_summary,
            } => {
                let tag = if *is_error { "tool_error" } else { "success" };
                (tag, content_summary.clone().unwrap_or_default())
            }
            ToolCallOutcome::McpError { code, message } => {
                ("mcp_error", format!("[{code}] {message}"))
            }
        };

        tracing::info!(
            tool = %record.tool_name,
            session_id = %record.session_id,
            duration_ms = record.duration.as_millis() as u64,
            source = source,
            outcome = outcome,
            detail = %detail,
            "tool_call"
        );
    }
}

#[cfg(test)]
#[path = "logger_tests.rs"]
mod tests;
