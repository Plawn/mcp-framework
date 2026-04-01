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
    /// Log a tool call record.
    ///
    /// Called via `tokio::spawn` — must not panic. Errors should be
    /// handled internally.
    fn log(&self, record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// A no-op logger that discards all records.
pub struct NoopLogger;

impl ToolCallLogger for NoopLogger {
    fn log(&self, _record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::ready(()))
    }
}

/// A logger that emits structured `tracing` events at INFO level.
///
/// Each tool call produces a single `tracing::info!` event with fields:
/// `tool`, `session_id`, `duration_ms`, `source`, `outcome`, and `detail`.
pub struct TracingLogger;

impl ToolCallLogger for TracingLogger {
    fn log(&self, record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>> {
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

        Box::pin(std::future::ready(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record::{ToolCallOutcome, ToolCallRecord, ToolCallSource};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, SystemTime};

    fn sample_record() -> ToolCallRecord {
        ToolCallRecord {
            tool_name: "test_tool".to_string(),
            arguments: None,
            session_id: "sess-1".to_string(),
            timestamp: SystemTime::now(),
            duration: Duration::from_millis(42),
            source: ToolCallSource::Inner,
            outcome: ToolCallOutcome::Success {
                is_error: false,
                content_summary: Some("hello".to_string()),
            },
        }
    }

    #[tokio::test]
    async fn noop_logger_completes() {
        let logger = NoopLogger;
        logger.log(sample_record()).await;
    }

    #[tokio::test]
    async fn tracing_logger_does_not_panic() {
        let logger = TracingLogger;
        logger.log(sample_record()).await;
    }

    #[tokio::test]
    async fn custom_logger_receives_record() {
        static COUNT: AtomicU32 = AtomicU32::new(0);

        struct CountingLogger;
        impl ToolCallLogger for CountingLogger {
            fn log(
                &self,
                _record: ToolCallRecord,
            ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                COUNT.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::ready(()))
            }
        }

        let logger = CountingLogger;
        logger.log(sample_record()).await;
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    }
}
