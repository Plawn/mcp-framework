//! Audit logging for tool call invocations.
//!
//! Implement [`ToolCallLogger`] to plug in a custom storage backend (database,
//! HTTP endpoint, file, etc.). Built-in implementations:
//! - [`NoopLogger`] — discards all records
//! - [`TracingLogger`] — emits structured `tracing` events at INFO level

mod logger;
mod record;

pub use logger::{NoopLogger, ToolCallLogger, TracingLogger};
pub use record::{ToolCallOutcome, ToolCallRecord, ToolCallSource};
