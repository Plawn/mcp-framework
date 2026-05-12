use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

use crate::newtypes::{SessionId, ToolName};

/// Which dispatch path handled the tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallSource {
    /// Handled by the [`CapabilityRegistry`](crate::CapabilityRegistry) (dynamic tools).
    Registry,
    /// Handled by the inner `ServerHandler` (static tools).
    Inner,
}

/// The outcome of a tool call.
#[derive(Debug, Clone)]
pub enum ToolCallOutcome {
    /// Tool executed successfully.
    ///
    /// `is_error` mirrors `CallToolResult::is_error` — when `true` the tool
    /// itself reported an error (e.g. bad input from the LLM), but the MCP
    /// protocol call succeeded.
    Success {
        is_error: bool,
        content_summary: Option<String>,
    },
    /// The call returned an MCP protocol-level error (`ErrorData`).
    McpError { code: i32, message: String },
}

/// A complete record of one `call_tool` invocation.
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    /// Name of the tool that was called.
    pub tool_name: ToolName,
    /// Arguments passed to the tool (raw JSON object), if any.
    pub arguments: Option<Map<String, Value>>,
    /// MCP session ID (falls back to `"default"` in stdio mode).
    pub session_id: SessionId,
    /// Wall-clock time when the call started.
    pub timestamp: SystemTime,
    /// How long the tool call took to complete.
    pub duration: Duration,
    /// Whether the call was dispatched via the registry or the inner handler.
    pub source: ToolCallSource,
    /// The outcome (success or error).
    pub outcome: ToolCallOutcome,
}
