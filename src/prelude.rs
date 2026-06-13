//! Convenience re-exports for the most commonly used types.
//!
//! ```rust,ignore
//! use mcp_framework::prelude::*;
//! ```

pub use crate::audit::{
    CompositeLogger, NoopLogger, ToolCallLogger, ToolCallOutcome, ToolCallRecord, ToolCallSource,
    TracingLogger,
};
#[cfg(feature = "metrics")]
pub use crate::metrics::{
    MetricsCollector, MetricsConfig, MetricsSnapshot, SessionMetrics, ToolMetrics,
};
pub use crate::persistence::{InMemoryBackend, PersistenceBackend, PersistenceError};
#[cfg(feature = "redis")]
pub use crate::persistence::RedisBackend;
pub use crate::auth::{AuthProvider, BasicAuthConfig, OAuthConfig, TokenMode, TokenStore};
pub use crate::capability::{
    AccessDecision, AccessValidator, CapabilityFilter, CapabilityRegistry, PromptFilter,
    ResourceFilter, ToolCallContext, ToolCallValidator, ToolFilter,
};
pub use crate::runner::{run, LogLevel, McpApp, McpAppBuilder, Settings, TransportMode};
pub use crate::session::{RequestContextExt, Session, SessionData, SessionStore};
pub use crate::EmptyParams;

// Re-exports from rmcp so consumers don't need it as a direct dependency
pub use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, GetPromptResult, ListToolsResult,
    PaginatedRequestParams, Prompt, ReadResourceResult, Resource, ServerCapabilities, ServerInfo,
    Tool,
};
pub use rmcp::handler::server::router::tool::ToolRouter;
pub use rmcp::handler::server::wrapper::Parameters;
pub use rmcp::service::RequestContext;
pub use rmcp::ErrorData as McpError;
pub use rmcp::RoleServer;
pub use rmcp::ServerHandler;
pub use rmcp::schemars;
