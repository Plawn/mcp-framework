//! # mcp-framework
//!
//! An opinionated Rust framework for building MCP (Model Context Protocol) servers.
//! Built on top of [`rmcp`](https://crates.io/crates/rmcp), it handles transport selection,
//! authentication, CLI argument parsing, and tracing so you only need to implement
//! `rmcp::ServerHandler`.
//!
//! ## Quick start (builder API)
//!
//! ```rust,ignore
//! use mcp_framework::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     McpAppBuilder::new("my-server")
//!         .server(|| MyServer::new())
//!         .run()
//!         .await
//! }
//! ```
//!
//! ## Quick start (struct API)
//!
//! ```rust,ignore
//! use mcp_framework::{run, McpApp, AuthProvider};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     run(McpApp {
//!         name: "my-server".into(),
//!         auth: AuthProvider::None,
//!         server_factory: || MyServer::new(),
//!         stdio_token_env: None,
//!         settings: None,
//!         capability_registry: None,
//!         capability_filter: None,
//!         access_validator: None,
//!         claims_decoder: None,
//!         session_store: None,
//!         tool_call_logger: None,
//!         persistence: None,
//!         protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
//!         extra_routes: None,
//!         public_routes: None,
//!     }).await
//! }
//! ```
//!
//! ## Features
//!
//! - **Two transports** — HTTP (Streamable HTTP) and stdio, plus an in-process loopback client
//!   ([`LoopbackEndpoint`](transport::LoopbackEndpoint)) that takes the same path as network traffic
//! - **Pluggable auth** — None, HTTP Basic, or OAuth 2.0 (Keycloak OIDC proxy with PKCE)
//! - **Automatic token refresh** — expired OAuth tokens are refreshed lazily on access
//! - **Dynamic capabilities** — add/remove tools, prompts, and resources at runtime
//!   via [`CapabilityRegistry`], with optional per-session filtering via [`CapabilityFilter`]
//! - **CLI or programmatic config** — built-in CLI args + env vars, or a [`Settings`] struct
//! - **Persistence** — pluggable key-value backend for surviving restarts
//!   ([`InMemoryBackend`] for testing, [`RedisBackend`](persistence::RedisBackend) with the `redis` feature)

pub mod audit;
pub mod auth;
pub mod capability;
pub mod constants;
pub mod http_util;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod newtypes;
pub mod persistence;
pub mod prelude;
pub mod runner;
pub mod session;
pub mod transport;

/// Empty parameter type for MCP tools that take no arguments.
///
/// Use this instead of `serde_json::Value` to ensure the generated JSON Schema
/// contains `"type": "object"`, which is required by MCP clients like Claude Code.
///
/// # Example
///
/// ```rust,ignore
/// use mcp_framework::EmptyParams;
/// use rmcp::handler::server::tool::Parameters;
///
/// #[tool(description = "Returns pong")]
/// fn ping(&self, Parameters(_): Parameters<EmptyParams>) -> String {
///     "pong".to_string()
/// }
/// ```
#[derive(Debug, Clone, serde::Deserialize, rmcp::schemars::JsonSchema)]
pub struct EmptyParams {}

pub use audit::{
    CompositeLogger, NoopLogger, ToolCallLogger, ToolCallOutcome, ToolCallRecord, ToolCallSource,
    TracingLogger,
};
pub use auth::{AuthProvider, BasicAuthConfig, ConfigError, OAuthConfig, TokenMode, TokenStore};
pub use capability::{
    AccessDecision, AccessValidator, CapabilityFilter, CapabilityRegistry, PromptFilter,
    ResourceFilter, ToolCallContext, ToolCallValidator, ToolFilter,
};
#[cfg(feature = "metrics")]
pub use metrics::{MetricsCollector, MetricsConfig, MetricsSnapshot, SessionMetrics, ToolMetrics};
pub use newtypes::{SessionId, ToolName};
#[cfg(feature = "redis")]
pub use persistence::RedisBackend;
pub use persistence::{InMemoryBackend, PersistenceBackend, PersistenceError};
pub use runner::{LogLevel, McpApp, McpAppBuilder, Settings, TransportMode, run};
pub use session::{RequestContextExt, Session, SessionData, SessionStore, resolve_session_id};
pub use transport::{MAX_PROTOCOL_VERSION_ENV, ProtocolLifecyclePolicy, resolve_max_protocol_version};
