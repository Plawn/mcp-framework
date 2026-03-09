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
//!         session_store: None,
//!     }).await
//! }
//! ```
//!
//! ## Features
//!
//! - **Triple transport** — HTTP (Streamable HTTP), SSE (Server-Sent Events), and stdio
//! - **Pluggable auth** — None, HTTP Basic, or OAuth 2.0 (Keycloak OIDC proxy with PKCE)
//! - **Automatic token refresh** — expired OAuth tokens are refreshed lazily on access
//! - **Dynamic capabilities** — add/remove tools, prompts, and resources at runtime
//!   via [`CapabilityRegistry`], with optional per-session filtering via [`CapabilityFilter`]
//! - **CLI or programmatic config** — built-in CLI args + env vars, or a [`Settings`] struct

pub mod auth;
pub mod capability;
pub mod http_util;
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

pub use auth::{AuthProvider, BasicAuthConfig, OAuthConfig, TokenStore};
pub use capability::{CapabilityFilter, CapabilityRegistry, PromptFilter, ResourceFilter, ToolFilter};
pub use runner::{run, LogLevel, McpApp, McpAppBuilder, Settings, TransportMode};
pub use session::{resolve_session_id, RequestContextExt, Session, SessionStore};
