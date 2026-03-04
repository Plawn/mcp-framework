//! # mcp-framework
//!
//! An opinionated Rust framework for building MCP (Model Context Protocol) servers.
//! Built on top of [`rmcp`](https://crates.io/crates/rmcp), it handles transport selection,
//! authentication, CLI argument parsing, and tracing so you only need to implement
//! `rmcp::ServerHandler`.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use mcp_framework::{run, McpApp, AuthProvider};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     run(McpApp {
//!         name: "my-server",
//!         auth: AuthProvider::None,
//!         server_factory: |_token_store| MyServer::new(),
//!         stdio_token_env: None,
//!         settings: None,
//!         capability_registry: None,
//!         capability_filter: None,
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
pub mod runner;
pub mod transport;

pub use auth::{AuthProvider, BasicAuthConfig, OAuthConfig, TokenStore};
pub use capability::{CapabilityFilter, CapabilityRegistry};
pub use runner::{run, LogLevel, McpApp, Settings, TransportMode};
