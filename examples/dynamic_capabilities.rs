//! MCP server with dynamic capabilities and a ToolFilter.
//!
//! Demonstrates:
//! - Adding tools at runtime via `CapabilityRegistry`
//! - Filtering tools per-session via `ToolFilter`
//! - Using the builder API with full configuration
//!
//! ```sh
//! cargo run --example dynamic_capabilities -- --transport http
//! ```

use std::sync::Arc;

use mcp_framework::auth::StoredToken;
use mcp_framework::prelude::*;
use rmcp::model::{Content, ServerCapabilities, ServerInfo};

// ── Server ───────────────────────────────────────────────────────────

struct DynServer;

impl ServerHandler for DynServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Server with dynamic tools and filtering.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a registry and add tools dynamically
    let registry = CapabilityRegistry::default();

    // A public tool available to everyone
    registry
        .add_tool(
            Tool {
                name: "ping".into(),
                description: Some("Returns pong".into()),
                input_schema: Default::default(),
                output_schema: None,
                annotations: None,
            },
            |_args| async { Ok(CallToolResult::success(vec![Content::text("pong")])) },
        )
        .await;

    // An admin tool that will be filtered out for unauthenticated sessions
    registry
        .add_tool(
            Tool {
                name: "admin_reset".into(),
                description: Some("Reset the server (admin only)".into()),
                input_schema: Default::default(),
                output_schema: None,
                annotations: None,
            },
            |_args| async {
                Ok(CallToolResult::success(vec![Content::text(
                    "Server reset!",
                )]))
            },
        )
        .await;

    // Filter: hide tools starting with "admin_" unless the session has a token
    let filter: Arc<dyn CapabilityFilter> = Arc::new(ToolFilter(
        |tools: Vec<Tool>, token: Option<&StoredToken>| match token {
            Some(_) => tools, // authenticated → see everything
            None => tools
                .into_iter()
                .filter(|t| !t.name.starts_with("admin_"))
                .collect(),
        },
    ));

    McpAppBuilder::new("dynamic-example")
        .server(|| DynServer)
        .capability_registry(registry)
        .capability_filter(filter)
        .run()
        .await
}
