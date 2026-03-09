//! MCP server with tools using the `#[tool_router]` macro.
//!
//! Exposes two tools:
//! - `greet`: returns a greeting for a given name
//! - `add`: adds two numbers
//!
//! ```sh
//! cargo run --example with_tools -- --transport http
//! ```

use mcp_framework::prelude::*;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{schemars, tool, tool_handler, tool_router};

// ── Tool parameter types ─────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GreetParams {
    #[schemars(description = "The name to greet")]
    name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AddParams {
    #[schemars(description = "First number")]
    a: f64,
    #[schemars(description = "Second number")]
    b: f64,
}

// ── Server ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct ToolServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl ToolServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl ToolServer {
    #[tool(description = "Return a friendly greeting")]
    fn greet(&self, Parameters(params): Parameters<GreetParams>) -> String {
        format!("Hello, {}! Welcome to the MCP server.", params.name)
    }

    #[tool(description = "Add two numbers together")]
    fn add(&self, Parameters(params): Parameters<AddParams>) -> String {
        format!("{}", params.a + params.b)
    }
}

#[tool_handler]
impl ServerHandler for ToolServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("A simple MCP server with greet and add tools.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("tools-example")
        .server(|| ToolServer::new())
        .run()
        .await
}
