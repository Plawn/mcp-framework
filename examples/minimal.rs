//! Minimal MCP server using the builder API.
//!
//! This is the simplest possible MCP server — no tools, no auth, no sessions.
//! It responds to `initialize` and `ping` only.
//!
//! ```sh
//! cargo run --example minimal -- --transport http
//! cargo run --example minimal -- --transport stdio
//! ```

use mcp_framework::prelude::*;
use rmcp::model::{ServerCapabilities, ServerInfo};

struct MinimalServer;

impl ServerHandler for MinimalServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("A minimal MCP server that does nothing useful.".into()),
            capabilities: ServerCapabilities::builder().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("minimal-example")
        .server(|| MinimalServer)
        .run()
        .await
}
