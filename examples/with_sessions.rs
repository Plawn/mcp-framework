//! MCP server with typed per-session state.
//!
//! Each connected client gets its own `MySession` that tracks how many
//! tool calls it has made. The session data persists across tool calls
//! within the same MCP session.
//!
//! ```sh
//! cargo run --example with_sessions -- --transport http
//! ```

use mcp_framework::prelude::*;

// ── Session data ─────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct MySession {
    call_count: u32,
}

// ── Server ───────────────────────────────────────────────────────────

struct SessionServer;

impl ServerHandler for SessionServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Tracks per-session call counts.")
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async move {
            Ok(ListToolsResult::with_all_items(vec![
                Tool::new("stats", "Show how many times you've called tools in this session", serde_json::Map::new()),
            ]))
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            let session = context.session::<MySession>();

            // Increment the call counter
            let data = session.update(|s| s.call_count += 1).await;

            if request.name.as_ref() == "stats" {
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Session '{}': {} tool call(s) so far.",
                    session.id(),
                    data.call_count
                ))]))
            } else {
                Err(McpError::invalid_params("unknown tool", None))
            }
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("sessions-example")
        .with_sessions::<MySession>()
        .server(|| SessionServer)
        .run()
        .await
}
