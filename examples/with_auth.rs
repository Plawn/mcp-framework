//! MCP server with HTTP Basic authentication.
//!
//! The server reads credentials from `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD`
//! env vars, or you can hardcode them as shown below.
//!
//! ```sh
//! # Using env vars:
//! BASIC_AUTH_USERNAME=admin BASIC_AUTH_PASSWORD=secret \
//!   cargo run --example with_auth -- --transport http
//!
//! # Test with curl:
//! curl -u admin:secret http://localhost:4000/mcp -d '...'
//! ```

use mcp_framework::prelude::*;

struct AuthServer;

impl ServerHandler for AuthServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("An MCP server protected by HTTP Basic auth.")
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_
    {
        async move {
            Ok(ListToolsResult::with_all_items(vec![
                Tool::new("whoami", "Returns info about the current authenticated session", serde_json::Map::new()),
            ]))
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            if request.name.as_ref() == "whoami" {
                let session_id = context.session_id();
                let token_store = context.token_store();
                let has_token = token_store.has_valid_token(session_id).await;
                let msg = format!(
                    "Session: {}\nAuthenticated: {}",
                    session_id, has_token
                );
                Ok(CallToolResult::success(vec![Content::text(msg)]))
            } else {
                Err(McpError::invalid_params("unknown tool", None))
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("auth-example")
        .auth(AuthProvider::Basic(BasicAuthConfig {
            username: std::env::var("BASIC_AUTH_USERNAME")
                .unwrap_or_else(|_| "admin".to_string()),
            password: std::env::var("BASIC_AUTH_PASSWORD")
                .unwrap_or_else(|_| "secret".to_string()),
        }))
        .server(|| AuthServer)
        .run()
        .await
}
