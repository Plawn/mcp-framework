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
use rmcp::model::{ServerCapabilities, ServerInfo};

struct AuthServer;

impl ServerHandler for AuthServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("An MCP server protected by HTTP Basic auth.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = Result<rmcp::model::ListToolsResult, McpError>> + Send + '_
    {
        async move {
            Ok(rmcp::model::ListToolsResult {
                tools: vec![Tool {
                    name: "whoami".into(),
                    description: Some("Returns info about the current authenticated session".into()),
                    input_schema: Default::default(),
                    output_schema: None,
                    annotations: None,
                }],
                next_cursor: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParam,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
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
                Ok(CallToolResult::success(vec![
                    rmcp::model::Content::text(msg),
                ]))
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
