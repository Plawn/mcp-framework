//! MCP server with role-based access validation via JWT claims.
//!
//! Demonstrates:
//! - Global claims decoder (defined once, shared by filter + validator)
//! - `ToolFilter` for visibility (hide admin tools from non-admins)
//! - `ToolCallValidator` for execution (reject admin tool calls without admin role)
//! - `StoredToken::claims::<C>()` for typed claim access
//!
//! ```sh
//! cargo run --example with_access_validator -- --transport http
//! ```

use std::sync::Arc;

use mcp_framework::auth::StoredToken;
use mcp_framework::prelude::*;

// ── Claims ──────────────────────────────────────────────────────────

/// Claims decoded from the JWT access token.
#[derive(Debug, Clone, serde::Deserialize)]
struct Claims {
    roles: Vec<String>,
}

/// Decode JWT claims from the access token (base64 payload, no signature check
/// — the auth middleware already validated the token).
fn decode_jwt_claims(token: &str) -> Option<Claims> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

// ── Server ──────────────────────────────────────────────────────────

struct MyServer;

impl ServerHandler for MyServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Server with role-based access control.")
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn is_admin(token: Option<&StoredToken>) -> bool {
    token
        .and_then(|t| t.claims::<Claims>())
        .map_or(false, |c| c.roles.iter().any(|r| r == "admin"))
}

// ── Main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let registry = CapabilityRegistry::default();

    registry
        .add_tool(
            Tool::new("public_ping", "Returns pong", serde_json::Map::new()),
            |_args| async { Ok(CallToolResult::success(vec![Content::text("pong")])) },
        )
        .await;

    registry
        .add_tool(
            Tool::new(
                "admin_reset",
                "Reset the server (admin only)",
                serde_json::Map::new(),
            ),
            |_args| async {
                Ok(CallToolResult::success(vec![Content::text(
                    "Server reset!",
                )]))
            },
        )
        .await;

    // Visibility: hide admin tools from non-admin sessions
    let filter: Arc<dyn CapabilityFilter> = Arc::new(ToolFilter(
        |tools: Vec<Tool>, token: Option<&StoredToken>| {
            if is_admin(token) {
                tools
            } else {
                tools
                    .into_iter()
                    .filter(|t| !t.name.starts_with("admin_"))
                    .collect()
            }
        },
    ));

    // Execution: reject admin tool calls without admin role
    let validator: Arc<dyn AccessValidator> = Arc::new(ToolCallValidator(
        |tool_name: &str,
         _args: Option<&serde_json::Map<String, serde_json::Value>>,
         token: Option<&StoredToken>,
         _session: &str| {
            if tool_name.starts_with("admin_") && !is_admin(token) {
                AccessDecision::Deny("admin role required".into())
            } else {
                AccessDecision::Allow
            }
        },
    ));

    McpAppBuilder::new("access-validator-example")
        .claims_decoder(decode_jwt_claims) // global — defined ONCE
        .capability_registry(registry)
        .capability_filter(filter) //           visibility
        .access_validator(validator) //         execution
        .server(|| MyServer)
        .run()
        .await
}
