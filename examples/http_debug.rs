//! Standalone HTTP MCP server for debugging with Claude Code.
//!
//! Exposes tools that return both small and large responses to test
//! SSE streaming behavior.
//!
//! ```sh
//! # Run with trace logging to see full SSE lifecycle:
//! cargo run --example http_debug -- --transport http --trace
//!
//! # Then point Claude Code at: http://localhost:4000/mcp
//! ```

use mcp_framework::prelude::*;
use rmcp::{tool, tool_handler, tool_router};

// ── Tool parameter types ─────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GreetParams {
    #[schemars(description = "The name to greet")]
    name: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SizeParams {
    #[schemars(description = "Approximate response size in bytes (default: 5000)")]
    size: Option<usize>,
}

// ── Server ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct DebugServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl DebugServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl DebugServer {
    /// Small response — should always work.
    #[tool(description = "Return a short greeting")]
    fn greet(&self, Parameters(params): Parameters<GreetParams>) -> String {
        format!("Hello, {}!", params.name)
    }

    /// Large response — reproduces the SSE streaming issue.
    #[tool(description = "Return a large JSON payload to test SSE streaming")]
    fn large_response(&self, Parameters(params): Parameters<SizeParams>) -> String {
        let size = params.size.unwrap_or(5000);
        let item = serde_json::json!({
            "id": 42,
            "name": "Test Project",
            "description": "A project with a long description that contains enough text to be realistic. This simulates the kind of data returned by real API calls.",
            "metadata": {
                "language": "English",
                "role": "CX Analyst",
                "studyQuestion": "What did you think of your experience?",
                "target": "customer"
            },
            "sources": [
                {"id": 1, "name": "Source A", "icon": "https://example.com/icon-a.png"},
                {"id": 2, "name": "Source B", "icon": "https://example.com/icon-b.png"},
                {"id": 3, "name": "Source C", "icon": "https://example.com/icon-c.png"},
            ]
        });
        let item_str = serde_json::to_string_pretty(&item).unwrap();
        let repeat = (size / item_str.len()).max(1);
        let items: Vec<_> = (0..repeat).map(|i| {
            let mut v = item.clone();
            v["id"] = serde_json::json!(i);
            v
        }).collect();
        serde_json::to_string_pretty(&serde_json::json!({ "projects": items })).unwrap()
    }

    /// No-params tool to test EmptyParams handling.
    #[tool(description = "Return pong")]
    fn ping(&self, Parameters(_): Parameters<EmptyParams>) -> String {
        "pong".to_string()
    }
}

#[tool_handler]
impl ServerHandler for DebugServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Debug MCP server for testing HTTP/SSE transport. \
                 Tools: greet (small), large_response (large), ping (empty params).",
            )
    }
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("http-debug")
        .server(|| DebugServer::new())
        .run()
        .await
}
