//! Integration tests for MCP servers running over HTTP/SSE transport.
//!
//! These tests use `build_app()` to create an Axum router, bind it to a
//! random port, then connect an rmcp HTTP client to exercise the full
//! Streamable HTTP + SSE path — the same path that was failing with
//! "connection closed before message completed" after the rmcp 1.2 upgrade.

use mcp_framework::auth::AuthProvider;
use mcp_framework::prelude::*;
use mcp_framework::session::SessionStore;
use mcp_framework::transport::{build_app, HttpAppConfig};
use rmcp::handler::server::tool::schema_for_output;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::{tool, ServiceExt};

// ── Tool parameter types ────────────────────────────────────────────

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

// ── Output schema types ─────────────────────────────────────────────

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct GreetOutput {
    #[schemars(description = "The greeting message")]
    message: String,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct ProjectSource {
    id: u64,
    name: String,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct ProjectItem {
    id: u64,
    name: String,
    description: String,
    metadata: ProjectMetadata,
    sources: Vec<ProjectSource>,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct ProjectMetadata {
    language: String,
    role: String,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct LargeResponseOutput {
    #[schemars(description = "List of projects")]
    projects: Vec<ProjectItem>,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
struct PingOutput {
    #[schemars(description = "The pong response")]
    message: String,
}

// ── Server ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct TestServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl TestServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[rmcp::tool_router]
impl TestServer {
    #[tool(
        description = "Return a short greeting",
        output_schema = schema_for_output::<GreetOutput>().unwrap()
    )]
    async fn greet(
        &self,
        Parameters(params): Parameters<GreetParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let msg = format!("Hello, {}!", params.name);
        Ok(CallToolResult::success(vec![Content::text(msg)]))
    }

    #[tool(
        description = "Return a large JSON payload to test SSE streaming",
        output_schema = schema_for_output::<LargeResponseOutput>().unwrap()
    )]
    fn large_response(&self, Parameters(params): Parameters<SizeParams>) -> String {
        let size = params.size.unwrap_or(5000);
        let item = serde_json::json!({
            "id": 42,
            "name": "Test Project",
            "description": "A project with a reasonably long description to simulate real API payloads.",
            "metadata": { "language": "English", "role": "Analyst" },
            "sources": [
                {"id": 1, "name": "Source A"},
                {"id": 2, "name": "Source B"},
                {"id": 3, "name": "Source C"},
            ]
        });
        let item_str = serde_json::to_string_pretty(&item).unwrap();
        let repeat = (size / item_str.len()).max(1);
        let items: Vec<_> = (0..repeat)
            .map(|i| {
                let mut v = item.clone();
                v["id"] = serde_json::json!(i);
                v
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({ "projects": items })).unwrap()
    }

    #[tool(
        description = "Return pong",
        output_schema = schema_for_output::<PingOutput>().unwrap()
    )]
    fn ping(&self, Parameters(_): Parameters<EmptyParams>) -> String {
        "pong".to_string()
    }
}

#[rmcp::tool_handler]
impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("HTTP integration test server")
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Start the HTTP MCP server on a random port, return the bound address.
async fn start_server() -> std::net::SocketAddr {
    let config: HttpAppConfig<_, ()> = HttpAppConfig {
        public_url: "http://localhost".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        auth: AuthProvider::None,
        server_factory: || TestServer::new(),
        app_name: "http-test".to_string(),
        capability_registry: None,
        capability_filter: None,
        session_store: SessionStore::default(),
    };

    let (app, _token_store) = build_app(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

/// Connect an rmcp HTTP client to the server at the given address.
async fn connect_client(
    addr: std::net::SocketAddr,
) -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
    let url = format!("http://{}/mcp", addr);
    let transport = StreamableHttpClientTransport::from_uri(url);
    ().serve(transport).await.expect("client connect failed")
}

fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("rmcp=trace,mcp_framework=trace")
        .with_test_writer()
        .try_init();
}

// ── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn http_initialize() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let info = client.peer().peer_info().expect("server info");
    assert!(info
        .instructions
        .as_deref()
        .unwrap_or("")
        .contains("HTTP integration test"));

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_list_tools() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(names.contains(&"greet"), "missing greet, got: {names:?}");
    assert!(
        names.contains(&"large_response"),
        "missing large_response, got: {names:?}"
    );
    assert!(names.contains(&"ping"), "missing ping, got: {names:?}");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_output_schemas_present() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let tools = client.list_all_tools().await?;
    for tool in &tools {
        assert!(
            tool.output_schema.is_some(),
            "tool '{}' should have an output_schema",
            tool.name
        );
        let schema = tool.output_schema.as_ref().unwrap();
        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "tool '{}' output_schema should have type: object",
            tool.name
        );
    }

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_call_small_tool() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let result = client
        .call_tool(CallToolRequestParams::new("greet").with_arguments(
            serde_json::json!({ "name": "World" })
                .as_object()
                .unwrap()
                .clone(),
        ))
        .await?;

    let text = result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    assert_eq!(text, "Hello, World!");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_call_large_tool() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    // Request a ~10KB response to stress SSE streaming
    let result = client
        .call_tool(CallToolRequestParams::new("large_response").with_arguments(
            serde_json::json!({ "size": 10000 })
                .as_object()
                .unwrap()
                .clone(),
        ))
        .await?;

    let text = result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    // Verify it's valid JSON and contains the projects array
    let parsed: serde_json::Value = serde_json::from_str(text)?;
    let projects = parsed["projects"].as_array().expect("expected projects array");
    assert!(
        projects.len() > 1,
        "expected multiple projects, got {}",
        projects.len()
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_call_empty_params_tool() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    let result = client
        .call_tool(CallToolRequestParams::new("ping"))
        .await?;

    let text = result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    assert_eq!(text, "pong");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn http_multiple_calls_same_session() -> anyhow::Result<()> {
    init_test_tracing();
    let addr = start_server().await;
    let client = connect_client(addr).await;

    // Make several calls on the same connection to test session reuse
    for i in 0..5 {
        let result = client
            .call_tool(CallToolRequestParams::new("greet").with_arguments(
                serde_json::json!({ "name": format!("User{i}") })
                    .as_object()
                    .unwrap()
                    .clone(),
            ))
            .await?;

        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .expect("expected text content");

        assert_eq!(text, format!("Hello, User{i}!"));
    }

    client.cancel().await?;
    Ok(())
}
