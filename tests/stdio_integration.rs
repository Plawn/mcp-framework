//! Integration tests for MCP servers running in stdio mode.
//!
//! Each test builds an example binary, spawns it as a child process with
//! `--transport stdio`, and communicates over stdin/stdout using an rmcp client.

use rmcp::model::CallToolRequestParam;
use rmcp::transport::TokioChildProcess;
use rmcp::ServiceExt;

/// Spawn an example binary with `--transport stdio`.
fn spawn_example(example: &str) -> anyhow::Result<TokioChildProcess> {
    let mut cmd = tokio::process::Command::new(env!("CARGO"));
    cmd.args(["run", "--example", example, "--"])
        .args(["--transport", "stdio"]);
    Ok(TokioChildProcess::new(cmd)?)
}

// ── Minimal server ──────────────────────────────────────────────────

#[tokio::test]
async fn minimal_server_initializes() -> anyhow::Result<()> {
    let transport = spawn_example("minimal")?;
    let client = ().serve(transport).await?;

    let info = client.peer().peer_info().expect("server info");
    assert!(info
        .instructions
        .as_deref()
        .unwrap_or("")
        .contains("minimal"));

    client.cancel().await?;
    Ok(())
}

// ── Server with tools ───────────────────────────────────────────────

#[tokio::test]
async fn list_tools_returns_registered_tools() -> anyhow::Result<()> {
    let transport = spawn_example("with_tools")?;
    let client = ().serve(transport).await?;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    assert!(names.contains(&"greet"), "expected 'greet' tool, got: {names:?}");
    assert!(names.contains(&"add"), "expected 'add' tool, got: {names:?}");

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn call_greet_tool() -> anyhow::Result<()> {
    let transport = spawn_example("with_tools")?;
    let client = ().serve(transport).await?;

    let result = client
        .call_tool(CallToolRequestParam {
            name: "greet".into(),
            arguments: Some(
                serde_json::json!({ "name": "World" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        })
        .await?;

    let text = result
        .content
        .as_ref()
        .and_then(|c| c.first())
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    assert!(
        text.contains("World"),
        "greeting should contain 'World', got: {text}"
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn call_add_tool() -> anyhow::Result<()> {
    let transport = spawn_example("with_tools")?;
    let client = ().serve(transport).await?;

    let result = client
        .call_tool(CallToolRequestParam {
            name: "add".into(),
            arguments: Some(
                serde_json::json!({ "a": 2.5, "b": 3.5 })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        })
        .await?;

    let text = result
        .content
        .as_ref()
        .and_then(|c| c.first())
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    assert_eq!(text, "6", "2.5 + 3.5 = 6");

    client.cancel().await?;
    Ok(())
}

// ── Server capabilities ─────────────────────────────────────────────

#[tokio::test]
async fn server_advertises_tool_capability() -> anyhow::Result<()> {
    let transport = spawn_example("with_tools")?;
    let client = ().serve(transport).await?;

    let info = client.peer().peer_info().expect("server info");
    assert!(
        info.capabilities.tools.is_some(),
        "expected tools capability to be advertised"
    );

    client.cancel().await?;
    Ok(())
}

// ── Dynamic capabilities ────────────────────────────────────────────

#[tokio::test]
async fn dynamic_tools_are_listed() -> anyhow::Result<()> {
    let transport = spawn_example("dynamic_capabilities")?;
    let client = ().serve(transport).await?;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    // The dynamic_capabilities example adds "ping" and "admin_reset" tools.
    // Without a token, ToolFilter hides "admin_reset".
    assert!(
        names.contains(&"ping"),
        "expected 'ping' tool, got: {names:?}"
    );

    client.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn call_dynamic_ping_tool() -> anyhow::Result<()> {
    let transport = spawn_example("dynamic_capabilities")?;
    let client = ().serve(transport).await?;

    let result = client
        .call_tool(CallToolRequestParam {
            name: "ping".into(),
            arguments: None,
        })
        .await?;

    let text = result
        .content
        .as_ref()
        .and_then(|c| c.first())
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .expect("expected text content");

    assert_eq!(text, "pong");

    client.cancel().await?;
    Ok(())
}

// ── Filtered capabilities ───────────────────────────────────────────

#[tokio::test]
async fn admin_tools_are_filtered_without_token() -> anyhow::Result<()> {
    let transport = spawn_example("dynamic_capabilities")?;
    let client = ().serve(transport).await?;

    let tools = client.list_all_tools().await?;
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

    // Without authentication, the ToolFilter should hide "admin_reset"
    assert!(
        !names.contains(&"admin_reset"),
        "admin_reset should be filtered out without a token, got: {names:?}"
    );

    client.cancel().await?;
    Ok(())
}
