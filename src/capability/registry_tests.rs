use super::*;
use rmcp::model::{Annotated, Content, GetPromptResult, RawResource, ReadResourceResult};

fn make_tool(name: &str) -> Tool {
    Tool::new(name.to_string(), format!("Tool {name}"), serde_json::Map::new())
}

fn make_prompt(name: &str) -> Prompt {
    Prompt::new(name, Some(format!("Prompt {name}")), None)
}

fn make_resource(uri: &str) -> Resource {
    Annotated {
        raw: RawResource::new(uri, uri),
        annotations: None,
    }
}

// ── Tool tests ───────────────────────────────────────────────────

#[tokio::test]
async fn add_and_list_tools() {
    let reg = CapabilityRegistry::new();
    assert!(reg.tools().await.is_empty());

    reg.add_tool(make_tool("alpha"), |_args| async {
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    })
    .await;

    let tools = reg.tools().await;
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name.as_ref(), "alpha");
}

#[tokio::test]
async fn remove_tool_returns_true_if_existed() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("beta"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;

    assert!(reg.remove_tool("beta").await);
    assert!(!reg.remove_tool("beta").await);
    assert!(reg.tools().await.is_empty());
}

#[tokio::test]
async fn try_call_tool_dispatches_to_handler() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("echo"), |_args| async {
        Ok(CallToolResult::success(vec![Content::text("hello")]))
    })
    .await;

    let result = reg.try_call_tool("echo", None).await;
    assert!(result.is_some());
    let result = result.unwrap().unwrap();
    assert!(!result.content.is_empty());
}

#[tokio::test]
async fn try_call_tool_returns_none_for_unknown() {
    let reg = CapabilityRegistry::new();
    assert!(reg.try_call_tool("unknown", None).await.is_none());
}

// ── Public call_tool tests ──────────────────────────────────────

#[tokio::test]
async fn call_tool_dispatches_to_handler() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("echo"), |_args| async {
        Ok(CallToolResult::success(vec![Content::text("hello")]))
    })
    .await;

    let result = reg
        .call_tool("echo", Some(serde_json::json!({})))
        .await
        .unwrap();
    assert!(!result.content.is_empty());
}

#[tokio::test]
async fn call_tool_accepts_none_args() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("ping"), |_args| async {
        Ok(CallToolResult::success(vec![Content::text("pong")]))
    })
    .await;

    let result = reg.call_tool("ping", None).await.unwrap();
    assert!(!result.content.is_empty());
}

#[tokio::test]
async fn call_tool_accepts_null_args() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("ping"), |_args| async {
        Ok(CallToolResult::success(vec![Content::text("pong")]))
    })
    .await;

    let result = reg
        .call_tool("ping", Some(serde_json::Value::Null))
        .await
        .unwrap();
    assert!(!result.content.is_empty());
}

#[tokio::test]
async fn call_tool_rejects_non_object_args() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("t"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;

    let err = reg
        .call_tool("t", Some(serde_json::json!("string")))
        .await
        .unwrap_err();
    assert!(err.message.contains("JSON object"));
}

#[tokio::test]
async fn call_tool_returns_error_for_unknown() {
    let reg = CapabilityRegistry::new();
    let err = reg.call_tool("missing", None).await.unwrap_err();
    assert!(err.message.contains("not found"));
}

// ── Prompt tests ─────────────────────────────────────────────────

#[tokio::test]
async fn add_and_list_prompts() {
    let reg = CapabilityRegistry::new();
    reg.add_prompt(make_prompt("greeting"), |_params| async {
        Ok(GetPromptResult::new(vec![]).with_description("Hello"))
    })
    .await;

    let prompts = reg.prompts().await;
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "greeting");
}

#[tokio::test]
async fn remove_prompt() {
    let reg = CapabilityRegistry::new();
    reg.add_prompt(make_prompt("p"), |_| async {
        Ok(GetPromptResult::new(vec![]))
    })
    .await;

    assert!(reg.remove_prompt("p").await);
    assert!(!reg.remove_prompt("p").await);
}

#[tokio::test]
async fn get_prompt_dispatches() {
    let reg = CapabilityRegistry::new();
    reg.add_prompt(make_prompt("test"), |_| async {
        Ok(GetPromptResult::new(vec![]).with_description("dispatched"))
    })
    .await;

    let result = reg
        .get_prompt(&GetPromptRequestParams::new("test"))
        .await;
    assert!(result.is_some());
    let result = result.unwrap().unwrap();
    assert_eq!(result.description.as_deref(), Some("dispatched"));
}

// ── Resource tests ───────────────────────────────────────────────

#[tokio::test]
async fn add_and_list_resources() {
    let reg = CapabilityRegistry::new();
    reg.add_resource(make_resource("file:///a.txt"), |_| async {
        Ok(ReadResourceResult::new(vec![]))
    })
    .await;

    let resources = reg.resources().await;
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].raw.uri, "file:///a.txt");
}

#[tokio::test]
async fn remove_resource() {
    let reg = CapabilityRegistry::new();
    reg.add_resource(make_resource("file:///b"), |_| async {
        Ok(ReadResourceResult::new(vec![]))
    })
    .await;

    assert!(reg.remove_resource("file:///b").await);
    assert!(!reg.remove_resource("file:///b").await);
}

#[tokio::test]
async fn read_resource_dispatches() {
    let reg = CapabilityRegistry::new();
    reg.add_resource(make_resource("file:///c"), |_| async {
        Ok(ReadResourceResult::new(vec![]))
    })
    .await;

    let result = reg
        .read_resource(&ReadResourceRequestParams::new("file:///c"))
        .await;
    assert!(result.is_some());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn read_resource_returns_none_for_unknown() {
    let reg = CapabilityRegistry::new();
    assert!(reg
        .read_resource(&ReadResourceRequestParams::new("nope"))
        .await
        .is_none());
}

// ── Clone sharing test ───────────────────────────────────────────

#[tokio::test]
async fn cloned_registry_shares_state() {
    let reg = CapabilityRegistry::new();
    let reg2 = reg.clone();

    reg.add_tool(make_tool("shared"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;

    assert_eq!(reg2.tools().await.len(), 1);
}

// ── Version tests ───────────────────────────────────────────────

#[tokio::test]
async fn empty_registry_has_consistent_version() {
    let reg1 = CapabilityRegistry::new();
    let reg2 = CapabilityRegistry::new();
    assert_eq!(reg1.version(), reg2.version());
}

#[tokio::test]
async fn version_changes_on_add_tool() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("a"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;
    let v1 = reg.version();
    assert_ne!(v1, 0);

    reg.add_tool(make_tool("b"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;
    let v2 = reg.version();
    assert_ne!(v2, v1);
}

#[tokio::test]
async fn version_changes_on_remove_tool() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("x"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;
    let v = reg.version();

    reg.remove_tool("x").await;
    assert_ne!(reg.version(), v);
}

#[tokio::test]
async fn version_unchanged_on_noop_remove() {
    let reg = CapabilityRegistry::new();
    let v = reg.version();
    reg.remove_tool("nonexistent").await;
    assert_eq!(reg.version(), v);
}

#[tokio::test]
async fn version_changes_on_prompt_mutations() {
    let reg = CapabilityRegistry::new();
    let empty_version = reg.version();

    reg.add_prompt(make_prompt("p"), |_| async {
        Ok(GetPromptResult::new(vec![]))
    })
    .await;
    assert_ne!(reg.version(), empty_version);

    reg.remove_prompt("p").await;
    assert_eq!(reg.version(), empty_version);
}

#[tokio::test]
async fn version_changes_on_resource_mutations() {
    let reg = CapabilityRegistry::new();
    let empty_version = reg.version();

    reg.add_resource(make_resource("file:///a"), |_| async {
        Ok(ReadResourceResult::new(vec![]))
    })
    .await;
    assert_ne!(reg.version(), empty_version);

    reg.remove_resource("file:///a").await;
    assert_eq!(reg.version(), empty_version);
}

#[tokio::test]
async fn version_returns_to_original_after_add_remove() {
    let reg = CapabilityRegistry::new();
    reg.add_tool(make_tool("a"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;
    let v_with_a = reg.version();

    reg.add_tool(make_tool("b"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;
    assert_ne!(reg.version(), v_with_a);

    reg.remove_tool("b").await;
    assert_eq!(reg.version(), v_with_a);
}

#[tokio::test]
async fn version_deterministic_across_registries() {
    let reg1 = CapabilityRegistry::new();
    let reg2 = CapabilityRegistry::new();

    for reg in [&reg1, &reg2] {
        reg.add_tool(make_tool("a"), |_| async {
            Ok(CallToolResult::success(vec![]))
        })
        .await;
        reg.add_prompt(make_prompt("b"), |_| async {
            Ok(GetPromptResult::new(vec![]))
        })
        .await;
    }

    assert_eq!(reg1.version(), reg2.version());
}

#[tokio::test]
async fn version_differs_with_different_tools() {
    let reg1 = CapabilityRegistry::new();
    let reg2 = CapabilityRegistry::new();

    reg1.add_tool(make_tool("a"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;
    reg2.add_tool(make_tool("b"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;

    assert_ne!(reg1.version(), reg2.version());
}

#[tokio::test]
async fn version_shared_across_clones() {
    let reg = CapabilityRegistry::new();
    let reg2 = reg.clone();

    reg.add_tool(make_tool("x"), |_| async {
        Ok(CallToolResult::success(vec![]))
    })
    .await;

    assert_eq!(reg2.version(), reg.version());
}
