use super::*;
use super::{PromptFilter, ResourceFilter, ToolFilter};

fn make_tool(name: &str) -> Tool {
    Tool::new(name.to_string(), name.to_string(), serde_json::Map::new())
}

#[test]
fn tool_filter_filters_tools() {
    let filter = ToolFilter(|tools: Vec<Tool>, _token: Option<&StoredToken>| -> Vec<Tool> {
        tools
            .into_iter()
            .filter(|t| !t.name.starts_with("admin_"))
            .collect()
    });

    let tools = vec![make_tool("public"), make_tool("admin_delete")];
    let filtered = filter.filter_tools(tools, None);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name.as_ref(), "public");
}

#[test]
fn tool_filter_passes_prompts_through() {
    let filter =
        ToolFilter(|_tools: Vec<Tool>, _token: Option<&StoredToken>| -> Vec<Tool> {
            Vec::new()
        });

    let prompts = vec![Prompt::new::<_, &str>("test", None, None)];
    let result = filter.filter_prompts(prompts.clone(), None);
    assert_eq!(result.len(), 1);
}

#[test]
fn prompt_filter_filters_prompts() {
    let filter =
        PromptFilter(|prompts: Vec<Prompt>, _token: Option<&StoredToken>| -> Vec<Prompt> {
            prompts
                .into_iter()
                .filter(|p| p.name != "secret")
                .collect()
        });

    let prompts = vec![
        Prompt::new::<_, &str>("public", None, None),
        Prompt::new::<_, &str>("secret", None, None),
    ];
    let filtered = filter.filter_prompts(prompts, None);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "public");

    let tools = vec![make_tool("any")];
    assert_eq!(filter.filter_tools(tools, None).len(), 1);
}

#[test]
fn resource_filter_filters_resources() {
    use rmcp::model::{Annotated, RawResource};

    let filter = ResourceFilter(
        |resources: Vec<Resource>, _token: Option<&StoredToken>| -> Vec<Resource> {
            resources
                .into_iter()
                .filter(|r| r.raw.uri != "secret://x")
                .collect()
        },
    );

    let resources = vec![
        Annotated {
            raw: RawResource::new("public://a", "public"),
            annotations: None,
        },
        Annotated {
            raw: RawResource::new("secret://x", "secret"),
            annotations: None,
        },
    ];
    let filtered = filter.filter_resources(resources, None);
    assert_eq!(filtered.len(), 1);

    let tools = vec![make_tool("any")];
    assert_eq!(filter.filter_tools(tools, None).len(), 1);
}

#[tokio::test]
async fn resolve_token_empty_extensions_returns_none() {
    let extensions = Extensions::new();
    let store = TokenStore::new();
    assert!(resolve_token(&extensions, &store).await.is_none());
}

#[tokio::test]
async fn resolve_token_with_session_id() {
    let mut extensions = Extensions::new();

    let request = http::Request::builder()
        .header("mcp-session-id", "sess-123")
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();
    extensions.insert(parts);

    let store = TokenStore::new();
    store
        .store_token(
            "sess-123".to_string(),
            StoredToken {
                access_token: "tok".to_string(),
                refresh_token: None,
                expires_at: None,
                decoded_claims: None,
            },
        )
        .await;

    let token = resolve_token(&extensions, &store).await;
    assert!(token.is_some());
    assert_eq!(token.unwrap().access_token, "tok");
}

#[test]
fn resolve_query_filter_no_parts() {
    let extensions = Extensions::new();
    assert!(resolve_query_filter(&extensions).is_empty());
}

#[test]
fn resolve_query_filter_no_query() {
    let mut extensions = Extensions::new();
    let (parts, _) = http::Request::builder().uri("/mcp").body(()).unwrap().into_parts();
    extensions.insert(parts);
    assert!(resolve_query_filter(&extensions).is_empty());
}

#[test]
fn resolve_query_filter_with_filter() {
    let mut extensions = Extensions::new();
    let (parts, _) = http::Request::builder()
        .uri("/mcp?filter=tool1,tool2")
        .body(())
        .unwrap()
        .into_parts();
    extensions.insert(parts);
    let filter = resolve_query_filter(&extensions);
    assert_eq!(filter.len(), 2);
    assert!(filter.contains("tool1"));
    assert!(filter.contains("tool2"));
}

#[test]
fn resolve_query_filter_url_encoded() {
    let mut extensions = Extensions::new();
    let (parts, _) = http::Request::builder()
        .uri("/mcp?filter=my%20tool,other_tool")
        .body(())
        .unwrap()
        .into_parts();
    extensions.insert(parts);
    let filter = resolve_query_filter(&extensions);
    assert!(filter.contains("my tool"));
    assert!(filter.contains("other_tool"));
}

#[test]
fn resolve_query_filter_with_other_params() {
    let mut extensions = Extensions::new();
    let (parts, _) = http::Request::builder()
        .uri("/mcp?other=value&filter=tool1&more=stuff")
        .body(())
        .unwrap()
        .into_parts();
    extensions.insert(parts);
    let filter = resolve_query_filter(&extensions);
    assert_eq!(filter.len(), 1);
    assert!(filter.contains("tool1"));
}

#[test]
fn resolve_query_filter_empty_value() {
    let mut extensions = Extensions::new();
    let (parts, _) = http::Request::builder()
        .uri("/mcp?filter=")
        .body(())
        .unwrap()
        .into_parts();
    extensions.insert(parts);
    assert!(resolve_query_filter(&extensions).is_empty());
}

#[tokio::test]
async fn resolve_token_falls_back_to_default() {
    let mut extensions = Extensions::new();

    let builder = http::Request::builder().body(()).unwrap();
    let (parts, _) = builder.into_parts();
    extensions.insert(parts);

    let store = TokenStore::new();
    store
        .store_token(
            "default".to_string(),
            StoredToken {
                access_token: "default-tok".to_string(),
                refresh_token: None,
                expires_at: None,
                decoded_claims: None,
            },
        )
        .await;

    let token = resolve_token(&extensions, &store).await;
    assert!(token.is_some());
    assert_eq!(token.unwrap().access_token, "default-tok");
}
