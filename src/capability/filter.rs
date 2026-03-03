use rmcp::model::{Extensions, Prompt, Resource, Tool};

use crate::auth::{StoredToken, TokenStore};

/// Trait for filtering capabilities based on the session's authentication token.
///
/// Implement this trait to control which tools, prompts, and resources are
/// visible to each connected client. The default implementations pass
/// everything through unfiltered.
pub trait CapabilityFilter: Send + Sync + 'static {
    /// Filter the list of tools visible to a given session.
    fn filter_tools(&self, tools: Vec<Tool>, token: Option<&StoredToken>) -> Vec<Tool> {
        let _ = token;
        tools
    }

    /// Filter the list of prompts visible to a given session.
    fn filter_prompts(&self, prompts: Vec<Prompt>, token: Option<&StoredToken>) -> Vec<Prompt> {
        let _ = token;
        prompts
    }

    /// Filter the list of resources visible to a given session.
    fn filter_resources(
        &self,
        resources: Vec<Resource>,
        token: Option<&StoredToken>,
    ) -> Vec<Resource> {
        let _ = token;
        resources
    }
}

/// Blanket implementation: a closure `Fn(Vec<Tool>, Option<&StoredToken>) -> Vec<Tool>`
/// can be used as a `CapabilityFilter` that only filters tools.
impl<F> CapabilityFilter for F
where
    F: Fn(Vec<Tool>, Option<&StoredToken>) -> Vec<Tool> + Send + Sync + 'static,
{
    fn filter_tools(&self, tools: Vec<Tool>, token: Option<&StoredToken>) -> Vec<Tool> {
        (self)(tools, token)
    }
}

/// Attempt to resolve the stored token for the current MCP session.
///
/// Extracts the `mcp-session-id` header from the HTTP request parts
/// injected by `StreamableHttpService` into the request context extensions,
/// then looks up the corresponding token in the `TokenStore`.
///
/// Returns `None` if no HTTP parts are available (e.g. stdio mode) or if
/// no token is stored for the session.
pub(crate) async fn resolve_token(
    extensions: &Extensions,
    token_store: &TokenStore,
) -> Option<StoredToken> {
    let parts = extensions.get::<http::request::Parts>()?;
    let session_id = parts
        .headers
        .get("mcp-session-id")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("default");
    token_store.get_token(session_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string().into(),
            description: None,
            input_schema: Default::default(),
            output_schema: None,
            annotations: None,
        }
    }

    #[test]
    fn closure_filter_tools() {
        let filter = |tools: Vec<Tool>, _token: Option<&StoredToken>| -> Vec<Tool> {
            tools
                .into_iter()
                .filter(|t| !t.name.starts_with("admin_"))
                .collect()
        };

        let tools = vec![make_tool("public"), make_tool("admin_delete")];
        let filtered = CapabilityFilter::filter_tools(&filter, tools, None);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name.as_ref(), "public");
    }

    #[test]
    fn closure_filter_passes_prompts_through() {
        let filter =
            |_tools: Vec<Tool>, _token: Option<&StoredToken>| -> Vec<Tool> { Vec::new() };

        let prompts = vec![Prompt {
            name: "test".to_string(),
            description: None,
            arguments: None,
        }];
        // Closure blanket impl only filters tools; prompts pass through
        let result = CapabilityFilter::filter_prompts(&filter, prompts.clone(), None);
        assert_eq!(result.len(), 1);
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

        // Build http::request::Parts with an mcp-session-id header
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
                },
            )
            .await;

        let token = resolve_token(&extensions, &store).await;
        assert!(token.is_some());
        assert_eq!(token.unwrap().access_token, "tok");
    }

    #[tokio::test]
    async fn resolve_token_falls_back_to_default() {
        let mut extensions = Extensions::new();

        // No mcp-session-id header → should use "default"
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
                },
            )
            .await;

        let token = resolve_token(&extensions, &store).await;
        assert!(token.is_some());
        assert_eq!(token.unwrap().access_token, "default-tok");
    }
}
