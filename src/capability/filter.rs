use std::collections::HashSet;

use rmcp::model::{Extensions, Prompt, Resource, Tool};

use crate::auth::{RequestToken, StoredToken, TokenStore};
use crate::session::resolve_session_id;

/// Trait for filtering capabilities based on the session's authentication token.
///
/// Implement this trait to control which tools, prompts, and resources are
/// visible to each connected client. The default implementations pass
/// everything through unfiltered.
///
/// For convenience, use [`ToolFilter`], [`PromptFilter`], or [`ResourceFilter`]
/// to wrap a closure that filters only one capability type.
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

/// Filters only tools. Prompts and resources pass through unfiltered.
///
/// # Example
///
/// ```rust,ignore
/// use mcp_framework::capability::ToolFilter;
///
/// let filter = Arc::new(ToolFilter(|tools: Vec<Tool>, _token| {
///     tools.into_iter().filter(|t| !t.name.starts_with("admin_")).collect()
/// }));
/// ```
pub struct ToolFilter<F>(pub F);

impl<F> CapabilityFilter for ToolFilter<F>
where
    F: Fn(Vec<Tool>, Option<&StoredToken>) -> Vec<Tool> + Send + Sync + 'static,
{
    fn filter_tools(&self, tools: Vec<Tool>, token: Option<&StoredToken>) -> Vec<Tool> {
        (self.0)(tools, token)
    }
}

/// Filters only prompts. Tools and resources pass through unfiltered.
pub struct PromptFilter<F>(pub F);

impl<F> CapabilityFilter for PromptFilter<F>
where
    F: Fn(Vec<Prompt>, Option<&StoredToken>) -> Vec<Prompt> + Send + Sync + 'static,
{
    fn filter_prompts(&self, prompts: Vec<Prompt>, token: Option<&StoredToken>) -> Vec<Prompt> {
        (self.0)(prompts, token)
    }
}

/// Filters only resources. Tools and prompts pass through unfiltered.
pub struct ResourceFilter<F>(pub F);

impl<F> CapabilityFilter for ResourceFilter<F>
where
    F: Fn(Vec<Resource>, Option<&StoredToken>) -> Vec<Resource> + Send + Sync + 'static,
{
    fn filter_resources(
        &self,
        resources: Vec<Resource>,
        token: Option<&StoredToken>,
    ) -> Vec<Resource> {
        (self.0)(resources, token)
    }
}

/// Attempt to resolve the stored token for the current MCP session.
///
/// Resolves the session identity from the HTTP request parts injected by
/// `StreamableHttpService` into the request context extensions (see
/// [`session_id_from_parts`]), then looks up the corresponding token in the
/// `TokenStore`.
///
/// In stdio mode, resolves the shared [`DEFAULT_SESSION_ID`](crate::constants::DEFAULT_SESSION_ID)
/// used by `stdio_token_env`.
///
/// In [`TokenMode::ResourceServer`](crate::auth::TokenMode::ResourceServer)
/// there is no server-side token state to look up: the auth middleware attaches
/// the validated credential to the request as a [`RequestToken`] instead, and it
/// takes precedence over the store. Consumers see the same `StoredToken` shape
/// either way (bearer + decoded claims); only `refresh_token` is always `None`,
/// because in that mode the refresh token never reaches this process.
pub(crate) async fn resolve_token(
    extensions: &Extensions,
    token_store: &TokenStore,
) -> Option<StoredToken> {
    if let Some(parts) = extensions.get::<http::request::Parts>()
        && let Some(request_token) = parts.extensions.get::<RequestToken>()
    {
        return Some(request_token.0.clone());
    }
    token_store.get_token(resolve_session_id(extensions)).await
}

/// Extract the set of tool names to exclude from the `?filter=` query parameter.
///
/// The query parameter value is a comma-separated list of tool names to exclude
/// from `list_tools` and `call_tool`. For example, `?filter=tool1,tool2` will
/// hide `tool1` and `tool2`.
///
/// Returns an empty set if no filter is present (e.g. stdio mode or no query param).
pub(crate) fn resolve_query_filter(extensions: &Extensions) -> HashSet<String> {
    let Some(parts) = extensions.get::<http::request::Parts>() else {
        return HashSet::new();
    };
    let Some(query) = parts.uri.query() else {
        return HashSet::new();
    };
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("filter=") {
            let decoded = urlencoding::decode(value).unwrap_or_else(|_| value.into());
            return decoded
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    HashSet::new()
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod tests;
