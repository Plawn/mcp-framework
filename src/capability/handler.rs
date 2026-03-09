use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::ErrorData as McpError;
use serde_json::Value;

use crate::auth::TokenStore;
use crate::session::SessionStore;

use super::filter::{resolve_token, CapabilityFilter};
use super::registry::CapabilityRegistry;

/// Ensure every tool's `input_schema` contains `"type": "object"`.
///
/// Some parameter types (e.g. `serde_json::Value`) produce schemas without a
/// `"type"` key, which causes clients like Claude Code to silently reject the
/// tool.  This function patches those schemas at runtime and emits a warning
/// so authors can fix the underlying type.
fn sanitize_tool_schemas(tools: &mut [Tool]) {
    for tool in tools.iter_mut() {
        let schema = Arc::make_mut(&mut tool.input_schema);
        if !schema.contains_key("type") {
            tracing::warn!(
                tool = %tool.name,
                "Tool input_schema is missing \"type\": \"object\" — patching at runtime. \
                 Consider using mcp_framework::EmptyParams instead of serde_json::Value \
                 for tools with no parameters."
            );
            schema.insert("type".to_string(), Value::String("object".to_string()));
            if !schema.contains_key("properties") {
                schema.insert("properties".to_string(), Value::Object(Default::default()));
            }
        }
    }
}

/// A `ServerHandler` wrapper that merges dynamic capabilities from a
/// [`CapabilityRegistry`] with the static capabilities of an inner handler.
///
/// - On `initialize`, the peer is registered for future notifications.
/// - On `list_*`, results from the inner handler and the registry are merged
///   (registry wins on name collisions) then passed through the optional
///   [`CapabilityFilter`].
/// - On `call_tool` / `get_prompt` / `read_resource`, the registry is tried
///   first; if the name/uri is not found there, the call falls through to
///   the inner handler.
/// - All other methods are delegated directly to the inner handler.
///
/// Additionally, `TokenStore` and `SessionStore<T>` are injected into
/// `context.extensions` before every call, so handlers can access them
/// via [`RequestContextExt`](crate::session::RequestContextExt).
pub(crate) struct DynamicHandler<S, T: Send + Sync + Default + Clone + 'static> {
    inner: S,
    registry: CapabilityRegistry,
    filter: Option<Arc<dyn CapabilityFilter>>,
    token_store: TokenStore,
    session_store: SessionStore<T>,
}

impl<S, T: Send + Sync + Default + Clone + 'static> DynamicHandler<S, T> {
    pub fn new(
        inner: S,
        registry: CapabilityRegistry,
        filter: Option<Arc<dyn CapabilityFilter>>,
        token_store: TokenStore,
        session_store: SessionStore<T>,
    ) -> Self {
        Self {
            inner,
            registry,
            filter,
            token_store,
            session_store,
        }
    }

    /// Insert `TokenStore` and `SessionStore<T>` into the extensions so
    /// handlers can retrieve them via `RequestContextExt`.
    fn enrich_extensions(&self, extensions: &mut Extensions) {
        extensions.insert(self.token_store.clone());
        extensions.insert(self.session_store.clone());
    }
}

impl<S: ServerHandler, T: Send + Sync + Default + Clone + 'static> ServerHandler
    for DynamicHandler<S, T>
{
    // ── initialize: capture the peer ─────────────────────────────────

    fn initialize(
        &self,
        request: InitializeRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<InitializeResult, McpError>> + Send + '_ {
        async move {
            self.enrich_extensions(&mut context.extensions);
            self.registry.register_peer(context.peer.clone()).await;
            self.inner.initialize(request, context).await
        }
    }

    // ── list_tools: merge + filter ───────────────────────────────────

    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async move {
            self.enrich_extensions(&mut context.extensions);
            let token = resolve_token(&context.extensions, &self.token_store).await;
            let mut inner_result = self.inner.list_tools(request, context).await?;

            // Merge registry tools, registry wins on name collision
            let registry_tools = self.registry.tools().await;
            for rt in &registry_tools {
                let name = rt.name.as_ref();
                inner_result.tools.retain(|t| t.name.as_ref() != name);
            }
            inner_result.tools.extend(registry_tools);

            // Patch schemas missing "type": "object" (e.g. Parameters<serde_json::Value>)
            sanitize_tool_schemas(&mut inner_result.tools);

            // Apply filter
            if let Some(ref filter) = self.filter {
                inner_result.tools = filter.filter_tools(inner_result.tools, token.as_ref());
            }

            Ok(inner_result)
        }
    }

    // ── list_prompts: merge + filter ─────────────────────────────────

    fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, McpError>> + Send + '_ {
        async move {
            self.enrich_extensions(&mut context.extensions);
            let token = resolve_token(&context.extensions, &self.token_store).await;
            let mut inner_result = self.inner.list_prompts(request, context).await?;

            let registry_prompts = self.registry.prompts().await;
            for rp in &registry_prompts {
                inner_result.prompts.retain(|p| p.name != rp.name);
            }
            inner_result.prompts.extend(registry_prompts);

            if let Some(ref filter) = self.filter {
                inner_result.prompts = filter.filter_prompts(inner_result.prompts, token.as_ref());
            }

            Ok(inner_result)
        }
    }

    // ── list_resources: merge + filter ───────────────────────────────

    fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        async move {
            self.enrich_extensions(&mut context.extensions);
            let token = resolve_token(&context.extensions, &self.token_store).await;
            let mut inner_result = self.inner.list_resources(request, context).await?;

            let registry_resources = self.registry.resources().await;
            for rr in &registry_resources {
                inner_result
                    .resources
                    .retain(|r| r.raw.uri != rr.raw.uri);
            }
            inner_result.resources.extend(registry_resources);

            if let Some(ref filter) = self.filter {
                inner_result.resources =
                    filter.filter_resources(inner_result.resources, token.as_ref());
            }

            Ok(inner_result)
        }
    }

    // ── call_tool: registry first, fallback to inner ─────────────────

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
            self.enrich_extensions(&mut context.extensions);
            if let Some(result) = self
                .registry
                .call_tool(&request.name, request.arguments.clone())
                .await
            {
                return result;
            }
            self.inner.call_tool(request, context).await
        }
    }

    // ── get_prompt: registry first, fallback to inner ────────────────

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, McpError>> + Send + '_ {
        async move {
            self.enrich_extensions(&mut context.extensions);
            if let Some(result) = self.registry.get_prompt(&request).await {
                return result;
            }
            self.inner.get_prompt(request, context).await
        }
    }

    // ── read_resource: registry first, fallback to inner ─────────────

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, McpError>> + Send + '_ {
        async move {
            self.enrich_extensions(&mut context.extensions);
            if let Some(result) = self.registry.read_resource(&request).await {
                return result;
            }
            self.inner.read_resource(request, context).await
        }
    }

    // ── get_tool: check registry first, then inner ─────────────────

    fn get_tool(&self, name: &str) -> Option<Tool> {
        // Registry tools take priority, then fall back to inner handler
        // Note: registry lookup is sync here because get_tool is sync
        self.inner.get_tool(name)
    }

    // ── Delegated methods ────────────────────────────────────────────

    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn ping(
        &self,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.ping(context)
    }

    fn complete(
        &self,
        request: CompleteRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CompleteResult, McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.complete(request, context)
    }

    fn set_level(
        &self,
        request: SetLevelRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.set_level(request, context)
    }

    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourceTemplatesResult, McpError>> + Send + '_
    {
        self.enrich_extensions(&mut context.extensions);
        self.inner.list_resource_templates(request, context)
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.subscribe(request, context)
    }

    fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.unsubscribe(request, context)
    }

    fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        mut context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.on_cancelled(notification, context)
    }

    fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        mut context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.on_progress(notification, context)
    }

    fn on_initialized(
        &self,
        mut context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.on_initialized(context)
    }

    fn on_roots_list_changed(
        &self,
        mut context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.on_roots_list_changed(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_tool(name: &'static str, schema: serde_json::Map<String, Value>) -> Tool {
        Tool::new(name, name, Arc::new(schema))
    }

    #[test]
    fn sanitize_patches_missing_type_object() {
        let mut tools = vec![make_tool("bad", serde_json::Map::new())];
        sanitize_tool_schemas(&mut tools);

        let schema = tools[0].input_schema.as_ref();
        assert_eq!(schema.get("type").unwrap(), "object");
        assert!(schema.contains_key("properties"));
    }

    #[test]
    fn sanitize_leaves_valid_schema_untouched() {
        let mut schema = serde_json::Map::new();
        schema.insert("type".to_string(), Value::String("object".to_string()));
        schema.insert(
            "properties".to_string(),
            Value::Object({
                let mut m = serde_json::Map::new();
                m.insert("name".to_string(), Value::Object(Default::default()));
                m
            }),
        );
        let mut tools = vec![make_tool("good", schema.clone())];
        sanitize_tool_schemas(&mut tools);

        assert_eq!(tools[0].input_schema.as_ref(), &schema);
    }

    #[test]
    fn sanitize_patches_serde_json_value_style_schema() {
        // This is what schemars generates for Parameters<serde_json::Value>
        let mut schema = serde_json::Map::new();
        schema.insert(
            "$schema".to_string(),
            Value::String("http://json-schema.org/draft-07/schema#".to_string()),
        );
        schema.insert("title".to_string(), Value::String("AnyValue".to_string()));

        let mut tools = vec![make_tool("any_value", schema)];
        sanitize_tool_schemas(&mut tools);

        let patched = tools[0].input_schema.as_ref();
        assert_eq!(patched.get("type").unwrap(), "object");
        assert!(patched.contains_key("properties"));
        // Original fields preserved
        assert!(patched.contains_key("$schema"));
        assert!(patched.contains_key("title"));
    }
}
