use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::ErrorData as McpError;
use serde_json::Value;

use crate::auth::TokenStore;
use crate::session::SessionStore;

use super::filter::{resolve_query_filter, resolve_token, CapabilityFilter};
use super::registry::CapabilityRegistry;

/// Strip schemars 1.x meta-fields (`$schema`, `title`) from a JSON schema object.
fn strip_meta_fields(schema: &mut serde_json::Map<String, Value>) {
    schema.remove("$schema");
    schema.remove("title");
}

/// Recursively resolve `$ref: "#/$defs/..."` pointers by inlining the
/// referenced definition.  Sibling keys on the `$ref` object (e.g.
/// `description`) are preserved and override keys from the definition.
fn resolve_refs(value: &mut Value, defs: &serde_json::Map<String, Value>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(ref_str)) = map.get("$ref") {
                if let Some(name) = ref_str.strip_prefix("#/$defs/") {
                    if let Some(def) = defs.get(name) {
                        let mut inlined = def.clone();
                        if let Value::Object(ref mut inlined_map) = inlined {
                            // Sibling keys (description, default, …) override the def
                            for (k, v) in map.iter() {
                                if k != "$ref" {
                                    inlined_map.insert(k.clone(), v.clone());
                                }
                            }
                        }
                        *value = inlined;
                        // The inlined definition may itself contain $refs
                        resolve_refs(value, defs);
                        return;
                    }
                }
            }
            for v in map.values_mut() {
                resolve_refs(v, defs);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                resolve_refs(v, defs);
            }
        }
        _ => {}
    }
}

/// Extract `$defs` from a schema and inline all `$ref` pointers that
/// reference them, then drop `$defs`.  This produces a self-contained
/// schema without indirection — friendlier for MCP clients that do not
/// fully support JSON Schema references.
fn inline_defs(schema: &mut serde_json::Map<String, Value>) {
    let defs = match schema.remove("$defs") {
        Some(Value::Object(d)) => d,
        other => {
            if let Some(v) = other {
                schema.insert("$defs".to_string(), v);
            }
            return;
        }
    };

    for value in schema.values_mut() {
        resolve_refs(value, &defs);
    }
}

/// Sanitize tool schemas for MCP client compatibility.
///
/// 1. Strips `$schema` and `title` keys that schemars 1.x injects — many MCP
///    clients (including Claude) don't expect meta-schema references in
///    `inputSchema` / `outputSchema` and may reject the tool or fail during
///    execution.
/// 2. Ensures every input schema contains `"type": "object"` — some parameter
///    types (e.g. `serde_json::Value`) produce schemas without a `"type"` key,
///    which causes clients to silently reject the tool.
fn sanitize_tool_schemas(tools: &mut [Tool]) {
    for tool in tools.iter_mut() {
        // ── input_schema ───────────────────────────────────────────
        let schema = Arc::make_mut(&mut tool.input_schema);
        strip_meta_fields(schema);
        inline_defs(schema);

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

        // ── output_schema ──────────────────────────────────────────
        if let Some(ref mut output_schema) = tool.output_schema {
            let os = Arc::make_mut(output_schema);
            strip_meta_fields(os);
            inline_defs(os);
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
            let query_filter = resolve_query_filter(&context.extensions);
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

            // Apply trait-based filter
            if let Some(ref filter) = self.filter {
                inner_result.tools = filter.filter_tools(inner_result.tools, token.as_ref());
            }

            // Apply URL query parameter filter (?filter=tool1,tool2 excludes named tools)
            if !query_filter.is_empty() {
                inner_result
                    .tools
                    .retain(|t| !query_filter.contains(t.name.as_ref()));
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

            // Reject tools excluded by URL query filter
            let query_filter = resolve_query_filter(&context.extensions);
            if query_filter.contains(request.name.as_ref()) {
                return Err(McpError::invalid_request(
                    format!("Tool '{}' is not available", request.name),
                    None,
                ));
            }

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
    fn sanitize_strips_schema_and_title_from_valid_schema() {
        let mut schema = serde_json::Map::new();
        schema.insert("type".to_string(), Value::String("object".to_string()));
        schema.insert(
            "$schema".to_string(),
            Value::String("https://json-schema.org/draft/2020-12/schema".to_string()),
        );
        schema.insert("title".to_string(), Value::String("MyParams".to_string()));
        schema.insert(
            "properties".to_string(),
            Value::Object(serde_json::Map::new()),
        );

        let mut tools = vec![make_tool("with_meta", schema)];
        sanitize_tool_schemas(&mut tools);

        let patched = tools[0].input_schema.as_ref();
        assert_eq!(patched.get("type").unwrap(), "object");
        assert!(!patched.contains_key("$schema"));
        assert!(!patched.contains_key("title"));
    }

    #[test]
    fn sanitize_inlines_ref_enums() {
        let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
            "$defs": {
                "MyAction": { "enum": ["ask", "brief"], "type": "string" }
            },
            "type": "object",
            "properties": {
                "action": {
                    "$ref": "#/$defs/MyAction",
                    "description": "The action"
                }
            },
            "required": ["action"]
        }))
        .unwrap();

        let mut tools = vec![make_tool("t", schema)];
        sanitize_tool_schemas(&mut tools);

        let patched = tools[0].input_schema.as_ref();
        assert!(!patched.contains_key("$defs"), "$defs should be removed");

        let action = patched["properties"]["action"].as_object().unwrap();
        assert_eq!(
            action.get("enum").unwrap(),
            &serde_json::json!(["ask", "brief"]),
            "enum values should be inlined"
        );
        assert_eq!(
            action.get("type").unwrap(),
            "string",
            "type from the definition should be present"
        );
        assert_eq!(
            action.get("description").unwrap(),
            "The action",
            "sibling description should be preserved"
        );
        assert!(!action.contains_key("$ref"), "$ref should be removed");
    }

    #[test]
    fn sanitize_inlines_anyof_with_ref() {
        let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
            "$defs": {
                "DetailLevel": { "enum": ["brief", "detailed"], "type": "string" }
            },
            "type": "object",
            "properties": {
                "detail": {
                    "anyOf": [
                        { "$ref": "#/$defs/DetailLevel" },
                        { "type": "null" }
                    ],
                    "description": "Level of detail"
                }
            }
        }))
        .unwrap();

        let mut tools = vec![make_tool("t", schema)];
        sanitize_tool_schemas(&mut tools);

        let patched = tools[0].input_schema.as_ref();
        assert!(!patched.contains_key("$defs"));

        let variants = patched["properties"]["detail"]["anyOf"].as_array().unwrap();
        assert_eq!(variants.len(), 2);
        assert_eq!(
            variants[0],
            serde_json::json!({"enum": ["brief", "detailed"], "type": "string"}),
            "$ref inside anyOf should be inlined"
        );
        assert_eq!(variants[1], serde_json::json!({"type": "null"}));
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
        // $schema and title are stripped for MCP client compatibility
        assert!(!patched.contains_key("$schema"));
        assert!(!patched.contains_key("title"));
    }
}
