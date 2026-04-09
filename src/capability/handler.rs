use std::sync::Arc;
use std::time::{Instant, SystemTime};

use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::ErrorData as McpError;
use serde_json::Value;

use crate::audit::{ToolCallLogger, ToolCallOutcome, ToolCallRecord, ToolCallSource};
use crate::auth::TokenStore;
use crate::session::{resolve_session_id, SessionStore};

use super::filter::{resolve_query_filter, resolve_token, CapabilityFilter};
use super::registry::CapabilityRegistry;
use super::validator::{AccessDecision, AccessValidator};

/// Infrastructure concerns shared across transport modes.
///
/// Groups the cross-cutting dependencies that `DynamicHandler` needs beyond
/// the inner `ServerHandler` and the `CapabilityRegistry`.
pub(crate) struct HandlerContext<T: Send + Sync + Default + Clone + 'static> {
    pub filter: Option<Arc<dyn CapabilityFilter>>,
    pub access_validator: Option<Arc<dyn AccessValidator>>,
    pub token_store: TokenStore,
    pub session_store: SessionStore<T>,
    pub tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
}

/// Merge `registry` items into `inner`, removing inner items that collide
/// (registry wins on name/key collision).
fn merge_registry_items<T>(inner: &mut Vec<T>, registry: Vec<T>, key_eq: fn(&T, &T) -> bool) {
    for ri in &registry {
        inner.retain(|item| !key_eq(item, ri));
    }
    inner.extend(registry);
}

/// Strip schemars 1.x meta-fields (`$schema`, `title`) from a JSON schema object.
fn strip_meta_fields(schema: &mut serde_json::Map<String, Value>) {
    schema.remove("$schema");
    schema.remove("title");
}

/// Recursively resolve `$ref: "#/$defs/..."` pointers by inlining the
/// referenced definition.
///
/// When the `$ref` holder has sibling keys, they are combined with the
/// referenced definition per JSON Schema semantics:
/// - `properties` is deep-merged (sibling keys win on collision).
/// - `required` is unioned.
/// - Other keys (e.g. `description`, `default`) override keys from the def.
///
/// This matters for `#[serde(tag = "...")]` tagged enums, where schemars emits
/// a variant shaped like
/// `{ "type": "object", "properties": {"action": {"const": "add"}}, "$ref": "#/$defs/Variant", "required": ["action"] }`.
/// A naive override would wipe out `Variant.properties` and `Variant.required`,
/// losing all the variant's real fields.
fn resolve_refs(value: &mut Value, defs: &serde_json::Map<String, Value>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(ref_str)) = map.get("$ref") {
                if let Some(name) = ref_str.strip_prefix("#/$defs/") {
                    if let Some(def) = defs.get(name) {
                        let mut inlined = def.clone();
                        if let Value::Object(ref mut inlined_map) = inlined {
                            for (k, v) in map.iter() {
                                if k == "$ref" {
                                    continue;
                                }
                                match (k.as_str(), inlined_map.get_mut(k), v) {
                                    // Deep-merge properties (sibling wins on key collision).
                                    (
                                        "properties",
                                        Some(Value::Object(def_props)),
                                        Value::Object(sib_props),
                                    ) => {
                                        for (pk, pv) in sib_props {
                                            def_props.insert(pk.clone(), pv.clone());
                                        }
                                    }
                                    // Union required lists.
                                    (
                                        "required",
                                        Some(Value::Array(def_req)),
                                        Value::Array(sib_req),
                                    ) => {
                                        for item in sib_req {
                                            if !def_req.contains(item) {
                                                def_req.push(item.clone());
                                            }
                                        }
                                    }
                                    // Everything else: sibling overrides def.
                                    _ => {
                                        inlined_map.insert(k.clone(), v.clone());
                                    }
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

/// Flatten a top-level `oneOf` / `anyOf` / `allOf` into a single object schema.
///
/// Anthropic's API rejects these combinators at the **root** of `input_schema`
/// (nested uses are fine). schemars 1.x emits a root-level `oneOf` for
/// `#[serde(tag = "...")]` tagged enums, where each variant is an object whose
/// `properties` include the discriminator with a `const` value.
///
/// We detect that pattern, merge every variant's properties into a single flat
/// object, and synthesize a `string` `enum` for the discriminator. The merged
/// schema advertises only the discriminator as `required`, since per-variant
/// constraints conflict when flattened. Runtime `serde` deserialization still
/// enforces the full per-variant contract, so no actual validation is lost —
/// only the LLM loses a visibility aid.
///
/// For combinators without a discriminator, we fall back to a plain property
/// union with no `required` fields.
fn flatten_top_level_combinator(schema: &mut serde_json::Map<String, Value>) {
    let combinator_key = ["oneOf", "anyOf", "allOf"]
        .iter()
        .copied()
        .find(|k| schema.contains_key(*k));
    let Some(combinator_key) = combinator_key else {
        return;
    };

    let Some(Value::Array(variants)) = schema.remove(combinator_key) else {
        return;
    };

    let mut merged_props = serde_json::Map::new();
    let mut tag_key: Option<String> = None;
    let mut tag_values: Vec<Value> = Vec::new();

    for variant in &variants {
        let Some(v_obj) = variant.as_object() else {
            continue;
        };
        let Some(Value::Object(v_props)) = v_obj.get("properties") else {
            continue;
        };

        for (prop_name, prop_schema) in v_props {
            // A property with a `const` value is the tagged-enum discriminator.
            if let Some(const_val) = prop_schema.get("const") {
                if tag_key.is_none() {
                    tag_key = Some(prop_name.clone());
                }
                if tag_key.as_deref() == Some(prop_name.as_str())
                    && !tag_values.contains(const_val)
                {
                    tag_values.push(const_val.clone());
                }
            } else {
                merged_props
                    .entry(prop_name.clone())
                    .or_insert_with(|| prop_schema.clone());
            }
        }
    }

    let mut required: Vec<Value> = Vec::new();
    if let Some(ref tk) = tag_key {
        merged_props.insert(
            tk.clone(),
            serde_json::json!({
                "type": "string",
                "enum": tag_values,
            }),
        );
        required.push(Value::String(tk.clone()));
    }

    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert("properties".to_string(), Value::Object(merged_props));
    if required.is_empty() {
        schema.remove("required");
    } else {
        schema.insert("required".to_string(), Value::Array(required));
    }
}

/// Sanitize tool schemas for MCP client compatibility.
///
/// 1. Strips `$schema` and `title` keys that schemars 1.x injects — many MCP
///    clients (including Claude) don't expect meta-schema references in
///    `inputSchema` / `outputSchema` and may reject the tool or fail during
///    execution.
/// 2. Inlines `$defs` by resolving `$ref` pointers recursively.
/// 3. Flattens any top-level `oneOf` / `anyOf` / `allOf` into a single object
///    schema (the Anthropic API rejects these combinators at the root of
///    `input_schema`).
/// 4. Ensures every input schema contains `"type": "object"` — some parameter
///    types (e.g. `serde_json::Value`) produce schemas without a `"type"` key,
///    which causes clients to silently reject the tool.
fn sanitize_tool_schemas(tools: &mut [Tool]) {
    for tool in tools.iter_mut() {
        // ── input_schema ───────────────────────────────────────────
        let schema = Arc::make_mut(&mut tool.input_schema);
        strip_meta_fields(schema);
        inline_defs(schema);
        flatten_top_level_combinator(schema);

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
            flatten_top_level_combinator(os);
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
/// - On `call_tool`, when a [`ToolCallLogger`] is configured, every invocation
///   is instrumented with timing, session, and outcome data, then logged
///   asynchronously (fire-and-forget via `tokio::spawn`).
/// - All other methods are delegated directly to the inner handler.
///
/// Additionally, `TokenStore` and `SessionStore<T>` are injected into
/// `context.extensions` before every call, so handlers can access them
/// via [`RequestContextExt`](crate::session::RequestContextExt).
pub(crate) struct DynamicHandler<S, T: Send + Sync + Default + Clone + 'static> {
    inner: S,
    registry: CapabilityRegistry,
    context: HandlerContext<T>,
}

impl<S, T: Send + Sync + Default + Clone + 'static> DynamicHandler<S, T> {
    pub fn new(inner: S, registry: CapabilityRegistry, context: HandlerContext<T>) -> Self {
        Self {
            inner,
            registry,
            context,
        }
    }

    /// Insert `TokenStore` and `SessionStore<T>` into the extensions so
    /// handlers can retrieve them via `RequestContextExt`.
    fn enrich_extensions(&self, extensions: &mut Extensions) {
        extensions.insert(self.context.token_store.clone());
        extensions.insert(self.context.session_store.clone());
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
            let token = resolve_token(&context.extensions, &self.context.token_store).await;
            let query_filter = resolve_query_filter(&context.extensions);
            let mut inner_result = self.inner.list_tools(request, context).await?;

            // Merge registry tools (registry wins on name collision)
            merge_registry_items(
                &mut inner_result.tools,
                self.registry.tools().await,
                |a, b| a.name.as_ref() == b.name.as_ref(),
            );

            // Patch schemas missing "type": "object" (e.g. Parameters<serde_json::Value>)
            sanitize_tool_schemas(&mut inner_result.tools);

            // Apply trait-based filter
            if let Some(ref filter) = self.context.filter {
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
            let token = resolve_token(&context.extensions, &self.context.token_store).await;
            let mut inner_result = self.inner.list_prompts(request, context).await?;

            merge_registry_items(
                &mut inner_result.prompts,
                self.registry.prompts().await,
                |a, b| a.name == b.name,
            );

            if let Some(ref filter) = self.context.filter {
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
            let token = resolve_token(&context.extensions, &self.context.token_store).await;
            let mut inner_result = self.inner.list_resources(request, context).await?;

            merge_registry_items(
                &mut inner_result.resources,
                self.registry.resources().await,
                |a, b| a.raw.uri == b.raw.uri,
            );

            if let Some(ref filter) = self.context.filter {
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

            // Access validation (authorization check before execution)
            if let Some(ref validator) = self.context.access_validator {
                let token = resolve_token(&context.extensions, &self.context.token_store).await;
                let session_id = resolve_session_id(&context.extensions);
                let decision = validator
                    .validate_tool_call(
                        request.name.as_ref(),
                        request.arguments.as_ref(),
                        token.as_ref(),
                        session_id,
                    )
                    .await;
                if let AccessDecision::Deny(reason) = decision {
                    return Err(McpError::invalid_request(
                        format!("Access denied for tool '{}': {}", request.name, reason),
                        None,
                    ));
                }
            }

            // Reject tools excluded by URL query filter
            let query_filter = resolve_query_filter(&context.extensions);
            if query_filter.contains(request.name.as_ref()) {
                return Err(McpError::invalid_request(
                    format!("Tool '{}' is not available", request.name),
                    None,
                ));
            }

            // When a logger is configured, capture state before dispatch
            let has_logger = self.context.tool_call_logger.is_some();
            let tool_name = if has_logger { Some(request.name.to_string()) } else { None };
            let session_id = if has_logger { Some(resolve_session_id(&context.extensions).to_string()) } else { None };
            let start = if has_logger { Some((SystemTime::now(), Instant::now())) } else { None };

            // Dispatch: try registry first, fall back to inner.
            // Clone arguments once for registry probe; reuse for audit if needed.
            let reg_args = request.arguments.clone();
            let (result, source) = if let Some(reg_result) = self
                .registry
                .call_tool(&request.name, reg_args.clone())
                .await
            {
                (reg_result, ToolCallSource::Registry)
            } else {
                (
                    self.inner.call_tool(request, context).await,
                    ToolCallSource::Inner,
                )
            };

            if let (Some(logger), Some(tool_name), Some(session_id), Some((start_wall, start_instant))) =
                (self.context.tool_call_logger.clone(), tool_name, session_id, start)
            {
                let duration = start_instant.elapsed();
                let outcome = match &result {
                    Ok(call_result) => ToolCallOutcome::Success {
                        is_error: call_result.is_error.unwrap_or(false),
                        content_summary: summarize_content(&call_result.content),
                    },
                    Err(mcp_err) => ToolCallOutcome::McpError {
                        code: mcp_err.code.0,
                        message: mcp_err.message.to_string(),
                    },
                };

                let record = ToolCallRecord {
                    tool_name,
                    arguments: reg_args,
                    session_id,
                    timestamp: start_wall,
                    duration,
                    source,
                    outcome,
                };

                // Observe the JoinHandle so logger panics are reported
                // instead of silently swallowed.
                tokio::spawn(async move {
                    if let Err(e) = tokio::spawn(async move {
                        logger.log(record).await;
                    }).await {
                        tracing::error!("audit logger panicked: {e}");
                    }
                });
            }

            result
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

            if let Some(ref validator) = self.context.access_validator {
                let token = resolve_token(&context.extensions, &self.context.token_store).await;
                let session_id = resolve_session_id(&context.extensions);
                let decision = validator
                    .validate_prompt_access(
                        &request.name,
                        request.arguments.as_ref(),
                        token.as_ref(),
                        session_id,
                    )
                    .await;
                if let AccessDecision::Deny(reason) = decision {
                    return Err(McpError::invalid_request(
                        format!("Access denied for prompt '{}': {}", request.name, reason),
                        None,
                    ));
                }
            }

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

            if let Some(ref validator) = self.context.access_validator {
                let token = resolve_token(&context.extensions, &self.context.token_store).await;
                let session_id = resolve_session_id(&context.extensions);
                let decision = validator
                    .validate_resource_access(
                        &request.uri,
                        token.as_ref(),
                        session_id,
                    )
                    .await;
                if let AccessDecision::Deny(reason) = decision {
                    return Err(McpError::invalid_request(
                        format!("Access denied for resource '{}': {}", request.uri, reason),
                        None,
                    ));
                }
            }

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

/// Produce a short summary of tool call content for audit logging.
///
/// Text is truncated to 256 characters. Binary content is replaced with type
/// tags (`<image>`, `<audio>`, `<resource>`, `<resource_link>`).
fn summarize_content(content: &[Content]) -> Option<String> {
    if content.is_empty() {
        return None;
    }

    let mut buf = String::new();
    for (i, item) in content.iter().enumerate() {
        if i > 0 {
            buf.push_str("; ");
        }
        match &item.raw {
            RawContent::Text(tc) => {
                if tc.text.len() > 256 {
                    let end = tc.text.floor_char_boundary(256);
                    buf.push_str(&tc.text[..end]);
                    buf.push_str("...");
                } else {
                    buf.push_str(&tc.text);
                }
            }
            RawContent::Image(_) => buf.push_str("<image>"),
            RawContent::Resource(_) => buf.push_str("<resource>"),
            RawContent::Audio(_) => buf.push_str("<audio>"),
            RawContent::ResourceLink(_) => buf.push_str("<resource_link>"),
        }
    }
    Some(buf)
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
    fn sanitize_flattens_top_level_oneof_tagged_enum() {
        // Mirrors what schemars 1.x emits for `#[serde(tag = "action")]` enums.
        let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "ManageNotesInput",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "const": "add" }
                    },
                    "$ref": "#/$defs/AddNoteInput",
                    "required": ["action"]
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "const": "delete" }
                    },
                    "$ref": "#/$defs/DeleteNoteInput",
                    "required": ["action"]
                }
            ],
            "$defs": {
                "AddNoteInput": {
                    "type": "object",
                    "properties": {
                        "task_id": { "type": "string" },
                        "body": { "type": "string" }
                    },
                    "required": ["task_id", "body"]
                },
                "DeleteNoteInput": {
                    "type": "object",
                    "properties": {
                        "task_id": { "type": "string" },
                        "note_id": { "type": "string" }
                    },
                    "required": ["task_id", "note_id"]
                }
            }
        }))
        .unwrap();

        let mut tools = vec![make_tool("manage_notes", schema)];
        sanitize_tool_schemas(&mut tools);
        let patched = tools[0].input_schema.as_ref();

        // Top-level oneOf is gone, replaced by a plain object schema.
        assert_eq!(patched.get("type").unwrap(), "object");
        assert!(!patched.contains_key("oneOf"));
        assert!(!patched.contains_key("anyOf"));
        assert!(!patched.contains_key("allOf"));
        assert!(!patched.contains_key("$defs"));
        assert!(!patched.contains_key("title"));
        assert!(!patched.contains_key("$schema"));

        // Discriminator becomes a string enum.
        let props = patched["properties"].as_object().unwrap();
        let action = props["action"].as_object().unwrap();
        assert_eq!(action["type"], "string");
        let action_enum: Vec<&str> = action["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(action_enum, vec!["add", "delete"]);

        // All variant fields are merged into the flat properties.
        assert_eq!(props["task_id"]["type"], "string");
        assert_eq!(props["body"]["type"], "string");
        assert_eq!(props["note_id"]["type"], "string");

        // Only the discriminator is required in the merged schema.
        let required: Vec<&str> = patched["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(required, vec!["action"]);
    }

    #[test]
    fn resolve_refs_deep_merges_properties_and_required() {
        // When a `$ref` holder has sibling `properties` / `required`, they must
        // combine with the referenced def, not overwrite it.
        let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
            "type": "object",
            "properties": {
                "variant": {
                    "type": "object",
                    "properties": { "tag": { "const": "x" } },
                    "$ref": "#/$defs/Inner",
                    "required": ["tag"]
                }
            },
            "$defs": {
                "Inner": {
                    "type": "object",
                    "properties": {
                        "a": { "type": "string" },
                        "b": { "type": "integer" }
                    },
                    "required": ["a"]
                }
            }
        }))
        .unwrap();

        let mut tools = vec![make_tool("t", schema)];
        sanitize_tool_schemas(&mut tools);
        let variant = tools[0].input_schema.as_ref()["properties"]["variant"]
            .as_object()
            .unwrap();

        let props = variant["properties"].as_object().unwrap();
        assert!(props.contains_key("tag"), "sibling tag preserved");
        assert!(props.contains_key("a"), "def property a preserved");
        assert!(props.contains_key("b"), "def property b preserved");

        let required: Vec<&str> = variant["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"a"));
        assert!(required.contains(&"tag"));
    }

    #[test]
    fn sanitize_flattens_top_level_oneof_without_discriminator() {
        // Fallback: no `const` property means no discriminator. Properties are
        // still merged into a single object and no `required` field survives.
        let schema: serde_json::Map<String, Value> = serde_json::from_value(serde_json::json!({
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "a": { "type": "string" }
                    },
                    "required": ["a"]
                },
                {
                    "type": "object",
                    "properties": {
                        "b": { "type": "integer" }
                    },
                    "required": ["b"]
                }
            ]
        }))
        .unwrap();

        let mut tools = vec![make_tool("t", schema)];
        sanitize_tool_schemas(&mut tools);
        let patched = tools[0].input_schema.as_ref();

        assert_eq!(patched.get("type").unwrap(), "object");
        assert!(!patched.contains_key("oneOf"));
        assert!(!patched.contains_key("required"));
        let props = patched["properties"].as_object().unwrap();
        assert!(props.contains_key("a"));
        assert!(props.contains_key("b"));
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

    #[test]
    fn summarize_content_empty() {
        assert_eq!(summarize_content(&[]), None);
    }

    #[test]
    fn summarize_content_text_truncation() {
        let long_text = "x".repeat(300);
        let content = vec![Content::text(long_text)];
        let summary = summarize_content(&content).unwrap();
        assert!(summary.len() < 270); // 256 + "..."
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn summarize_content_short_text() {
        let content = vec![Content::text("hello")];
        let summary = summarize_content(&content).unwrap();
        assert_eq!(summary, "hello");
    }

    #[test]
    fn summarize_content_mixed() {
        let content = vec![
            Content::text("hello"),
            Content::image("base64data", "image/png"),
        ];
        let summary = summarize_content(&content).unwrap();
        assert_eq!(summary, "hello; <image>");
    }
}
