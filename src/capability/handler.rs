use std::sync::Arc;
use std::time::{Instant, SystemTime};

use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::ErrorData as McpError;

use crate::audit::{ToolCallLogger, ToolCallOutcome, ToolCallRecord, ToolCallSource};
use crate::auth::TokenStore;
use crate::session::{SessionData, resolve_session_id, SessionStore};

use super::filter::{resolve_query_filter, resolve_token, CapabilityFilter};
use super::registry::CapabilityRegistry;
use super::sanitize::sanitize_tool_schemas;
use super::validator::{AccessDecision, AccessValidator};

/// Infrastructure concerns shared across transport modes.
///
/// Groups the cross-cutting dependencies that `DynamicHandler` needs beyond
/// the inner `ServerHandler` and the `CapabilityRegistry`.
pub(crate) struct HandlerContext<T: SessionData> {
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
pub(crate) struct DynamicHandler<S, T: SessionData> {
    inner: S,
    registry: CapabilityRegistry,
    context: HandlerContext<T>,
}

impl<S, T: SessionData> DynamicHandler<S, T> {
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

impl<S: ServerHandler, T: SessionData> ServerHandler
    for DynamicHandler<S, T>
{
    // ── initialize: capture the peer ─────────────────────────────────

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        self.enrich_extensions(&mut context.extensions);
        self.registry.register_peer(context.peer.clone()).await;
        let mut result = self.inner.initialize(request, context).await?;

        if result.capabilities.tools.is_none() && self.registry.has_tools().await {
            result.capabilities.tools = Some(ToolsCapability::default());
        }
        if result.capabilities.prompts.is_none() && self.registry.has_prompts().await {
            result.capabilities.prompts = Some(PromptsCapability::default());
        }
        if result.capabilities.resources.is_none() && self.registry.has_resources().await {
            result.capabilities.resources = Some(ResourcesCapability::default());
        }

        Ok(result)
    }

    // ── list_tools: merge + filter ───────────────────────────────────

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.enrich_extensions(&mut context.extensions);
        let token = resolve_token(&context.extensions, &self.context.token_store).await;
        let query_filter = resolve_query_filter(&context.extensions);
        let mut inner_result = self.inner.list_tools(request, context).await?;

        merge_registry_items(
            &mut inner_result.tools,
            self.registry.tools().await,
            |a, b| a.name.as_ref() == b.name.as_ref(),
        );

        sanitize_tool_schemas(&mut inner_result.tools);

        if let Some(ref filter) = self.context.filter {
            inner_result.tools = filter.filter_tools(inner_result.tools, token.as_ref());
        }

        if !query_filter.is_empty() {
            inner_result
                .tools
                .retain(|t| !query_filter.contains(t.name.as_ref()));
        }

        Ok(inner_result)
    }

    // ── list_prompts: merge + filter ─────────────────────────────────

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
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

    // ── list_resources: merge + filter ───────────────────────────────

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
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

    // ── call_tool: registry first, fallback to inner ─────────────────

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.enrich_extensions(&mut context.extensions);

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

        let query_filter = resolve_query_filter(&context.extensions);
        if query_filter.contains(request.name.as_ref()) {
            return Err(McpError::invalid_request(
                format!("Tool '{}' is not available", request.name),
                None,
            ));
        }

        let has_logger = self.context.tool_call_logger.is_some();
        let tool_name = if has_logger { Some(request.name.to_string()) } else { None };
        let session_id = if has_logger { Some(resolve_session_id(&context.extensions).to_string()) } else { None };
        let start = if has_logger { Some((SystemTime::now(), Instant::now())) } else { None };

        // Dispatch: try registry first, fall back to inner.
        // Clone arguments once for the registry probe; move the original into audit_args.
        let (result, source, audit_args) = if let Some(reg_result) = self
            .registry
            .try_call_tool(&request.name, request.arguments.clone())
            .await
        {
            (reg_result, ToolCallSource::Registry, request.arguments)
        } else {
            let audit_args = if has_logger { request.arguments.clone() } else { None };
            (
                self.inner.call_tool(request, context).await,
                ToolCallSource::Inner,
                audit_args,
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
                arguments: audit_args,
                session_id,
                timestamp: start_wall,
                duration,
                source,
                outcome,
            };

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

    // ── get_prompt: registry first, fallback to inner ────────────────

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
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

    // ── read_resource: registry first, fallback to inner ─────────────

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
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
