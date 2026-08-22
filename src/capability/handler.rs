use std::sync::Arc;
use std::time::{Instant, SystemTime};

use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RoleServer, SubscriptionContext};

use crate::audit::{ToolCallLogger, ToolCallOutcome, ToolCallRecord, ToolCallSource};
use crate::auth::TokenStore;
use crate::newtypes::{SessionId, ToolName};
use crate::session::{SessionData, SessionStore, resolve_session_id};

use super::filter::{CapabilityFilter, resolve_query_filter, resolve_token};
use super::registry::CapabilityRegistry;
use super::sanitize::sanitize_tool_schemas;
use super::validator::{AccessDecision, AccessValidator};
use crate::transport::protocol::cap_protocol_versions;

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
    /// Highest MCP revision this server advertises, or `None` for whatever the
    /// inner handler supports. See
    /// [`resolve_max_protocol_version`](crate::transport::resolve_max_protocol_version).
    pub max_protocol_version: Option<ProtocolVersion>,
    /// Set only by the loopback transport, which has no HTTP request to carry the caller's
    /// identity. Synthesizes the request parts a network client would have sent, so session
    /// resolution and token extraction keep working off a single mechanism.
    pub loopback_identity: Option<crate::transport::LoopbackIdentity>,
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
        if let Some(parts) = self
            .context
            .loopback_identity
            .as_ref()
            .and_then(|id| id.to_parts())
        {
            extensions.insert(parts);
        }
    }

    /// Advertise the capabilities backed by the registry when the inner
    /// handler doesn't declare them itself.
    ///
    /// Shared by `initialize` (2025-11-25 and earlier) and `discover`
    /// (2026-07-28, which has no initialize handshake).
    async fn augment_capabilities(&self, capabilities: &mut ServerCapabilities) {
        if capabilities.tools.is_none() && self.registry.has_tools().await {
            capabilities.tools = Some(ToolsCapability::default());
        }
        if capabilities.prompts.is_none() && self.registry.has_prompts().await {
            capabilities.prompts = Some(PromptsCapability::default());
        }
        if capabilities.resources.is_none() && self.registry.has_resources().await {
            capabilities.resources = Some(ResourcesCapability::default());
        }
    }
}

impl<S: ServerHandler, T: SessionData> ServerHandler for DynamicHandler<S, T> {
    // ── initialize: capture the peer ─────────────────────────────────

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        self.enrich_extensions(&mut context.extensions);
        self.registry.register_peer(context.peer.clone()).await;
        let mut result = self.inner.initialize(request, context).await?;
        self.augment_capabilities(&mut result.capabilities).await;
        Ok(result)
    }

    // ── discover: the 2026-07-28 replacement for initialize ──────────

    /// SEP-2567 removed the `initialize` handshake for protocol version
    /// 2026-07-28, so `discover` is the only place capabilities are
    /// advertised there. Delegate to the inner handler (so a custom
    /// `discover`/`get_info` still wins) and apply the same registry
    /// augmentation as `initialize`.
    async fn discover(
        &self,
        mut context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, McpError> {
        self.enrich_extensions(&mut context.extensions);
        let mut result = self.inner.discover(context).await?;
        self.augment_capabilities(&mut result.capabilities).await;
        // rmcp's default `discover` builds `supported_versions` from the *inner*
        // handler's `supported_protocol_versions()`, which never sees the
        // ceiling. Left alone, `server/discover` would advertise a revision the
        // very next request is refused for.
        result.supported_versions = self.supported_protocol_versions().into_owned();
        Ok(result)
    }

    /// The single point where the advertised revision set is decided.
    ///
    /// rmcp's trait default returns every [`ProtocolVersion::KNOWN_VERSIONS`],
    /// so a server that never opted into a revision still offers it — and a
    /// client that picks it gets a lifecycle the deployment has never been
    /// tested against. Capping here rather than in each transport keeps
    /// `server/discover`, `initialize` and the loopback on one answer.
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        cap_protocol_versions(
            self.inner.supported_protocol_versions(),
            self.context.max_protocol_version.as_ref(),
        )
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
        let inner_count = inner_result.tools.len();
        let registry_tools = self.registry.tools().await;
        let registry_count = registry_tools.len();

        merge_registry_items(&mut inner_result.tools, registry_tools, |a, b| {
            a.name.as_ref() == b.name.as_ref()
        });

        // The audit lives on the registry, so a dynamic tool already checked at
        // registration is not re-reported here on every poll.
        sanitize_tool_schemas(&mut inner_result.tools, self.registry.description_audit());
        let merged_count = inner_result.tools.len();

        if let Some(ref filter) = self.context.filter {
            inner_result.tools = filter.filter_tools(inner_result.tools, token.as_ref());
        }

        if !query_filter.is_empty() {
            inner_result
                .tools
                .retain(|t| !query_filter.contains(t.name.as_ref()));
        }

        tracing::info!(
            inner_count,
            registry_count,
            merged_count,
            returned_count = inner_result.tools.len(),
            capability_filter_enabled = self.context.filter.is_some(),
            query_filter_count = query_filter.len(),
            "MCP tools/list completed"
        );

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
            |a, b| a.uri == b.uri,
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
    ) -> Result<CallToolResponse, McpError> {
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
        let tool_name = if has_logger {
            Some(ToolName::new(request.name.as_ref()))
        } else {
            None
        };
        let session_id = if has_logger {
            Some(SessionId::new(resolve_session_id(&context.extensions)))
        } else {
            None
        };
        let start = if has_logger {
            Some((SystemTime::now(), Instant::now()))
        } else {
            None
        };

        // Dispatch: try registry first, fall back to inner.
        // Only construct ToolCallContext (which clones Meta) when the tool
        // is actually in the registry, avoiding the heap allocation on miss.
        let reg_result = if self.registry.contains_tool(&request.name).await {
            let tool_ctx = crate::capability::registry::ToolCallContext {
                peer: context.peer.clone(),
                meta: context.meta.clone(),
                // Resolved again rather than reusing the audit copy above: that one only exists
                // when a logger is configured, and a tool's behaviour must not depend on whether
                // the application happens to be auditing.
                session_id: resolve_session_id(&context.extensions).to_string(),
            };
            self.registry
                .try_call_tool(&request.name, request.arguments.clone(), Some(tool_ctx))
                .await
        } else {
            None
        };

        let (result, source, audit_args) = if let Some(reg_result) = reg_result {
            (
                reg_result.map(CallToolResponse::from),
                ToolCallSource::Registry,
                request.arguments,
            )
        } else {
            let audit_args = if has_logger {
                request.arguments.clone()
            } else {
                None
            };
            (
                self.inner.call_tool(request, context).await,
                ToolCallSource::Inner,
                audit_args,
            )
        };

        if let (
            Some(logger),
            Some(tool_name),
            Some(session_id),
            Some((start_wall, start_instant)),
        ) = (
            self.context.tool_call_logger.clone(),
            tool_name,
            session_id,
            start,
        ) {
            let duration = start_instant.elapsed();
            let outcome = match &result {
                Ok(CallToolResponse::Complete(call_result)) => ToolCallOutcome::Success {
                    is_error: call_result.is_error.unwrap_or(false),
                    content_summary: summarize_content(&call_result.content),
                },
                // MRTR (SEP-2322) and the Tasks extension let a tool answer
                // without a final result. The dispatch itself succeeded, so
                // record it as a non-error success tagged with the response
                // kind rather than dropping the row.
                Ok(other) => ToolCallOutcome::Success {
                    is_error: false,
                    content_summary: Some(
                        match other {
                            CallToolResponse::InputRequired(_) => "<input_required>",
                            CallToolResponse::Task(_) => "<task>",
                            _ => "<pending>",
                        }
                        .to_string(),
                    ),
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
                })
                .await
                {
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
    ) -> Result<GetPromptResponse, McpError> {
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
            return result.map(GetPromptResponse::from);
        }
        self.inner.get_prompt(request, context).await
    }

    // ── read_resource: registry first, fallback to inner ─────────────

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        self.enrich_extensions(&mut context.extensions);

        if let Some(ref validator) = self.context.access_validator {
            let token = resolve_token(&context.extensions, &self.context.token_store).await;
            let session_id = resolve_session_id(&context.extensions);
            let decision = validator
                .validate_resource_access(&request.uri, token.as_ref(), session_id)
                .await;
            if let AccessDecision::Deny(reason) = decision {
                return Err(McpError::invalid_request(
                    format!("Access denied for resource '{}': {}", request.uri, reason),
                    None,
                ));
            }
        }

        if let Some(result) = self.registry.read_resource(&request).await {
            return result.map(ReadResourceResponse::from);
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

    // `logging/setLevel` is deprecated by SEP-2577 but still served to
    // clients on older protocol revisions, so keep delegating it.
    #[allow(deprecated)]
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

    // ── subscriptions ────────────────────────────────────────────────
    //
    // 2026-07-28 replaces resources/subscribe with the long-lived
    // `subscriptions/listen` request. Both paths are delegated so the
    // inner handler decides; legacy clients keep working unchanged.

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.inner.accepted_subscription_filter(requested)
    }

    fn listen(
        &self,
        context: SubscriptionContext,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.inner.listen(context)
    }

    #[allow(deprecated)]
    fn subscribe(
        &self,
        request: SubscribeRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.subscribe(request, context)
    }

    #[allow(deprecated)]
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

    async fn on_initialized(&self, mut context: NotificationContext<RoleServer>) {
        self.enrich_extensions(&mut context.extensions);
        let session_id = resolve_session_id(&context.extensions);
        self.registry
            .notify_if_changed(session_id, &context.peer)
            .await;
        self.inner.on_initialized(context).await;
    }

    fn on_roots_list_changed(
        &self,
        mut context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.on_roots_list_changed(context)
    }

    fn on_custom_request(
        &self,
        request: CustomRequest,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CustomResult, McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.on_custom_request(request, context)
    }

    fn on_custom_notification(
        &self,
        notification: CustomNotification,
        mut context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.on_custom_notification(notification, context)
    }

    // ── Tasks extension (SEP-2663) ───────────────────────────────────
    //
    // A tool may answer with `CallToolResponse::Task`; the follow-up
    // tasks/* requests must reach the same handler that created it.

    fn get_task(
        &self,
        request: GetTaskParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetTaskResult, McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.get_task(request, context)
    }

    fn update_task(
        &self,
        request: UpdateTaskParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.update_task(request, context)
    }

    fn cancel_task(
        &self,
        request: CancelTaskParams,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.cancel_task(request, context)
    }
}

/// Produce a short summary of tool call content for audit logging.
///
/// Text is truncated to 256 characters. Binary content is replaced with type
/// tags (`<image>`, `<audio>`, `<resource>`, `<resource_link>`).
fn summarize_content(content: &[ContentBlock]) -> Option<String> {
    if content.is_empty() {
        return None;
    }

    let mut buf = String::new();
    for (i, item) in content.iter().enumerate() {
        if i > 0 {
            buf.push_str("; ");
        }
        match item {
            ContentBlock::Text(tc) => {
                if tc.text.len() > 256 {
                    let end = tc.text.floor_char_boundary(256);
                    buf.push_str(&tc.text[..end]);
                    buf.push_str("...");
                } else {
                    buf.push_str(&tc.text);
                }
            }
            ContentBlock::Image(_) => buf.push_str("<image>"),
            ContentBlock::Resource(_) => buf.push_str("<resource>"),
            ContentBlock::Audio(_) => buf.push_str("<audio>"),
            ContentBlock::ResourceLink(_) => buf.push_str("<resource_link>"),
            // `ContentBlock` is `#[non_exhaustive]` upstream.
            _ => buf.push_str("<content>"),
        }
    }
    Some(buf)
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
