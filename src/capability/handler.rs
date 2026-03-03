use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::ErrorData as McpError;

use crate::auth::TokenStore;

use super::filter::{resolve_token, CapabilityFilter};
use super::registry::CapabilityRegistry;

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
pub(crate) struct DynamicHandler<S> {
    inner: S,
    registry: CapabilityRegistry,
    filter: Option<Arc<dyn CapabilityFilter>>,
    token_store: TokenStore,
}

impl<S> DynamicHandler<S> {
    pub fn new(
        inner: S,
        registry: CapabilityRegistry,
        filter: Option<Arc<dyn CapabilityFilter>>,
        token_store: TokenStore,
    ) -> Self {
        Self {
            inner,
            registry,
            filter,
            token_store,
        }
    }
}

impl<S: ServerHandler> ServerHandler for DynamicHandler<S> {
    // ── initialize: capture the peer ─────────────────────────────────

    fn initialize(
        &self,
        request: InitializeRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<InitializeResult, McpError>> + Send + '_ {
        async move {
            self.registry.register_peer(context.peer.clone()).await;
            self.inner.initialize(request, context).await
        }
    }

    // ── list_tools: merge + filter ───────────────────────────────────

    fn list_tools(
        &self,
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        async move {
            let token = resolve_token(&context.extensions, &self.token_store).await;
            let mut inner_result = self.inner.list_tools(request, context).await?;

            // Merge registry tools, registry wins on name collision
            let registry_tools = self.registry.tools().await;
            for rt in &registry_tools {
                let name = rt.name.as_ref();
                inner_result.tools.retain(|t| t.name.as_ref() != name);
            }
            inner_result.tools.extend(registry_tools);

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
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListPromptsResult, McpError>> + Send + '_ {
        async move {
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
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, McpError>> + Send + '_ {
        async move {
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
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
        async move {
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
        request: GetPromptRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<GetPromptResult, McpError>> + Send + '_ {
        async move {
            if let Some(result) = self.registry.get_prompt(&request).await {
                return result;
            }
            self.inner.get_prompt(request, context).await
        }
    }

    // ── read_resource: registry first, fallback to inner ─────────────

    fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResult, McpError>> + Send + '_ {
        async move {
            if let Some(result) = self.registry.read_resource(&request).await {
                return result;
            }
            self.inner.read_resource(request, context).await
        }
    }

    // ── Delegated methods ────────────────────────────────────────────

    fn get_info(&self) -> ServerInfo {
        self.inner.get_info()
    }

    fn ping(
        &self,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.inner.ping(context)
    }

    fn complete(
        &self,
        request: CompleteRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CompleteResult, McpError>> + Send + '_ {
        self.inner.complete(request, context)
    }

    fn set_level(
        &self,
        request: SetLevelRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.inner.set_level(request, context)
    }

    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParam>,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourceTemplatesResult, McpError>> + Send + '_
    {
        self.inner.list_resource_templates(request, context)
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.inner.subscribe(request, context)
    }

    fn unsubscribe(
        &self,
        request: UnsubscribeRequestParam,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.inner.unsubscribe(request, context)
    }

    fn on_cancelled(
        &self,
        notification: CancelledNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.inner.on_cancelled(notification, context)
    }

    fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.inner.on_progress(notification, context)
    }

    fn on_initialized(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.inner.on_initialized(context)
    }

    fn on_roots_list_changed(
        &self,
        context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.inner.on_roots_list_changed(context)
    }
}
