use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RoleServer};
use rmcp::ErrorData as McpError;

use crate::auth::TokenStore;
use crate::session::SessionStore;

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
        request: InitializeRequestParam,
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
        request: Option<PaginatedRequestParam>,
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
        request: Option<PaginatedRequestParam>,
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
        request: CallToolRequestParam,
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
        request: GetPromptRequestParam,
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
        request: ReadResourceRequestParam,
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
        request: CompleteRequestParam,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CompleteResult, McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.complete(request, context)
    }

    fn set_level(
        &self,
        request: SetLevelRequestParam,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.set_level(request, context)
    }

    fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParam>,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourceTemplatesResult, McpError>> + Send + '_
    {
        self.enrich_extensions(&mut context.extensions);
        self.inner.list_resource_templates(request, context)
    }

    fn subscribe(
        &self,
        request: SubscribeRequestParam,
        mut context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), McpError>> + Send + '_ {
        self.enrich_extensions(&mut context.extensions);
        self.inner.subscribe(request, context)
    }

    fn unsubscribe(
        &self,
        request: UnsubscribeRequestParam,
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
