use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rmcp::model::{
    Annotated, CallToolResult, GetPromptRequestParams, GetPromptResult, JsonObject, Meta, Prompt,
    RawResource, ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, Tool,
};
use rmcp::{ErrorData as McpError, Peer, RoleServer};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::constants::NS_CAP_VERSIONS;
use crate::persistence::{PersistenceBackend, PersistenceError, spawn_persist};

enum NotifyKind {
    Tools,
    Prompts,
    Resources,
}

impl std::fmt::Display for NotifyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tools => write!(f, "tool list"),
            Self::Prompts => write!(f, "prompt list"),
            Self::Resources => write!(f, "resource list"),
        }
    }
}

#[derive(Clone)]
pub struct ToolCallContext {
    pub peer: Peer<RoleServer>,
    pub meta: Meta,
}

type StoredHandler = Arc<
    dyn Fn(
            Option<JsonObject>,
            Option<ToolCallContext>,
        ) -> Pin<Box<dyn Future<Output = Result<CallToolResult, McpError>> + Send>>
        + Send
        + Sync,
>;

/// Type-erased async handler for a dynamic prompt.
pub type PromptHandler = Arc<
    dyn Fn(
            GetPromptRequestParams,
        ) -> Pin<Box<dyn Future<Output = Result<GetPromptResult, McpError>> + Send>>
        + Send
        + Sync,
>;

/// Type-erased async handler for a dynamic resource.
pub type ResourceHandler = Arc<
    dyn Fn(
            ReadResourceRequestParams,
        ) -> Pin<Box<dyn Future<Output = Result<ReadResourceResult, McpError>> + Send>>
        + Send
        + Sync,
>;

async fn hash_sorted_keys<V>(map: &RwLock<HashMap<String, V>>, hasher: &mut impl Hasher) {
    let guard = map.read().await;
    let mut keys: Vec<&String> = guard.keys().collect();
    keys.sort();
    for key in keys {
        key.hash(hasher);
    }
}

fn empty_capability_hash() -> u64 {
    std::collections::hash_map::DefaultHasher::new().finish()
}

/// A thread-safe registry for dynamic MCP capabilities (tools, prompts, resources).
///
/// The registry stores capabilities alongside their execution handlers and keeps
/// track of connected peers so that mutations automatically trigger MCP
/// list-changed notifications.
///
/// All fields are `Arc`-wrapped so the struct is cheaply `Clone`-able and can
/// be shared across tasks.
#[derive(Clone)]
pub struct CapabilityRegistry {
    tools: Arc<RwLock<HashMap<String, (Tool, StoredHandler)>>>,
    prompts: Arc<RwLock<HashMap<String, (Prompt, PromptHandler)>>>,
    resources: Arc<RwLock<HashMap<String, (Resource, ResourceHandler)>>>,
    peers: Arc<RwLock<Vec<Peer<RoleServer>>>>,
    version: Arc<AtomicU64>,
    session_versions: Arc<RwLock<HashMap<String, u64>>>,
    persistence: Option<Arc<dyn PersistenceBackend>>,
}

impl CapabilityRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            prompts: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(Vec::new())),
            version: Arc::new(AtomicU64::new(empty_capability_hash())),
            session_versions: Arc::new(RwLock::new(HashMap::new())),
            persistence: None,
        }
    }

    // ── Versioning ──────────────────────────────────────────────────

    async fn recompute_version(&self) {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        hash_sorted_keys(&self.tools, &mut hasher).await;
        hash_sorted_keys(&self.prompts, &mut hasher).await;
        hash_sorted_keys(&self.resources, &mut hasher).await;
        self.version.store(hasher.finish(), Ordering::Release);
    }

    /// Current capability version — a content hash of all registered names/URIs.
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Attach a persistence backend for `session_versions`.
    pub fn set_persistence(&mut self, backend: Arc<dyn PersistenceBackend>) {
        self.persistence = Some(backend);
    }

    /// Load persisted session versions from the backend.
    pub async fn load_persisted_versions(&self) -> Result<(), PersistenceError> {
        let backend = match &self.persistence {
            Some(b) => b,
            None => return Ok(()),
        };

        let keys = backend.keys(NS_CAP_VERSIONS).await?;
        let mut loaded = 0usize;

        for key in keys {
            let bytes = match backend.get(NS_CAP_VERSIONS, &key).await? {
                Some(b) => b,
                None => continue,
            };
            match serde_json::from_slice::<u64>(&bytes) {
                Ok(v) => {
                    self.session_versions.write().await.insert(key, v);
                    loaded += 1;
                }
                Err(e) => {
                    tracing::warn!("Skipping corrupted cap_version {key}: {e}");
                }
            }
        }

        if loaded > 0 {
            tracing::info!("Loaded {loaded} persisted capability version(s)");
        }
        Ok(())
    }

    /// Compare the current version with the last version seen by a session.
    /// If they differ (or the session is new), send list-changed notifications
    /// and update the tracked version.
    pub(crate) async fn notify_if_changed(&self, session_id: &str, peer: &Peer<RoleServer>) {
        let current = self.version();

        let should_notify = {
            let mut versions = self.session_versions.write().await;
            let stale = match versions.get(session_id) {
                Some(&last) => last != current,
                None => true,
            };
            if stale {
                versions.insert(session_id.to_string(), current);
            }
            stale
        };

        if should_notify {
            if let Some(ref backend) = self.persistence {
                spawn_persist(backend, NS_CAP_VERSIONS, session_id.to_string(), &current, None);
            }

            if let Err(e) = peer.notify_tool_list_changed().await {
                tracing::warn!("Failed to notify session {session_id} of tool list change: {e}");
            }
            if let Err(e) = peer.notify_prompt_list_changed().await {
                tracing::warn!("Failed to notify session {session_id} of prompt list change: {e}");
            }
            if let Err(e) = peer.notify_resource_list_changed().await {
                tracing::warn!("Failed to notify session {session_id} of resource list change: {e}");
            }
        }
    }

    // ── Tools ────────────────────────────────────────────────────────

    /// Register a dynamic tool with its execution handler.
    ///
    /// If a tool with the same name already exists it is replaced.
    /// All connected peers are notified of the change.
    pub async fn add_tool<H, Fut>(&self, tool: Tool, handler: H)
    where
        H: Fn(Option<JsonObject>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<CallToolResult, McpError>> + Send + 'static,
    {
        let name = tool.name.to_string();
        let handler: StoredHandler = Arc::new(move |args, _ctx| Box::pin(handler(args)));
        self.tools.write().await.insert(name, (tool, handler));
        self.recompute_version().await;
        self.notify_peers(NotifyKind::Tools).await;
    }

    pub async fn add_tool_with_context<H, Fut>(&self, tool: Tool, handler: H)
    where
        H: Fn(Option<JsonObject>, ToolCallContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<CallToolResult, McpError>> + Send + 'static,
    {
        let name = tool.name.to_string();
        let handler: StoredHandler = Arc::new(move |args, ctx| match ctx {
            Some(ctx) => Box::pin(handler(args, ctx)),
            None => Box::pin(async {
                Err(McpError::internal_error(
                    "tool requires call context but none was provided (programmatic call)",
                    None,
                ))
            }),
        });
        self.tools.write().await.insert(name, (tool, handler));
        self.recompute_version().await;
        self.notify_peers(NotifyKind::Tools).await;
    }

    /// Remove a dynamic tool by name. Returns `true` if it existed.
    pub async fn remove_tool(&self, name: &str) -> bool {
        let removed = self.tools.write().await.remove(name).is_some();
        if removed {
            self.recompute_version().await;
            self.notify_peers(NotifyKind::Tools).await;
        }
        removed
    }

    /// List all registered dynamic tools (metadata only).
    pub async fn tools(&self) -> Vec<Tool> {
        self.tools
            .read()
            .await
            .values()
            .map(|(t, _)| t.clone())
            .collect()
    }

    // ── Prompts ──────────────────────────────────────────────────────

    /// Register a dynamic prompt with its execution handler.
    pub async fn add_prompt<H, Fut>(&self, prompt: Prompt, handler: H)
    where
        H: Fn(GetPromptRequestParams) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<GetPromptResult, McpError>> + Send + 'static,
    {
        let name = prompt.name.clone();
        let handler: PromptHandler = Arc::new(move |params| Box::pin(handler(params)));
        self.prompts.write().await.insert(name, (prompt, handler));
        self.recompute_version().await;
        self.notify_peers(NotifyKind::Prompts).await;
    }

    /// Remove a dynamic prompt by name. Returns `true` if it existed.
    pub async fn remove_prompt(&self, name: &str) -> bool {
        let removed = self.prompts.write().await.remove(name).is_some();
        if removed {
            self.recompute_version().await;
            self.notify_peers(NotifyKind::Prompts).await;
        }
        removed
    }

    /// List all registered dynamic prompts (metadata only).
    pub async fn prompts(&self) -> Vec<Prompt> {
        self.prompts
            .read()
            .await
            .values()
            .map(|(p, _)| p.clone())
            .collect()
    }

    // ── Resources ────────────────────────────────────────────────────

    /// Register a dynamic resource with its execution handler.
    pub async fn add_resource<H, Fut>(&self, resource: Resource, handler: H)
    where
        H: Fn(ReadResourceRequestParams) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ReadResourceResult, McpError>> + Send + 'static,
    {
        let uri = resource.raw.uri.clone();
        let handler: ResourceHandler = Arc::new(move |params| Box::pin(handler(params)));
        self.resources.write().await.insert(uri, (resource, handler));
        self.recompute_version().await;
        self.notify_peers(NotifyKind::Resources).await;
    }

    /// Remove a dynamic resource by URI. Returns `true` if it existed.
    pub async fn remove_resource(&self, uri: &str) -> bool {
        let removed = self.resources.write().await.remove(uri).is_some();
        if removed {
            self.recompute_version().await;
            self.notify_peers(NotifyKind::Resources).await;
        }
        removed
    }

    /// List all registered dynamic resources (metadata only).
    pub async fn resources(&self) -> Vec<Resource> {
        self.resources
            .read()
            .await
            .values()
            .map(|(r, _)| r.clone())
            .collect()
    }

    // ── MCP Apps (ext-apps) ──────────────────────────────────────────

    /// Register an MCP App resource — a single-file HTML bundle served via
    /// `resources/read` with MIME type `text/html;profile=mcp-app`.
    ///
    /// The `uri` must use the `ui://` scheme (e.g. `ui://my-server/nps-chart`).
    /// The `html` content is stored in memory and returned verbatim on read.
    pub async fn register_app_resource(&self, uri: impl Into<String>, html: impl Into<String>) {
        let uri: String = uri.into();
        let html: String = html.into();
        let resource = Annotated {
            raw: RawResource::new(&uri, &uri)
                .with_mime_type(crate::constants::APP_MIME_TYPE),
            annotations: None,
        };
        let uri_clone = uri.clone();
        self.add_resource(resource, move |_params| {
            let uri = uri_clone.clone();
            let html = html.clone();
            async move {
                Ok(ReadResourceResult::new(vec![
                    ResourceContents::text(html, uri)
                        .with_mime_type(crate::constants::APP_MIME_TYPE),
                ]))
            }
        })
        .await;
    }

    /// Enrich a [`Tool`] with `_meta.ui.resourceUri` so that MCP hosts render
    /// the associated app resource inline.
    ///
    /// This is a pure transformation — the tool is not registered. Call
    /// [`add_tool`](Self::add_tool) separately.
    pub fn app_tool(mut tool: Tool, resource_uri: &str) -> Tool {
        let mut meta = tool.meta.take().unwrap_or_default();
        meta.0.insert(
            "ui".to_string(),
            serde_json::json!({ "resourceUri": resource_uri }),
        );
        tool.with_meta(meta)
    }

    /// Returns `true` if the registry contains a tool with the given name.
    pub(crate) async fn contains_tool(&self, name: &str) -> bool {
        self.tools.read().await.contains_key(name)
    }

    /// Returns `true` if the registry has any tools registered.
    pub(crate) async fn has_tools(&self) -> bool {
        !self.tools.read().await.is_empty()
    }

    /// Returns `true` if the registry has any prompts registered.
    pub(crate) async fn has_prompts(&self) -> bool {
        !self.prompts.read().await.is_empty()
    }

    /// Returns `true` if the registry has any resources registered.
    pub(crate) async fn has_resources(&self) -> bool {
        !self.resources.read().await.is_empty()
    }

    // ── Peer management ───────────────────────────────────────────────

    /// Register a connected peer so it receives list-changed notifications.
    pub(crate) async fn register_peer(&self, peer: Peer<RoleServer>) {
        self.peers.write().await.push(peer);
    }

    /// Return a snapshot of all connected (non-closed) peers.
    ///
    /// Stale peers whose transport has closed are pruned from the backing
    /// storage on each call, preventing unbounded accumulation in
    /// long-running servers.
    pub async fn peers(&self) -> Vec<Peer<RoleServer>> {
        let mut peers = self.peers.write().await;
        peers.retain(|p| !p.is_transport_closed());
        peers.iter().cloned().collect()
    }

    // ── Public: programmatic dispatch ───────────────────────────────

    fn validate_tool_args(args: Option<Value>) -> Result<Option<JsonObject>, McpError> {
        match args {
            None => Ok(None),
            Some(Value::Object(map)) => Ok(Some(map)),
            Some(Value::Null) => Ok(None),
            Some(_) => Err(McpError::invalid_params(
                "tool arguments must be a JSON object",
                None,
            )),
        }
    }

    /// Invoke a registered tool by name.
    ///
    /// This is the public API for calling tools programmatically from Rust
    /// (e.g. from a script engine pipeline) without going through the MCP
    /// protocol. Returns an error if the tool is not registered or if the
    /// arguments are not a JSON object.
    ///
    /// **Note:** tools registered via [`add_tool_with_context`](Self::add_tool_with_context)
    /// will fail through this method because no call context is available.
    /// Use [`call_tool_with_context`](Self::call_tool_with_context) instead.
    pub async fn call_tool(
        &self,
        name: &str,
        args: Option<Value>,
    ) -> Result<CallToolResult, McpError> {
        let json_args = Self::validate_tool_args(args)?;

        let guard = self.tools.read().await;
        let handler = match guard.get(name) {
            Some((_, h)) => Arc::clone(h),
            None => {
                return Err(McpError::invalid_request(
                    format!("tool '{}' not found in registry", name),
                    None,
                ))
            }
        };
        drop(guard);
        handler(json_args, None).await
    }

    /// Invoke a registered tool by name, providing a [`ToolCallContext`].
    ///
    /// This is the context-aware variant of [`call_tool`](Self::call_tool).
    /// Use this when calling tools registered via
    /// [`add_tool_with_context`](Self::add_tool_with_context).
    pub async fn call_tool_with_context(
        &self,
        name: &str,
        args: Option<Value>,
        context: ToolCallContext,
    ) -> Result<CallToolResult, McpError> {
        let json_args = Self::validate_tool_args(args)?;

        let guard = self.tools.read().await;
        let handler = match guard.get(name) {
            Some((_, h)) => Arc::clone(h),
            None => {
                return Err(McpError::invalid_request(
                    format!("tool '{}' not found in registry", name),
                    None,
                ))
            }
        };
        drop(guard);
        handler(json_args, Some(context)).await
    }

    // ── Internal: dispatch ───────────────────────────────────────────

    /// Try to dispatch a tool call to the registry.
    ///
    /// Returns `None` if the tool is not in the registry (caller should
    /// fall back to the inner handler).
    pub(crate) async fn try_call_tool(
        &self,
        name: &str,
        args: Option<JsonObject>,
        context: Option<ToolCallContext>,
    ) -> Option<Result<CallToolResult, McpError>> {
        let guard = self.tools.read().await;
        let (_, handler) = guard.get(name)?;
        let handler = Arc::clone(handler);
        drop(guard);
        Some(handler(args, context).await)
    }

    /// Try to dispatch a prompt request to the registry.
    pub(crate) async fn get_prompt(
        &self,
        params: &GetPromptRequestParams,
    ) -> Option<Result<GetPromptResult, McpError>> {
        let guard = self.prompts.read().await;
        let (_, handler) = guard.get(&params.name)?;
        let handler = Arc::clone(handler);
        drop(guard);
        Some(handler(params.clone()).await)
    }

    /// Try to dispatch a resource read to the registry.
    pub(crate) async fn read_resource(
        &self,
        params: &ReadResourceRequestParams,
    ) -> Option<Result<ReadResourceResult, McpError>> {
        let guard = self.resources.read().await;
        let (_, handler) = guard.get(&params.uri)?;
        let handler = Arc::clone(handler);
        drop(guard);
        Some(handler(params.clone()).await)
    }

    // ── Internal: notifications ──────────────────────────────────────

    async fn notify_peers(&self, kind: NotifyKind) {
        let mut peers = self.peers.write().await;
        let mut to_remove = Vec::new();
        for (i, peer) in peers.iter().enumerate() {
            if peer.is_transport_closed() {
                to_remove.push(i);
                continue;
            }
            let result = match kind {
                NotifyKind::Tools => peer.notify_tool_list_changed().await,
                NotifyKind::Prompts => peer.notify_prompt_list_changed().await,
                NotifyKind::Resources => peer.notify_resource_list_changed().await,
            };
            if let Err(e) = result {
                tracing::warn!("Failed to notify peer of {kind} change: {e}");
                to_remove.push(i);
            }
        }
        for i in to_remove.into_iter().rev() {
            peers.swap_remove(i);
        }
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "registry_tests.rs"]
mod tests;
