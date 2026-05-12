use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rmcp::model::{
    CallToolResult, GetPromptRequestParams, GetPromptResult, JsonObject, Prompt,
    ReadResourceRequestParams, ReadResourceResult, Resource, Tool,
};
use rmcp::{ErrorData as McpError, Peer, RoleServer};
use serde_json::Value;
use tokio::sync::RwLock;

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

/// Type-erased async handler for a dynamic tool.
///
/// Receives the optional JSON arguments and returns a `CallToolResult`.
pub type ToolHandler = Arc<
    dyn Fn(
            Option<JsonObject>,
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
    tools: Arc<RwLock<HashMap<String, (Tool, ToolHandler)>>>,
    prompts: Arc<RwLock<HashMap<String, (Prompt, PromptHandler)>>>,
    resources: Arc<RwLock<HashMap<String, (Resource, ResourceHandler)>>>,
    peers: Arc<RwLock<Vec<Peer<RoleServer>>>>,
}

impl CapabilityRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            tools: Arc::new(RwLock::new(HashMap::new())),
            prompts: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(RwLock::new(HashMap::new())),
            peers: Arc::new(RwLock::new(Vec::new())),
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
        let handler: ToolHandler = Arc::new(move |args| Box::pin(handler(args)));
        self.tools.write().await.insert(name, (tool, handler));
        self.notify_peers(NotifyKind::Tools).await;
    }

    /// Remove a dynamic tool by name. Returns `true` if it existed.
    pub async fn remove_tool(&self, name: &str) -> bool {
        let removed = self.tools.write().await.remove(name).is_some();
        if removed {
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
        self.notify_peers(NotifyKind::Prompts).await;
    }

    /// Remove a dynamic prompt by name. Returns `true` if it existed.
    pub async fn remove_prompt(&self, name: &str) -> bool {
        let removed = self.prompts.write().await.remove(name).is_some();
        if removed {
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
        self.notify_peers(NotifyKind::Resources).await;
    }

    /// Remove a dynamic resource by URI. Returns `true` if it existed.
    pub async fn remove_resource(&self, uri: &str) -> bool {
        let removed = self.resources.write().await.remove(uri).is_some();
        if removed {
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

    // ── Internal: peer management ────────────────────────────────────

    /// Register a connected peer so it receives list-changed notifications.
    pub(crate) async fn register_peer(&self, peer: Peer<RoleServer>) {
        self.peers.write().await.push(peer);
    }

    // ── Public: programmatic dispatch ───────────────────────────────

    /// Invoke a registered tool by name.
    ///
    /// This is the public API for calling tools programmatically from Rust
    /// (e.g. from a script engine pipeline) without going through the MCP
    /// protocol. Returns an error if the tool is not registered or if the
    /// arguments are not a JSON object.
    pub async fn call_tool(
        &self,
        name: &str,
        args: Option<Value>,
    ) -> Result<CallToolResult, McpError> {
        let json_args = match args {
            None => None,
            Some(Value::Object(map)) => Some(map),
            Some(Value::Null) => None,
            Some(_) => {
                return Err(McpError::invalid_params(
                    "tool arguments must be a JSON object",
                    None,
                ));
            }
        };

        match self.try_call_tool(name, json_args).await {
            Some(result) => result,
            None => Err(McpError::invalid_request(
                format!("tool '{}' not found in registry", name),
                None,
            )),
        }
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
    ) -> Option<Result<CallToolResult, McpError>> {
        let guard = self.tools.read().await;
        let (_, handler) = guard.get(name)?;
        let handler = Arc::clone(handler);
        drop(guard);
        Some(handler(args).await)
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
