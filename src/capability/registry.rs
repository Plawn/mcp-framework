use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rmcp::model::{
    CallToolResult, GetPromptRequestParams, GetPromptResult, JsonObject, Prompt,
    ReadResourceRequestParams, ReadResourceResult, Resource, Tool,
};
use rmcp::{ErrorData as McpError, Peer, RoleServer};
use tokio::sync::RwLock;

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
        self.notify_tools_changed().await;
    }

    /// Remove a dynamic tool by name. Returns `true` if it existed.
    pub async fn remove_tool(&self, name: &str) -> bool {
        let removed = self.tools.write().await.remove(name).is_some();
        if removed {
            self.notify_tools_changed().await;
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
        self.notify_prompts_changed().await;
    }

    /// Remove a dynamic prompt by name. Returns `true` if it existed.
    pub async fn remove_prompt(&self, name: &str) -> bool {
        let removed = self.prompts.write().await.remove(name).is_some();
        if removed {
            self.notify_prompts_changed().await;
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
        self.notify_resources_changed().await;
    }

    /// Remove a dynamic resource by URI. Returns `true` if it existed.
    pub async fn remove_resource(&self, uri: &str) -> bool {
        let removed = self.resources.write().await.remove(uri).is_some();
        if removed {
            self.notify_resources_changed().await;
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

    // ── Internal: peer management ────────────────────────────────────

    /// Register a connected peer so it receives list-changed notifications.
    pub(crate) async fn register_peer(&self, peer: Peer<RoleServer>) {
        self.peers.write().await.push(peer);
    }

    // ── Internal: dispatch ───────────────────────────────────────────

    /// Try to dispatch a tool call to the registry.
    ///
    /// Returns `None` if the tool is not in the registry (caller should
    /// fall back to the inner handler).
    pub(crate) async fn call_tool(
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

    async fn notify_tools_changed(&self) {
        let mut peers = self.peers.write().await;
        let mut to_remove = Vec::new();
        for (i, peer) in peers.iter().enumerate() {
            if peer.is_transport_closed() {
                to_remove.push(i);
                continue;
            }
            if let Err(e) = peer.notify_tool_list_changed().await {
                tracing::warn!("Failed to notify peer of tool list change: {}", e);
                to_remove.push(i);
            }
        }
        // Remove closed/failed peers in reverse order to keep indices valid
        for i in to_remove.into_iter().rev() {
            peers.swap_remove(i);
        }
    }

    async fn notify_prompts_changed(&self) {
        let mut peers = self.peers.write().await;
        let mut to_remove = Vec::new();
        for (i, peer) in peers.iter().enumerate() {
            if peer.is_transport_closed() {
                to_remove.push(i);
                continue;
            }
            if let Err(e) = peer.notify_prompt_list_changed().await {
                tracing::warn!("Failed to notify peer of prompt list change: {}", e);
                to_remove.push(i);
            }
        }
        for i in to_remove.into_iter().rev() {
            peers.swap_remove(i);
        }
    }

    async fn notify_resources_changed(&self) {
        let mut peers = self.peers.write().await;
        let mut to_remove = Vec::new();
        for (i, peer) in peers.iter().enumerate() {
            if peer.is_transport_closed() {
                to_remove.push(i);
                continue;
            }
            if let Err(e) = peer.notify_resource_list_changed().await {
                tracing::warn!("Failed to notify peer of resource list change: {}", e);
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
mod tests {
    use super::*;
    use rmcp::model::{Annotated, Content, GetPromptResult, RawResource, ReadResourceResult};

    fn make_tool(name: &str) -> Tool {
        Tool::new(name.to_string(), format!("Tool {name}"), serde_json::Map::new())
    }

    fn make_prompt(name: &str) -> Prompt {
        Prompt::new(name, Some(format!("Prompt {name}")), None)
    }

    fn make_resource(uri: &str) -> Resource {
        Annotated {
            raw: RawResource::new(uri, uri),
            annotations: None,
        }
    }

    // ── Tool tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn add_and_list_tools() {
        let reg = CapabilityRegistry::new();
        assert!(reg.tools().await.is_empty());

        reg.add_tool(make_tool("alpha"), |_args| async {
            Ok(CallToolResult::success(vec![Content::text("ok")]))
        })
        .await;

        let tools = reg.tools().await;
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name.as_ref(), "alpha");
    }

    #[tokio::test]
    async fn remove_tool_returns_true_if_existed() {
        let reg = CapabilityRegistry::new();
        reg.add_tool(make_tool("beta"), |_| async {
            Ok(CallToolResult::success(vec![]))
        })
        .await;

        assert!(reg.remove_tool("beta").await);
        assert!(!reg.remove_tool("beta").await);
        assert!(reg.tools().await.is_empty());
    }

    #[tokio::test]
    async fn call_tool_dispatches_to_handler() {
        let reg = CapabilityRegistry::new();
        reg.add_tool(make_tool("echo"), |_args| async {
            Ok(CallToolResult::success(vec![Content::text("hello")]))
        })
        .await;

        let result = reg.call_tool("echo", None).await;
        assert!(result.is_some());
        let result = result.unwrap().unwrap();
        assert!(!result.content.is_empty());
    }

    #[tokio::test]
    async fn call_tool_returns_none_for_unknown() {
        let reg = CapabilityRegistry::new();
        assert!(reg.call_tool("unknown", None).await.is_none());
    }

    // ── Prompt tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn add_and_list_prompts() {
        let reg = CapabilityRegistry::new();
        reg.add_prompt(make_prompt("greeting"), |_params| async {
            Ok(GetPromptResult::new(vec![]).with_description("Hello"))
        })
        .await;

        let prompts = reg.prompts().await;
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].name, "greeting");
    }

    #[tokio::test]
    async fn remove_prompt() {
        let reg = CapabilityRegistry::new();
        reg.add_prompt(make_prompt("p"), |_| async {
            Ok(GetPromptResult::new(vec![]))
        })
        .await;

        assert!(reg.remove_prompt("p").await);
        assert!(!reg.remove_prompt("p").await);
    }

    #[tokio::test]
    async fn get_prompt_dispatches() {
        let reg = CapabilityRegistry::new();
        reg.add_prompt(make_prompt("test"), |_| async {
            Ok(GetPromptResult::new(vec![]).with_description("dispatched"))
        })
        .await;

        let result = reg
            .get_prompt(&GetPromptRequestParams::new("test"))
            .await;
        assert!(result.is_some());
        let result = result.unwrap().unwrap();
        assert_eq!(result.description.as_deref(), Some("dispatched"));
    }

    // ── Resource tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn add_and_list_resources() {
        let reg = CapabilityRegistry::new();
        reg.add_resource(make_resource("file:///a.txt"), |_| async {
            Ok(ReadResourceResult::new(vec![]))
        })
        .await;

        let resources = reg.resources().await;
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].raw.uri, "file:///a.txt");
    }

    #[tokio::test]
    async fn remove_resource() {
        let reg = CapabilityRegistry::new();
        reg.add_resource(make_resource("file:///b"), |_| async {
            Ok(ReadResourceResult::new(vec![]))
        })
        .await;

        assert!(reg.remove_resource("file:///b").await);
        assert!(!reg.remove_resource("file:///b").await);
    }

    #[tokio::test]
    async fn read_resource_dispatches() {
        let reg = CapabilityRegistry::new();
        reg.add_resource(make_resource("file:///c"), |_| async {
            Ok(ReadResourceResult::new(vec![]))
        })
        .await;

        let result = reg
            .read_resource(&ReadResourceRequestParams::new("file:///c"))
            .await;
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn read_resource_returns_none_for_unknown() {
        let reg = CapabilityRegistry::new();
        assert!(reg
            .read_resource(&ReadResourceRequestParams::new("nope"))
            .await
            .is_none());
    }

    // ── Clone sharing test ───────────────────────────────────────────

    #[tokio::test]
    async fn cloned_registry_shares_state() {
        let reg = CapabilityRegistry::new();
        let reg2 = reg.clone();

        reg.add_tool(make_tool("shared"), |_| async {
            Ok(CallToolResult::success(vec![]))
        })
        .await;

        assert_eq!(reg2.tools().await.len(), 1);
    }
}
