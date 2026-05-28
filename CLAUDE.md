# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Check Commands

```bash
cargo check          # type-check without building
cargo build          # debug build
cargo build --release # release build (strip + LTO)
cargo test           # run all tests
cargo test <name>    # run a single test by name
```

Requires **nightly** Rust (pinned in `rust-toolchain.toml`).

## Architecture

This is a Rust library crate that provides an opinionated framework for building MCP (Model Context Protocol) servers on top of [`rmcp`](https://crates.io/crates/rmcp). It handles transport selection, authentication, and CLI argument parsing so consumers only need to implement `rmcp::ServerHandler`.

### Entry point pattern

Consumers create a `McpApp` with a name, auth provider, and server factory closure, then call `run()`:

```rust
mcp_framework::run(McpApp {
    name: "my-server",
    auth: AuthProvider::Basic(BasicAuthConfig::from_env().unwrap()),
    server_factory: |token_store, session_store| MyServer::new(token_store, session_store),
    stdio_token_env: Some("MY_TOKEN"),
    session_store: None,
    ..
}).await
```

`run()` (`src/runner.rs`) handles `.env` loading, CLI parsing (clap), tracing setup, and dispatches to the chosen transport.

### Transport layer (`src/transport/`)

Two modes selected via `--transport` CLI flag:
- **HTTP** (`http.rs`): Axum router with `rmcp::StreamableHttpService` at `/mcp`, OAuth well-known endpoints, CORS. `build_app()` is extracted as a pure function for testability.
- **Stdio** (`stdio.rs`): stdin/stdout via `rmcp` transport, used for Claude Desktop local integration.

### Auth layer (`src/auth/`)

`AuthProvider` enum drives which middleware and routes are registered:
- **None**: no auth middleware
- **Basic**: HTTP Basic auth middleware, credentials from `BASIC_AUTH_*` env vars
- **OAuth**: Full OAuth2/OIDC proxy for Keycloak — includes RFC 8414/9728 metadata endpoints, RFC 7591 dynamic client registration, PKCE authorization flow, and token proxying. All OAuth routes live under `/oauth/`.

Key type: `TokenStore` — thread-safe token storage shared between auth middleware and the server handler via the factory closure. Supports automatic token refresh for OAuth mode.

### Session layer (`src/session/`)

`SessionStore<T>` — generic, thread-safe per-session data store with TTL expiration. The type parameter `T` (must implement `Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static`) is defined by the consumer. Default TTL is 30 minutes. A background cleanup task purges expired sessions in HTTP mode.

Helper function `resolve_session_id(extensions)` extracts the `mcp-session-id` header from MCP request context extensions, falling back to `"default"` for stdio mode.

### Audit logging (`src/audit/`)

Pluggable tool call audit logging. Every `call_tool` invocation can be logged via a `ToolCallLogger` trait implementation. The framework ships two built-in loggers:
- `NoopLogger` — discards all records
- `TracingLogger` — emits structured `tracing::info!` events

Key types:
- `ToolCallRecord` — captures tool name, arguments (`Option<Map<String, Value>>`), session ID, timestamp (`SystemTime`), duration (`Duration`), dispatch source (registry vs inner handler), and outcome
- `ToolCallOutcome` — `Success { is_error, content_summary }` or `McpError { code, message }`. `is_error: true` means the tool reported a tool-level error (e.g. bad LLM input) but the MCP protocol call itself succeeded
- `ToolCallSource` — `Registry` (dynamic tools from `CapabilityRegistry`) or `Inner` (static tools from `ServerHandler`)

Logging is fire-and-forget via `tokio::spawn` — zero impact on tool call latency. When no logger is configured, the hot path has zero overhead (no clones, no allocations).

The interception point is `DynamicHandler::call_tool` in `src/capability/handler.rs`.

#### Using a built-in logger

```rust
McpAppBuilder::new("my-server")
    .tool_call_logger(Arc::new(TracingLogger))
    .server(|| MyServer::new())
    .run()
    .await?;
```

#### Implementing a custom storage backend

Implement the `ToolCallLogger` trait. The `log` method returns `Pin<Box<dyn Future<Output = ()> + Send>>` — this allows async I/O (database writes, HTTP calls). Handle errors internally; the framework cannot act on them since logging is fire-and-forget.

```rust
use mcp_framework::audit::{ToolCallLogger, ToolCallRecord, ToolCallOutcome};
use std::future::Future;
use std::pin::Pin;

struct FileLogger { path: std::path::PathBuf }

impl ToolCallLogger for FileLogger {
    fn log(&self, record: ToolCallRecord) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let path = self.path.clone();
        Box::pin(async move {
            let line = format!(
                "{} tool={} session={} duration={}ms outcome={}\n",
                humantime::format_rfc3339(record.timestamp),
                record.tool_name,
                record.session_id,
                record.duration.as_millis(),
                match &record.outcome {
                    ToolCallOutcome::Success { is_error, .. } =>
                        if *is_error { "tool_error" } else { "success" },
                    ToolCallOutcome::McpError { code, .. } =>
                        &format!("mcp_error({code})"),
                },
            );
            if let Err(e) = tokio::fs::OpenOptions::new()
                .create(true).append(true).open(&path).await
                .and_then(|mut f| {
                    use tokio::io::AsyncWriteExt;
                    // write_all requires a mutable borrow in an async block
                    Box::pin(async move { f.write_all(line.as_bytes()).await })
                }).await
            {
                tracing::warn!("audit log write failed: {e}");
            }
        })
    }
}
```

Then wire it via the builder: `.tool_call_logger(Arc::new(FileLogger { path: "audit.log".into() }))`

### Access validation (`src/capability/validator.rs`)

Pre-execution authorization for tool calls, prompt access, and resource reads. Unlike `CapabilityFilter` which controls **visibility** (what clients can *see*), `AccessValidator` controls **execution** (what clients can *do*). A tool hidden by the filter can still be called directly if the client knows its name — the access validator closes that gap.

Key types:
- `AccessDecision` — `Allow` or `Deny(reason)`
- `AccessValidator` trait — three async methods with default `Allow` implementations: `validate_tool_call`, `validate_prompt_access`, `validate_resource_access`
- `ToolCallValidator<F>` — convenience wrapper for a closure that validates only tool calls

The interception point is `DynamicHandler::call_tool` / `get_prompt` / `read_resource` in `src/capability/handler.rs`, before dispatch to the registry or inner handler.

#### Global claims decoder

A claims decoder can be configured once on the `TokenStore` (or via `McpAppBuilder::claims_decoder`). It decodes the JWT access token into a typed struct and caches the result in `StoredToken::decoded_claims`. Every component that touches a token — filters, validators, handlers — can access the decoded claims via `token.claims::<C>()`.

The decoder is applied automatically during `TokenStore::store_token`, including after token refresh.

#### Using access validation with JWT roles

```rust
#[derive(Debug, Clone, serde::Deserialize)]
struct Claims { roles: Vec<String> }

fn decode_jwt(token: &str) -> Option<Claims> {
    let payload = base64::decode(token.split('.').nth(1)?).ok()?;
    serde_json::from_slice(&payload).ok()
}

fn is_admin(token: Option<&StoredToken>) -> bool {
    token.and_then(|t| t.claims::<Claims>())
        .map_or(false, |c| c.roles.contains(&"admin".into()))
}

McpAppBuilder::new("my-server")
    .claims_decoder(decode_jwt)                            // global, defined ONCE
    .capability_filter(Arc::new(ToolFilter(|tools, token| {
        if is_admin(token) { tools } else {
            tools.into_iter().filter(|t| !t.name.starts_with("admin_")).collect()
        }
    })))
    .access_validator(Arc::new(ToolCallValidator(|name, _args, token, _session| {
        if name.starts_with("admin_") && !is_admin(token) {
            AccessDecision::Deny("admin role required".into())
        } else {
            AccessDecision::Allow
        }
    })))
    .server(|| MyServer::new())
    .run()
    .await?;
```

### MCP Apps / ext-apps (`src/capability/registry.rs`)

Support for [MCP Apps](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/ext-apps) (ext-apps, spec v1.7.0) — tools that declare a companion UI rendered by the host inline in the chat.

#### How it works

MCP Apps let a tool return both **structured data** (JSON text for the LLM) and a **visual UI** (HTML for the human) in a single interaction. The flow has three steps:

1. **Tool call** — the host calls a tool (e.g. `get_nps`). The tool returns JSON text as usual. But the tool's metadata contains `_meta.ui.resourceUri` pointing to a `ui://` URI.
2. **Resource fetch** — the host sees the `_meta.ui` pointer and calls `resources/read` on the **same MCP server** with that `ui://` URI. The server returns a self-contained HTML bundle with MIME type `text/html;profile=mcp-app`.
3. **Render** — the host renders the HTML in a sandboxed iframe inline next to the text response.

The HTML is served over the MCP protocol itself (via `resources/read`), not over a separate HTTP endpoint. The bundle must be **single-file** — all CSS, JS, and assets inlined — because it is delivered as a string in the resource contents.

#### API

Two helpers on `CapabilityRegistry`:

- **`register_app_resource(uri, html)`** — registers a `ui://` resource with MIME type `text/html;profile=mcp-app`. The HTML string is stored in memory and returned verbatim when the host calls `resources/read`. The resource appears in `resources/list` automatically.
- **`app_tool(tool, resource_uri)`** — static method that injects `_meta.ui.resourceUri` into a `Tool`'s existing metadata (preserving any other `_meta` fields). Returns the enriched `Tool`. Does **not** register the tool — call `add_tool` separately.

The MIME type constant `APP_MIME_TYPE` is in `src/constants.rs`.

#### Usage

```rust
use mcp_framework::prelude::*;

// In your server setup, with access to a CapabilityRegistry:

// 1. Register the HTML bundle as a ui:// resource.
//    Use include_str! to embed the file at compile time,
//    or pass a String loaded at runtime.
registry.register_app_resource(
    "ui://my-server/nps-chart",
    include_str!("../ui/dist/nps-chart.html"),
).await;

// 2. Create a tool and tag it with the resource URI.
let tool = CapabilityRegistry::app_tool(
    Tool::new("get_nps", "Get NPS scores", serde_json::Map::new()),
    "ui://my-server/nps-chart",
);

// 3. Register the tool with its handler as usual.
//    The handler returns JSON for the LLM; the host fetches
//    the HTML separately via resources/read.
registry.add_tool(tool, |args| async {
    let data = compute_nps(args).await;
    Ok(CallToolResult::success(vec![
        Content::text(serde_json::to_string(&data).unwrap()),
    ]))
}).await;
```

#### Passing data to the UI

The HTML bundle runs in an isolated iframe — it does not receive the tool call arguments or result automatically. To pass data, embed it in the HTML at build time (e.g. template variables in the Vite build), or use a convention like a `<script id="data">` tag populated by the resource handler. The current implementation serves the HTML as a static string; dynamic per-call rendering would require creating a unique resource per invocation.

### Persistence layer (`src/persistence.rs`)

`PersistenceBackend` trait — async key-value interface with namespace separation (`"tokens"`, `"sessions"`). Both `TokenStore` and `SessionStore<T>` accept an optional backend via `.with_persistence()` or `.set_persistence()`. When configured:

- **Write-through**: mutations (`store_token`, `update`, `remove`, `purge_expired`) are written to the backend asynchronously (fire-and-forget via `tokio::spawn`)
- **Load-at-startup**: `load_persisted()` reads all keys from the backend and populates the in-memory store. Called automatically during `run()` before the listener starts
- **No backend = current behavior**: zero overhead, no serialization

The trait uses `Pin<Box<dyn Future>>` returns for object safety (`Arc<dyn PersistenceBackend>`). `InMemoryBackend` is shipped for testing. `Instant` fields are serialized as seconds-remaining and reconstructed on load. `StoredToken::decoded_claims` is not serialized — it is re-decoded via the existing `claims_decoder`.

Builder API: `.persistence(Arc::new(MyBackend::new()))` wires the backend into both stores.

#### Built-in backends

- `InMemoryBackend` — always available, useful for testing. TTL is ignored.
- `RedisBackend` — requires the `redis` cargo feature. Stores keys as `{ns}:{key}` with a companion index Set (`{ns}:__idx__`) per namespace so that `keys()` is O(members) via `SMEMBERS` rather than scanning the keyspace. `set` and `delete` maintain the index atomically using pipelined transactions. TTL is handled natively via Redis `EXPIRE`.

#### Using Redis persistence

Enable the feature in `Cargo.toml`:

```toml
[dependencies]
mcp-framework = { version = "0.1", features = ["redis"] }
```

Then wire it via the builder:

```rust
use std::sync::Arc;
use mcp_framework::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let redis = RedisBackend::connect("redis://127.0.0.1/").await?;

    McpAppBuilder::new("my-server")
        .persistence(Arc::new(redis))
        .server(|| MyServer::new())
        .run()
        .await
}
```

If you already have a `redis::aio::ConnectionManager` (e.g. shared with other parts of your application), use `RedisBackend::from_connection_manager(conn)` instead.

### HTTP utilities (`src/http_util/`)

- `HttpError`: unified error type that converts to Axum responses with proper status codes and JSON bodies
- `QueryBuilder`: fluent API for constructing URL query parameters

## Environment Variables

| Variable | Used in | Default |
|---|---|---|
| `BIND_ADDR` | HTTP mode | `0.0.0.0:4000` |
| `PUBLIC_URL` | HTTP mode | `http://{BIND_ADDR}` |
| `BASIC_AUTH_USERNAME`, `BASIC_AUTH_PASSWORD` | Basic auth | — |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_ISSUER_URL`, `OAUTH_REDIRECT_URL` | OAuth | — |
| `OAUTH_SCOPES` | OAuth | `openid,profile,email` |
