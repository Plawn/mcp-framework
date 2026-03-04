# mcp-framework

An opinionated Rust framework for building [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) servers. Built on top of [`rmcp`](https://crates.io/crates/rmcp).

Handles transport selection, authentication, CLI parsing, and tracing so you only need to implement `rmcp::ServerHandler`.

## Features

- **Triple transport** — HTTP (Streamable HTTP), SSE (Server-Sent Events), and stdio
- **Pluggable auth** — None, HTTP Basic, or OAuth 2.0 (Keycloak OIDC proxy with PKCE, dynamic client registration)
- **Automatic token refresh** — expired OAuth tokens are refreshed lazily on access
- **Dynamic capabilities** — add/remove tools, prompts, and resources at runtime
- **Typed session storage** — generic `SessionStore<T>` for per-session data with TTL and automatic cleanup
- **CLI or programmatic config** — use built-in CLI args + env vars, or pass a `Settings` struct directly

## Usage

Add the dependency:

```toml
[dependencies]
mcp-framework = { git = "https://github.com/Plawn/mcp-framework" }
```

Implement your server and call `run`:

```rust
use mcp_framework::{run, McpApp, AuthProvider};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(McpApp {
        name: "my-mcp-server",
        auth: AuthProvider::None,
        server_factory: |_token_store, _session_store| MyServer::new(),
        stdio_token_env: None,
        settings: None, // use CLI args + env vars
        capability_registry: None,
        capability_filter: None,
        session_store: None,
    }).await
}
```

### Manual settings

Pass a `Settings` struct to bypass CLI parsing and env vars entirely:

```rust
use mcp_framework::{run, McpApp, AuthProvider, Settings, TransportMode};

run(McpApp {
    name: "my-mcp-server",
    auth: AuthProvider::None,
    server_factory: |_token_store, _session_store| MyServer::new(),
    stdio_token_env: None,
    settings: Some(Settings {
        transport: TransportMode::Http,
        bind_addr: "127.0.0.1:8080".to_string(),
        public_url: Some("https://my-app.example.com".to_string()),
        ..Default::default()
    }),
    capability_registry: None,
    capability_filter: None,
    session_store: None,
}).await
```

### CLI mode (when `settings: None`)

```
my-server --transport http      # default, starts Streamable HTTP server
my-server --transport sse       # SSE transport (legacy MCP)
my-server --transport stdio     # stdio for Claude Desktop
my-server --debug               # debug logging
my-server --trace               # trace-level logging
```

## Authentication

### None

```rust
auth: AuthProvider::None,
```

### HTTP Basic

```rust
use mcp_framework::BasicAuthConfig;

auth: AuthProvider::Basic(BasicAuthConfig {
    username: "admin".to_string(),
    password: "secret".to_string(),
}),
// or from BASIC_AUTH_USERNAME / BASIC_AUTH_PASSWORD env vars:
auth: AuthProvider::Basic(BasicAuthConfig::from_env().unwrap()),
```

### OAuth 2.0 (Keycloak)

```rust
use mcp_framework::OAuthConfig;

auth: AuthProvider::OAuth(OAuthConfig {
    client_id: "my-client".to_string(),
    client_secret: "secret".to_string(),
    issuer_url: "https://keycloak.example.com/realms/myrealm".to_string(),
    redirect_url: "http://localhost:4000/oauth/callback".to_string(),
    scopes: vec!["openid".into(), "profile".into()],
}),
// or from OAUTH_* env vars:
auth: AuthProvider::OAuth(OAuthConfig::from_env().unwrap()),
```

OAuth mode exposes:
- `/.well-known/oauth-protected-resource` (RFC 9728)
- `/.well-known/oauth-authorization-server` (RFC 8414)
- `/oauth/register` (RFC 7591 dynamic client registration)
- `/oauth/authorize`, `/oauth/token` (Keycloak proxy)
- `/oauth/login`, `/oauth/callback`, `/oauth/status` (browser flow)

## Session storage

`SessionStore<T>` provides typed, per-session data with automatic TTL expiration. The generic `T` defaults to `()` — consumers that don't need sessions can ignore it entirely.

```rust
use mcp_framework::{run, McpApp, AuthProvider, SessionStore, resolve_session_id};
use std::time::Duration;

#[derive(Default, Clone)]
struct MySession {
    user_name: Option<String>,
    request_count: u32,
}

struct MyServer {
    session_store: SessionStore<MySession>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(McpApp {
        name: "my-server",
        auth: AuthProvider::None,
        server_factory: |_token_store, session_store| MyServer { session_store },
        stdio_token_env: None,
        settings: None,
        capability_registry: None,
        capability_filter: None,
        session_store: None, // default: 30 min TTL
    }).await
}
```

Inside your server handler, use `resolve_session_id` to get the current session ID from request extensions, then access the store:

```rust
let session_id = resolve_session_id(&request.extensions);
let session = self.session_store.get_or_create(session_id).await;

// Update session data
self.session_store.update(session_id, |s| {
    s.request_count += 1;
}).await;
```

To customize the TTL, either provide a `SessionStore` directly or set `session_ttl` in `Settings`:

```rust
// Option 1: provide a pre-built store
session_store: Some(SessionStore::new(Duration::from_secs(3600))),

// Option 2: set TTL in settings
settings: Some(Settings {
    session_ttl: Some(Duration::from_secs(3600)),
    ..Default::default()
}),
```

In HTTP mode, a background cleanup task automatically purges expired sessions.

## Dynamic capabilities

Add or remove tools, prompts, and resources at runtime with `CapabilityRegistry`:

```rust
use mcp_framework::CapabilityRegistry;

let registry = CapabilityRegistry::default();

// Add a tool at runtime
registry.add_tool(my_tool_info, |params| async { /* ... */ }).await;

// Remove a tool
registry.remove_tool("tool-name").await;

// Pass to McpApp
run(McpApp {
    // ...
    capability_registry: Some(registry),
    capability_filter: None,
    session_store: None,
}).await
```

Use `CapabilityFilter` to control which capabilities are visible per session (e.g., based on the authenticated user's token):

```rust
use mcp_framework::CapabilityFilter;

let filter: Arc<dyn CapabilityFilter> = Arc::new(|tools, token| {
    // Filter tools based on user's access token
    tools.retain(|t| user_has_access(&token, &t.name));
});

run(McpApp {
    // ...
    capability_filter: Some(filter),
    session_store: None,
    // ...
}).await
```

## Environment variables

When using CLI mode (`settings: None`):

| Variable | Description | Default |
|---|---|---|
| `BIND_ADDR` | HTTP listen address | `0.0.0.0:4000` |
| `PUBLIC_URL` | Public URL for OAuth callbacks | `http://{BIND_ADDR}` |
| `BASIC_AUTH_USERNAME` | Basic auth username | — |
| `BASIC_AUTH_PASSWORD` | Basic auth password | — |
| `OAUTH_CLIENT_ID` | OAuth client ID | — |
| `OAUTH_CLIENT_SECRET` | OAuth client secret | — |
| `OAUTH_ISSUER_URL` | Keycloak realm URL | — |
| `OAUTH_REDIRECT_URL` | OAuth redirect URL | — |
| `OAUTH_SCOPES` | Comma-separated scopes | `openid,profile,email` |

A `.env` file is loaded automatically in CLI mode.

## Use locally

```json
    "mcpServers": {
      "gitdoc": {
        "command": "<path to bin>",
         "args": ["-t", "stdio"],
        "env": {
          "URL": "http://127.0.0.1:3000"
        }
      }
    },
```