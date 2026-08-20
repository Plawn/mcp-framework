# mcp-framework

An opinionated Rust framework for building [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) servers. Built on top of [`rmcp`](https://crates.io/crates/rmcp).

Handles transport selection, authentication, CLI parsing, and tracing so you only need to implement `rmcp::ServerHandler`.

## Features

- **Triple transport** — HTTP (Streamable HTTP), SSE (Server-Sent Events), and stdio
- **Pluggable auth** — None, HTTP Basic, or OAuth 2.0 (Keycloak OIDC proxy with PKCE and dynamic client registration, or a stateless pure resource server)
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

### Builder API (recommended)

```rust
use mcp_framework::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("my-mcp-server")
        .server(|| MyServer::new())
        .run()
        .await
}
```

Full configuration:

```rust
use mcp_framework::prelude::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("my-mcp-server")
        .auth(AuthProvider::OAuth(OAuthConfig::from_env()?))
        .server(|| MyServer::new())
        .settings(Settings {
            transport: TransportMode::Http,
            bind_addr: "127.0.0.1:8080".to_string(),
            public_url: Some("https://my-app.example.com".to_string()),
            ..Default::default()
        })
        .stdio_token_env("MY_APP_TOKEN")
        .capability_filter(Arc::new(ToolFilter(|tools, _token| {
            tools.into_iter().filter(|t| !t.name.starts_with("admin_")).collect()
        })))
        .run()
        .await
}
```

Tokens and sessions are accessible via `RequestContextExt` on the request context — no need to pass stores to the server factory.

### Struct API

The original struct-based API is still supported:

```rust
use mcp_framework::{run, McpApp, AuthProvider, ProtocolLifecyclePolicy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(McpApp {
        name: "my-mcp-server".into(),
        auth: AuthProvider::None,
        server_factory: || MyServer::new(),
        stdio_token_env: None,
        settings: None,
        capability_registry: None,
        capability_filter: None,
        session_store: None,
        protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
    }).await
}
```

### Manual settings

Pass a `Settings` struct to bypass CLI parsing and env vars entirely:

```rust
use mcp_framework::{run, McpApp, AuthProvider, ProtocolLifecyclePolicy, Settings, TransportMode};

run(McpApp {
    name: "my-mcp-server".into(),
    auth: AuthProvider::None,
    server_factory: || MyServer::new(),
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
    protocol_lifecycle: ProtocolLifecyclePolicy::Hybrid,
}).await
```

### Protocol lifecycle compatibility

HTTP servers default to `ProtocolLifecyclePolicy::Hybrid`: legacy
`initialize` clients keep their sessions, correct 2026 clients use the
stateless `server/discover` lifecycle, and clients that advertise 2026 while
still using `initialize` are safely negotiated down to `2025-11-25`.

Use `.protocol_lifecycle(ProtocolLifecyclePolicy::Strict)` only when every
client is known to use the lifecycle matching its advertised protocol version.

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

#### Token modes

`MCP_TOKEN_MODE` (or `OAuthConfig::token_mode`) picks who holds the grant:

| Mode | The client holds | The server keeps | Refresh |
|---|---|---|---|
| `passthrough` (default) | the Keycloak JWT | access + refresh token | both sides — and Keycloak's refresh-token rotation makes them fight |
| `opaque` | a framework UUID | access + refresh token | the framework |
| `resource_server` | the Keycloak JWT | nothing | the client, alone |

`resource_server` is what MCP 2025-06-18 and later specify: the MCP server is an
OAuth *resource server*, not an authorization server. It validates the inbound
JWT against the issuer's published keys and keeps no token state — so it scales
horizontally without shared persistence, and a rotated refresh token can no
longer break the session. In that mode `/oauth/token`, `/oauth/authorize` and
the browser-flow routes stop proxying (they answer `404`); `/oauth/register`
stays, because Keycloak's registration endpoint sends no CORS headers. Discovery
points clients at Keycloak directly.

```bash
MCP_TOKEN_MODE=resource_server
OAUTH_UNKNOWN_TOKEN_VALIDATION=jwks
OAUTH_EXPECTED_AUDIENCE=my-mcp-server   # mandatory in this mode; boot fails without it
```

The audience is mandatory here and only here: without it the server would accept
every token the issuer ever signed, for any service. Keycloak must be configured
to put that value in `aud` (audience mapper on the client or a client scope).

Capability filters, access validators and tool handlers see the credential as
usual — use `ctx.token()` rather than `ctx.token_store().get_token(...)`, which
has nothing to find in this mode. `refresh_token` is always `None`: it belongs
to the client. Forwarding the inbound bearer to an upstream API is forbidden by
the spec; use RFC 8693 token exchange, or an audience the deployment
deliberately shares.

## Session storage

`SessionStore<T>` provides typed, per-session data with automatic TTL expiration. The generic `T` defaults to `()` — consumers that don't need sessions can ignore it entirely.

```rust
use mcp_framework::prelude::*;

#[derive(Default, Clone)]
struct MySession {
    user_name: Option<String>,
    request_count: u32,
}

struct MyServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    McpAppBuilder::new("my-server")
        .with_sessions::<MySession>()
        .server(|| MyServer)
        .run()
        .await
}
```

Inside your server handler, use `RequestContextExt` to access the session directly from the request context:

```rust
let session = context.session::<MySession>();

// Update session data
let data = session.update(|s| {
    s.request_count += 1;
}).await;

// Access session ID
let id = session.id();
```

To customize the TTL, either provide a `SessionStore` directly or set `session_ttl` in `Settings`:

```rust
// Option 1: provide a pre-built store
.session_store(SessionStore::new(Duration::from_secs(3600)))

// Option 2: set TTL in settings
.settings(Settings {
    session_ttl: Some(Duration::from_secs(3600)),
    ..Default::default()
})
```

In HTTP mode, background cleanup tasks automatically purge expired sessions and tokens.

## Dynamic capabilities

Add or remove tools, prompts, and resources at runtime with `CapabilityRegistry`:

```rust
use mcp_framework::CapabilityRegistry;

let registry = CapabilityRegistry::default();

// Add a tool at runtime
registry.add_tool(my_tool_info, |params| async { /* ... */ }).await;

// Remove a tool
registry.remove_tool("tool-name").await;

// Pass to builder
McpAppBuilder::new("my-server")
    .server(|| MyServer::new())
    .capability_registry(registry)
    .run()
    .await
```

### Capability filtering

Use `ToolFilter`, `PromptFilter`, or `ResourceFilter` to control which capabilities are visible per session. Each wrapper filters one capability type and passes the others through unfiltered:

```rust
use mcp_framework::{ToolFilter, PromptFilter};
use std::sync::Arc;

// Filter tools based on the user's access token
let filter = Arc::new(ToolFilter(|tools, token| {
    tools.into_iter().filter(|t| user_has_access(&token, &t.name)).collect()
}));

// Or implement CapabilityFilter directly for full control over all three types
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
| `MCP_TOKEN_MODE` | `passthrough`, `opaque`, or `resource_server` | `passthrough` |
| `OAUTH_UNKNOWN_TOKEN_VALIDATION` | How to check a bearer the proxy did not issue: `jwks`, `introspection`, `jwks_then_introspection`, `reject` | `jwks_then_introspection` |
| `OAUTH_EXPECTED_AUDIENCE` | Comma-separated audiences a locally validated JWT must carry. Required when `MCP_TOKEN_MODE=resource_server` | — (unconstrained) |

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
