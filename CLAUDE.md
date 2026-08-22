# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It is an index. The rationale, invariants and worked examples for each subsystem live in `docs/` — read the relevant file **before** changing that subsystem:

| Area | Doc |
|---|---|
| `AuthProvider`, OAuth token modes, bearer validation, Keycloak harness | [`docs/auth.md`](docs/auth.md) |
| Session identity, sessionless revisions, transport session recovery, persistence backends | [`docs/sessions.md`](docs/sessions.md) |
| Advertised protocol revisions, the `max_protocol_version` ceiling, lifecycle policy | [`docs/protocol.md`](docs/protocol.md) |
| In-process (loopback) transport | [`docs/loopback.md`](docs/loopback.md) |
| Access validation, claims decoder, MCP Apps, tool schema sanitization | [`docs/capabilities.md`](docs/capabilities.md) |
| Audit logging, effectiveness metrics | [`docs/observability.md`](docs/observability.md) |

## Build & Check Commands

```bash
cargo check          # type-check without building
cargo build          # debug build
cargo build --release # release build (strip + LTO)
cargo test           # run all tests
cargo test <name>    # run a single test by name
```

Requires **nightly** Rust (pinned in `rust-toolchain.toml`).

The OAuth lifecycle tests are `#[ignore]`d and need Docker — `cargo test --test oauth_lifecycle_rmcp -- --ignored --test-threads=1`. See [`docs/auth.md`](docs/auth.md).

## Architecture

A Rust library crate providing an opinionated framework for building MCP (Model Context Protocol) servers on top of [`rmcp`](https://crates.io/crates/rmcp). It handles transport selection, authentication, and CLI argument parsing so consumers only need to implement `rmcp::ServerHandler`.

| Module | Responsibility |
|---|---|
| `src/runner.rs` | `run()` / `McpApp` / `McpAppBuilder` — `.env`, CLI (clap), tracing, transport dispatch |
| `src/transport/` | `http.rs` (axum + `StreamableHttpService` at `/mcp`), `stdio.rs`, `session_persistence.rs` |
| `src/auth/` | `AuthProvider`, `TokenStore`, middleware, OAuth proxy, JWKS, session bindings |
| `src/session/` | `SessionStore<T>`, session identity resolution |
| `src/capability/` | `CapabilityRegistry`, `DynamicHandler`, filters, access validators, schema sanitization |
| `src/persistence.rs` | `PersistenceBackend` trait, `InMemoryBackend`, `RedisBackend` (feature `redis`) |
| `src/audit/`, `src/metrics/` | `ToolCallLogger` stream and the feature-gated collector built on it |
| `src/http_util/` | `HttpError` (converts to axum responses), `QueryBuilder` |

### Entry point pattern

`McpAppBuilder` is the recommended surface — a name, an auth provider, a server factory, then `run()`:

```rust
McpAppBuilder::new("my-server")
    .auth(AuthProvider::Basic(BasicAuthConfig::from_env()?))
    .with_sessions::<MySession>()
    .server(|| MyServer::new())
    .run()
    .await
```

The server factory takes **no arguments** — a handler reaches the stores through `RequestContextExt`
(`ctx.session::<T>()`, `ctx.session_id()`, `ctx.token()`, `ctx.token_store()`) on the rmcp
`RequestContext`. `run(McpApp { .. })` remains as the struct API; every builder field maps to a
struct field of the same name.

Other builder methods: `.settings()`, `.stdio_token_env()`, `.persistence()`, `.capability_registry()`, `.capability_filter()`, `.access_validator()`, `.claims_decoder()`, `.tool_call_logger()`, `.metrics()`, `.protocol_lifecycle()`, `.extra_routes()` (behind auth), `.public_routes()` (outside auth), `.loopback()`, `.build()`.

`build_app()` (`src/transport/http.rs`) is extracted as a pure function for testability and returns `Result<(Router, TokenStore, CapabilityRegistry), ConfigError>` — it validates the configuration before assembling anything, so a consumer building an `McpApp` by hand cannot route around the boot-time guards.

### rmcp version & the MRTR response types

Pinned to **rmcp 3.1**. Two upstream changes shape every consumer `ServerHandler`:

- **MRTR (SEP-2322)** — `call_tool` / `get_prompt` / `read_resource` return `CallToolResponse` / `GetPromptResponse` / `ReadResourceResponse` (enums) instead of the `*Result` structs. A handler that produces a plain result appends `.into()`; `DynamicHandler` matches on `CallToolResponse::Complete` for audit and treats the non-terminal variants (`InputRequired`, `Task`) as successful dispatches.
- **Flat content model (rmcp 2.0)** — `Content` / `RawContent` / `Annotated<T>` collapsed into `ContentBlock`, and `Annotated<RawResource>` into a flat `Resource`. `prelude::Content` remains as a `#[deprecated]` alias of `ContentBlock`. Most wire types are `#[non_exhaustive]`, so build them with `Type::new(..).with_*(..)` rather than struct literals — and match them with a wildcard arm.

`DynamicHandler` also forwards the 3.x additions to the inner handler so wrapping stays transparent: `discover` (the 2026-07-28 replacement for `initialize` — it gets the same registry capability augmentation), `supported_protocol_versions`, `accepted_subscription_filter` / `listen`, `on_custom_request` / `on_custom_notification`, and the Tasks extension (`get_task` / `update_task` / `cancel_task`). The legacy `set_level` / `subscribe` / `unsubscribe` delegations are kept behind `#[allow(deprecated)]` because they still serve clients on older revisions.

### Transport layer

Two modes selected via the `--transport` CLI flag: **HTTP** (axum router, OAuth well-known endpoints, CORS) and **stdio** (used for Claude Desktop local integration). There is no SSE transport — `TransportMode` is `Http | Stdio`.

Two independent knobs decide how a client is served — `.max_protocol_version()` controls which revisions are **offered**, `.protocol_lifecycle()` controls what happens to a client that announces a modern revision through the **legacy** lifecycle. Full treatment in [`docs/protocol.md`](docs/protocol.md).

`.max_protocol_version(ProtocolVersion::V_2025_11_25)` (env override `MCP_MAX_PROTOCOL_VERSION`) caps the advertised set. Without it rmcp's trait default offers every `KNOWN_VERSIONS`, so a server advertises `2026-07-28` — and its sessionless `server/discover` lifecycle — without anyone deciding to. The cap is applied at the single forward point in `DynamicHandler`, validated at boot in `build_app()`, and deliberately **not** applied to the loopback.

`ProtocolLifecyclePolicy` (`src/transport/protocol.rs`, `.protocol_lifecycle()`) decides what happens to a client that announces a sessionless protocol version through the legacy `initialize` lifecycle:

- `Hybrid` (default) — such an `initialize` is negotiated down to `2025-11-25`, so rmcp creates a session and the rest of the client's legacy lifecycle stays coherent. Correct 2026-07-28 clients using `server/discover` are always served statelessly.
- `Strict` — rmcp's routing, unmodified. Only for a deployment where every client picks the lifecycle matching the version it advertises.

### In-process transport (loopback) → [`docs/loopback.md`](docs/loopback.md)

`McpAppBuilder::loopback()` hands out a `LoopbackEndpoint`: an in-process caller (agent loop, scheduler, job) becomes a real MCP client over a channel pair instead of a socket, so it goes through the same `DynamicHandler`, registry, capability filter, access validator and tool-call logger as network traffic. Calling `CapabilityRegistry::call_tool` directly is the shortcut it exists to remove — that path silently bypasses all four.

The endpoint is a **snapshot** of the builder, so it must be taken last: `validate()` refuses to build when a captured field was configured afterwards. It keeps its own `TokenStore` and `SessionStore` (both keyed by a session id the in-process caller chooses), which is also why in-process session data is not persisted.

### Auth layer → [`docs/auth.md`](docs/auth.md)

`AuthProvider` (None / Basic / OAuth) drives which middleware and routes are registered. Under OAuth, `TokenMode` decides who holds the grant:

- `Passthrough` (default) — the framework proxies `/oauth/token` and co-owns the refresh token with the client.
- `Opaque` — the client holds a framework UUID; the framework refreshes internally. Needs shared persistence.
- `ResourceServer` — what MCP 2025-06-18 and later specify: JWKS-only validation, **no** token state, `OAUTH_EXPECTED_AUDIENCE` mandatory. Stateless.

Bearers the proxy did not issue go through `validate_unknown_bearer` (`TokenStore` → JWKS → introspection), governed by `OAUTH_UNKNOWN_TOKEN_VALIDATION`.

### Session layer → [`docs/sessions.md`](docs/sessions.md)

`SessionStore<T>` — generic, thread-safe per-session data store with TTL expiration (default 30 min), purged by a background task in HTTP mode. `resolve_session_id(extensions)` / `session_id_from_parts(&Parts)` resolve the identity, shared with `resolve_token`.

MCP 2026-07-28 removes protocol-level sessions, so identity is derived from the credential's claims (`credential_session_key`) and injected under `MCP_FALLBACK_SESSION_HEADER`. That header is authoritative and is therefore stripped from every inbound request before auth runs.

### Persistence layer → [`docs/sessions.md`](docs/sessions.md)

`PersistenceBackend` — async key-value interface with namespace separation. Write-through on mutation, load-at-startup, read-through on a memory miss (this is what makes multi-instance deployment work without sticky sessions). No backend configured = zero overhead. `InMemoryBackend` ships for testing; `RedisBackend` behind the `redis` feature.

### Capability layer → [`docs/capabilities.md`](docs/capabilities.md)

`CapabilityFilter` controls **visibility** (what clients see), `AccessValidator` controls **execution** (what clients may do) — a hidden tool can still be called by name. Both read decoded JWT claims via the global claims decoder. The registry also supports MCP Apps (`ui://` resources tagged into `_meta.ui`), and `sanitize_tool_schemas` rewrites every schema on its way to `tools/list`.

### Audit & metrics → [`docs/observability.md`](docs/observability.md)

Every `call_tool` produces a `ToolCallRecord`, dispatched fire-and-forget to a `ToolCallLogger` (`NoopLogger`, `TracingLogger`, or a custom one). The feature-gated `MetricsCollector` *is* a logger, so metrics add no new interception point; it exposes `snapshot()` in-process and a Prometheus/JSON endpoint mounted outside the auth layer.

## Environment Variables

| Variable | Used in | Default |
|---|---|---|
| `BIND_ADDR` | HTTP mode | `0.0.0.0:4000` |
| `PUBLIC_URL` | HTTP mode | `http://{BIND_ADDR}` |
| `BASIC_AUTH_USERNAME`, `BASIC_AUTH_PASSWORD` | Basic auth | — |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_ISSUER_URL`, `OAUTH_REDIRECT_URL` | OAuth | — |
| `OAUTH_SCOPES` | OAuth; also advertised as `scopes_supported` in the RFC 8414 and RFC 9728 documents | `openid,profile,email` |
| `MCP_MAX_PROTOCOL_VERSION` | `build_app()` / stdio boot | — (uncapped; `none`/`off`/`latest` lift a builder ceiling, any other value must be a known revision) |
| `MCP_TOKEN_MODE` | `OAuthConfig::from_env()` | `passthrough` (also `opaque`, `resource_server`) |
| `OAUTH_UNKNOWN_TOKEN_VALIDATION` | `OAuthConfig::from_env()` | `jwks_then_introspection` (also `jwks`, `introspection`, `reject`; in `resource_server` mode the default is coerced to `jwks` and the other two are boot errors) |
| `OAUTH_EXPECTED_AUDIENCE` | `OAuthConfig::from_env()` | — (comma-separated; empty = `aud` unconstrained — **required** when `MCP_TOKEN_MODE=resource_server`) |
| `MCP_METRICS_PATH` | `MetricsConfig::from_env()` (feature `metrics`) | `/metrics` (`off`/empty disables) |
| `MCP_METRICS_NAMESPACE` | `MetricsConfig::from_env()` | `mcp` |
| `MCP_METRICS_TRACK_SESSIONS` | `MetricsConfig::from_env()` | `true` |
| `MCP_METRICS_MAX_SESSIONS` | `MetricsConfig::from_env()` | `10000` |
| `MCP_METRICS_BUCKETS_MS` | `MetricsConfig::from_env()` | `1,5,10,25,50,100,250,500,1000,2500,5000,10000` |
