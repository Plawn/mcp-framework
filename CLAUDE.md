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

### rmcp version & the MRTR response types

Pinned to **rmcp 3.1**. Two upstream changes shape every consumer `ServerHandler`:

- **MRTR (SEP-2322)** — `call_tool` / `get_prompt` / `read_resource` return `CallToolResponse` / `GetPromptResponse` / `ReadResourceResponse` (enums) instead of the `*Result` structs. A handler that produces a plain result appends `.into()`; `DynamicHandler` matches on `CallToolResponse::Complete` for audit and treats the non-terminal variants (`InputRequired`, `Task`) as successful dispatches.
- **Flat content model (rmcp 2.0)** — `Content` / `RawContent` / `Annotated<T>` collapsed into `ContentBlock`, and `Annotated<RawResource>` into a flat `Resource`. `prelude::Content` remains as a `#[deprecated]` alias of `ContentBlock`. Most wire types are `#[non_exhaustive]`, so build them with `Type::new(..).with_*(..)` rather than struct literals — and match them with a wildcard arm.

`DynamicHandler` also forwards the 3.x additions to the inner handler so wrapping stays transparent: `discover` (the 2026-07-28 replacement for `initialize` — it gets the same registry capability augmentation), `supported_protocol_versions`, `accepted_subscription_filter` / `listen`, `on_custom_request` / `on_custom_notification`, and the Tasks extension (`get_task` / `update_task` / `cancel_task`). The legacy `set_level` / `subscribe` / `unsubscribe` delegations are kept behind `#[allow(deprecated)]` because they still serve clients on older revisions.

### Transport layer (`src/transport/`)

Two modes selected via `--transport` CLI flag:
- **HTTP** (`http.rs`): Axum router with `rmcp::StreamableHttpService` at `/mcp`, OAuth well-known endpoints, CORS. `build_app()` is extracted as a pure function for testability.
- **Stdio** (`stdio.rs`): stdin/stdout via `rmcp` transport, used for Claude Desktop local integration.

### Auth layer (`src/auth/`)

`AuthProvider` enum drives which middleware and routes are registered:
- **None**: no auth middleware
- **Basic**: HTTP Basic auth middleware, credentials from `BASIC_AUTH_*` env vars
- **OAuth**: OAuth2/OIDC for Keycloak — RFC 8414/9728 metadata endpoints, RFC 7591 dynamic client registration, PKCE authorization flow, and (in the proxying token modes) token proxying. All OAuth routes live under `/oauth/`. How much of the flow is actually proxied depends on `TokenMode` — see below.

Key type: `TokenStore` — thread-safe token storage shared between auth middleware and the server handler via the factory closure. Supports automatic token refresh for OAuth mode.

#### Token modes (`TokenMode`)

When using OAuth, three modes are available. They differ on one question — **who holds the grant** — and everything else follows from the answer:

| | `Passthrough` (default) | `Opaque` | `ResourceServer` |
|---|---|---|---|
| What the client holds | the real Keycloak JWT | a framework UUID | the real Keycloak JWT |
| What the server keeps | access + refresh token | access + refresh token | **nothing** |
| Who refreshes | both (see below) | the framework | the client, alone |
| `/oauth/token` | proxied | proxied, response rewritten | not proxied (`404`) |
| `/oauth/authorize` | proxied | proxied | not proxied (`404`) |
| Bearer validation | store, then `validate_unknown_bearer` | opaque → store | `validate_unknown_bearer` only |
| Horizontal scaling | needs shared persistence | needs shared persistence | stateless |

- **Passthrough**: simple, but client and server co-own the same refresh token. Keycloak rotates refresh tokens, so the first server-side refresh invalidates the client's copy and the link breaks one cycle later. A platform logout also kills the MCP session.
- **Opaque**: the client never sees a JWT; the framework refreshes internally. Costs server-side state that every instance must share.
- **ResourceServer**: what MCP 2025-06-18 and later actually specify — the MCP server is an OAuth *resource server*, not an authorization server. See below.

Configurable via:
- `OAuthConfig` field: `token_mode: TokenMode::Opaque`
- Environment variable: `MCP_TOKEN_MODE=passthrough|opaque|resource_server` (default: `passthrough`, read by `OAuthConfig::from_env()`; `resource-server` is accepted as an alias)

`TokenMode` lives inside `OAuthConfig`, making misconfiguration structurally impossible (e.g. setting opaque mode with Basic auth).

**Architecture**: The `token_handler` (`src/auth/proxy.rs`) dispatches to either `passthrough_token_handler` or `opaque_token_handler` based on the configured `TokenMode`. In opaque mode, the handler intercepts the Keycloak response, stores the real token in `TokenStore`, generates opaque UUIDs, and returns those to the client. The `bearer_auth_middleware` (`src/auth/middleware.rs`) resolves opaque tokens back to real Keycloak tokens. Refresh requests are intercepted to swap opaque refresh tokens for real ones before contacting Keycloak.

In passthrough mode, the HTTP middleware treats tokens captured by `/oauth/token` as trusted grants and enforces the expiry recorded in `TokenStore`. A bearer unknown to the store (for example, a bring-your-own or token-exchange Keycloak token) goes through `TokenStore::validate_unknown_bearer` (see below). Inactive, malformed, expired, or unrefreshable credentials return `401` with the protected-resource `WWW-Authenticate` challenge before rmcp dispatches the request.

#### Pure resource server mode (`TokenMode::ResourceServer`)

The framework validates the inbound JWT locally and keeps **no** token state: no `TokenStore` entry, no server-side refresh, no proxied exchange. An expired or invalid bearer gets `401` plus the protected-resource `WWW-Authenticate` challenge; the client re-authenticates against the authorization server on its own, with a refresh token nobody else has touched.

`TokenMode::is_stateful()` is the single predicate every stateful path keys off — the token proxy, the legacy login flow, `TokenStore` writes, server-side refresh.

**Validation.** The middleware branches before any store access and calls the same `TokenStore::validate_unknown_bearer` described below, so the JWKS rules are unchanged: asymmetric algorithms only, keys cached by `kid`, rate-limited refetches, `iss` / `exp` / `nbf` / `aud` checked locally. `UnknownTokenValidation::Jwks` is the recommended policy — a pure resource server has no reason to ask the authorization server anything, and `reject` is refused outright (every bearer is "unknown" when the framework issues none).

**`OAUTH_EXPECTED_AUDIENCE` is mandatory here**, and `OAuthConfig::validate()` fails at boot without it (called from `McpAppBuilder::validate` and from `run_http_mode`, since `McpApp` can be built without the builder). The reason is not pedantry: this mode accepts a bearer on the strength of a signature alone, so an unconstrained `aud` would accept *every* token the issuer ever signed, including one minted for a different service — the confused-deputy case RFC 8707 and the MCP spec require a resource server to refuse. In the proxying modes the audience is implied by the fact that this server performed the exchange itself, which is why the check is scoped to this mode.

**What token consumers receive.** There is no store entry to look up, so the middleware attaches the validated credential to the request as a `RequestToken(StoredToken)` extension, and `resolve_token` (`src/capability/filter.rs`) prefers it over the store. rmcp injects the axum `http::request::Parts` — extensions included — into the MCP request context, which is how it survives the trip. Since every consumer path already funnels through `resolve_token`, capability filters, access validators and tool handlers see exactly what they see in the proxying modes:

- `access_token` — the bearer the client sent, verbatim
- `decoded_claims` — populated by the global claims decoder, as usual
- `expires_at` — from the JWT's `exp`
- `refresh_token` — **always `None`**. It belongs to the client and never reaches this process.

From a `RequestContext`, use `ctx.token()` (`RequestContextExt`) rather than `ctx.token_store().get_token(ctx.session_id())`: the latter returns `None` in this mode even though the request is perfectly authenticated.

**Session identity.** Unchanged from passthrough: `credential_session_key` derives a stable per-user key from the JWT's `sid` (else `sub`), injected under `MCP_FALLBACK_SESSION_HEADER`. `SessionStore<T>` therefore still works — it is application data, not credentials, and nothing about this mode says the application may not keep state.

**Routing.** Five paths stop proxying: `/oauth/token`, `/oauth/authorize`, `/oauth/login`, `/oauth/callback`, `/oauth/status`. They answer `404` with a reason rather than being absent from the router — an absent path falls through to the auth-wrapped MCP fallback and answers `401`, blaming the client's credentials for a route that does not exist.

`/oauth/token` is the point of the mode. `/oauth/authorize` goes with it for a reason worth stating: the proxy rewrites `client_id` to the configured `OAUTH_CLIENT_ID`, so the authorization code it returns is bound to *that* client, while the client then redeems it at Keycloak's token endpoint under its own `client_id` — `invalid_grant`. Half a proxied flow is worse than none. The legacy login routes perform the exchange server-side and write the grant into `TokenStore`, which is the state this mode abolishes.

**`/oauth/register` stays.** Keycloak's `clients-registrations/openid-connect` endpoint sends no CORS headers, so a browser-based MCP client cannot perform RFC 7591 dynamic client registration against it directly; the framework's translation is still needed. Its offline fallback now returns the **configured** `OAUTH_CLIENT_ID` instead of a fabricated UUID — nothing rewrites `client_id` downstream any more, so an invented id would simply not exist at Keycloak. (As before, that Keycloak client must allow the client's `redirect_uri`.)

**Discovery.** `/.well-known/oauth-protected-resource` (and `.../mcp`) advertises the Keycloak issuer in `authorization_servers` — RFC 9728, the resource server pointing at the AS instead of at itself. `/.well-known/oauth-authorization-server` is still served, because MCP 2025-03-26 clients probe the resource server for it and a `404` strands them, but it now describes **Keycloak**: `issuer`, `authorization_endpoint` and `token_endpoint` are Keycloak's, and only `registration_endpoint` remains ours (the CORS reason above). A welcome side effect: the advertised issuer finally matches the `iss` the tokens carry, which is the RFC 9207 mismatch rmcp's client reports as `AuthorizationServerIssuerMismatch` under passthrough.

**Migrating from passthrough.** The framework side is three settings:

```bash
MCP_TOKEN_MODE=resource_server
OAUTH_UNKNOWN_TOKEN_VALIDATION=jwks
OAUTH_EXPECTED_AUDIENCE=my-mcp-server   # mandatory; boot fails without it
```

What to check before flipping it:

1. **Keycloak must put that audience in the token.** Add an audience mapper to the client (or a client scope) so `aud` contains the value above. Without it every request 401s — the failure is loud, and the accepted `aud` / `azp` are logged on every acceptance in the other modes, which is how to read the right value off real traffic first.
2. **The client must handle its own refresh.** Any MCP client implementing 2025-06-18 does; a client that relied on the framework proxying `/oauth/token` will not.
3. **The Keycloak client must allow the client's `redirect_uri` directly**, since `/oauth/authorize` no longer rewrites anything.
4. **Server-side code that read `token.refresh_token` stops working** — that value is gone by design. Code reading `access_token` or `claims::<C>()` is unaffected.
5. **Existing sessions are not migrated.** Tokens the store holds from the previous mode are simply ignored; clients re-authenticate once.

**Calling an upstream API with the inbound bearer is forbidden, and the framework does not do it for you.** The MCP spec is explicit: a token issued for this resource server must not be forwarded to another service — that is the confused deputy the audience check exists to prevent, and it is exactly what "just pass the bearer through" does. Two supported paths:

- **Token exchange (RFC 8693)** — the server exchanges the inbound token for one whose `aud` is the upstream service. Requires a confidential client; the framework does not implement this, a consumer that needs it does the exchange in its own tool handler using the credential from `ctx.token()`.
- **An explicitly shared audience** — the deployment deliberately mints tokens carrying both services in `aud`, and both list each other in `OAUTH_EXPECTED_AUDIENCE`. Simpler, and correspondingly blunter: the two services become one trust boundary.

#### Validating bearers the proxy did not issue (`UnknownTokenValidation`)

RFC 7662 introspection used to be the only check available for such a bearer, and it is not always reachable: **Keycloak refuses the introspection endpoint to public clients**, answering `403 {"error":"invalid_request","error_description":"Client not allowed."}`. That refusal is a property of the configured `OAUTH_CLIENT_ID`, not of the token, so on a public-client deployment *every* unknown bearer was rejected — including a perfectly valid token-exchange token whose `aud` is the downstream service.

Verifying the signature against the issuer's published keys has no such requirement, so `validate_unknown_bearer` tries, in order:

1. **`TokenStore`** — a proxy-issued token is already trusted; it never causes a JWKS or introspection round-trip. (Not applicable in `ResourceServer` mode, where the store is always empty.)
2. **JWKS** (`src/auth/jwks.rs`) — `jwks_uri` discovered from `{issuer}/.well-known/openid-configuration`, keys cached by `kid`, signature plus `iss` / `exp` / `nbf` (and `aud`, when configured) checked locally.
3. **Introspection** — only if JWKS *could not answer*.

The order is governed by `OAUTH_UNKNOWN_TOKEN_VALIDATION` / `OAuthConfig::unknown_token_validation`:

| Value | Behaviour |
|---|---|
| `jwks_then_introspection` (default) | JWKS first, introspection as a fallback |
| `jwks` | local validation only — never contacts the authorization server |
| `introspection` | the pre-0.3 behaviour |
| `reject` | refuse every bearer the proxy did not issue |

Two properties are worth knowing:

- **A verdict from the issuer's own keys is final.** `JwksRejection::Invalid` (bad signature, wrong `iss`, expired) is *not* re-litigated through introspection; only `NotAJwt` / `UnknownKey` / `Unavailable` fall through. This is what keeps `jwks_then_introspection` as strict as `jwks`.
- **Fetches are rate-limited.** An unknown `kid` triggers a refetch (Keycloak rotates signing keys) but at most once per `JWKS_REFRESH_COOLDOWN`, and the cooldown keys off the last *attempt* — so neither a forged `kid` nor an issuer that is down can turn one inbound request into one outbound request. Keys already fetched survive a failed refresh.

`OAUTH_EXPECTED_AUDIENCE` (comma-separated) constrains `aud` on a locally validated token. It is empty by default **except in `ResourceServer` mode, where it is mandatory** (see above). Elsewhere it is empty because: a token-exchange token legitimately carries an audience this server was never told about, so refusing it out of the box would break the case this path exists for. The observed `aud` / `azp` are logged on every acceptance, which is how a deployment tightens the list from real traffic.

Rejections are typed (`BearerRejection`) so the logs separate the three cases the client cannot distinguish behind its uniform `401`: introspection not permitted (a server misconfiguration — warned once, then never retried), the token being genuinely invalid, and an unknown token validated locally via JWKS.

Only signature algorithms from asymmetric families are accepted, so the issuer's public key can never double as an HMAC shared secret (`alg` confusion).

**Session key at token exchange**: no MCP session exists yet when `/oauth/token` runs, so `mcp-session-id` is never present — reading it collapsed every grant, for every user, onto `"default"`. Each mode uses the key it can actually resolve later:

- **Passthrough** keys by `credential_session_key(access_token)`, the same derivation `bearer_auth_middleware` applies to the bearer it receives. When a protocol session id shows up later, the middleware **adopts** that entry under the session key — carrying over `refresh_token` / `expires_at`, and writing it *before* attempting refresh, since `get_token` operates on the session key.
- **Opaque** mints a fresh per-grant UUID. It cannot be derived from a credential: the client never sees the Keycloak token, and the opaque tokens it does see rotate on every refresh while this key must stay put. It is resolved from the opaque token instead, via `TokenStore::resolve_opaque_access`. The middleware then binds the request to that grant id via `MCP_FALLBACK_SESSION_HEADER`, so `ctx.session_id()` and the token store agree and a reconnect lands back on the same session.

**Retiring the superseded passthrough grant**: the key is derived from the access token, so a `refresh_token` grant stores the rotated credentials under a *new* key — and used to leave the previous entry behind. That entry still held the refresh token Keycloak had just rotated away, and the middleware would happily adopt it: refresh → `invalid_grant` → a spurious `401` for a client holding a perfectly good bearer. `/oauth/token` therefore indexes every passthrough grant by `sha256(refresh_token)` → `grant_key` in `NS_GRANT_REFRESH` (in memory, write-through to persistence, read-through on a memory miss — the same shape as `NS_OPAQUE_REFRESH`). On a `refresh_token` grant the handler resolves the spent refresh token to the grant it belongs to, removes that token entry and its index entry, *then* stores the new grant. The removal is skipped when the old key equals the new one. On this branch that never happens — a rotated access token always hashes to a different key — but the guard is what keeps the cleanup correct once identity is claims-derived (task 920's `sid`/`sub`), where both grants land on the same entry. **Limitation**: only the instance serving the refresh drops the entry from its own memory. A peer that already cached the old grant keeps treating it as trusted until it expires, since read-through fires only on a miss — the consistency caveat documented under *Persistence layer*. Left as-is on purpose: passthrough disappears with the arrival of a ResourceServer mode, so this is a transition-period mitigation, not a design to build on. Covered by `tests/passthrough_grant_cleanup.rs`, including a two-replica case sharing one backend (exchange on A, refresh on B, verified from a third store built fresh over persistence).

**Persistence**: The forward opaque mapping is stored in the `NS_OPAQUE` namespace (keyed by session_id). To support multi-instance read-through (resolving an opaque token on an instance that did not mint it), two inverse indexes are also persisted: `NS_OPAQUE_ACCESS` (`opaque_access → session_id`) and `NS_OPAQUE_REFRESH` (`opaque_refresh → session_id`). All survive restarts when a persistence backend (e.g. Redis) is configured. `resolve_opaque_access`/`resolve_opaque_refresh` fall back to the inverse index on a memory miss and then hydrate the full in-memory index from the forward mapping.

**Zombie handling**: When a Keycloak refresh fails (e.g. token revoked via platform logout), the opaque mapping is cleaned up and the client receives a 401, forcing re-authentication.

```rust
let mut oauth = OAuthConfig::from_env().unwrap();
oauth.token_mode = TokenMode::Opaque;

McpAppBuilder::new("my-server")
    .auth(AuthProvider::OAuth(oauth))
    .persistence(Arc::new(redis))
    .server(|| MyServer::new())
    .run()
    .await?;
```

### Session layer (`src/session/`)

`SessionStore<T>` — generic, thread-safe per-session data store with TTL expiration. The type parameter `T` (must implement `Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static`) is defined by the consumer. Default TTL is 30 minutes. A background cleanup task purges expired sessions in HTTP mode.

Helper function `resolve_session_id(extensions)` extracts the session identity from MCP request context extensions, falling back to `"default"` for stdio mode. It delegates to `session_id_from_parts(&Parts)`, shared with `resolve_token` in `src/capability/filter.rs` so both resolve identity identically.

#### Sessionless protocol revisions (MCP 2026-07-28 / SEP-2567)

MCP 2026-07-28 removes protocol-level sessions, so `mcp-session-id` is absent for clients negotiating that revision — and rmcp serves those requests statelessly regardless of `legacy_session_mode`. Since this framework keys `TokenStore`, `SessionStore<T>`, and the opaque-token mappings by session id, collapsing every such client onto `"default"` would let concurrent users read and overwrite each other's tokens.

The auth middleware therefore derives a stable identity from the credential when the protocol supplies none — `credential_session_key(cred)` — injected under `MCP_FALLBACK_SESSION_HEADER` (`x-mcp-framework-session`). The framework header is deliberately distinct from `mcp-session-id` — writing that one back onto the request would make rmcp's Streamable HTTP transport look up a session that never existed and reject it.

**The identity comes from claims, not from the bearer bytes.** Hashing the token was the original scheme and it does not survive a refresh: in a resource-server deployment the client's access token rotates every 5-15 minutes, so a byte-derived id changes with it and the `SessionStore<T>` entry it keyed is orphaned for its whole TTL. `credential_session_key` therefore reads the JWT payload (via `jwt_claim`) and takes the first stable thing it finds:

| source | key | stability |
|---|---|---|
| `sid` claim | `cred-sid-{sha256(sid)[..16]}` | Keycloak SSO session — unchanged across every refresh |
| `sub` claim | `cred-sub-{sha256(sub)[..16]}` | the principal — stable, but shared by all their SSO sessions |
| raw bytes | `cred-{sha256(credential)[..16]}` | rotates with the credential (non-JWT only: opaque bearers, Basic auth passwords) |

The three families carry distinct prefixes, so a `sid` value that happens to equal another token's `sub` can never collapse two identities into one.

Hashing keeps the literal claim out of logs and store keys — that is all it does. A truncated sha256 is unsalted and unkeyed, so a low-entropy `sub` (a username, an email, a sequential id) is dictionary-testable: anyone holding a candidate value can confirm it against an observed key. Real unlinkability would need an HMAC under a server-held secret, which is **not** implemented. Treat the derived id as pseudonymous, not confidential.

Claims are read through `jwt_payload`, which first checks that the credential is *shaped* like a JWT: exactly three non-empty dot-separated segments, a header decoding to a JSON object with a string `alg` (`typ` optional), and a payload decoding to a JSON object. Decoding only the second segment is not enough — plenty of opaque credentials contain dots, and one whose middle segment happens to be base64 JSON (`opaque.<b64 json>.handle`) would otherwise be keyed by claims it never asserts. Anything failing the shape check falls through to the byte-hash family.

`jwt_payload` decodes **without verifying the signature** (`jwt_claim`, `jwt_subject`, `jwt_is_expired` and `jwt_is_strictly_newer` all sit on top of it). That is deliberate and safe here: the values only *partition* state — which session id, which principal, which of two bearers is newer — and never grant access. Whether the bearer may be used at all is decided independently by `validate_unknown_bearer` (JWKS or introspection) before any of that state is written.

**Consequences on the passthrough store/adopt path.** `/oauth/token` keys its grant by `credential_session_key(access_token)`, so a `refresh_token` grant for the same SSO session now **replaces** that entry instead of adding a sibling: the store keeps one live entry per grant whose `refresh_token` is always the most recently issued one. On the middleware side a sessionless rotation now lands on the entry the previous bearer wrote, so it goes through the principal comparison (which accepts it — same `sub`, and additionally same derived key, which covers a token carrying `sid` but no `sub`).

**Invariant: an observed bearer never downgrades proxy-issued grant material.** A stable key means several bearers of one grant map to one entry, and HTTP orders none of them — once `/oauth/token` has refreshed the grant to `t2 + rt2`, a request already in flight with the superseded `t1` still arrives. Overwriting the entry with `t1 + None` would leave the grant permanently unrefreshable while the client believes otherwise. So when the entry under the key already carries a `refresh_token`, an arriving bearer that does not match it byte-for-byte may only *advance* it: the access token is replaced solely when `jwt_is_strictly_newer` says so (`iat`, falling back to `exp`), and the stored `refresh_token` is carried over either way. An older or unorderable bearer leaves the entry untouched and is still served — from the grant's material, which is why an expired straggler can be rescued by a server-side refresh instead of a spurious `401`. Carrying the refresh token forward is not a widening: both bearers were validated and belong to the same principal, which is the same reasoning that already permits `matching_grant_token` adoption. Entries with no refresh material (bring-your-own-token clients) are unaffected and rotate freely.

**Risks accepted.** Existing sessionless sessions get a new key at deploy: their `SessionStore<T>` data is lost once and the stale entries expire on their own within the 30 min TTL (tokens re-register on the next request). And two clients of the same user in the same SSO session share one identity — with a `sub`-only token, all of that user's sessions do. That is intended: it is the same human, and it is what makes a refresh transparent. A consumer needing per-connection rather than per-user state must key it itself.

**Precedence.** `session_id_from_parts` reads `MCP_FALLBACK_SESSION_HEADER` **first**, then `mcp-session-id`, then `DEFAULT_SESSION_ID`. The framework header wins because the middleware only writes it where it is the more accurate identity — either the protocol supplied nothing, or opaque mode resolved the grant (see below). On 2025-11-25 and earlier the middleware returns `mcp-session-id` untouched and never writes the framework header, so behaviour there is unchanged.

**Anti-spoofing.** Because the framework header is authoritative, `strip_framework_session_header` is layered outermost in `wrap_auth_middleware` and removes any client-supplied value before auth runs. It is applied to *every* request, including under `AuthProvider::None` where no auth middleware runs to overwrite it. Without it a client could send `x-mcp-framework-session: <victim-id>` and bind its request to another user's tokens.

Covered by `tests/session_identity.rs`, which drives the real `build_app` router (strip layer + auth middleware) through an `extra_routes` handler that echoes `session_id_from_parts`, and by `tests/oauth_passthrough_identity.rs` for the claims-derived key end to end (refresh keeps one identity, two SSO sessions of one user stay isolated).

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

### Effectiveness metrics (`src/metrics/`, feature `metrics`)

Opt-in, feature-gated aggregation of tool call effectiveness. Compiled out entirely unless the `metrics` cargo feature is enabled — zero cost (no module, no fields populated) otherwise.

The `MetricsCollector` **is** a `ToolCallLogger`: it consumes the same `ToolCallRecord` stream as audit logging, so there is no new interception point and no added tool-call latency. `.metrics(collector)` composes with any logger already set via `.tool_call_logger()` (both receive every record, via `CompositeLogger`).

What's measured (cumulative since process start):
- **Per tool**: call frequency, success / `tool_error` / `mcp_error` counts, success & error rates, latency p50/p95/p99 + mean. Percentiles come from a bounded-memory bucketed histogram (`histogram.rs`), interpolated like Prometheus `histogram_quantile` — no per-call sample retention.
- **Per session**: call count, error rate, per-tool distribution. Cardinality-capped (`max_sessions`).

Exposure (both, answering the ticket's open question):
- **In-process**: `collector.snapshot() -> MetricsSnapshot` (serde-serializable; per-tool + per-session). Works in stdio mode too.
- **HTTP endpoint**: served *outside* the auth layer (so a Prometheus scraper needs no credentials) at `MetricsConfig::endpoint_path` (default `/metrics`). Prometheus text by default; `?format=json` returns the snapshot. Per-session data is JSON-only — session ids would explode Prometheus label cardinality, so the exposition emits per-tool series + an `mcp_active_sessions` gauge.

Key types: `MetricsCollector`, `MetricsConfig` (with `Default` and `from_env`), `MetricsSnapshot` / `ToolMetrics` / `SessionMetrics`. The endpoint is mounted via the general `public_routes: Option<Router>` field (the un-authed counterpart to `extra_routes`, threaded through `McpApp` → `HttpAppConfig`); `.metrics()` merges its router there. `public_routes` is a feature-independent type, so there's no `cfg` churn on struct literals, and it doubles as the mounting point for health checks / probes via `McpAppBuilder::public_routes`.

```rust
use mcp_framework::prelude::*;

let metrics = MetricsCollector::new(MetricsConfig::default());

McpAppBuilder::new("my-server")
    .metrics(metrics.clone())     // logs records + mounts /metrics
    .server(|| MyServer::new())
    .run()
    .await?;

// query in-process anytime:
let snap = metrics.snapshot();
println!("{} calls, p95 of busiest tool: {:?}ms",
    snap.total_calls, snap.tools.first().map(|t| t.p95_ms));
```

Enable the feature in `Cargo.toml`: `mcp-framework = { version = "0.1", features = ["metrics"] }`.

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

### Tool schema sanitization (`src/capability/sanitize.rs`)

`sanitize_tool_schemas` rewrites every `Tool` on its way to `tools/list`, so the
schema schemars emits is one an MCP client actually accepts. It runs, in order:

1. **`$schema` / `title` stripping** at every nesting level. `title` is *folded
   into `description`* first when the node has none — a `#[schemars(title =
   "...")]` or a type name is sometimes the only documentation there is, and it
   is what the LLM would otherwise never see. Once a `description` is present,
   the title is dropped as before.
2. **`$defs` inlining** — `$ref` pointers are resolved recursively, sibling keys
   merged per JSON Schema semantics (`properties` deep-merged, `required`
   unioned, everything else overriding).
3. **Root-level `oneOf` / `anyOf` / `allOf` flattening** — the Anthropic API
   rejects a combinator at the root of `input_schema`, and schemars emits one
   for every `#[serde(tag = "...")]` tagged enum. The variants' properties are
   merged into one flat object with a synthesized `string` `enum` discriminator.
4. **`"type": "object"` patching** for schemas that have no `type` (e.g. a
   `serde_json::Value` parameter), with a `tracing::warn!`.
5. **A documentation audit** (`audit_descriptions`), warned once per tool
   *version*.

**Flattening keeps the documentation.** Flattening is lossy by nature — runtime
`serde` still enforces the real per-variant contract, but the schema can no
longer express it. What it must *not* lose is what `tools/list` exposes as prose:

- the synthesized discriminator carries the composed variant docs,
  ``` `add`: Add a note · `remove`: Remove a note ``` (an undocumented variant
  contributes just its value; if none is documented, no description is invented
  — the `enum` already lists the values);
- every other property states the variants that require it, appended to its own
  description: `Required when action=add, remove.` This is the only place the
  per-variant `required` survives;
- a property name shared by several variants still resolves first-wins, but a
  description from a later variant fills in for a missing one.

**The audit** is a pure `audit_descriptions(&Tool) -> Vec<String>`; the logging
and the deduplication live in `DescriptionAudit`, so the rule is testable
without capturing `tracing` output. It reports a tool with no `description`,
and — in a single aggregated finding, to keep the log readable on a large
server — the input-schema properties that have none. It runs **after**
sanitization, so a description folded from a `title` counts as documentation,
and a blank description counts as none.

**Where it runs, and how often.** `tools/list` alone would be both too late and
too often: a tool registered but never listed would never be checked, while a
polling client would re-log the same finding on every call. So:

- **dynamic tools are audited at registration** (`CapabilityRegistry::add_tool`
  / `add_tool_with_context`), on a throwaway sanitized copy — the author sees
  the warning even if no client ever connects;
- **inner-handler tools** are only observable at list time, so they are audited
  there;
- both paths share **one** `DescriptionAudit`, owned by the registry and handed
  to `DynamicHandler`. It keeps the set of tool versions already audited, keyed
  by a hash of name + description + input schema — so a tool warns once, and
  again only if it is edited.

### Persistence layer (`src/persistence.rs`)

`PersistenceBackend` trait — async key-value interface with namespace separation (`"tokens"`, `"sessions"`). Both `TokenStore` and `SessionStore<T>` accept an optional backend via `.with_persistence()` or `.set_persistence()`. When configured:

- **Write-through**: mutations (`store_token`, `update`, `remove`, `purge_expired`) are written to the backend asynchronously (fire-and-forget via `tokio::spawn`)
- **Load-at-startup**: `load_persisted()` reads all keys from the backend and populates the in-memory store. Called automatically during `run()` before the listener starts
- **Read-through**: on a memory miss, the read paths (`TokenStore::get_token_raw`, `TokenStore::resolve_opaque_*`, `SessionStore::get`) fall back to the backend, deserialize, and write-back into the in-memory cache. This is what makes **multi-instance / horizontal scaling without sticky sessions** work: a request that lands on an instance which did not create the session still resolves the token/opaque-mapping/session from Redis instead of returning a 401. A memory hit never touches the backend (zero overhead on the hot path).
- **No backend = current behavior**: zero overhead, no serialization

**Distributed refresh lock**: the `PersistenceBackend` trait exposes `try_acquire_lock(ns, key, token, ttl)`/`release_lock(ns, key, token)` (default: no-op that always acquires; `RedisBackend` overrides with atomic `SET key token NX PX`, `InMemoryBackend` with an in-process lock map). The caller passes a unique per-acquisition `token` (a fresh UUID); `release_lock` is **compare-and-delete** (Redis: a Lua `GET==token then DEL` script) so a late release after TTL expiry cannot drop a lock a peer has since re-acquired. On token expiry, `TokenStore::get_token` first takes the process-local per-session lock, then the distributed lock (`NS_REFRESH_LOCK`) before refreshing — serializing refresh across instances so Keycloak refresh-token rotation isn't broken by concurrent refreshes (distributed thundering herd). While a peer holds the lock, the waiter polls persistence and **adopts** the peer's refreshed token instead of issuing a duplicate refresh. `REFRESH_LOCK_TTL` auto-expires a crashed holder's lock, and `REFRESH_LOCK_WAIT` is kept above it so a waiter eventually acquires rather than racing.

**Consistency caveat**: read-through resolves the "never seen on this instance" case. A value that was *updated* on a peer after being cached locally can still be served stale until it expires (read-through only fires on a miss, by design — to keep zero overhead on hits). For tokens this is bounded: on expiry the refresh path re-reads persistence and adopts a peer's fresh token. For session data, callers needing strict cross-instance freshness should not rely on the local cache for mutable shared state.

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
| `MCP_TOKEN_MODE` | `OAuthConfig::from_env()` | `passthrough` (also `opaque`, `resource_server`) |
| `OAUTH_UNKNOWN_TOKEN_VALIDATION` | `OAuthConfig::from_env()` | `jwks_then_introspection` (also `jwks`, `introspection`, `reject`) |
| `OAUTH_EXPECTED_AUDIENCE` | `OAuthConfig::from_env()` | — (comma-separated; empty = `aud` unconstrained — **required** when `MCP_TOKEN_MODE=resource_server`) |
| `MCP_METRICS_PATH` | `MetricsConfig::from_env()` (feature `metrics`) | `/metrics` (`off`/empty disables) |
| `MCP_METRICS_NAMESPACE` | `MetricsConfig::from_env()` | `mcp` |
| `MCP_METRICS_TRACK_SESSIONS` | `MetricsConfig::from_env()` | `true` |
| `MCP_METRICS_MAX_SESSIONS` | `MetricsConfig::from_env()` | `10000` |
| `MCP_METRICS_BUCKETS_MS` | `MetricsConfig::from_env()` | `1,5,10,25,50,100,250,500,1000,2500,5000,10000` |
