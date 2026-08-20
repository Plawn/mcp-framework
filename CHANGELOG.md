# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: breaking changes bump the minor version).

> History before `0.2.0` was not retro-documented; see `git log` for earlier releases.

## [0.3.1] — Unreleased

### Added — `transport::loopback`, an in-process caller that is a real client

An application embedding this framework often calls its own tools from inside
the same process — an agent loop, a scheduler, a chat turn. Doing that through
a hand-held executor puts those calls *underneath* the protocol, so none of
what the framework applies on the MCP path applies to them: no
`ToolCallLogger`, no metrics, no `CapabilityFilter`, no `AccessValidator`. The
divergence is silent — the calls work, they are simply neither audited nor
filtered.

- **`LoopbackEndpoint::connect(identity)`** returns a `LoopbackSession` that
  derefs to a `Peer<RoleClient>`. The transport is a pair of typed
  `futures::channel::mpsc` halves (`ClientJsonRpcMessage` /
  `ServerJsonRpcMessage`) — no byte serialisation — driving the **same**
  `DynamicHandler` as HTTP, so every hook applies with no exception to write.
- **Identity is not a second mechanism.** `LoopbackIdentity::to_parts()`
  synthesises `http::request::Parts` carrying `mcp-session-id` and
  `Authorization`, so `resolve_session_id` / `resolve_token` remain the only
  resolution path.
- **`TokenMode::Opaque` is refused at connect time**
  (`LoopbackConnectError::UnresolvableCredential`): a framework-issued bearer is
  resolvable only through the HTTP transport's `TokenStore`, and letting it
  through would make the call anonymous rather than authenticated.
- **The endpoint owns its stores.** An in-process caller's session id usually
  comes from *its* client; sharing the HTTP transport's `SessionStore` would put
  an externally-reachable collision between the two surfaces. The endpoint keeps
  its own `TokenStore`, `SessionStore` and `token_mode`.
- **`LoopbackSession` cancels both ends on drop**, and a failed handshake aborts
  the server task — evicting an entry from a cache closes the connection, it
  does not leak a task.
- **`McpAppBuilder::validate()` refuses a divergent builder.** A
  `capability_filter` (or any other setting) applied *after* `loopback()` used
  to miss the loopback surface silently; construction now fails, naming the
  field.

### Added — `ToolCallContext.session_id`

A tool handler now knows which session its call came from. Without it, every
tool needing that fact becomes one more special case in the application's
wiring.

### Added — a documentation audit at tool registration, and a `title` fallback

Tool and parameter descriptions come from `///` doc comments (via schemars) or
from the manual `Tool::new` argument. Nothing flagged a tool or a property left
without one — the call still works, and the only symptom is an LLM picking the
wrong tool or the wrong argument.

- `audit_descriptions(&Tool) -> Vec<String>` reports the deficits (the tool
  itself, then one aggregated finding listing the undocumented parameters);
  `DescriptionAudit` logs them as a single `tracing::warn!` per tool, alongside
  the existing "missing type" warning. The rule is pure, so it is tested without
  capturing `tracing` output.
- **Dynamic tools are audited at registration**, not only when a client lists
  them: `add_tool` / `add_tool_with_context` audit a throwaway sanitized copy,
  so a tool that is registered but never listed is still checked. Inner-handler
  tools, observable only at list time, keep being audited there.
- Both paths share the registry's `DescriptionAudit`, which remembers the tool
  versions it has already reported (hash of name + description + input schema).
  A polling client no longer turns the audit into a log flood, and an edited
  tool is audited again.
- `title` is no longer dropped outright: it is folded into `description` when
  the node has none, at every nesting level, and still stripped when a
  description is already there. It was sometimes the only doc a type carried.
  The audit runs after sanitization, so a folded title counts as documentation.

### Fixed — descriptions survive the tagged-enum flattening

`sanitize_tool_schemas` flattens the root-level `oneOf` schemars emits for
`#[serde(tag = "...")]` enums, because the Anthropic API rejects a combinator
at the root of `input_schema`. The flattening used to throw away everything
`tools/list` exposes as documentation: each variant's doc comment, the
per-variant `required`, and — on a property name shared by several variants —
any description the first variant did not happen to carry.

- The synthesized discriminator now carries the composed variant docs:
  ``` `add`: Add a note · `remove`: Remove a note ``` (an undocumented variant
  contributes just its value; if no variant is documented, no description is
  invented).
- Every other property states the variants that require it:
  `Required when action=add, remove.`, appended to its own description. This is
  the only place the per-variant `required` can survive a flat object schema.
- A homonymous property across variants still resolves first-wins, but a
  description from a later variant now fills in for a missing one.
- A blank description counts as no description throughout (one `nonblank`
  helper): a whitespace-only string on an earlier variant no longer shuts out a
  real description from a later one, and it is never used as the discriminator's
  fallback. This is the rule the documentation audit already applied.

### Dependencies

- added `futures` `0.3` — the `Sink`/`Stream` halves of the loopback transport
- `rmcp` gains the `client` feature (the loopback's own end is a client)

## [0.3.0] — Unreleased

### Added — local (JWKS) validation of bearers the proxy did not issue

Keycloak refuses the RFC 7662 introspection endpoint to **public** clients
(`403 {"error":"invalid_request","error_description":"Client not allowed."}`).
Since introspection was the only check available for a bearer absent from
`TokenStore`, a public-client deployment in `TokenMode::Passthrough` rejected
every such token with `401` at MCP `initialize` — including a valid
token-exchange token minted for a downstream audience.

- **`src/auth/jwks.rs`.** OIDC discovery → `jwks_uri` → key set, cached by `kid`
  with a TTL. An unknown `kid` triggers a refetch (signing keys rotate), but at
  most once per cooldown, and the cooldown keys off the last *attempt* — so
  neither a forged `kid` nor an unreachable issuer turns one inbound request
  into one outbound request. Keys already held survive a failed refresh.
  Asymmetric algorithms only (`alg` confusion).
- **`TokenStore::validate_unknown_bearer`.** Order: `TokenStore` (a
  proxy-issued token causes no round-trip at all) → JWKS → introspection. A
  verdict from the issuer's own keys is *final*: only "could not answer"
  (`NotAJwt` / `UnknownKey` / `Unavailable`) falls through, so the default
  policy is no weaker than `jwks` alone.
- **Typed `BearerRejection`** replaces the previous boolean, separating in the
  logs what the client's uniform `401` cannot: introspection not permitted (a
  server misconfiguration — warned once per store, then never retried), an
  invalid token, and a token accepted locally via JWKS.

**Breaking for consumers** building `OAuthConfig` with a struct literal: two
new fields, `unknown_token_validation` and `expected_audiences`.
`OAuthConfig::from_env()` reads them from `OAUTH_UNKNOWN_TOKEN_VALIDATION`
(`jwks` | `introspection` | `jwks_then_introspection` | `reject`, default
`jwks_then_introspection`) and `OAUTH_EXPECTED_AUDIENCE` (comma-separated,
empty = `aud` unconstrained). Existing behaviour is preserved by
`OAUTH_UNKNOWN_TOKEN_VALIDATION=introspection`.

### Dependencies

- added `jsonwebtoken` `11` (`rust_crypto` + `use_pem`, no default features) —
  the pure-Rust provider, so the build needs no C toolchain

## [0.2.0] — 2026-08-05

### Changed — rmcp 1.7 → 3.1

The `rmcp` dependency moved from a pinned `=1.7` to `3.1`, crossing three major
versions (1.8, 2.x, 3.x). The JSON wire format is unchanged; the breaking
changes are at the Rust API level and **propagate to consumers** that implement
`ServerHandler` themselves.

#### Breaking for consumers

- **Tool / prompt / resource handlers return the MRTR response enums**
  (SEP-2322, multi round-trip requests). `ServerHandler::call_tool`,
  `get_prompt`, and `read_resource` now return `CallToolResponse`,
  `GetPromptResponse`, and `ReadResourceResponse` instead of the corresponding
  `*Result` structs. Existing handlers that build a plain result compile again
  by appending `.into()`:

  ```rust
  // before
  ) -> impl Future<Output = Result<CallToolResult, McpError>> + Send + '_ {
      Ok(CallToolResult::success(vec![Content::text(msg)]))

  // after
  ) -> impl Future<Output = Result<CallToolResponse, McpError>> + Send + '_ {
      Ok(CallToolResult::success(vec![ContentBlock::text(msg)]).into())
  ```

  Handlers registered on `CapabilityRegistry` are **unaffected** — they still
  return `CallToolResult` and the framework converts.

- **Flat content model.** `Content` / `RawContent` / `Annotated<T>` collapsed
  into the `ContentBlock` union, and `RawResource` / `Annotated<RawResource>`
  into a flat `Resource`. Field access changes from `resource.raw.uri` to
  `resource.uri` and from `content.raw.as_text()` to `content.as_text()`.
  `prelude::Content` is kept as a `#[deprecated]` alias of `ContentBlock`, so
  `Content::text(..)` still compiles with a warning.

- **Most wire types are `#[non_exhaustive]`.** Struct-literal construction from
  downstream crates no longer compiles; use `Type::new(..).with_*(..)`. Matching
  on `ContentBlock` now requires a wildcard arm.

- **`Meta` was split** into `MetaObject` / `RequestMetaObject` /
  `NotificationMetaObject`; the `Meta` alias is gone.
  `ToolCallContext::meta` is now a `RequestMetaObject`.

- **MSRV is Rust 1.88** upstream. This crate already pins nightly via
  `rust-toolchain.toml`, so nothing changes here.

#### Added — `DynamicHandler` forwards the new `ServerHandler` surface

`DynamicHandler` wraps the consumer's handler, so any trait method it does not
delegate silently falls back to rmcp's default instead of the consumer's
implementation. The 3.x additions are now forwarded:

- `discover` — the 2026-07-28 replacement for the `initialize` handshake. It
  receives the same registry capability augmentation as `initialize`, so
  registry-backed tools/prompts/resources are advertised on sessionless
  revisions too.
- `supported_protocol_versions`
- `accepted_subscription_filter` / `listen` — the 2026-07-28 replacement for
  `resources/subscribe`.
- `on_custom_request` / `on_custom_notification`
- `get_task` / `update_task` / `cancel_task` — the Tasks extension (SEP-2663),
  needed because a tool may now answer with `CallToolResponse::Task`.

`set_level`, `subscribe`, and `unsubscribe` are deprecated upstream
(SEP-2577 / SEP-2567) but still delegated behind `#[allow(deprecated)]`: they
remain the only path for clients on older protocol revisions.

#### Fixed — session isolation on sessionless protocol revisions

MCP 2026-07-28 (SEP-2567) removes protocol-level sessions, and rmcp 3.x serves
requests negotiating that revision statelessly regardless of
`legacy_session_mode`. Because rmcp advertises 2026-07-28 by default, upgrading
would otherwise have let every such client collapse onto the shared
`"default"` session id — concurrent users reading and overwriting each other's
entries in `TokenStore` and `SessionStore<T>`.

The auth middleware now derives a stable per-credential identity when the
protocol supplies none (`cred-{sha256(credential)[..16]}`) and injects it under
a new `x-mcp-framework-session` header, which `session_id_from_parts` reads.
Behaviour on 2025-11-25 and earlier is byte-for-byte unchanged: on those
revisions `mcp-session-id` is present, the middleware returns it untouched, and
the framework header is never written.

The framework header is deliberately *not* `mcp-session-id`: writing that back
onto the request would make rmcp's Streamable HTTP transport look up a session
that never existed and reject the request.

`session_id_from_parts` reads the framework header **in preference to**
`mcp-session-id`, because the middleware only writes it where it is the more
accurate identity — see the opaque-mode fix below. To keep that precedence safe,
`strip_framework_session_header` is layered outermost on every request (including
under `AuthProvider::None`, where no auth middleware runs) and removes any
client-supplied value before auth sees it. Without it a client could send
`x-mcp-framework-session: <victim>` and bind its request to another user's
tokens.

#### Fixed — every OAuth grant landed on the same `"default"` session

`/oauth/token` keyed its `TokenStore` entry by the `mcp-session-id` request
header. That header is never present on a token exchange — the MCP session does
not exist yet — so every grant, for every user, was stored under `"default"`.

- In **passthrough** mode each new login overwrote the previous user's entry, and
  the `refresh_token` captured at the exchange was unreachable from the session
  the client later connected under, so server-side refresh could never fire.
- In **opaque** mode it was worse: `store_opaque_mapping` on the shared key also
  *revoked* the previous user's opaque tokens, logging them out on someone else's
  login.

Each mode now uses the key it can actually resolve later:

- **Passthrough** keys by `credential_session_key(access_token)` — the same
  derivation `bearer_auth_middleware` applies to the bearer it receives, so the
  middleware finds the entry again. When a protocol session id shows up later,
  the middleware **adopts** that entry (carrying over `refresh_token` /
  `expires_at`) under the session key before attempting refresh.
- **Opaque** mints a fresh per-grant UUID. It cannot derive the key from a
  credential: the client never sees the Keycloak token, and the opaque tokens it
  does see rotate on every refresh while the key must stay put. It is resolved
  from the opaque token instead, via `TokenStore::resolve_opaque_access`.

The opaque branch of `bearer_auth_middleware` now also binds the request to the
resolved grant id via the framework header, so `ctx.session_id()` and the token
store agree and a reconnect lands back on the same session — the reason
`session_id_from_parts` prefers that header over `mcp-session-id`.

#### Audit logging

`ToolCallOutcome` gained coverage for non-terminal MRTR responses. A tool that
answers with `InputRequired` or `Task` is recorded as a successful dispatch with
a `<input_required>` / `<task>` content summary rather than being dropped.

#### Notes / not yet adopted

- `StreamableHttpServerConfig::stateful_mode` was renamed
  `legacy_session_mode`; the framework uses the default (`true`), so legacy
  sessions still work exactly as before.
- rmcp 3.1 adds `StreamableHttpServerConfig::session_store` for cross-instance
  session recovery. It is not wired up yet — it overlaps with this crate's own
  Redis-backed read-through and is a candidate for a follow-up.

### Added — multi-instance token and session resolution

(Work already present in the tree, released together with the above.)

- **Read-through persistence.** On a memory miss, `TokenStore::get_token_raw`,
  `TokenStore::resolve_opaque_*`, and `SessionStore::get` fall back to the
  persistence backend and write the value back into the in-memory cache. This
  is what makes horizontal scaling without sticky sessions work: a request
  landing on an instance that did not create the session resolves from Redis
  instead of returning 401. A memory hit never touches the backend.
- **Inverse opaque-token indexes.** `NS_OPAQUE_ACCESS`
  (`opaque_access → session_id`) and `NS_OPAQUE_REFRESH`
  (`opaque_refresh → session_id`) are persisted alongside the forward mapping so
  an opaque token can be resolved on an instance that did not mint it.
- **Distributed refresh lock.** `PersistenceBackend` gained
  `try_acquire_lock(ns, key, token, ttl)` / `release_lock(ns, key, token)`
  (default no-op; `RedisBackend` uses atomic `SET NX PX`, `InMemoryBackend` an
  in-process map). `release_lock` is compare-and-delete via a Lua
  `GET == token then DEL`, so a late release after TTL expiry cannot drop a lock
  a peer has since re-acquired. On token expiry, `TokenStore::get_token` takes
  the process-local lock and then the distributed one before refreshing —
  serializing refresh across instances so Keycloak refresh-token rotation is not
  broken by a distributed thundering herd. A waiter polls persistence and adopts
  the peer's refreshed token instead of issuing a duplicate refresh.

**Known consistency caveat:** read-through only fires on a miss (by design, to
keep hits free). A value updated on a peer after being cached locally can be
served stale until it expires. For tokens this is bounded — the refresh path
re-reads persistence on expiry. Callers needing strict cross-instance freshness
for mutable session data should not rely on the local cache.

### Dependencies

- `rmcp` / `rmcp-macros` `1.7.0` → `3.1.0`
- `sse-stream` `0.2.3` → `0.2.5`
- added `sha2` `0.10` (direct; already present transitively via `oauth2`)
- added `tower` `0.5` as a **dev**-dependency (`ServiceExt::oneshot`, to drive
  the router in-process in `tests/session_identity.rs`)
