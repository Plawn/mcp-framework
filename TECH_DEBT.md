# Tech Debt

## HTTP transport

- **Outer-app extension point for unauthenticated routes.** `HttpAppConfig::extra_routes` only lets consumers register routes *inside* the auth wrapper. There is no way to add an unauthenticated endpoint (e.g. `/health`, `/metrics`) next to `/.well-known/*` and `/oauth/*`. If a consumer needs this, we would need a second field (e.g. `public_routes: Option<Router>`) merged into the outer `app` before `fallback_service(mcp_router)`.

- **Silent `/mcp` shadowing in `extra_routes`.** A route registered at `/mcp` inside `extra_routes` silently shadows the MCP fallback with no startup warning. `Router::merge` panics on collisions between registered routes, but cannot detect collisions with a `fallback_service`. Currently documented as "avoid" in the field doc — a debug-assert or startup warning scanning `extra_routes` for `/mcp` would be more defensive.

## Builder plumbing

- **Field propagation boilerplate in `McpAppBuilder`.** Every optional field (`capability_filter`, `access_validator`, `claims_decoder`, `session_store`, `tool_call_logger`, `extra_routes`, …) is copied field-by-field through `with_sessions`, `with_factory`, and `build`. Adding a new field touches ~5 sites. A struct-update helper or a macro could cut the tax, but the refactor is broader than any single feature PR.

## OAuth / opaque token mode

- **`TokenMode` should live inside `OAuthConfig`, not as an independent field.** `TokenMode` is threaded as a standalone field through `McpApp`, `McpAppBuilder`, `HttpAppConfig`, `McpOAuthState`, and `AuthMiddlewareState`, yet it is only meaningful for `AuthProvider::OAuth`. Setting `TokenMode::Opaque` with `AuthProvider::Basic` is a silent misconfiguration. Moving `TokenMode` into `OAuthConfig` would eliminate ~10 lines of per-struct boilerplate, make misconfiguration structurally impossible, and subsume `TokenMode::from_env()` into `OAuthConfig::from_env()`. Deferred because it changes the public API surface across 6 types and all consumers.

- **`token_handler` mixes passthrough and opaque logic inline.** The handler has two opaque-mode branch points interleaved with passthrough logic: an early return for `grant_type=refresh_token`, and a post-Keycloak-response replacement. A wrapping handler pattern (`opaque_token_handler` delegating to `passthrough_token_handler`) would cleanly separate concerns. Not urgent with only two branch points, but would become worthwhile if a third token mode or more grant types are added.

## Capability registry

- **No integration test for `call_tool_with_context` happy path.** The `WithContext` error path (no context) has unit tests, but the happy path (`Some(ctx)`) cannot be tested in `registry_tests.rs` because `Peer<RoleServer>` can only be constructed inside the `rmcp` crate. An integration test that sets up a full MCP connection would be needed to cover this.
