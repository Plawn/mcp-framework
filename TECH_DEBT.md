# Tech Debt

## HTTP transport

- **Outer-app extension point for unauthenticated routes.** `HttpAppConfig::extra_routes` only lets consumers register routes *inside* the auth wrapper. There is no way to add an unauthenticated endpoint (e.g. `/health`, `/metrics`) next to `/.well-known/*` and `/oauth/*`. If a consumer needs this, we would need a second field (e.g. `public_routes: Option<Router>`) merged into the outer `app` before `fallback_service(mcp_router)`.

- **Silent `/mcp` shadowing in `extra_routes`.** A route registered at `/mcp` inside `extra_routes` silently shadows the MCP fallback with no startup warning. `Router::merge` panics on collisions between registered routes, but cannot detect collisions with a `fallback_service`. Currently documented as "avoid" in the field doc — a debug-assert or startup warning scanning `extra_routes` for `/mcp` would be more defensive.

## Builder plumbing

- **Field propagation boilerplate in `McpAppBuilder`.** Every optional field (`capability_filter`, `access_validator`, `claims_decoder`, `session_store`, `tool_call_logger`, `extra_routes`, …) is copied field-by-field through `with_sessions`, `with_factory`, and `build`. Adding a new field touches ~5 sites. A struct-update helper or a macro could cut the tax, but the refactor is broader than any single feature PR.
