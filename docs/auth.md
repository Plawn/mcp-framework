# Authentication (`src/auth/`)

Token modes, resource-server mode, bearer validation, and the OAuth lifecycle harness.
Overview and defaults: [CLAUDE.md](../CLAUDE.md).

## Providers

`AuthProvider` enum drives which middleware and routes are registered:
- **None**: no auth middleware
- **Basic**: HTTP Basic auth middleware, credentials from `BASIC_AUTH_*` env vars
- **OAuth**: OAuth2/OIDC for Keycloak — RFC 8414/9728 metadata endpoints, RFC 7591 dynamic client registration, PKCE authorization flow, and (in the proxying token modes) token proxying. All OAuth routes live under `/oauth/`. How much of the flow is actually proxied depends on `TokenMode` — see below.

Key type: `TokenStore` — thread-safe token storage shared between auth middleware and the server handler via the factory closure. Supports automatic token refresh for OAuth mode.

### Token modes (`TokenMode`)

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

### Pure resource server mode (`TokenMode::ResourceServer`)

The framework validates the inbound JWT locally and keeps **no** token state: no `TokenStore` entry, no server-side refresh, no proxied exchange. An expired or invalid bearer gets `401` plus the protected-resource `WWW-Authenticate` challenge; the client re-authenticates against the authorization server on its own, with a refresh token nobody else has touched.

`TokenMode::is_stateful()` is the single predicate every stateful path keys off — the token proxy, the legacy login flow, `TokenStore` writes, server-side refresh.

**Validation is JWKS-only, structurally.** The middleware branches before any store access and calls `TokenStore::validate_bearer_via_jwks` — *not* the policy-driven `validate_unknown_bearer` used by the proxying modes. The JWKS rules themselves are unchanged (asymmetric algorithms only, keys cached by `kid`, rate-limited refetches, `iss` / `exp` / `nbf` / `aud` checked locally), but introspection is not reachable from this path at all.

The reason is the mandatory audience check below. RFC 7662 introspection answers "is this token active?" — it does not tell this server that the token was minted *for* it, and the framework accepts an `active: true` response without re-deriving `iss` / `aud`. Leaving introspection available as a fallback would therefore hand back the confused-deputy hole the `aud` check exists to close: a token for another service, or an opaque token this server cannot even read, would be accepted the moment JWKS declined it. So `OAuthConfig::validate()` settles the policy at boot:

| `OAUTH_UNKNOWN_TOKEN_VALIDATION` | In `ResourceServer` mode |
|---|---|
| `jwks` | used as-is |
| `jwks_then_introspection` (the default) | **coerced to `jwks`**, with a startup `tracing::warn!` naming the coercion |
| `introspection` | **boot error** — the mode cannot honour it |
| `reject` | **boot error** — every bearer is "unknown" when the framework issues none |

The default is coerced rather than refused so that an env file written for passthrough still boots. `OAuthConfig::effective_unknown_token_validation()` exposes the same resolution, and `configure_unknown_bearer_validation` uses it, so the store cannot be left holding a policy the middleware would not honour.

**A protocol session belongs to the principal that opened it.** The proxying modes get this for free: passthrough compares the inbound bearer's principal against the token already bound to the session and 401s a mismatch, and opaque resolves the session id *from* the opaque token, overwriting whatever `mcp-session-id` the client sent. Resource-server mode keeps no token state, which removed that comparison — so Bob, holding a valid JWT of his own, could send Alice's `mcp-session-id` and land inside Alice's rmcp session and `SessionStore` entry.

`SessionBindings` (`src/auth/binding.rs`) closes it: after JWT validation, when the client supplied a protocol session id, the middleware claims `session_id → credential_session_key(bearer)` — the `sha256`-derived identity, never token material. The first request establishes the binding; a later request presenting a different identity gets `401`. The table is bounded (`SESSION_BINDING_MAX_ENTRIES`) and expires with the transport session TTL, and is written through to persistence under `NS_SESSION_BINDING` so a peer instance behind a round-robin load balancer enforces the same binding. Keying on `sid`/`sub` rather than on the bearer bytes means client-side token rotation does not lock a user out of their own session. A *derived* session id needs no binding — it is already a function of the credential.

**Nothing token-shaped is built, loaded, or swept.** The `TokenStore` is created without a `RefreshConfig` and without a persistence backend; `run_http` skips `load_persisted()` and never starts the token cleanup task. Session, capability and session-binding persistence stay wired. A deployment switching over from passthrough therefore keeps its Redis without this mode adopting — or garbage-collecting — the grants already in it.

**`OAUTH_EXPECTED_AUDIENCE` is mandatory here**, and `OAuthConfig::validate()` fails at boot without it. The check lives at the bottom of the public entry points rather than only in the runner: **`build_app` returns `Result<(Router, TokenStore, CapabilityRegistry), ConfigError>`** and validates before assembling anything, and `run_http` calls it before binding the listener, so a consumer that builds an `McpApp` by hand — or calls `build_app` directly — cannot route around the guard. The reason is not pedantry: this mode accepts a bearer on the strength of a signature alone, so an unconstrained `aud` would accept *every* token the issuer ever signed, including one minted for a different service — the confused-deputy case RFC 8707 and the MCP spec require a resource server to refuse. In the proxying modes the audience is implied by the fact that this server performed the exchange itself, which is why the check is scoped to this mode.

**What token consumers receive.** There is no store entry to look up, so the middleware attaches the validated credential to the request as a `RequestToken(StoredToken)` extension, and `resolve_token` (`src/capability/filter.rs`) prefers it over the store. rmcp injects the axum `http::request::Parts` — extensions included — into the MCP request context, which is how it survives the trip. Since every consumer path already funnels through `resolve_token`, capability filters, access validators and tool handlers see exactly what they see in the proxying modes:

- `access_token` — the bearer the client sent, verbatim
- `decoded_claims` — populated by the global claims decoder, as usual
- `expires_at` — from the JWT's `exp`
- `refresh_token` — **always `None`**. It belongs to the client and never reaches this process.

From a `RequestContext`, use `ctx.token()` (`RequestContextExt`) rather than `ctx.token_store().get_token(ctx.session_id())`: the latter returns `None` in this mode even though the request is perfectly authenticated.

**Session identity.** Unchanged from passthrough: `credential_session_key` derives a stable per-user key from the JWT's `sid` (else `sub`), injected under `MCP_FALLBACK_SESSION_HEADER`. `SessionStore<T>` therefore still works — it is application data, not credentials, and nothing about this mode says the application may not keep state.

**Routing.** Five paths stop proxying: `/oauth/token`, `/oauth/authorize`, `/oauth/login`, `/oauth/callback`, `/oauth/status`. They answer `404` with a reason rather than being absent from the router — an absent path falls through to the auth-wrapped MCP fallback and answers `401`, blaming the client's credentials for a route that does not exist.

`/oauth/token` is the point of the mode. `/oauth/authorize` goes with it for a reason worth stating: the proxy rewrites `client_id` to the configured `OAUTH_CLIENT_ID`, so the authorization code it returns is bound to *that* client, while the client then redeems it at Keycloak's token endpoint under its own `client_id` — `invalid_grant`. Half a proxied flow is worse than none. The legacy login routes perform the exchange server-side and write the grant into `TokenStore`, which is the state this mode abolishes.

**`/oauth/register` stays.** Keycloak's `clients-registrations/openid-connect` endpoint sends no CORS headers, so a browser-based MCP client cannot perform RFC 7591 dynamic client registration against it directly; the framework's translation is still needed. It forwards the request's `scope` (RFC 7591 §2) — a client registered without the scopes it asked for is refused `invalid_scope` at authorization time, and dropping the field silently gave it the realm's defaults instead. Empty or absent `scope` is *not* forwarded: Keycloak replaces the client's default scopes the moment the field is present. Its offline fallback now returns the **configured** `OAUTH_CLIENT_ID` instead of a fabricated UUID — nothing rewrites `client_id` downstream any more, so an invented id would simply not exist at Keycloak. (As before, that Keycloak client must allow the client's `redirect_uri`.)

**Discovery.** `/.well-known/oauth-protected-resource` (and `.../mcp`) advertises the Keycloak issuer in `authorization_servers` — RFC 9728, the resource server pointing at the AS instead of at itself. `/.well-known/oauth-authorization-server` is still served, because MCP 2025-03-26 clients probe the resource server for it and a `404` strands them, but it now describes **Keycloak**: `issuer`, `authorization_endpoint` and `token_endpoint` are Keycloak's, and only `registration_endpoint` remains ours (the CORS reason above). A welcome side effect: the advertised issuer finally matches the `iss` the tokens carry, which is the RFC 9207 mismatch rmcp's client reports as `AuthorizationServerIssuerMismatch` under passthrough.

Both documents advertise the **configured** scopes — `OAUTH_SCOPES`, verbatim, in `scopes_supported` — rather than a hard-coded `openid profile email`. The default is unchanged, so nothing moves for a deployment that never set the variable; a deployment that defines MCP-specific scopes (`OAUTH_SCOPES=openid,profile,email,mcp:tools,mcp:resources`) can finally get clients to ask for them, since a client picks its scopes out of exactly these documents. This applies to every token mode, not only to resource-server.

**Migrating from passthrough.** The framework side is three settings:

```bash
MCP_TOKEN_MODE=resource_server
OAUTH_UNKNOWN_TOKEN_VALIDATION=jwks
OAUTH_EXPECTED_AUDIENCE=my-mcp-server   # mandatory; boot fails without it
```

`keycloak/mcp-realm.json` is an import-ready realm for exactly this shape — a
public PKCE client, the audience mapper Keycloak needs in place of RFC 8707
`resource`, DCR policies and MCP-length lifetimes; `keycloak/README.md` explains
what to substitute per deployment and which values are still proposals.

What to check before flipping it:

1. **Keycloak must put that audience in the token.** Add an audience mapper to the client (or a client scope) so `aud` contains the value above. Without it every request 401s — the failure is loud, and the accepted `aud` / `azp` are logged on every acceptance in the other modes, which is how to read the right value off real traffic first.
2. **The client must handle its own refresh.** Any MCP client implementing 2025-06-18 does; a client that relied on the framework proxying `/oauth/token` will not.
3. **The Keycloak client must allow the client's `redirect_uri` directly**, since `/oauth/authorize` no longer rewrites anything.
4. **Server-side code that read `token.refresh_token` stops working** — that value is gone by design. Code reading `access_token` or `claims::<C>()` is unaffected.
5. **Existing sessions are not migrated.** Grants persisted by the previous mode are neither loaded nor deleted — they simply sit there, so flipping back is possible; clients re-authenticate once.

**Calling an upstream API with the inbound bearer is forbidden, and the framework does not do it for you.** The MCP spec is explicit: a token issued for this resource server must not be forwarded to another service — that is the confused deputy the audience check exists to prevent, and it is exactly what "just pass the bearer through" does. Two supported paths:

- **Token exchange (RFC 8693)** — the server exchanges the inbound token for one whose `aud` is the upstream service. Requires a confidential client; the framework does not implement this, a consumer that needs it does the exchange in its own tool handler using the credential from `ctx.token()`.
- **An explicitly shared audience** — the deployment deliberately mints tokens carrying both services in `aud`, and both list each other in `OAUTH_EXPECTED_AUDIENCE`. Simpler, and correspondingly blunter: the two services become one trust boundary.

### OAuth lifecycle harness (`tests/oauth_lifecycle_rmcp.rs`)

The mode above is the one where the framework does the *least*, which makes it the
one hardest to test with fakes: everything that matters happens between a real
authorization server and a real MCP client. So this binary runs both. An
ephemeral **Keycloak 26.3** (testcontainers, importing `keycloak/mcp-realm.json`)
plays the AS, the framework runs in-process behind `build_app` on `127.0.0.1:0`,
and the client is rmcp's own `OAuthState` / `AuthorizationManager` / `AuthClient`
stack over `StreamableHttpClientTransport` — the same code path a real MCP client
executes, PKCE and automatic refresh included.

Every test is `#[ignore]`d (`run with --ignored`) and the CI job
`integration-keycloak` runs them with `--test-threads=1`. A missing Docker daemon
skips **locally only**: with `CI` set it panics, since a job whose whole purpose
is to run these tests passing without a container is the same green-for-nothing
failure as before. A daemon that is present but produces a broken Keycloak
**panics** everywhere — a silent skip once hid a real failure.

**Fixture.** One container per test binary, behind a `tokio::sync::OnceCell`
holding a leaked `ContainerAsync`. The shipped realm is deliberately *not* a test
fixture — it demands TLS and ships no users — so `write_patched_realm` injects
everything a test needs and a deployment must not have, keeping the harness
pointed at the artefact that is actually released: `accessTokenLifespan` down to
5 s (expiry has to be observable), every `oidc-audience-mapper` rewritten to the
audience the framework is configured with — **exactly one** demanded in each of
`mcp-audience`, `mcp:tools` and `mcp:resources` (see the DCR note below), since a
realm that lost two of the three would otherwise fail three tests later as an
unexplained `401` — `sslRequired: none`, and the users `alice` and `bob`. The
DCR policies are patched **not at all**: they are exercised as shipped.
Readiness is **not** a log line — Quarkus logs to stderr and
"Listening on:" does not mean the import landed — it is a poll of
`{issuer}/.well-known/openid-configuration` asserting the `issuer` field.

**What the scenarios pin.**

| Test | Property |
|---|---|
| `lifecycle_discovery_auth_and_refresh_{legacy_session,sessionless}` | 401 → `WWW-Authenticate` → PRM discovery → PKCE → tool call; past expiry the *client* refreshes and the same session's counter continues at 2. The access token is asserted to have **rotated**, so "the client refreshed" cannot be confused with "the old token still worked". |
| `expired_bearer_is_refused_once_the_skew_leeway_passes` | the framework's own side of that: a bearer well past `exp` gets `401`. Split out because `JWKS_CLOCK_SKEW_LEEWAY` (30 s) means "expired" and "refused" are half a minute apart, which scenario 1 cannot pay on every run. |
| `lifecycle_session_loss_then_reinitialize_legacy_session` | the **server-side** session really disappearing under a running client: a raw `DELETE /mcp` with that `mcp-session-id`, then another call through the *same* rmcp client. rmcp 3.1 defaults to `reinit_on_expired_session`, so the `404` is absorbed — `perform_reinitialization` aborts the old streams and replays the message, and the caller sees a result, not a `SessionExpired`. On 2025-11-25 the identity *is* the `mcp-session-id`, so the new session is a new identity and the counter restarts at 1. Then two consecutive refresh cycles. |
| `lifecycle_session_loss_then_reinitialize_sessionless` | the same reconnect on 2026-07-28, where identity is `credential_session_key`: the `SessionStore<T>` entry survives a full client teardown and the counter continues. |
| `lifecycle_revoked_grant_requires_reauthorization` | admin-side revocation → `AuthError::AuthorizationRequired` → full re-auth succeeds, with a **new** identity. Run sessionless on purpose: only there is the identity derived from the credential's `sid`, so "the grant was revoked" and "the identity changed" are causally linked — on 2025-11-25 the assertion would only be observing that a new `initialize` returns a new session id. |
| `lifecycle_dynamic_client_registration` | the RFC 7591 path, with no client id configured anywhere on the client side: rmcp registers, authorizes (answering the consent form the realm's `Consent Required` policy imposes), and calls a tool. Keycloak's admin API is asked whether the client really exists, with the redirect URI it asked for. The framework's own `/oauth/register` proxy is exercised separately in the same test, since a spec-current client does not go through it — and the client *it* created is read back from the admin API too: it must carry the `mcp:tools` / `mcp:resources` it asked for (proof the proxy forwards `scope`) and at least one scope injecting the expected audience (proof that forwarding did not cost it its `aud`). |
| `direct_registration_from_an_untrusted_redirect_host_is_refused` | the other half of the `trusted-hosts` policy, as shipped: a registration posted straight at Keycloak asking for a `redirect_uri` on an untrusted host gets `403` naming that policy. `client-uris-must-match` is what the realm relies on once the sender-IP half is off (see below), so it is checked rather than assumed. |
| `realm_injects_the_expected_audience_and_scopes` | the realm actually mints `aud` containing `OAUTH_EXPECTED_AUDIENCE`, and a `scope` claim containing the MCP scopes — without it every other test would fail for the wrong reason. Also asserts the PRM advertises them. |

`assert_no_token_state` is what catches a regression reintroducing token state,
and it looks in **both** places: the `tokens` namespace of the wired
`InMemoryBackend` *and* the in-memory store — this mode builds the store without
a persistence backend, so an in-memory `store_token` would leave the namespace
empty and slip past a backend-only check. In memory it checks twice:
`TokenStore::token_count` (a diagnostic accessor next to `peek_token`, counting
the map and deliberately not reading through to persistence) must be 0, which
catches an entry under *any* key including one no test ever observes, and
`TokenStore::peek_token` is asked for each identity the test did observe, so the
likely regression fails with that identity in the message rather than as a bare
count. Every scenario that gets a request accepted calls it — the four lifecycle
ones, the DCR test, and the expiry test (which accepts a bearer before proving
the expired one is refused, and passes an empty identity list: `token_count` is
the assertion there). Only the audience test does not.

Four implementation notes that are not obvious:

- **The container is reaped by the *next* run.** testcontainers 0.27 ships no
  reaper — removal happens in `ContainerAsync::drop`, and a `static` fixture is
  never dropped. Paying a 30 s boot per test to get a droppable local is the
  only alternative, so instead every container is labelled
  `app.mcp-framework.harness=oauth-lifecycle` and each run removes the previous
  one's before starting. Steady state is one idle Keycloak between runs.
- **Revocation needs the consent deleted too.** rmcp appends `offline_access`
  when the AS advertises it, so `POST /admin/realms/mcp/users/{id}/logout` leaves
  the offline grant — and the refresh token — perfectly usable. The harness pairs
  it with `DELETE …/consents/mcp-client`.
- **Dynamic registration does not go through the framework.** In resource-server
  mode the protected-resource metadata points at Keycloak, so an RFC 9728 client
  follows `authorization_servers` to the AS, reads *its* metadata, and posts its
  RFC 7591 registration to Keycloak's own `clients-registrations` endpoint.
  `/oauth/register` stays served — and is still needed — for browser clients and
  for MCP 2025-03-26 clients that probe the resource server itself, because
  Keycloak's endpoint sends no CORS headers; the test asserts both documents say
  so, then exercises the proxy by hand. Three Keycloak behaviours had to be
  accommodated in the realm for the direct path to work at all, all documented
  in `keycloak/README.md`: a registration request carrying `scope` (rmcp always
  sends one, and `/oauth/register` now forwards it) makes Keycloak **replace**
  the client's default scopes — leaving `basic` as the only default and
  everything requested as optional, dropping `mcp-audience` and with it the
  `aud` the resource server requires — hence the audience mapper is also
  attached to `mcp:tools` / `mcp:resources`; declaring the `offline_access`
  client scope in an export suppresses Keycloak's own offline-token setup,
  leaving the realm role uncreated so that the `offline_access` rmcp appends
  (SEP-2207) fails the exchange — hence the export omits that scope and lets
  Keycloak build it; and `trusted-hosts` has a sender-IP half
  (`host-sending-registration-request-must-match`) which, in this mode, rejects
  every legitimate client — the registration comes from the MCP client itself,
  from anywhere — so the realm ships it **off** and leans on
  `client-uris-must-match`, which the test above pins.
- **Two reqwest majors coexist.** rmcp 3.1 is built on reqwest 0.13, the
  framework on 0.12, and `AuthClient::new` wants rmcp's. The dev-dependency is
  renamed `reqwest13` so only this binary sees it and every other test keeps
  resolving `reqwest` to 0.12.

### Validating bearers the proxy did not issue (`UnknownTokenValidation`)

RFC 7662 introspection used to be the only check available for such a bearer, and it is not always reachable: **Keycloak refuses the introspection endpoint to public clients**, answering `403 {"error":"invalid_request","error_description":"Client not allowed."}`. That refusal is a property of the configured `OAUTH_CLIENT_ID`, not of the token, so on a public-client deployment *every* unknown bearer was rejected — including a perfectly valid token-exchange token whose `aud` is the downstream service.

Verifying the signature against the issuer's published keys has no such requirement, so `validate_unknown_bearer` tries, in order:

1. **`TokenStore`** — a proxy-issued token is already trusted; it never causes a JWKS or introspection round-trip. (Not applicable in `ResourceServer` mode: that mode does not go through `validate_unknown_bearer` at all, see above.)
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

**Retiring the superseded passthrough grant**: the key is derived from the access token, so a `refresh_token` grant stores the rotated credentials under a *new* key — and used to leave the previous entry behind. That entry still held the refresh token Keycloak had just rotated away, and the middleware would happily adopt it: refresh → `invalid_grant` → a spurious `401` for a client holding a perfectly good bearer. `/oauth/token` therefore indexes every passthrough grant by `sha256(refresh_token)` → `grant_key` in `NS_GRANT_REFRESH` (in memory, write-through to persistence, read-through on a memory miss — the same shape as `NS_OPAQUE_REFRESH`). On a `refresh_token` grant the handler resolves the spent refresh token to the grant it belongs to, removes that token entry and its index entry, *then* stores the new grant. The removal is skipped when the old key equals the new one. On this branch that never happens — a rotated access token always hashes to a different key — but the guard is what keeps the cleanup correct once identity is claims-derived (task 920's `sid`/`sub`), where both grants land on the same entry. **Limitation**: only the instance serving the refresh drops the entry from its own memory. A peer that already cached the old grant keeps treating it as trusted until it expires, since read-through fires only on a miss — the consistency caveat documented under *Persistence layer* in [sessions.md](sessions.md). Left as-is on purpose: passthrough disappears with the arrival of a ResourceServer mode, so this is a transition-period mitigation, not a design to build on. Covered by `tests/passthrough_grant_cleanup.rs`, including a two-replica case sharing one backend (exchange on A, refresh on B, verified from a third store built fresh over persistence).

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
