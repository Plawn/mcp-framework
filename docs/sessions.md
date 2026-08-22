# Sessions & persistence

Session identity, transport session recovery, and the `PersistenceBackend` layer.
Overview and defaults: [CLAUDE.md](../CLAUDE.md).

## Session layer (`src/session/`)

`SessionStore<T>` — generic, thread-safe per-session data store with TTL expiration. The type parameter `T` (must implement `Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static`) is defined by the consumer. Default TTL is 30 minutes. A background cleanup task purges expired sessions in HTTP mode.

Helper function `resolve_session_id(extensions)` extracts the session identity from MCP request context extensions, falling back to `"default"` for stdio mode. It delegates to `session_id_from_parts(&Parts)`, shared with `resolve_token` in `src/capability/filter.rs` so both resolve identity identically.

### Sessionless protocol revisions (MCP 2026-07-28 / SEP-2567)

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

### Transport session recovery (`src/transport/session_persistence.rs`)

Three stores are keyed by the session id, and each owns exactly one kind of data — never duplicate one into another:

| Store | Namespace | Holds | Written by |
|---|---|---|---|
| rmcp transport session (`TransportSessionStore`, adapts `rmcp::…::SessionStore`) | `mcp_transport_sessions` | the `initialize` parameters rmcp needs to rebuild a protocol session | rmcp, once at `initialize`; re-armed by the framework on `load` |
| `SessionStore<T>` | `sessions` | consumer-defined application data | the consumer, through `update` |
| `TokenStore` | `tokens` / `opaque*` / `grant_refresh` | credentials and grant material | the auth layer |

The transport store is what turns a legacy-session request landing on an instance that did not create it into a restored session instead of a `404` → client re-`initialize`. It is mounted in `build_app` whenever a persistence backend is configured, with the same TTL as `SessionStore<T>`; without persistence rmcp keeps sessions in process memory as before. Sessionless revisions (2026-07-28) have no protocol session to restore and are unaffected.

**TTL.** rmcp writes the entry once and never refreshes it while an instance that already holds the session in memory serves traffic, so the entry's lifetime is counted from creation, not from last activity. The framework re-arms the TTL on every successful `load` through `PersistenceBackend::touch` — atomic, so a session a peer deleted between the read and the re-arm is reported gone rather than resurrected; `Unsupported` (a backend without the primitive) restores without re-arming; an error answers "unknown session" (rmcp: `404`, the client re-initializes) rather than a `500` the client would retry. The remaining gap is a **warmed pool**: once every instance has restored the session, no `load` happens any more and the entry expires after one TTL of the last restore even under continuous traffic — an instance joining (or restarting) after that point re-initializes the client, exactly the pre-recovery behaviour. Touching the entry on every legacy-session request would close it at one backend round-trip per request; not done.

Covered by `http_legacy_session_is_restored_on_another_instance` (`tests/http_integration.rs`, two `build_app` instances sharing one `InMemoryBackend`), the unit tests in `session_persistence.rs` (re-arm, delete-between-read-and-touch, touch error → unknown session, backend without `touch` → restores without re-arming) and `touch_re_arms_a_live_key_and_reports_a_deleted_one` against a real Redis.

## Persistence layer (`src/persistence.rs`)

`PersistenceBackend` trait — async key-value interface with namespace separation (`"tokens"`, `"sessions"`, `"session_binding"`, …). Both `TokenStore` and `SessionStore<T>` accept an optional backend via `.with_persistence()` or `.set_persistence()`. When configured:

- **Write-through**: mutations (`store_token`, `update`, `remove`, `purge_expired`) are written to the backend asynchronously (fire-and-forget via `tokio::spawn`)
- **Load-at-startup**: `load_persisted()` reads all keys from the backend and populates the in-memory store. Called automatically during `run()` before the listener starts
- **Read-through**: on a memory miss, the read paths (`TokenStore::get_token_raw`, `TokenStore::resolve_opaque_*`, `SessionStore::get`) fall back to the backend, deserialize, and write-back into the in-memory cache. This is what makes **multi-instance / horizontal scaling without sticky sessions** work: a request that lands on an instance which did not create the session still resolves the token/opaque-mapping/session from Redis instead of returning a 401. A memory hit never touches the backend (zero overhead on the hot path).
- **No backend = current behavior**: zero overhead, no serialization

**`touch`**: `PersistenceBackend::touch(ns, key, ttl) -> Touch` re-arms an entry's TTL atomically and reports `Armed` / `Missing` (`RedisBackend`: `EXPIRE`; `InMemoryBackend`: presence check under its lock). The default answers `Unsupported` without doing anything: callers keep what they read but get no TTL extension — the behaviour of a backend written before the method existed, with no write and therefore no resurrection. It exists so that transport session recovery never resurrects a deleted session — see the session layer.

**Distributed refresh lock**: the `PersistenceBackend` trait exposes `try_acquire_lock(ns, key, token, ttl)`/`release_lock(ns, key, token)` (default: no-op that always acquires; `RedisBackend` overrides with atomic `SET key token NX PX`, `InMemoryBackend` with an in-process lock map). The caller passes a unique per-acquisition `token` (a fresh UUID); `release_lock` is **compare-and-delete** (Redis: a Lua `GET==token then DEL` script) so a late release after TTL expiry cannot drop a lock a peer has since re-acquired. On token expiry, `TokenStore::get_token` first takes the process-local per-session lock, then the distributed lock (`NS_REFRESH_LOCK`) before refreshing — serializing refresh across instances so Keycloak refresh-token rotation isn't broken by concurrent refreshes (distributed thundering herd). While a peer holds the lock, the waiter polls persistence and **adopts** the peer's refreshed token instead of issuing a duplicate refresh. `REFRESH_LOCK_TTL` auto-expires a crashed holder's lock, and `REFRESH_LOCK_WAIT` is kept above it so a waiter eventually acquires rather than racing.

**Consistency caveat**: read-through resolves the "never seen on this instance" case. A value that was *updated* on a peer after being cached locally can still be served stale until it expires (read-through only fires on a miss, by design — to keep zero overhead on hits). For tokens this is bounded: on expiry the refresh path re-reads persistence and adopts a peer's fresh token. For session data, callers needing strict cross-instance freshness should not rely on the local cache for mutable shared state.

The trait uses `Pin<Box<dyn Future>>` returns for object safety (`Arc<dyn PersistenceBackend>`). `InMemoryBackend` is shipped for testing. `Instant` fields are serialized as seconds-remaining and reconstructed on load. `StoredToken::decoded_claims` is not serialized — it is re-decoded via the existing `claims_decoder`.

Builder API: `.persistence(Arc::new(MyBackend::new()))` wires the backend into both stores.

### Built-in backends

- `InMemoryBackend` — always available, useful for testing. TTL is ignored.
- `RedisBackend` — requires the `redis` cargo feature. Stores keys as `{ns}:{key}` with a companion index Set (`{ns}:__idx__`) per namespace so that `keys()` is O(members) via `SMEMBERS` rather than scanning the keyspace. `set` and `delete` maintain the index atomically using pipelined transactions. TTL is handled natively via Redis `EXPIRE`.

### Using Redis persistence

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
