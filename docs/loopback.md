# In-process transport (`src/transport/loopback.rs`)

A client that speaks the protocol to this application without a socket.
Overview and defaults: [CLAUDE.md](../CLAUDE.md).

## Why it exists

An application usually has callers *inside* the process: an agent loop, a scheduler, a background job. The tempting shortcut is to let them reach into the `CapabilityRegistry` directly — and `CapabilityRegistry::call_tool` is not the path the network transports take, so such a caller bypasses the `CapabilityFilter`, the `AccessValidator`, and — the one that hurts silently — the `ToolCallLogger`. Metrics and audit trails then describe *external* traffic only, and nothing in the code says so.

A loopback endpoint removes the shortcut: the in-process caller becomes a real MCP client, same `DynamicHandler`, same registry, same filter, same logger — only the socket is missing, replaced by a pair of typed channels. Messages move as `JsonRpcMessage` values, never as bytes, so the isolation costs a channel hop rather than a serialization round-trip.

## Usage

```rust
let mut builder = McpAppBuilder::new("engine").server(|| server.clone()); // … configure everything first
let loopback = builder.loopback();          // does not consume the builder
tokio::spawn(async move { builder.run().await });

let session = loopback.connect(LoopbackIdentity::new("thread-42")).await?;
let tools = session.list_all_tools().await?;
```

- `LoopbackEndpoint` is cheap to clone (everything it holds is an `Arc` or a handle). It is generic over the server factory — almost always an unnameable closure — so a caller that wants to *store* one uses the object-safe `Arc<dyn DynLoopback>` (`connect_session`, `forget_session_dyn`).
- `LoopbackSession` derefs to the rmcp client, so `session.peer()`, `session.call_tool(..)`, `session.list_all_tools()` read exactly as they would on a `RunningService`. It owns the task serving the other end; dropping it or calling `cancel()` closes the session and ends that task (aborting it cancels the per-request handler tasks too, rather than orphaning them).
- `forget_session(session_id)` drops the endpoint's session state for a caller that is gone.

## Configure before `loopback()`

The endpoint is a **snapshot** of the builder: server factory, registry, capability filter, access validator, tool-call logger, claims decoder, session TTL and token mode are captured at the call. Configuring any of them afterwards would apply to the network transport only, leaving the in-process caller on the old value — a filter or a validator applied to half the traffic, silently. `McpAppBuilder::validate()` therefore refuses to build and **names the fields that diverged**; call `loopback()` last.

The registry is materialized at that point if it was unset, so both sides dispatch through the same one — that shared registry is the point of the whole exercise.

## Identity, and the two stores it does not share

`LoopbackIdentity::new(session_id)` names an anonymous caller; `.with_bearer_token(t)` presents a bearer exactly as a network client would in its `Authorization` header (it is also written to the endpoint's `TokenStore` under that session id, so capability filters receive it the same way they do over HTTP). The endpoint synthesizes the `http::request::Parts` a network client would have sent, so identity resolution stays the single mechanism it is everywhere else — no second one.

The endpoint owns its own `TokenStore` **and** `SessionStore`, distinct from the ones the HTTP transport builds. Both are keyed by session id alone, and a loopback session id is chosen by the in-process caller — often from data it received from outside (a chat thread id straight out of a request body). Sharing either store would let a caller that names its session after a network client's read and write that client's state.

Consequences worth knowing rather than discovering: **in-process session data is not persisted** (a persistence backend attached to the app reaches the HTTP store only) and does not survive a restart. Sessions of `T = ()` — the common case — hold nothing anyway.

## Refusals

`connect` returns `LoopbackConnectError` rather than repairing a caller that cannot name itself:

| Variant | Cause |
|---|---|
| `InvalidIdentity` | an **empty** session id (a valid header value, so nothing downstream would complain — the session store would take `""` as a real key), or a session id / token no header can hold (a newline, a NUL), which would make the parts unbuildable and collapse several broken callers onto `DEFAULT_SESSION_ID`, sharing one session |
| `UnresolvableCredential` | a bearer presented under `TokenMode::Opaque`, where the credential is a UUID the **HTTP** transport's store resolves and this endpoint cannot. Storing it as-is would hand filters, validators and forwarded backends something that looks real and authenticates nothing. The caller may retry anonymously — a de-escalation, safe by construction — as long as it logs that it did |
| `Initialize` | the MCP `initialize` handshake failed (boxed: rmcp's error is several hundred bytes and this is the rarest of the three) |
