# Protocol revisions

MCP revisions are dated (`2024-11-05` … `2026-07-28`) and each one changes the
lifecycle, not just the payloads. `2026-07-28` (SEP-2567 / SEP-2243) is the
sharpest break: it removes the `initialize` handshake in favour of
`server/discover`, drops protocol-level sessions, and moves per-request context
into `_meta` and standard HTTP headers.

Two independent knobs decide how a client is served:

| Knob | Question it answers |
|---|---|
| `max_protocol_version` | Which revisions does the server **offer**? |
| `ProtocolLifecyclePolicy` | What happens to a client that announces a modern revision through the **legacy** lifecycle? |

## `max_protocol_version` — the advertised ceiling

rmcp's `ServerHandler::supported_protocol_versions()` defaults to every
`ProtocolVersion::KNOWN_VERSIONS`. A server therefore offers `2026-07-28`
without anyone having decided to, and a client that takes it up gets a
lifecycle the deployment may never have been exercised against.

```rust
McpAppBuilder::new("my-server")
    .max_protocol_version(ProtocolVersion::V_2025_11_25)
    .server(|| MyServer::new())
```

`MCP_MAX_PROTOCOL_VERSION` overrides the builder value at boot, so the ceiling
is a deployment decision rather than a rebuild: production can pin the revision
it is known to serve while staging keeps running uncapped as the canary.
`none` / `off` / `latest` / `unset` **lift** a ceiling compiled into the binary;
an unset or empty variable leaves the builder value alone. Any other value must
name a revision rmcp knows, or `build_app()` refuses to start — a typo that was
silently ignored would advertise the full set and reintroduce exactly the
negotiation the ceiling exists to prevent.

### What the ceiling actually does

It is applied at one place — `DynamicHandler::supported_protocol_versions()` —
and reaches the wire through two routes, both covered by
`tests/protocol_matrix.rs`:

- **`server/discover`** answers `result.supportedVersions` with the capped list.
  rmcp's default `discover` builds that field from the *inner* handler, so
  `DynamicHandler::discover` overwrites it; without that, discovery would
  advertise a revision the very next request is refused for.
- **A request above the ceiling** is refused with rmcp's
  `-32022 Unsupported protocol version`, whose `data.supported` carries the
  list. Well-behaved clients retry against it.

That retry is the whole mechanism, and it is not theoretical: driving
claude.ai against a capped server three times, each connection was refused at
`2026-07-28`, fell back to `initialize(2025-11-25)` unaided, and loaded the
full tool list at connect time — where the uncapped `server/discover` path had
been leaving the connector's tool list empty until a manual refresh.

### Where the ceiling does *not* bite

- Under `Hybrid`, a modern `initialize` is rewritten by middleware **before**
  rmcp sees it, so the answer is the same capped or not. Don't credit the
  ceiling with that downgrade.
- Under `Strict`, rmcp 3.1.4's `initialize` route ignores
  `supported_protocol_versions()` altogether: it answers `200` echoing a
  revision the server never advertised, while `server/discover` honours the
  ceiling. This is an upstream bug, pinned by
  `strict_initialize_ignores_the_ceiling_upstream_bug` so the assertion fails
  the day it is fixed. Harmless in practice — clients reaching `initialize`
  with a modern version are legacy-lifecycle clients `Hybrid` already repairs.
- The **loopback** transport is deliberately uncapped. The ceiling steers
  third-party clients away from an untested lifecycle; the loopback peer is the
  framework's own rmcp client negotiating in-process, and honouring a ceiling
  set below rmcp's client default would only refuse our own caller.

### Retiring a ceiling

A ceiling is a compatibility measure, not an architecture. It is logged at boot
(`INFO … advertised MCP revisions capped`) so it stays visible, and it should
be re-tested against the clients that motivated it — lift it with
`MCP_MAX_PROTOCOL_VERSION=none` on one instance and watch whether the symptom
returns.

## `ProtocolLifecyclePolicy`

See the summary in [`CLAUDE.md`](../CLAUDE.md#transport-layer). `Hybrid`
(default) negotiates a modern `initialize` down to `2025-11-25` so rmcp creates
a session and the client's legacy lifecycle stays coherent; `Strict` applies
rmcp's routing unmodified.
