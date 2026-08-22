# Capability layer (`src/capability/`)

Access validation, MCP Apps (ext-apps), and tool schema sanitization.
Overview and defaults: [CLAUDE.md](../CLAUDE.md).

## Access validation (`src/capability/validator.rs`)

Pre-execution authorization for tool calls, prompt access, and resource reads. Unlike `CapabilityFilter` which controls **visibility** (what clients can *see*), `AccessValidator` controls **execution** (what clients can *do*). A tool hidden by the filter can still be called directly if the client knows its name — the access validator closes that gap.

Key types:
- `AccessDecision` — `Allow` or `Deny(reason)`
- `AccessValidator` trait — three async methods with default `Allow` implementations: `validate_tool_call`, `validate_prompt_access`, `validate_resource_access`
- `ToolCallValidator<F>` — convenience wrapper for a closure that validates only tool calls

The interception point is `DynamicHandler::call_tool` / `get_prompt` / `read_resource` in `src/capability/handler.rs`, before dispatch to the registry or inner handler.

### Global claims decoder

A claims decoder can be configured once on the `TokenStore` (or via `McpAppBuilder::claims_decoder`). It decodes the JWT access token into a typed struct and caches the result in `StoredToken::decoded_claims`. Every component that touches a token — filters, validators, handlers — can access the decoded claims via `token.claims::<C>()`.

The decoder is applied automatically during `TokenStore::store_token`, including after token refresh.

### Using access validation with JWT roles

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

## MCP Apps / ext-apps (`src/capability/registry.rs`)

Support for [MCP Apps](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/ext-apps) (ext-apps, spec v1.7.0) — tools that declare a companion UI rendered by the host inline in the chat.

### How it works

MCP Apps let a tool return both **structured data** (JSON text for the LLM) and a **visual UI** (HTML for the human) in a single interaction. The flow has three steps:

1. **Tool call** — the host calls a tool (e.g. `get_nps`). The tool returns JSON text as usual. But the tool's metadata contains `_meta.ui.resourceUri` pointing to a `ui://` URI.
2. **Resource fetch** — the host sees the `_meta.ui` pointer and calls `resources/read` on the **same MCP server** with that `ui://` URI. The server returns a self-contained HTML bundle with MIME type `text/html;profile=mcp-app`.
3. **Render** — the host renders the HTML in a sandboxed iframe inline next to the text response.

The HTML is served over the MCP protocol itself (via `resources/read`), not over a separate HTTP endpoint. The bundle must be **single-file** — all CSS, JS, and assets inlined — because it is delivered as a string in the resource contents.

### API

Two helpers on `CapabilityRegistry`:

- **`register_app_resource(uri, html)`** — registers a `ui://` resource with MIME type `text/html;profile=mcp-app`. The HTML string is stored in memory and returned verbatim when the host calls `resources/read`. The resource appears in `resources/list` automatically.
- **`app_tool(tool, resource_uri)`** — static method that injects `_meta.ui.resourceUri` into a `Tool`'s existing metadata (preserving any other `_meta` fields). Returns the enriched `Tool`. Does **not** register the tool — call `add_tool` separately.

The MIME type constant `APP_MIME_TYPE` is in `src/constants.rs`.

### Usage

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

### Passing data to the UI

The HTML bundle runs in an isolated iframe — it does not receive the tool call arguments or result automatically. To pass data, embed it in the HTML at build time (e.g. template variables in the Vite build), or use a convention like a `<script id="data">` tag populated by the resource handler. The current implementation serves the HTML as a static string; dynamic per-call rendering would require creating a unique resource per invocation.

## Tool schema sanitization (`src/capability/sanitize.rs`)

`sanitize_tool_schemas` rewrites every `Tool` on its way to `tools/list`, so the
schema schemars emits is one an MCP client actually accepts. It runs, in order:

1. **`$schema` / `title` stripping** at every *schema node*. The walker is
   schema-aware: `properties` / `patternProperties` / `$defs` / `definitions`
   / `dependentSchemas` are maps of user-chosen names and are traversed without
   being treated as nodes (a parameter named `title` survives), and the data
   keywords `enum` / `const` / `default` / `examples` are never entered. `title` is *folded
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
