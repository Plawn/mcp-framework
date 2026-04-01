# Tech Debt

Known improvements deferred for later.

## `DynamicHandler::new()` parameter sprawl

**File:** `src/capability/handler.rs`

The constructor takes 6 positional parameters (`inner`, `registry`, `filter`, `token_store`, `session_store`, `tool_call_logger`). Each new cross-cutting concern adds another param here and at both call sites (stdio in `runner.rs`, HTTP in `http.rs`).

**Fix:** Group infrastructure concerns into a `HandlerContext<T>` struct:

```rust
struct HandlerContext<T: ...> {
    filter: Option<Arc<dyn CapabilityFilter>>,
    token_store: TokenStore,
    session_store: SessionStore<T>,
    tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
}
```

Reduces `DynamicHandler::new()` to `(inner, registry, context)`.

## `list_tools` / `list_prompts` / `list_resources` duplication

**File:** `src/capability/handler.rs`

All three `list_*` methods follow the same pattern: enrich extensions, resolve token, call inner, merge registry items (registry wins on collision), apply filter. The merge logic is copy-pasted with only the type and field name varying.

**Fix:** Extract a generic merge helper or macro. Note: `list_tools` also applies URL query filtering and schema sanitization, which the other two don't, so the abstraction needs to account for that asymmetry.

## `TracingLogger` boxes a synchronous operation

**File:** `src/audit/logger.rs`

`TracingLogger::log()` does all work synchronously (`tracing::info!`) then returns `Box::pin(std::future::ready(()))`. The `Pin<Box<dyn Future>>` allocation is wasted. This is a trait design constraint — the trait must support async loggers (DB, HTTP), so sync loggers pay a small boxing cost.

**Fix (optional):** Add a `log_sync(&self, record) -> ()` default method to the trait, with `log()` auto-delegating to it. Sync loggers override `log_sync`, async loggers override `log`. Low priority — the allocation is negligible.

## `tokio::spawn` drops JoinHandle for audit logging

**File:** `src/capability/handler.rs` (in `call_tool`)

The spawned audit task's `JoinHandle` is dropped, so logger panics are silently swallowed. The trait doc says "must not panic" but there's no enforcement.

**Fix (optional):** Wrap with `catch_unwind` and log panics:

```rust
tokio::spawn(async move {
    if let Err(e) = AssertUnwindSafe(logger.log(record)).catch_unwind().await {
        tracing::error!("audit logger panicked: {e:?}");
    }
});
```

Low priority — panicking in a logger is a bug in the logger impl, not in the framework.
