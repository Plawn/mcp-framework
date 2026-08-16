//! In-process transport — a client that speaks the protocol to this app without a socket.
//!
//! An application usually has callers *inside* the process: an agent loop, a scheduler, a
//! background job. The tempting shortcut is to let them reach into the
//! [`CapabilityRegistry`](crate::CapabilityRegistry) directly. That shortcut costs more than it
//! saves: `CapabilityRegistry::call_tool` is not the path the network transports take, so such a
//! caller bypasses the [`CapabilityFilter`], the [`AccessValidator`], and — the one that hurts
//! silently — the [`ToolCallLogger`]. Metrics and audit trails then describe *external* traffic
//! only, and nothing in the code says so.
//!
//! A loopback endpoint removes the shortcut. The in-process caller becomes a real MCP client:
//! same [`DynamicHandler`], same registry, same filter, same logger, same session and token
//! stores — only the socket is missing, replaced by a pair of typed channels. Messages move as
//! `JsonRpcMessage` values, never as bytes, so the isolation costs a channel hop rather than a
//! serialization round-trip.
//!
//! ```rust,ignore
//! let builder = McpAppBuilder::new("engine").server(|| server.clone()) /* … */;
//! let loopback = builder.loopback();          // does not consume the builder
//! tokio::spawn(async move { builder.run().await });
//!
//! let client = loopback.connect(LoopbackIdentity::new("thread-42")).await?;
//! let tools = client.list_all_tools().await?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures::channel::mpsc;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::service::{RoleClient, RunningService};
use rmcp::ServiceExt;

use crate::auth::{StoredToken, TokenStore};
use crate::capability::{CapabilityFilter, CapabilityRegistry, DynamicHandler, HandlerContext};
use crate::capability::AccessValidator;
use crate::audit::ToolCallLogger;
use crate::session::{SessionData, SessionStore};

/// Messages buffered in each direction before the sender waits.
///
/// A loopback client issues one request at a time in the common case; the buffer only absorbs
/// notifications and progress messages arriving while a response is in flight.
const CHANNEL_BUFFER: usize = 32;

/// Who the in-process caller claims to be.
///
/// The framework resolves both the session id and the bearer token from the HTTP request parts
/// of a call (see [`resolve_session_id`](crate::resolve_session_id)) — that is the single
/// identity mechanism, and a loopback client uses it rather than adding a second one: the
/// endpoint synthesizes the parts a network client would have sent.
///
/// `session_id` keys the [`SessionStore`] and the [`TokenStore`], so two callers that must not
/// see each other's session state must not share one.
#[derive(Clone, Debug)]
pub struct LoopbackIdentity {
    session_id: String,
    bearer_token: Option<String>,
}

impl LoopbackIdentity {
    /// An anonymous caller — no credentials, only a session of its own.
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            bearer_token: None,
        }
    }

    /// Present a bearer token, exactly as a network client would in its `Authorization` header.
    ///
    /// The token is also written to the endpoint's [`TokenStore`] under `session_id`, so
    /// capability filters receive it the same way they do over HTTP.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Refuse an identity the framework could not carry faithfully.
    ///
    /// Checked at [`connect`](LoopbackEndpoint::connect) rather than tolerated at request time.
    /// The two rejected shapes are the ones that would *silently* become another identity:
    ///
    /// - an **empty** session id is a perfectly valid header value, so nothing downstream would
    ///   complain — [`resolve_session_id`](crate::resolve_session_id) would hand `""` to the
    ///   session store as a real key and to a context-aware tool as a real caller;
    /// - a session id or token that **no header can hold** (a newline, a NUL) makes the parts
    ///   unbuildable, and a caller without parts falls back to
    ///   [`DEFAULT_SESSION_ID`](crate::constants::DEFAULT_SESSION_ID) — several broken callers
    ///   would then merge into one shared session, and read each other's state.
    ///
    /// Both are refusals rather than repairs: an in-process caller that cannot name itself has a
    /// bug, and inventing a name for it is how the bug stops being visible.
    fn validate(&self) -> Result<(), LoopbackConnectError> {
        if self.session_id.is_empty() {
            return Err(LoopbackConnectError::InvalidIdentity(
                "the session id is empty".to_string(),
            ));
        }
        self.build_parts()
            .map(|_| ())
            .map_err(|e| LoopbackConnectError::InvalidIdentity(e.to_string()))
    }

    fn build_parts(&self) -> Result<http::request::Parts, http::Error> {
        let mut builder = http::Request::builder()
            .method(http::Method::POST)
            .uri("/mcp")
            .header(crate::constants::MCP_SESSION_ID_HEADER, &self.session_id);
        if let Some(ref token) = self.bearer_token {
            builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        Ok(builder.body(())?.into_parts().0)
    }

    /// Rebuild the request metadata a network client would have carried.
    ///
    /// Called once per request rather than cached because `http::request::Parts` is not `Clone`.
    /// The cost is one small header map next to a whole tool call.
    pub(crate) fn to_parts(&self) -> Option<http::request::Parts> {
        match self.build_parts() {
            Ok(parts) => Some(parts),
            // Unreachable: `connect` refuses such an identity. Kept as a guard rather than an
            // `expect` because the consequence of being wrong is a shared session, not a panic —
            // and logged at `error` because reaching here means the refusal was bypassed.
            Err(e) => {
                tracing::error!(
                    session_id = %self.session_id,
                    error = %e,
                    "loopback identity is not expressible as request headers — this call degrades to the default session"
                );
                None
            }
        }
    }
}

/// Why an in-process session could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum LoopbackConnectError {
    /// The identity would not survive the trip through request headers. See
    /// [`LoopbackIdentity::validate`].
    #[error("loopback identity cannot be carried by the protocol: {0}")]
    InvalidIdentity(String),
    /// The MCP `initialize` handshake failed.
    #[error(transparent)]
    Initialize(#[from] rmcp::service::ClientInitializeError),
}

/// A factory for in-process clients of an [`McpApp`](crate::McpApp).
///
/// Obtained from [`McpAppBuilder::loopback`](crate::McpAppBuilder::loopback) *before* the builder
/// is consumed by `run()`, so one application can serve a network transport and hand out loopback
/// sessions at the same time. Cheap to clone: everything it holds is an `Arc` or a handle.
///
/// The endpoint owns its own [`TokenStore`], distinct from the one the HTTP transport builds:
/// in-process callers are not HTTP sessions and their credentials have no reason to collide with
/// (or be readable from) a network client's.
pub struct LoopbackEndpoint<T: SessionData, F> {
    server_factory: F,
    registry: CapabilityRegistry,
    filter: Option<Arc<dyn CapabilityFilter>>,
    access_validator: Option<Arc<dyn AccessValidator>>,
    tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
    token_store: TokenStore,
    session_store: SessionStore<T>,
}

impl<T: SessionData, F: Clone> Clone for LoopbackEndpoint<T, F> {
    fn clone(&self) -> Self {
        Self {
            server_factory: self.server_factory.clone(),
            registry: self.registry.clone(),
            filter: self.filter.clone(),
            access_validator: self.access_validator.clone(),
            tool_call_logger: self.tool_call_logger.clone(),
            token_store: self.token_store.clone(),
            session_store: self.session_store.clone(),
        }
    }
}

impl<T: SessionData, F> LoopbackEndpoint<T, F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server_factory: F,
        registry: CapabilityRegistry,
        filter: Option<Arc<dyn CapabilityFilter>>,
        access_validator: Option<Arc<dyn AccessValidator>>,
        tool_call_logger: Option<Arc<dyn ToolCallLogger>>,
        token_store: TokenStore,
        session_store: SessionStore<T>,
    ) -> Self {
        Self {
            server_factory,
            registry,
            filter,
            access_validator,
            tool_call_logger,
            token_store,
            session_store,
        }
    }
}

impl<T, F, S> LoopbackEndpoint<T, F>
where
    T: SessionData,
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    /// Open a client session onto this application.
    ///
    /// The returned service has completed the `initialize` handshake and is ready to issue
    /// requests. It owns a spawned task serving the other end; dropping it, or calling
    /// [`RunningService::cancel`], closes the session and ends that task.
    pub async fn connect(
        &self,
        identity: LoopbackIdentity,
    ) -> Result<RunningService<RoleClient, ()>, LoopbackConnectError> {
        identity.validate()?;

        // The credentials presented at connect **replace** whatever the store held for this
        // session id, in both directions. Storing on `Some` and doing nothing on `None` would
        // make the token outlive its session: the store is keyed by session id alone, a loopback
        // token has no `expires_at` so `purge_expired` never reclaims it, and `resolve_token`
        // ignores the `Authorization` header entirely. A session re-opened *anonymously* under a
        // name a privileged caller used earlier would silently inherit that caller's rights —
        // exactly the quiet privilege the loopback exists to remove.
        match identity.bearer_token {
            Some(ref token) => {
                self.token_store
                    .store_token(
                        identity.session_id.clone(),
                        StoredToken::new(token.clone(), None, None),
                    )
                    .await;
            }
            None => self.token_store.remove_token(&identity.session_id).await,
        }

        let handler = DynamicHandler::new(
            (self.server_factory)(),
            self.registry.clone(),
            HandlerContext {
                filter: self.filter.clone(),
                access_validator: self.access_validator.clone(),
                token_store: self.token_store.clone(),
                session_store: self.session_store.clone(),
                tool_call_logger: self.tool_call_logger.clone(),
                loopback_identity: Some(identity.clone()),
            },
        );

        // Two typed channels rather than one duplex pipe: the messages never become bytes, so
        // nothing is serialized, parsed, or size-limited on the way through.
        let (to_server, from_client) = mpsc::channel::<ClientJsonRpcMessage>(CHANNEL_BUFFER);
        let (to_client, from_server) = mpsc::channel::<ServerJsonRpcMessage>(CHANNEL_BUFFER);

        let session_id = identity.session_id.clone();
        // The server side must already be listening when the client sends `initialize`, so it is
        // spawned first and never awaited here.
        tokio::spawn(async move {
            match handler.serve((to_client, from_client)).await {
                Ok(running) => {
                    if let Err(e) = running.waiting().await {
                        tracing::debug!(session_id = %session_id, error = %e, "loopback session ended");
                    }
                }
                Err(e) => {
                    tracing::warn!(session_id = %session_id, error = %e, "loopback server side failed to start")
                }
            }
        });

        Ok(().serve((to_server, from_server)).await?)
    }

    /// Drop everything this endpoint holds for `session_id`.
    ///
    /// Closing the client ends the conversation but leaves its *state* behind: the token store
    /// keeps a credential that nothing expires, and the session store keeps whatever the tools
    /// wrote. Over a process lifetime that is a slow leak, and — worse — a credential waiting for
    /// the next caller who happens to reuse the name. A caller that owns the lifecycle of its
    /// sessions (a chat thread, a job) calls this when one ends.
    ///
    /// The session store is shared with the network transport by design, so a loopback caller
    /// must not name a session after an HTTP one: forgetting it here would forget it there too.
    pub async fn forget_session(&self, session_id: &str) {
        self.token_store.remove_token(session_id).await;
        // deliberate: le `Option<T>` rendu est l'état qu'on jette — c'est le but de l'appel.
        let _ = self.session_store.remove(session_id).await;
    }
}

/// Object-safe view of a [`LoopbackEndpoint`].
///
/// An endpoint is generic over its server factory, which is almost always an unnameable
/// closure — so a caller that wants to *store* one needs this instead. `Arc<dyn DynLoopback>`
/// is the usual shape.
pub trait DynLoopback: Send + Sync {
    fn connect_session(
        &self,
        identity: LoopbackIdentity,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<RunningService<RoleClient, ()>, LoopbackConnectError>>
                + Send
                + '_,
        >,
    >;

    /// See [`LoopbackEndpoint::forget_session`].
    fn forget_session_dyn<'a>(
        &'a self,
        session_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

impl<T, F, S> DynLoopback for LoopbackEndpoint<T, F>
where
    T: SessionData,
    F: Fn() -> S + Clone + Send + Sync + 'static,
    S: ServerHandler + Send + 'static,
{
    fn connect_session(
        &self,
        identity: LoopbackIdentity,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<RunningService<RoleClient, ()>, LoopbackConnectError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(self.connect(identity))
    }

    fn forget_session_dyn<'a>(
        &'a self,
        session_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(self.forget_session(session_id))
    }
}
