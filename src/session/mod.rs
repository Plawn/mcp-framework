//! Typed session storage for MCP servers.
//!
//! [`SessionStore`] provides a generic, thread-safe store keyed by session ID.
//! Consumers define their own session data type `T` (must implement [`SessionData`]),
//! and the store handles creation, access, TTL expiration, and background cleanup.
//!
//! # Example
//!
//! ```rust,ignore
//! use mcp_framework::session::SessionStore;
//! use std::time::Duration;
//!
//! #[derive(Default, Clone)]
//! struct MySession {
//!     user_name: Option<String>,
//!     request_count: u32,
//! }
//!
//! let store = SessionStore::<MySession>::new(Duration::from_secs(1800));
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::model::Extensions;
use rmcp::service::{RequestContext, RoleServer};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use crate::auth::{StoredToken, TokenStore};
use crate::constants::{
    DEFAULT_SESSION_ID, DEFAULT_SESSION_TTL, MCP_FALLBACK_SESSION_HEADER, MCP_SESSION_ID_HEADER,
    NS_SESSION_LOCK, NS_SESSIONS, SESSION_LOCK_POLL, SESSION_LOCK_TTL, SESSION_LOCK_WAIT,
};
use crate::persistence::{
    PersistenceBackend, PersistenceError, instant_to_unix_millis, persist,
    remaining_until_unix_millis,
};

/// Trait alias for the bounds required on session data types.
///
/// Any type that is `Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static`
/// automatically implements `SessionData`. Use this as a bound instead of
/// spelling out the full trait list.
pub trait SessionData:
    Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static
{
}
impl<T: Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static> SessionData for T {}

/// Internal entry wrapping session data with a last-access timestamp.
struct SessionEntry<T> {
    data: T,
    last_access: Instant,
}

#[derive(Serialize, serde::Deserialize)]
struct PersistedSession<T> {
    data: T,
    #[serde(default)]
    expires_at_unix_ms: Option<u64>,
    /// Legacy format written before absolute deadlines were introduced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remaining_ttl_secs: Option<u64>,
}

/// A generic, thread-safe session store keyed by session ID.
///
/// `T` is the consumer-defined session data type. It must implement
/// `SessionData`.
///
/// Cloning a `SessionStore` produces a new handle to the **same** underlying data
/// (same pattern as [`TokenStore`](crate::auth::TokenStore)).
#[derive(Clone)]
pub struct SessionStore<T: Send + Sync + 'static> {
    sessions: Arc<RwLock<HashMap<String, SessionEntry<T>>>>,
    ttl: Duration,
    persistence: Option<Arc<dyn PersistenceBackend>>,
    /// Orders in-memory mutations with their persistence side effects.
    mutation_lock: Arc<Mutex<()>>,
}

impl<T: SessionData> SessionStore<T> {
    /// Create a new session store with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            persistence: None,
            mutation_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Attach a persistence backend for surviving server restarts.
    pub fn with_persistence(mut self, backend: Arc<dyn PersistenceBackend>) -> Self {
        self.persistence = Some(backend);
        self
    }

    /// Set the persistence backend (mutable reference variant).
    pub fn set_persistence(&mut self, backend: Arc<dyn PersistenceBackend>) {
        self.persistence = Some(backend);
    }

    /// Return the inactivity TTL configured for this store.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    async fn persist_entry(&self, session_id: &str, data: &T) {
        if let Some(ref backend) = self.persistence {
            let persisted = PersistedSession {
                data: data.clone(),
                expires_at_unix_ms: Some(instant_to_unix_millis(Instant::now() + self.ttl)),
                remaining_ttl_secs: None,
            };
            persist(backend, NS_SESSIONS, session_id, &persisted, Some(self.ttl)).await;
        }
    }

    /// Acquire the persistence-backed per-session lock used by every operation
    /// that can write a session record. Clones already share `mutation_lock`;
    /// this second layer orders independent server replicas.
    async fn acquire_persistence_lock(
        &self,
        session_id: &str,
    ) -> Option<(Arc<dyn PersistenceBackend>, String)> {
        let backend = self.persistence.clone()?;
        let owner = uuid::Uuid::new_v4().to_string();
        let deadline = Instant::now() + SESSION_LOCK_WAIT;

        loop {
            match backend
                .try_acquire_lock(NS_SESSION_LOCK, session_id, &owner, SESSION_LOCK_TTL)
                .await
            {
                Ok(true) => return Some((backend, owner)),
                Ok(false) if Instant::now() < deadline => {
                    tokio::time::sleep(SESSION_LOCK_POLL).await;
                }
                Ok(false) => {
                    tracing::warn!("Timed out waiting for session lock {session_id}");
                    return None;
                }
                Err(e) => {
                    tracing::warn!("Failed to acquire session lock {session_id}: {e}");
                    return None;
                }
            }
        }
    }

    async fn release_persistence_lock(
        lock: Option<(Arc<dyn PersistenceBackend>, String)>,
        session_id: &str,
    ) {
        if let Some((backend, owner)) = lock
            && let Err(e) = backend
                .release_lock(NS_SESSION_LOCK, session_id, &owner)
                .await
        {
            tracing::warn!("Failed to release session lock {session_id}: {e}");
        }
    }

    /// Get the session data for `session_id`, creating it with `T::default()` if absent.
    ///
    /// Updates the last-access timestamp.
    pub async fn get_or_create(&self, session_id: &str) -> T {
        let _mutation = self.mutation_lock.lock().await;

        let distributed_lock = self.acquire_persistence_lock(session_id).await;
        let loaded = self.load_session_from_backend(session_id).await;
        let locally_cached = self
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|entry| entry.data.clone());
        let is_new = loaded.is_none() && locally_cached.is_none();

        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                data: T::default(),
                last_access: Instant::now(),
            });
        if let Some(authoritative) = loaded {
            entry.data = authoritative;
        }
        entry.last_access = Instant::now();
        let data = entry.data.clone();
        drop(sessions);

        // Touch the persisted record while holding the distributed lock. This
        // extends the sliding TTL without writing a stale replica cache.
        if self.persistence.is_some() || is_new {
            self.persist_entry(session_id, &data).await;
        }
        Self::release_persistence_lock(distributed_lock, session_id).await;

        data
    }

    /// Get the session data for `session_id` if it exists.
    ///
    /// Updates the last-access timestamp on hit. On a memory miss, falls back to
    /// the persistence backend (read-through) so a request served by an instance
    /// that did not create the session can still resolve it; the loaded entry is
    /// written back to the in-memory cache.
    pub async fn get(&self, session_id: &str) -> Option<T> {
        let _mutation = self.mutation_lock.lock().await;

        let distributed_lock = self.acquire_persistence_lock(session_id).await;
        let persisted = self.load_session_from_backend(session_id).await;
        let cached = self
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|entry| entry.data.clone());
        let data = persisted.or(cached);
        let Some(data) = data else {
            Self::release_persistence_lock(distributed_lock, session_id).await;
            return None;
        };

        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                data: data.clone(),
                last_access: Instant::now(),
            });
        entry.data = data;
        entry.last_access = Instant::now();
        let data = entry.data.clone();
        drop(sessions);
        if self.persistence.is_some() {
            self.persist_entry(session_id, &data).await;
        }
        Self::release_persistence_lock(distributed_lock, session_id).await;
        Some(data)
    }

    /// Read a session directly from the persistence backend. Does not touch the
    /// in-memory cache. Returns `None` if there is no backend, no entry, or the
    /// entry is corrupted.
    async fn load_session_from_backend(&self, session_id: &str) -> Option<T> {
        let backend = self.persistence.as_ref()?;
        let bytes = match backend.get(NS_SESSIONS, session_id).await {
            Ok(b) => b?,
            Err(e) => {
                tracing::warn!("Read-through get failed for session {session_id}: {e}");
                return None;
            }
        };
        match serde_json::from_slice::<PersistedSession<T>>(&bytes) {
            Ok(p) => {
                let expired = p
                    .expires_at_unix_ms
                    .is_some_and(|deadline| remaining_until_unix_millis(deadline).is_zero());
                if expired {
                    if let Err(e) = backend.delete(NS_SESSIONS, session_id).await {
                        tracing::warn!("Failed to delete expired session {session_id}: {e}");
                    }
                    None
                } else {
                    Some(p.data)
                }
            }
            Err(e) => {
                tracing::warn!("Corrupted persisted session {session_id}: {e}");
                None
            }
        }
    }

    /// Update the session data for `session_id` using a closure.
    ///
    /// If the session does not exist, it is created with `T::default()` first.
    /// Returns the updated value.
    pub async fn update<F>(&self, session_id: &str, f: F) -> T
    where
        F: FnOnce(&mut T),
    {
        let _mutation = self.mutation_lock.lock().await;

        let distributed_lock = self.acquire_persistence_lock(session_id).await;
        let loaded = self.load_session_from_backend(session_id).await;

        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                data: T::default(),
                last_access: Instant::now(),
            });
        if let Some(authoritative) = loaded {
            entry.data = authoritative;
        }
        f(&mut entry.data);
        entry.last_access = Instant::now();
        let data = entry.data.clone();
        drop(sessions);

        self.persist_entry(session_id, &data).await;
        Self::release_persistence_lock(distributed_lock, session_id).await;
        data
    }

    /// Remove the session for `session_id`, returning the data if it existed.
    pub async fn remove(&self, session_id: &str) -> Option<T> {
        let _mutation = self.mutation_lock.lock().await;
        let distributed_lock = self.acquire_persistence_lock(session_id).await;
        let persisted = self.load_session_from_backend(session_id).await;
        let mut sessions = self.sessions.write().await;
        let cached = sessions.remove(session_id).map(|e| e.data);
        let removed = persisted.or(cached);
        drop(sessions);

        if removed.is_some()
            && let Some(ref backend) = self.persistence
            && let Err(e) = backend.delete(NS_SESSIONS, session_id).await
        {
            tracing::warn!("Failed to delete persisted session {session_id}: {e}");
        }
        Self::release_persistence_lock(distributed_lock, session_id).await;

        removed
    }

    /// Purge all sessions whose last access is older than the TTL.
    pub async fn purge_expired(&self) {
        let _mutation = self.mutation_lock.lock().await;
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        let ttl = self.ttl;

        let expired_keys: Vec<String> = sessions
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_access) >= ttl)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &expired_keys {
            sessions.remove(key);
        }
        drop(sessions);

        // Do not delete a record merely because this replica's cache is old: a
        // peer may have touched or updated the authoritative persisted entry.
        for key in &expired_keys {
            let distributed_lock = self.acquire_persistence_lock(key).await;
            let _ = self.load_session_from_backend(key).await;
            Self::release_persistence_lock(distributed_lock, key).await;
        }
    }

    /// Load all sessions from the persistence backend into memory.
    ///
    /// Entries that fail to deserialize are skipped with a warning.
    pub async fn load_persisted(&self) -> Result<(), PersistenceError> {
        let _mutation = self.mutation_lock.lock().await;
        let backend = match &self.persistence {
            Some(b) => b,
            None => return Ok(()),
        };

        let keys = backend.keys(NS_SESSIONS).await?;
        let mut entries = Vec::new();

        for key in keys {
            let bytes = match backend.get(NS_SESSIONS, &key).await? {
                Some(b) => b,
                None => continue,
            };

            let persisted: PersistedSession<T> = match serde_json::from_slice(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("Skipping corrupted persisted session {key}: {e}");
                    continue;
                }
            };

            let remaining = persisted
                .expires_at_unix_ms
                .map(remaining_until_unix_millis)
                .unwrap_or_else(|| {
                    Duration::from_secs(persisted.remaining_ttl_secs.unwrap_or_default())
                });
            if remaining.is_zero() {
                backend.delete(NS_SESSIONS, &key).await?;
                continue;
            }
            let remaining = remaining.min(self.ttl);
            let last_access = Instant::now() - self.ttl.saturating_sub(remaining);

            entries.push((
                key,
                SessionEntry {
                    data: persisted.data,
                    last_access,
                },
            ));
        }

        if !entries.is_empty() {
            let count = entries.len();
            let mut sessions = self.sessions.write().await;
            for (key, entry) in entries {
                sessions.insert(key, entry);
            }
            tracing::info!("Loaded {count} persisted session(s)");
        }

        Ok(())
    }

    /// Spawn a background task that periodically purges expired sessions.
    ///
    /// The cleanup interval is `ttl / 2`. The task runs until the returned
    /// [`JoinHandle`] is aborted or the runtime shuts down.
    pub fn start_cleanup_task(&self) -> JoinHandle<()> {
        let store = self.clone();
        let interval = (self.ttl / 2).max(Duration::from_millis(1));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                store.purge_expired().await;
            }
        })
    }

    /// Return the number of active sessions.
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Return whether the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.sessions.read().await.is_empty()
    }
}

// DEFAULT_SESSION_TTL is re-exported from crate::constants

impl<T: SessionData> Default for SessionStore<T> {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_TTL)
    }
}

/// Resolve the session identity carried by an HTTP request.
///
/// [`MCP_FALLBACK_SESSION_HEADER`] wins when present, then the protocol session
/// (`mcp-session-id`), then [`DEFAULT_SESSION_ID`].
///
/// The framework header takes precedence because the auth middleware only sets
/// it where it is the more accurate identity, and it always strips any
/// client-supplied value first:
///
/// - **Sessionless revisions.** MCP 2026-07-28 removed protocol sessions
///   (SEP-2567), so `mcp-session-id` is absent; the middleware injects a
///   per-credential id instead of letting every concurrent client share
///   [`DEFAULT_SESSION_ID`].
/// - **Opaque token mode.** The grant, not the connection, is the identity: the
///   opaque token outlives any `mcp-session-id` and is what keys the
///   `TokenStore`. The middleware injects the resolved grant id so callers and
///   the token store agree.
///
/// Otherwise the header is absent and the protocol session is used unchanged.
pub fn session_id_from_parts(parts: &http::request::Parts) -> &str {
    parts
        .headers
        .get(MCP_FALLBACK_SESSION_HEADER)
        .or_else(|| parts.headers.get(MCP_SESSION_ID_HEADER))
        .and_then(|h| h.to_str().ok())
        .unwrap_or(DEFAULT_SESSION_ID)
}

/// Extract the MCP session ID from request context extensions.
///
/// Reads the HTTP request parts injected by `StreamableHttpService` and
/// resolves them via [`session_id_from_parts`]. Returns `"default"` when no
/// HTTP parts are available (e.g. stdio mode).
pub fn resolve_session_id(extensions: &Extensions) -> &str {
    extensions
        .get::<http::request::Parts>()
        .map(session_id_from_parts)
        .unwrap_or(DEFAULT_SESSION_ID)
}

/// A scoped handle to a specific session within a [`SessionStore`].
///
/// Created via [`RequestContextExt::session`]. Delegates all operations to the
/// underlying store using the resolved session ID.
pub struct Session<'a, T: SessionData> {
    store: &'a SessionStore<T>,
    session_id: &'a str,
}

impl<'a, T: SessionData> Session<'a, T> {
    /// Return the session ID.
    pub fn id(&self) -> &str {
        self.session_id
    }

    /// Get the session data if it exists.
    pub async fn get(&self) -> Option<T> {
        self.store.get(self.session_id).await
    }

    /// Get the session data, creating it with `T::default()` if absent.
    pub async fn get_or_create(&self) -> T {
        self.store.get_or_create(self.session_id).await
    }

    /// Update the session data using a closure. Creates with `T::default()` if absent.
    pub async fn update<F>(&self, f: F) -> T
    where
        F: FnOnce(&mut T),
    {
        self.store.update(self.session_id, f).await
    }

    /// Remove the session, returning the data if it existed.
    pub async fn remove(&self) -> Option<T> {
        self.store.remove(self.session_id).await
    }
}

/// Extension trait for accessing sessions and tokens from a request context.
///
/// This trait is automatically available on `RequestContext<RoleServer>` when
/// the stores have been injected into `context.extensions` by [`DynamicHandler`].
///
/// # Example
///
/// ```rust,ignore
/// use mcp_framework::prelude::*;
///
/// let session = context.session::<MySession>();
/// let data = session.update(|s| s.call_count += 1).await;
/// ```
pub trait RequestContextExt {
    /// Get a [`Session`] handle for the current MCP session.
    ///
    /// # Panics
    ///
    /// Panics if `SessionStore<T>` was not injected into the context.
    /// This happens when `with_sessions::<T>()` was not called on the builder.
    fn session<T: SessionData>(&self) -> Session<'_, T>;

    /// Get the MCP session ID (falls back to `"default"` in stdio mode).
    fn session_id(&self) -> &str;

    /// Get a reference to the [`TokenStore`] from the context.
    ///
    /// # Panics
    ///
    /// Panics if `TokenStore` was not injected into the context.
    fn token_store(&self) -> &TokenStore;

    /// The credential bound to the current request, wherever it happens to live.
    ///
    /// Prefer this over `ctx.token_store().get_token(ctx.session_id())`: in
    /// [`TokenMode::ResourceServer`](crate::auth::TokenMode::ResourceServer) the
    /// framework keeps no token state, so a store lookup returns `None` even
    /// though the request is perfectly authenticated. This accessor reads the
    /// request-scoped credential the auth middleware attached after validating
    /// it, and falls back to the store in the proxying modes.
    ///
    /// The returned [`StoredToken`] carries the same `access_token` and decoded
    /// claims either way; only `refresh_token` is always `None` in
    /// resource-server mode, because the refresh token never reaches this
    /// process.
    ///
    /// # Panics
    ///
    /// Panics if `TokenStore` was not injected into the context.
    fn token(&self) -> impl std::future::Future<Output = Option<StoredToken>> + Send;
}

impl RequestContextExt for RequestContext<RoleServer> {
    fn session<T: SessionData>(&self) -> Session<'_, T> {
        let store = self
            .extensions
            .get::<SessionStore<T>>()
            .expect("SessionStore<T> not in context. Call .with_sessions::<T>() on the builder.");
        let session_id = resolve_session_id(&self.extensions);
        Session { store, session_id }
    }

    fn session_id(&self) -> &str {
        resolve_session_id(&self.extensions)
    }

    fn token_store(&self) -> &TokenStore {
        self.extensions
            .get::<TokenStore>()
            .expect("TokenStore not in context")
    }

    async fn token(&self) -> Option<StoredToken> {
        crate::capability::filter::resolve_token(&self.extensions, self.token_store()).await
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;

#[cfg(test)]
#[path = "handle_tests.rs"]
mod handle_tests;

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod persistence_tests;
