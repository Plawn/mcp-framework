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
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::auth::TokenStore;
use crate::constants::{NS_SESSIONS, DEFAULT_SESSION_TTL, MCP_SESSION_ID_HEADER, DEFAULT_SESSION_ID};
use crate::persistence::{PersistenceBackend, PersistenceError, spawn_persist};

/// Trait alias for the bounds required on session data types.
///
/// Any type that is `Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static`
/// automatically implements `SessionData`. Use this as a bound instead of
/// spelling out the full trait list.
pub trait SessionData: Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static {}
impl<T: Send + Sync + Default + Clone + Serialize + DeserializeOwned + 'static> SessionData for T {}

/// Internal entry wrapping session data with a last-access timestamp.
struct SessionEntry<T> {
    data: T,
    last_access: Instant,
}

#[derive(Serialize, serde::Deserialize)]
struct PersistedSession<T> {
    data: T,
    remaining_ttl_secs: u64,
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
}

impl<T: SessionData> SessionStore<T> {
    /// Create a new session store with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            persistence: None,
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

    fn persist_entry(&self, session_id: &str, data: &T) {
        if let Some(ref backend) = self.persistence {
            let persisted = PersistedSession {
                data: data.clone(),
                remaining_ttl_secs: self.ttl.as_secs(),
            };
            spawn_persist(backend, NS_SESSIONS, session_id.to_string(), &persisted, Some(self.ttl));
        }
    }

    /// Get the session data for `session_id`, creating it with `T::default()` if absent.
    ///
    /// Updates the last-access timestamp.
    pub async fn get_or_create(&self, session_id: &str) -> T {
        let mut sessions = self.sessions.write().await;
        let is_new = !sessions.contains_key(session_id);
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                data: T::default(),
                last_access: Instant::now(),
            });
        entry.last_access = Instant::now();
        let data = entry.data.clone();
        drop(sessions);

        if is_new {
            self.persist_entry(session_id, &data);
        }

        data
    }

    /// Get the session data for `session_id` if it exists.
    ///
    /// Updates the last-access timestamp on hit.
    pub async fn get(&self, session_id: &str) -> Option<T> {
        let mut sessions = self.sessions.write().await;
        if let Some(entry) = sessions.get_mut(session_id) {
            entry.last_access = Instant::now();
            Some(entry.data.clone())
        } else {
            None
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
        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                data: T::default(),
                last_access: Instant::now(),
            });
        f(&mut entry.data);
        entry.last_access = Instant::now();
        let data = entry.data.clone();
        drop(sessions);

        self.persist_entry(session_id, &data);
        data
    }

    /// Remove the session for `session_id`, returning the data if it existed.
    pub async fn remove(&self, session_id: &str) -> Option<T> {
        let mut sessions = self.sessions.write().await;
        let removed = sessions.remove(session_id).map(|e| e.data);
        drop(sessions);

        if removed.is_some() {
            if let Some(ref backend) = self.persistence {
                let backend = backend.clone();
                let key = session_id.to_string();
                tokio::spawn(async move {
                    if let Err(e) = backend.delete(NS_SESSIONS, &key).await {
                        tracing::warn!("Failed to delete persisted session {key}: {e}");
                    }
                });
            }
        }

        removed
    }

    /// Purge all sessions whose last access is older than the TTL.
    pub async fn purge_expired(&self) {
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

        if !expired_keys.is_empty() {
            if let Some(ref backend) = self.persistence {
                let backend = backend.clone();
                let keys = expired_keys;
                tokio::spawn(async move {
                    for key in &keys {
                        if let Err(e) = backend.delete(NS_SESSIONS, key).await {
                            tracing::warn!("Failed to delete persisted session {key}: {e}");
                        }
                    }
                });
            }
        }
    }

    /// Load all sessions from the persistence backend into memory.
    ///
    /// Entries that fail to deserialize are skipped with a warning.
    pub async fn load_persisted(&self) -> Result<(), PersistenceError> {
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

            let last_access = Instant::now()
                - (self.ttl.saturating_sub(Duration::from_secs(persisted.remaining_ttl_secs)));

            entries.push((key, SessionEntry {
                data: persisted.data,
                last_access,
            }));
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
        let interval = self.ttl / 2;
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

impl<T: SessionData> Default
    for SessionStore<T>
{
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_TTL)
    }
}

/// Extract the MCP session ID from request context extensions.
///
/// Looks for the `mcp-session-id` header in the HTTP request parts
/// injected by `StreamableHttpService`. Returns `"default"` if no
/// HTTP parts or header are available (e.g., stdio mode).
pub fn resolve_session_id(extensions: &Extensions) -> &str {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| {
            parts
                .headers
                .get(MCP_SESSION_ID_HEADER)
                .and_then(|h| h.to_str().ok())
        })
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

impl<'a, T: SessionData>
    Session<'a, T>
{
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
    fn session<T: SessionData>(
        &self,
    ) -> Session<'_, T>;

    /// Get the MCP session ID (falls back to `"default"` in stdio mode).
    fn session_id(&self) -> &str;

    /// Get a reference to the [`TokenStore`] from the context.
    ///
    /// # Panics
    ///
    /// Panics if `TokenStore` was not injected into the context.
    fn token_store(&self) -> &TokenStore;
}

impl RequestContextExt for RequestContext<RoleServer> {
    fn session<T: SessionData>(
        &self,
    ) -> Session<'_, T> {
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
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
