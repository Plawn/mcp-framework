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
use crate::persistence::{PersistenceBackend, PersistenceError, spawn_persist};

const NS_SESSIONS: &str = "sessions";

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

/// Default TTL for sessions: 30 minutes.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

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
                .get("mcp-session-id")
                .and_then(|h| h.to_str().ok())
        })
        .unwrap_or("default")
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
mod tests {
    use super::*;

    #[derive(Default, Clone, Debug, PartialEq, Serialize, serde::Deserialize)]
    struct TestSession {
        counter: u32,
        name: Option<String>,
    }

    #[tokio::test]
    async fn get_or_create_returns_default() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        let session = store.get_or_create("sess-1").await;
        assert_eq!(session, TestSession::default());
    }

    #[tokio::test]
    async fn get_returns_none_for_missing() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        assert!(store.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn update_modifies_session() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        store.get_or_create("sess-1").await;

        let updated = store
            .update("sess-1", |s| {
                s.counter = 42;
                s.name = Some("Alice".to_string());
            })
            .await;

        assert_eq!(updated.counter, 42);
        assert_eq!(updated.name.as_deref(), Some("Alice"));

        // Verify persistence
        let fetched = store.get("sess-1").await.unwrap();
        assert_eq!(fetched.counter, 42);
    }

    #[tokio::test]
    async fn update_creates_if_absent() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        let result = store.update("new-sess", |s| s.counter = 10).await;
        assert_eq!(result.counter, 10);
    }

    #[tokio::test]
    async fn remove_returns_data() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        store.update("sess-1", |s| s.counter = 5).await;

        let removed = store.remove("sess-1").await;
        assert_eq!(removed.unwrap().counter, 5);
        assert!(store.get("sess-1").await.is_none());
    }

    #[tokio::test]
    async fn purge_expired_removes_old_sessions() {
        let store = SessionStore::<TestSession>::new(Duration::from_millis(50));
        store.get_or_create("old").await;

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Create a fresh session
        store.get_or_create("fresh").await;

        store.purge_expired().await;

        assert!(store.get("old").await.is_none());
        // "fresh" was re-created by get, so still has a recent last_access
        // but purge_expired doesn't touch last_access — re-check
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn cleanup_task_purges_expired() {
        let store = SessionStore::<TestSession>::new(Duration::from_millis(50));
        store.get_or_create("will-expire").await;

        let handle = store.start_cleanup_task();

        // Wait for cleanup to run (interval = ttl/2 = 25ms, plus some margin)
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(store.is_empty().await);
        handle.abort();
    }

    #[test]
    fn resolve_session_id_no_parts() {
        let extensions = Extensions::new();
        assert_eq!(resolve_session_id(&extensions), "default");
    }

    #[test]
    fn resolve_session_id_with_header() {
        let mut extensions = Extensions::new();
        let request = http::Request::builder()
            .header("mcp-session-id", "sess-abc")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        extensions.insert(parts);

        assert_eq!(resolve_session_id(&extensions), "sess-abc");
    }

    #[test]
    fn resolve_session_id_no_header() {
        let mut extensions = Extensions::new();
        let request = http::Request::builder().body(()).unwrap();
        let (parts, _) = request.into_parts();
        extensions.insert(parts);

        assert_eq!(resolve_session_id(&extensions), "default");
    }

    #[tokio::test]
    async fn default_store_has_30min_ttl() {
        let store = SessionStore::<TestSession>::default();
        assert_eq!(store.ttl, DEFAULT_SESSION_TTL);
    }

    // ── Session handle tests ────────────────────────────────────────

    #[tokio::test]
    async fn session_handle_get_or_create() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        let session = Session {
            store: &store,
            session_id: "s1",
        };

        let data = session.get_or_create().await;
        assert_eq!(data, TestSession::default());
    }

    #[tokio::test]
    async fn session_handle_update() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        let session = Session {
            store: &store,
            session_id: "s1",
        };

        let data = session.update(|s| s.counter = 42).await;
        assert_eq!(data.counter, 42);
        assert_eq!(session.id(), "s1");

        let fetched = session.get().await.unwrap();
        assert_eq!(fetched.counter, 42);
    }

    #[tokio::test]
    async fn session_handle_remove() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        let session = Session {
            store: &store,
            session_id: "s1",
        };

        session.update(|s| s.counter = 10).await;
        let removed = session.remove().await;
        assert_eq!(removed.unwrap().counter, 10);
        assert!(session.get().await.is_none());
    }

    // ── Persistence tests ───────────────────────────────────────────

    #[tokio::test]
    async fn session_store_persists_on_update() {
        let backend = Arc::new(crate::persistence::InMemoryBackend::new());
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
            .with_persistence(backend.clone());

        store.update("s1", |s| s.counter = 42).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let data = backend.dump().await;
        assert!(data.contains_key(&("sessions".to_string(), "s1".to_string())));

        let bytes = &data[&("sessions".to_string(), "s1".to_string())];
        let persisted: PersistedSession<TestSession> = serde_json::from_slice(bytes).unwrap();
        assert_eq!(persisted.data.counter, 42);
        assert_eq!(persisted.remaining_ttl_secs, 60);
    }

    #[tokio::test]
    async fn session_store_loads_persisted() {
        let backend = Arc::new(crate::persistence::InMemoryBackend::new());

        let persisted = PersistedSession {
            data: TestSession {
                counter: 99,
                name: Some("loaded".to_string()),
            },
            remaining_ttl_secs: 60,
        };
        backend
            .set("sessions", "s1", &serde_json::to_vec(&persisted).unwrap(), None)
            .await
            .unwrap();

        let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
            .with_persistence(backend);
        store.load_persisted().await.unwrap();

        let data = store.get("s1").await.unwrap();
        assert_eq!(data.counter, 99);
        assert_eq!(data.name.as_deref(), Some("loaded"));
    }

    #[tokio::test]
    async fn session_store_remove_cleans_backend() {
        let backend = Arc::new(crate::persistence::InMemoryBackend::new());
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
            .with_persistence(backend.clone());

        store.update("s1", |s| s.counter = 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(backend.dump().await.contains_key(&("sessions".into(), "s1".into())));

        store.remove("s1").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!backend.dump().await.contains_key(&("sessions".into(), "s1".into())));
    }

    #[tokio::test]
    async fn session_store_purge_cleans_backend() {
        let backend = Arc::new(crate::persistence::InMemoryBackend::new());
        let store = SessionStore::<TestSession>::new(Duration::from_millis(50))
            .with_persistence(backend.clone());

        store.update("s1", |s| s.counter = 1).await;
        tokio::time::sleep(Duration::from_millis(30)).await;

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(50)).await;

        store.purge_expired().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(backend.dump().await.is_empty());
    }

    #[tokio::test]
    async fn session_store_no_backend_unchanged() {
        let store = SessionStore::<TestSession>::new(Duration::from_secs(60));
        store.update("s1", |s| s.counter = 1).await;
        assert_eq!(store.get("s1").await.unwrap().counter, 1);
        store.load_persisted().await.unwrap();
    }

    #[tokio::test]
    async fn session_store_skips_corrupted() {
        let backend = Arc::new(crate::persistence::InMemoryBackend::new());
        backend.set("sessions", "bad", b"garbage", None).await.unwrap();

        let persisted = PersistedSession {
            data: TestSession { counter: 1, name: None },
            remaining_ttl_secs: 60,
        };
        backend.set("sessions", "good", &serde_json::to_vec(&persisted).unwrap(), None).await.unwrap();

        let store = SessionStore::<TestSession>::new(Duration::from_secs(60))
            .with_persistence(backend);
        store.load_persisted().await.unwrap();

        assert!(store.get("bad").await.is_none());
        assert_eq!(store.get("good").await.unwrap().counter, 1);
    }
}
