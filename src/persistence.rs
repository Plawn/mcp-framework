use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::RwLock;

pub type PersistenceError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Object-safe boxed future returned by [`PersistenceBackend`] methods.
///
/// `BoxFuture<'a, T>` is shorthand for
/// `Pin<Box<dyn Future<Output = Result<T, PersistenceError>> + Send + 'a>>`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, PersistenceError>> + Send + 'a>>;

/// Async key-value persistence backend.
///
/// Used by both [`SessionStore`](crate::session::SessionStore) and
/// [`TokenStore`](crate::auth::TokenStore) to survive server restarts.
/// Keys are scoped by namespace (`"tokens"`, `"sessions"`) to avoid collisions
/// when a single backend instance (e.g. one Redis connection) is shared.
///
/// # Object safety
///
/// Methods return `Pin<Box<dyn Future>>` so the trait is object-safe and can be
/// stored as `Arc<dyn PersistenceBackend>`.
pub trait PersistenceBackend: Send + Sync + 'static {
    fn get(
        &self,
        ns: &str,
        key: &str,
    ) -> BoxFuture<'_, Option<Vec<u8>>>;

    fn set(
        &self,
        ns: &str,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> BoxFuture<'_, ()>;

    fn delete(
        &self,
        ns: &str,
        key: &str,
    ) -> BoxFuture<'_, ()>;

    fn keys(
        &self,
        ns: &str,
    ) -> BoxFuture<'_, Vec<String>>;

    /// Atomically acquire a distributed lock for `key` within `ns`, held for at
    /// most `ttl` (after which it auto-expires so a crashed holder can't deadlock
    /// the key). Returns `true` if the lock was acquired, `false` if another
    /// holder already owns it.
    ///
    /// `token` is a caller-supplied unique value (e.g. a fresh UUID) that
    /// identifies *this* acquisition. It must be passed back to
    /// [`release_lock`](Self::release_lock) so the lock is only released by the
    /// holder that took it — preventing the classic "lock TTL expired, a peer
    /// re-acquired, and the original holder's late release deletes the peer's
    /// lock" race.
    ///
    /// # Default implementation
    ///
    /// The default always returns `true` — i.e. **no** distributed mutual
    /// exclusion. Backends that support an atomic set-if-not-exists (e.g. Redis
    /// `SET key val NX PX ttl`) should override this to provide real
    /// cross-instance locking. With the default, callers fall back to
    /// process-local locking only.
    fn try_acquire_lock(
        &self,
        ns: &str,
        key: &str,
        token: &str,
        ttl: Duration,
    ) -> BoxFuture<'_, bool> {
        let _ = (ns, key, token, ttl);
        Box::pin(async { Ok(true) })
    }

    /// Release a lock previously acquired via [`try_acquire_lock`](Self::try_acquire_lock).
    ///
    /// `token` must match the value passed to `try_acquire_lock`; the lock is
    /// only deleted if it is still held under that token (compare-and-delete).
    /// This makes a late release a no-op once the lock has been re-acquired by
    /// another holder.
    ///
    /// The default is a no-op (paired with the default `try_acquire_lock`).
    fn release_lock(
        &self,
        ns: &str,
        key: &str,
        token: &str,
    ) -> BoxFuture<'_, ()> {
        let _ = (ns, key, token);
        Box::pin(async { Ok(()) })
    }
}

/// In-memory persistence backend for testing.
///
/// Stores all data in a `HashMap` behind an `RwLock`. TTL is ignored — entries
/// persist until explicitly deleted or overwritten. A real backend (e.g. Redis)
/// may auto-expire entries based on TTL; keep this in mind when writing tests.
pub struct InMemoryBackend {
    data: Arc<RwLock<HashMap<(String, String), Vec<u8>>>>,
    /// Held locks keyed by (ns, key) with their `(token, expiry)`. Provides real
    /// atomic mutual exclusion within a process (atomicity from the `RwLock`),
    /// so multi-instance behaviour can be exercised in tests. The token enables
    /// compare-and-delete on release.
    locks: Arc<RwLock<HashMap<(String, String), (String, Instant)>>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn dump(&self) -> HashMap<(String, String), Vec<u8>> {
        self.data.read().await.clone()
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistenceBackend for InMemoryBackend {
    fn get(
        &self,
        ns: &str,
        key: &str,
    ) -> BoxFuture<'_, Option<Vec<u8>>> {
        let ns = ns.to_string();
        let key = key.to_string();
        Box::pin(async move {
            let data = self.data.read().await;
            Ok(data.get(&(ns, key)).cloned())
        })
    }

    fn set(
        &self,
        ns: &str,
        key: &str,
        value: &[u8],
        _ttl: Option<Duration>,
    ) -> BoxFuture<'_, ()> {
        let ns = ns.to_string();
        let key = key.to_string();
        let value = value.to_vec();
        Box::pin(async move {
            let mut data = self.data.write().await;
            data.insert((ns, key), value);
            Ok(())
        })
    }

    fn delete(
        &self,
        ns: &str,
        key: &str,
    ) -> BoxFuture<'_, ()> {
        let ns = ns.to_string();
        let key = key.to_string();
        Box::pin(async move {
            let mut data = self.data.write().await;
            data.remove(&(ns, key));
            Ok(())
        })
    }

    fn keys(
        &self,
        ns: &str,
    ) -> BoxFuture<'_, Vec<String>> {
        let ns = ns.to_string();
        Box::pin(async move {
            let data = self.data.read().await;
            let keys = data
                .keys()
                .filter(|(n, _)| *n == ns)
                .map(|(_, k)| k.clone())
                .collect();
            Ok(keys)
        })
    }

    fn try_acquire_lock(
        &self,
        ns: &str,
        key: &str,
        token: &str,
        ttl: Duration,
    ) -> BoxFuture<'_, bool> {
        let k = (ns.to_string(), key.to_string());
        let token = token.to_string();
        Box::pin(async move {
            let now = Instant::now();
            let mut locks = self.locks.write().await;
            match locks.get(&k) {
                Some((_, expiry)) if *expiry > now => Ok(false), // still held by someone else
                _ => {
                    locks.insert(k, (token, now + ttl));
                    Ok(true)
                }
            }
        })
    }

    fn release_lock(
        &self,
        ns: &str,
        key: &str,
        token: &str,
    ) -> BoxFuture<'_, ()> {
        let k = (ns.to_string(), key.to_string());
        let token = token.to_string();
        Box::pin(async move {
            let mut locks = self.locks.write().await;
            // Compare-and-delete: only release if we still hold it under our token.
            if let Some((held, _)) = locks.get(&k)
                && *held == token {
                    locks.remove(&k);
                }
            Ok(())
        })
    }
}

pub(crate) fn spawn_persist<T: Serialize>(
    backend: &Arc<dyn PersistenceBackend>,
    ns: &'static str,
    key: String,
    value: &T,
    ttl: Option<Duration>,
) {
    match serde_json::to_vec(value) {
        Ok(bytes) => spawn_persist_raw(backend, ns, key, bytes, ttl),
        Err(e) => {
            tracing::warn!("Failed to serialize {ns}/{key}: {e}");
        }
    }
}

/// Fire-and-forget write of an already-serialized value (raw bytes).
pub(crate) fn spawn_persist_raw(
    backend: &Arc<dyn PersistenceBackend>,
    ns: &'static str,
    key: String,
    value: Vec<u8>,
    ttl: Option<Duration>,
) {
    let backend = backend.clone();
    tokio::spawn(async move {
        if let Err(e) = backend.set(ns, &key, &value, ttl).await {
            tracing::warn!("Failed to persist {ns}/{key}: {e}");
        }
    });
}

#[cfg(feature = "redis")]
#[path = "persistence_redis.rs"]
mod redis_backend;
#[cfg(feature = "redis")]
pub use redis_backend::RedisBackend;

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod tests;
