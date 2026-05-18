use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use redis::AsyncCommands;
use redis::aio::ConnectionManager;

use super::{PersistenceBackend, PersistenceError};

/// Redis-backed persistence backend.
///
/// Keys are stored as `{ns}:{key}` with a companion Set `{ns}:__idx__` that
/// tracks all live keys per namespace. This makes `keys()` O(members) instead
/// of scanning the entire keyspace. `set` and `delete` maintain the index with
/// pipelined `SADD`/`SREM` commands.
///
/// Uses [`ConnectionManager`] internally, which multiplexes commands over a
/// single connection and reconnects automatically on failure.
pub struct RedisBackend {
    conn: ConnectionManager,
    prefix: Option<String>,
}

impl RedisBackend {
    /// Connect to Redis at the given URL (e.g. `redis://127.0.0.1/`).
    pub async fn connect(url: &str) -> Result<Self, PersistenceError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn, prefix: None })
    }

    /// Wrap an existing [`ConnectionManager`].
    pub fn from_connection_manager(conn: ConnectionManager) -> Self {
        Self { conn, prefix: None }
    }

    /// Set a key prefix applied to all Redis keys.
    ///
    /// Useful when multiple applications share the same Redis database.
    /// With prefix `"myapp"`, keys become `myapp:{ns}:{key}`.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    fn redis_key(&self, ns: &str, key: &str) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{ns}:{key}"),
            None => format!("{ns}:{key}"),
        }
    }

    fn index_key(&self, ns: &str) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{ns}:__idx__"),
            None => format!("{ns}:__idx__"),
        }
    }
}

impl PersistenceBackend for RedisBackend {
    fn get(
        &self,
        ns: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, PersistenceError>> + Send + '_>> {
        let rkey = self.redis_key(ns, key);
        let mut conn = self.conn.clone();
        Box::pin(async move {
            let value: Option<Vec<u8>> = conn.get(&rkey).await?;
            Ok(value)
        })
    }

    fn set(
        &self,
        ns: &str,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = Result<(), PersistenceError>> + Send + '_>> {
        let rkey = self.redis_key(ns, key);
        let idx = self.index_key(ns);
        let member = key.to_string();
        let value = value.to_vec();
        let mut conn = self.conn.clone();
        Box::pin(async move {
            let mut pipe = redis::pipe()
                .atomic()
                .sadd(&idx, &member)
                .ignore()
                .cmd("SET")
                .arg(&rkey)
                .arg(&value)
                .to_owned();
            if let Some(ttl) = ttl {
                let secs = ttl.as_secs().max(1);
                pipe = pipe
                    .cmd("EXPIRE")
                    .arg(&rkey)
                    .arg(secs)
                    .to_owned();
            }
            pipe.query_async::<()>(&mut conn).await?;
            Ok(())
        })
    }

    fn delete(
        &self,
        ns: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), PersistenceError>> + Send + '_>> {
        let rkey = self.redis_key(ns, key);
        let idx = self.index_key(ns);
        let member = key.to_string();
        let mut conn = self.conn.clone();
        Box::pin(async move {
            redis::pipe()
                .atomic()
                .del(&rkey)
                .ignore()
                .srem(&idx, &member)
                .ignore()
                .query_async::<()>(&mut conn)
                .await?;
            Ok(())
        })
    }

    fn keys(
        &self,
        ns: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, PersistenceError>> + Send + '_>> {
        let idx = self.index_key(ns);
        let mut conn = self.conn.clone();
        Box::pin(async move {
            let members: Vec<String> = conn.smembers(&idx).await?;
            Ok(members)
        })
    }
}
