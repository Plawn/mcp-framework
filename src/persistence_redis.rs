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
}

impl RedisBackend {
    /// Connect to Redis at the given URL (e.g. `redis://127.0.0.1/`).
    pub async fn connect(url: &str) -> Result<Self, PersistenceError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    /// Wrap an existing [`ConnectionManager`].
    pub fn from_connection_manager(conn: ConnectionManager) -> Self {
        Self { conn }
    }

    fn redis_key(ns: &str, key: &str) -> String {
        format!("{ns}:{key}")
    }

    fn index_key(ns: &str) -> String {
        format!("{ns}:__idx__")
    }
}

impl PersistenceBackend for RedisBackend {
    fn get(
        &self,
        ns: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, PersistenceError>> + Send + '_>> {
        let rkey = Self::redis_key(ns, key);
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
        let rkey = Self::redis_key(ns, key);
        let idx = Self::index_key(ns);
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
        let rkey = Self::redis_key(ns, key);
        let idx = Self::index_key(ns);
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
        let idx = Self::index_key(ns);
        let mut conn = self.conn.clone();
        Box::pin(async move {
            let members: Vec<String> = conn.smembers(&idx).await?;
            Ok(members)
        })
    }
}
