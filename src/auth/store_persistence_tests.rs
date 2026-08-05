use super::*;

fn test_token(
    access_token: &str,
    refresh_token: Option<&str>,
    expires_at: Option<Instant>,
) -> StoredToken {
    StoredToken {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.map(|s| s.to_string()),
        expires_at,
        decoded_claims: None,
    }
}

// ── Persistence tests ───────────────────────────────────────────

#[tokio::test]
async fn token_store_persists_on_store() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = TokenStore::new().with_persistence(backend.clone());

    let token = test_token(
        "my-access",
        Some("my-refresh"),
        Some(Instant::now() + Duration::from_secs(3600)),
    );
    store.store_token("sess-1".to_string(), token).await;

    let data = backend.dump().await;
    assert!(data.contains_key(&("tokens".to_string(), "sess-1".to_string())));

    let bytes = &data[&("tokens".to_string(), "sess-1".to_string())];
    let persisted: PersistedToken = serde_json::from_slice(bytes).unwrap();
    assert_eq!(persisted.access_token, "my-access");
    assert_eq!(persisted.refresh_token.as_deref(), Some("my-refresh"));
    assert!(persisted.expires_at_unix_ms.is_some());
    assert!(persisted.expires_in_secs.is_none());
}

#[tokio::test]
async fn token_store_loads_persisted() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let persisted = PersistedToken {
        access_token: "loaded-token".to_string(),
        refresh_token: Some("loaded-refresh".to_string()),
        expires_at_unix_ms: None,
        expires_in_secs: Some(7200),
    };
    let bytes = serde_json::to_vec(&persisted).unwrap();
    backend.set("tokens", "sess-x", &bytes, None).await.unwrap();

    let store = TokenStore::new().with_persistence(backend);
    store.load_persisted().await.unwrap();

    let token = store.get_token_raw("sess-x").await.unwrap();
    assert_eq!(token.access_token, "loaded-token");
    assert_eq!(token.refresh_token.as_deref(), Some("loaded-refresh"));
    assert!(!token.is_expired());
}

#[tokio::test]
async fn token_store_does_not_reset_an_absolute_expiry_on_restart() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let persisted = PersistedToken {
        access_token: "already-expired".to_string(),
        refresh_token: None,
        expires_at_unix_ms: Some(instant_to_unix_millis(
            Instant::now() - Duration::from_secs(1),
        )),
        expires_in_secs: None,
    };
    backend
        .set(
            "tokens",
            "expired",
            &serde_json::to_vec(&persisted).unwrap(),
            None,
        )
        .await
        .unwrap();

    let store = TokenStore::new().with_persistence(backend.clone());
    store.load_persisted().await.unwrap();

    assert!(store.peek_token("expired").await.is_none());
    assert!(
        !backend
            .dump()
            .await
            .contains_key(&("tokens".to_string(), "expired".to_string()))
    );
}

#[tokio::test]
async fn token_store_loads_persisted_applies_claims_decoder() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let persisted = PersistedToken {
        access_token: "admin-jwt".to_string(),
        refresh_token: None,
        expires_at_unix_ms: None,
        expires_in_secs: Some(3600),
    };
    backend
        .set(
            "tokens",
            "s1",
            &serde_json::to_vec(&persisted).unwrap(),
            None,
        )
        .await
        .unwrap();

    #[derive(Debug)]
    struct Claims {
        role: String,
    }

    let store = TokenStore::new()
        .with_claims_decoder(|token: &str| -> Option<Claims> {
            if token == "admin-jwt" {
                Some(Claims {
                    role: "admin".into(),
                })
            } else {
                None
            }
        })
        .with_persistence(backend);

    store.load_persisted().await.unwrap();

    let token = store.get_token_raw("s1").await.unwrap();
    let claims = token.claims::<Claims>().expect("claims should be decoded");
    assert_eq!(claims.role, "admin");
}

#[tokio::test]
async fn token_store_skips_corrupted() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    backend
        .set("tokens", "bad", b"not-json{{{", None)
        .await
        .unwrap();

    let persisted = PersistedToken {
        access_token: "good".to_string(),
        refresh_token: None,
        expires_at_unix_ms: None,
        expires_in_secs: Some(3600),
    };
    backend
        .set(
            "tokens",
            "good",
            &serde_json::to_vec(&persisted).unwrap(),
            None,
        )
        .await
        .unwrap();

    let store = TokenStore::new().with_persistence(backend);
    store.load_persisted().await.unwrap();

    assert!(store.get_token_raw("bad").await.is_none());
    assert!(store.get_token_raw("good").await.is_some());
}

#[tokio::test]
async fn token_store_purge_cleans_backend() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = TokenStore::new().with_persistence(backend.clone());

    let expired = test_token("old", None, Some(Instant::now() - Duration::from_secs(60)));
    store.store_token("expired-sess".to_string(), expired).await;

    assert!(!backend.dump().await.is_empty());

    store.purge_expired().await;

    assert!(backend.dump().await.is_empty());
}

#[tokio::test]
async fn token_store_remove_cleans_backend() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = TokenStore::new().with_persistence(backend.clone());

    store
        .store_token("s1".to_string(), test_token("tok", None, None))
        .await;
    assert!(
        backend
            .dump()
            .await
            .contains_key(&("tokens".into(), "s1".into()))
    );

    store.remove_token("s1").await;
    assert!(
        !backend
            .dump()
            .await
            .contains_key(&("tokens".into(), "s1".into()))
    );
}

#[tokio::test]
async fn token_store_no_backend_unchanged() {
    let store = TokenStore::new();
    store
        .store_token("s1".to_string(), test_token("t", None, None))
        .await;
    assert!(store.get_token_raw("s1").await.is_some());
    store.load_persisted().await.unwrap();
}

// === Read-through (multi-instance, no sticky sessions) ===

use crate::persistence::{BoxFuture, InMemoryBackend, PersistenceBackend};

/// Backend wrapper that counts `get` calls, to assert that an in-memory hit does
/// not touch the backend (no Redis overhead on the hot path).
struct CountingBackend {
    inner: InMemoryBackend,
    gets: Arc<std::sync::atomic::AtomicUsize>,
}

impl PersistenceBackend for CountingBackend {
    fn get(&self, ns: &str, key: &str) -> BoxFuture<'_, Option<Vec<u8>>> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get(ns, key)
    }
    fn set(&self, ns: &str, key: &str, value: &[u8], ttl: Option<Duration>) -> BoxFuture<'_, ()> {
        self.inner.set(ns, key, value, ttl)
    }
    fn delete(&self, ns: &str, key: &str) -> BoxFuture<'_, ()> {
        self.inner.delete(ns, key)
    }
    fn keys(&self, ns: &str) -> BoxFuture<'_, Vec<String>> {
        self.inner.keys(ns)
    }
    fn try_acquire_lock(
        &self,
        ns: &str,
        key: &str,
        token: &str,
        ttl: Duration,
    ) -> BoxFuture<'_, bool> {
        self.inner.try_acquire_lock(ns, key, token, ttl)
    }
    fn release_lock(&self, ns: &str, key: &str, token: &str) -> BoxFuture<'_, ()> {
        self.inner.release_lock(ns, key, token)
    }
}

#[tokio::test]
async fn token_read_through_cross_instance() {
    let backend = Arc::new(InMemoryBackend::new());
    let store_a = TokenStore::new().with_persistence(backend.clone());
    let store_b = TokenStore::new().with_persistence(backend.clone());

    // Session created on instance A.
    store_a
        .store_token(
            "s1".into(),
            test_token(
                "acc",
                Some("ref"),
                Some(Instant::now() + Duration::from_secs(3600)),
            ),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await; // let fire-and-forget persist land

    // Instance B never saw this session in RAM — must resolve via read-through.
    let t = store_b
        .peek_token("s1")
        .await
        .expect("B should read token through Redis");
    assert_eq!(t.access_token, "acc");

    // And it is now cached in B (subsequent calls hit RAM).
    assert!(store_b.has_valid_token("s1").await);
}

#[tokio::test]
async fn read_through_no_overhead_on_memory_hit() {
    let gets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let backend = Arc::new(CountingBackend {
        inner: InMemoryBackend::new(),
        gets: gets.clone(),
    });
    let store = TokenStore::new().with_persistence(backend.clone());

    store
        .store_token(
            "s1".into(),
            test_token(
                "acc",
                None,
                Some(Instant::now() + Duration::from_secs(3600)),
            ),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let before = gets.load(std::sync::atomic::Ordering::SeqCst);
    // In-memory hit — must not touch the backend.
    let _ = store.peek_token("s1").await;
    let after = gets.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        before, after,
        "memory hit should not read through to backend"
    );
}

// === Distributed refresh lock ===

#[tokio::test]
async fn inmemory_lock_is_exclusive() {
    let b = InMemoryBackend::new();
    assert!(
        b.try_acquire_lock("refresh_lock", "s1", "tok1", Duration::from_secs(10))
            .await
            .unwrap()
    );
    assert!(
        !b.try_acquire_lock("refresh_lock", "s1", "tok2", Duration::from_secs(10))
            .await
            .unwrap()
    );
    b.release_lock("refresh_lock", "s1", "tok1").await.unwrap();
    assert!(
        b.try_acquire_lock("refresh_lock", "s1", "tok3", Duration::from_secs(10))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn inmemory_lock_auto_expires() {
    let b = InMemoryBackend::new();
    assert!(
        b.try_acquire_lock("ns", "k", "t", Duration::from_millis(40))
            .await
            .unwrap()
    );
    assert!(
        !b.try_acquire_lock("ns", "k", "t", Duration::from_millis(40))
            .await
            .unwrap()
    );
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(
        b.try_acquire_lock("ns", "k", "t", Duration::from_millis(40))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn inmemory_lock_release_is_compare_and_delete() {
    // The classic race: holder A's lock TTL expires, peer B re-acquires, then A's
    // late release must NOT drop B's lock.
    let b = InMemoryBackend::new();

    // A acquires with a short TTL.
    assert!(
        b.try_acquire_lock("refresh_lock", "s1", "token_A", Duration::from_millis(30))
            .await
            .unwrap()
    );

    // A's lock expires; B re-acquires under its own token.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        b.try_acquire_lock("refresh_lock", "s1", "token_B", Duration::from_secs(10))
            .await
            .unwrap()
    );

    // A's late release targets its own (now-expired) token → must be a no-op.
    b.release_lock("refresh_lock", "s1", "token_A")
        .await
        .unwrap();

    // B still holds the lock — a third party cannot acquire it.
    assert!(
        !b.try_acquire_lock("refresh_lock", "s1", "token_C", Duration::from_secs(10))
            .await
            .unwrap()
    );

    // Only B's own release frees it.
    b.release_lock("refresh_lock", "s1", "token_B")
        .await
        .unwrap();
    assert!(
        b.try_acquire_lock("refresh_lock", "s1", "token_C", Duration::from_secs(10))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn get_token_adopts_peer_refreshed_token() {
    // Backend holds a fresh token written by a peer instance; local RAM holds an
    // expired one. get_token must adopt the peer's token rather than refreshing
    // (the refresh URL is unreachable, so a real refresh would fail).
    let backend = Arc::new(InMemoryBackend::new());
    let mut store = TokenStore::with_refresh_config(RefreshConfig {
        client_id: "c".into(),
        client_secret: None,
        token_url: "http://127.0.0.1:1/nonexistent".into(),
    });
    store.set_persistence(backend.clone());

    // Seed local RAM with an expired token (also persisted to the backend).
    store
        .store_token(
            "s1".into(),
            test_token(
                "expired",
                Some("r"),
                Some(Instant::now() - Duration::from_secs(60)),
            ),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Simulate a peer refresh: overwrite the backend entry with a fresh token.
    let fresh = serde_json::to_vec(&PersistedToken::from_stored(&test_token(
        "fresh_acc",
        Some("r2"),
        Some(Instant::now() + Duration::from_secs(3600)),
    )))
    .unwrap();
    backend.set("tokens", "s1", &fresh, None).await.unwrap();

    let got = store
        .get_token("s1")
        .await
        .expect("should adopt peer token");
    assert_eq!(got.access_token, "fresh_acc");
}
