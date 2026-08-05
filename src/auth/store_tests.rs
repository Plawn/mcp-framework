use super::*;

fn test_token(access_token: &str, refresh_token: Option<&str>, expires_at: Option<Instant>) -> StoredToken {
    StoredToken {
        access_token: access_token.to_string(),
        refresh_token: refresh_token.map(|s| s.to_string()),
        expires_at,
        decoded_claims: None,
    }
}

#[test]
fn test_token_expiry_buffer_expired() {
    let token = test_token("test", None, Some(Instant::now() + Duration::from_secs(29)));
    assert!(token.is_expired());
}

#[test]
fn test_token_expiry_buffer_valid() {
    let token = test_token("test", None, Some(Instant::now() + Duration::from_secs(31)));
    assert!(!token.is_expired());
}

#[test]
fn test_token_no_expiry_never_expires() {
    let token = test_token("test", None, None);
    assert!(!token.is_expired());
}

#[tokio::test]
async fn test_refresh_failure_returns_none() {
    let store = TokenStore::with_refresh_config(RefreshConfig {
        client_id: "test".to_string(),
        client_secret: Some("secret".to_string()),
        token_url: "http://127.0.0.1:1/nonexistent".to_string(),
    });

    let expired_token = test_token("old_access", Some("refresh_tok"), Some(Instant::now() - Duration::from_secs(60)));
    store.store_token("session1".to_string(), expired_token).await;

    let result = store.get_token("session1").await;
    assert!(result.is_none(), "Expected None when refresh fails on expired token");
}

#[tokio::test]
async fn test_concurrent_refresh_uses_lock() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let call_count = Arc::new(AtomicUsize::new(0));
    let store = TokenStore::with_refresh_config(RefreshConfig {
        client_id: "test".to_string(),
        client_secret: Some("secret".to_string()),
        token_url: "http://127.0.0.1:1/nonexistent".to_string(),
    });

    let expired_token = test_token("old", Some("refresh"), Some(Instant::now() - Duration::from_secs(60)));
    store.store_token("s1".to_string(), expired_token).await;

    let store1 = store.clone();
    let store2 = store.clone();
    let count1 = call_count.clone();
    let count2 = call_count.clone();

    let (r1, r2) = tokio::join!(
        async move {
            let r = store1.get_token("s1").await;
            count1.fetch_add(1, Ordering::SeqCst);
            r
        },
        async move {
            let r = store2.get_token("s1").await;
            count2.fetch_add(1, Ordering::SeqCst);
            r
        },
    );

    assert!(r1.is_none());
    assert!(r2.is_none());
    assert_eq!(call_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_valid_token_returned_directly() {
    let store = TokenStore::new();
    let token = test_token("valid", None, Some(Instant::now() + Duration::from_secs(3600)));
    store.store_token("s1".to_string(), token).await;

    let result = store.get_token("s1").await;
    assert!(result.is_some());
    assert_eq!(result.unwrap().access_token, "valid");
}

#[tokio::test]
async fn test_expired_token_no_refresh_config_returns_none() {
    let store = TokenStore::new();
    let token = test_token("expired", Some("refresh"), Some(Instant::now() - Duration::from_secs(60)));
    store.store_token("s1".to_string(), token).await;

    let result = store.get_token("s1").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_remove_token_cleans_refresh_lock() {
    let store = TokenStore::new();
    let token = test_token("test", None, None);
    store.store_token("s1".to_string(), token).await;

    let _lock = store.get_refresh_lock("s1").await;
    assert!(store.refresh_locks.read().await.contains_key("s1"));

    store.remove_token("s1").await;
    assert!(!store.refresh_locks.read().await.contains_key("s1"));
    assert!(store.get_token_raw("s1").await.is_none());
}

#[tokio::test]
async fn test_purge_expired_removes_expired_tokens() {
    let store = TokenStore::new();

    let expired = test_token("old", None, Some(Instant::now() - Duration::from_secs(60)));
    store.store_token("expired-sess".to_string(), expired).await;

    let _lock = store.get_refresh_lock("expired-sess").await;

    let valid = test_token("fresh", None, Some(Instant::now() + Duration::from_secs(3600)));
    store.store_token("valid-sess".to_string(), valid).await;

    store.purge_expired().await;

    assert!(store.get_token_raw("expired-sess").await.is_none());
    assert!(!store.refresh_locks.read().await.contains_key("expired-sess"));

    assert!(store.get_token_raw("valid-sess").await.is_some());
}

#[tokio::test]
async fn test_purge_expired_no_expiry_kept() {
    let store = TokenStore::new();

    let token = test_token("eternal", None, None);
    store.store_token("s1".to_string(), token).await;

    store.purge_expired().await;
    assert!(store.get_token_raw("s1").await.is_some());
}

#[tokio::test]
async fn test_claims_decoder_applied_on_store() {
    #[derive(Debug)]
    struct Claims { role: String }

    let store = TokenStore::new().with_claims_decoder(|token: &str| -> Option<Claims> {
        if token == "admin-jwt" {
            Some(Claims { role: "admin".into() })
        } else {
            None
        }
    });

    store.store_token("s1".to_string(), test_token("admin-jwt", None, None)).await;
    let stored = store.get_token_raw("s1").await.unwrap();
    let claims = stored.claims::<Claims>().expect("should have decoded claims");
    assert_eq!(claims.role, "admin");

    store.store_token("s2".to_string(), test_token("unknown", None, None)).await;
    let stored = store.get_token_raw("s2").await.unwrap();
    assert!(stored.claims::<Claims>().is_none());
}

#[tokio::test]
async fn test_no_decoder_leaves_claims_none() {
    let store = TokenStore::new();
    store.store_token("s1".to_string(), test_token("any", None, None)).await;
    let stored = store.get_token_raw("s1").await.unwrap();
    assert!(stored.decoded_claims.is_none());
}

#[test]
fn test_claims_wrong_type_returns_none() {
    #[derive(Debug)]
    struct A;
    #[derive(Debug)]
    struct B;

    let token = StoredToken {
        access_token: "x".into(),
        refresh_token: None,
        expires_at: None,
        decoded_claims: Some(Arc::new(A)),
    };
    assert!(token.claims::<A>().is_some());
    assert!(token.claims::<B>().is_none());
}

// ── Persistence tests ───────────────────────────────────────────

#[tokio::test]
async fn token_store_persists_on_store() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = TokenStore::new().with_persistence(backend.clone());

    let token = test_token("my-access", Some("my-refresh"), Some(Instant::now() + Duration::from_secs(3600)));
    store.store_token("sess-1".to_string(), token).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    let data = backend.dump().await;
    assert!(data.contains_key(&("tokens".to_string(), "sess-1".to_string())));

    let bytes = &data[&("tokens".to_string(), "sess-1".to_string())];
    let persisted: PersistedToken = serde_json::from_slice(bytes).unwrap();
    assert_eq!(persisted.access_token, "my-access");
    assert_eq!(persisted.refresh_token.as_deref(), Some("my-refresh"));
    assert!(persisted.expires_in_secs.unwrap() > 3500);
}

#[tokio::test]
async fn token_store_loads_persisted() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let persisted = PersistedToken {
        access_token: "loaded-token".to_string(),
        refresh_token: Some("loaded-refresh".to_string()),
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
async fn token_store_loads_persisted_applies_claims_decoder() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let persisted = PersistedToken {
        access_token: "admin-jwt".to_string(),
        refresh_token: None,
        expires_in_secs: Some(3600),
    };
    backend.set("tokens", "s1", &serde_json::to_vec(&persisted).unwrap(), None).await.unwrap();

    #[derive(Debug)]
    struct Claims { role: String }

    let store = TokenStore::new()
        .with_claims_decoder(|token: &str| -> Option<Claims> {
            if token == "admin-jwt" { Some(Claims { role: "admin".into() }) } else { None }
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

    backend.set("tokens", "bad", b"not-json{{{", None).await.unwrap();

    let persisted = PersistedToken {
        access_token: "good".to_string(),
        refresh_token: None,
        expires_in_secs: Some(3600),
    };
    backend.set("tokens", "good", &serde_json::to_vec(&persisted).unwrap(), None).await.unwrap();

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

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!backend.dump().await.is_empty());

    store.purge_expired().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(backend.dump().await.is_empty());
}

#[tokio::test]
async fn token_store_remove_cleans_backend() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = TokenStore::new().with_persistence(backend.clone());

    store.store_token("s1".to_string(), test_token("tok", None, None)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(backend.dump().await.contains_key(&("tokens".into(), "s1".into())));

    store.remove_token("s1").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!backend.dump().await.contains_key(&("tokens".into(), "s1".into())));
}

#[tokio::test]
async fn token_store_no_backend_unchanged() {
    let store = TokenStore::new();
    store.store_token("s1".to_string(), test_token("t", None, None)).await;
    assert!(store.get_token_raw("s1").await.is_some());
    store.load_persisted().await.unwrap();
}

// === Opaque token mode tests ===

#[tokio::test]
async fn opaque_store_and_resolve() {
    let store = TokenStore::new();
    store.store_opaque_mapping("s1".into(), "oa1".into(), "or1".into()).await;

    assert_eq!(store.resolve_opaque_access("oa1").await, Some("s1".to_string()));
    assert_eq!(store.resolve_opaque_refresh("or1").await, Some("s1".to_string()));
    assert_eq!(store.resolve_opaque_access("nonexistent").await, None);
    assert_eq!(store.resolve_opaque_refresh("nonexistent").await, None);
}

#[tokio::test]
async fn opaque_rotation_replaces_old() {
    let store = TokenStore::new();
    store.store_opaque_mapping("s1".into(), "oa1".into(), "or1".into()).await;
    store.store_opaque_mapping("s1".into(), "oa2".into(), "or2".into()).await;

    // Old tokens no longer resolve
    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(store.resolve_opaque_refresh("or1").await, None);

    // New tokens resolve correctly
    assert_eq!(store.resolve_opaque_access("oa2").await, Some("s1".to_string()));
    assert_eq!(store.resolve_opaque_refresh("or2").await, Some("s1".to_string()));
}

#[tokio::test]
async fn opaque_remove_for_session() {
    let store = TokenStore::new();
    store.store_opaque_mapping("s1".into(), "oa1".into(), "or1".into()).await;

    store.remove_opaque_for_session("s1").await;

    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(store.resolve_opaque_refresh("or1").await, None);
}

#[tokio::test]
async fn opaque_multiple_sessions() {
    let store = TokenStore::new();
    store.store_opaque_mapping("s1".into(), "oa1".into(), "or1".into()).await;
    store.store_opaque_mapping("s2".into(), "oa2".into(), "or2".into()).await;

    assert_eq!(store.resolve_opaque_access("oa1").await, Some("s1".to_string()));
    assert_eq!(store.resolve_opaque_access("oa2").await, Some("s2".to_string()));

    // Removing s1 doesn't affect s2
    store.remove_opaque_for_session("s1").await;
    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(store.resolve_opaque_access("oa2").await, Some("s2".to_string()));
}

#[tokio::test]
async fn opaque_purge_expired_cleans_mappings() {
    let store = TokenStore::new();

    // Store a token that is already expired
    store.store_token(
        "expired".to_string(),
        test_token("t", None, Some(Instant::now() - Duration::from_secs(1))),
    ).await;
    store.store_opaque_mapping("expired".into(), "oa_e".into(), "or_e".into()).await;

    // Store a valid token
    store.store_token(
        "valid".to_string(),
        test_token("t2", None, Some(Instant::now() + Duration::from_secs(3600))),
    ).await;
    store.store_opaque_mapping("valid".into(), "oa_v".into(), "or_v".into()).await;

    store.purge_expired().await;

    // Expired session's opaque mapping is gone
    assert_eq!(store.resolve_opaque_access("oa_e").await, None);
    // Valid session's opaque mapping remains
    assert_eq!(store.resolve_opaque_access("oa_v").await, Some("valid".to_string()));
}

#[tokio::test]
async fn opaque_remove_token_cleans_opaque_mappings() {
    let store = TokenStore::new();
    store.store_token("s1".to_string(), test_token("t", None, None)).await;
    store.store_opaque_mapping("s1".into(), "oa1".into(), "or1".into()).await;

    store.remove_token("s1").await;

    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(store.resolve_opaque_refresh("or1").await, None);
}

#[tokio::test]
async fn opaque_persistence_roundtrip() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let store = TokenStore::new().with_persistence(backend.clone());
    store.store_token("s1".to_string(), test_token("kc_token", None, Some(Instant::now() + Duration::from_secs(3600)))).await;
    store.store_opaque_mapping("s1".into(), "oa1".into(), "or1".into()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify persisted to backend
    assert!(backend.dump().await.contains_key(&("opaque".into(), "s1".into())));

    // Load into a fresh store
    let store2 = TokenStore::new().with_persistence(backend.clone());
    store2.load_persisted().await.unwrap();

    assert_eq!(store2.resolve_opaque_access("oa1").await, Some("s1".to_string()));
    assert_eq!(store2.resolve_opaque_refresh("or1").await, Some("s1".to_string()));
}

#[tokio::test]
async fn opaque_persistence_orphan_cleanup() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    // Store an opaque mapping but no token — simulates token expiry between restarts
    let mapping = serde_json::to_vec(&serde_json::json!({
        "opaque_access": "oa_orphan",
        "opaque_refresh": "or_orphan",
    })).unwrap();
    backend.set("opaque", "orphan_session", &mapping, None).await.unwrap();

    let store = TokenStore::new().with_persistence(backend.clone());
    store.load_persisted().await.unwrap();

    // Orphaned mapping should not be loaded
    assert_eq!(store.resolve_opaque_access("oa_orphan").await, None);
}

#[tokio::test]
async fn opaque_remove_nonexistent_is_noop() {
    let store = TokenStore::new();
    // Should not panic
    store.remove_opaque_for_session("nonexistent").await;
    assert_eq!(store.resolve_opaque_access("anything").await, None);
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
    fn get(
        &self,
        ns: &str,
        key: &str,
    ) -> BoxFuture<'_, Option<Vec<u8>>> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.get(ns, key)
    }
    fn set(
        &self,
        ns: &str,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> BoxFuture<'_, ()> {
        self.inner.set(ns, key, value, ttl)
    }
    fn delete(
        &self,
        ns: &str,
        key: &str,
    ) -> BoxFuture<'_, ()> {
        self.inner.delete(ns, key)
    }
    fn keys(
        &self,
        ns: &str,
    ) -> BoxFuture<'_, Vec<String>> {
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
    fn release_lock(
        &self,
        ns: &str,
        key: &str,
        token: &str,
    ) -> BoxFuture<'_, ()> {
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
            test_token("acc", Some("ref"), Some(Instant::now() + Duration::from_secs(3600))),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await; // let fire-and-forget persist land

    // Instance B never saw this session in RAM — must resolve via read-through.
    let t = store_b.peek_token("s1").await.expect("B should read token through Redis");
    assert_eq!(t.access_token, "acc");

    // And it is now cached in B (subsequent calls hit RAM).
    assert!(store_b.has_valid_token("s1").await);
}

#[tokio::test]
async fn opaque_read_through_cross_instance() {
    let backend = Arc::new(InMemoryBackend::new());
    let store_a = TokenStore::new().with_persistence(backend.clone());
    let store_b = TokenStore::new().with_persistence(backend.clone());

    store_a
        .store_token(
            "s1".into(),
            test_token("kc", Some("r"), Some(Instant::now() + Duration::from_secs(3600))),
        )
        .await;
    store_a.store_opaque_mapping("s1".into(), "oa".into(), "or".into()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Opaque access resolved on B (the "wrong" instance) — no 401.
    assert_eq!(store_b.resolve_opaque_access("oa").await, Some("s1".to_string()));
    // Refresh opaque now hits the hydrated in-memory index.
    assert_eq!(store_b.resolve_opaque_refresh("or").await, Some("s1".to_string()));
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
            test_token("acc", None, Some(Instant::now() + Duration::from_secs(3600))),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let before = gets.load(std::sync::atomic::Ordering::SeqCst);
    // In-memory hit — must not touch the backend.
    let _ = store.peek_token("s1").await;
    let after = gets.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(before, after, "memory hit should not read through to backend");
}

#[tokio::test]
async fn opaque_rotation_cleans_inverse_index() {
    let backend = Arc::new(InMemoryBackend::new());
    let store_a = TokenStore::new().with_persistence(backend.clone());
    let store_b = TokenStore::new().with_persistence(backend.clone());

    store_a.store_opaque_mapping("s1".into(), "oa_old".into(), "or_old".into()).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    store_a.store_opaque_mapping("s1".into(), "oa_new".into(), "or_new".into()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // New mapping resolves cross-instance.
    assert_eq!(store_b.resolve_opaque_access("oa_new").await, Some("s1".to_string()));
    // Old opaque token no longer resolves anywhere.
    let store_c = TokenStore::new().with_persistence(backend.clone());
    assert_eq!(store_c.resolve_opaque_access("oa_old").await, None);
}

#[tokio::test]
async fn opaque_remove_cross_instance_cleans_inverse() {
    let backend = Arc::new(InMemoryBackend::new());
    let store_a = TokenStore::new().with_persistence(backend.clone());
    let store_b = TokenStore::new().with_persistence(backend.clone());

    store_a.store_opaque_mapping("s1".into(), "oa".into(), "or".into()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // B removes the session it never saw in RAM (recovers opaques from Redis).
    store_b.remove_opaque_for_session("s1").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let store_c = TokenStore::new().with_persistence(backend.clone());
    assert_eq!(store_c.resolve_opaque_access("oa").await, None);
    assert_eq!(store_c.resolve_opaque_refresh("or").await, None);
}

// === Distributed refresh lock ===

#[tokio::test]
async fn inmemory_lock_is_exclusive() {
    let b = InMemoryBackend::new();
    assert!(b.try_acquire_lock("refresh_lock", "s1", "tok1", Duration::from_secs(10)).await.unwrap());
    assert!(!b.try_acquire_lock("refresh_lock", "s1", "tok2", Duration::from_secs(10)).await.unwrap());
    b.release_lock("refresh_lock", "s1", "tok1").await.unwrap();
    assert!(b.try_acquire_lock("refresh_lock", "s1", "tok3", Duration::from_secs(10)).await.unwrap());
}

#[tokio::test]
async fn inmemory_lock_auto_expires() {
    let b = InMemoryBackend::new();
    assert!(b.try_acquire_lock("ns", "k", "t", Duration::from_millis(40)).await.unwrap());
    assert!(!b.try_acquire_lock("ns", "k", "t", Duration::from_millis(40)).await.unwrap());
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(b.try_acquire_lock("ns", "k", "t", Duration::from_millis(40)).await.unwrap());
}

#[tokio::test]
async fn inmemory_lock_release_is_compare_and_delete() {
    // The classic race: holder A's lock TTL expires, peer B re-acquires, then A's
    // late release must NOT drop B's lock.
    let b = InMemoryBackend::new();

    // A acquires with a short TTL.
    assert!(b.try_acquire_lock("refresh_lock", "s1", "token_A", Duration::from_millis(30)).await.unwrap());

    // A's lock expires; B re-acquires under its own token.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(b.try_acquire_lock("refresh_lock", "s1", "token_B", Duration::from_secs(10)).await.unwrap());

    // A's late release targets its own (now-expired) token → must be a no-op.
    b.release_lock("refresh_lock", "s1", "token_A").await.unwrap();

    // B still holds the lock — a third party cannot acquire it.
    assert!(!b.try_acquire_lock("refresh_lock", "s1", "token_C", Duration::from_secs(10)).await.unwrap());

    // Only B's own release frees it.
    b.release_lock("refresh_lock", "s1", "token_B").await.unwrap();
    assert!(b.try_acquire_lock("refresh_lock", "s1", "token_C", Duration::from_secs(10)).await.unwrap());
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
            test_token("expired", Some("r"), Some(Instant::now() - Duration::from_secs(60))),
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

    let got = store.get_token("s1").await.expect("should adopt peer token");
    assert_eq!(got.access_token, "fresh_acc");
}
