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

use crate::persistence::{InMemoryBackend, PersistenceBackend};

// === Opaque token mode tests ===

#[tokio::test]
async fn opaque_store_and_resolve() {
    let store = TokenStore::new();
    store
        .store_opaque_mapping("s1".into(), "oa1".into(), "or1".into())
        .await;

    assert_eq!(
        store.resolve_opaque_access("oa1").await,
        Some("s1".to_string())
    );
    assert_eq!(
        store.resolve_opaque_refresh("or1").await,
        Some("s1".to_string())
    );
    assert_eq!(store.resolve_opaque_access("nonexistent").await, None);
    assert_eq!(store.resolve_opaque_refresh("nonexistent").await, None);
}

#[tokio::test]
async fn opaque_access_expiry_is_enforced_independently_from_refresh() {
    let backend = Arc::new(InMemoryBackend::new());
    let store = TokenStore::new().with_persistence(backend.clone());
    store
        .store_opaque_mapping_with_access_ttl(
            "s1".into(),
            "short-access".into(),
            "long-refresh".into(),
            Duration::from_millis(10),
        )
        .await;

    tokio::time::sleep(Duration::from_millis(25)).await;

    assert_eq!(store.resolve_opaque_access("short-access").await, None);
    assert_eq!(
        store.resolve_opaque_refresh("long-refresh").await,
        Some("s1".to_string())
    );

    // The backend used by this test deliberately ignores TTLs. A fresh replica
    // must therefore reject the expired access token from the absolute deadline.
    let fresh_replica = TokenStore::new().with_persistence(backend);
    assert_eq!(
        fresh_replica.resolve_opaque_access("short-access").await,
        None
    );
    assert_eq!(
        fresh_replica.resolve_opaque_refresh("long-refresh").await,
        Some("s1".to_string())
    );
}

#[tokio::test]
async fn opaque_rotation_replaces_old() {
    let store = TokenStore::new();
    store
        .store_opaque_mapping("s1".into(), "oa1".into(), "or1".into())
        .await;
    store
        .store_opaque_mapping("s1".into(), "oa2".into(), "or2".into())
        .await;

    // Old tokens no longer resolve
    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(store.resolve_opaque_refresh("or1").await, None);

    // New tokens resolve correctly
    assert_eq!(
        store.resolve_opaque_access("oa2").await,
        Some("s1".to_string())
    );
    assert_eq!(
        store.resolve_opaque_refresh("or2").await,
        Some("s1".to_string())
    );
}

#[tokio::test]
async fn opaque_remove_for_session() {
    let store = TokenStore::new();
    store
        .store_opaque_mapping("s1".into(), "oa1".into(), "or1".into())
        .await;

    store.remove_opaque_for_session("s1").await;

    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(store.resolve_opaque_refresh("or1").await, None);
}

#[tokio::test]
async fn opaque_multiple_sessions() {
    let store = TokenStore::new();
    store
        .store_opaque_mapping("s1".into(), "oa1".into(), "or1".into())
        .await;
    store
        .store_opaque_mapping("s2".into(), "oa2".into(), "or2".into())
        .await;

    assert_eq!(
        store.resolve_opaque_access("oa1").await,
        Some("s1".to_string())
    );
    assert_eq!(
        store.resolve_opaque_access("oa2").await,
        Some("s2".to_string())
    );

    // Removing s1 doesn't affect s2
    store.remove_opaque_for_session("s1").await;
    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(
        store.resolve_opaque_access("oa2").await,
        Some("s2".to_string())
    );
}

#[tokio::test]
async fn opaque_purge_expired_cleans_mappings() {
    let store = TokenStore::new();

    // Store a token that is already expired
    store
        .store_token(
            "expired".to_string(),
            test_token("t", None, Some(Instant::now() - Duration::from_secs(1))),
        )
        .await;
    store
        .store_opaque_mapping("expired".into(), "oa_e".into(), "or_e".into())
        .await;

    // Store a valid token
    store
        .store_token(
            "valid".to_string(),
            test_token("t2", None, Some(Instant::now() + Duration::from_secs(3600))),
        )
        .await;
    store
        .store_opaque_mapping("valid".into(), "oa_v".into(), "or_v".into())
        .await;

    store.purge_expired().await;

    // Expired session's opaque mapping is gone
    assert_eq!(store.resolve_opaque_access("oa_e").await, None);
    // Valid session's opaque mapping remains
    assert_eq!(
        store.resolve_opaque_access("oa_v").await,
        Some("valid".to_string())
    );
}

#[tokio::test]
async fn opaque_remove_token_cleans_opaque_mappings() {
    let store = TokenStore::new();
    store
        .store_token("s1".to_string(), test_token("t", None, None))
        .await;
    store
        .store_opaque_mapping("s1".into(), "oa1".into(), "or1".into())
        .await;

    store.remove_token("s1").await;

    assert_eq!(store.resolve_opaque_access("oa1").await, None);
    assert_eq!(store.resolve_opaque_refresh("or1").await, None);
}

#[tokio::test]
async fn opaque_persistence_roundtrip() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    let store = TokenStore::new().with_persistence(backend.clone());
    store
        .store_token(
            "s1".to_string(),
            test_token(
                "kc_token",
                None,
                Some(Instant::now() + Duration::from_secs(3600)),
            ),
        )
        .await;
    store
        .store_opaque_mapping("s1".into(), "oa1".into(), "or1".into())
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify persisted to backend
    assert!(
        backend
            .dump()
            .await
            .contains_key(&("opaque".into(), "s1".into()))
    );

    // Load into a fresh store
    let store2 = TokenStore::new().with_persistence(backend.clone());
    store2.load_persisted().await.unwrap();

    assert_eq!(
        store2.resolve_opaque_access("oa1").await,
        Some("s1".to_string())
    );
    assert_eq!(
        store2.resolve_opaque_refresh("or1").await,
        Some("s1".to_string())
    );
}

#[tokio::test]
async fn opaque_persistence_orphan_cleanup() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());

    // Store an opaque mapping but no token — simulates token expiry between restarts
    let mapping = serde_json::to_vec(&serde_json::json!({
        "opaque_access": "oa_orphan",
        "opaque_refresh": "or_orphan",
    }))
    .unwrap();
    backend
        .set("opaque", "orphan_session", &mapping, None)
        .await
        .unwrap();

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

#[tokio::test]
async fn opaque_read_through_cross_instance() {
    let backend = Arc::new(InMemoryBackend::new());
    let store_a = TokenStore::new().with_persistence(backend.clone());
    let store_b = TokenStore::new().with_persistence(backend.clone());

    store_a
        .store_token(
            "s1".into(),
            test_token(
                "kc",
                Some("r"),
                Some(Instant::now() + Duration::from_secs(3600)),
            ),
        )
        .await;
    store_a
        .store_opaque_mapping("s1".into(), "oa".into(), "or".into())
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Opaque access resolved on B (the "wrong" instance) — no 401.
    assert_eq!(
        store_b.resolve_opaque_access("oa").await,
        Some("s1".to_string())
    );
    // Refresh opaque now hits the hydrated in-memory index.
    assert_eq!(
        store_b.resolve_opaque_refresh("or").await,
        Some("s1".to_string())
    );
}

#[tokio::test]
async fn opaque_rotation_cleans_inverse_index() {
    let backend = Arc::new(InMemoryBackend::new());
    let store_a = TokenStore::new().with_persistence(backend.clone());
    let store_b = TokenStore::new().with_persistence(backend.clone());

    store_a
        .store_opaque_mapping("s1".into(), "oa_old".into(), "or_old".into())
        .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    store_a
        .store_opaque_mapping("s1".into(), "oa_new".into(), "or_new".into())
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // New mapping resolves cross-instance.
    assert_eq!(
        store_b.resolve_opaque_access("oa_new").await,
        Some("s1".to_string())
    );
    // Old opaque token no longer resolves anywhere.
    let store_c = TokenStore::new().with_persistence(backend.clone());
    assert_eq!(store_c.resolve_opaque_access("oa_old").await, None);
}

#[tokio::test]
async fn opaque_remove_cross_instance_cleans_inverse() {
    let backend = Arc::new(InMemoryBackend::new());
    let store_a = TokenStore::new().with_persistence(backend.clone());
    let store_b = TokenStore::new().with_persistence(backend.clone());

    store_a
        .store_opaque_mapping("s1".into(), "oa".into(), "or".into())
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // B removes the session it never saw in RAM (recovers opaques from Redis).
    store_b.remove_opaque_for_session("s1").await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let store_c = TokenStore::new().with_persistence(backend.clone());
    assert_eq!(store_c.resolve_opaque_access("oa").await, None);
    assert_eq!(store_c.resolve_opaque_refresh("or").await, None);
}
