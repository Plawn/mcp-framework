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

    let expired_token = test_token(
        "old_access",
        Some("refresh_tok"),
        Some(Instant::now() - Duration::from_secs(60)),
    );
    store
        .store_token("session1".to_string(), expired_token)
        .await;

    let result = store.get_token("session1").await;
    assert!(
        result.is_none(),
        "Expected None when refresh fails on expired token"
    );
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

    let expired_token = test_token(
        "old",
        Some("refresh"),
        Some(Instant::now() - Duration::from_secs(60)),
    );
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
    let token = test_token(
        "valid",
        None,
        Some(Instant::now() + Duration::from_secs(3600)),
    );
    store.store_token("s1".to_string(), token).await;

    let result = store.get_token("s1").await;
    assert!(result.is_some());
    assert_eq!(result.unwrap().access_token, "valid");
}

#[tokio::test]
async fn test_expired_token_no_refresh_config_returns_none() {
    let store = TokenStore::new();
    let token = test_token(
        "expired",
        Some("refresh"),
        Some(Instant::now() - Duration::from_secs(60)),
    );
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

    let valid = test_token(
        "fresh",
        None,
        Some(Instant::now() + Duration::from_secs(3600)),
    );
    store.store_token("valid-sess".to_string(), valid).await;

    store.purge_expired().await;

    assert!(store.get_token_raw("expired-sess").await.is_none());
    assert!(
        !store
            .refresh_locks
            .read()
            .await
            .contains_key("expired-sess")
    );

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
async fn purge_keeps_expired_token_when_it_can_be_refreshed() {
    let backend = Arc::new(crate::persistence::InMemoryBackend::new());
    let store = TokenStore::new().with_persistence(backend.clone());
    store
        .store_token(
            "refreshable".to_string(),
            test_token(
                "expired-access",
                Some("still-valid-refresh"),
                Some(Instant::now() - Duration::from_secs(60)),
            ),
        )
        .await;

    store.purge_expired().await;

    let retained = store
        .peek_token("refreshable")
        .await
        .expect("refresh material retained");
    assert_eq!(
        retained.refresh_token.as_deref(),
        Some("still-valid-refresh")
    );
    assert!(
        backend
            .dump()
            .await
            .contains_key(&("tokens".to_string(), "refreshable".to_string()))
    );
}

#[tokio::test]
async fn test_claims_decoder_applied_on_store() {
    #[derive(Debug)]
    struct Claims {
        role: String,
    }

    let store = TokenStore::new().with_claims_decoder(|token: &str| -> Option<Claims> {
        if token == "admin-jwt" {
            Some(Claims {
                role: "admin".into(),
            })
        } else {
            None
        }
    });

    store
        .store_token("s1".to_string(), test_token("admin-jwt", None, None))
        .await;
    let stored = store.get_token_raw("s1").await.unwrap();
    let claims = stored
        .claims::<Claims>()
        .expect("should have decoded claims");
    assert_eq!(claims.role, "admin");

    store
        .store_token("s2".to_string(), test_token("unknown", None, None))
        .await;
    let stored = store.get_token_raw("s2").await.unwrap();
    assert!(stored.claims::<Claims>().is_none());
}

#[tokio::test]
async fn test_no_decoder_leaves_claims_none() {
    let store = TokenStore::new();
    store
        .store_token("s1".to_string(), test_token("any", None, None))
        .await;
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
