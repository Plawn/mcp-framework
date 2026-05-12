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
