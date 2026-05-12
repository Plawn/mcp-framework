use super::*;

#[tokio::test]
async fn in_memory_backend_roundtrip() {
    let backend = InMemoryBackend::new();

    assert!(backend.get("ns", "key1").await.unwrap().is_none());

    backend.set("ns", "key1", b"hello", None).await.unwrap();
    assert_eq!(
        backend.get("ns", "key1").await.unwrap().as_deref(),
        Some(b"hello".as_slice())
    );

    let keys = backend.keys("ns").await.unwrap();
    assert_eq!(keys, vec!["key1".to_string()]);

    assert!(backend.keys("other_ns").await.unwrap().is_empty());

    backend.delete("ns", "key1").await.unwrap();
    assert!(backend.get("ns", "key1").await.unwrap().is_none());
}

#[tokio::test]
async fn in_memory_backend_namespace_isolation() {
    let backend = InMemoryBackend::new();

    backend.set("tokens", "k", b"token", None).await.unwrap();
    backend
        .set("sessions", "k", b"session", None)
        .await
        .unwrap();

    assert_eq!(
        backend.get("tokens", "k").await.unwrap().as_deref(),
        Some(b"token".as_slice())
    );
    assert_eq!(
        backend.get("sessions", "k").await.unwrap().as_deref(),
        Some(b"session".as_slice())
    );
}
