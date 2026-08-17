//! Unit tests for the JWKS cache's staleness / cooldown arithmetic.
//!
//! End-to-end verification (signature, `iss`, `exp`, `aud`, unknown-`kid`
//! refetch) runs against a real mock issuer in `tests/oauth_jwks_validation.rs`.

use super::*;

#[test]
fn an_empty_cache_is_stale_and_may_be_fetched() {
    let cache = KeyCache::default();
    assert!(cache.is_stale());
    assert!(cache.cooldown_elapsed());
}

#[test]
fn a_fresh_cache_is_neither_stale_nor_refetchable() {
    let cache = KeyCache {
        keys: HashMap::new(),
        fetched_at: Some(Instant::now()),
        attempted_at: Some(Instant::now()),
        last_error: None,
    };
    assert!(!cache.is_stale());
    // This is the anti-hammering guard: a token carrying a random `kid` misses
    // the cache on every request, and must not turn into one outbound JWKS
    // fetch per inbound request.
    assert!(!cache.cooldown_elapsed());
}

#[test]
fn a_failed_fetch_also_engages_the_cooldown() {
    // The cooldown keys off `attempted_at`, not `fetched_at` — otherwise an
    // issuer that is down (no keys ever cached, `fetched_at` still `None`)
    // would be retried on every single inbound request.
    let cache = KeyCache {
        keys: HashMap::new(),
        fetched_at: None,
        attempted_at: Some(Instant::now()),
        last_error: Some("connection refused".into()),
    };
    assert!(cache.is_stale());
    assert!(!cache.cooldown_elapsed());
}

#[test]
fn the_cooldown_expires_before_the_ttl() {
    // Otherwise a rotated signing key could only be picked up after the full
    // TTL, even though an unknown `kid` is exactly the signal that it rotated.
    assert!(JWKS_REFRESH_COOLDOWN < JWKS_CACHE_TTL);
}

#[test]
fn symmetric_algorithms_are_never_accepted() {
    // Accepting an HMAC family alongside RSA is the `alg` confusion attack:
    // the issuer's *public* key is public, so it would double as the shared
    // secret an attacker signs their own tokens with.
    for alg in ACCEPTED_ALGORITHMS {
        assert_ne!(alg.family(), jsonwebtoken::AlgorithmFamily::Hmac);
    }
}

#[test]
fn a_verdict_from_the_issuers_keys_is_final() {
    // "Could not answer" may fall through to introspection; "checked it, it's
    // bad" must not get a second opinion.
    assert!(JwksRejection::NotAJwt.may_fall_back());
    assert!(JwksRejection::UnknownKey.may_fall_back());
    assert!(JwksRejection::Unavailable("boom".into()).may_fall_back());
    assert!(!JwksRejection::Invalid("bad signature".into()).may_fall_back());
}

#[test]
fn an_unnamed_published_key_is_cached_under_the_empty_kid() {
    // A header without `kid` resolves to `""`, so a JWKS holding a single
    // unnamed key still matches it.
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "RSA",
        "n": "t9pJsVVvTdGuph_D6wVlw84VxTSHsmd2OoJRsL1_2N3BAu9DGSascsocrCPogzGmd-AaEr2VNMWub8Erdt4HhdYuCSRYVwDRjquOyKsBFH1p7QQqzohUdrgvvhBbzAWhZo0JkBEcd7f1dyJoZoyANs3r0-g_xUj_6DqE3Fb9DU7s22dv_aPfna7_yWcmYXv2Nd9AK9NE33KLAxUQ7VOPm2mBuP0c5bJxQID0LCcYgpas01Sf3m5QLH_ywiL78z2s2h-rQRJoKAoi7yGtgtwZcYplFbk6EsvUHRRnIFoP2nlCAF3i_wgeIyPEXsLTxl25lXFJnPnROZobWpH42JSttQ",
        "e": "AQAB"
    }))
    .expect("valid RSA JWK");

    assert_eq!(jwk_kid(&jwk), "");
}
