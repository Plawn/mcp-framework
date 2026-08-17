//! Local validation of bearer tokens against the issuer's published JWKS.
//!
//! RFC 7662 introspection is the framework's original way of checking a bearer
//! it did not mint, but it is not always available: Keycloak refuses the
//! introspection endpoint to **public** clients with `403 Client not allowed.`.
//! That refusal is a property of the configured `OAUTH_CLIENT_ID`, not of the
//! token, so a perfectly valid JWT — for instance one obtained by
//! token-exchange and forwarded as `Authorization: Bearer` — could never be
//! accepted.
//!
//! Verifying the signature against the issuer's public keys has no such
//! requirement. This module discovers `jwks_uri` from
//! `{issuer}/.well-known/openid-configuration`, caches the keys by `kid`, and
//! verifies tokens with [`jsonwebtoken`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::constants::{
    JWKS_CACHE_TTL, JWKS_CLOCK_SKEW_LEEWAY, JWKS_FETCH_TIMEOUT, JWKS_REFRESH_COOLDOWN,
};

/// Signature algorithms accepted for a locally validated bearer.
///
/// Asymmetric only, deliberately. Allowing an HMAC family here would let an
/// attacker present a token signed with the *public* key as if it were a shared
/// secret — the classic `alg` confusion attack.
const ACCEPTED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Why a token could not be accepted on the JWKS path.
///
/// The distinction matters to the caller: [`Unavailable`](Self::Unavailable) and
/// [`UnknownKey`](Self::UnknownKey) mean "JWKS could not answer" and may fall
/// through to introspection, whereas [`Invalid`](Self::Invalid) is a verdict —
/// the issuer's own keys rejected the token and no second opinion is warranted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksRejection {
    /// The credential is not a JWT at all (opaque token, or unparsable header).
    NotAJwt,
    /// The token's `alg` is not one this framework accepts.
    UnsupportedAlgorithm(String),
    /// No key matched the token's `kid`, even after a refetch.
    UnknownKey,
    /// Discovery or the JWKS fetch failed — the issuer could not be consulted.
    Unavailable(String),
    /// The token was checked against the issuer's keys and did not pass.
    Invalid(String),
}

impl std::fmt::Display for JwksRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAJwt => write!(f, "credential is not a JWT"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported JWT algorithm '{alg}'"),
            Self::UnknownKey => write!(f, "no issuer key matches the token's kid"),
            Self::Unavailable(why) => write!(f, "issuer keys unavailable: {why}"),
            Self::Invalid(why) => write!(f, "token rejected by issuer keys: {why}"),
        }
    }
}

impl JwksRejection {
    /// Whether the caller may still ask the authorization server. A token the
    /// issuer's keys actively rejected must not get a second chance.
    pub fn may_fall_back(&self) -> bool {
        !matches!(self, Self::Invalid(_))
    }
}

/// The subset of a validated JWT's claims the framework itself cares about.
///
/// Consumer-defined claims stay the business of the configured
/// [`claims_decoder`](crate::auth::TokenStore::with_claims_decoder); this struct
/// only carries what auth needs: when the token dies, who it belongs to, and the
/// audience actually observed (logged so a deployment can tighten
/// `OAUTH_EXPECTED_AUDIENCE` from real traffic).
#[derive(Debug, Clone, Default)]
pub struct ValidatedJwt {
    pub subject: Option<String>,
    pub expires_at: Option<Instant>,
    pub audiences: Vec<String>,
    pub authorized_party: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisteredClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    aud: Option<Audience>,
}

/// `aud` is a string or an array of strings (RFC 7519 §4.1.3).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    jwks_uri: String,
}

#[derive(Default)]
struct KeyCache {
    /// `kid` → key. Keys published without a `kid` are stored under `""` and
    /// used for tokens whose header omits `kid` too.
    keys: HashMap<String, Arc<DecodingKey>>,
    /// When the keys currently held were successfully loaded.
    fetched_at: Option<Instant>,
    /// When a fetch was last *attempted*, successful or not. The cooldown keys
    /// off this rather than off `fetched_at`, so an issuer that is down does not
    /// get one outbound request per inbound request either.
    attempted_at: Option<Instant>,
    /// Why the last attempt failed, replayed to callers during the cooldown so a
    /// cache miss caused by an unreachable issuer is not misreported as an
    /// unknown key.
    last_error: Option<String>,
}

impl KeyCache {
    fn is_stale(&self) -> bool {
        match self.fetched_at {
            Some(at) => at.elapsed() >= JWKS_CACHE_TTL,
            None => true,
        }
    }

    /// Whether a fetch is permitted right now (anti-hammering guard).
    fn cooldown_elapsed(&self) -> bool {
        match self.attempted_at {
            Some(at) => at.elapsed() >= JWKS_REFRESH_COOLDOWN,
            None => true,
        }
    }
}

/// Verifies bearer tokens against the OIDC issuer's published signing keys.
///
/// Cheap to clone (all state is behind `Arc`), so one instance is shared by the
/// whole process and its key cache is shared with it.
#[derive(Clone)]
pub struct JwksValidator {
    issuer: String,
    discovery_url: String,
    expected_audiences: Arc<Vec<String>>,
    http_client: HttpClient,
    cache: Arc<RwLock<KeyCache>>,
    /// Serializes refetches so a burst of requests triggers one fetch, not N.
    fetch_lock: Arc<Mutex<()>>,
}

impl JwksValidator {
    pub fn new(issuer_url: &str, expected_audiences: Vec<String>, http_client: HttpClient) -> Self {
        let issuer = issuer_url.trim_end_matches('/').to_string();
        Self {
            discovery_url: format!("{issuer}/.well-known/openid-configuration"),
            issuer,
            expected_audiences: Arc::new(expected_audiences),
            http_client,
            cache: Arc::new(RwLock::new(KeyCache::default())),
            fetch_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Verify `token` against the issuer's keys.
    ///
    /// Checks, in order: the token parses as a JWT with an accepted asymmetric
    /// `alg`; a published key matches its `kid`; the signature holds; and `iss`,
    /// `exp`, `nbf` (and `aud` when configured) are satisfied.
    pub async fn validate(&self, token: &str) -> Result<ValidatedJwt, JwksRejection> {
        let header = decode_header(token).map_err(|_| JwksRejection::NotAJwt)?;

        if !ACCEPTED_ALGORITHMS.contains(&header.alg) {
            return Err(JwksRejection::UnsupportedAlgorithm(format!(
                "{:?}",
                header.alg
            )));
        }

        let kid = header.kid.unwrap_or_default();

        // Miss (or stale cache) → refetch once, then look again. A `kid` that is
        // still unknown afterwards is not retried: the cooldown inside
        // `refresh_keys` makes the second attempt a no-op anyway.
        let key = match self.cached_key(&kid).await {
            Some(key) => key,
            None => {
                self.refresh_keys().await?;
                // Second lookup ignores the TTL: we just made our best effort to
                // refresh, and a key we still hold beats rejecting a token the
                // issuer really did sign. Keys are only dropped by a *successful*
                // refresh, so this cannot resurrect a rotated-out key forever.
                self.cache
                    .read()
                    .await
                    .keys
                    .get(&kid)
                    .cloned()
                    .ok_or(JwksRejection::UnknownKey)?
            }
        };

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = JWKS_CLOCK_SKEW_LEEWAY.as_secs();
        validation.set_required_spec_claims(&["exp", "iss"]);
        if self.expected_audiences.is_empty() {
            // Unconstrained by configuration. A token-exchange token legitimately
            // carries the *downstream* service as `aud`, so refusing an audience
            // we were never told about would break the very case this path exists
            // for. The observed value is logged by the caller instead.
            validation.validate_aud = false;
        } else {
            validation.set_audience(self.expected_audiences.as_slice());
        }

        let data = decode::<RegisteredClaims>(token, &key, &validation)
            .map_err(|e| JwksRejection::Invalid(e.to_string()))?;

        Ok(ValidatedJwt {
            subject: data.claims.sub,
            expires_at: data.claims.exp.and_then(remaining_from_unix_secs),
            audiences: data.claims.aud.map(Audience::into_vec).unwrap_or_default(),
            authorized_party: data.claims.azp,
        })
    }

    /// Look up a key by `kid`, treating a stale cache as a miss so the TTL
    /// forces a refetch.
    async fn cached_key(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        let cache = self.cache.read().await;
        if cache.is_stale() {
            return None;
        }
        cache.keys.get(kid).cloned()
    }

    /// Fetch the JWKS (discovering `jwks_uri` first) and replace the cache.
    ///
    /// Rate-limited: while the cooldown has not elapsed this makes no network
    /// call at all, so neither an unknown `kid` nor an issuer that is down can
    /// be turned into one outbound request per inbound request. During the
    /// cooldown the previous outcome is replayed — keys still cached means
    /// `Ok`, otherwise the error that left the cache empty.
    async fn refresh_keys(&self) -> Result<(), JwksRejection> {
        let _guard = self.fetch_lock.lock().await;

        // Another task may have fetched while we waited for the lock.
        {
            let cache = self.cache.read().await;
            if !cache.cooldown_elapsed() {
                return match &cache.last_error {
                    Some(e) if cache.keys.is_empty() => Err(JwksRejection::Unavailable(e.clone())),
                    _ => Ok(()),
                };
            }
        }

        let outcome = self.fetch_keys().await;
        let mut cache = self.cache.write().await;
        cache.attempted_at = Some(Instant::now());

        match outcome {
            Ok(keys) => {
                tracing::debug!(
                    issuer = %self.issuer,
                    keys = keys.len(),
                    "Refreshed issuer signing keys from JWKS"
                );
                cache.keys = keys;
                cache.fetched_at = Some(Instant::now());
                cache.last_error = None;
                Ok(())
            }
            Err(e) => {
                // The previously fetched keys are deliberately kept: an issuer
                // that is briefly unreachable should not invalidate tokens it
                // already signed with keys we hold.
                cache.last_error = Some(e.clone());
                Err(JwksRejection::Unavailable(e))
            }
        }
    }

    /// The network half of [`Self::refresh_keys`], with no cache bookkeeping.
    async fn fetch_keys(&self) -> Result<HashMap<String, Arc<DecodingKey>>, String> {
        let jwks_uri = self.discover_jwks_uri().await?;
        let jwks: JwkSet = self.fetch_json(&jwks_uri).await?;

        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => {
                    keys.insert(jwk_kid(jwk), Arc::new(key));
                }
                Err(e) => {
                    // A JWKS legitimately mixes key types (Keycloak publishes an
                    // encryption key alongside the signing one). Skip what we
                    // cannot use rather than failing the whole refresh.
                    tracing::debug!(kid = %jwk_kid(jwk), "Skipping unusable JWKS entry: {e}");
                }
            }
        }

        if keys.is_empty() {
            return Err(format!("JWKS at {jwks_uri} contains no usable key"));
        }
        Ok(keys)
    }

    async fn discover_jwks_uri(&self) -> Result<String, String> {
        let document: DiscoveryDocument = self.fetch_json(&self.discovery_url).await?;
        Ok(document.jwks_uri)
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, String> {
        let response = self
            .http_client
            .get(url)
            .timeout(JWKS_FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("GET {url} failed: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            return Err(format!("GET {url} returned {status}"));
        }

        response
            .json()
            .await
            .map_err(|e| format!("GET {url} returned an unparsable body: {e}"))
    }
}

/// The cache key for a published key: its `kid`, or `""` when the issuer
/// publishes a single unnamed key.
fn jwk_kid(jwk: &Jwk) -> String {
    jwk.common.key_id.clone().unwrap_or_default()
}

/// Convert a `exp` (seconds since the epoch) into an [`Instant`], or `None` when
/// it is already in the past. `decode` has enforced `exp` by the time this runs,
/// so `None` only happens within the leeway window.
fn remaining_from_unix_secs(exp: u64) -> Option<Instant> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let remaining = exp.checked_sub(now)?;
    Some(Instant::now() + Duration::from_secs(remaining))
}

#[cfg(test)]
#[path = "jwks_tests.rs"]
mod tests;
