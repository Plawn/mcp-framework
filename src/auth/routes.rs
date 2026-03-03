use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope,
};
use serde::Deserialize;
use std::sync::Arc;

use super::{OAuthConfig, TokenStore, StoredToken};
use super::templates;
use crate::http_util::HttpError;

/// Shared state for OAuth routes
#[derive(Clone)]
pub struct OAuthState {
    pub config: OAuthConfig,
    pub store: TokenStore,
    pub http_client: reqwest::Client,
    pub app_name: String,
}

/// Query params for the callback
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// Query params for starting auth flow
#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    /// Optional session ID to associate the token with
    pub session_id: Option<String>,
}

/// Create the OAuth router
pub fn oauth_router(state: OAuthState) -> Router {
    Router::new()
        .route("/login", get(login_handler))
        .route("/callback", get(callback_handler))
        .route("/status", get(status_handler))
        .with_state(Arc::new(state))
}

/// Handler to start the OAuth flow
async fn login_handler(
    State(state): State<Arc<OAuthState>>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<impl IntoResponse, HttpError> {
    let client = state.config.build_client().map_err(|e| {
        tracing::error!("Failed to build OAuth client: {}", e);
        HttpError::internal("OAuth configuration error")
    })?;

    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate state (include session_id if provided)
    let csrf_state = match &query.session_id {
        Some(sid) => format!("{}:{}", uuid::Uuid::new_v4(), sid),
        None => uuid::Uuid::new_v4().to_string(),
    };

    // Build authorization URL
    let mut auth_request = client
        .authorize_url(|| CsrfToken::new(csrf_state.clone()))
        .set_pkce_challenge(pkce_challenge);

    // Add scopes
    for scope in &state.config.scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, _) = auth_request.url();

    // Store pending auth
    state.store.store_pending_auth(
        csrf_state,
        pkce_verifier.secret().clone(),
    ).await;

    Ok(Redirect::temporary(auth_url.as_str()))
}

/// Handler for OAuth callback
async fn callback_handler(
    State(state): State<Arc<OAuthState>>,
    Query(query): Query<CallbackQuery>,
) -> Result<impl IntoResponse, HttpError> {
    // Retrieve pending auth
    let pending = state.store.take_pending_auth(&query.state).await.ok_or_else(|| {
        tracing::warn!("Invalid or expired OAuth state: {}", query.state);
        HttpError::bad_request("Invalid or expired authentication state")
    })?;

    if pending.is_expired() {
        return Err(HttpError::bad_request("Authentication request has timed out"));
    }

    // Extract session_id from state if present
    let session_id = query.state.split(':').nth(1).map(|s| s.to_string());

    let client = state.config.build_client().map_err(|e| {
        tracing::error!("Failed to build OAuth client: {}", e);
        HttpError::internal("OAuth configuration error")
    })?;

    // Exchange code for token using the shared HTTP client
    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code))
        .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
        .request_async(&state.http_client)
        .await
        .map_err(|e| {
            tracing::error!("Token exchange failed: {:?}", e);
            HttpError::internal(format!("Failed to exchange authorization code: {}", e))
        })?;

    let stored_token = StoredToken::from_token_response(&token_response);

    // Store with session_id if available, otherwise use a generated one
    let final_session_id = session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    state.store.store_token(final_session_id.clone(), stored_token).await;

    tracing::info!("OAuth successful for session: {}", final_session_id);

    Ok(templates::success_page(&final_session_id, &state.app_name))
}

/// Handler to check auth status
async fn status_handler(
    State(state): State<Arc<OAuthState>>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<&'static str, HttpError> {
    let session_id = query
        .session_id
        .as_deref()
        .ok_or_else(|| HttpError::bad_request("session_id required"))?;

    if state.store.has_valid_token(session_id).await {
        Ok("authenticated")
    } else {
        Err(HttpError::unauthorized("not authenticated"))
    }
}
