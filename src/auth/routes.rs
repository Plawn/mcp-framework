use axum::{
    Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use serde::Deserialize;
use std::sync::Arc;

use super::templates;
use super::{OAuthConfig, ProxiedAuthorization, StoredToken, TokenStore};
use crate::constants::{OAUTH_CALLBACK_PATH, OAUTH_LOGIN_PATH, OAUTH_STATUS_PATH};
use crate::http_util::HttpError;

/// Shared state for OAuth routes
#[derive(Clone)]
pub struct OAuthState {
    pub config: OAuthConfig,
    pub store: TokenStore,
    pub http_client: reqwest::Client,
    pub app_name: String,
}

/// Query params for the callback.
///
/// `code` is absent on an error response (RFC 6749 §4.1.2.1). Keycloak's other
/// parameters (`iss`, `session_state`) are ignored: on the proxied flow the
/// framework issues its own `iss`.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
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
        .route(OAUTH_LOGIN_PATH, get(login_handler))
        .route(OAUTH_CALLBACK_PATH, get(callback_handler))
        .route(OAUTH_STATUS_PATH, get(status_handler))
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
    state
        .store
        .store_pending_auth(csrf_state, pkce_verifier.secret().clone())
        .await;

    Ok(Redirect::temporary(auth_url.as_str()))
}

/// Handler for `/oauth/callback`, shared by two flows told apart by `state`:
///
/// - a `state` minted by `/oauth/authorize` (the proxy an MCP client drives):
///   the response is forwarded to the client's `redirect_uri` — see
///   [`forward_proxied_callback`];
/// - anything else is the historical server-side login started at
///   `/oauth/login`, unchanged.
///
/// One route rather than two because this is the server callback the Keycloak
/// client is already configured to allow.
async fn callback_handler(
    State(state): State<Arc<OAuthState>>,
    Query(query): Query<CallbackQuery>,
) -> Result<axum::response::Response, HttpError> {
    if let Some(proxied) = state.store.take_proxied_authorization(&query.state).await {
        return forward_proxied_callback(&proxied, &query);
    }
    login_callback(&state, query)
        .await
        .map(IntoResponse::into_response)
}

/// Complete the client's leg of a proxied authorization: `302` to its
/// `redirect_uri` with Keycloak's `code` (or error), the client's own `state`,
/// and `iss` set to the issuer this server advertises (RFC 9207 §2).
fn forward_proxied_callback(
    proxied: &ProxiedAuthorization,
    query: &CallbackQuery,
) -> Result<axum::response::Response, HttpError> {
    let mut target = url::Url::parse(&proxied.redirect_uri).map_err(|e| {
        tracing::error!("Stored redirect_uri no longer parses: {e}");
        HttpError::internal("Invalid stored redirect_uri")
    })?;

    {
        let mut pairs = target.query_pairs_mut();
        match (&query.code, &query.error) {
            (Some(code), None) => {
                pairs.append_pair("code", code);
            }
            (_, Some(error)) => {
                pairs.append_pair("error", error);
                if let Some(description) = &query.error_description {
                    pairs.append_pair("error_description", description);
                }
                if let Some(uri) = &query.error_uri {
                    pairs.append_pair("error_uri", uri);
                }
            }
            (None, None) => {
                return Err(HttpError::bad_request(
                    "Authorization response carries neither code nor error",
                ));
            }
        }
        if let Some(client_state) = &proxied.client_state {
            pairs.append_pair("state", client_state);
        }
        pairs.append_pair("iss", &proxied.issuer);
    }

    tracing::info!(
        error = query.error.as_deref(),
        "Forwarding proxied authorization response to the client"
    );

    Ok((
        axum::http::StatusCode::FOUND,
        [(axum::http::header::LOCATION, target.to_string())],
    )
        .into_response())
}

/// The historical `/oauth/login` flow: server-side code exchange.
async fn login_callback(
    state: &OAuthState,
    query: CallbackQuery,
) -> Result<impl IntoResponse + use<>, HttpError> {
    let Some(code) = query.code else {
        tracing::warn!(
            "OAuth login failed at the authorization server: {:?}",
            query.error
        );
        return Err(HttpError::bad_request(format!(
            "Authentication failed: {}",
            query.error.as_deref().unwrap_or("no authorization code")
        )));
    };

    // Retrieve pending auth
    let pending = state
        .store
        .take_pending_auth(&query.state)
        .await
        .ok_or_else(|| {
            tracing::warn!("Invalid or expired OAuth state: {}", query.state);
            HttpError::bad_request("Invalid or expired authentication state")
        })?;

    if pending.is_expired() {
        return Err(HttpError::bad_request(
            "Authentication request has timed out",
        ));
    }

    // Extract session_id from state if present
    let session_id = query.state.split(':').nth(1).map(|s| s.to_string());

    let client = state.config.build_client().map_err(|e| {
        tracing::error!("Failed to build OAuth client: {}", e);
        HttpError::internal("OAuth configuration error")
    })?;

    // Exchange code for token using the shared HTTP client
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
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
    state
        .store
        .store_token(final_session_id.clone(), stored_token)
        .await;

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
