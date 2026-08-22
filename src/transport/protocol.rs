use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header::CONTENT_LENGTH};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rmcp::model::ProtocolVersion;

use crate::auth::ConfigError;

const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";
const LEGACY_FALLBACK_VERSION: &str = "2025-11-25";
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Selects how Streamable HTTP handles lifecycle/version mismatches.
///
/// This policy only affects clients that announce a sessionless protocol
/// version through the legacy `initialize` lifecycle. Correct modern clients
/// using `server/discover` are always served statelessly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProtocolLifecyclePolicy {
    /// Preserve legacy clients and repair clients that combine
    /// `initialize(2026-07-28+)` with `notifications/initialized`.
    ///
    /// Their initialize request is negotiated as `2025-11-25`, so rmcp creates
    /// a session and the rest of their legacy lifecycle remains coherent.
    #[default]
    Hybrid,
    /// Apply rmcp's protocol routing without compatibility normalization.
    ///
    /// Use this when every client is known to choose the lifecycle matching
    /// its advertised protocol version.
    Strict,
}

/// Environment override for the highest MCP revision the server advertises.
///
/// Takes precedence over
/// [`McpAppBuilder::max_protocol_version`](crate::McpAppBuilder::max_protocol_version)
/// so a deployment can cap (or uncap) without a rebuild — production pins the
/// revision it is known to serve while staging keeps running as the canary.
pub const MAX_PROTOCOL_VERSION_ENV: &str = "MCP_MAX_PROTOCOL_VERSION";

/// Values that explicitly mean "no ceiling", so an environment can *lift* a
/// ceiling compiled into the binary instead of only lowering it.
const UNCAPPED_ALIASES: &[&str] = &["none", "off", "latest", "unset"];

/// Resolve the advertised-revision ceiling from `builder_default` and
/// [`MAX_PROTOCOL_VERSION_ENV`].
///
/// The environment wins when set: `MCP_MAX_PROTOCOL_VERSION=2025-11-25` caps,
/// `=none` (or `off` / `latest` / `unset`) removes a ceiling the builder set,
/// and an unset or empty variable leaves `builder_default` alone.
///
/// # Errors
///
/// Returns [`ConfigError`] for a value that is not one of
/// [`ProtocolVersion::KNOWN_VERSIONS`]. A typo must fail the boot: silently
/// ignoring it would advertise the full set and reintroduce exactly the
/// negotiation the ceiling exists to prevent.
pub fn resolve_max_protocol_version(
    builder_default: Option<ProtocolVersion>,
) -> Result<Option<ProtocolVersion>, ConfigError> {
    let Ok(raw) = std::env::var(MAX_PROTOCOL_VERSION_ENV) else {
        return validate_max_protocol_version(builder_default);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return validate_max_protocol_version(builder_default);
    }
    if UNCAPPED_ALIASES
        .iter()
        .any(|alias| trimmed.eq_ignore_ascii_case(alias))
    {
        return Ok(None);
    }
    // `ProtocolVersion` has no public constructor from an arbitrary string, so
    // the lookup against the known set *is* the parse — an unrecognised value
    // has nowhere to go but the error.
    ProtocolVersion::KNOWN_VERSIONS
        .iter()
        .find(|known| known.as_str() == trimmed)
        .cloned()
        .map(Some)
        .ok_or_else(|| unknown_revision(trimmed))
}

fn unknown_revision(value: &str) -> ConfigError {
    ConfigError::new(format!(
        "{MAX_PROTOCOL_VERSION_ENV}: unknown MCP revision {value:?} (known: {})",
        ProtocolVersion::KNOWN_VERSIONS
            .iter()
            .map(ProtocolVersion::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Reject a ceiling that is not a revision rmcp knows about.
///
/// Also enforced by [`build_app`](crate::transport::build_app), so a consumer
/// assembling an [`HttpAppConfig`](crate::transport::HttpAppConfig) by hand
/// cannot route around the check.
pub(crate) fn validate_max_protocol_version(
    max: Option<ProtocolVersion>,
) -> Result<Option<ProtocolVersion>, ConfigError> {
    let Some(version) = max else {
        return Ok(None);
    };
    if ProtocolVersion::KNOWN_VERSIONS.contains(&version) {
        return Ok(Some(version));
    }
    Err(unknown_revision(version.as_str()))
}

/// Drop every revision above `max` from what the server advertises.
///
/// Revision identifiers are ISO dates, so lexicographic order *is* chronological
/// order — no parsing needed. An empty intersection is refused: a server that
/// advertises nothing can never be reached, so the ceiling is ignored and the
/// handler's own set is served with an `ERROR` naming the mismatch.
pub(crate) fn cap_protocol_versions(
    advertised: std::borrow::Cow<'static, [ProtocolVersion]>,
    max: Option<&ProtocolVersion>,
) -> std::borrow::Cow<'static, [ProtocolVersion]> {
    let Some(max) = max else {
        return advertised;
    };
    let capped: Vec<ProtocolVersion> = advertised
        .iter()
        .filter(|version| version.as_str() <= max.as_str())
        .cloned()
        .collect();
    if capped.is_empty() {
        tracing::error!(
            max_protocol_version = max.as_str(),
            handler_versions = ?advertised.iter().map(ProtocolVersion::as_str).collect::<Vec<_>>(),
            "{MAX_PROTOCOL_VERSION_ENV} excludes every revision the handler supports; ignoring it"
        );
        return advertised;
    }
    std::borrow::Cow::Owned(capped)
}

fn is_modern_date_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    version >= MODERN_PROTOCOL_VERSION
}

fn normalize_initialize(value: &mut serde_json::Value) -> Option<String> {
    let object = value.as_object_mut()?;
    if object.get("method")?.as_str()? != "initialize" {
        return None;
    }
    let version = object
        .get_mut("params")?
        .as_object_mut()?
        .get_mut("protocolVersion")?;
    let requested = version.as_str()?.to_owned();
    if !is_modern_date_version(&requested) {
        return None;
    }
    *version = serde_json::Value::String(LEGACY_FALLBACK_VERSION.to_owned());
    Some(requested)
}

pub(crate) async fn normalize_protocol_lifecycle(
    State(policy): State<ProtocolLifecyclePolicy>,
    request: Request,
    next: Next,
) -> Response {
    if policy != ProtocolLifecyclePolicy::Hybrid || request.method() != Method::POST {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();
    let bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    let mut value = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return next
                .run(Request::from_parts(parts, Body::from(bytes)))
                .await;
        }
    };

    let Some(requested_version) = normalize_initialize(&mut value) else {
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    };

    // Preserve rmcp's header/body mismatch validation. A matching modern
    // header is rewritten with the body; an already mismatching header is not.
    if parts
        .headers
        .get(MCP_PROTOCOL_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some(requested_version.as_str())
    {
        parts.headers.insert(
            MCP_PROTOCOL_VERSION_HEADER,
            HeaderValue::from_static(LEGACY_FALLBACK_VERSION),
        );
    }
    parts.headers.remove(CONTENT_LENGTH);

    let normalized = match serde_json::to_vec(&value) {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    tracing::warn!(
        requested_protocol_version = %requested_version,
        negotiated_protocol_version = LEGACY_FALLBACK_VERSION,
        policy = ?policy,
        "normalized modern protocol version used with legacy initialize lifecycle"
    );

    next.run(Request::from_parts(parts, Body::from(normalized)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_keeps_everything_at_or_below_it() {
        let all = std::borrow::Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS);
        let capped = cap_protocol_versions(all.clone(), Some(&ProtocolVersion::V_2025_11_25));
        assert_eq!(
            capped
                .iter()
                .map(ProtocolVersion::as_str)
                .collect::<Vec<_>>(),
            ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
        );
        assert_eq!(cap_protocol_versions(all.clone(), None).len(), all.len());
    }

    #[test]
    fn a_ceiling_that_would_advertise_nothing_is_ignored() {
        // Better a server that speaks a revision nobody asked it to cap than a
        // server nothing can connect to.
        let only_modern =
            std::borrow::Cow::Owned(vec![ProtocolVersion::V_2026_07_28]);
        let capped =
            cap_protocol_versions(only_modern, Some(&ProtocolVersion::V_2024_11_05));
        assert_eq!(capped.as_ref(), [ProtocolVersion::V_2026_07_28]);
    }

    #[test]
    fn only_a_known_revision_is_accepted_as_a_ceiling() {
        assert_eq!(
            validate_max_protocol_version(Some(ProtocolVersion::V_2025_06_18)).unwrap(),
            Some(ProtocolVersion::V_2025_06_18)
        );
        assert_eq!(validate_max_protocol_version(None).unwrap(), None);

        let error = unknown_revision("2019-01-01");
        assert!(error.message().contains("2019-01-01"));
        assert!(error.message().contains("2026-07-28"));
    }

    #[test]
    fn only_modern_initialize_is_normalized() {
        let mut modern = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2026-07-28" }
        });
        assert_eq!(
            normalize_initialize(&mut modern).as_deref(),
            Some("2026-07-28")
        );
        assert_eq!(modern["params"]["protocolVersion"], "2025-11-25");

        let mut legacy = serde_json::json!({
            "method": "initialize",
            "params": { "protocolVersion": "2025-11-25" }
        });
        assert_eq!(normalize_initialize(&mut legacy), None);
        assert_eq!(legacy["params"]["protocolVersion"], "2025-11-25");

        let mut discover = serde_json::json!({
            "method": "server/discover",
            "params": { "protocolVersion": "2026-07-28" }
        });
        assert_eq!(normalize_initialize(&mut discover), None);
    }
}
