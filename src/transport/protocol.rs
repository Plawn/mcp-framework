use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header::CONTENT_LENGTH};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

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
