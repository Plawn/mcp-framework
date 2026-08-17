//! Axum router exposing the metrics endpoint.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    http::header,
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;

use super::collector::MetricsCollector;

#[derive(Debug, Deserialize)]
struct MetricsQuery {
    /// `?format=json` returns the JSON snapshot; anything else returns
    /// Prometheus text.
    format: Option<String>,
}

/// Build a router serving the collector's metrics at its configured path.
///
/// Returns `None` when the endpoint is disabled in [`MetricsConfig`]
/// (`endpoint_path = None`). The route is unauthenticated by design so that a
/// Prometheus scraper can reach it; mount it outside the auth layer.
pub(crate) fn metrics_router(collector: Arc<MetricsCollector>) -> Option<Router> {
    let path = collector.endpoint_path()?.to_string();
    Some(
        Router::new()
            .route(&path, get(serve_metrics))
            .with_state(collector),
    )
}

async fn serve_metrics(
    State(collector): State<Arc<MetricsCollector>>,
    Query(query): Query<MetricsQuery>,
) -> axum::response::Response {
    if query.format.as_deref() == Some("json") {
        let snapshot = collector.snapshot();
        axum::Json(snapshot).into_response()
    } else {
        let body = collector.render_prometheus();
        ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
    }
}
