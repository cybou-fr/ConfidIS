use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use std::time::Instant;
use tracing::{Instrument, info_span};

use crate::security_events::{SecurityEvent, SecurityEventSeverity, emit_security_event};
use crate::state::NodeState;

/// Rejects requests with HTTP 429 when the global rate limit is exceeded.
pub(crate) async fn rate_limit_check(
    State(state): State<Arc<NodeState>>,
    req: Request,
    next: Next,
) -> Response {
    if state.rate_limiter.try_acquire() {
        next.run(req).await
    } else {
        emit_security_event(
            &state,
            SecurityEvent::new(
                &state,
                "rate_limit.exceeded",
                SecurityEventSeverity::Warning,
                "global HTTP rate limit exceeded",
            )
            .with_context("path", req.uri().path()),
        );
        tracing::warn!(
            path = req.uri().path(),
            "rate limit exceeded — returning 429"
        );
        (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded\n").into_response()
    }
}

/// Middleware that adds correlation IDs to requests for tracing and records metrics
pub async fn correlation_middleware(mut request: Request, next: Next) -> Response {
    let start_time = Instant::now();
    let method = request.method().to_string();

    // Generate or extract request ID
    let request_id = extract_or_generate_request_id(request.headers());

    // Store method for metrics recording
    request.extensions_mut().insert(method.clone());

    // Create a tracing span for this request
    let span = info_span!(
        "http_request",
        method = %method,
        uri = %request.uri(),
        request_id = %request_id,
        user_agent = ?request.headers().get("user-agent"),
    );

    // Process the request
    let response = next.run(request).instrument(span).await;

    // Record metrics
    let duration = start_time.elapsed().as_secs_f64();
    let status = response.status().as_u16();

    if let Some(metrics) = crate::metrics::ConfidISMetrics::global() {
        metrics.record_http_request(&method, status, duration);
    }

    // Add request ID to response headers
    let mut response = response;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap(),
    );

    response
}

/// Extract request ID from headers or generate a new one
fn extract_or_generate_request_id(headers: &HeaderMap) -> String {
    if let Some(request_id) = headers.get("x-request-id")
        && let Ok(id_str) = request_id.to_str()
    {
        return id_str.to_string();
    }

    // Generate a new UUID for request ID
    uuid::Uuid::new_v4().to_string()
}
