use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::security_events::{SecurityEvent, SecurityEventSeverity, emit_security_event};
use crate::state::NodeState;

/// Constant-time string comparison to prevent timing-oracle attacks.
/// Length mismatch returns false without leaking which side is longer.
fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

/// Axum middleware that enforces bearer-token authentication on UI-facing routes.
///
/// When `config.ui_token` is `None` the middleware is a no-op — all requests pass through.
/// When `config.ui_token` is `Some(token)` every request must include:
///   `Authorization: Bearer <token>`
/// Requests with a missing, malformed, or wrong token receive `401 Unauthorized`.
pub async fn require_ui_token(
    State(state): State<Arc<NodeState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.config.ui_token.as_deref() else {
        // No token configured — pass through (dev / single-operator mode).
        return next.run(request).await;
    };

    let provided = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if ct_eq(token, expected) => next.run(request).await,
        _ => {
            emit_security_event(
                &state,
                SecurityEvent::new(
                    &state,
                    "auth.failure",
                    SecurityEventSeverity::Warning,
                    "UI request rejected: missing or invalid bearer token",
                )
                .with_context("method", request.method())
                .with_context("uri", request.uri()),
            );
            tracing::warn!(
                method = %request.method(),
                uri = %request.uri(),
                "UI request rejected: missing or invalid bearer token"
            );
            (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer realm=\"confidis-node\"")],
                "unauthorized: valid bearer token required",
            )
                .into_response()
        }
    }
}

/// Axum middleware that injects defensive HTTP security headers into every response.
///
/// - `X-Frame-Options: DENY` — prevents click-jacking via iframes.
/// - `X-Content-Type-Options: nosniff` — stops MIME-type sniffing.
/// - `Referrer-Policy: no-referrer` — no referrer is sent with cross-origin requests.
/// - `X-XSS-Protection: 0` — disables the legacy XSS auditor (modern browsers ignore it;
///   disabling avoids it being weaponised against the page).
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("0"));
    response
}

/// Axum middleware that enforces bearer-token authentication on compliance routes.
///
/// When `config.compliance_token` is `None` the middleware rejects all requests.
/// When `config.compliance_token` is `Some(token)` every request must include:
///   `Authorization: Bearer <token>`
/// Requests with a missing, malformed, or wrong token receive `401 Unauthorized`.
///
/// Compliance routes provide SOC/SIEM access to security events and audit logs
/// without exposing owner data or operational controls.
pub async fn require_compliance_token(
    State(state): State<Arc<NodeState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.config.compliance_token.as_deref() else {
        // No compliance token configured — reject all requests.
        return (
            StatusCode::FORBIDDEN,
            "compliance access disabled: compliance_token not configured",
        )
            .into_response();
    };

    let provided = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if ct_eq(token, expected) => next.run(request).await,
        _ => {
            emit_security_event(
                &state,
                SecurityEvent::new(
                    &state,
                    "compliance.auth.failure",
                    SecurityEventSeverity::Warning,
                    "Compliance request rejected: missing or invalid bearer token",
                )
                .with_context("method", request.method())
                .with_context("uri", request.uri()),
            );
            tracing::warn!(
                method = %request.method(),
                uri = %request.uri(),
                "Compliance request rejected: missing or invalid bearer token"
            );
            (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer realm=\"confidis-compliance\"")],
                "unauthorized: valid compliance bearer token required",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn constant_time_compare_accepts_identical_tokens() {
        assert!(ct_eq(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn constant_time_compare_rejects_mismatch_at_any_position() {
        let expected = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(!ct_eq(
            "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            expected
        ));
        assert!(!ct_eq(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee",
            expected
        ));
    }

    #[test]
    fn constant_time_compare_rejects_length_mismatch() {
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("abcd", "abc"));
        assert!(!ct_eq("", "abc"));
    }

    #[test]
    fn constant_time_compare_is_byte_exact() {
        assert!(!ct_eq("Bearer token", "bearer token"));
        assert!(!ct_eq("é", "e"));
    }
}
