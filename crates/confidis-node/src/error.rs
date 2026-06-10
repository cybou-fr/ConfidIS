use axum::http::StatusCode;
use axum::http::header::{HeaderName, HeaderValue};
use axum::response::{IntoResponse, Response};
use confidis_error::ConfidISError;

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

const ERROR_CODE_HEADER: HeaderName = HeaderName::from_static("x-confidis-error-code");

impl ApiError {
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "validation_failed",
            message: message.into(),
        }
    }

    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
        }
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.into(),
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
        }
    }

    #[cfg(any())]
    pub(crate) fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "service_unavailable",
            message: message.into(),
        }
    }

    pub(crate) fn internal(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: err.to_string(),
        }
    }

    pub(crate) fn status(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self::internal(value)
    }
}

impl From<ConfidISError> for ApiError {
    fn from(value: ConfidISError) -> Self {
        let code = value.code();
        match value {
            ConfidISError::Validation(message) => Self::bad_request(message),
            ConfidISError::NotFound(message) => Self::not_found(message),
            ConfidISError::Unauthorized(message) => Self::unauthorized(message),
            ConfidISError::Forbidden(message) => Self::forbidden(message),
            ConfidISError::Conflict(message) => Self::status(StatusCode::CONFLICT, code, message),
            ConfidISError::Expired(message) => Self::status(StatusCode::GONE, code, message),
            ConfidISError::Internal(message) => {
                Self::status(StatusCode::INTERNAL_SERVER_ERROR, code, message)
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.message).into_response();
        response
            .headers_mut()
            .insert(ERROR_CODE_HEADER, HeaderValue::from_static(self.code));
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_validation_to_bad_request() {
        let err = ApiError::from(ConfidISError::validation("bad input"));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "validation_failed");
        assert!(err.message.contains("bad input"));
    }

    #[test]
    fn maps_not_found_to_not_found() {
        let err = ApiError::from(ConfidISError::not_found("missing shard"));
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert_eq!(err.code, "not_found");
        assert!(err.message.contains("missing shard"));
    }

    #[test]
    fn maps_unauthorized_to_unauthorized() {
        let err = ApiError::from(ConfidISError::unauthorized("bad signature"));
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "unauthorized");
        assert!(err.message.contains("bad signature"));
    }

    #[test]
    fn maps_forbidden_to_forbidden() {
        let err = ApiError::from(ConfidISError::forbidden("denied"));
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "forbidden");
        assert!(err.message.contains("denied"));
    }

    #[test]
    fn maps_conflict_to_conflict() {
        let err = ApiError::from(ConfidISError::conflict("already exists"));
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(err.code, "conflict");
        assert!(err.message.contains("already exists"));
    }

    #[test]
    fn maps_expired_to_gone() {
        let err = ApiError::from(ConfidISError::expired("expired shard"));
        assert_eq!(err.status, StatusCode::GONE);
        assert_eq!(err.code, "expired");
        assert!(err.message.contains("expired shard"));
    }

    #[test]
    fn maps_internal_to_internal_server_error() {
        let err = ApiError::from(ConfidISError::internal("boom"));
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code, "internal_error");
        assert!(err.message.contains("boom"));
    }

    #[test]
    fn into_response_includes_machine_readable_error_code_header() {
        let response = ApiError::from(ConfidISError::expired("expired shard")).into_response();
        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            response.headers().get(ERROR_CODE_HEADER).unwrap(),
            "expired"
        );
    }
}
