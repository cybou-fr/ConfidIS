use thiserror::Error;

pub type Result<T> = std::result::Result<T, ConfidISError>;

#[derive(Debug, Error, Clone)]
pub enum ConfidISError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("expired: {0}")]
    Expired(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ConfidISError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation_failed",
            Self::NotFound(_) => "not_found",
            Self::Unauthorized(_) => "unauthorized",
            Self::Forbidden(_) => "forbidden",
            Self::Conflict(_) => "conflict",
            Self::Expired(_) => "expired",
            Self::Internal(_) => "internal_error",
        }
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized(message.into())
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    pub fn expired(message: impl Into<String>) -> Self {
        Self::Expired(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl From<anyhow::Error> for ConfidISError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value.to_string())
    }
}
