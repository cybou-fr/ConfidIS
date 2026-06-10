/// Input validation guards for node HTTP handlers.
///
/// All functions return `Err(ApiError::bad_request(...))` on failure so callers
/// can use `?` directly in handlers.
use axum::http::StatusCode;

use crate::error::ApiError;

// ── String field size limits ──────────────────────────────────────────────────

/// Maximum byte length for a free-form string field (endpoint, node_id, region, …).
pub(crate) const MAX_STRING_LEN: usize = 512;

/// Maximum number of entries in the Noise session map before new sessions are
/// refused. This bounds per-process memory used by in-flight handshakes.
pub(crate) const MAX_NOISE_SESSIONS: usize = 10_000;

/// Maximum ledger file size that will be read into memory (50 MiB).
#[cfg(any())]
pub(crate) const MAX_LEDGER_FILE_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum shard body size accepted by `PUT /shards/*` (64 MiB).
/// Must be consistent with the axum `DefaultBodyLimit` applied in `server.rs`.
pub(crate) const MAX_SHARD_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Maximum length of a hex-encoded Ed25519 public key (32 bytes × 2 hex chars).
pub(crate) const ED25519_PUBKEY_HEX_LEN: usize = 64;

/// Maximum length of a hex-encoded Ed25519 private key seed (32 bytes × 2 hex chars).
#[cfg(any())]
pub(crate) const ED25519_PRIVKEY_HEX_LEN: usize = 64;

/// Maximum length of a hex-encoded Ed25519 signature (64 bytes × 2 hex chars).
pub(crate) const ED25519_SIG_HEX_LEN: usize = 128;

/// Maximum length of a hex-encoded CONFIDIS wallet address (BLAKE3 digest).
#[cfg(any())]
pub(crate) const WALLET_ADDRESS_HEX_LEN: usize = 64;

/// Maximum length of a Noise handshake message in hex.
/// Noise_XX msg1/msg3 are ≤96 bytes → ≤192 hex chars; we allow 2× that (384)
/// to accommodate any future protocol extensions.
pub(crate) const MAX_NOISE_MSG_HEX_LEN: usize = 384;

/// Maximum length for `?address=` query parameter (Ed25519 pubkey hex = 64 chars).
#[cfg(any())]
pub(crate) const MAX_ADDRESS_QUERY_LEN: usize = 64;

// ── Guard functions ───────────────────────────────────────────────────────────

/// Reject strings that exceed `MAX_STRING_LEN`.
pub(crate) fn check_str_len(value: &str, field: &str) -> Result<(), ApiError> {
    if value.len() > MAX_STRING_LEN {
        return Err(ApiError::bad_request(format!(
            "field `{field}` exceeds maximum length of {MAX_STRING_LEN} bytes"
        )));
    }
    Ok(())
}

/// Reject a hex string that is not exactly `expected_len` ASCII hex characters.
/// This guards against oversized inputs before any `hex::decode` call, and
/// catches strings that are clearly too short or the wrong format.
pub(crate) fn check_hex_len(value: &str, field: &str, expected_len: usize) -> Result<(), ApiError> {
    if value.len() != expected_len {
        return Err(ApiError::bad_request(format!(
            "field `{field}` must be exactly {expected_len} hex characters, got {}",
            value.len()
        )));
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(format!(
            "field `{field}` contains non-hex characters"
        )));
    }
    Ok(())
}

/// Reject a Noise message hex string that exceeds `MAX_NOISE_MSG_HEX_LEN`.
pub(crate) fn check_noise_msg_hex(value: &str, field: &str) -> Result<(), ApiError> {
    if value.len() > MAX_NOISE_MSG_HEX_LEN {
        return Err(ApiError::bad_request(format!(
            "field `{field}` exceeds maximum Noise message length of {MAX_NOISE_MSG_HEX_LEN} hex chars"
        )));
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(format!(
            "field `{field}` contains non-hex characters"
        )));
    }
    Ok(())
}

/// Reject a raw shard body that exceeds `MAX_SHARD_BODY_BYTES`.
/// Called **before** any hashing or capacity check so expensive operations are
/// avoided on clearly oversized inputs.
pub(crate) fn check_shard_body_size(len: usize) -> Result<(), ApiError> {
    if len > MAX_SHARD_BODY_BYTES {
        return Err(ApiError::status(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("shard body is {len} bytes; maximum is {MAX_SHARD_BODY_BYTES} bytes (64 MiB)"),
        ));
    }
    Ok(())
}

/// Reject a ledger file that exceeds `MAX_LEDGER_FILE_BYTES` before reading.
#[cfg(any())]
pub(crate) fn check_ledger_file_size(path: &std::path::Path) -> Result<(), ApiError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| ApiError::bad_request(format!("cannot stat ledger file: {e}")))?;
    if meta.len() > MAX_LEDGER_FILE_BYTES {
        return Err(ApiError::bad_request(format!(
            "ledger file is {} bytes; maximum allowed is {MAX_LEDGER_FILE_BYTES} bytes (50 MiB)",
            meta.len()
        )));
    }
    Ok(())
}

/// Validate `?address=` query parameter: must be exactly 64 hex chars.
#[cfg(any())]
pub(crate) fn check_address_param(address: &str) -> Result<(), ApiError> {
    if address.len() > MAX_ADDRESS_QUERY_LEN {
        return Err(ApiError::bad_request(format!(
            "?address= parameter exceeds maximum length of {MAX_ADDRESS_QUERY_LEN} characters"
        )));
    }
    Ok(())
}
