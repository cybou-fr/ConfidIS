use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use confidis_crypto::blake3_hex;
use confidis_protocol::ShardId;

use crate::error::ApiError;
use crate::noise_service::get_transport_session;
use crate::noise_session::NoiseServerSessionInner;
use crate::state::NodeState;
use crate::storage_backend::run_storage_task;
use crate::validate::check_shard_body_size;

/// `PUT /shards/{shard_id}/secure`
///
/// Upload a shard encrypted with the Noise session transport key.
/// The session UUID is passed in the `x-noise-session` header.
pub(crate) async fn put_shard_secure(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<ShardId>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    crate::shard_service::enforce_node_shard_access(&state, &headers, "PUT", &shard_id.0).await?;
    check_shard_body_size(body.len())?;
    let session = get_transport_session(&state, &headers).await?;
    let mut inner = session.inner.lock().await;
    let NoiseServerSessionInner::Transport(ref mut transport) = *inner else {
        return Err(ApiError::bad_request("noise session not in transport mode"));
    };
    let plaintext = transport
        .decrypt(&body)
        .map_err(|e| ApiError::bad_request(format!("Noise decrypt failed: {e}")))?;

    let hash = blake3_hex(&plaintext);
    if hash != shard_id.0 {
        return Err(ApiError::bad_request(format!(
            "hash mismatch: expected {}, got {}",
            shard_id.0, hash
        )));
    }
    crate::shard_service::verify_put_fee_authorization(
        &state,
        &headers,
        &shard_id.0,
        plaintext.len(),
    )?;
    let fee_operation_id =
        crate::shard_service::ensure_fee_acceptance_not_replayed(&state, &headers, &shard_id.0)
            .await?;
    let expires_at = headers
        .get("x-confidis-expires-at")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<DateTime<Utc>>().ok());
    let delete_authority_hash = headers
        .get("x-confidis-delete-authority-hash")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("noise-upload")
        .to_string();
    let node_id = state.config.node_id.clone();
    let signing_key = state.config.signing_key.clone();
    let receipt = run_storage_task(&state, move |store| {
        store.put(
            node_id,
            &plaintext,
            expires_at,
            delete_authority_hash,
            signing_key.as_ref(),
        )
    })
    .await
    .map_err(ApiError::from)?;
    crate::shard_service::record_fee_acceptance(&state, fee_operation_id, &shard_id.0).await?;
    Ok((StatusCode::CREATED, Json(receipt)))
}

/// `GET /shards/{shard_id}/secure`
///
/// Retrieve a shard, encrypting the response with the Noise session transport key.
/// The session UUID is passed in the `x-noise-session` header.
pub(crate) async fn get_shard_secure(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<ShardId>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    crate::shard_service::enforce_node_shard_access(&state, &headers, "GET", &shard_id.0).await?;
    let session = get_transport_session(&state, &headers).await?;
    let data = run_storage_task(&state, move |store| store.get(&shard_id))
        .await
        .map_err(ApiError::from)?;

    let mut inner = session.inner.lock().await;
    let NoiseServerSessionInner::Transport(ref mut transport) = *inner else {
        return Err(ApiError::bad_request("noise session not in transport mode"));
    };
    let ciphertext = transport
        .encrypt(&data)
        .map_err(|e| ApiError::internal(format!("Noise encrypt failed: {e}")))?;

    Ok((StatusCode::OK, ciphertext))
}
