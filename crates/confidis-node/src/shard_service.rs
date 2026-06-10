//! Shard storage request handlers.
//!
//! Contains the HTTP handler functions for the shard read/write/delete surface
//! (`PUT /shard/{id}`, `GET /shard/{id}`, `DELETE /shard/{id}`, `GET /shard/{id}/status`)
//! together with their private validation helpers.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use confidis_crypto::{
    blake3_hex, sign_hex, verify_hex, verifying_key_from_hex, verifying_key_to_hex,
};
use confidis_error::ConfidISError;
use confidis_protocol::{
    CelluleId, SHARD_DELETE_OPERATION, ShardDeleteRequest, ShardId, ShardProviderRecord,
    ShardReceipt, shard_delete_request_signing_payload, shard_provider_record_signing_payload,
};
use serde::Serialize;
use serde::{Deserialize, Serialize as SerdeSerialize};
#[cfg(test)]
use uuid::Uuid;

use crate::error::ApiError;
use crate::security_events::{SecurityEvent, SecurityEventSeverity, emit_security_event};
use crate::state::{NodeState, OwnerUploadWindow};
use crate::storage_backend::run_storage_task;
use crate::validate::check_shard_body_size;

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct ShardStatusResponse {
    pub(crate) shard_id: String,
    pub(crate) present: bool,
    pub(crate) valid: bool,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PutShardResponse {
    #[serde(flatten)]
    receipt: ShardReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_record: Option<ShardProviderRecord>,
}

struct ProviderRecordContext {
    cellule_id: CelluleId,
    manifest_id: uuid::Uuid,
    shard_index: usize,
    segment_index: u32,
}
#[cfg(any())]
fn decode_fee_authorization(value: &str) -> Result<StorageFeeAuthorization, ApiError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request("invalid x-confidis-fee-authorization encoding"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::bad_request("invalid x-confidis-fee-authorization JSON"))
}

pub(crate) fn verify_put_fee_authorization(
    state: &Arc<NodeState>,
    headers: &HeaderMap,
    shard_id: &str,
    body_len: usize,
) -> Result<(), ApiError> {
    let Some(raw) = headers
        .get("x-confidis-fee-authorization")
        .and_then(|v| v.to_str().ok())
    else {
        // CONFIDIS OS v1 uses local quotas and federation agreements for write
        // admission. Legacy storage fee authorizations are still verified when
        // supplied, but they are no longer required for production writes.
        return Ok(());
    };
    let _ = (raw, state, shard_id, body_len);
    Err(ApiError::forbidden(
        "legacy storage fee authorization is not available in this CONFIDIS OS build",
    ))
}

fn fee_acceptance_path(store_path: &Path) -> PathBuf {
    store_path
        .join("fee-acceptance")
        .join("accepted-shards.json")
}

fn fee_acceptance_key(operation_id: &str, shard_id: &str) -> String {
    format!("{operation_id}:{shard_id}")
}

fn operation_id_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-confidis-operation-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

#[derive(Debug, Default, Deserialize, SerdeSerialize)]
struct FeeAcceptanceStore {
    accepted: HashSet<String>,
}

async fn load_fee_acceptance_store(path: &Path) -> Result<FeeAcceptanceStore, ApiError> {
    match tokio::fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::internal(format!("invalid fee acceptance store: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FeeAcceptanceStore::default()),
        Err(e) => Err(ApiError::internal(format!(
            "failed to read fee acceptance store: {e}"
        ))),
    }
}

async fn save_fee_acceptance_store(
    path: &Path,
    store: &FeeAcceptanceStore,
) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::internal(format!("failed to create fee acceptance dir: {e}")))?;
    }
    let bytes = serde_json::to_vec_pretty(store).map_err(|e| {
        ApiError::internal(format!("failed to serialize fee acceptance store: {e}"))
    })?;
    tokio::fs::write(path, bytes)
        .await
        .map_err(|e| ApiError::internal(format!("failed to write fee acceptance store: {e}")))
}

pub(crate) async fn ensure_fee_acceptance_not_replayed(
    state: &Arc<NodeState>,
    headers: &HeaderMap,
    shard_id: &str,
) -> Result<Option<String>, ApiError> {
    let Some(operation_id) = operation_id_header(headers) else {
        return Ok(None);
    };
    let _lock = state.fee_acceptance_lock.lock().await;
    let path = fee_acceptance_path(&state.config.store_path);
    let mut store = load_fee_acceptance_store(&path).await?;
    let key = fee_acceptance_key(&operation_id, shard_id);
    if store.accepted.contains(&key) {
        return Err(ApiError::status(
            StatusCode::CONFLICT,
            "fee_authorization_replayed",
            "fee authorization already accepted for this operation and shard",
        ));
    }
    store.accepted.insert(key);
    save_fee_acceptance_store(&path, &store).await?;
    Ok(Some(operation_id))
}

pub(crate) async fn record_fee_acceptance(
    state: &Arc<NodeState>,
    operation_id: Option<String>,
    shard_id: &str,
) -> Result<(), ApiError> {
    let _ = (state, operation_id, shard_id);
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `PUT /shard/{shard_id}` — store a content-addressed shard.
/// Enforce the authority node ban list on a shard operation by the requesting
/// node's signed Ed25519 identity.
///
/// Node participation is permissionless, so the identity proof is **optional in
/// development** (no proof ⇒ allowed). When the node runs with
/// `production_profile`, the proof is **mandatory** for inter-node shard
/// read/write so authority bans actually bind to data operations (not just peer
/// gossip). When a valid proof is present, a banned/quarantined node pubkey is
/// rejected with 403.
pub(crate) async fn enforce_node_shard_access(
    state: &Arc<NodeState>,
    headers: &HeaderMap,
    method: &str,
    shard_id: &str,
) -> Result<(), ApiError> {
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    match (
        h("x-confidis-node-pubkey"),
        h("x-confidis-node-ts"),
        h("x-confidis-node-sig"),
    ) {
        (Some(pk), Some(ts), Some(sig)) => {
            let issued: DateTime<Utc> = ts
                .parse()
                .map_err(|_| ApiError::bad_request("invalid x-confidis-node-ts"))?;
            let now = Utc::now();
            let ttl = chrono::Duration::minutes(confidis_protocol::SHARD_ACCESS_PROOF_TTL_MINUTES);
            if issued < now - ttl || issued > now + ttl {
                return Err(ApiError::unauthorized(
                    "node access proof timestamp out of window",
                ));
            }
            let key = verifying_key_from_hex(pk)
                .map_err(|_| ApiError::unauthorized("invalid x-confidis-node-pubkey"))?;
            let payload = confidis_protocol::shard_access_proof_payload(pk, method, shard_id, issued);
            verify_hex(&key, &payload, sig)
                .map_err(|_| ApiError::unauthorized("invalid node access proof signature"))?;
            if let Some(root) = &state.config.confidis_root_pubkey {
                let list = state.node_ban_list.read().await;
                if let Some(l) = list.as_ref()
                    && confidis_protocol::verify_node_ban_list(l, root, Utc::now()).is_ok()
                    && l.is_banned(pk)
                {
                    return Err(ApiError::forbidden(
                        "node is banned/quarantined by the CONFIDIS authority",
                    ));
                }
            }
            Ok(())
        }
        (None, None, None) => {
            if state.config.production_profile {
                Err(ApiError::forbidden(
                    "node shard-access identity proof required under production_profile \
                     (x-confidis-node-pubkey / -ts / -sig)",
                ))
            } else {
                Ok(())
            }
        }
        _ => Err(ApiError::unauthorized(
            "incomplete node access proof headers",
        )),
    }
}

pub(crate) async fn put_shard(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PutShardResponse>, ApiError> {
    enforce_node_shard_access(&state, &headers, "PUT", &shard_id).await?;
    let provider_context = provider_record_context(&headers)?;
    // Reject oversized bodies BEFORE blake3 hashing to avoid DoS via expensive hashing.
    check_shard_body_size(body.len())?;
    let actual = blake3_hex(&body);
    if actual != shard_id {
        return Err(ApiError::bad_request(format!(
            "shard id mismatch: expected {shard_id}, got {actual}"
        )));
    }
    verify_put_fee_authorization(&state, &headers, &shard_id, body.len())?;
    let fee_operation_id = ensure_fee_acceptance_not_replayed(&state, &headers, &shard_id).await?;
    // Reject if storing this shard would exceed the configured capacity.
    if state.config.max_bytes > 0 {
        let stats = run_storage_task(&state, |store| store.stats())
            .await
            .map_err(ApiError::from)?;
        if stats.used_bytes.saturating_add(body.len() as u64) > state.config.max_bytes {
            emit_security_event(
                &state,
                SecurityEvent::new(
                    &state,
                    "storage.capacity_exceeded",
                    SecurityEventSeverity::Warning,
                    "shard upload rejected because node storage is full",
                )
                .with_context("used_bytes", stats.used_bytes)
                .with_context("max_bytes", state.config.max_bytes)
                .with_context("incoming_bytes", body.len()),
            );
            return Err(ApiError::status(
                StatusCode::INSUFFICIENT_STORAGE,
                "storage_capacity_exceeded",
                format!(
                    "node storage full: used {} of {} bytes",
                    stats.used_bytes, state.config.max_bytes
                ),
            ));
        }
    }

    let expires_at = required_datetime_header(&headers, "x-confidis-expires-at")?;
    let node_id = state.config.node_id.clone();
    let signing_key = state.config.signing_key.clone();
    let body_len = body.len();

    // Per-owner upload quota: enforce max_shards_per_owner_per_hour when configured.
    // The owner is identified by the delete-authority hash (required header below),
    // so we read it early for the quota check.
    let delete_authority_hash = required_header(&headers, "x-confidis-delete-authority-hash")?;
    if state.config.max_shards_per_owner_per_hour > 0 {
        let limit = state.config.max_shards_per_owner_per_hour;
        let mut windows = state.owner_upload_windows.write().await;
        let now = std::time::Instant::now();
        let window = windows
            .entry(delete_authority_hash.clone())
            .or_insert(OwnerUploadWindow {
                window_start: now,
                count: 0,
            });
        // Reset window if an hour has elapsed.
        if now.duration_since(window.window_start).as_secs() >= 3600 {
            window.window_start = now;
            window.count = 0;
        }
        if window.count >= limit {
            emit_security_event(
                &state,
                SecurityEvent::new(
                    &state,
                    "quota.owner_upload_exceeded",
                    SecurityEventSeverity::Warning,
                    "owner upload quota exceeded",
                )
                .with_context("delete_authority_hash", &delete_authority_hash)
                .with_context("limit", limit),
            );
            return Err(ApiError::status(
                StatusCode::TOO_MANY_REQUESTS,
                "owner_upload_quota_exceeded",
                format!("owner upload quota exceeded: limit is {limit} shards per hour"),
            ));
        }
        window.count += 1;
    }

    let receipt = run_storage_task(&state, move |store| {
        store.put(
            node_id,
            body.as_ref(),
            Some(expires_at),
            delete_authority_hash,
            signing_key.as_ref(),
        )
    })
    .await
    .map_err(ApiError::from)?;
    record_fee_acceptance(&state, fee_operation_id, &shard_id).await?;
    let provider_record = build_provider_record(&state, &receipt, provider_context)?;

    // Record metrics for successful shard upload
    if let Some(metrics) = crate::metrics::ConfidISMetrics::global() {
        metrics.record_shard_operation("upload", true);
        metrics.record_shard_upload(body_len as u64);
    }

    Ok(Json(PutShardResponse {
        receipt,
        provider_record,
    }))
}

/// `GET /shard/{shard_id}` — retrieve a stored shard by its content-address.
pub(crate) async fn get_shard(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    enforce_node_shard_access(&state, &headers, "GET", &shard_id).await?;
    let bytes = run_storage_task(&state, move |store| store.get(&ShardId(shard_id)))
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::OK, bytes).into_response())
}

/// `GET /shards/{shard_id}/upload-receipt` — recover the last stored receipt
/// for a shard that was accepted before the client durably saved its upload
/// cache. This does not return shard bytes; it only returns signed evidence
/// that lets a retried `cellule put` resume without replaying a paid PUT.
pub(crate) async fn shard_upload_receipt(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Json<PutShardResponse>, ApiError> {
    enforce_node_shard_access(&state, &headers, "GET", &shard_id).await?;
    let provider_context = provider_record_context(&headers)?;
    let shard = ShardId(shard_id.clone());

    let status = run_storage_task(&state, {
        let shard = shard.clone();
        move |store| store.status(&shard)
    })
    .await
    .map_err(ApiError::from)?;
    if !status.present || !status.valid {
        return Err(ApiError::status(
            StatusCode::NOT_FOUND,
            "shard_not_available",
            status
                .error
                .unwrap_or_else(|| "shard is not present and valid".to_string()),
        ));
    }

    let receipt = run_storage_task(&state, {
        let shard = shard.clone();
        move |store| {
            store
                .read_all_receipts()?
                .into_iter()
                .find(|receipt| {
                    receipt.shard_id == shard
                        && receipt.receipt_type == confidis_protocol::ShardReceiptType::Stored
                })
                .ok_or_else(|| {
                    ConfidISError::not_found(format!("stored receipt not found for shard {}", shard.0))
                })
        }
    })
    .await
    .map_err(ApiError::from)?;
    let provider_record = build_provider_record(&state, &receipt, provider_context)?;

    Ok(Json(PutShardResponse {
        receipt,
        provider_record,
    }))
}

/// `DELETE /shard/{shard_id}` — delete a shard with a verified signed delete request.
pub(crate) async fn delete_shard(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<String>,
    Json(request): Json<ShardDeleteRequest>,
) -> Result<Json<ShardReceipt>, ApiError> {
    let shard = ShardId(shard_id.clone());
    if let Err(err) = verify_delete_request(&request, &shard) {
        emit_security_event(
            &state,
            SecurityEvent::new(
                &state,
                "shard.delete_rejected",
                SecurityEventSeverity::Warning,
                "shard delete request rejected",
            )
            .with_context("shard_id", &shard_id)
            .with_context("reason", &err.message),
        );
        return Err(err);
    }
    let node_id = state.config.node_id.clone();
    let signing_key = state.config.signing_key.clone();
    let signer_public_key = request.signer_public_key.clone();
    let receipt = run_storage_task(&state, move |store| {
        store.delete(node_id, &shard, &signer_public_key, signing_key.as_ref())
    })
    .await
    .map_err(|err| match err {
        ConfidISError::Forbidden(message) => {
            emit_security_event(
                &state,
                SecurityEvent::new(
                    &state,
                    "shard.delete_rejected",
                    SecurityEventSeverity::Warning,
                    "shard delete signer is not authorized",
                )
                .with_context("shard_id", &shard_id)
                .with_context("reason", &message),
            );
            ApiError::forbidden(message)
        }
        other => ApiError::from(other),
    })?;
    emit_security_event(
        &state,
        SecurityEvent::new(
            &state,
            "shard.deleted",
            SecurityEventSeverity::Info,
            "shard deleted with verified request",
        )
        .with_context("shard_id", receipt.shard_id.0.clone())
        .with_context("receipt_id", receipt.receipt_id),
    );
    Ok(Json(receipt))
}

/// `GET /shard/{shard_id}/status` — probe shard presence and integrity without returning data.
pub(crate) async fn shard_status(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<String>,
) -> Json<ShardStatusResponse> {
    let status = run_storage_task(&state, {
        let shard_id = shard_id.clone();
        move |store| store.status(&ShardId(shard_id))
    })
    .await;
    let (present, valid, error) = match status {
        Ok(s) => (s.present, s.valid, s.error),
        Err(err) => (false, false, Some(err.to_string())),
    };
    Json(ShardStatusResponse {
        shard_id,
        present,
        valid,
        error,
    })
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn required_header(headers: &HeaderMap, name: &str) -> Result<String, ApiError> {
    headers
        .get(name)
        .ok_or_else(|| ApiError::bad_request(format!("missing required header {name}")))?
        .to_str()
        .map(str::to_owned)
        .map_err(|_| ApiError::bad_request(format!("invalid header {name}")))
}

fn required_datetime_header(headers: &HeaderMap, name: &str) -> Result<DateTime<Utc>, ApiError> {
    let value = required_header(headers, name)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ApiError::bad_request(format!("invalid RFC3339 header {name}")))
}

fn optional_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, ApiError> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(str::to_owned)
                .map_err(|_| ApiError::bad_request(format!("invalid header {name}")))
        })
        .transpose()
}

fn provider_record_context(headers: &HeaderMap) -> Result<Option<ProviderRecordContext>, ApiError> {
    let cellule_id = optional_header(headers, "x-confidis-provider-cellule-id")?;
    let manifest_id = optional_header(headers, "x-confidis-provider-manifest-id")?;
    let shard_index = optional_header(headers, "x-confidis-provider-shard-index")?;
    let segment_index = optional_header(headers, "x-confidis-provider-segment-index")?;
    let any = cellule_id.is_some()
        || manifest_id.is_some()
        || shard_index.is_some()
        || segment_index.is_some();
    if !any {
        return Ok(None);
    }
    let Some(cellule_id) = cellule_id else {
        return Err(ApiError::bad_request("missing x-confidis-provider-cellule-id"));
    };
    let Some(manifest_id) = manifest_id else {
        return Err(ApiError::bad_request(
            "missing x-confidis-provider-manifest-id",
        ));
    };
    let Some(shard_index) = shard_index else {
        return Err(ApiError::bad_request(
            "missing x-confidis-provider-shard-index",
        ));
    };
    let Some(segment_index) = segment_index else {
        return Err(ApiError::bad_request(
            "missing x-confidis-provider-segment-index",
        ));
    };
    Ok(Some(ProviderRecordContext {
        cellule_id: CelluleId(cellule_id),
        manifest_id: uuid::Uuid::parse_str(&manifest_id)
            .map_err(|_| ApiError::bad_request("invalid x-confidis-provider-manifest-id UUID"))?,
        shard_index: shard_index
            .parse()
            .map_err(|_| ApiError::bad_request("invalid x-confidis-provider-shard-index"))?,
        segment_index: segment_index
            .parse()
            .map_err(|_| ApiError::bad_request("invalid x-confidis-provider-segment-index"))?,
    }))
}

fn build_provider_record(
    state: &Arc<NodeState>,
    receipt: &ShardReceipt,
    context: Option<ProviderRecordContext>,
) -> Result<Option<ShardProviderRecord>, ApiError> {
    let Some(context) = context else {
        return Ok(None);
    };
    let Some(signing_key) = state.config.signing_key.as_ref() else {
        return Ok(None);
    };
    let Some(endpoint) = state.config.public_endpoint.as_ref() else {
        return Ok(None);
    };
    let Some(receipt_signature) = receipt.signature.clone() else {
        return Ok(None);
    };

    let mut record = ShardProviderRecord {
        version: 1,
        provider_record_id: uuid::Uuid::new_v4(),
        cellule_id: context.cellule_id,
        manifest_id: context.manifest_id,
        shard_id: receipt.shard_id.clone(),
        shard_index: context.shard_index,
        segment_index: context.segment_index,
        node_id: receipt.node_id.clone(),
        public_key: verifying_key_to_hex(&signing_key.verifying_key()),
        endpoint: endpoint.clone(),
        region: state.config.region.clone(),
        failure_domain: state.config.failure_domain.clone(),
        receipt_id: receipt.receipt_id,
        receipt_signature,
        issued_at: Utc::now(),
        expires_at: receipt.expires_at,
        signature: None,
    };
    let payload = shard_provider_record_signing_payload(&record)
        .map_err(|err| ApiError::internal(format!("failed to sign provider record: {err}")))?;
    record.signature = Some(sign_hex(signing_key, &payload));
    Ok(Some(record))
}

fn verify_delete_request(request: &ShardDeleteRequest, shard_id: &ShardId) -> Result<(), ApiError> {
    if request.version != 1 {
        return Err(ApiError::bad_request("unsupported delete request version"));
    }
    if request.operation != SHARD_DELETE_OPERATION {
        return Err(ApiError::bad_request("unsupported delete operation"));
    }
    if request.shard_id != *shard_id {
        return Err(ApiError::bad_request(format!(
            "delete request shard id mismatch: expected {}, got {}",
            shard_id.0, request.shard_id.0
        )));
    }
    if request.expires_at <= request.issued_at {
        return Err(ApiError::bad_request(
            "delete request expires before issued_at",
        ));
    }

    let now = Utc::now();
    if now > request.expires_at {
        return Err(ApiError::unauthorized("delete request expired"));
    }
    if request.issued_at > now + chrono::Duration::minutes(5) {
        return Err(ApiError::bad_request(
            "delete request issued_at is too far in the future",
        ));
    }

    let key = verifying_key_from_hex(&request.signer_public_key)
        .map_err(|err| ApiError::unauthorized(format!("invalid delete signer: {err}")))?;
    let payload = shard_delete_request_signing_payload(request)
        .map_err(|err| ApiError::bad_request(format!("invalid delete request: {err}")))?;
    verify_hex(&key, &payload, &request.signature)
        .map_err(|_| ApiError::unauthorized("invalid delete request signature"))?;

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeServerConfig;
    use crate::rate_limit::RateLimiter;
    use crate::state::NodeState;
    use crate::storage_backend::{MemoryStorage, StorageBackend};
    use confidis_crypto::generate_signing_key;
    #[cfg(any())]
    use confidis_crypto::{sign_hex, verifying_key_to_hex};
    use confidis_protocol::{NodeId, PlacementPolicy, TransportPolicy};
    #[cfg(any())]
    use confidis_protocol::{
        PaidShardAuthorization, STORAGE_FEE_AUTHORIZATION_OPERATION, StorageFeeAuthorization,
        WalletAddress,
    };
    use std::sync::Arc;

    fn test_state_with(
        configure: impl FnOnce(&mut NodeServerConfig, &std::path::Path),
    ) -> (tempfile::TempDir, Arc<NodeState>, Arc<dyn StorageBackend>) {
        let temp = tempfile::tempdir().expect("temp dir");
        let store: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new());
        let mut config = NodeServerConfig {
            node_id: NodeId("test-node".to_string()),
            production_profile: false,
            transport_policy: TransportPolicy::Development,
            listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
            public_endpoint: None,
            bootstrap_peers: Vec::new(),
            discovery_backend: "federation_gossip".to_string(),
            kademlia_listen_addr: None,
            kademlia_bootstrap_peers: Vec::new(),
            kademlia_relay_peers: Vec::new(),
            store_path: temp.path().to_path_buf(),
            region: "eu-fr".to_string(),
            failure_domain: "fd-test".to_string(),
            max_bytes: 1024 * 1024,
            signing_key: None,
            placement_policy: PlacementPolicy::default(),
            node_ban_list_path: None,
            authority_private_key_path: None,
            node_ban_list_url: None,
            confidis_root_pubkey: None,
            confidis_root_source: "missing".to_string(),
            node_ban_list: None,
            x25519_static_key: None,
            registry_path: None,
            read_access_revocations_path: None,
            packages_path: None,
            ui_token: None,
            ui_allowed_origin: None,
            min_expiry_days: 1,
            max_expiry_days: 365,
            max_shards_per_owner_per_hour: 0,
            max_cellules_per_owner: 0,
            authorized_operator_pubkeys: Vec::new(),
            webui_path: None,
            content_dir: None,
            security_event_webhook_urls: Vec::new(),
            compliance_token: None,
        };
        configure(&mut config, temp.path());

        let state = Arc::new(NodeState::new(
            config,
            store.clone(),
            Arc::new(RateLimiter::new(10, 0)),
        ));

        (temp, state, store)
    }

    fn test_state() -> (tempfile::TempDir, Arc<NodeState>, Arc<dyn StorageBackend>) {
        test_state_with(|_, _| {})
    }

    #[tokio::test]
    async fn get_shard_returns_not_found_for_missing_shard() {
        let (_temp, state, _store) = test_state();

        let result = get_shard(
            State(state),
            AxumPath("missing-shard".to_string()),
            HeaderMap::new(),
        )
        .await;

        let err = result.expect_err("expected not found error");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_shard_returns_gone_for_expired_shard() {
        let (_temp, state, store) = test_state();
        let payload = b"expired-payload";
        let receipt = store
            .put(
                state.config.node_id.clone(),
                payload,
                Some(Utc::now() - chrono::Duration::seconds(1)),
                "delete-auth".to_string(),
                None,
            )
            .expect("put shard");

        let result = get_shard(State(state), AxumPath(receipt.shard_id.0), HeaderMap::new()).await;

        let err = result.expect_err("expected expired error");
        assert_eq!(err.status, StatusCode::GONE);
    }

    #[test]
    fn production_put_allows_quota_based_admission_without_storage_fee_authorization() {
        let authority = generate_signing_key();
        let (_temp, state, _store) = test_state_with(|config, _| {
            config.production_profile = true;
            config.confidis_root_pubkey = Some(authority.verifying_key());
        });
        let payload = b"paid-shard";
        let shard_id = blake3_hex(payload);
        let headers = HeaderMap::new();

        verify_put_fee_authorization(&state, &headers, &shard_id, payload.len())
            .expect("quota-based CONFIDIS OS admission does not require fee authorization");
    }

    #[test]
    #[cfg(any())]
    fn production_put_accepts_signed_storage_fee_authorization() {
        let authority = generate_signing_key();
        let authority_public_key = verifying_key_to_hex(&authority.verifying_key());
        let (_temp, state, _store) = test_state_with(|config, temp_path| {
            config.production_profile = true;
            config.confidis_root_pubkey = Some(authority.verifying_key());
            let mut ledger =
                confidis_ledger::create_genesis_ledger(authority_public_key.clone(), 1_000).unwrap();
            confidis_ledger::sign_genesis_ledger(
                &mut ledger,
                &confidis_crypto::signing_key_to_hex(&authority),
            )
            .unwrap();
            let wallet = WalletAddress("wallet".to_string());
            confidis_ledger::append_authority_transfer(
                &mut ledger,
                &confidis_crypto::signing_key_to_hex(&authority),
                authority_public_key.clone(),
                wallet.clone(),
                100,
            )
            .unwrap();
            confidis_ledger::append_authority_fee_debit(
                &mut ledger,
                &confidis_crypto::signing_key_to_hex(&authority),
                authority_public_key.clone(),
                wallet,
                b"paid-shard".len() as u64,
            )
            .unwrap();
        });
        let payload = b"paid-shard";
        let shard_id = ShardId(blake3_hex(payload));
        let ledger: confidis_ledger::Ledger = serde_json::from_slice(
        )
        .unwrap();
        let fee_entry = ledger
            .entries
            .iter()
            .find(|entry| entry.added_encoded_bytes == Some(payload.len() as u64))
            .unwrap();
        let policy_hash = confidis_ledger::global_pricing_policy_hash().unwrap();
        let mut authorization = StorageFeeAuthorization {
            version: 1,
            authorization_id: Uuid::new_v4(),
            operation: STORAGE_FEE_AUTHORIZATION_OPERATION.to_string(),
            op_id: "cellule-test".to_string(),
            wallet_address: WalletAddress("wallet".to_string()),
            fee_entry_id: fee_entry.entry_id,
            fee_entry_hash: fee_entry.entry_hash.clone(),
            fee_policy_version: confidis_ledger::GLOBAL_FEE_POLICY_VERSION,
            fee_policy_hash: policy_hash,
            total_added_encoded_bytes: payload.len() as u64,
            paid_shards: vec![PaidShardAuthorization {
                shard_id: shard_id.clone(),
                size_bytes: payload.len() as u64,
            }],
            paid_shards_hash: fee_entry.paid_shards_hash.clone(),
            content_hash: fee_entry.content_hash.clone(),
            manifest_hash: fee_entry.manifest_hash.clone(),
            issued_at: Utc::now(),
            authority_public_keys: vec![authority_public_key.clone()],
            authority_threshold: 1,
            authority_signatures: Vec::new(),
            authority_public_key,
            signature: String::new(),
        };
        let signing_payload =
            confidis_protocol::storage_fee_authorization_signing_payload(&authorization).unwrap();
        authorization.signature = sign_hex(&authority, &signing_payload);
        authorization
            .authority_signatures
            .push(confidis_protocol::AuthoritySignature {
                public_key: authorization.authority_public_key.clone(),
                signature: authorization.signature.clone(),
            });
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&authorization).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert("x-confidis-fee-authorization", header.parse().unwrap());
        headers.insert("x-confidis-operation-id", "cellule-test".parse().unwrap());

        verify_put_fee_authorization(&state, &headers, &shard_id.0, payload.len())
            .expect("valid fee authorization");

        let mut wrong_fee_entry = authorization.clone();
        wrong_fee_entry.fee_entry_hash = "wrong-entry-hash".to_string();
        wrong_fee_entry.signature = String::new();
        wrong_fee_entry.authority_signatures.clear();
        let signing_payload =
            confidis_protocol::storage_fee_authorization_signing_payload(&wrong_fee_entry).unwrap();
        wrong_fee_entry.signature = sign_hex(&authority, &signing_payload);
        wrong_fee_entry
            .authority_signatures
            .push(confidis_protocol::AuthoritySignature {
                public_key: wrong_fee_entry.authority_public_key.clone(),
                signature: wrong_fee_entry.signature.clone(),
            });
        let wrong_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&wrong_fee_entry).unwrap());
        headers.insert("x-confidis-fee-authorization", wrong_header.parse().unwrap());
        let err = verify_put_fee_authorization(&state, &headers, &shard_id.0, payload.len())
            .expect_err("fee authorization must reference a real ledger fee entry");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        let mut wrong_commitment = authorization.clone();
        wrong_commitment.content_hash = Some("a".repeat(64));
        wrong_commitment.signature = String::new();
        wrong_commitment.authority_signatures.clear();
        let signing_payload =
            confidis_protocol::storage_fee_authorization_signing_payload(&wrong_commitment).unwrap();
        wrong_commitment.signature = sign_hex(&authority, &signing_payload);
        wrong_commitment
            .authority_signatures
            .push(confidis_protocol::AuthoritySignature {
                public_key: wrong_commitment.authority_public_key.clone(),
                signature: wrong_commitment.signature.clone(),
            });
        let wrong_commitment_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&wrong_commitment).unwrap());
        headers.insert(
            "x-confidis-fee-authorization",
            wrong_commitment_header.parse().unwrap(),
        );
        let err = verify_put_fee_authorization(&state, &headers, &shard_id.0, payload.len())
            .expect_err("fee authorization commitments must match the ledger fee entry");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        headers.insert("x-confidis-fee-authorization", header.parse().unwrap());

        headers.remove("x-confidis-operation-id");
        let err = verify_put_fee_authorization(&state, &headers, &shard_id.0, payload.len())
            .expect_err("missing operation id must fail closed");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        headers.insert("x-confidis-operation-id", "wrong-cellule".parse().unwrap());
        let err = verify_put_fee_authorization(&state, &headers, &shard_id.0, payload.len())
            .expect_err("operation id mismatch must fail closed");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[test]
    #[cfg(any())]
    fn production_put_enforces_genesis_two_of_three_fee_authorization() {
        let keys = [
            generate_signing_key(),
            generate_signing_key(),
            generate_signing_key(),
        ];
        let public_keys: Vec<String> = keys
            .iter()
            .map(|key| verifying_key_to_hex(&key.verifying_key()))
            .collect();
        let (_temp, state, _store) = test_state_with(|config, temp_path| {
            config.production_profile = true;
            let authority_set = confidis_ledger::AuthoritySet {
                public_keys: public_keys.clone(),
                threshold: 2,
            };
            let mut ledger = confidis_ledger::create_genesis_ledger_with_authority_set(
                authority_set,
                public_keys[0].clone(),
                1_000,
            )
            .unwrap();
            let quorum = vec![
                confidis_crypto::signing_key_to_hex(&keys[0]),
                confidis_crypto::signing_key_to_hex(&keys[1]),
            ];
            confidis_ledger::sign_genesis_ledger_with_authority_keys(&mut ledger, &quorum).unwrap();
            let wallet = WalletAddress("wallet".to_string());
            confidis_ledger::append_authority_transfer_with_authority_keys(
                &mut ledger,
                &quorum,
                public_keys[0].clone(),
                wallet.clone(),
                100,
            )
            .unwrap();
            confidis_ledger::append_authority_fee_debit_with_authority_keys(
                &mut ledger,
                &quorum,
                public_keys[0].clone(),
                wallet,
                b"paid-shard".len() as u64,
            )
            .unwrap();
        });
        let payload = b"paid-shard";
        let shard_id = ShardId(blake3_hex(payload));
        let ledger: confidis_ledger::Ledger = serde_json::from_slice(
        )
        .unwrap();
        let fee_entry = ledger
            .entries
            .iter()
            .find(|entry| entry.added_encoded_bytes == Some(payload.len() as u64))
            .unwrap();
        let policy_hash = confidis_ledger::global_pricing_policy_hash().unwrap();
        let mut authorization = StorageFeeAuthorization {
            version: 1,
            authorization_id: Uuid::new_v4(),
            operation: STORAGE_FEE_AUTHORIZATION_OPERATION.to_string(),
            op_id: "cellule-test".to_string(),
            wallet_address: WalletAddress("wallet".to_string()),
            fee_entry_id: fee_entry.entry_id,
            fee_entry_hash: fee_entry.entry_hash.clone(),
            fee_policy_version: confidis_ledger::GLOBAL_FEE_POLICY_VERSION,
            fee_policy_hash: policy_hash,
            total_added_encoded_bytes: payload.len() as u64,
            paid_shards: vec![PaidShardAuthorization {
                shard_id: shard_id.clone(),
                size_bytes: payload.len() as u64,
            }],
            paid_shards_hash: fee_entry.paid_shards_hash.clone(),
            content_hash: fee_entry.content_hash.clone(),
            manifest_hash: fee_entry.manifest_hash.clone(),
            issued_at: Utc::now(),
            authority_public_keys: public_keys.clone(),
            authority_threshold: 2,
            authority_signatures: Vec::new(),
            authority_public_key: public_keys[0].clone(),
            signature: String::new(),
        };
        let signing_payload =
            confidis_protocol::storage_fee_authorization_signing_payload(&authorization).unwrap();
        authorization.signature = sign_hex(&keys[0], &signing_payload);
        authorization
            .authority_signatures
            .push(confidis_protocol::AuthoritySignature {
                public_key: public_keys[0].clone(),
                signature: authorization.signature.clone(),
            });

        let mut headers = HeaderMap::new();
        let one_signature_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&authorization).unwrap());
        headers.insert(
            "x-confidis-fee-authorization",
            one_signature_header.parse().unwrap(),
        );
        headers.insert("x-confidis-operation-id", "cellule-test".parse().unwrap());
        let err = verify_put_fee_authorization(&state, &headers, &shard_id.0, payload.len())
            .expect_err("one signature must not satisfy 2-of-3");
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        authorization
            .authority_signatures
            .push(confidis_protocol::AuthoritySignature {
                public_key: public_keys[1].clone(),
                signature: sign_hex(&keys[1], &signing_payload),
            });
        let two_signature_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&authorization).unwrap());
        headers.insert(
            "x-confidis-fee-authorization",
            two_signature_header.parse().unwrap(),
        );
        verify_put_fee_authorization(&state, &headers, &shard_id.0, payload.len())
            .expect("two valid genesis signatures satisfy 2-of-3");
    }

    #[tokio::test]
    async fn fee_acceptance_replay_store_persists_operation_shard_pairs() {
        let (temp, state, _store) = test_state();
        let shard_id = "replay-shard";
        let mut headers = HeaderMap::new();
        headers.insert("x-confidis-operation-id", "cellule-op-1".parse().unwrap());

        let first = ensure_fee_acceptance_not_replayed(&state, &headers, shard_id)
            .await
            .expect("first acceptance");
        assert_eq!(first.as_deref(), Some("cellule-op-1"));

        let second = ensure_fee_acceptance_not_replayed(&state, &headers, shard_id)
            .await
            .expect_err("same operation/shard must be rejected");
        assert_eq!(second.status, StatusCode::CONFLICT);

        let (_temp2, restarted_state, _store2) = test_state_with(|config, _| {
            config.store_path = temp.path().to_path_buf();
        });
        let after_restart =
            ensure_fee_acceptance_not_replayed(&restarted_state, &headers, shard_id)
                .await
                .expect_err("replay store must persist across node restart");
        assert_eq!(after_restart.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn delete_shard_returns_forbidden_for_wrong_delete_signer() {
        let (_temp, state, store) = test_state();
        let payload = b"delete-me";
        let authorized_key = generate_signing_key();
        let unauthorized_key = generate_signing_key();
        use confidis_crypto::verifying_key_to_hex;
        let delete_authority_hash =
            blake3_hex(verifying_key_to_hex(&authorized_key.verifying_key()).as_bytes());
        let receipt = store
            .put(
                state.config.node_id.clone(),
                payload,
                Some(Utc::now() + chrono::Duration::hours(1)),
                delete_authority_hash,
                None,
            )
            .expect("put shard");

        let mut request = ShardDeleteRequest {
            version: 1,
            request_id: Uuid::new_v4(),
            operation: SHARD_DELETE_OPERATION.to_string(),
            shard_id: receipt.shard_id.clone(),
            signer_public_key: verifying_key_to_hex(&unauthorized_key.verifying_key()),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            signature: String::new(),
        };
        let payload = shard_delete_request_signing_payload(&request).expect("delete payload");
        request.signature = sign_hex(&unauthorized_key, &payload);

        let result = delete_shard(
            State(state),
            AxumPath(receipt.shard_id.0.clone()),
            Json(request),
        )
        .await;

        let err = result.expect_err("expected forbidden error");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }
}
