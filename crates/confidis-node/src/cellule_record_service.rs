//! Minimal signed Cellule public-record registry for manifest discovery.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use chrono::Utc;
use confidis_protocol::{CellulePublicRecord, verify_cellule_public_record};

use crate::error::ApiError;
use crate::node_info_service::HealthResponse;
use crate::state::{MAX_CELLULE_RECORDS, NodeState};

pub(crate) async fn cellule_record(
    State(state): State<Arc<NodeState>>,
    AxumPath(cellule_id): AxumPath<String>,
) -> Result<Json<CellulePublicRecord>, ApiError> {
    let now = Utc::now();
    let records = state.cellule_records.read().await;
    let Some(record) = records.get(&cellule_id) else {
        return Err(ApiError::not_found("Cellule record not found"));
    };
    if now >= record.expires_at {
        return Err(ApiError::not_found("Cellule record expired"));
    }
    Ok(Json(record.clone()))
}

pub(crate) async fn announce_cellule_record(
    State(state): State<Arc<NodeState>>,
    Json(record): Json<CellulePublicRecord>,
) -> Result<Json<HealthResponse>, ApiError> {
    verify_cellule_public_record(&record)
        .map_err(|_| ApiError::unauthorized("invalid Cellule record signature"))?;

    let snapshot = {
        let mut records = state.cellule_records.write().await;
        let cellule_id = record.cellule_id.0.clone();
        if !records.contains_key(&cellule_id) && records.len() >= MAX_CELLULE_RECORDS {
            return Err(ApiError::status(
                axum::http::StatusCode::INSUFFICIENT_STORAGE,
                "cellule_record_registry_full",
                "Cellule record registry limit reached",
            ));
        }
        if let Some(existing) = records.get(&cellule_id)
            && record.sequence < existing.sequence
        {
            return Err(ApiError::status(
                axum::http::StatusCode::CONFLICT,
                "stale_cellule_record",
                "stale Cellule record sequence",
            ));
        }
        records.insert(cellule_id, record);
        records.values().cloned().collect::<Vec<_>>()
    };

    if let Err(err) = crate::cellule_record_cache::persist_cellule_record_cache(
        &state.config.store_path,
        snapshot,
    )
    .await
    {
        tracing::warn!(error = %err, "failed to persist Cellule record cache");
    }

    Ok(Json(HealthResponse {
        status: "ok",
        node_id: state.config.node_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        shard_count: 0,
        peer_count: state.routing_table.read().await.len(),
        discovery_backend: state.config.discovery_backend.clone(),
        kademlia_enabled: state.config.discovery_backend == "hybrid_kademlia",
        ban_verification_enabled: state.config.confidis_root_pubkey.is_some(),
        noise_sessions: state.noise_sessions.read().await.len(),
        node_ban_list_present: state.node_ban_list.read().await.is_some(),
        node_banned: false,
        trust_root_source: state.config.confidis_root_source.clone(),
        listen_port: state.config.listen_addr.port(),
        webui_enabled: state.config.webui_path.is_some(),
        content_dir_enabled: state.config.content_dir.is_some(),
        ui_auth_required: !state.config.production_profile && state.config.ui_token.is_some(),
        ui_cors_restricted: state.config.ui_allowed_origin.is_some(),
        operator_ui_enabled: !state.config.production_profile,
        public_ui_only: state.config.production_profile,
    }))
}

#[cfg(test)]
mod tests {
    use axum::extract::State;
    use chrono::Utc;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex};
    use confidis_protocol::{
        CellulePublicRecord, cellule_record_id_from_public_key, cellule_record_signing_payload,
    };

    use super::{announce_cellule_record, cellule_record};
    use crate::test_support::{TestNodeStateOptions, test_node_state};

    fn signed_record(sequence: u64) -> CellulePublicRecord {
        let key = generate_signing_key();
        let public_key = verifying_key_to_hex(&key.verifying_key());
        let mut record = CellulePublicRecord {
            version: 1,
            cellule_id: cellule_record_id_from_public_key(&public_key).expect("cellule id"),
            cellule_public_key: public_key,
            manifest_cid: "a".repeat(64),
            sequence,
            expires_at: Utc::now() + chrono::Duration::days(30),
            signature: String::new(),
        };
        let payload = cellule_record_signing_payload(&record).expect("payload");
        record.signature = sign_hex(&key, &payload);
        record
    }

    #[tokio::test]
    async fn announce_and_resolve_cellule_record() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state = test_node_state(&temp, TestNodeStateOptions::default());
        let record = signed_record(1);
        let cellule_id = record.cellule_id.0.clone();

        let _ = announce_cellule_record(State(state.clone()), axum::Json(record.clone()))
            .await
            .expect("announce");

        let axum::Json(resolved) = cellule_record(State(state), axum::extract::Path(cellule_id))
            .await
            .expect("resolve");
        assert_eq!(resolved.signature, record.signature);
    }

    #[tokio::test]
    async fn stale_sequence_is_rejected() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state = test_node_state(&temp, TestNodeStateOptions::default());
        let mut current = signed_record(2);
        let mut stale = current.clone();
        stale.sequence = 1;
        stale.signature.clear();
        let key = generate_signing_key();
        let public_key = verifying_key_to_hex(&key.verifying_key());
        stale.cellule_public_key = public_key.clone();
        stale.cellule_id = cellule_record_id_from_public_key(&public_key).expect("cellule id");
        current.cellule_public_key = public_key.clone();
        current.cellule_id = stale.cellule_id.clone();
        current.signature.clear();
        let payload = cellule_record_signing_payload(&current).expect("payload");
        current.signature = sign_hex(&key, &payload);
        let payload = cellule_record_signing_payload(&stale).expect("payload");
        stale.signature = sign_hex(&key, &payload);

        let _ = announce_cellule_record(State(state.clone()), axum::Json(current))
            .await
            .expect("announce current");
        let err = announce_cellule_record(State(state), axum::Json(stale))
            .await
            .expect_err("stale rejected");
        assert_eq!(err.status, axum::http::StatusCode::CONFLICT);
    }
}
