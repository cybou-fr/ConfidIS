use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::registry_service::{
    load_cellule_registry, remove_cellule_record, update_cellule_record, upsert_cellule_record,
};
use crate::security_events::{emit_security_event, SecurityEvent, SecurityEventSeverity};
use crate::state::NodeState;

#[derive(Debug, Deserialize)]
pub(crate) struct WalletCellulesCreateRequest {
    pub(crate) create: confidis_protocol::CelluleOwnerCreate,
    #[serde(default)]
    pub(crate) paid_shards: Vec<confidis_protocol::PaidShardAuthorization>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletCellulesCreateResponse {
    cellule_id: confidis_protocol::CelluleId,
    owner_public_key: String,
}

/// POST /wallet/cellules — create a new Cellule via owner-signed request.
pub(crate) async fn wallet_cellules_create(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<WalletCellulesCreateRequest>,
) -> Result<Json<WalletCellulesCreateResponse>, ApiError> {
    let now = Utc::now();
    confidis_protocol::verify_cellule_owner_create(&request.create, now)
        .map_err(|err| ApiError::forbidden(format!("owner create denied: {err}")))?;

    let record = confidis_protocol::CellulePublicRecord {
        version: 1,
        cellule_id: request.create.cellule_id.clone(),
        cellule_public_key: request.create.owner_public_key.clone(),
        manifest_cid: String::new(), // Set during data upload/put.
        sequence: 0,
        expires_at: now + chrono::Duration::days(request.create.retention_days),
        signature: String::new(), // Signed by authority during data-add/put.
    };
    upsert_cellule_record(&state, record).await?;

    Ok(Json(WalletCellulesCreateResponse {
        cellule_id: request.create.cellule_id,
        owner_public_key: request.create.owner_public_key,
    }))
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletCellulesIndexResponse {
    cellules: Vec<WalletCelluleSummary>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletCelluleSummary {
    cellule_id: confidis_protocol::CelluleId,
    label: String,
    owner_public_key: String,
    expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<DateTime<Utc>>,
    package_count: u32,
}

/// GET /wallet/index?owner=<pubkey> — list Cellules owned by the given key.
pub(crate) async fn wallet_index(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<WalletCellulesIndexResponse>, ApiError> {
    let owner_pubkey = params
        .get("owner")
        .ok_or_else(|| ApiError::bad_request("missing owner parameter"))?;

    let cellules: Vec<WalletCelluleSummary> = load_cellule_registry(&state)
        .await?
        .into_iter()
        .filter(|record: &confidis_protocol::CellulePublicRecord| {
            record.cellule_public_key == *owner_pubkey
        })
        .map(|record| WalletCelluleSummary {
            cellule_id: record.cellule_id,
            label: String::new(),
            owner_public_key: record.cellule_public_key,
            expires_at: record.expires_at,
            created_at: None,
            package_count: 0,
        })
        .collect();

    Ok(Json(WalletCellulesIndexResponse { cellules }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct WalletCellulesRenewRequest {
    renew: confidis_protocol::CelluleOwnerRenew,
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletCellulesRenewResponse {
    cellule_id: confidis_protocol::CelluleId,
    new_expiry: DateTime<Utc>,
}

/// POST /wallet/cellules/{cellule_id}/renew — renew a Cellule via owner-signed request.
pub(crate) async fn wallet_cellules_renew(
    State(state): State<Arc<NodeState>>,
    AxumPath(cellule_id): AxumPath<String>,
    Json(request): Json<WalletCellulesRenewRequest>,
) -> Result<Json<WalletCellulesRenewResponse>, ApiError> {
    let now = Utc::now();
    let cellule_id = confidis_protocol::CelluleId(cellule_id);
    let record = crate::registry_service::find_cellule_record(&state, &cellule_id.0).await?;
    if request.renew.owner_public_key != record.cellule_public_key {
        return Err(ApiError::forbidden(
            "owner renew denied: public key does not match registered owner",
        ));
    }
    if now >= record.expires_at {
        return Err(ApiError::bad_request(
            "owner renew denied: Cellule is already expired; create a new Cellule instead",
        ));
    }
    confidis_protocol::verify_cellule_owner_renew_request(&request.renew, &cellule_id, now)
        .map_err(|err| ApiError::forbidden(format!("owner renew denied: {err}")))?;

    update_cellule_record(&state, &cellule_id, |record| {
        record.expires_at = request.renew.new_expiry;
    })
    .await?;

    emit_security_event(
        &state,
        SecurityEvent::new(
            &state,
            "cellule.renewed",
            SecurityEventSeverity::Info,
            "cellule renewed successfully",
        )
        .with_context("cellule_id", cellule_id.0.clone())
        .with_context("owner_public_key", request.renew.owner_public_key.clone())
        .with_context("new_expiry", request.renew.new_expiry.to_rfc3339()),
    );

    Ok(Json(WalletCellulesRenewResponse {
        cellule_id,
        new_expiry: request.renew.new_expiry,
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct WalletCellulesDeleteRequest {
    delete: confidis_protocol::CelluleOwnerDelete,
}

/// POST /wallet/cellules/{cellule_id}/delete — delete a Cellule via owner-signed request.
pub(crate) async fn wallet_cellules_delete(
    State(state): State<Arc<NodeState>>,
    AxumPath(cellule_id): AxumPath<String>,
    Json(request): Json<WalletCellulesDeleteRequest>,
) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let cellule_id = confidis_protocol::CelluleId(cellule_id);
    let record = crate::registry_service::find_cellule_record(&state, &cellule_id.0).await?;
    if request.delete.owner_public_key != record.cellule_public_key {
        return Err(ApiError::forbidden(
            "owner delete denied: public key does not match registered owner",
        ));
    }
    confidis_protocol::verify_cellule_owner_delete(&request.delete, &cellule_id, now)
        .map_err(|err| ApiError::forbidden(format!("owner delete denied: {err}")))?;

    remove_cellule_record(&state, &cellule_id).await?;

    emit_security_event(
        &state,
        SecurityEvent::new(
            &state,
            "cellule.deleted",
            SecurityEventSeverity::Info,
            "cellule deleted successfully",
        )
        .with_context("cellule_id", cellule_id.0.clone())
        .with_context("owner_public_key", request.delete.owner_public_key.clone()),
    );

    Ok(StatusCode::NO_CONTENT)
}
