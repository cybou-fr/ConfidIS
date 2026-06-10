use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use confidis_protocol::{
    CelluleOwnerReportProof, CellulePublicRecord, verify_cellule_owner_report_proof,
};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::registry_service::find_cellule_record;
use crate::state::NodeState;

#[derive(Debug, Deserialize)]
pub(crate) struct OwnerReportChallengeRequest {
    cellule_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct OwnerReportChallengeResponse {
    cellule_id: confidis_protocol::CelluleId,
    owner_public_key: String,
    challenge: String,
    expires_at: DateTime<Utc>,
    scope: Vec<String>,
}

/// POST /owner/report/challenge — issue a short-lived owner report challenge.
///
/// This UI-facing endpoint proves only that the local registry knows the requested
/// Cellule owner key. It does not reveal manifest-derived placement data.
pub(crate) async fn owner_report_challenge(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<OwnerReportChallengeRequest>,
) -> Result<Json<OwnerReportChallengeResponse>, ApiError> {
    let record = find_cellule_record(&state, &request.cellule_id).await?;
    let now = Utc::now();
    let expires_at =
        now + chrono::Duration::minutes(confidis_protocol::CELLULE_READ_PROOF_TTL_MINUTES);
    let challenge = CelluleOwnerReportProof::generate_challenge();

    let mut challenges = state.owner_report_challenges.write().await;
    challenges.retain(|_, expiry| *expiry > now);
    challenges.insert(challenge.clone(), expires_at);

    Ok(Json(OwnerReportChallengeResponse {
        cellule_id: record.cellule_id,
        owner_public_key: record.cellule_public_key,
        challenge,
        expires_at,
        scope: vec!["cellule.report".to_string()],
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct OwnerReportVerifyRequest {
    proof: CelluleOwnerReportProof,
}

#[derive(Debug, Serialize)]
pub(crate) struct OwnerReportVerifyResponse {
    authorized: bool,
    cellule_id: confidis_protocol::CelluleId,
    owner_public_key: String,
    requested_scope: Vec<String>,
    record: CellulePublicRecord,
    warning: &'static str,
}

/// POST /owner/report/verify — verify an owner signature before report delivery.
///
/// The response deliberately returns only authorization metadata plus the public
/// Cellule record. Full placement/data-health reports must be reconstructed from
/// owner-side manifest context without giving the node or browser private keys.
pub(crate) async fn owner_report_verify(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<OwnerReportVerifyRequest>,
) -> Result<Json<OwnerReportVerifyResponse>, ApiError> {
    let now = Utc::now();
    {
        let mut challenges = state.owner_report_challenges.write().await;
        challenges.retain(|_, expiry| *expiry > now);
        let Some(expires_at) = challenges.remove(&request.proof.challenge) else {
            return Err(ApiError::unauthorized(
                "owner report challenge not found or expired",
            ));
        };
        if expires_at <= now {
            return Err(ApiError::unauthorized("owner report challenge expired"));
        }
    }

    let record = find_cellule_record(&state, &request.proof.cellule_id.0).await?;
    verify_cellule_owner_report_proof(&record, &request.proof, &request.proof.challenge, now)
        .map_err(|err| ApiError::forbidden(format!("owner report denied: {err}")))?;

    Ok(Json(OwnerReportVerifyResponse {
        authorized: true,
        cellule_id: request.proof.cellule_id,
        owner_public_key: request.proof.owner_public_key,
        requested_scope: request.proof.requested_scope,
        record,
        warning: "Owner signature accepted. Full placement reports require owner-side manifest context; this node response does not include Cellule keys, manifest plaintext, or shard placement.",
    }))
}
