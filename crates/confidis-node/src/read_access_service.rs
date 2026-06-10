//! Company read-access request handlers.
//!
//! This module owns the CONFIDIS-mediated read surface for recipient identities:
//! challenge issuance, grant/proof verification, scoped public Cellule record
//! delivery, and owner-signed encrypted field package delivery.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use confidis_crypto::verifying_key_to_hex;
use confidis_protocol::{
    CelluleFieldAccessPackage, CellulePublicRecord, CelluleReadAccessGrant, CelluleReadAccessProof,
    NodeId, scope_covers, verify_cellule_field_access_package, verify_cellule_read_access,
    verify_cellule_read_access_grant_revocation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::registry_service::{find_cellule_record, load_read_access_revocation_log};
use crate::state::NodeState;

#[derive(Debug, Serialize)]
pub(crate) struct ReadAccessChallengeResponse {
    challenge: String,
    expires_at: DateTime<Utc>,
}

/// POST /access/read/challenge — issue a short-lived recipient proof challenge.
pub(crate) async fn read_access_challenge(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<ReadAccessChallengeResponse>, ApiError> {
    let now = Utc::now();
    let expires_at =
        now + chrono::Duration::minutes(confidis_protocol::CELLULE_READ_PROOF_TTL_MINUTES);
    let challenge = CelluleReadAccessProof::generate_challenge();

    let mut challenges = state.read_access_challenges.write().await;
    challenges.retain(|_, expiry| *expiry > now);
    challenges.insert(challenge.clone(), expires_at);

    Ok(Json(ReadAccessChallengeResponse {
        challenge,
        expires_at,
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReadAccessVerifyRequest {
    grant: CelluleReadAccessGrant,
    proof: CelluleReadAccessProof,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadAccessVerifyResponse {
    authorized: bool,
    grant_id: Uuid,
    cellule_id: confidis_protocol::CelluleId,
    recipient_public_key: String,
    requested_scope: Vec<String>,
    warning: &'static str,
}

/// POST /access/read/verify — verify owner grant + recipient proof before read access.
///
/// This endpoint authorizes only the presented scope. It does not return plaintext,
/// Cellule keys, manifests, or full placement reports.
pub(crate) async fn read_access_verify(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<ReadAccessVerifyRequest>,
) -> Result<Json<ReadAccessVerifyResponse>, ApiError> {
    verify_read_access_request(&state, &request).await?;

    Ok(Json(ReadAccessVerifyResponse {
        authorized: true,
        grant_id: request.grant.grant_id,
        cellule_id: request.grant.cellule_id,
        recipient_public_key: request.proof.recipient_public_key,
        requested_scope: request.proof.requested_scope,
        warning: "Authorization is limited to the signed scope. CONFIDIS-mediated access should keep audit trail; exported plaintext cannot be technically clawed back.",
    }))
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadAccessCelluleRecordResponse {
    authorized: bool,
    cellule_id: confidis_protocol::CelluleId,
    fields: serde_json::Map<String, serde_json::Value>,
    audit: ReadAccessAuditReceipt,
    warning: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReadAccessAuditReceipt {
    version: u16,
    receipt_id: Uuid,
    node_id: NodeId,
    public_key: Option<String>,
    grant_id: Uuid,
    cellule_id: confidis_protocol::CelluleId,
    recipient_public_key: String,
    requested_scope: Vec<String>,
    delivered_fields: Vec<String>,
    issued_at: DateTime<Utc>,
    signature: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReadAccessFieldPackageRequest {
    grant: CelluleReadAccessGrant,
    proof: CelluleReadAccessProof,
    package: CelluleFieldAccessPackage,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadAccessFieldPackageResponse {
    authorized: bool,
    grant_id: Uuid,
    cellule_id: confidis_protocol::CelluleId,
    package: CelluleFieldAccessPackage,
    audit: ReadAccessAuditReceipt,
    warning: &'static str,
}

/// POST /access/read/cellule-record — deliver scoped public Cellule record fields.
///
/// This is the first CONFIDIS-mediated read delivery surface for company identities.
/// It is intentionally limited to public registry fields; plaintext user data,
/// Cellule keys, manifest plaintext, and full placement reports remain out of scope.
pub(crate) async fn read_access_cellule_record(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<ReadAccessVerifyRequest>,
) -> Result<Json<ReadAccessCelluleRecordResponse>, ApiError> {
    verify_read_access_request(&state, &request).await?;
    let record = find_cellule_record(&state, &request.grant.cellule_id.0).await?;
    let (fields, delivered_fields) =
        scoped_cellule_record_fields(&record, &request.proof.requested_scope)?;
    let audit = read_access_audit_receipt(&state, &request, delivered_fields.clone())?;

    Ok(Json(ReadAccessCelluleRecordResponse {
        authorized: true,
        cellule_id: request.grant.cellule_id,
        fields,
        audit,
        warning: "Scoped read delivery is limited to returned fields. Keep CONFIDIS API/client access for audit trail; exported plaintext cannot be technically clawed back.",
    }))
}

/// POST /access/read/field-package — deliver owner-signed encrypted field package.
///
/// The node verifies the owner grant, recipient proof, package signature, and requested
/// scope, then returns only the already-encrypted package plus a node audit receipt.
pub(crate) async fn read_access_field_package(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<ReadAccessFieldPackageRequest>,
) -> Result<Json<ReadAccessFieldPackageResponse>, ApiError> {
    let access_request = ReadAccessVerifyRequest {
        grant: request.grant.clone(),
        proof: request.proof.clone(),
    };
    verify_read_access_request(&state, &access_request).await?;
    verify_cellule_field_access_package(&request.package, &request.grant)
        .map_err(|err| ApiError::forbidden(format!("field access package denied: {err}")))?;

    let delivered_fields: Vec<String> = request
        .package
        .fields
        .iter()
        .map(|envelope| envelope.field.clone())
        .collect();
    if !scope_covers(&request.proof.requested_scope, &delivered_fields) {
        return Err(ApiError::forbidden(
            "field access package fields are outside the proof requested_scope",
        ));
    }
    let audit = read_access_audit_receipt(&state, &access_request, delivered_fields)?;

    Ok(Json(ReadAccessFieldPackageResponse {
        authorized: true,
        grant_id: request.grant.grant_id,
        cellule_id: request.grant.cellule_id,
        package: request.package,
        audit,
        warning: "Field package delivery returns owner-signed encrypted data only. Keep CONFIDIS API/client access for audit trail; plaintext opened by the recipient cannot be technically clawed back.",
    }))
}

async fn verify_read_access_request(
    state: &Arc<NodeState>,
    request: &ReadAccessVerifyRequest,
) -> Result<(), ApiError> {
    let now = Utc::now();
    {
        let mut challenges = state.read_access_challenges.write().await;
        challenges.retain(|_, expiry| *expiry > now);
        let Some(expires_at) = challenges.remove(&request.proof.challenge) else {
            return Err(ApiError::unauthorized(
                "read access challenge not found or expired",
            ));
        };
        if expires_at <= now {
            return Err(ApiError::unauthorized("read access challenge expired"));
        }
    }

    verify_cellule_read_access(
        &request.grant,
        &request.proof,
        &request.proof.challenge,
        now,
    )
    .map_err(|err| ApiError::forbidden(format!("read access denied: {err}")))?;
    verify_grant_not_revoked(state, &request.grant, now).await?;
    Ok(())
}

async fn verify_grant_not_revoked(
    state: &Arc<NodeState>,
    grant: &CelluleReadAccessGrant,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let revocation_log = load_read_access_revocation_log(state).await?;
    if let Some(revocation) = revocation_log
        .revocations
        .iter()
        .find(|revocation| revocation.grant_id == grant.grant_id)
    {
        verify_cellule_read_access_grant_revocation(revocation, grant, now)
            .map_err(|err| ApiError::forbidden(format!("read access grant revoked: {err}")))?;
        return Err(ApiError::forbidden("read access grant revoked"));
    }
    Ok(())
}

fn scoped_cellule_record_fields(
    record: &CellulePublicRecord,
    requested_scope: &[String],
) -> Result<(serde_json::Map<String, serde_json::Value>, Vec<String>), ApiError> {
    let full_record = requested_scope
        .iter()
        .any(|scope| scope == "*" || scope == "cellule.public_record");
    let mut fields = serde_json::Map::new();
    let mut delivered = Vec::new();
    let mut add_field = |name: &str, value: serde_json::Value| {
        if full_record || requested_scope.iter().any(|scope| scope == name) {
            fields.insert(name.to_string(), value);
            delivered.push(name.to_string());
        }
    };

    add_field("cellule.cellule_id", serde_json::json!(record.cellule_id.0));
    add_field(
        "cellule.public_key",
        serde_json::json!(record.cellule_public_key),
    );
    add_field(
        "cellule.manifest_cid",
        serde_json::json!(record.manifest_cid),
    );
    add_field("cellule.sequence", serde_json::json!(record.sequence));
    add_field("cellule.expires_at", serde_json::json!(record.expires_at));
    add_field("cellule.signature", serde_json::json!(record.signature));

    if fields.is_empty() {
        return Err(ApiError::bad_request(
            "requested scope has no deliverable Cellule public-record fields",
        ));
    }
    Ok((fields, delivered))
}

fn read_access_audit_receipt(
    state: &Arc<NodeState>,
    request: &ReadAccessVerifyRequest,
    delivered_fields: Vec<String>,
) -> Result<ReadAccessAuditReceipt, ApiError> {
    let mut receipt = ReadAccessAuditReceipt {
        version: 1,
        receipt_id: Uuid::new_v4(),
        node_id: state.config.node_id.clone(),
        public_key: state
            .config
            .signing_key
            .as_ref()
            .map(|key| verifying_key_to_hex(&key.verifying_key())),
        grant_id: request.grant.grant_id,
        cellule_id: request.grant.cellule_id.clone(),
        recipient_public_key: request.proof.recipient_public_key.clone(),
        requested_scope: request.proof.requested_scope.clone(),
        delivered_fields,
        issued_at: Utc::now(),
        signature: None,
    };
    if let Some(signing_key) = state.config.signing_key.as_ref() {
        let mut unsigned = receipt.clone();
        unsigned.signature = None;
        let payload = serde_json::to_vec(&unsigned)
            .map_err(|e| ApiError::internal(format!("failed to serialize audit receipt: {e}")))?;
        receipt.signature = Some(confidis_crypto::sign_hex(signing_key, &payload));
    }
    Ok(receipt)
}
