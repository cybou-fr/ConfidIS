use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::NodeState;

#[derive(Debug, Deserialize)]
pub(crate) struct OperatorSharedQuery {
    pub recipient: String,
    pub q: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OperatorSharedCellulesResponse {
    pub recipient_public_key: String,
    pub query: Option<String>,
    pub count: usize,
    pub items: Vec<OperatorSharedCellule>,
    pub warning: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct OperatorSharedCelluleResponse {
    pub item: OperatorSharedCellule,
    pub warning: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct OperatorSharedCellule {
    pub package_id: Uuid,
    pub cellule_id: confidis_protocol::CelluleId,
    pub owner_public_key: String,
    pub recipient_public_key: String,
    pub recipient_x25519_pubkey: String,
    pub fields: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: confidis_protocol::RecipientPackageStatus,
    pub package_hash: String,
    pub data: Value,
}

/// GET /operator/shared-cellules?recipient=<operator-pubkey>&q=<text>
///
/// Lists active recipient packages addressed to the operator identity. The route
/// is mounted with the UI-token middleware; it deliberately stays out of the
/// public protocol surface.
pub(crate) async fn operator_shared_cellules(
    State(state): State<Arc<NodeState>>,
    Query(query): Query<OperatorSharedQuery>,
) -> Result<Json<OperatorSharedCellulesResponse>, ApiError> {
    validate_recipient(&query.recipient)?;
    require_authorized_operator(&state, &query.recipient)?;

    let search = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    let mut items = Vec::new();
    for raw in load_raw_package_values(&state).await? {
        let Some(item) = operator_item_from_raw(raw, &query.recipient)? else {
            continue;
        };
        if let Some(search) = search
            && !item_matches(&item, search)
        {
            continue;
        }
        items.push(item);
    }

    items.sort_by_key(|item| std::cmp::Reverse(item.issued_at));
    Ok(Json(OperatorSharedCellulesResponse {
        recipient_public_key: query.recipient,
        query: search.map(ToOwned::to_owned),
        count: items.len(),
        items,
        warning: OPERATOR_SHARED_WARNING,
    }))
}

/// GET /operator/shared-cellules/{package_id}?recipient=<operator-pubkey>
pub(crate) async fn operator_shared_cellule(
    State(state): State<Arc<NodeState>>,
    AxumPath(package_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<OperatorSharedCelluleResponse>, ApiError> {
    let package_id =
        Uuid::parse_str(&package_id).map_err(|_| ApiError::bad_request("invalid package_id"))?;
    let recipient = params
        .get("recipient")
        .ok_or_else(|| ApiError::bad_request("missing recipient parameter"))?;
    validate_recipient(recipient)?;
    require_authorized_operator(&state, recipient)?;

    for raw in load_raw_package_values(&state).await? {
        let Some(item) = operator_item_from_raw(raw, recipient)? else {
            continue;
        };
        if item.package_id == package_id {
            return Ok(Json(OperatorSharedCelluleResponse {
                item,
                warning: OPERATOR_SHARED_WARNING,
            }));
        }
    }

    Err(ApiError::not_found("shared Cellule package not found"))
}

const OPERATOR_SHARED_WARNING: &str = "Operator inventory APIs expose package metadata only. Retrieve encrypted field packages through the signed recipient-proof read-access flow.";

fn validate_recipient(recipient: &str) -> Result<(), ApiError> {
    if recipient.len() != 64 || !recipient.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "recipient must be a 32-byte public key encoded as hex",
        ));
    }
    Ok(())
}

fn require_authorized_operator(state: &Arc<NodeState>, recipient: &str) -> Result<(), ApiError> {
    if state.config.authorized_operator_pubkeys.is_empty()
        || state
            .config
            .authorized_operator_pubkeys
            .iter()
            .any(|key| key == recipient)
    {
        return Ok(());
    }
    Err(ApiError::forbidden(
        "recipient is not in authorized_operator_pubkeys",
    ))
}

async fn load_raw_package_values(state: &Arc<NodeState>) -> Result<Vec<Value>, ApiError> {
    let Some(path) = state.config.packages_path.as_deref() else {
        return Ok(Vec::new());
    };
    if !tokio::fs::try_exists(path)
        .await
        .map_err(|e| ApiError::internal(format!("failed to check packages registry path: {e}")))?
    {
        return Ok(Vec::new());
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| ApiError::internal(format!("failed to read packages registry: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::internal(format!("invalid packages registry JSON: {e}")))
}

fn operator_item_from_raw(
    raw: Value,
    recipient: &str,
) -> Result<Option<OperatorSharedCellule>, ApiError> {
    let record: confidis_protocol::RecipientPackageRecord = serde_json::from_value(raw.clone())
        .map_err(|e| {
            ApiError::internal(format!("invalid recipient package registry entry: {e}"))
        })?;

    if record.recipient_public_key != recipient {
        return Ok(None);
    }
    if record.status != confidis_protocol::RecipientPackageStatus::Active {
        return Ok(None);
    }
    if record
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return Ok(None);
    }

    Ok(Some(OperatorSharedCellule {
        package_id: record.package_id,
        cellule_id: record.cellule_id,
        owner_public_key: record.owner_public_key,
        recipient_public_key: record.recipient_public_key,
        recipient_x25519_pubkey: record.recipient_x25519_pubkey,
        fields: record.fields,
        issued_at: record.issued_at,
        expires_at: record.expires_at,
        status: record.status,
        package_hash: record.package_hash,
        data: Value::Null,
    }))
}

fn item_matches(item: &OperatorSharedCellule, query: &str) -> bool {
    let needle = query.to_ascii_lowercase();
    let haystack = serde_json::to_string(item)
        .unwrap_or_default()
        .to_ascii_lowercase();
    haystack.contains(&needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use confidis_protocol::{CelluleId, RecipientPackageRecord, RecipientPackageStatus};

    use crate::test_support::{TestNodeStateOptions, test_node_state};

    fn package(package_id: Uuid, recipient_public_key: &str, data: Option<Value>) -> Value {
        let mut value = serde_json::to_value(RecipientPackageRecord {
            package_id,
            cellule_id: CelluleId("cellule-shared-test".to_string()),
            owner_public_key: "a".repeat(64),
            recipient_public_key: recipient_public_key.to_string(),
            recipient_x25519_pubkey: "b".repeat(64),
            fields: vec!["patient.name".to_string(), "kyc.status".to_string()],
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(7)),
            status: RecipientPackageStatus::Active,
            package_hash: "c".repeat(64),
            owner_signature: "d".repeat(128),
            delivery_receipts: Vec::new(),
        })
        .unwrap();
        if let Some(data) = data {
            value["predecrypted_data"] = data;
        }
        value
    }

    #[tokio::test]
    async fn lists_active_package_metadata_without_plaintext_for_recipient() {
        let temp = tempfile::tempdir().unwrap();
        let packages_path = temp.path().join("packages.json");
        let recipient = "1".repeat(64);
        let other = "2".repeat(64);
        let wanted_id = Uuid::new_v4();
        let values = vec![
            package(
                wanted_id,
                &recipient,
                Some(serde_json::json!({ "patient": { "name": "Alice Martin" } })),
            ),
            package(
                Uuid::new_v4(),
                &other,
                Some(serde_json::json!({ "name": "Bob" })),
            ),
        ];
        tokio::fs::write(&packages_path, serde_json::to_vec(&values).unwrap())
            .await
            .unwrap();
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                packages_path: Some(packages_path),
                ..Default::default()
            },
        );

        let Json(response) = operator_shared_cellules(
            State(state),
            Query(OperatorSharedQuery {
                recipient,
                q: Some("kyc.status".to_string()),
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.count, 1);
        assert_eq!(response.items[0].package_id, wanted_id);
        assert!(response.items[0].data.is_null());
    }

    #[tokio::test]
    async fn rejects_recipient_outside_authorized_operator_allowlist() {
        let temp = tempfile::tempdir().unwrap();
        let packages_path = temp.path().join("packages.json");
        let recipient = "1".repeat(64);
        let values = vec![package(
            Uuid::new_v4(),
            &recipient,
            Some(serde_json::json!({ "patient": { "name": "Alice Martin" } })),
        )];
        tokio::fs::write(&packages_path, serde_json::to_vec(&values).unwrap())
            .await
            .unwrap();
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                packages_path: Some(packages_path),
                authorized_operator_pubkeys: vec!["2".repeat(64)],
                ..Default::default()
            },
        );

        let err = operator_shared_cellules(
            State(state),
            Query(OperatorSharedQuery { recipient, q: None }),
        )
        .await
        .expect_err("unauthorized operator must be rejected");

        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(err.code, "forbidden");
    }
}
