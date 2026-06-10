use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::registry_service::{
    load_cellule_registry, load_package_registry, mark_package_removed, upsert_package_record,
};
use crate::security_events::{SecurityEvent, SecurityEventSeverity, emit_security_event};
use crate::state::NodeState;

#[derive(Debug, Deserialize)]
pub(crate) struct WalletPackagesCreateRequest {
    pub package: confidis_protocol::RecipientPackageRecord,
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletPackagesCreateResponse {
    pub package_id: Uuid,
    pub cellule_id: confidis_protocol::CelluleId,
    pub recipient_public_key: String,
    pub issued_at: DateTime<Utc>,
}

/// POST /wallet/packages — create a recipient package via owner-signed request.
pub(crate) async fn wallet_packages_create(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<WalletPackagesCreateRequest>,
) -> Result<Json<WalletPackagesCreateResponse>, ApiError> {
    let now = Utc::now();
    confidis_protocol::verify_recipient_package_record(&request.package, now)
        .map_err(|err| ApiError::forbidden(format!("package create denied: {err}")))?;

    // Verify the owner owns the cellule.
    let _cellule_record = load_cellule_registry(&state)
        .await?
        .iter()
        .find(|r| {
            r.cellule_id == request.package.cellule_id
                && r.cellule_public_key == request.package.owner_public_key
        })
        .ok_or_else(|| ApiError::forbidden("owner does not control this cellule"))?;

    upsert_package_record(&state, request.package.clone()).await?;

    emit_security_event(
        &state,
        SecurityEvent::new(
            &state,
            "recipient_package.created",
            SecurityEventSeverity::Info,
            "recipient package created successfully",
        )
        .with_context("package_id", request.package.package_id.to_string())
        .with_context("cellule_id", request.package.cellule_id.0.clone())
        .with_context("owner_public_key", request.package.owner_public_key.clone())
        .with_context(
            "recipient_public_key",
            request.package.recipient_public_key.clone(),
        ),
    );

    Ok(Json(WalletPackagesCreateResponse {
        package_id: request.package.package_id,
        cellule_id: request.package.cellule_id.clone(),
        recipient_public_key: request.package.recipient_public_key.clone(),
        issued_at: request.package.issued_at,
    }))
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletPackagesIndexResponse {
    pub packages: Vec<WalletPackageSummary>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletPackageSummary {
    pub package_id: Uuid,
    pub cellule_id: confidis_protocol::CelluleId,
    pub recipient_public_key: String,
    pub fields: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: confidis_protocol::RecipientPackageStatus,
}

/// GET /wallet/packages?owner=<pubkey> — list recipient packages owned by the given key.
pub(crate) async fn wallet_packages_index(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<WalletPackagesIndexResponse>, ApiError> {
    let owner_pubkey = params
        .get("owner")
        .ok_or_else(|| ApiError::bad_request("missing owner parameter"))?;

    let owner_packages: Vec<WalletPackageSummary> = load_package_registry(&state)
        .await?
        .into_iter()
        .filter(|p| p.owner_public_key == *owner_pubkey)
        .map(|p| WalletPackageSummary {
            package_id: p.package_id,
            cellule_id: p.cellule_id,
            recipient_public_key: p.recipient_public_key,
            fields: p.fields,
            issued_at: p.issued_at,
            expires_at: p.expires_at,
            status: p.status,
        })
        .collect();

    emit_security_event(
        &state,
        SecurityEvent::new(
            &state,
            "packages.indexed",
            SecurityEventSeverity::Info,
            "packages indexed successfully",
        )
        .with_context("owner_public_key", owner_pubkey.clone())
        .with_context("package_count", owner_packages.len().to_string()),
    );

    Ok(Json(WalletPackagesIndexResponse {
        packages: owner_packages,
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct WalletPackagesRemoveRequest {
    pub remove: confidis_protocol::RecipientPackageRemove,
}

/// POST /wallet/packages/{package_id}/remove — remove a recipient package.
pub(crate) async fn wallet_packages_remove(
    State(state): State<Arc<NodeState>>,
    AxumPath(package_id): AxumPath<String>,
    Json(request): Json<WalletPackagesRemoveRequest>,
) -> Result<StatusCode, ApiError> {
    let package_id =
        Uuid::parse_str(&package_id).map_err(|_| ApiError::bad_request("invalid package_id"))?;

    let now = Utc::now();
    confidis_protocol::verify_recipient_package_remove(&request.remove, &package_id, now)
        .map_err(|err| ApiError::forbidden(format!("package remove denied: {err}")))?;

    let package = load_package_registry(&state)
        .await?
        .into_iter()
        .find(|package| package.package_id == package_id)
        .ok_or_else(|| ApiError::not_found("package not found"))?;
    if package.owner_public_key != request.remove.owner_public_key {
        return Err(ApiError::forbidden(
            "package remove denied: public key does not match registered owner",
        ));
    }

    mark_package_removed(&state, package_id).await?;

    emit_security_event(
        &state,
        SecurityEvent::new(
            &state,
            "recipient_package.removed",
            SecurityEventSeverity::Info,
            "recipient package removed successfully",
        )
        .with_context("package_id", package_id.to_string())
        .with_context("owner_public_key", request.remove.owner_public_key.clone()),
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex, x25519_generate};
    use confidis_protocol::{
        CelluleId, CellulePublicRecord, RECIPIENT_PACKAGE_REMOVE_OPERATION, RecipientPackageRecord,
        RecipientPackageRemove, RecipientPackageStatus, recipient_package_record_signing_payload,
        recipient_package_remove_signing_payload,
    };

    use crate::test_support::{TestNodeStateOptions, test_node_state};

    fn test_state(
        temp: &tempfile::TempDir,
        registry_path: std::path::PathBuf,
        packages_path: std::path::PathBuf,
    ) -> Arc<NodeState> {
        test_node_state(
            temp,
            TestNodeStateOptions {
                node_id: "wallet-package-test-node",
                registry_path: Some(registry_path),
                packages_path: Some(packages_path),
                ..Default::default()
            },
        )
    }

    fn signed_package(
        package_id: Uuid,
        cellule_id: CelluleId,
        owner_key: &ed25519_dalek::SigningKey,
    ) -> RecipientPackageRecord {
        let recipient_key = generate_signing_key();
        let (_, recipient_x25519_pubkey) = x25519_generate();
        let mut package = RecipientPackageRecord {
            package_id,
            cellule_id,
            owner_public_key: verifying_key_to_hex(&owner_key.verifying_key()),
            recipient_public_key: verifying_key_to_hex(&recipient_key.verifying_key()),
            recipient_x25519_pubkey,
            fields: vec!["kyc.status".to_string()],
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(7)),
            status: RecipientPackageStatus::Active,
            package_hash: "a".repeat(64),
            owner_signature: String::new(),
            delivery_receipts: Vec::new(),
        };
        let payload = recipient_package_record_signing_payload(&package).expect("package payload");
        package.owner_signature = sign_hex(owner_key, &payload);
        package
    }

    fn signed_remove(
        package_id: Uuid,
        owner_key: &ed25519_dalek::SigningKey,
    ) -> RecipientPackageRemove {
        let mut remove = RecipientPackageRemove {
            version: 1,
            operation: RECIPIENT_PACKAGE_REMOVE_OPERATION.to_string(),
            package_id,
            owner_public_key: verifying_key_to_hex(&owner_key.verifying_key()),
            issued_at: Utc::now(),
            signature: String::new(),
        };
        let payload = recipient_package_remove_signing_payload(&remove).expect("remove payload");
        remove.signature = sign_hex(owner_key, &payload);
        remove
    }

    #[tokio::test]
    async fn package_create_index_and_remove_update_registry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let registry_path = temp.path().join("registry.json");
        let packages_path = temp.path().join("packages.json");
        let owner_key = generate_signing_key();
        let owner_public_key = verifying_key_to_hex(&owner_key.verifying_key());
        let cellule_id = CelluleId("cellule-package-test".to_string());
        let registry = vec![CellulePublicRecord {
            version: 1,
            cellule_id: cellule_id.clone(),
            cellule_public_key: owner_public_key.clone(),
            manifest_cid: String::new(),
            sequence: 0,
            expires_at: Utc::now() + chrono::Duration::days(30),
            signature: String::new(),
        }];
        std::fs::write(
            &registry_path,
            serde_json::to_vec_pretty(&registry).unwrap(),
        )
        .unwrap();

        let state = test_state(&temp, registry_path, packages_path.clone());
        let package_id = Uuid::new_v4();
        let package = signed_package(package_id, cellule_id.clone(), &owner_key);

        let Json(create_response) = wallet_packages_create(
            State(state.clone()),
            Json(WalletPackagesCreateRequest {
                package: package.clone(),
            }),
        )
        .await
        .expect("create package");
        assert_eq!(create_response.package_id, package_id);
        assert_eq!(create_response.cellule_id, cellule_id);

        let mut params = HashMap::new();
        params.insert("owner".to_string(), owner_public_key.clone());
        let Json(index_response) = wallet_packages_index(State(state.clone()), Query(params))
            .await
            .expect("index packages");
        assert_eq!(index_response.packages.len(), 1);
        assert_eq!(index_response.packages[0].package_id, package_id);
        assert_eq!(index_response.packages[0].fields, vec!["kyc.status"]);

        let status = wallet_packages_remove(
            State(state),
            AxumPath(package_id.to_string()),
            Json(WalletPackagesRemoveRequest {
                remove: signed_remove(package_id, &owner_key),
            }),
        )
        .await
        .expect("remove package");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let stored: Vec<RecipientPackageRecord> =
            serde_json::from_slice(&std::fs::read(&packages_path).unwrap()).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].status, RecipientPackageStatus::Removed);
    }

    #[tokio::test]
    async fn package_mutations_reject_a_different_owner_for_existing_id() {
        let temp = tempfile::tempdir().expect("temp dir");
        let registry_path = temp.path().join("registry.json");
        let packages_path = temp.path().join("packages.json");
        let owner_key = generate_signing_key();
        let attacker_key = generate_signing_key();
        let owner_cellule = CelluleId("owner-cellule".to_string());
        let attacker_cellule = CelluleId("attacker-cellule".to_string());
        let registry = vec![
            CellulePublicRecord {
                version: 1,
                cellule_id: owner_cellule.clone(),
                cellule_public_key: verifying_key_to_hex(&owner_key.verifying_key()),
                manifest_cid: String::new(),
                sequence: 0,
                expires_at: Utc::now() + chrono::Duration::days(30),
                signature: String::new(),
            },
            CellulePublicRecord {
                version: 1,
                cellule_id: attacker_cellule.clone(),
                cellule_public_key: verifying_key_to_hex(&attacker_key.verifying_key()),
                manifest_cid: String::new(),
                sequence: 0,
                expires_at: Utc::now() + chrono::Duration::days(30),
                signature: String::new(),
            },
        ];
        std::fs::write(
            &registry_path,
            serde_json::to_vec_pretty(&registry).unwrap(),
        )
        .unwrap();
        let state = test_state(&temp, registry_path, packages_path.clone());
        let package_id = Uuid::new_v4();

        let _ = wallet_packages_create(
            State(state.clone()),
            Json(WalletPackagesCreateRequest {
                package: signed_package(package_id, owner_cellule, &owner_key),
            }),
        )
        .await
        .expect("initial owner package");

        let overwrite = wallet_packages_create(
            State(state.clone()),
            Json(WalletPackagesCreateRequest {
                package: signed_package(package_id, attacker_cellule, &attacker_key),
            }),
        )
        .await
        .expect_err("existing package id must not be overwritten");
        assert_eq!(overwrite.status, StatusCode::CONFLICT);

        let remove = wallet_packages_remove(
            State(state),
            AxumPath(package_id.to_string()),
            Json(WalletPackagesRemoveRequest {
                remove: signed_remove(package_id, &attacker_key),
            }),
        )
        .await
        .expect_err("non-owner package remove must be rejected");
        assert_eq!(remove.status, StatusCode::FORBIDDEN);

        let stored: Vec<RecipientPackageRecord> =
            serde_json::from_slice(&std::fs::read(&packages_path).unwrap()).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].status, RecipientPackageStatus::Active);
        assert_eq!(
            stored[0].owner_public_key,
            verifying_key_to_hex(&owner_key.verifying_key())
        );
    }
}
