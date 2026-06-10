use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;

use confidis_protocol::{
    CelluleId, CellulePublicRecord, CelluleReadAccessRevocationLog, RecipientPackageRecord,
    RecipientPackageStatus,
};

use crate::error::ApiError;
use crate::state::NodeState;

pub(crate) fn cellule_registry_path(state: &Arc<NodeState>) -> Result<&Path, ApiError> {
    state
        .config
        .registry_path
        .as_deref()
        .ok_or_else(|| ApiError::not_found("registry_path not configured — add it to node config"))
}

pub(crate) fn package_registry_path(state: &Arc<NodeState>) -> Result<&Path, ApiError> {
    state
        .config
        .packages_path
        .as_deref()
        .ok_or_else(|| ApiError::internal("packages_path not configured"))
}

pub(crate) fn read_access_revocation_log_path(state: &Arc<NodeState>) -> Option<&Path> {
    state.config.read_access_revocations_path.as_deref()
}

pub(crate) async fn load_cellule_registry_from_path(
    path: &Path,
) -> Result<Vec<CellulePublicRecord>, ApiError> {
    if !tokio::fs::try_exists(path)
        .await
        .map_err(|e| ApiError::internal(format!("failed to check registry path: {e}")))?
    {
        return Ok(Vec::new());
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| ApiError::internal(format!("failed to read registry: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::internal(format!("invalid registry JSON: {e}")))
}

pub(crate) async fn load_cellule_registry(
    state: &Arc<NodeState>,
) -> Result<Vec<CellulePublicRecord>, ApiError> {
    load_cellule_registry_from_path(cellule_registry_path(state)?).await
}

pub(crate) async fn save_cellule_registry_to_path(
    path: &Path,
    records: &[CellulePublicRecord],
) -> Result<(), ApiError> {
    write_json_atomic(path, records, "registry").await
}

pub(crate) async fn save_cellule_registry(
    state: &Arc<NodeState>,
    records: &[CellulePublicRecord],
) -> Result<(), ApiError> {
    save_cellule_registry_to_path(cellule_registry_path(state)?, records).await
}

pub(crate) async fn upsert_cellule_record(
    state: &Arc<NodeState>,
    record: CellulePublicRecord,
) -> Result<(), ApiError> {
    let _lock = state.cellule_registry_write_lock.lock().await;
    let mut records = load_cellule_registry(state).await?;
    if records
        .iter()
        .any(|existing| existing.cellule_id == record.cellule_id)
    {
        return Err(ApiError::status(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "Cellule already exists; use renew for an existing Cellule",
        ));
    }
    records.push(record);
    save_cellule_registry(state, &records).await
}

pub(crate) async fn update_cellule_record(
    state: &Arc<NodeState>,
    cellule_id: &CelluleId,
    update: impl FnOnce(&mut CellulePublicRecord),
) -> Result<(), ApiError> {
    let _lock = state.cellule_registry_write_lock.lock().await;
    let mut records = load_cellule_registry(state).await?;
    let record = records
        .iter_mut()
        .find(|record| &record.cellule_id == cellule_id)
        .ok_or_else(|| ApiError::not_found("Cellule not found"))?;
    update(record);
    save_cellule_registry(state, &records).await
}

pub(crate) async fn remove_cellule_record(
    state: &Arc<NodeState>,
    cellule_id: &CelluleId,
) -> Result<(), ApiError> {
    let _lock = state.cellule_registry_write_lock.lock().await;
    let mut records = load_cellule_registry(state).await?;
    let initial_len = records.len();
    records.retain(|record| &record.cellule_id != cellule_id);
    if records.len() == initial_len {
        return Err(ApiError::not_found("Cellule not found"));
    }
    save_cellule_registry(state, &records).await
}

pub(crate) async fn find_cellule_record(
    state: &Arc<NodeState>,
    cellule_id: &str,
) -> Result<CellulePublicRecord, ApiError> {
    load_cellule_registry(state)
        .await?
        .into_iter()
        .find(|record| record.cellule_id.0 == cellule_id)
        .ok_or_else(|| ApiError::not_found("Cellule not found in registry"))
}

pub(crate) async fn load_package_registry_from_path(
    path: &Path,
) -> Result<Vec<RecipientPackageRecord>, ApiError> {
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

pub(crate) async fn load_package_registry(
    state: &Arc<NodeState>,
) -> Result<Vec<RecipientPackageRecord>, ApiError> {
    load_package_registry_from_path(package_registry_path(state)?).await
}

pub(crate) async fn save_package_registry_to_path(
    path: &Path,
    packages: &[RecipientPackageRecord],
) -> Result<(), ApiError> {
    write_json_atomic(path, packages, "packages registry").await
}

pub(crate) async fn save_package_registry(
    state: &Arc<NodeState>,
    packages: &[RecipientPackageRecord],
) -> Result<(), ApiError> {
    save_package_registry_to_path(package_registry_path(state)?, packages).await
}

pub(crate) async fn upsert_package_record(
    state: &Arc<NodeState>,
    package: RecipientPackageRecord,
) -> Result<(), ApiError> {
    let _lock = state.package_registry_write_lock.lock().await;
    let mut packages = load_package_registry(state).await?;
    if packages
        .iter()
        .any(|existing| existing.package_id == package.package_id)
    {
        return Err(ApiError::status(
            axum::http::StatusCode::CONFLICT,
            "conflict",
            "recipient package already exists",
        ));
    }
    packages.push(package);
    save_package_registry(state, &packages).await
}

pub(crate) async fn mark_package_removed(
    state: &Arc<NodeState>,
    package_id: Uuid,
) -> Result<(), ApiError> {
    let _lock = state.package_registry_write_lock.lock().await;
    let mut packages = load_package_registry(state).await?;
    let package = packages
        .iter_mut()
        .find(|package| package.package_id == package_id)
        .ok_or_else(|| ApiError::not_found("package not found"))?;
    package.status = RecipientPackageStatus::Removed;
    save_package_registry(state, &packages).await
}

pub(crate) async fn load_read_access_revocation_log_from_path(
    path: &Path,
) -> Result<CelluleReadAccessRevocationLog, ApiError> {
    if !tokio::fs::try_exists(path).await.map_err(|e| {
        ApiError::internal(format!(
            "failed to check read-access revocation log path: {e}"
        ))
    })? {
        return Ok(CelluleReadAccessRevocationLog {
            version: 1,
            revocations: Vec::new(),
        });
    }

    let bytes = tokio::fs::read(path).await.map_err(|e| {
        ApiError::internal(format!("failed to read read-access revocation log: {e}"))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::internal(format!("invalid read-access revocation log JSON: {e}")))
}

pub(crate) async fn load_read_access_revocation_log(
    state: &Arc<NodeState>,
) -> Result<CelluleReadAccessRevocationLog, ApiError> {
    let Some(path) = read_access_revocation_log_path(state) else {
        return Ok(CelluleReadAccessRevocationLog {
            version: 1,
            revocations: Vec::new(),
        });
    };
    load_read_access_revocation_log_from_path(path).await
}

async fn write_json_atomic<T: Serialize + ?Sized>(
    path: &Path,
    value: &T,
    label: &str,
) -> Result<(), ApiError> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| ApiError::internal(format!("failed to serialize {label}: {e}")))?;
    let tmp_path = tmp_path_for(path);
    tokio::fs::write(&tmp_path, json)
        .await
        .map_err(|e| ApiError::internal(format!("failed to write {label} tmp: {e}")))?;
    tokio::fs::rename(&tmp_path, path)
        .await
        .map_err(|e| ApiError::internal(format!("failed to commit {label}: {e}")))
}

fn tmp_path_for(path: &Path) -> PathBuf {
    path.with_extension("tmp")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::{TestNodeStateOptions, test_node_state};
    use axum::http::StatusCode;
    use chrono::Utc;
    use confidis_protocol::RecipientPackageStatus;

    #[tokio::test]
    async fn load_cellule_registry_returns_empty_when_file_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let records = load_cellule_registry_from_path(&temp.path().join("missing.json"))
            .await
            .unwrap();

        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn load_cellule_registry_rejects_invalid_json() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("registry.json");
        std::fs::write(&path, b"not-json").unwrap();

        let err = load_cellule_registry_from_path(&path)
            .await
            .expect_err("invalid registry");

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.message.contains("invalid registry JSON"));
    }

    #[tokio::test]
    async fn find_cellule_record_uses_configured_registry_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("registry.json");
        let record = CellulePublicRecord {
            version: 1,
            cellule_id: CelluleId("cellule-registry-test".to_string()),
            cellule_public_key: "owner-public-key".to_string(),
            manifest_cid: "manifest-cid".to_string(),
            sequence: 9,
            expires_at: Utc::now(),
            signature: "signature".to_string(),
        };
        std::fs::write(&path, serde_json::to_vec(&vec![record]).unwrap()).unwrap();
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "registry-test-node",
                registry_path: Some(path),
                ..Default::default()
            },
        );

        let found = find_cellule_record(&state, "cellule-registry-test")
            .await
            .unwrap();

        assert_eq!(found.manifest_cid, "manifest-cid");
    }

    #[tokio::test]
    async fn upsert_update_and_remove_cellule_record_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("registry.json");
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "registry-test-node",
                registry_path: Some(path.clone()),
                ..Default::default()
            },
        );
        let cellule_id = CelluleId("cellule-registry-write-test".to_string());
        let record = CellulePublicRecord {
            version: 1,
            cellule_id: cellule_id.clone(),
            cellule_public_key: "owner-public-key".to_string(),
            manifest_cid: "manifest-before".to_string(),
            sequence: 1,
            expires_at: Utc::now(),
            signature: "signature".to_string(),
        };

        upsert_cellule_record(&state, record).await.unwrap();
        update_cellule_record(&state, &cellule_id, |record| {
            record.manifest_cid = "manifest-after".to_string();
            record.sequence = 2;
        })
        .await
        .unwrap();

        let records = load_cellule_registry_from_path(&path).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].manifest_cid, "manifest-after");
        assert_eq!(records[0].sequence, 2);
        assert!(!tmp_path_for(&path).exists());

        remove_cellule_record(&state, &cellule_id).await.unwrap();
        assert!(
            load_cellule_registry_from_path(&path)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(!tmp_path_for(&path).exists());
    }

    #[tokio::test]
    async fn upsert_and_mark_package_removed_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("packages.json");
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "registry-test-node",
                packages_path: Some(path.clone()),
                ..Default::default()
            },
        );
        let package_id = Uuid::new_v4();
        let package = RecipientPackageRecord {
            package_id,
            cellule_id: CelluleId("cellule-package-registry-test".to_string()),
            owner_public_key: "owner-public-key".to_string(),
            recipient_public_key: "recipient-public-key".to_string(),
            recipient_x25519_pubkey: "recipient-x25519-public-key".to_string(),
            fields: vec!["kyc.status".to_string()],
            issued_at: Utc::now(),
            expires_at: None,
            status: RecipientPackageStatus::Active,
            package_hash: "a".repeat(64),
            owner_signature: "signature".to_string(),
            delivery_receipts: Vec::new(),
        };

        upsert_package_record(&state, package).await.unwrap();
        mark_package_removed(&state, package_id).await.unwrap();

        let packages = load_package_registry_from_path(&path).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].status, RecipientPackageStatus::Removed);
        assert!(!tmp_path_for(&path).exists());
    }

    #[tokio::test]
    async fn load_read_access_revocation_log_returns_empty_when_path_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let log = load_read_access_revocation_log_from_path(
            &temp.path().join("missing-revocations.json"),
        )
        .await
        .unwrap();

        assert_eq!(log.version, 1);
        assert!(log.revocations.is_empty());
    }

    #[tokio::test]
    async fn load_read_access_revocation_log_rejects_invalid_json() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("read-access-revocations.json");
        std::fs::write(&path, b"not-json").unwrap();

        let err = load_read_access_revocation_log_from_path(&path)
            .await
            .expect_err("invalid revocation log");

        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.message
                .contains("invalid read-access revocation log JSON")
        );
    }
}
