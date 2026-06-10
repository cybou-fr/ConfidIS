use anyhow::Result;
use confidis_protocol::CelluleLifecycleState;
use serde::Serialize;
use std::path::Path;

use super::helpers::{read_registry, read_sealed_cellule_key};

#[derive(Debug, Serialize)]
pub(super) struct AuditExportOutput {
    pub(super) exported_at: chrono::DateTime<chrono::Utc>,
    pub(super) cellule_count: usize,
    pub(super) entries: Vec<CelluleAuditEntry>,
}

#[derive(Debug, Serialize)]
pub(super) struct CelluleAuditEntry {
    pub(super) cellule_id: String,
    pub(super) cellule_public_key: String,
    pub(super) manifest_cid: String,
    pub(super) sequence: u64,
    pub(super) expires_at: String,
    pub(super) lifecycle: String,
    pub(super) days_remaining: i64,
    pub(super) manifest_version: Option<u16>,
    pub(super) manifest_created_at: Option<String>,
    pub(super) original_size_bytes: Option<u64>,
    pub(super) segment_size_bytes: Option<u64>,
    pub(super) shard_count: Option<usize>,
    pub(super) data_shards: Option<usize>,
    pub(super) parity_shards: Option<usize>,
    pub(super) provider_endpoints: Option<Vec<String>>,
    /// Unique regions across all shard placements (EU sovereignty evidence).
    pub(super) regions: Option<Vec<String>>,
    /// Unique failure domains across all shard placements.
    pub(super) failure_domains: Option<Vec<String>>,
    pub(super) manifest_error: Option<String>,
}

pub(super) fn cellule_audit_export(
    registry: &Path,
    blob_store: &Path,
    private_key: &str,
    cellule_key: &Path,
) -> Result<AuditExportOutput> {
    let records = read_registry(registry)?;
    let now = chrono::Utc::now();
    let cellule_count = records.len();
    let mut entries = Vec::with_capacity(cellule_count);

    let key = read_sealed_cellule_key(private_key, cellule_key)?;

    for record in records {
        let lifecycle = match record.lifecycle_state_at(now) {
            CelluleLifecycleState::Active => "active",
            CelluleLifecycleState::ExpiringSoon => "expiring_soon",
            CelluleLifecycleState::Expired => "expired",
        };
        let days_remaining = (record.expires_at - now).num_days();

        let manifest_result = load_manifest_for_audit(&record.manifest_cid, blob_store, &key);
        let (manifest_fields, manifest_error) = match manifest_result {
            Ok(m) => {
                let provider_endpoints: Vec<String> = m
                    .shards
                    .iter()
                    .flat_map(|d| d.provider_hints.iter().cloned())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();
                let mut regions_set = std::collections::BTreeSet::new();
                let mut domains_set = std::collections::BTreeSet::new();
                for shard in &m.shards {
                    if let Some(r) = &shard.region {
                        regions_set.insert(r.clone());
                    }
                    if let Some(fd) = &shard.failure_domain {
                        domains_set.insert(fd.clone());
                    }
                }
                let regions = if regions_set.is_empty() {
                    None
                } else {
                    Some(regions_set.into_iter().collect())
                };
                let failure_domains = if domains_set.is_empty() {
                    None
                } else {
                    Some(domains_set.into_iter().collect())
                };
                (
                    (
                        Some(m.version),
                        Some(m.created_at.to_rfc3339()),
                        Some(m.original_size_bytes),
                        Some(m.segment_size_bytes),
                        Some(m.shards.len()),
                        Some(m.erasure_policy.data_shards),
                        Some(m.erasure_policy.parity_shards),
                        Some(provider_endpoints),
                        regions,
                        failure_domains,
                    ),
                    None,
                )
            }
            Err(err) => (
                (None, None, None, None, None, None, None, None, None, None),
                Some(err.to_string()),
            ),
        };

        entries.push(CelluleAuditEntry {
            cellule_id: record.cellule_id.0.clone(),
            cellule_public_key: record.cellule_public_key.clone(),
            manifest_cid: record.manifest_cid.clone(),
            sequence: record.sequence,
            expires_at: record.expires_at.to_rfc3339(),
            lifecycle: lifecycle.to_string(),
            days_remaining,
            manifest_version: manifest_fields.0,
            manifest_created_at: manifest_fields.1,
            original_size_bytes: manifest_fields.2,
            segment_size_bytes: manifest_fields.3,
            shard_count: manifest_fields.4,
            data_shards: manifest_fields.5,
            parity_shards: manifest_fields.6,
            provider_endpoints: manifest_fields.7,
            regions: manifest_fields.8,
            failure_domains: manifest_fields.9,
            manifest_error,
        });
    }

    entries.sort_by_key(|entry| entry.days_remaining);

    Ok(AuditExportOutput {
        exported_at: now,
        cellule_count,
        entries,
    })
}

fn load_manifest_for_audit(
    manifest_cid: &str,
    blob_store: &Path,
    key: &[u8; 32],
) -> Result<confidis_protocol::Manifest> {
    use anyhow::Context;
    let encrypted = crate::commands::blob::read_blob(blob_store, manifest_cid)?;
    let actual_cid = confidis_crypto::blake3_hex(&encrypted);
    if actual_cid != manifest_cid {
        anyhow::bail!("manifest CID mismatch: expected {manifest_cid}, got {actual_cid}");
    }
    let bytes = confidis_crypto::decrypt_with_cellule_key(key, &encrypted)?;
    serde_json::from_slice(&bytes).context("invalid decrypted manifest")
}
