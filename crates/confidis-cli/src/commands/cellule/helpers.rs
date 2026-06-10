use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use confidis_crypto::{signing_key_from_hex, verifying_key_from_hex};
use confidis_protocol::{
    CelluleId, CellulePublicRecord, MAX_CELLULE_LIFETIME_DAYS, Manifest, ShardDescriptor,
    cellule_expiry_is_valid_at, cellule_record_id_from_public_key, cellule_record_signing_payload,
    verify_cellule_public_record, verify_cellule_public_record_signature,
};

use crate::commands::blob::read_blob;
use crate::commands::placement::PlacementUploadOutput;

use super::types::CelluleGetArgs;

pub(super) fn cellule_id_from_public_key(public_key: &str) -> Result<CelluleId> {
    cellule_record_id_from_public_key(public_key)
}

pub(super) fn create_cellule_record(
    public_key: String,
    private_key: &str,
    manifest_cid: String,
    expires_at: &str,
    sequence: u64,
) -> Result<CellulePublicRecord> {
    let id = cellule_id_from_public_key(&public_key)?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
        .context("expires_at must be RFC3339")?
        .with_timezone(&chrono::Utc);
    let now = chrono::Utc::now();
    if !cellule_expiry_is_valid_at(now, expires_at) {
        bail!(
            "expires_at must be in the future and no more than {} days from now",
            MAX_CELLULE_LIFETIME_DAYS
        );
    }
    let mut record = CellulePublicRecord {
        version: 1,
        cellule_id: id,
        cellule_public_key: public_key,
        manifest_cid,
        sequence,
        expires_at,
        signature: String::new(),
    };
    let key = signing_key_from_hex(private_key)?;
    let payload = cellule_record_signing_payload(&record)?;
    record.signature = confidis_crypto::sign_hex(&key, &payload);
    Ok(record)
}

pub(super) fn verify_cellule_record(record: &CellulePublicRecord) -> Result<()> {
    verify_cellule_public_record(record)
}

pub(super) fn verify_cellule_record_signature(record: &CellulePublicRecord) -> Result<()> {
    verify_cellule_public_record_signature(record)
}

pub(super) fn read_registry(path: &Path) -> Result<Vec<CellulePublicRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("invalid Cellule registry")
}

pub(super) fn publish_record(registry: &Path, record: CellulePublicRecord) -> Result<()> {
    verify_cellule_record(&record)?;
    let mut records = read_registry(registry)?;
    records.retain(|existing| existing.cellule_id != record.cellule_id);
    records.push(record);
    fs::write(registry, serde_json::to_vec_pretty(&records)?)
        .with_context(|| format!("failed to write {}", registry.display()))
}

pub(crate) fn read_sealed_cellule_key(private_key: &str, path: &Path) -> Result<[u8; 32]> {
    let sealed = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    confidis_crypto::open_cellule_key(private_key, &sealed)
}

pub(super) fn safe_path_segment(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn validated_expires_at(expires_at: &str) -> Result<String> {
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
        .context("expires_at must be RFC3339")?
        .with_timezone(&chrono::Utc);
    Ok(expires_at.to_rfc3339())
}

pub(super) fn resolve_cellule_record(args: &CelluleGetArgs) -> Result<CellulePublicRecord> {
    let records = read_registry(&args.registry)?;
    let record = records
        .into_iter()
        .find(|record| record.cellule_id.0 == args.cellule_id)
        .context("Cellule record not found")?;
    verify_cellule_record_signature(&record)?;
    Ok(record)
}

pub(super) fn resolve_manifest(args: &CelluleGetArgs) -> Result<(CellulePublicRecord, Manifest)> {
    let record = resolve_cellule_record(args)?;

    let encrypted_manifest = read_blob(&args.blob_store, &record.manifest_cid)?;
    let manifest = decrypt_manifest(args, &record, &encrypted_manifest)?;
    Ok((record, manifest))
}

pub(super) fn decrypt_manifest(
    args: &CelluleGetArgs,
    record: &CellulePublicRecord,
    encrypted_manifest: &[u8],
) -> Result<Manifest> {
    let actual_cid = confidis_crypto::blake3_hex(&encrypted_manifest);
    if actual_cid != record.manifest_cid {
        bail!(
            "manifest CID mismatch: expected {}, got {}",
            record.manifest_cid,
            actual_cid
        );
    }

    let key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;
    let manifest_bytes = confidis_crypto::decrypt_with_cellule_key(&key, &encrypted_manifest)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("invalid decrypted manifest")?;
    if manifest.cellule_id.0 != args.cellule_id {
        bail!(
            "manifest Cellule ID mismatch: expected {}, got {}",
            args.cellule_id,
            manifest.cellule_id.0
        );
    }
    // Verify the manifest's Ed25519 signature using the Cellule's public key.
    if let Some(sig) = &manifest.signature {
        let verifying_key = verifying_key_from_hex(&record.cellule_public_key)
            .context("invalid cellule public key in record")?;
        let mut unsigned = manifest.clone();
        unsigned.signature = None;
        let payload = serde_json::to_vec(&unsigned)
            .context("failed to serialize manifest for verification")?;
        confidis_crypto::verify_hex(&verifying_key, &payload, sig)
            .context("manifest signature verification failed")?;
    }
    Ok(manifest)
}

/// Build a Manifest from one upload-per-segment. Each `ShardDescriptor` is
/// tagged with its `segment_index`; `segment_size_bytes` is the fixed streaming
/// segment size so `cellule get` can derive each segment's original length.
/// A single-segment input yields a manifest byte-equivalent to the previous
/// single-segment path (segment_index 0 everywhere).
pub(crate) fn manifest_from_segments(
    segments: &[(u32, PlacementUploadOutput)],
    cellule_id: CelluleId,
    original_len: u64,
    segment_size: u64,
) -> Manifest {
    let mut shards = Vec::new();
    for (segment_index, upload) in segments {
        for placement in &upload.plan.placements {
            let receipt = upload
                .receipts
                .iter()
                .find(|receipt| receipt.shard_id == placement.shard_id);
            shards.push(ShardDescriptor {
                shard_id: placement.shard_id.clone(),
                shard_index: placement.shard_index,
                segment_index: *segment_index,
                size_bytes: receipt
                    .map(|receipt| receipt.size_bytes)
                    .unwrap_or_default(),
                provider_hints: vec![placement.endpoint.clone()],
                region: Some(placement.region.clone()),
                failure_domain: Some(placement.failure_domain.clone()),
            });
        }
    }

    let (group_id, erasure_policy) = segments
        .first()
        .map(|(_, u)| (u.plan.group_id.clone(), u.plan.erasure_policy.clone()))
        .unwrap_or_default();

    Manifest {
        version: 1,
        manifest_id: uuid::Uuid::new_v4(),
        cellule_id,
        group_id,
        erasure_policy,
        original_size_bytes: original_len,
        segment_size_bytes: segment_size,
        shards,
        created_at: chrono::Utc::now(),
        signature: None,
    }
}
