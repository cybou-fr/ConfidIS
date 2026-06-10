use std::path::Path;

use anyhow::{Context, Result};
use confidis_crypto::{signing_key_from_hex, verifying_key_to_hex};
use confidis_protocol::{
    SHARD_DELETE_OPERATION, ShardDeleteRequest, ShardId, ShardReceiptType,
    shard_delete_request_signing_payload,
};

use crate::commands::blob::delete_blob;
use crate::network::network_client;
use crate::verify::parse_and_verify_receipt;

use super::helpers::{read_registry, resolve_manifest};
use super::types::{CelluleDeleteOutput, CelluleGetArgs, ShardDeleteFailure};

pub(super) async fn cellule_delete(args: CelluleGetArgs) -> Result<CelluleDeleteOutput> {
    let (record, manifest) = resolve_manifest(&args)?;
    let client = network_client()?;
    let mut deletion_receipts = Vec::new();
    let mut failures = Vec::new();

    for descriptor in &manifest.shards {
        let mut receipt = None;
        let mut last_error = None;
        for endpoint in &descriptor.provider_hints {
            let url = format!(
                "{}/shards/{}",
                endpoint.trim_end_matches('/'),
                descriptor.shard_id.0
            );
            let request = create_delete_request(descriptor.shard_id.clone(), &args.private_key)?;
            match client.delete(url).json(&request).send().await {
                Ok(response) if response.status().is_success() => {
                    let text = response.text().await?;
                    match parse_and_verify_receipt(
                        &text,
                        &descriptor.shard_id,
                        ShardReceiptType::Deleted,
                        None,
                        None,
                    ) {
                        Ok(parsed) => {
                            receipt = Some(parsed);
                            break;
                        }
                        Err(err) => {
                            last_error = Some(format!("invalid deletion receipt: {err}"));
                        }
                    }
                }
                Ok(response) => {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    last_error = Some(format!("{status} {text}"));
                }
                Err(err) => {
                    last_error = Some(err.to_string());
                }
            }
        }
        if let Some(receipt) = receipt {
            deletion_receipts.push(receipt);
        } else {
            failures.push(ShardDeleteFailure {
                shard_id: descriptor.shard_id.clone(),
                shard_index: descriptor.shard_index,
                providers: descriptor.provider_hints.clone(),
                reason: last_error.unwrap_or_else(|| "no provider accepted delete".to_string()),
            });
        }
    }

    let deleted_shards = deletion_receipts.len();
    let failed_shards = failures.len();

    let manifest_deleted = if failed_shards == 0 {
        delete_blob(&args.blob_store, &record.manifest_cid)?
    } else {
        false
    };
    let record_deleted = if failed_shards == 0 {
        delete_record(&args.registry, &args.cellule_id)?
    } else {
        false
    };

    Ok(CelluleDeleteOutput {
        cellule_id: args.cellule_id,
        manifest_cid: record.manifest_cid,
        status: if failed_shards == 0 {
            "deleted".to_string()
        } else {
            "partial".to_string()
        },
        deleted_shards,
        failed_shards,
        manifest_deleted,
        record_deleted,
        deletion_receipts,
        failures,
    })
}

pub(crate) fn create_delete_request(
    shard_id: ShardId,
    private_key: &str,
) -> Result<ShardDeleteRequest> {
    let signing_key = signing_key_from_hex(private_key)?;
    let signer_public_key = verifying_key_to_hex(&signing_key.verifying_key());
    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + chrono::Duration::minutes(5);
    let mut request = ShardDeleteRequest {
        version: 1,
        request_id: uuid::Uuid::new_v4(),
        operation: SHARD_DELETE_OPERATION.to_string(),
        shard_id,
        issued_at,
        expires_at,
        signer_public_key,
        signature: String::new(),
    };
    let payload = shard_delete_request_signing_payload(&request)?;
    request.signature = confidis_crypto::sign_hex(&signing_key, &payload);
    Ok(request)
}

pub(crate) fn delete_authority_hash_from_private_key(private_key: &str) -> Result<String> {
    let signing_key = signing_key_from_hex(private_key)?;
    Ok(delete_authority_hash(&verifying_key_to_hex(
        &signing_key.verifying_key(),
    )))
}

pub(crate) fn delete_authority_hash(public_key: &str) -> String {
    confidis_crypto::blake3_hex(public_key.as_bytes())
}

fn delete_record(registry: &Path, cellule_id: &str) -> Result<bool> {
    let mut records = read_registry(registry)?;
    let before = records.len();
    records.retain(|record| record.cellule_id.0 != cellule_id);
    let deleted = records.len() != before;
    std::fs::write(registry, serde_json::to_vec_pretty(&records)?)
        .with_context(|| format!("failed to write {}", registry.display()))?;
    Ok(deleted)
}
