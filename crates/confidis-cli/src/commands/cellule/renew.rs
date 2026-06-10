use anyhow::{Context, Result, bail};
use confidis_crypto::signing_key_from_hex;
use confidis_protocol::{
    CelluleLifecycleState, MAX_CELLULE_LIFETIME_DAYS, cellule_expiry_is_valid_at,
};

use crate::commands::blob::write_blob;
use crate::commands::placement::{fetch_shard_from_hints, upload_shard_to_endpoint};
use crate::network::network_client;

use super::helpers::{
    create_cellule_record, publish_record, read_sealed_cellule_key, resolve_manifest,
};
use super::types::{CelluleGetArgs, CelluleRenewArgs, CelluleRenewOutput};

pub(super) async fn cellule_renew(args: CelluleRenewArgs) -> Result<CelluleRenewOutput> {
    let get_args = CelluleGetArgs {
        nodes: Vec::new(),
        cellule_id: args.cellule_id.clone(),
        registry: args.registry.clone(),
        blob_store: args.blob_store.clone(),
        private_key: args.private_key.clone(),
        cellule_key: args.cellule_key.clone(),
    };
    let (record, manifest) = resolve_manifest(&get_args)?;

    let now = chrono::Utc::now();
    if record.lifecycle_state_at(now) == CelluleLifecycleState::Expired {
        bail!(
            "Cellule expired at {}; create a new Cellule instead",
            record.expires_at.to_rfc3339()
        );
    }

    let new_expires_at = chrono::DateTime::parse_from_rfc3339(&args.expires_at)
        .context("--expires-at must be RFC3339")?
        .with_timezone(&chrono::Utc);
    if !cellule_expiry_is_valid_at(now, new_expires_at) {
        bail!(
            "new expires_at must be in the future and no more than {} days from now",
            MAX_CELLULE_LIFETIME_DAYS
        );
    }
    if new_expires_at <= record.expires_at {
        bail!(
            "new expires_at ({}) must be after the current expiry ({})",
            new_expires_at.to_rfc3339(),
            record.expires_at.to_rfc3339()
        );
    }

    let client = network_client()?;
    let new_expires_header = new_expires_at.to_rfc3339();
    let mut renewed_shards = 0usize;
    let mut failures = Vec::new();

    for descriptor in &manifest.shards {
        let mut renewed = false;
        let bytes = match fetch_shard_from_hints(
            &client,
            &descriptor.shard_id,
            &descriptor.provider_hints,
            Some(&args.private_key),
        )
        .await
        {
            Ok((_, bytes)) => bytes,
            Err(err) => {
                failures.push(format!("shard {}: {err}", descriptor.shard_id.0));
                continue;
            }
        };

        // Re-PUT to each provider with new expiry
        for endpoint in &descriptor.provider_hints {
            match upload_shard_to_endpoint(
                &client,
                endpoint,
                &descriptor.shard_id,
                &bytes,
                &args.private_key,
                &new_expires_header,
            )
            .await
            {
                Ok(_) => {
                    renewed = true;
                    break;
                }
                Err(err) => {
                    failures.push(format!(
                        "shard {} at {}: {err}",
                        descriptor.shard_id.0, endpoint
                    ));
                }
            }
        }

        if renewed {
            renewed_shards += 1;
        }
    }

    let failed_shards = manifest.shards.len() - renewed_shards;

    // Rebuild manifest with new manifest_id and updated timestamp
    let mut new_manifest = manifest.clone();
    new_manifest.manifest_id = uuid::Uuid::new_v4();
    new_manifest.created_at = now;
    new_manifest.signature = None;
    let signing_key = signing_key_from_hex(&args.private_key)?;
    let manifest_payload =
        serde_json::to_vec(&new_manifest).context("failed to serialize manifest for signing")?;
    new_manifest.signature = Some(confidis_crypto::sign_hex(&signing_key, &manifest_payload));

    let cellule_key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;
    let manifest_plaintext =
        serde_json::to_vec(&new_manifest).context("failed to serialize manifest")?;
    let encrypted_manifest =
        confidis_crypto::encrypt_with_cellule_key(&cellule_key, &manifest_plaintext)?;
    let new_manifest_cid = confidis_crypto::blake3_hex(&encrypted_manifest);
    write_blob(&args.blob_store, &new_manifest_cid, &encrypted_manifest)?;

    let new_record = create_cellule_record(
        record.cellule_public_key.clone(),
        &args.private_key,
        new_manifest_cid.clone(),
        &args.expires_at,
        record.sequence + 1,
    )?;
    publish_record(&args.registry, new_record)?;

    Ok(CelluleRenewOutput {
        cellule_id: args.cellule_id,
        old_expires_at: record.expires_at.to_rfc3339(),
        new_expires_at: new_expires_at.to_rfc3339(),
        old_manifest_cid: record.manifest_cid,
        new_manifest_cid,
        sequence: record.sequence + 1,
        renewed_shards,
        failed_shards,
        failures,
    })
}
