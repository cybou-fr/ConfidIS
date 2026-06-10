use anyhow::{Context, Result, bail};
use chrono::Utc;
use confidis_protocol::{
    CELLULE_OWNER_REPORT_PROOF_OPERATION, CelluleLifecycleState, CelluleOwnerReportProof,
    cellule_owner_report_proof_signing_payload, verify_cellule_owner_report_proof,
};
use serde::Deserialize;
use std::path::Path;
use uuid::Uuid;

use crate::network::network_client;

use super::helpers::{read_registry, resolve_manifest};
use super::types::{
    AvailabilitySummary, CelluleGetArgs, CelluleOwnerReportOutput, CelluleReportExportArgs,
    CelluleReportProofArgs, CelluleReportProofOutput, OwnerReportManifestSummary, OwnerReportShard,
    ProviderAvailability,
};

pub(super) fn cellule_report_proof(
    args: CelluleReportProofArgs,
) -> Result<CelluleReportProofOutput> {
    let records = read_registry(&args.registry)?;
    let record = records
        .into_iter()
        .find(|record| record.cellule_id.0 == args.cellule_id)
        .context("Cellule not found in registry")?;

    let owner_key = confidis_crypto::signing_key_from_hex(&args.owner_private_key)?;
    let owner_public_key = confidis_crypto::verifying_key_to_hex(&owner_key.verifying_key());
    if owner_public_key != record.cellule_public_key {
        bail!("owner private key does not match the Cellule owner public key in registry");
    }

    let requested_scope = normalize_scope(args.scope);
    if requested_scope.is_empty() {
        bail!("at least one --scope value is required; use --scope cellule.report");
    }

    let now = Utc::now();
    let mut proof = CelluleOwnerReportProof {
        version: 1,
        proof_id: Uuid::new_v4(),
        operation: CELLULE_OWNER_REPORT_PROOF_OPERATION.to_string(),
        cellule_id: record.cellule_id.clone(),
        owner_public_key,
        requested_scope: requested_scope.clone(),
        challenge: args.challenge,
        issued_at: now,
        signature: String::new(),
    };
    let payload = cellule_owner_report_proof_signing_payload(&proof)?;
    proof.signature = confidis_crypto::sign_hex(&owner_key, &payload);
    verify_cellule_owner_report_proof(&record, &proof, &proof.challenge, now)?;

    Ok(CelluleReportProofOutput {
        proof,
        cellule_id: record.cellule_id,
        requested_scope,
        warning: "Owner report proof authorizes report delivery only. Full placement reports still require local owner manifest context; do not paste private keys into the browser.".to_string(),
    })
}

#[derive(Debug, Deserialize)]
struct ReportProofEnvelope {
    proof: CelluleOwnerReportProof,
}

#[derive(Debug, Deserialize)]
struct ShardStatusProbe {
    present: bool,
}

pub(super) async fn cellule_report_export(
    args: CelluleReportExportArgs,
) -> Result<CelluleOwnerReportOutput> {
    let proof = read_report_proof(&args.proof)?;
    if proof.cellule_id.0 != args.cellule_id {
        bail!("owner report proof Cellule ID does not match --cellule-id");
    }

    let get_args = CelluleGetArgs {
        nodes: Vec::new(),
        cellule_id: args.cellule_id.clone(),
        registry: args.registry.clone(),
        blob_store: args.blob_store.clone(),
        private_key: args.owner_private_key.clone(),
        cellule_key: args.cellule_key.clone(),
    };
    let (record, manifest) = resolve_manifest(&get_args)?;
    verify_cellule_owner_report_proof(&record, &proof, &proof.challenge, Utc::now())?;

    let client = network_client()?;
    let mut shards = Vec::with_capacity(manifest.shards.len());
    for descriptor in &manifest.shards {
        let mut providers = Vec::with_capacity(descriptor.provider_hints.len());
        for endpoint in &descriptor.provider_hints {
            let endpoint = endpoint.trim_end_matches('/').to_string();
            let url = format!("{}/shards/{}/status", endpoint, descriptor.shard_id.0);
            match super::get::send_get_with_retry(|| Ok(client.get(&url))).await {
                Ok(response) if response.status().is_success() => {
                    let status = response.status().as_u16();
                    let text = response.text().await?;
                    match serde_json::from_str::<ShardStatusProbe>(&text) {
                        Ok(probe) => providers.push(ProviderAvailability {
                            endpoint,
                            present: probe.present,
                            status: Some(status),
                            error: None,
                        }),
                        Err(err) => providers.push(ProviderAvailability {
                            endpoint,
                            present: false,
                            status: Some(status),
                            error: Some(format!("invalid status response: {err}")),
                        }),
                    }
                }
                Ok(response) => {
                    let status = response.status().as_u16();
                    let text = response.text().await.unwrap_or_default();
                    providers.push(ProviderAvailability {
                        endpoint,
                        present: false,
                        status: Some(status),
                        error: Some(text),
                    });
                }
                Err(err) => providers.push(ProviderAvailability {
                    endpoint,
                    present: false,
                    status: None,
                    error: Some(err.to_string()),
                }),
            }
        }
        let available = providers.iter().any(|provider| provider.present);
        shards.push(OwnerReportShard {
            shard_index: descriptor.shard_index,
            shard_id: descriptor.shard_id.clone(),
            size_bytes: descriptor.size_bytes,
            region: descriptor.region.clone(),
            failure_domain: descriptor.failure_domain.clone(),
            provider_hints: descriptor.provider_hints.clone(),
            available,
            providers,
        });
    }

    let available_shards = shards.iter().filter(|shard| shard.available).count();
    let total_shards = manifest.erasure_policy.total_shards();
    let missing_shards = total_shards.saturating_sub(available_shards);
    let availability = AvailabilitySummary {
        available_shards,
        missing_shards,
        repair_needed: missing_shards > 0,
        restore_possible: available_shards >= manifest.erasure_policy.data_shards,
    };

    let providers = manifest
        .shards
        .iter()
        .flat_map(|descriptor| descriptor.provider_hints.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let regions = manifest
        .shards
        .iter()
        .filter_map(|descriptor| descriptor.region.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let failure_domains = manifest
        .shards
        .iter()
        .filter_map(|descriptor| descriptor.failure_domain.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let now = Utc::now();
    let lifecycle = match record.lifecycle_state_at(now) {
        CelluleLifecycleState::Active => "active",
        CelluleLifecycleState::ExpiringSoon => "expiring_soon",
        CelluleLifecycleState::Expired => "expired",
    };

    Ok(CelluleOwnerReportOutput {
        report_id: Uuid::new_v4(),
        generated_at: now,
        proof_id: proof.proof_id,
        cellule_id: record.cellule_id,
        owner_public_key: record.cellule_public_key,
        manifest_cid: record.manifest_cid,
        sequence: record.sequence,
        lifecycle: lifecycle.to_string(),
        expires_at: record.expires_at,
        days_remaining: (record.expires_at - now).num_days(),
        manifest: OwnerReportManifestSummary {
            version: manifest.version,
            manifest_id: manifest.manifest_id,
            group_id: manifest.group_id,
            created_at: manifest.created_at,
            original_size_bytes: manifest.original_size_bytes,
            segment_size_bytes: manifest.segment_size_bytes,
            data_shards: manifest.erasure_policy.data_shards,
            parity_shards: manifest.erasure_policy.parity_shards,
            total_shards,
        },
        availability,
        providers,
        regions,
        failure_domains,
        shards,
        warning: "Owner report was reconstructed locally from owner manifest context. Do not share this full placement report with company readers unless intentionally authorized.".to_string(),
    })
}

fn read_report_proof(path: &Path) -> Result<CelluleOwnerReportProof> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if let Ok(proof) = serde_json::from_slice::<CelluleOwnerReportProof>(&bytes) {
        return Ok(proof);
    }
    let envelope: ReportProofEnvelope = serde_json::from_slice(&bytes)
        .context("report proof must be a proof or proof output JSON")?;
    Ok(envelope.proof)
}

fn normalize_scope(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        for part in value.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}
