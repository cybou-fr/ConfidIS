use anyhow::Result;
use serde::Deserialize;

use crate::network::network_client;

use super::helpers::resolve_manifest;
use super::types::{
    AvailabilitySummary, CelluleAvailabilityOutput, CelluleGetArgs, ProviderAvailability,
    ShardAvailability,
};

#[derive(Debug, Deserialize)]
struct ShardStatusProbe {
    present: bool,
}

pub(super) async fn cellule_availability(
    args: CelluleGetArgs,
) -> Result<CelluleAvailabilityOutput> {
    let (record, manifest) = resolve_manifest(&args)?;
    let client = network_client()?;
    let mut shards = Vec::with_capacity(manifest.shards.len());

    for descriptor in &manifest.shards {
        let endpoints =
            super::get::resolve_provider_endpoints(&client, descriptor, &args.nodes).await;
        let mut providers = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
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
        shards.push(ShardAvailability {
            shard_index: descriptor.shard_index,
            shard_id: descriptor.shard_id.clone(),
            available,
            providers,
        });
    }

    let available_shards = shards.iter().filter(|shard| shard.available).count();
    let total_shards = manifest.erasure_policy.total_shards();
    let missing_shards = total_shards.saturating_sub(available_shards);

    Ok(CelluleAvailabilityOutput {
        cellule_id: args.cellule_id,
        manifest_cid: record.manifest_cid,
        sequence: record.sequence,
        data_shards: manifest.erasure_policy.data_shards,
        parity_shards: manifest.erasure_policy.parity_shards,
        total_shards,
        available_shards,
        missing_shards,
        repair_needed: missing_shards > 0,
        restore_possible: available_shards >= manifest.erasure_policy.data_shards,
        shards,
    })
}

pub(super) fn summarize_availability(
    available_shards: usize,
    total_shards: usize,
    data_shards: usize,
) -> AvailabilitySummary {
    let missing_shards = total_shards.saturating_sub(available_shards);
    AvailabilitySummary {
        available_shards,
        missing_shards,
        repair_needed: missing_shards > 0,
        restore_possible: available_shards >= data_shards,
    }
}

pub(super) fn summarize_availability_output(
    output: &CelluleAvailabilityOutput,
) -> AvailabilitySummary {
    AvailabilitySummary {
        available_shards: output.available_shards,
        missing_shards: output.missing_shards,
        repair_needed: output.repair_needed,
        restore_possible: output.restore_possible,
    }
}
