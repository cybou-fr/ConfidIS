use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use confidis_crypto::signing_key_from_hex;
use confidis_placement::build_placement_plan;
use confidis_protocol::PlacementPolicy;

use crate::commands::blob::write_blob;
use crate::commands::placement::{
    fetch_shard_from_hints, upload_shard_to_endpoint, verify_remote_shard,
};
use crate::network::{fetch_candidates, network_client};

use super::delete::create_delete_request;
use super::helpers::{
    create_cellule_record, publish_record, read_registry, read_sealed_cellule_key,
    resolve_manifest, safe_path_segment, verify_cellule_record,
};
use super::types::{
    CelluleGetArgs, CelluleRebalanceArgs, CelluleRebalanceOutput, CelluleRebalancePlanArgs,
    CelluleRebalancePlanOutput, CelluleRebalanceScanArgs, CelluleRebalanceScanOutput,
    CelluleRebalanceScanResult, CelluleRebalanceScanSummary, CelluleRebalanceWatchArgs,
    CelluleRebalanceWatchOutput, ShardRebalanceMove, ShardRebalanceMoveResult,
};

fn load_placement_policy(path: Option<&Path>) -> Result<PlacementPolicy> {
    match path {
        None => Ok(PlacementPolicy::default()),
        Some(p) => {
            let bytes = fs::read(p)
                .with_context(|| format!("failed to read placement policy file {}", p.display()))?;
            serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid placement policy JSON in {}", p.display()))
        }
    }
}

pub(super) async fn cellule_rebalance_plan(
    args: CelluleRebalancePlanArgs,
) -> Result<CelluleRebalancePlanOutput> {
    if args.nodes.is_empty() {
        bail!("at least one --node is required");
    }

    let get_args = CelluleGetArgs {
        nodes: args.nodes.clone(),
        cellule_id: args.cellule_id.clone(),
        registry: args.registry.clone(),
        blob_store: args.blob_store.clone(),
        private_key: args.private_key.clone(),
        cellule_key: args.cellule_key.clone(),
    };
    let (record, manifest) = resolve_manifest(&get_args)?;
    let client = network_client()?;
    let candidates = fetch_candidates(&client, &args.nodes).await?;
    let candidates_by_endpoint: HashMap<_, _> = candidates
        .iter()
        .map(|candidate| (candidate.endpoint.as_str(), candidate))
        .collect();
    let placement_policy = load_placement_policy(args.placement_policy_file.as_deref())?;
    let total = manifest.erasure_policy.total_shards();
    let segment_count = manifest
        .shards
        .iter()
        .map(|d| d.segment_index)
        .max()
        .map(|m| m + 1)
        .unwrap_or(1);

    // Per-segment target placement. Each segment is placed independently
    // (build_placement_plan expects exactly `total_shards` ids); shards are
    // keyed by `(segment_index, shard_index)`.
    let mut targets: HashMap<(u32, usize), confidis_protocol::ShardPlacement> = HashMap::new();
    let mut target_failure_domains: HashSet<String> = HashSet::new();
    for si in 0..segment_count {
        let mut ordered: Vec<Option<confidis_protocol::ShardId>> = vec![None; total];
        for d in manifest.shards.iter().filter(|d| d.segment_index == si) {
            if d.shard_index < total {
                ordered[d.shard_index] = Some(d.shard_id.clone());
            }
        }
        let seg_ids: Vec<confidis_protocol::ShardId> = ordered
            .into_iter()
            .enumerate()
            .map(|(i, x)| x.with_context(|| format!("segment {si} missing shard {i}")))
            .collect::<Result<_>>()?;
        let plan = build_placement_plan(
            format!("{}-s{si}", manifest.group_id),
            manifest.erasure_policy.clone(),
            &seg_ids,
            &candidates,
            &placement_policy,
        )?;
        for p in &plan.placements {
            target_failure_domains.insert(p.failure_domain.clone());
            targets.insert((si, p.shard_index), p.clone());
        }
    }

    let current_failure_domains: HashSet<_> = manifest
        .shards
        .iter()
        .filter_map(|descriptor| {
            descriptor
                .provider_hints
                .first()
                .and_then(|endpoint| candidates_by_endpoint.get(endpoint.trim_end_matches('/')))
                .map(|candidate| candidate.failure_domain.as_str())
        })
        .collect();

    let mut seen_current_domains = HashSet::new();
    let mut moves = Vec::new();
    for descriptor in &manifest.shards {
        let target = targets
            .get(&(descriptor.segment_index, descriptor.shard_index))
            .context("target placement missing (segment, shard)")?;
        let current_endpoint = descriptor
            .provider_hints
            .first()
            .map(|endpoint| endpoint.trim_end_matches('/').to_string());
        let current_candidate = current_endpoint
            .as_deref()
            .and_then(|endpoint| candidates_by_endpoint.get(endpoint));
        let current_failure_domain =
            current_candidate.map(|candidate| candidate.failure_domain.clone());
        let duplicate_domain = current_failure_domain
            .as_ref()
            .is_some_and(|domain| !seen_current_domains.insert(domain.clone()));
        let current_matches_target = current_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint == target.endpoint);

        if current_matches_target {
            continue;
        }

        let reason = if current_endpoint.is_none() {
            "missing_provider_hint"
        } else if current_candidate.is_none() {
            "current_node_not_in_candidate_set"
        } else if duplicate_domain {
            "duplicate_failure_domain"
        } else {
            "better_capacity_weighted_target"
        };

        moves.push(ShardRebalanceMove {
            segment_index: descriptor.segment_index,
            shard_index: descriptor.shard_index,
            shard_id: descriptor.shard_id.clone(),
            current_endpoint,
            current_node_id: current_candidate.map(|candidate| candidate.node_id.clone()),
            current_failure_domain,
            target_endpoint: target.endpoint.clone(),
            target_node_id: target.node_id.clone(),
            target_failure_domain: target.failure_domain.clone(),
            reason: reason.to_string(),
        });
    }

    Ok(CelluleRebalancePlanOutput {
        cellule_id: args.cellule_id,
        manifest_cid: record.manifest_cid,
        sequence: record.sequence,
        total_shards: manifest.erasure_policy.total_shards(),
        proposed_moves: moves.len(),
        current_failure_domains: current_failure_domains.len(),
        target_failure_domains: target_failure_domains.len(),
        moves,
    })
}

pub(super) async fn cellule_rebalance(
    args: CelluleRebalanceArgs,
) -> Result<CelluleRebalanceOutput> {
    fs::create_dir_all(&args.work_dir)
        .with_context(|| format!("failed to create {}", args.work_dir.display()))?;

    let plan = cellule_rebalance_plan(CelluleRebalancePlanArgs {
        nodes: args.nodes.clone(),
        cellule_id: args.cellule_id.clone(),
        registry: args.registry.clone(),
        blob_store: args.blob_store.clone(),
        private_key: args.private_key.clone(),
        cellule_key: args.cellule_key.clone(),
        placement_policy_file: args.placement_policy_file.clone(),
    })
    .await?;
    let planned_moves = plan.moves.len();

    let get_args = CelluleGetArgs {
        nodes: args.nodes.clone(),
        cellule_id: args.cellule_id.clone(),
        registry: args.registry.clone(),
        blob_store: args.blob_store.clone(),
        private_key: args.private_key.clone(),
        cellule_key: args.cellule_key.clone(),
    };
    let (record, mut manifest) = resolve_manifest(&get_args)?;
    if record.manifest_cid != plan.manifest_cid {
        bail!("Cellule record changed while planning rebalance");
    }

    if plan.moves.is_empty() {
        return Ok(CelluleRebalanceOutput {
            cellule_id: args.cellule_id,
            old_manifest_cid: record.manifest_cid.clone(),
            new_manifest_cid: record.manifest_cid,
            planned_moves,
            moved_shards: 0,
            delete_failures: 0,
            sequence: record.sequence,
            moves: Vec::new(),
            manifest_path: None,
            encrypted_manifest_path: None,
            record_path: None,
        });
    }

    let client = network_client()?;
    let mut moved = Vec::with_capacity(plan.moves.len());
    for rebalance_move in &plan.moves {
        let descriptor = manifest
            .shards
            .iter()
            .find(|descriptor| {
                descriptor.segment_index == rebalance_move.segment_index
                    && descriptor.shard_index == rebalance_move.shard_index
            })
            .context("manifest missing (segment, shard) entry")?;
        let (from_endpoint, bytes) = fetch_shard_from_hints(
            &client,
            &descriptor.shard_id,
            &descriptor.provider_hints,
            Some(args.private_key.as_str()),
        )
        .await?;
        if from_endpoint == rebalance_move.target_endpoint {
            continue;
        }
        let receipt = upload_shard_to_endpoint(
            &client,
            &rebalance_move.target_endpoint,
            &descriptor.shard_id,
            &bytes,
            &args.private_key,
            &record.expires_at.to_rfc3339(),
        )
        .await?;
        verify_remote_shard(
            &client,
            &rebalance_move.target_endpoint,
            &descriptor.shard_id,
        )
        .await?;
        moved.push(ShardRebalanceMoveResult {
            segment_index: descriptor.segment_index,
            shard_index: descriptor.shard_index,
            shard_id: descriptor.shard_id.clone(),
            from_endpoint,
            to_endpoint: rebalance_move.target_endpoint.clone(),
            receipt,
            old_deleted: false,
            delete_error: None,
        });
    }

    if moved.is_empty() {
        return Ok(CelluleRebalanceOutput {
            cellule_id: args.cellule_id,
            old_manifest_cid: record.manifest_cid.clone(),
            new_manifest_cid: record.manifest_cid,
            planned_moves,
            moved_shards: 0,
            delete_failures: 0,
            sequence: record.sequence,
            moves: moved,
            manifest_path: None,
            encrypted_manifest_path: None,
            record_path: None,
        });
    }

    for move_result in &moved {
        let descriptor = manifest
            .shards
            .iter_mut()
            .find(|descriptor| {
                descriptor.segment_index == move_result.segment_index
                    && descriptor.shard_index == move_result.shard_index
            })
            .context("manifest missing moved (segment, shard) entry")?;
        descriptor.provider_hints = vec![move_result.to_endpoint.clone()];
    }

    manifest.manifest_id = uuid::Uuid::new_v4();
    manifest.created_at = chrono::Utc::now();
    manifest.signature = None;
    let signing_key = signing_key_from_hex(&args.private_key)?;
    let manifest_payload =
        serde_json::to_vec(&manifest).context("failed to serialize manifest for signing")?;
    manifest.signature = Some(confidis_crypto::sign_hex(&signing_key, &manifest_payload));

    let manifest_path = args.work_dir.join("rebalance-manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;

    let cellule_key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;
    let manifest_plaintext = fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let encrypted_manifest =
        confidis_crypto::encrypt_with_cellule_key(&cellule_key, &manifest_plaintext)?;
    let encrypted_manifest_path = args.work_dir.join("rebalance-manifest.enc");
    fs::write(&encrypted_manifest_path, &encrypted_manifest)
        .with_context(|| format!("failed to write {}", encrypted_manifest_path.display()))?;
    let new_manifest_cid = confidis_crypto::blake3_hex(&encrypted_manifest);
    write_blob(&args.blob_store, &new_manifest_cid, &encrypted_manifest)?;

    let sequence = record.sequence + 1;
    let new_record = create_cellule_record(
        record.cellule_public_key,
        &args.private_key,
        new_manifest_cid.clone(),
        &record.expires_at.to_rfc3339(),
        sequence,
    )?;
    let record_path = args.work_dir.join("rebalance-cellule-record.json");
    fs::write(&record_path, serde_json::to_vec_pretty(&new_record)?)
        .with_context(|| format!("failed to write {}", record_path.display()))?;
    publish_record(&args.registry, new_record)?;

    let mut delete_failures = 0usize;
    for move_result in &mut moved {
        let request = create_delete_request(move_result.shard_id.clone(), &args.private_key)?;
        let url = format!(
            "{}/shards/{}",
            move_result.from_endpoint.trim_end_matches('/'),
            move_result.shard_id.0
        );
        match client.delete(url).json(&request).send().await {
            Ok(response) if response.status().is_success() => {
                move_result.old_deleted = true;
            }
            Ok(response) => {
                delete_failures += 1;
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                move_result.delete_error = Some(format!("{status} {text}"));
            }
            Err(err) => {
                delete_failures += 1;
                move_result.delete_error = Some(err.to_string());
            }
        }
    }

    Ok(CelluleRebalanceOutput {
        cellule_id: args.cellule_id,
        old_manifest_cid: record.manifest_cid,
        new_manifest_cid,
        planned_moves,
        moved_shards: moved.len(),
        delete_failures,
        sequence,
        moves: moved,
        manifest_path: Some(manifest_path.to_string_lossy().to_string()),
        encrypted_manifest_path: Some(encrypted_manifest_path.to_string_lossy().to_string()),
        record_path: Some(record_path.to_string_lossy().to_string()),
    })
}

async fn cellule_rebalance_scan(
    args: CelluleRebalanceScanArgs,
) -> Result<CelluleRebalanceScanOutput> {
    if args.nodes.is_empty() {
        bail!("at least one --node is required");
    }

    fs::create_dir_all(&args.work_dir)
        .with_context(|| format!("failed to create {}", args.work_dir.display()))?;

    let records = read_registry(&args.registry)?;
    let mut output = CelluleRebalanceScanOutput {
        scanned: records.len(),
        rebalanced: 0,
        unchanged: 0,
        failed: 0,
        results: Vec::with_capacity(records.len()),
    };

    for record in records {
        let cellule_id = record.cellule_id.0.clone();
        if let Err(err) = verify_cellule_record(&record) {
            output.failed += 1;
            output.results.push(CelluleRebalanceScanResult {
                cellule_id,
                status: "failed".to_string(),
                rebalance: None,
                error: Some(err.to_string()),
            });
            continue;
        }

        let rebalance_work_dir = args.work_dir.join(safe_path_segment(&cellule_id));
        match cellule_rebalance(CelluleRebalanceArgs {
            nodes: args.nodes.clone(),
            cellule_id: cellule_id.clone(),
            work_dir: rebalance_work_dir,
            registry: args.registry.clone(),
            blob_store: args.blob_store.clone(),
            private_key: args.private_key.clone(),
            cellule_key: args.cellule_key.clone(),
            placement_policy_file: args.placement_policy_file.clone(),
        })
        .await
        {
            Ok(rebalance) => {
                if rebalance.moved_shards > 0 {
                    output.rebalanced += 1;
                    output.results.push(CelluleRebalanceScanResult {
                        cellule_id,
                        status: "rebalanced".to_string(),
                        rebalance: Some(rebalance),
                        error: None,
                    });
                } else {
                    output.unchanged += 1;
                    output.results.push(CelluleRebalanceScanResult {
                        cellule_id,
                        status: "unchanged".to_string(),
                        rebalance: Some(rebalance),
                        error: None,
                    });
                }
            }
            Err(err) => {
                output.failed += 1;
                output.results.push(CelluleRebalanceScanResult {
                    cellule_id,
                    status: "failed".to_string(),
                    rebalance: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    Ok(output)
}

pub(super) async fn cellule_rebalance_watch(
    args: CelluleRebalanceWatchArgs,
) -> Result<CelluleRebalanceWatchOutput> {
    if args.interval_seconds == 0 {
        bail!("--interval-seconds must be greater than zero");
    }

    let mut output = CelluleRebalanceWatchOutput {
        interval_seconds: args.interval_seconds,
        max_runs: args.max_runs,
        runs_completed: 0,
        last_run: None,
        history: Vec::new(),
    };

    loop {
        let run_dir = args
            .scan
            .work_dir
            .join(format!("run-{:06}", output.runs_completed + 1));
        let scan = cellule_rebalance_scan(CelluleRebalanceScanArgs {
            work_dir: run_dir,
            ..args.scan.clone()
        })
        .await?;

        output.runs_completed += 1;
        output.last_run = Some(scan);
        if let Some(last_run) = &output.last_run {
            output.history.push(CelluleRebalanceScanSummary {
                scanned: last_run.scanned,
                rebalanced: last_run.rebalanced,
                unchanged: last_run.unchanged,
                failed: last_run.failed,
            });
        }

        fs::write(&args.output, serde_json::to_vec_pretty(&output)?)
            .with_context(|| format!("failed to write {}", args.output.display()))?;
        println!("{}", serde_json::to_string_pretty(&output)?);

        if args
            .max_runs
            .is_some_and(|max_runs| output.runs_completed >= max_runs)
        {
            break;
        }

        tokio::time::sleep(Duration::from_secs(args.interval_seconds)).await;
    }

    Ok(output)
}
