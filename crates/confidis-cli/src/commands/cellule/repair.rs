use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use confidis_crypto::signing_key_from_hex;
use confidis_erasure::{encode_segment, reconstruct_segment};
use confidis_placement::build_placement_plan;
use confidis_protocol::{PlacementPolicy, ShardId};

use crate::commands::blob::write_blob;
use crate::commands::placement::upload_repair_shards;
use crate::network::{fetch_candidates, network_client};

use super::availability::{
    cellule_availability, summarize_availability, summarize_availability_output,
};
use super::helpers::{
    create_cellule_record, publish_record, read_registry, read_sealed_cellule_key,
    resolve_manifest, safe_path_segment, verify_cellule_record_signature,
};
use super::types::{
    CelluleGetArgs, CelluleRepairArgs, CelluleRepairOutput, CelluleRepairScanArgs,
    CelluleRepairScanOutput, CelluleRepairScanResult, CelluleRepairScanSummary,
    CelluleRepairWatchArgs, CelluleRepairWatchOutput,
};

pub(super) async fn cellule_repair(args: CelluleRepairArgs) -> Result<CelluleRepairOutput> {
    if args.nodes.is_empty() {
        bail!("at least one --node is required");
    }

    fs::create_dir_all(&args.work_dir)
        .with_context(|| format!("failed to create {}", args.work_dir.display()))?;

    let get_args = CelluleGetArgs {
        nodes: args.nodes.clone(),
        cellule_id: args.cellule_id.clone(),
        registry: args.registry.clone(),
        blob_store: args.blob_store.clone(),
        private_key: args.private_key.clone(),
        cellule_key: args.cellule_key.clone(),
    };
    let (record, mut manifest) = resolve_manifest(&get_args)?;
    let now = chrono::Utc::now();
    if record.deletion_due_at(now) {
        bail!(
            "Cellule expired at {}; repair is closed and deletion is due",
            record.expires_at.to_rfc3339()
        );
    }
    // Per-segment repair. Each streaming segment is an independent
    // Reed–Solomon group; shards are identified by `(segment_index,
    // shard_index)`. Single-segment Cellules iterate exactly once.
    let client = network_client()?;
    let candidates = fetch_candidates(&client, &args.nodes).await?;
    let policy = manifest.erasure_policy.clone();
    let total = policy.total_shards();
    let segment_count = manifest
        .shards
        .iter()
        .map(|d| d.segment_index)
        .max()
        .map(|m| m + 1)
        .unwrap_or(1);

    let mut total_available = 0usize;
    let mut repaired_shards: Vec<usize> = Vec::new();
    let mut receipt_count = 0usize;
    let mut any_missing = false;

    for si in 0..segment_count {
        // Scope the immutable borrow of `manifest.shards` so we can mutate
        // descriptors for this segment afterwards.
        let fetched = {
            let seg_desc: Vec<_> = manifest
                .shards
                .iter()
                .filter(|d| d.segment_index == si)
                .collect();
            super::get::fetch_segment_shards(
                &client,
                &seg_desc,
                total,
                Some(args.private_key.as_str()),
                &args.nodes,
            )
            .await?
        };
        let avail = fetched.iter().filter(|s| s.is_some()).count();
        total_available += avail;
        if avail < policy.data_shards {
            bail!(
                "segment {si}: not enough valid shards to repair: fetched {avail}, need {}",
                policy.data_shards
            );
        }
        let missing: Vec<usize> = fetched
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.is_none().then_some(i))
            .collect();
        if missing.is_empty() {
            continue;
        }
        any_missing = true;

        let seg_len = confidis_protocol::segment_original_len(
            manifest.original_size_bytes,
            manifest.segment_size_bytes,
            si,
        ) as usize;
        let restored = reconstruct_segment(&policy, seg_len, fetched)?;
        let encoded = encode_segment(&restored, &policy)?;
        let shard_ids: Vec<ShardId> = encoded
            .shards
            .iter()
            .map(|bytes| ShardId(confidis_crypto::blake3_hex(bytes)))
            .collect();
        let plan = build_placement_plan(
            format!("{}-s{si}", manifest.group_id),
            policy.clone(),
            &shard_ids,
            &candidates,
            &PlacementPolicy::default(),
        )?;
        let receipts = upload_repair_shards(
            &client,
            &plan,
            &encoded.shards,
            &missing,
            &args.private_key,
            &record.expires_at.to_rfc3339(),
        )
        .await?;
        receipt_count += receipts.len();

        for index in &missing {
            let placement = plan
                .placements
                .iter()
                .find(|placement| placement.shard_index == *index)
                .context("repair placement missing shard index")?;
            let descriptor = manifest
                .shards
                .iter_mut()
                .find(|d| d.segment_index == si && d.shard_index == *index)
                .context("manifest missing (segment, shard) entry")?;
            descriptor.shard_id = placement.shard_id.clone();
            descriptor.size_bytes = encoded.shards[*index].len() as u64;
            descriptor.provider_hints = vec![placement.endpoint.clone()];
            repaired_shards.push(*index);
        }
    }

    let before = summarize_availability(
        total_available,
        total * segment_count as usize,
        policy.data_shards * segment_count as usize,
    );
    if !any_missing {
        return Ok(CelluleRepairOutput {
            cellule_id: args.cellule_id,
            old_manifest_cid: record.manifest_cid.clone(),
            new_manifest_cid: record.manifest_cid,
            status: "healthy".to_string(),
            repaired_shards: Vec::new(),
            before: before.clone(),
            after: before,
            receipt_count: 0,
            sequence: record.sequence,
            manifest_path: None,
            encrypted_manifest_path: None,
            record_path: None,
        });
    }

    manifest.manifest_id = uuid::Uuid::new_v4();
    manifest.created_at = chrono::Utc::now();
    manifest.signature = None;
    let signing_key = signing_key_from_hex(&args.private_key)?;
    let manifest_payload =
        serde_json::to_vec(&manifest).context("failed to serialize manifest for signing")?;
    manifest.signature = Some(confidis_crypto::sign_hex(&signing_key, &manifest_payload));

    let manifest_path = args.work_dir.join("repair-manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("failed to write {}", manifest_path.display()))?;

    let cellule_key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;
    let manifest_plaintext = fs::read(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let encrypted_manifest =
        confidis_crypto::encrypt_with_cellule_key(&cellule_key, &manifest_plaintext)?;
    let encrypted_manifest_path = args.work_dir.join("repair-manifest.enc");
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
    let record_path = args.work_dir.join("repair-cellule-record.json");
    fs::write(&record_path, serde_json::to_vec_pretty(&new_record)?)
        .with_context(|| format!("failed to write {}", record_path.display()))?;
    publish_record(&args.registry, new_record)?;

    let after = summarize_availability_output(
        &cellule_availability(CelluleGetArgs {
            nodes: args.nodes.clone(),
            cellule_id: args.cellule_id.clone(),
            registry: args.registry.clone(),
            blob_store: args.blob_store.clone(),
            private_key: args.private_key.clone(),
            cellule_key: args.cellule_key.clone(),
        })
        .await?,
    );

    Ok(CelluleRepairOutput {
        cellule_id: args.cellule_id,
        old_manifest_cid: record.manifest_cid,
        new_manifest_cid,
        status: "repaired".to_string(),
        repaired_shards,
        before,
        after,
        receipt_count,
        sequence,
        manifest_path: Some(manifest_path.to_string_lossy().to_string()),
        encrypted_manifest_path: Some(encrypted_manifest_path.to_string_lossy().to_string()),
        record_path: Some(record_path.to_string_lossy().to_string()),
    })
}

pub(super) async fn cellule_repair_scan(
    args: CelluleRepairScanArgs,
) -> Result<CelluleRepairScanOutput> {
    if args.nodes.is_empty() {
        bail!("at least one --node is required");
    }

    fs::create_dir_all(&args.work_dir)
        .with_context(|| format!("failed to create {}", args.work_dir.display()))?;

    let records = read_registry(&args.registry)?;
    let mut output = CelluleRepairScanOutput {
        scanned: records.len(),
        repaired: 0,
        healthy: 0,
        expired: 0,
        unrecoverable: 0,
        failed: 0,
        results: Vec::with_capacity(records.len()),
    };
    let now = chrono::Utc::now();

    for record in records {
        let cellule_id = record.cellule_id.0.clone();
        if let Err(err) = verify_cellule_record_signature(&record) {
            output.failed += 1;
            output.results.push(CelluleRepairScanResult {
                cellule_id,
                status: "failed".to_string(),
                availability: None,
                repair: None,
                error: Some(err.to_string()),
            });
            continue;
        }

        if record.deletion_due_at(now) {
            output.expired += 1;
            output.results.push(CelluleRepairScanResult {
                cellule_id,
                status: "expired".to_string(),
                availability: None,
                repair: None,
                error: None,
            });
            continue;
        }

        let availability = match cellule_availability(CelluleGetArgs {
            nodes: args.nodes.clone(),
            cellule_id: cellule_id.clone(),
            registry: args.registry.clone(),
            blob_store: args.blob_store.clone(),
            private_key: args.private_key.clone(),
            cellule_key: args.cellule_key.clone(),
        })
        .await
        {
            Ok(availability) => availability,
            Err(err) => {
                output.failed += 1;
                output.results.push(CelluleRepairScanResult {
                    cellule_id,
                    status: "failed".to_string(),
                    availability: None,
                    repair: None,
                    error: Some(err.to_string()),
                });
                continue;
            }
        };

        let availability_summary = summarize_availability_output(&availability);
        if !availability.repair_needed {
            output.healthy += 1;
            output.results.push(CelluleRepairScanResult {
                cellule_id,
                status: "healthy".to_string(),
                availability: Some(availability_summary),
                repair: None,
                error: None,
            });
            continue;
        }

        if !availability.restore_possible {
            output.unrecoverable += 1;
            output.results.push(CelluleRepairScanResult {
                cellule_id,
                status: "unrecoverable".to_string(),
                availability: Some(availability_summary),
                repair: None,
                error: None,
            });
            continue;
        }

        let repair_work_dir = args.work_dir.join(safe_path_segment(&cellule_id));
        match cellule_repair(CelluleRepairArgs {
            nodes: args.nodes.clone(),
            cellule_id: cellule_id.clone(),
            work_dir: repair_work_dir,
            registry: args.registry.clone(),
            blob_store: args.blob_store.clone(),
            private_key: args.private_key.clone(),
            cellule_key: args.cellule_key.clone(),
        })
        .await
        {
            Ok(repair) => {
                if repair.status == "repaired" {
                    output.repaired += 1;
                } else {
                    output.healthy += 1;
                }
                output.results.push(CelluleRepairScanResult {
                    cellule_id,
                    status: repair.status.clone(),
                    availability: Some(availability_summary),
                    repair: Some(repair),
                    error: None,
                });
            }
            Err(err) => {
                output.failed += 1;
                output.results.push(CelluleRepairScanResult {
                    cellule_id,
                    status: "failed".to_string(),
                    availability: Some(availability_summary),
                    repair: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    Ok(output)
}

pub(super) async fn cellule_repair_watch(
    args: CelluleRepairWatchArgs,
) -> Result<CelluleRepairWatchOutput> {
    if args.interval_seconds == 0 {
        bail!("--interval-seconds must be greater than zero");
    }

    let mut output = CelluleRepairWatchOutput {
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
        let scan = cellule_repair_scan(CelluleRepairScanArgs {
            work_dir: run_dir,
            ..args.scan.clone()
        })
        .await?;

        output.runs_completed += 1;
        output.last_run = Some(scan);
        if let Some(last_run) = &output.last_run {
            output.history.push(CelluleRepairScanSummary {
                scanned: last_run.scanned,
                repaired: last_run.repaired,
                healthy: last_run.healthy,
                expired: last_run.expired,
                unrecoverable: last_run.unrecoverable,
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
