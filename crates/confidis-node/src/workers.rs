use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use confidis_crypto::{sign_hex, verifying_key_to_hex};
use confidis_protocol::{
    CellulePublicRecord, NodeBanList, NodeCapacityReport, NodeUptimeRecord, PeerList, PeerRecord,
    ShardProviderRecord, ShardReceipt, uptime_record_signing_payload, verify_cellule_public_record,
    verify_node_ban_list, verify_shard_provider_record, verify_uptime_record,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::maintenance_status_store::persist_maintenance_status;
use crate::retry::with_retry;
use crate::signing::sign_peer_record;
use crate::state::{MAX_ROUTING_TABLE_SIZE, MaintenanceJobStatus, NodeState, PeerCircuit};
use crate::storage_backend::run_storage_task;
use crate::util::normalize_endpoint;

async fn wait_interval_or_shutdown(
    interval: &mut tokio::time::Interval,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = interval.tick() => true,
        res = shutdown_rx.changed() => {
            if res.is_ok() {
                tracing::info!("worker shutdown requested");
            }
            false
        }
    }
}

/// Record that a maintenance job is starting.
pub(crate) async fn record_maintenance_start(
    state: &Arc<NodeState>,
    job_id: &str,
    label: &str,
    detail: Option<String>,
) {
    let snapshot = {
        let mut jobs = state.maintenance_jobs.write().await;
        let job = jobs
            .entry(job_id.to_string())
            .or_insert_with(|| MaintenanceJobStatus::new(job_id, label));
        job.label = label.to_string();
        job.status = "running".to_string();
        job.last_started_at = Some(Utc::now());
        job.detail = detail;
        jobs.values().cloned().collect::<Vec<_>>()
    };
    persist_maintenance_status(&state.config.store_path, snapshot).await;
}

pub(crate) async fn record_maintenance_success(
    state: &Arc<NodeState>,
    job_id: &str,
    label: &str,
    detail: Option<String>,
) {
    let now = Utc::now();
    let snapshot = {
        let mut jobs = state.maintenance_jobs.write().await;
        let job = jobs
            .entry(job_id.to_string())
            .or_insert_with(|| MaintenanceJobStatus::new(job_id, label));
        job.label = label.to_string();
        job.status = "ok".to_string();
        job.last_duration_ms = job
            .last_started_at
            .map(|started| (now - started).num_milliseconds().max(0) as u64);
        job.last_finished_at = Some(now);
        job.last_error = None;
        job.runs = job.runs.saturating_add(1);
        job.attention = false;
        job.detail = detail;
        jobs.values().cloned().collect::<Vec<_>>()
    };
    persist_maintenance_status(&state.config.store_path, snapshot).await;
}

pub(crate) async fn record_maintenance_attention(
    state: &Arc<NodeState>,
    job_id: &str,
    label: &str,
    error: String,
    detail: Option<String>,
) {
    let now = Utc::now();
    let snapshot = {
        let mut jobs = state.maintenance_jobs.write().await;
        let job = jobs
            .entry(job_id.to_string())
            .or_insert_with(|| MaintenanceJobStatus::new(job_id, label));
        job.label = label.to_string();
        job.status = "attention".to_string();
        job.last_duration_ms = job
            .last_started_at
            .map(|started| (now - started).num_milliseconds().max(0) as u64);
        job.last_finished_at = Some(now);
        job.last_error = Some(error);
        job.runs = job.runs.saturating_add(1);
        job.error_runs = job.error_runs.saturating_add(1);
        job.attention = true;
        job.detail = detail;
        jobs.values().cloned().collect::<Vec<_>>()
    };
    persist_maintenance_status(&state.config.store_path, snapshot).await;
}

pub(crate) fn start_expiry_worker(state: Arc<NodeState>, mut shutdown_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        // Allow tests to set a shorter interval via environment variable.
        let interval_secs = std::env::var("CONFIDIS_EXPIRY_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // Retry queue: (shard_id_hex, attempt_count, earliest_retry_time)
        let mut retry_queue: Vec<(String, u32, std::time::Instant)> = Vec::new();

        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "expiry", "Retention expiry", None).await;
            let now = Utc::now();
            let wall = std::time::Instant::now();
            let mut deleted_expired = 0usize;
            let mut expiring_soon_count = 0usize;
            let mut attention_error: Option<String> = None;

            // ── Retry previously-failed deletions ─────────────────────────────
            let due: Vec<_> = retry_queue
                .iter()
                .enumerate()
                .filter(|(_, (_, _, earliest))| wall >= *earliest)
                .map(|(i, _)| i)
                .collect();
            // Drain in reverse so indices stay valid.
            for i in due.into_iter().rev() {
                let (shard_hex, attempt, _) = retry_queue.remove(i);
                let shard_id = confidis_protocol::ShardId(shard_hex.clone());
                let node_id = state.config.node_id.clone();
                let signing_key = state.config.signing_key.clone();
                match run_storage_task(&state, move |store| {
                    store.delete_unchecked(node_id, &shard_id, signing_key.as_ref(), true)
                })
                .await
                {
                    Ok(_) => {
                        tracing::info!(
                            shard_id = %shard_hex,
                            attempt,
                            "expiry-worker: retry deletion succeeded"
                        );
                    }
                    Err(err) if attempt < 5 => {
                        // Exponential back-off: 2^attempt minutes, capped at ~32 min.
                        let backoff = Duration::from_secs(60 * (1u64 << attempt.min(5)));
                        tracing::warn!(
                            shard_id = %shard_hex,
                            attempt,
                            backoff_secs = backoff.as_secs(),
                            error = %err,
                            "expiry-worker: deletion failed, scheduling retry"
                        );
                        retry_queue.push((shard_hex, attempt + 1, wall + backoff));
                    }
                    Err(err) => {
                        tracing::error!(
                            shard_id = %shard_hex,
                            attempt,
                            error = %err,
                            "expiry-worker: deletion failed after max retries — manual cleanup required"
                        );
                        attention_error = Some(format!(
                            "expired shard {shard_hex} could not be deleted after retries: {err}"
                        ));
                    }
                }
            }

            // ── Delete shards that have just expired ──────────────────────────
            let node_id = state.config.node_id.clone();
            let signing_key = state.config.signing_key.clone();
            match run_storage_task(&state, move |store| {
                store.delete_expired(node_id, now, signing_key.as_ref())
            })
            .await
            {
                Ok(receipts) if !receipts.is_empty() => {
                    deleted_expired = receipts.len();
                    tracing::info!(
                        count = receipts.len(),
                        "expiry-worker: deleted expired shard(s)"
                    );
                }
                Err(err) => {
                    // Collect the affected shard IDs from metadata for retry.
                    tracing::error!(error = %err, "expiry-worker: batch deletion failed — queuing individual retries");
                    attention_error = Some(format!("batch deletion failed: {err}"));
                    if let Ok(expired_shards) = run_storage_task(&state, move |store| {
                        let mut expired_shards = Vec::new();
                        for metadata in store.read_all_metadata()? {
                            let Some(expires_at) = metadata.expires_at else {
                                continue;
                            };
                            if now >= expires_at && store.exists(&metadata.shard_id)? {
                                expired_shards.push(metadata.shard_id);
                            }
                        }
                        Ok(expired_shards)
                    })
                    .await
                    {
                        for shard_id in expired_shards {
                            let already_queued =
                                retry_queue.iter().any(|(id, _, _)| id == &shard_id.0);
                            if !already_queued {
                                retry_queue.push((
                                    shard_id.0.clone(),
                                    0,
                                    wall + Duration::from_secs(60),
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }

            // ── Warn about shards expiring within the next 30 days ────────────
            if let Ok(soon) = run_storage_task(&state, move |store| {
                store.expiring_soon(now, chrono::Duration::days(30))
            })
            .await
            {
                expiring_soon_count = soon.len();
                for (shard_id, expires_at) in soon {
                    let days_left = (expires_at - now).num_days();
                    tracing::warn!(
                        shard_id = %shard_id.0,
                        expires_at = %expires_at,
                        days_left,
                        "expiry-worker: shard expiring soon — consider renewing the Cellule",
                    );
                }
            }
            let detail = Some(format!(
                "deleted {deleted_expired} expired shard(s), {expiring_soon_count} expiring within 30 days, {} retry item(s)",
                retry_queue.len()
            ));
            if let Some(error) = attention_error {
                record_maintenance_attention(&state, "expiry", "Retention expiry", error, detail)
                    .await;
            } else {
                record_maintenance_success(&state, "expiry", "Retention expiry", detail).await;
            }
        }
    });
}

pub(crate) fn start_integrity_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "integrity", "Shard integrity", None).await;
            let node_id = state.config.node_id.clone();
            let signing_key = state.config.signing_key.clone();
            if let Err(err) = run_storage_task(&state, move |store| {
                store.check_integrity(node_id, Utc::now(), signing_key.as_ref())
            })
            .await
            {
                tracing::error!(error = %err, "integrity worker failed");
                record_maintenance_attention(
                    &state,
                    "integrity",
                    "Shard integrity",
                    err.to_string(),
                    Some("local shard verification failed".to_string()),
                )
                .await;
            } else {
                record_maintenance_success(
                    &state,
                    "integrity",
                    "Shard integrity",
                    Some("local shard metadata verified".to_string()),
                )
                .await;
            }
        }
    });
}

pub(crate) fn start_audit_worker(state: Arc<NodeState>, mut shutdown_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        let interval_secs = std::env::var("CONFIDIS_AUDIT_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(3600);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "audit", "Signed audit export", None).await;
            match write_audit_export(&state).await {
                Ok(summary) => {
                    record_maintenance_success(
                        &state,
                        "audit",
                        "Signed audit export",
                        Some(summary),
                    )
                    .await;
                }
                Err(err) => {
                    tracing::error!(error = %err, "audit worker failed");
                    record_maintenance_attention(
                        &state,
                        "audit",
                        "Signed audit export",
                        err.to_string(),
                        Some("signed audit snapshot could not be written".to_string()),
                    )
                    .await;
                }
            }
        }
    });
}

async fn write_audit_export(state: &Arc<NodeState>) -> anyhow::Result<String> {
    let now = Utc::now();
    let (stats, receipts) = run_storage_task(state, |store| {
        Ok((store.stats()?, store.read_all_receipts()?))
    })
    .await?;
    let free_bytes = state.config.max_bytes.saturating_sub(stats.used_bytes);
    let health_score = if state.config.max_bytes == 0 {
        0.0
    } else {
        free_bytes as f32 / state.config.max_bytes as f32
    };
    let capacity = NodeCapacityReport {
        node_id: state.config.node_id.clone(),
        public_key: state
            .config
            .signing_key
            .as_ref()
            .map(|key| verifying_key_to_hex(&key.verifying_key())),
        free_bytes,
        used_bytes: stats.used_bytes,
        max_bytes: state.config.max_bytes,
        reserved_bytes: 0,
        region: state.config.region.clone(),
        failure_domain: state.config.failure_domain.clone(),
        health_score,
        current_shard_count: stats.shard_count,
        issued_at: now,
        signature: None,
    };
    let deletion_receipts = receipts
        .iter()
        .filter(|receipt| receipt.receipt_type == confidis_protocol::ShardReceiptType::Deleted)
        .count();
    let recent_receipts = receipts.iter().take(100).cloned().collect::<Vec<_>>();
    let maintenance_jobs = state
        .maintenance_jobs
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let authority = {
        let ban_list = state.node_ban_list.read().await;
        AuditAuthorityStatus {
            trust_root_source: state.config.confidis_root_source.clone(),
            ban_list_present: ban_list.is_some(),
            ban_list_issued_at: ban_list.as_ref().map(|list| list.issued_at),
            ban_list_expires_at: ban_list.as_ref().map(|list| list.expires_at),
            banned_node_count: ban_list.as_ref().map(|list| list.banned_nodes.len()),
        }
    };
    let routing_peer_count = state.routing_table.read().await.len();
    let uptime_peer_count = state.uptime_table.read().await.len();
    let security_event_count = count_security_events(&state.config.store_path).await;

    let mut export = AuditExport {
        version: 1,
        export_id: uuid::Uuid::new_v4(),
        node_id: state.config.node_id.0.clone(),
        issued_at: now,
        capacity,
        authority,
        routing_peer_count,
        uptime_peer_count,
        security_event_count,
        receipt_count: receipts.len(),
        deletion_receipt_count: deletion_receipts,
        recent_receipts,
        maintenance_jobs,
        public_key: None,
        signature: None,
    };
    if let Some(signing_key) = &state.config.signing_key {
        export.public_key = Some(verifying_key_to_hex(&signing_key.verifying_key()));
        let payload = audit_export_signing_payload(&export)?;
        export.signature = Some(sign_hex(signing_key, &payload));
    }

    let audit_dir = state.config.store_path.join("maintenance").join("audit");
    tokio::fs::create_dir_all(&audit_dir).await?;
    let timestamp = now.format("%Y%m%dT%H%M%SZ");
    let path = audit_dir.join(format!("audit-{timestamp}-{}.json", export.export_id));
    write_json_atomic(&path, &export).await?;
    write_json_atomic(&audit_dir.join("latest.json"), &export).await?;

    Ok(format!(
        "wrote signed audit snapshot with {} receipt(s), {} deletion receipt(s), {} maintenance job(s)",
        export.receipt_count,
        export.deletion_receipt_count,
        export.maintenance_jobs.len()
    ))
}

async fn write_json_atomic<T: Serialize>(path: &std::path::Path, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp_path = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(value)?;
    tokio::fs::write(&tmp_path, bytes).await?;
    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}

fn audit_export_signing_payload(export: &AuditExport) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = export.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned)
}

async fn count_security_events(store_path: &std::path::Path) -> usize {
    let path = store_path.join("security").join("events.jsonl");
    let Ok(body) = tokio::fs::read_to_string(path).await else {
        return 0;
    };
    body.lines().filter(|line| !line.trim().is_empty()).count()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditAuthorityStatus {
    trust_root_source: String,
    ban_list_present: bool,
    ban_list_issued_at: Option<chrono::DateTime<Utc>>,
    ban_list_expires_at: Option<chrono::DateTime<Utc>>,
    banned_node_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditExport {
    version: u16,
    export_id: uuid::Uuid,
    node_id: String,
    issued_at: chrono::DateTime<Utc>,
    capacity: NodeCapacityReport,
    authority: AuditAuthorityStatus,
    routing_peer_count: usize,
    uptime_peer_count: usize,
    security_event_count: usize,
    receipt_count: usize,
    deletion_receipt_count: usize,
    recent_receipts: Vec<ShardReceipt>,
    maintenance_jobs: Vec<MaintenanceJobStatus>,
    public_key: Option<String>,
    signature: Option<String>,
}

pub(crate) fn start_discovery_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "discovery", "Peer discovery", None).await;

            let our_record = build_self_peer_record(&state).await;

            let endpoints: Vec<String> = {
                let table = state.routing_table.read().await;
                table.keys().cloned().collect()
            };

            for endpoint in &endpoints {
                // Circuit breaker: skip peers that are in the open state.
                {
                    let circuit = state.peer_circuit.read().await;
                    if let Some(cb) = circuit.get(endpoint)
                        && cb.is_open()
                    {
                        tracing::debug!(
                            endpoint,
                            failures = cb.consecutive_failures,
                            "circuit open — skipping peer this cycle"
                        );
                        continue;
                    }
                }

                let mut peer_ok = false;

                // Announce our own record to the peer.
                if let Some(record) = &our_record {
                    let ep = endpoint.clone();
                    let record = record.clone();
                    let client = client.clone();
                    let _ = with_retry("announce_peer", 2, Duration::from_millis(200), || {
                        let ep = ep.clone();
                        let record = record.clone();
                        let client = client.clone();
                        async move {
                            client
                                .put(format!("{ep}/peers/announce"))
                                .json(&record)
                                .send()
                                .await
                        }
                    })
                    .await;
                }

                // Fetch and merge the peer's routing table.
                let result = with_retry("fetch_peers", 2, Duration::from_millis(300), || {
                    let client = client.clone();
                    let ep = endpoint.clone();
                    async move {
                        client
                            .get(format!("{ep}/peers"))
                            .send()
                            .await?
                            .json::<PeerList>()
                            .await
                    }
                })
                .await;

                if let Some(peer_list) = result {
                    peer_ok = true;
                    let now = Utc::now();
                    let mut table = state.routing_table.write().await;
                    for peer in peer_list.peers {
                        if let Some(my_endpoint) = &state.config.public_endpoint
                            && normalize_endpoint(&peer.endpoint) == normalize_endpoint(my_endpoint)
                        {
                            continue;
                        }
                        if let Some(expires_at) = peer.expires_at
                            && now >= expires_at
                        {
                            continue;
                        }
                        let key = normalize_endpoint(&peer.endpoint);
                        if table.len() >= MAX_ROUTING_TABLE_SIZE && !table.contains_key(&key) {
                            continue;
                        }
                        table.insert(key, peer);
                    }
                }

                // Update circuit breaker state.
                {
                    let mut circuit = state.peer_circuit.write().await;
                    let cb = circuit.entry(endpoint.clone()).or_insert(PeerCircuit {
                        consecutive_failures: 0,
                        skip_until: None,
                    });
                    if peer_ok {
                        if cb.record_success() {
                            tracing::info!(endpoint, "circuit closed — peer recovered");
                        }
                        if cb.consecutive_failures == 0 {
                            circuit.remove(endpoint);
                        }
                    } else if let Some(backoff) = cb.record_failure() {
                        tracing::warn!(
                            endpoint,
                            failures = cb.consecutive_failures,
                            backoff_secs = backoff.as_secs(),
                            "circuit opened for peer after repeated failures"
                        );
                    }
                }
            }

            // Evict peers whose record has expired; keep bootstrap stubs (no expires_at)
            {
                let now = Utc::now();
                let mut table = state.routing_table.write().await;
                let before = table.len();
                table.retain(|_, record| record.expires_at.is_none_or(|exp| now < exp));
                let evicted = before - table.len();
                if evicted > 0 {
                    tracing::info!(evicted, "evicted stale peer(s) from routing table");
                }
            }
            let (peer_count, peer_snapshot) = {
                let table = state.routing_table.read().await;
                (table.len(), table.values().cloned().collect::<Vec<_>>())
            };
            match crate::peer_cache::persist_peer_cache(
                &state.config.store_path,
                peer_snapshot,
                state.config.public_endpoint.as_deref(),
            )
            .await
            {
                Ok(cached) => {
                    tracing::debug!(cached, "persisted signed peer cache");
                }
                Err(err) => {
                    tracing::warn!(error = %err, "failed to persist signed peer cache");
                }
            }
            record_maintenance_success(
                &state,
                "discovery",
                "Peer discovery",
                Some(format!("{peer_count} peer(s) in routing table")),
            )
            .await;
        }
    });
}

/// Loads and refreshes the CONFIDIS authority-signed node ban list.
///
/// The list is signed by the CONFIDIS authority root key; invalid downloads never
/// replace the last known-good in-memory list. Node participation is
/// permissionless — this list is only a reactive sanction surface.
pub(crate) fn start_node_ban_list_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("failed to build reqwest client");
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "node_ban_list", "CONFIDIS node ban list refresh", None)
                .await;

            let Some(root_key) = state.config.confidis_root_pubkey.as_ref() else {
                record_maintenance_attention(
                    &state,
                    "node_ban_list",
                    "CONFIDIS node ban list refresh",
                    "CONFIDIS authority root key is not configured".to_string(),
                    Some("node ban list signature cannot be verified".to_string()),
                )
                .await;
                continue;
            };

            if let Some(path) = state.config.node_ban_list_path.as_ref() {
                match tokio::fs::read_to_string(path)
                    .await
                    .ok()
                    .and_then(|body| serde_json::from_str::<NodeBanList>(&body).ok())
                {
                    Some(list) => {
                        if let Err(err) = verify_node_ban_list(&list, root_key, Utc::now()) {
                            record_maintenance_attention(
                                &state,
                                "node_ban_list",
                                "CONFIDIS node ban list refresh",
                                format!("local node ban list is invalid: {err}"),
                                Some(path.display().to_string()),
                            )
                            .await;
                        } else {
                            *state.node_ban_list.write().await = Some(list);
                        }
                    }
                    None => {
                        record_maintenance_attention(
                            &state,
                            "node_ban_list",
                            "CONFIDIS node ban list refresh",
                            "local node ban list is missing or invalid".to_string(),
                            Some(path.display().to_string()),
                        )
                        .await;
                    }
                }
            }

            let Some(feed_url) = state.config.node_ban_list_url.clone() else {
                let count = state
                    .node_ban_list
                    .read()
                    .await
                    .as_ref()
                    .map(|list| list.banned_nodes.len())
                    .unwrap_or(0);
                record_maintenance_success(
                    &state,
                    "node_ban_list",
                    "CONFIDIS node ban list refresh",
                    Some(format!(
                        "loaded {count} banned node(s); no remote feed configured"
                    )),
                )
                .await;
                continue;
            };

            let result = with_retry("node_ban_list_feed", 2, Duration::from_secs(5), || {
                let client = client.clone();
                let feed_url = feed_url.clone();
                async move {
                    let response = client.get(&feed_url).send().await?;
                    response.error_for_status()?.json::<NodeBanList>().await
                }
            })
            .await;

            let Some(list) = result else {
                record_maintenance_attention(
                    &state,
                    "node_ban_list",
                    "CONFIDIS node ban list refresh",
                    "could not refresh node ban list".to_string(),
                    Some(feed_url),
                )
                .await;
                continue;
            };

            if let Err(err) = verify_node_ban_list(&list, root_key, Utc::now()) {
                record_maintenance_attention(
                    &state,
                    "node_ban_list",
                    "CONFIDIS node ban list refresh",
                    format!("downloaded node ban list is invalid: {err}"),
                    Some(feed_url),
                )
                .await;
                continue;
            }

            if let Some(path) = state.config.node_ban_list_path.as_ref()
                && let Err(err) = persist_node_ban_list(path, &list).await
            {
                record_maintenance_attention(
                    &state,
                    "node_ban_list",
                    "CONFIDIS node ban list refresh",
                    format!("could not persist node ban list: {err}"),
                    Some(path.display().to_string()),
                )
                .await;
                continue;
            }

            let count = list.banned_nodes.len();
            *state.node_ban_list.write().await = Some(list);
            record_maintenance_success(
                &state,
                "node_ban_list",
                "CONFIDIS node ban list refresh",
                Some(format!("{count} banned node(s) loaded")),
            )
            .await;
        }
    });
}

async fn persist_node_ban_list(path: &std::path::Path, list: &NodeBanList) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp_path = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(list)?;
    tokio::fs::write(&tmp_path, bytes).await?;
    tokio::fs::rename(&tmp_path, path).await?;
    Ok(())
}

/// Broadcasts a self-signed `NodeUptimeRecord` to all known peers every 30 seconds,
/// and collects uptime records from peers' `GET /uptime` responses.
///
/// Records are verified before storing — a compromised peer cannot forge another node's uptime.
pub(crate) fn start_uptime_gossip_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "uptime", "Uptime gossip", None).await;

            let own_record = build_self_uptime_record(&state);

            let endpoints: Vec<String> = {
                let table = state.routing_table.read().await;
                table.keys().cloned().collect()
            };

            for endpoint in &endpoints {
                if let Some(rec) = &own_record {
                    let ep = endpoint.clone();
                    let rec = rec.clone();
                    let client = client.clone();
                    let _ = with_retry("announce_uptime", 2, Duration::from_millis(200), || {
                        let client = client.clone();
                        let ep = ep.clone();
                        let rec = rec.clone();
                        async move {
                            client
                                .put(format!("{ep}/uptime/announce"))
                                .json(&rec)
                                .send()
                                .await
                        }
                    })
                    .await;
                }

                let result = with_retry("fetch_uptime", 2, Duration::from_millis(300), || {
                    let client = client.clone();
                    let ep = endpoint.clone();
                    async move {
                        client
                            .get(format!("{ep}/uptime"))
                            .send()
                            .await?
                            .json::<Vec<NodeUptimeRecord>>()
                            .await
                    }
                })
                .await;

                if let Some(records) = result {
                    let mut table = state.uptime_table.write().await;
                    for rec in records {
                        if rec.node_id == state.config.node_id.0 {
                            continue;
                        }
                        if verify_uptime_record(&rec).is_err() {
                            continue;
                        }
                        let key = rec.node_id.clone();
                        if table.len() < crate::state::MAX_UPTIME_TABLE_SIZE
                            || table.contains_key(&key)
                        {
                            let entry = table.entry(key).or_insert_with(|| rec.clone());
                            if rec.recorded_at > entry.recorded_at {
                                *entry = rec;
                            }
                        }
                    }
                }
            }

            if let Some(rec) = own_record {
                let mut table = state.uptime_table.write().await;
                table.insert(rec.node_id.clone(), rec);
            }
            let records = state.uptime_table.read().await.len();
            record_maintenance_success(
                &state,
                "uptime",
                "Uptime gossip",
                Some(format!("{records} uptime record(s) known")),
            )
            .await;
        }
    });
}

/// Gossips signed shard provider records to known signed peers.
///
/// This is a bounded registry-to-registry propagation layer, not a full DHT:
/// records remain self-signed by storage nodes, expire quickly, and every
/// receiver re-verifies them before accepting them.
pub(crate) fn start_provider_gossip_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");
        let interval_secs = std::env::var("CONFIDIS_PROVIDER_GOSSIP_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30)
            .max(1);
        let record_limit = std::env::var("CONFIDIS_PROVIDER_GOSSIP_RECORD_LIMIT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(128)
            .max(1);
        let peer_limit = std::env::var("CONFIDIS_PROVIDER_GOSSIP_PEER_LIMIT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(8)
            .max(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "provider_gossip", "Provider record gossip", None)
                .await;

            let records = provider_gossip_records(&state, record_limit).await;
            let endpoints = signed_peer_gossip_endpoints(&state, peer_limit).await;
            let mut announced = 0usize;
            for endpoint in &endpoints {
                for record in &records {
                    let ep = endpoint.clone();
                    let record = record.clone();
                    let client = client.clone();
                    if with_retry(
                        "announce_provider_record",
                        2,
                        Duration::from_millis(200),
                        || {
                            let client = client.clone();
                            let ep = ep.clone();
                            let record = record.clone();
                            async move {
                                client
                                    .put(format!("{ep}/providers/announce"))
                                    .json(&record)
                                    .send()
                                    .await?
                                    .error_for_status()?;
                                Ok::<_, reqwest::Error>(())
                            }
                        },
                    )
                    .await
                    .is_some()
                    {
                        announced = announced.saturating_add(1);
                    }
                }
            }

            record_maintenance_success(
                &state,
                "provider_gossip",
                "Provider record gossip",
                Some(format!(
                    "announced {announced} provider record(s) across {} signed peer(s)",
                    endpoints.len()
                )),
            )
            .await;
        }
    });
}

/// Gossips signed Cellule public records to known signed peers.
///
/// This is deliberately still a bounded beta registry, not a DHT. The owner
/// signature remains the trust root; peers only cache and forward the newest
/// valid public record so a fresh client can find the encrypted manifest CID.
pub(crate) fn start_cellule_record_gossip_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");
        let interval_secs = std::env::var("CONFIDIS_CELLULE_RECORD_GOSSIP_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30)
            .max(1);
        let record_limit = std::env::var("CONFIDIS_CELLULE_RECORD_GOSSIP_RECORD_LIMIT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(128)
            .max(1);
        let peer_limit = std::env::var("CONFIDIS_CELLULE_RECORD_GOSSIP_PEER_LIMIT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(8)
            .max(1);
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(
                &state,
                "cellule_record_gossip",
                "Cellule record gossip",
                None,
            )
            .await;

            let records = cellule_record_gossip_records(&state, record_limit).await;
            let endpoints = signed_peer_gossip_endpoints(&state, peer_limit).await;
            let mut announced = 0usize;
            for endpoint in &endpoints {
                for record in &records {
                    let ep = endpoint.clone();
                    let record = record.clone();
                    let client = client.clone();
                    if with_retry(
                        "announce_cellule_record",
                        2,
                        Duration::from_millis(200),
                        || {
                            let client = client.clone();
                            let ep = ep.clone();
                            let record = record.clone();
                            async move {
                                client
                                    .put(format!("{ep}/cellule-records/announce"))
                                    .json(&record)
                                    .send()
                                    .await?
                                    .error_for_status()?;
                                Ok::<_, reqwest::Error>(())
                            }
                        },
                    )
                    .await
                    .is_some()
                    {
                        announced = announced.saturating_add(1);
                    }
                }
            }

            record_maintenance_success(
                &state,
                "cellule_record_gossip",
                "Cellule record gossip",
                Some(format!(
                    "announced {announced} Cellule record(s) across {} signed peer(s)",
                    endpoints.len()
                )),
            )
            .await;
        }
    });
}

async fn provider_gossip_records(state: &NodeState, limit: usize) -> Vec<ShardProviderRecord> {
    let now = Utc::now();
    let records = state.provider_records.read().await;
    let mut records = records
        .values()
        .flat_map(|records| records.iter())
        .filter(|record| record.expires_at.is_some_and(|expires_at| now < expires_at))
        .filter(|record| verify_shard_provider_record(record).is_ok())
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by_key(|record| std::cmp::Reverse(record.issued_at));
    records.truncate(limit);
    records
}

async fn cellule_record_gossip_records(
    state: &NodeState,
    limit: usize,
) -> Vec<CellulePublicRecord> {
    let now = Utc::now();
    let records = state.cellule_records.read().await;
    let mut records = records
        .values()
        .filter(|record| now < record.expires_at)
        .filter(|record| verify_cellule_public_record(record).is_ok())
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by_key(|record| std::cmp::Reverse(record.sequence));
    records.truncate(limit);
    records
}

async fn signed_peer_gossip_endpoints(state: &NodeState, limit: usize) -> Vec<String> {
    let now = Utc::now();
    let self_endpoint = state
        .config
        .public_endpoint
        .as_ref()
        .map(|endpoint| normalize_endpoint(endpoint));
    let table = state.routing_table.read().await;
    let mut endpoints = table
        .values()
        .filter(|peer| peer.public_key.is_some() && peer.signature.is_some())
        .filter(|peer| peer.expires_at.is_some_and(|expires_at| now < expires_at))
        .map(|peer| normalize_endpoint(&peer.endpoint))
        .filter(|endpoint| self_endpoint.as_ref() != Some(endpoint))
        .collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    endpoints.truncate(limit);
    endpoints
}

fn build_self_uptime_record(state: &NodeState) -> Option<NodeUptimeRecord> {
    let signing_key = state.config.signing_key.as_ref()?;
    let endpoint = state.config.public_endpoint.as_ref()?;
    let uptime_seconds = state.started_at.elapsed().as_secs();

    use ed25519_dalek::Signer;
    let mut rec = NodeUptimeRecord {
        version: 1,
        node_id: state.config.node_id.0.clone(),
        ed25519_pubkey: verifying_key_to_hex(&signing_key.verifying_key()),
        endpoint: normalize_endpoint(endpoint),
        uptime_seconds,
        recorded_at: Utc::now(),
        signature: None,
    };
    let payload = uptime_record_signing_payload(&rec).ok()?;
    let sig = signing_key.sign(&payload);
    rec.signature = Some(hex::encode(sig.to_bytes()));
    Some(rec)
}

async fn build_self_peer_record(state: &NodeState) -> Option<PeerRecord> {
    let endpoint = state.config.public_endpoint.as_ref()?;
    let now = Utc::now();
    let mut record = PeerRecord {
        endpoint: normalize_endpoint(endpoint),
        node_id: Some(state.config.node_id.clone()),
        public_key: state
            .config
            .signing_key
            .as_ref()
            .map(|key| verifying_key_to_hex(&key.verifying_key())),
        region: Some(state.config.region.clone()),
        failure_domain: Some(state.config.failure_domain.clone()),
        issued_at: Some(now),
        expires_at: Some(now + chrono::Duration::minutes(10)),
        signature: None,
    };
    sign_peer_record(&mut record, state.config.signing_key.as_ref()).ok()?;
    Some(record)
}

/// Evict Noise sessions that have exceeded `NOISE_SESSION_TTL_SECS`.
///
/// Runs every 60 seconds. Stale sessions (pending or transport) are dropped
/// so their memory is reclaimed and nonce counters cannot be replayed.
pub(crate) fn start_noise_cleanup_worker(
    state: std::sync::Arc<crate::state::NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    use crate::state::NOISE_SESSION_TTL_SECS;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "noise_cleanup", "Secure session cleanup", None).await;
            let deadline = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(NOISE_SESSION_TTL_SECS))
                .unwrap_or(std::time::Instant::now());
            let mut sessions = state.noise_sessions.write().await;
            let before = sessions.len();
            sessions.retain(|_, s| s.created_at >= deadline);
            let evicted = before - sessions.len();
            if evicted > 0 {
                tracing::debug!(evicted, "evicted stale Noise sessions");
            }
            record_maintenance_success(
                &state,
                "noise_cleanup",
                "Secure session cleanup",
                Some(format!("evicted {evicted} stale session(s)")),
            )
            .await;
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RepairScanSummary {
    scanned: usize,
    repairs_needed: usize,
}

async fn scan_repair_backlog(state: &Arc<NodeState>) -> Result<RepairScanSummary, String> {
    let statuses = run_storage_task(state, |store| {
        let mut statuses = Vec::new();
        for metadata in store.read_all_metadata()? {
            let status = store.status(&metadata.shard_id);
            statuses.push((metadata.shard_id, status));
        }
        Ok(statuses)
    })
    .await
    .map_err(|err| err.to_string())?;

    let mut scanned = 0usize;
    let mut repairs_needed = 0usize;
    for (shard_id, status) in statuses {
        scanned += 1;
        match status {
            Ok(status) if !status.valid => {
                repairs_needed += 1;
                tracing::warn!(
                    shard_id = %shard_id.0,
                    error = ?status.error,
                    "repair-scan: shard integrity issue detected"
                );
            }
            Ok(_) => {}
            Err(err) => {
                repairs_needed += 1;
                tracing::warn!(
                    shard_id = %shard_id.0,
                    error = %err,
                    "repair-scan: failed to evaluate shard status"
                );
            }
        }
    }

    Ok(RepairScanSummary {
        scanned,
        repairs_needed,
    })
}

pub(crate) fn start_repair_worker(state: Arc<NodeState>, mut shutdown_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        // Allow tests to set a shorter interval via environment variable.
        let interval_secs = std::env::var("CONFIDIS_REPAIR_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3600); // 1 hour default
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "repair", "Data repair scan", None).await;

            // Scan-only by design for public testnet: this worker detects local
            // shards that have lost integrity but does NOT reconstruct them.
            // Automated network repair (manifest + peer coordination) is the
            // manual `confidis cellule repair` / `repair-scan` CLI path and is
            // intentionally out of testnet scope. Status is reported honestly:
            // a non-zero repair backlog raises operator attention, it is not
            // silently reported as success.
            let RepairScanSummary {
                scanned,
                repairs_needed,
            } = match scan_repair_backlog(&state).await {
                Ok(summary) => summary,
                Err(err) => {
                    tracing::warn!(error = %err, "repair-scan: failed to read shard metadata");
                    record_maintenance_attention(
                        &state,
                        "repair",
                        "Data repair scan",
                        err,
                        Some("failed to scan local shard metadata".to_string()),
                    )
                    .await;
                    continue;
                }
            };

            if repairs_needed > 0 {
                record_maintenance_attention(
                    &state,
                    "repair",
                    "Data repair scan",
                    format!(
                        "{repairs_needed} of {scanned} local shard(s) need repair; \
                         automated network repair is not enabled for testnet — \
                         run `confidis cellule repair-scan`"
                    ),
                    Some(format!(
                        "scanned {scanned} local shard(s); {repairs_needed} need repair (scan only, no reconstruction performed)"
                    )),
                )
                .await;
            } else {
                record_maintenance_success(
                    &state,
                    "repair",
                    "Data repair scan",
                    Some(format!(
                        "scanned {scanned} local shard(s); all valid (scan only, no reconstruction performed)"
                    )),
                )
                .await;
            }
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RebalanceScanSummary {
    local_shards: usize,
    healthy_peers: usize,
}

async fn scan_rebalance_inputs(state: &Arc<NodeState>) -> Result<RebalanceScanSummary, String> {
    let local_shards = run_storage_task(state, |store| store.read_all_metadata())
        .await
        .map_err(|err| err.to_string())?
        .len();
    let healthy_peers = state
        .routing_table
        .read()
        .await
        .values()
        .filter(|peer| peer.node_id.is_some())
        .count();
    Ok(RebalanceScanSummary {
        local_shards,
        healthy_peers,
    })
}

pub(crate) fn start_rebalance_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        // Allow tests to set a shorter interval via environment variable.
        let interval_secs = std::env::var("CONFIDIS_REBALANCE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(7200); // 2 hours default
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(&state, "rebalance", "Data placement scan", None).await;

            // Scan-only by design for public testnet: this worker reports local
            // shard count and known healthy peers but does NOT move any shards.
            // Placement decisions need owner manifest context that is not
            // available node-side, so automated rebalancing is intentionally
            // out of testnet scope (manual `confidis cellule rebalance` only).
            let RebalanceScanSummary {
                local_shards,
                healthy_peers,
            } = match scan_rebalance_inputs(&state).await {
                Ok(summary) => summary,
                Err(err) => {
                    tracing::warn!(error = %err, "placement-scan: failed to read shard metadata");
                    record_maintenance_attention(
                        &state,
                        "rebalance",
                        "Data placement scan",
                        err,
                        Some("failed to scan local shard metadata".to_string()),
                    )
                    .await;
                    continue;
                }
            };

            record_maintenance_success(
                &state,
                "rebalance",
                "Data placement scan",
                Some(format!(
                    "scanned {local_shards} local shard(s), {healthy_peers} healthy peer(s) known; \
                     automated rebalancing is not enabled for testnet (scan only, no shards moved)"
                )),
            )
            .await;
        }
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeletionConvergenceSummary {
    still_pending: usize,
    closed_by_timeout: usize,
    failed_retries: usize,
    detail: String,
}

async fn update_deletion_convergence(
    state: &Arc<NodeState>,
    now: chrono::DateTime<Utc>,
) -> DeletionConvergenceSummary {
    let mut pending_deletions = 0usize;
    let mut closed_by_timeout = 0usize;
    let mut failed_retries = 0usize;

    let mut convergence_states = state.deletion_convergence.write().await;

    let mut to_remove = Vec::new();
    for (cellule_id, state) in convergence_states.iter_mut() {
        pending_deletions += 1;

        if state.retry_count >= 5 {
            tracing::warn!(
                cellule_id = %cellule_id,
                retries = state.retry_count,
                "deletion-convergence: tracking failed after max retries (no receipt confirmation)"
            );
            failed_retries += 1;
            continue;
        }

        let time_since_initiated = now.signed_duration_since(state.initiated_at);
        if time_since_initiated > chrono::Duration::hours(24) {
            tracing::warn!(
                cellule_id = %cellule_id,
                pending_nodes = state.pending_nodes.len(),
                "deletion-convergence: entry closed by 24h timeout WITHOUT receipt confirmation"
            );
            closed_by_timeout += 1;
            to_remove.push(cellule_id.clone());
        } else {
            state.retry_count += 1;
            state.last_attempt = now;
        }
    }

    for cellule_id in to_remove {
        convergence_states.remove(&cellule_id);
    }

    let still_pending = pending_deletions - closed_by_timeout;
    let detail = format!(
        "{still_pending} pending, {closed_by_timeout} closed by timeout WITHOUT receipt confirmation, \
         {failed_retries} failed after max retries (tracking only, receipts not collected)"
    );

    DeletionConvergenceSummary {
        still_pending,
        closed_by_timeout,
        failed_retries,
        detail,
    }
}

pub(crate) fn start_deletion_convergence_worker(
    state: Arc<NodeState>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        // Allow tests to set a shorter interval via environment variable.
        let interval_secs = std::env::var("CONFIDIS_DELETION_CONVERGENCE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300); // 5 minutes default
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        loop {
            if !wait_interval_or_shutdown(&mut interval, &mut shutdown_rx).await {
                break;
            }
            record_maintenance_start(
                &state,
                "deletion_convergence",
                "Deletion convergence tracking",
                None,
            )
            .await;

            // Honest scope for public testnet: this worker tracks pending
            // deletions and ages them out, but it does NOT yet contact nodes
            // that still owe deletion receipts. Entries past the deadline are
            // CLOSED BY TIMEOUT — that is not the same as receipt-confirmed
            // physical deletion, so it must never be reported as "converged".
            // Real receipt-driven convergence is post-testnet (see ROADMAP).
            let summary = update_deletion_convergence(&state, Utc::now()).await;

            // Closing a deletion without receipt confirmation, or exhausting
            // retries, is an RGPD-relevant gap the operator must see — surface
            // it as attention rather than a green success.
            if summary.closed_by_timeout > 0 || summary.failed_retries > 0 {
                record_maintenance_attention(
                    &state,
                    "deletion_convergence",
                    "Deletion convergence tracking",
                    "one or more deletions were closed without receipt confirmation".to_string(),
                    Some(summary.detail),
                )
                .await;
            } else {
                record_maintenance_success(
                    &state,
                    "deletion_convergence",
                    "Deletion convergence tracking",
                    Some(summary.detail),
                )
                .await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_manager::ConfidISConfig;
    use crate::rate_limit::RateLimiter;
    use crate::state::DeletionConvergenceState;
    use crate::storage_backend::{StorageConfig, StorageFactory};
    use std::collections::HashSet;
    use std::sync::Arc;

    fn test_state() -> (tempfile::TempDir, Arc<NodeState>) {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut config = ConfidISConfig::default();
        config.node.node_id = "worker-test-node".to_string();
        config.storage.store_path = temp.path().to_path_buf();
        config.storage_backend.backend_type = "memory".to_string();
        config.storage_backend.filesystem_root = None;
        let server_config = config
            .to_node_server_config()
            .expect("node server config for worker test");
        let store = StorageFactory::create(StorageConfig::Memory).expect("memory store");
        let state = Arc::new(NodeState::new(
            server_config,
            store,
            Arc::new(RateLimiter::new(100, 100)),
        ));
        (temp, state)
    }

    #[tokio::test]
    async fn maintenance_success_clears_attention_but_keeps_error_count() {
        let (temp, state) = test_state();

        record_maintenance_start(&state, "repair", "Data repair scan", None).await;
        record_maintenance_attention(
            &state,
            "repair",
            "Data repair scan",
            "integrity backlog".to_string(),
            Some("1 shard needs repair".to_string()),
        )
        .await;
        record_maintenance_start(&state, "repair", "Data repair scan", None).await;
        record_maintenance_success(
            &state,
            "repair",
            "Data repair scan",
            Some("scanned 1 local shard(s); all valid".to_string()),
        )
        .await;

        let jobs = state.maintenance_jobs.read().await;
        let repair = jobs.get("repair").expect("repair job");
        assert_eq!(repair.status, "ok");
        assert_eq!(repair.runs, 2);
        assert_eq!(repair.error_runs, 1);
        assert!(!repair.attention);
        assert!(repair.last_error.is_none());
        assert_eq!(
            repair.detail.as_deref(),
            Some("scanned 1 local shard(s); all valid")
        );

        let disk = std::fs::read_to_string(temp.path().join("maintenance").join("status.json"))
            .expect("persisted maintenance status");
        let snapshot: serde_json::Value = serde_json::from_str(&disk).expect("status json");
        let persisted_repair = snapshot["jobs"]
            .as_array()
            .expect("jobs")
            .iter()
            .find(|job| job["job_id"] == "repair")
            .expect("persisted repair job");
        assert_eq!(persisted_repair["status"], "ok");
        assert_eq!(persisted_repair["runs"], 2);
        assert_eq!(persisted_repair["error_runs"], 1);
    }

    #[tokio::test]
    async fn audit_export_writes_signed_latest_snapshot() {
        let (temp, state) = test_state();
        record_maintenance_start(&state, "audit", "Signed audit export", None).await;
        record_maintenance_success(
            &state,
            "audit",
            "Signed audit export",
            Some("previous run ok".to_string()),
        )
        .await;

        let summary = write_audit_export(&state).await.expect("audit export");

        assert!(summary.contains("wrote signed audit snapshot"));
        let latest = temp
            .path()
            .join("maintenance")
            .join("audit")
            .join("latest.json");
        let export: serde_json::Value =
            serde_json::from_slice(&std::fs::read(latest).expect("latest audit"))
                .expect("latest audit json");
        assert_eq!(export["version"], 1);
        assert_eq!(export["node_id"], "worker-test-node");
        assert_eq!(export["capacity"]["used_bytes"], 0);
        assert_eq!(export["receipt_count"], 0);
        assert!(
            export["public_key"]
                .as_str()
                .is_some_and(|value| value.len() == 64)
        );
        assert!(
            export["signature"]
                .as_str()
                .is_some_and(|value| value.len() == 128)
        );
        assert!(
            export["maintenance_jobs"]
                .as_array()
                .expect("maintenance jobs")
                .iter()
                .any(|job| job["job_id"] == "audit" && job["status"] == "ok")
        );
    }

    #[tokio::test]
    async fn repair_scan_counts_missing_local_shards_as_backlog() {
        let (_temp, state) = test_state();
        let node_id = state.config.node_id.clone();
        let signing_key = state.config.signing_key.as_ref();
        let valid = state
            .store
            .put(
                node_id.clone(),
                b"valid shard",
                None,
                "delete-authority-a".to_string(),
                signing_key,
            )
            .expect("valid shard");
        let missing = state
            .store
            .put(
                node_id.clone(),
                b"missing shard",
                None,
                "delete-authority-b".to_string(),
                signing_key,
            )
            .expect("missing shard");
        state
            .store
            .delete_unchecked(node_id, &missing.shard_id, signing_key, false)
            .expect("remove shard bytes but keep metadata");

        let summary = scan_repair_backlog(&state).await.expect("repair scan");

        assert_eq!(
            summary,
            RepairScanSummary {
                scanned: 2,
                repairs_needed: 1,
            }
        );
        let valid_status = state.store.status(&valid.shard_id).expect("valid status");
        assert!(valid_status.present);
        assert!(valid_status.valid);
    }

    #[tokio::test]
    async fn rebalance_scan_reports_local_shards_and_healthy_peers() {
        let (_temp, state) = test_state();
        state
            .store
            .put(
                state.config.node_id.clone(),
                b"local shard one",
                None,
                "delete-authority-a".to_string(),
                state.config.signing_key.as_ref(),
            )
            .expect("first shard");
        state
            .store
            .put(
                state.config.node_id.clone(),
                b"local shard two",
                None,
                "delete-authority-b".to_string(),
                state.config.signing_key.as_ref(),
            )
            .expect("second shard");
        {
            let mut table = state.routing_table.write().await;
            table.insert(
                "https://healthy.example.test".to_string(),
                PeerRecord {
                    endpoint: "https://healthy.example.test".to_string(),
                    node_id: Some(confidis_protocol::NodeId("peer-a".to_string())),
                    public_key: None,
                    region: Some("eu-fr".to_string()),
                    failure_domain: Some("fd-a".to_string()),
                    issued_at: None,
                    expires_at: None,
                    signature: None,
                },
            );
            table.insert(
                "https://bootstrap-stub.example.test".to_string(),
                PeerRecord {
                    endpoint: "https://bootstrap-stub.example.test".to_string(),
                    node_id: None,
                    public_key: None,
                    region: None,
                    failure_domain: None,
                    issued_at: None,
                    expires_at: None,
                    signature: None,
                },
            );
        }

        let summary = scan_rebalance_inputs(&state).await.expect("rebalance scan");

        assert_eq!(
            summary,
            RebalanceScanSummary {
                local_shards: 2,
                healthy_peers: 1,
            }
        );
    }

    #[tokio::test]
    async fn deletion_convergence_increments_pending_retry_count() {
        let (_temp, state) = test_state();
        let now = Utc::now();
        state.deletion_convergence.write().await.insert(
            "cellule-pending".to_string(),
            DeletionConvergenceState {
                cellule_id: "cellule-pending".to_string(),
                initiated_at: now - chrono::Duration::hours(1),
                pending_nodes: HashSet::from(["https://node-a.example.test".to_string()]),
                last_attempt: now - chrono::Duration::minutes(10),
                retry_count: 0,
            },
        );

        let summary = update_deletion_convergence(&state, now).await;

        assert_eq!(
            summary,
            DeletionConvergenceSummary {
                still_pending: 1,
                closed_by_timeout: 0,
                failed_retries: 0,
                detail: "1 pending, 0 closed by timeout WITHOUT receipt confirmation, 0 failed after max retries (tracking only, receipts not collected)".to_string(),
            }
        );
        let states = state.deletion_convergence.read().await;
        let pending = states.get("cellule-pending").expect("pending remains");
        assert_eq!(pending.retry_count, 1);
        assert_eq!(pending.last_attempt, now);
    }

    #[tokio::test]
    async fn deletion_convergence_timeout_is_not_reported_as_success() {
        let (_temp, state) = test_state();
        let now = Utc::now();
        state.deletion_convergence.write().await.insert(
            "cellule-timeout".to_string(),
            DeletionConvergenceState {
                cellule_id: "cellule-timeout".to_string(),
                initiated_at: now - chrono::Duration::hours(25),
                pending_nodes: HashSet::from(["https://node-a.example.test".to_string()]),
                last_attempt: now - chrono::Duration::hours(1),
                retry_count: 2,
            },
        );

        let summary = update_deletion_convergence(&state, now).await;

        assert_eq!(summary.still_pending, 0);
        assert_eq!(summary.closed_by_timeout, 1);
        assert_eq!(summary.failed_retries, 0);
        assert!(
            summary
                .detail
                .contains("closed by timeout WITHOUT receipt confirmation")
        );
        assert!(state.deletion_convergence.read().await.is_empty());
    }

    #[tokio::test]
    async fn deletion_convergence_max_retries_remains_pending_attention() {
        let (_temp, state) = test_state();
        let now = Utc::now();
        state.deletion_convergence.write().await.insert(
            "cellule-failed".to_string(),
            DeletionConvergenceState {
                cellule_id: "cellule-failed".to_string(),
                initiated_at: now - chrono::Duration::hours(2),
                pending_nodes: HashSet::from(["https://node-a.example.test".to_string()]),
                last_attempt: now - chrono::Duration::minutes(5),
                retry_count: 5,
            },
        );

        let summary = update_deletion_convergence(&state, now).await;

        assert_eq!(summary.still_pending, 1);
        assert_eq!(summary.closed_by_timeout, 0);
        assert_eq!(summary.failed_retries, 1);
        assert_eq!(
            state
                .deletion_convergence
                .read()
                .await
                .get("cellule-failed")
                .expect("failed item remains for operator attention")
                .retry_count,
            5
        );
    }
}
