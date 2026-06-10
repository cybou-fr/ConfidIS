#[cfg(any())]
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::Subcommand;
use confidis_erasure::reconstruct_segment;
use confidis_placement::build_placement_plan;
#[cfg(any())]
use confidis_protocol::NodeCandidate;
use confidis_protocol::{
    CelluleId, ErasurePolicy, PlacementPlan, PlacementPolicy, ShardId, ShardPlacement,
    ShardProviderRecord, ShardReceipt, ShardReceiptType,
};
use serde::{Deserialize, Serialize};

use crate::commands::cellule::{delete_authority_hash_from_private_key, validated_expires_at};
use crate::commands::shard::read_shard_ids;
use crate::network::{fetch_candidates, network_client};
use crate::verify::parse_and_verify_receipt;

const UPLOAD_MAX_ATTEMPTS: usize = 4;
const UPLOAD_CACHE_VERSION: u16 = 1;

fn is_transient_upload_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

async fn send_upload_with_retry<F>(
    mut build_request: F,
    bytes: Vec<u8>,
) -> Result<(reqwest::StatusCode, String)>
where
    F: FnMut() -> Result<reqwest::RequestBuilder>,
{
    for attempt in 0..UPLOAD_MAX_ATTEMPTS {
        let response = build_request()?.body(bytes.clone()).send().await?;
        let status = response.status();
        let text = response.text().await?;
        if status.is_success()
            || !is_transient_upload_status(status)
            || attempt + 1 == UPLOAD_MAX_ATTEMPTS
        {
            return Ok((status, text));
        }
        let delay_ms = 50_u64 * (1_u64 << attempt);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    unreachable!("upload retry loop always returns on its final attempt")
}

fn encode_fee_authorization(
    authorization: &confidis_protocol::StorageFeeAuthorization,
) -> Result<String> {
    let json = serde_json::to_vec(authorization)
        .context("failed to serialize storage fee authorization")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
}

#[derive(Debug, Subcommand)]
pub(crate) enum PlacementCommand {
    Upload {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        shard_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        group_id: Option<String>,
    },
    Restore {
        #[arg(long)]
        placement: PathBuf,
        #[arg(long)]
        original_len: usize,
        /// Node Ed25519 private key (hex) for the signed shard-access proof.
        /// Optional in development; required when target nodes run
        /// `production_profile` (the authority ban list binds to reads there).
        #[arg(long)]
        node_private_key: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlacementUploadOutput {
    pub(crate) plan: PlacementPlan,
    pub(crate) receipts: Vec<ShardReceipt>,
    #[serde(default)]
    pub(crate) provider_records: Vec<ShardProviderRecord>,
}

pub(crate) struct ProviderUploadContext {
    pub(crate) cellule_id: CelluleId,
    pub(crate) manifest_id: uuid::Uuid,
    pub(crate) segment_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlacementUploadCache {
    version: u16,
    plan: PlacementPlan,
    receipts: Vec<ShardReceipt>,
    #[serde(default)]
    provider_records: Vec<ShardProviderRecord>,
}

#[derive(Debug, Deserialize)]
struct ShardPutResponse {
    #[serde(flatten)]
    receipt: ShardReceipt,
    provider_record: Option<ShardProviderRecord>,
}

pub(crate) async fn placement(command: PlacementCommand) -> Result<()> {
    match command {
        PlacementCommand::Upload {
            nodes,
            private_key,
            expires_at,
            shard_dir,
            output,
            group_id,
        } => {
            if nodes.is_empty() {
                bail!("at least one --node is required");
            }

            let client = network_client()?;
            let candidates = fetch_candidates(&client, &nodes).await?;
            let (group_id, shard_ids) = read_shard_ids(group_id, &shard_dir)?;
            let plan = build_placement_plan(
                group_id,
                ErasurePolicy::default(),
                &shard_ids,
                &candidates,
                &PlacementPolicy::default(),
            )?;

            let receipts =
                upload_plan(&client, &plan, &shard_dir, &private_key, &expires_at, None).await?;

            let upload = PlacementUploadOutput {
                plan,
                receipts,
                provider_records: Vec::new(),
            };
            fs::write(&output, serde_json::to_vec_pretty(&upload)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        PlacementCommand::Restore {
            placement,
            original_len,
            node_private_key,
            output,
        } => {
            let bytes = fs::read(&placement)
                .with_context(|| format!("failed to read {}", placement.display()))?;
            let upload: PlacementUploadOutput =
                serde_json::from_slice(&bytes).context("invalid placement upload file")?;
            let restored =
                restore_from_placement(&upload.plan, original_len, node_private_key.as_deref())
                    .await?;
            fs::write(&output, restored)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
    }
    Ok(())
}

pub(crate) async fn restore_from_placement(
    plan: &PlacementPlan,
    original_len: usize,
    node_private_key: Option<&str>,
) -> Result<Vec<u8>> {
    let client = network_client()?;
    let mut shards = vec![None; plan.erasure_policy.total_shards()];
    let mut fetched = 0usize;

    for placement in &plan.placements {
        let url = format!(
            "{}/shards/{}",
            placement.endpoint.trim_end_matches('/'),
            placement.shard_id.0
        );
        let mut req = client.get(url);
        if let Some(pk) = node_private_key {
            for (k, v) in
                &crate::network::node_access_proof_headers(pk, "GET", &placement.shard_id.0)?
            {
                req = req.header(*k, v);
            }
        }
        let response = match req.send().await {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let bytes = response.bytes().await?.to_vec();
        let actual = confidis_crypto::blake3_hex(&bytes);
        if actual != placement.shard_id.0 {
            continue;
        }
        if shards[placement.shard_index].is_none() {
            shards[placement.shard_index] = Some(bytes);
            fetched += 1;
        }
        if fetched >= plan.erasure_policy.data_shards {
            break;
        }
    }

    if fetched < plan.erasure_policy.data_shards {
        bail!(
            "not enough valid shards: fetched {}, need {}",
            fetched,
            plan.erasure_policy.data_shards
        );
    }

    reconstruct_segment(&plan.erasure_policy, original_len, shards)
}

pub(crate) async fn upload_plan(
    client: &reqwest::Client,
    plan: &PlacementPlan,
    shard_dir: &Path,
    private_key: &str,
    expires_at: &str,
    fee_authorization: Option<&confidis_protocol::StorageFeeAuthorization>,
) -> Result<Vec<ShardReceipt>> {
    Ok(upload_plan_with_provider_context(
        client,
        plan,
        shard_dir,
        private_key,
        expires_at,
        fee_authorization,
        None,
    )
    .await?
    .receipts)
}

pub(crate) async fn upload_plan_with_provider_context(
    client: &reqwest::Client,
    plan: &PlacementPlan,
    shard_dir: &Path,
    private_key: &str,
    expires_at: &str,
    fee_authorization: Option<&confidis_protocol::StorageFeeAuthorization>,
    provider_context: Option<&ProviderUploadContext>,
) -> Result<PlacementUploadOutput> {
    upload_plan_with_provider_context_resumable(
        client,
        plan,
        shard_dir,
        private_key,
        expires_at,
        fee_authorization,
        provider_context,
        None,
    )
    .await
}

pub(crate) async fn upload_plan_with_provider_context_resumable(
    client: &reqwest::Client,
    plan: &PlacementPlan,
    shard_dir: &Path,
    private_key: &str,
    expires_at: &str,
    fee_authorization: Option<&confidis_protocol::StorageFeeAuthorization>,
    provider_context: Option<&ProviderUploadContext>,
    cache_path: Option<&Path>,
) -> Result<PlacementUploadOutput> {
    let delete_authority_hash = delete_authority_hash_from_private_key(private_key)?;
    let expires_at = validated_expires_at(expires_at)?;
    let mut receipts = Vec::with_capacity(plan.placements.len());
    let mut provider_records = Vec::with_capacity(plan.placements.len());
    let mut cache = load_upload_cache_for_plan(cache_path, plan)?;
    persist_upload_cache(cache_path, &cache)?;

    for placement in &plan.placements {
        if let Some(cached) =
            verified_cached_upload(&cache, placement, provider_context).transpose()?
        {
            receipts.push(cached.receipt);
            if let Some(record) = cached.provider_record {
                provider_records.push(record);
            }
            continue;
        }

        if let Some(parsed) =
            recover_remote_upload(client, placement, private_key, provider_context).await?
        {
            let verified = verify_shard_put_response(parsed, placement, provider_context)?;
            record_verified_upload(
                &mut cache,
                &mut receipts,
                &mut provider_records,
                placement,
                verified,
            );
            persist_upload_cache(cache_path, &cache)?;
            continue;
        }

        let path = shard_dir.join(format!("shard-{:02}.bin", placement.shard_index));
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let actual = confidis_crypto::blake3_hex(&bytes);
        if actual != placement.shard_id.0 {
            bail!(
                "shard {} hash changed: expected {}, got {}",
                placement.shard_index,
                placement.shard_id.0,
                actual
            );
        }

        let url = format!(
            "{}/shards/{}",
            placement.endpoint.trim_end_matches('/'),
            placement.shard_id.0
        );
        let proof =
            crate::network::node_access_proof_headers(private_key, "PUT", &placement.shard_id.0)?;
        let (status, text) = send_upload_with_retry(
            || {
                let mut req = client
                    .put(&url)
                    .header("x-confidis-delete-authority-hash", &delete_authority_hash)
                    .header("x-confidis-expires-at", &expires_at);
                if let Some(authz) = fee_authorization {
                    req = req
                        .header(
                            "x-confidis-fee-authorization",
                            encode_fee_authorization(authz)?,
                        )
                        .header("x-confidis-operation-id", &authz.op_id);
                }
                for (k, v) in &proof {
                    req = req.header(*k, v);
                }
                if let Some(context) = provider_context {
                    req = req
                        .header("x-confidis-provider-cellule-id", context.cellule_id.0.as_str())
                        .header(
                            "x-confidis-provider-manifest-id",
                            context.manifest_id.to_string(),
                        )
                        .header(
                            "x-confidis-provider-segment-index",
                            context.segment_index.to_string(),
                        )
                        .header(
                            "x-confidis-provider-shard-index",
                            placement.shard_index.to_string(),
                        );
                }
                Ok(req)
            },
            bytes,
        )
        .await?;
        if !status.is_success() {
            bail!(
                "upload failed for shard {} to {}: {status} {text}",
                placement.shard_index,
                placement.endpoint
            );
        }
        let parsed: ShardPutResponse =
            serde_json::from_str(&text).context("invalid shard receipt")?;
        let verified = verify_shard_put_response(parsed, placement, provider_context)?;
        record_verified_upload(
            &mut cache,
            &mut receipts,
            &mut provider_records,
            placement,
            verified,
        );
        persist_upload_cache(cache_path, &cache)?;
    }
    Ok(PlacementUploadOutput {
        plan: plan.clone(),
        receipts,
        provider_records,
    })
}
#[cfg(any())]
pub(crate) fn cached_upload_plan_for_shards(
    cache_path: &Path,
    shard_ids: &[ShardId],
    candidates: &[NodeCandidate],
    policy: &PlacementPolicy,
) -> Result<Option<PlacementPlan>> {
    let Some(cache) = read_upload_cache(cache_path)? else {
        return Ok(None);
    };
    if cache.version != UPLOAD_CACHE_VERSION {
        return Ok(None);
    }
    if !plan_matches_shard_ids(&cache.plan, shard_ids) {
        return Ok(None);
    }
    if !cached_plan_uses_current_candidates(&cache.plan, candidates) {
        return Ok(None);
    }
    if !cached_plan_satisfies_policy(&cache.plan, policy) {
        return Ok(None);
    }
    Ok(Some(cache.plan))
}

struct CachedUpload {
    receipt: ShardReceipt,
    provider_record: Option<ShardProviderRecord>,
}

struct VerifiedShardUpload {
    receipt: ShardReceipt,
    provider_record: Option<ShardProviderRecord>,
}

async fn recover_remote_upload(
    client: &reqwest::Client,
    placement: &ShardPlacement,
    private_key: &str,
    provider_context: Option<&ProviderUploadContext>,
) -> Result<Option<ShardPutResponse>> {
    let url = format!(
        "{}/shards/{}/upload-receipt",
        placement.endpoint.trim_end_matches('/'),
        placement.shard_id.0
    );
    let proof =
        crate::network::node_access_proof_headers(private_key, "GET", &placement.shard_id.0)?;
    let mut req = client.get(url);
    for (k, v) in &proof {
        req = req.header(*k, v);
    }
    if let Some(context) = provider_context {
        req = req
            .header("x-confidis-provider-cellule-id", context.cellule_id.0.as_str())
            .header(
                "x-confidis-provider-manifest-id",
                context.manifest_id.to_string(),
            )
            .header(
                "x-confidis-provider-segment-index",
                context.segment_index.to_string(),
            )
            .header(
                "x-confidis-provider-shard-index",
                placement.shard_index.to_string(),
            );
    }

    let response = match req.send().await {
        Ok(response) => response,
        Err(_) => return Ok(None),
    };
    if !response.status().is_success() {
        return Ok(None);
    }
    let text = response.text().await?;
    let parsed = serde_json::from_str(&text).context("invalid remote upload receipt response")?;
    Ok(Some(parsed))
}

fn verify_shard_put_response(
    parsed: ShardPutResponse,
    placement: &ShardPlacement,
    provider_context: Option<&ProviderUploadContext>,
) -> Result<VerifiedShardUpload> {
    crate::verify::verify_receipt(
        &parsed.receipt,
        &placement.shard_id,
        ShardReceiptType::Stored,
        Some(&placement.node_id),
        placement.node_public_key.as_deref(),
    )?;
    let provider_record = if let Some(record) = parsed.provider_record {
        let context = provider_context.context("provider context missing for provider record")?;
        crate::verify::verify_provider_record(
            &record,
            &context.cellule_id,
            context.manifest_id,
            context.segment_index,
            placement,
            &parsed.receipt,
        )?;
        Some(record)
    } else {
        None
    };
    Ok(VerifiedShardUpload {
        receipt: parsed.receipt,
        provider_record,
    })
}

fn record_verified_upload(
    cache: &mut PlacementUploadCache,
    receipts: &mut Vec<ShardReceipt>,
    provider_records: &mut Vec<ShardProviderRecord>,
    placement: &ShardPlacement,
    verified: VerifiedShardUpload,
) {
    receipts.push(verified.receipt.clone());
    cache.receipts.retain(|receipt| {
        receipt.shard_id != placement.shard_id || receipt.node_id != placement.node_id
    });
    cache.provider_records.retain(|record| {
        record.shard_id != placement.shard_id
            || record.node_id != placement.node_id
            || record.shard_index != placement.shard_index
    });
    cache.receipts.push(verified.receipt);
    if let Some(record) = verified.provider_record {
        provider_records.push(record.clone());
        cache.provider_records.push(record);
    }
}

fn verified_cached_upload(
    cache: &PlacementUploadCache,
    placement: &ShardPlacement,
    provider_context: Option<&ProviderUploadContext>,
) -> Option<Result<CachedUpload>> {
    for receipt in cache.receipts.iter().rev() {
        if receipt.shard_id != placement.shard_id || receipt.node_id != placement.node_id {
            continue;
        }
        if crate::verify::verify_receipt(
            receipt,
            &placement.shard_id,
            ShardReceiptType::Stored,
            Some(&placement.node_id),
            placement.node_public_key.as_deref(),
        )
        .is_err()
        {
            continue;
        }

        let provider_record = if let Some(context) = provider_context {
            let mut verified = None;
            for record in cache.provider_records.iter().rev() {
                if record.shard_id != placement.shard_id
                    || record.node_id != placement.node_id
                    || record.shard_index != placement.shard_index
                    || record.segment_index != context.segment_index
                {
                    continue;
                }
                if crate::verify::verify_provider_record(
                    record,
                    &context.cellule_id,
                    context.manifest_id,
                    context.segment_index,
                    placement,
                    receipt,
                )
                .is_ok()
                {
                    verified = Some(record.clone());
                    break;
                }
            }
            Some(verified?)
        } else {
            None
        };

        return Some(Ok(CachedUpload {
            receipt: receipt.clone(),
            provider_record,
        }));
    }
    None
}

fn load_upload_cache_for_plan(
    cache_path: Option<&Path>,
    plan: &PlacementPlan,
) -> Result<PlacementUploadCache> {
    let Some(path) = cache_path else {
        return Ok(empty_upload_cache(plan));
    };
    let Some(cache) = read_upload_cache(path)? else {
        return Ok(empty_upload_cache(plan));
    };
    if cache.version == UPLOAD_CACHE_VERSION && upload_plans_match(&cache.plan, plan) {
        Ok(cache)
    } else {
        Ok(empty_upload_cache(plan))
    }
}

fn empty_upload_cache(plan: &PlacementPlan) -> PlacementUploadCache {
    PlacementUploadCache {
        version: UPLOAD_CACHE_VERSION,
        plan: plan.clone(),
        receipts: Vec::new(),
        provider_records: Vec::new(),
    }
}

fn read_upload_cache(path: &Path) -> Result<Option<PlacementUploadCache>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    match serde_json::from_slice(&bytes) {
        Ok(cache) => Ok(Some(cache)),
        Err(_) => Ok(None),
    }
}

fn persist_upload_cache(cache_path: Option<&Path>, cache: &PlacementUploadCache) -> Result<()> {
    let Some(path) = cache_path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(cache)?)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to replace upload cache {} with {}",
            path.display(),
            tmp.display()
        )
    })?;
    Ok(())
}

fn upload_plans_match(left: &PlacementPlan, right: &PlacementPlan) -> bool {
    left.version == right.version
        && left.group_id == right.group_id
        && left.erasure_policy == right.erasure_policy
        && left.placements.len() == right.placements.len()
        && left
            .placements
            .iter()
            .zip(&right.placements)
            .all(|(left, right)| shard_placements_match(left, right))
}

fn shard_placements_match(left: &ShardPlacement, right: &ShardPlacement) -> bool {
    left.shard_index == right.shard_index
        && left.shard_id == right.shard_id
        && left.node_id == right.node_id
        && left.node_public_key == right.node_public_key
        && left.endpoint == right.endpoint
        && left.failure_domain == right.failure_domain
        && left.region == right.region
}
#[cfg(any())]
fn plan_matches_shard_ids(plan: &PlacementPlan, shard_ids: &[ShardId]) -> bool {
    plan.placements.len() == shard_ids.len()
        && plan
            .placements
            .iter()
            .enumerate()
            .all(|(index, placement)| {
                placement.shard_index == index && placement.shard_id == shard_ids[index]
            })
}
#[cfg(any())]
fn cached_plan_uses_current_candidates(plan: &PlacementPlan, candidates: &[NodeCandidate]) -> bool {
    plan.placements.iter().all(|placement| {
        candidates.iter().any(|candidate| {
            candidate.node_id == placement.node_id
                && candidate.public_key == placement.node_public_key
                && candidate.endpoint == placement.endpoint
                && candidate.failure_domain == placement.failure_domain
                && candidate.region == placement.region
        })
    })
}
#[cfg(any())]
fn cached_plan_satisfies_policy(plan: &PlacementPlan, policy: &PlacementPolicy) -> bool {
    if policy.min_unique_nodes > 0 {
        let nodes: BTreeSet<_> = plan
            .placements
            .iter()
            .map(|placement| placement.node_id.0.as_str())
            .collect();
        if nodes.len() < policy.min_unique_nodes {
            return false;
        }
    }
    if policy.min_failure_domains > 0 {
        let domains: BTreeSet<_> = plan
            .placements
            .iter()
            .map(|placement| placement.failure_domain.as_str())
            .collect();
        if domains.len() < policy.min_failure_domains {
            return false;
        }
    }
    true
}

pub(crate) async fn upload_repair_shards(
    client: &reqwest::Client,
    plan: &PlacementPlan,
    shards: &[Vec<u8>],
    shard_indexes: &[usize],
    private_key: &str,
    expires_at: &str,
) -> Result<Vec<ShardReceipt>> {
    let delete_authority_hash = delete_authority_hash_from_private_key(private_key)?;
    let expires_at = validated_expires_at(expires_at)?;
    let mut receipts = Vec::with_capacity(shard_indexes.len());

    for shard_index in shard_indexes {
        let placement = plan
            .placements
            .iter()
            .find(|placement| placement.shard_index == *shard_index)
            .context("repair placement missing shard index")?;
        let bytes = shards
            .get(*shard_index)
            .context("repair shard index outside encoded shards")?;
        let actual = confidis_crypto::blake3_hex(bytes);
        if actual != placement.shard_id.0 {
            bail!(
                "repair shard {} hash changed: expected {}, got {}",
                placement.shard_index,
                placement.shard_id.0,
                actual
            );
        }

        let url = format!(
            "{}/shards/{}",
            placement.endpoint.trim_end_matches('/'),
            placement.shard_id.0
        );
        let proof =
            crate::network::node_access_proof_headers(private_key, "PUT", &placement.shard_id.0)?;
        let (status, text) = send_upload_with_retry(
            || {
                let mut req = client
                    .put(&url)
                    .header("x-confidis-delete-authority-hash", &delete_authority_hash)
                    .header("x-confidis-expires-at", &expires_at);
                for (k, v) in &proof {
                    req = req.header(*k, v);
                }
                Ok(req)
            },
            bytes.clone(),
        )
        .await?;
        if !status.is_success() {
            bail!(
                "repair upload failed for shard {} to {}: {status} {text}",
                placement.shard_index,
                placement.endpoint
            );
        }
        receipts.push(parse_and_verify_receipt(
            &text,
            &placement.shard_id,
            ShardReceiptType::Stored,
            Some(&placement.node_id),
            placement.node_public_key.as_deref(),
        )?);
    }

    Ok(receipts)
}

pub(crate) async fn upload_shard_to_endpoint(
    client: &reqwest::Client,
    endpoint: &str,
    shard_id: &ShardId,
    bytes: &[u8],
    private_key: &str,
    expires_at: &str,
) -> Result<ShardReceipt> {
    let actual = confidis_crypto::blake3_hex(bytes);
    if actual != shard_id.0 {
        bail!(
            "shard hash changed: expected {}, got {}",
            shard_id.0,
            actual
        );
    }

    let url = format!("{}/shards/{}", endpoint.trim_end_matches('/'), shard_id.0);
    let proof = crate::network::node_access_proof_headers(private_key, "PUT", &shard_id.0)?;
    let delete_authority_hash = delete_authority_hash_from_private_key(private_key)?;
    let expires_at = validated_expires_at(expires_at)?;
    let (status, text) = send_upload_with_retry(
        || {
            let mut req = client
                .put(&url)
                .header("x-confidis-delete-authority-hash", &delete_authority_hash)
                .header("x-confidis-expires-at", &expires_at);
            for (k, v) in &proof {
                req = req.header(*k, v);
            }
            Ok(req)
        },
        bytes.to_vec(),
    )
    .await?;
    if !status.is_success() {
        bail!(
            "upload failed for shard {} to {endpoint}: {status} {text}",
            shard_id.0
        );
    }
    let receipt = parse_and_verify_receipt(&text, shard_id, ShardReceiptType::Stored, None, None)?;
    Ok(receipt)
}

pub(crate) async fn fetch_shard_from_hints(
    client: &reqwest::Client,
    shard_id: &ShardId,
    provider_hints: &[String],
    node_private_key: Option<&str>,
) -> Result<(String, Vec<u8>)> {
    for endpoint in provider_hints {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let url = format!("{}/shards/{}", endpoint, shard_id.0);
        let mut req = client.get(url);
        if let Some(pk) = node_private_key {
            for (k, v) in &crate::network::node_access_proof_headers(pk, "GET", &shard_id.0)? {
                req = req.header(*k, v);
            }
        }
        let response = match req.send().await {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let bytes = response.bytes().await?.to_vec();
        if confidis_crypto::blake3_hex(&bytes) == shard_id.0 {
            return Ok((endpoint, bytes));
        }
    }
    bail!("no valid provider found for shard {}", shard_id.0)
}

pub(crate) async fn verify_remote_shard(
    client: &reqwest::Client,
    endpoint: &str,
    shard_id: &ShardId,
) -> Result<()> {
    let url = format!("{}/shards/{}", endpoint.trim_end_matches('/'), shard_id.0);
    let response = client.get(url).send().await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        bail!(
            "target verification failed for shard {} at {}: {status} {}",
            shard_id.0,
            endpoint,
            String::from_utf8_lossy(&bytes)
        );
    }
    let actual = confidis_crypto::blake3_hex(&bytes);
    if actual != shard_id.0 {
        bail!(
            "target verification hash mismatch for shard {} at {}: got {}",
            shard_id.0,
            endpoint,
            actual
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex};
    use confidis_protocol::{NodeId, ShardReceiptType};

    #[tokio::test]
    async fn resumable_upload_uses_verified_cached_receipt_without_reading_shard_file() {
        let temp = unique_temp_dir("confidis-placement-upload-cache");
        let shard_dir = temp.join("shards");
        fs::create_dir_all(&shard_dir).expect("create shard dir");

        let node_key = generate_signing_key();
        let node_public_key = verifying_key_to_hex(&node_key.verifying_key());
        let shard_id = ShardId(confidis_crypto::blake3_hex(b"cached shard bytes"));
        let plan = PlacementPlan {
            version: 1,
            group_id: "cache-test-group".to_string(),
            erasure_policy: ErasurePolicy::default(),
            placements: vec![ShardPlacement {
                shard_index: 0,
                shard_id: shard_id.clone(),
                node_id: NodeId("cache-node".to_string()),
                node_public_key: Some(node_public_key.clone()),
                endpoint: "http://127.0.0.1:9".to_string(),
                failure_domain: "fd-cache".to_string(),
                region: "eu-test".to_string(),
            }],
            created_at: chrono::Utc::now(),
        };
        let mut receipt = ShardReceipt {
            version: 1,
            receipt_id: uuid::Uuid::new_v4(),
            receipt_type: ShardReceiptType::Stored,
            node_id: NodeId("cache-node".to_string()),
            public_key: Some(node_public_key),
            shard_id: shard_id.clone(),
            issued_at: chrono::Utc::now(),
            size_bytes: 18,
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            signature: None,
        };
        let payload = confidis_protocol::shard_receipt_signing_payload(&receipt)
            .expect("receipt signing payload");
        receipt.signature = Some(sign_hex(&node_key, &payload));

        let cache_path = temp.join("upload-cache").join("seg-0000.json");
        persist_upload_cache(
            Some(&cache_path),
            &PlacementUploadCache {
                version: UPLOAD_CACHE_VERSION,
                plan: plan.clone(),
                receipts: vec![receipt.clone()],
                provider_records: Vec::new(),
            },
        )
        .expect("write upload cache");

        let owner_key = generate_signing_key();
        let client = reqwest::Client::new();
        let upload = upload_plan_with_provider_context_resumable(
            &client,
            &plan,
            &shard_dir,
            &confidis_crypto::signing_key_to_hex(&owner_key),
            &(chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
            None,
            None,
            Some(&cache_path),
        )
        .await
        .expect("cached upload should not touch network or shard file");

        assert_eq!(upload.receipts.len(), 1);
        assert_eq!(upload.receipts[0].receipt_id, receipt.receipt_id);
        let _ = fs::remove_dir_all(temp);
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}
