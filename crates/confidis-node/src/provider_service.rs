//! Minimal provider-record registry for shard discovery.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use chrono::Utc;
use confidis_protocol::{
    ShardId, ShardProviderList, ShardProviderRecord, verify_shard_provider_record,
};

use crate::error::ApiError;
use crate::node_info_service::HealthResponse;
use crate::state::{MAX_PROVIDER_RECORD_SHARDS, MAX_PROVIDER_RECORDS_PER_SHARD, NodeState};

pub(crate) async fn providers_for_shard(
    State(state): State<Arc<NodeState>>,
    AxumPath(shard_id): AxumPath<String>,
) -> Json<ShardProviderList> {
    let now = Utc::now();
    let ban_list = valid_node_ban_list(&state, now).await;
    let records = state.provider_records.read().await;
    let providers = records
        .get(&shard_id)
        .map(|items| {
            items
                .iter()
                .filter(|record| record.expires_at.is_none_or(|expires_at| now < expires_at))
                .filter(|record| {
                    ban_list
                        .as_ref()
                        .is_none_or(|list| !list.is_banned(&record.public_key))
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    Json(ShardProviderList {
        version: 1,
        issued_at: now,
        shard_id: ShardId(shard_id),
        providers,
    })
}

pub(crate) async fn announce_provider_record(
    State(state): State<Arc<NodeState>>,
    Json(record): Json<ShardProviderRecord>,
) -> Result<Json<HealthResponse>, ApiError> {
    verify_shard_provider_record(&record)
        .map_err(|_| ApiError::unauthorized("invalid provider record signature"))?;
    if provider_public_key_is_banned(&state, &record.public_key, Utc::now()).await {
        return Err(ApiError::forbidden(
            "node is banned/quarantined by the CONFIDIS authority",
        ));
    }

    let snapshot = {
        let mut records = state.provider_records.write().await;
        let shard_id = record.shard_id.0.clone();
        if !records.contains_key(&shard_id) && records.len() >= MAX_PROVIDER_RECORD_SHARDS {
            return Err(ApiError::status(
                axum::http::StatusCode::INSUFFICIENT_STORAGE,
                "provider_registry_full",
                "provider registry shard limit reached",
            ));
        }
        let now = Utc::now();
        let entry = records.entry(shard_id).or_default();
        entry.retain(|existing| {
            existing
                .expires_at
                .is_none_or(|expires_at| now < expires_at)
                && existing.provider_record_id != record.provider_record_id
                && !(existing.shard_id == record.shard_id
                    && existing.node_id == record.node_id
                    && existing.endpoint == record.endpoint)
        });
        entry.push(record);
        entry.sort_by_key(|record| std::cmp::Reverse(record.issued_at));
        entry.truncate(MAX_PROVIDER_RECORDS_PER_SHARD);
        records
            .values()
            .flat_map(|records| records.iter().cloned())
            .collect::<Vec<_>>()
    };

    if let Err(err) =
        crate::provider_cache::persist_provider_cache(&state.config.store_path, snapshot).await
    {
        tracing::warn!(error = %err, "failed to persist provider cache");
    }

    Ok(Json(HealthResponse {
        status: "ok",
        node_id: state.config.node_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        shard_count: 0,
        peer_count: state.routing_table.read().await.len(),
        discovery_backend: state.config.discovery_backend.clone(),
        kademlia_enabled: state.config.discovery_backend == "hybrid_kademlia",
        ban_verification_enabled: state.config.confidis_root_pubkey.is_some(),
        noise_sessions: state.noise_sessions.read().await.len(),
        node_ban_list_present: state.node_ban_list.read().await.is_some(),
        node_banned: false,
        trust_root_source: state.config.confidis_root_source.clone(),
        listen_port: state.config.listen_addr.port(),
        webui_enabled: state.config.webui_path.is_some(),
        content_dir_enabled: state.config.content_dir.is_some(),
        ui_auth_required: !state.config.production_profile && state.config.ui_token.is_some(),
        ui_cors_restricted: state.config.ui_allowed_origin.is_some(),
        operator_ui_enabled: !state.config.production_profile,
        public_ui_only: state.config.production_profile,
    }))
}

async fn provider_public_key_is_banned(
    state: &Arc<NodeState>,
    public_key: &str,
    now: chrono::DateTime<Utc>,
) -> bool {
    valid_node_ban_list(state, now)
        .await
        .as_ref()
        .is_some_and(|list| list.is_banned(public_key))
}

async fn valid_node_ban_list(
    state: &Arc<NodeState>,
    now: chrono::DateTime<Utc>,
) -> Option<confidis_protocol::NodeBanList> {
    let root = state.config.confidis_root_pubkey.as_ref()?;
    let list = state.node_ban_list.read().await;
    let list = list.as_ref()?;
    (confidis_protocol::verify_node_ban_list(list, root, now).is_ok()).then(|| list.clone())
}
