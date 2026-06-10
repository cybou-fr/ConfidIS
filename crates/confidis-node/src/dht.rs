use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use confidis_crypto::{verify_hex, verifying_key_from_hex, verifying_key_to_hex};
use confidis_protocol::{
    CellulePublicRecord, PeerRecord, ShardProviderRecord, peer_record_signing_payload,
    verify_cellule_public_record, verify_shard_provider_record,
};
use futures::StreamExt;
use libp2p::kad::{self, GetRecordOk, QueryResult, Quorum, Record, RecordKey, store::MemoryStore};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder, identity, noise, tcp, yamux};
use libp2p::{identify, relay};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::signing::sign_peer_record;
use crate::state::{
    MAX_CELLULE_RECORDS, MAX_PROVIDER_RECORD_SHARDS, MAX_PROVIDER_RECORDS_PER_SHARD,
    MAX_ROUTING_TABLE_SIZE, NodeState,
};
use crate::util::normalize_endpoint;
use crate::workers::{
    record_maintenance_attention, record_maintenance_start, record_maintenance_success,
};

const DEFAULT_KADEMLIA_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/0";
const PUBLISH_INTERVAL_SECS: u64 = 60;
const QUERY_INTERVAL_SECS: u64 = 45;
const MAX_DHT_PROVIDER_LIST: usize = 32;
const MAX_DHT_INDEX_KEYS_PER_KIND: usize = 512;
const MAX_DHT_RECORD_BYTES: usize = 512 * 1024;
const DHT_INDEX_SLOT_SECS: i64 = 300;
const DHT_INDEX_LOOKBACK_SLOTS: i64 = 3;
const KADEMLIA_IDENTITY_FILE: &str = ".confidis_kademlia_identity";

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ConfidISDhtEvent", prelude = "libp2p::swarm::derive_prelude")]
struct ConfidISDhtBehaviour {
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    relay: relay::client::Behaviour,
}

enum ConfidISDhtEvent {
    Kademlia(kad::Event),
    Identify(identify::Event),
    Relay(relay::client::Event),
}

impl From<kad::Event> for ConfidISDhtEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kademlia(event)
    }
}

impl From<identify::Event> for ConfidISDhtEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<relay::client::Event> for ConfidISDhtEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::Relay(event)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
enum ConfidISDhtPayload {
    Peer(PeerRecord),
    ProviderList(Vec<ShardProviderRecord>),
    Cellule(CellulePublicRecord),
    Index(ConfidISDhtIndex),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfidISDhtIndex {
    issued_at: DateTime<Utc>,
    peer_keys: Vec<String>,
    provider_keys: Vec<String>,
    cellule_keys: Vec<String>,
}

struct ParsedBootstrapPeer {
    peer_id: Option<PeerId>,
    address: Multiaddr,
}

pub(crate) fn start_kademlia_worker(state: Arc<NodeState>, mut shutdown_rx: watch::Receiver<bool>) {
    if state.config.discovery_backend != "hybrid_kademlia" {
        return;
    }

    tokio::spawn(async move {
        if let Err(err) = run_kademlia_worker(state.clone(), &mut shutdown_rx).await {
            record_maintenance_attention(
                &state,
                "kademlia",
                "Hybrid Kademlia discovery",
                err.to_string(),
                None,
            )
            .await;
            tracing::warn!(error = %err, "Kademlia worker stopped");
        }
    });
}

async fn run_kademlia_worker(
    state: Arc<NodeState>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    let local_key = load_or_create_kademlia_identity(&state.config.store_path)?;
    let local_peer_id = local_key.public().to_peer_id();
    let mut swarm = build_kademlia_swarm(local_key)?;
    record_maintenance_start(
        &state,
        "kademlia",
        "Hybrid Kademlia discovery",
        Some(format!(
            "starting peer_id={local_peer_id}, bootstrap_peers={}, relay_peers={}",
            state.config.kademlia_bootstrap_peers.len(),
            state.config.kademlia_relay_peers.len()
        )),
    )
    .await;
    record_dht_event("worker_start");

    let listen_addr = state
        .config
        .kademlia_listen_addr
        .as_deref()
        .unwrap_or(DEFAULT_KADEMLIA_LISTEN_ADDR)
        .parse::<Multiaddr>()
        .context("invalid kademlia_listen_addr multiaddr")?;
    swarm.listen_on(listen_addr)?;

    let mut bootstrap_count = 0usize;
    for raw in &state.config.kademlia_bootstrap_peers {
        match parse_bootstrap_multiaddr(raw) {
            Ok(peer) => {
                if let Some(peer_id) = peer.peer_id {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, peer.address.clone());
                    if let Err(err) = swarm.dial(peer.address.with(Protocol::P2p(peer_id))) {
                        tracing::debug!(peer = raw, error = %err, "failed to dial Kademlia bootstrap peer");
                    }
                } else if let Err(err) = swarm.dial(peer.address) {
                    tracing::debug!(peer = raw, error = %err, "failed to dial Kademlia bootstrap peer");
                }
                bootstrap_count += 1;
            }
            Err(err) => {
                tracing::warn!(peer = raw, error = %err, "invalid Kademlia bootstrap peer");
            }
        }
    }
    if bootstrap_count > 0 {
        let _ = swarm.behaviour_mut().kademlia.bootstrap();
    }
    configure_relay_peers(&mut swarm, &state).await;

    tracing::info!(
        peer_id = %local_peer_id,
        bootstrap_count,
        "started CONFIDIS hybrid Kademlia discovery"
    );

    let mut publish_interval = tokio::time::interval(Duration::from_secs(dht_interval_secs(
        "CONFIDIS_DHT_PUBLISH_INTERVAL_SECS",
        PUBLISH_INTERVAL_SECS,
    )));
    let mut query_interval = tokio::time::interval(Duration::from_secs(dht_interval_secs(
        "CONFIDIS_DHT_QUERY_INTERVAL_SECS",
        QUERY_INTERVAL_SECS,
    )));

    loop {
        tokio::select! {
            _ = publish_interval.tick() => {
                publish_snapshot(&mut swarm, &state).await;
            }
            _ = query_interval.tick() => {
                query_known_records(&mut swarm, &state).await;
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(event, &mut swarm, &state).await;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() {
                    tracing::info!("Kademlia worker shutdown requested");
                }
                break;
            }
        }
    }

    Ok(())
}

fn build_kademlia_swarm(local_key: identity::Keypair) -> Result<libp2p::Swarm<ConfidISDhtBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay| {
            let peer_id = key.public().to_peer_id();
            let store = MemoryStore::new(peer_id);
            let mut kademlia = kad::Behaviour::new(peer_id, store);
            kademlia.set_mode(Some(kad::Mode::Server));
            let identify = identify::Behaviour::new(
                identify::Config::new_with_signed_peer_record(
                    "/confidis/identify/1.0".to_string(),
                    key,
                )
                .with_agent_version(format!("confidis-node/{}", env!("CARGO_PKG_VERSION")))
                .with_push_listen_addr_updates(true),
            );
            ConfidISDhtBehaviour {
                kademlia,
                identify,
                relay,
            }
        })?
        .build();
    Ok(swarm)
}

fn load_or_create_kademlia_identity(store_path: &Path) -> Result<identity::Keypair> {
    let path = store_path.join(KADEMLIA_IDENTITY_FILE);
    if path.exists() {
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read Kademlia identity {}", path.display()))?;
        return identity::Keypair::from_protobuf_encoding(&bytes)
            .with_context(|| format!("invalid Kademlia identity {}", path.display()));
    }
    fs::create_dir_all(store_path)
        .with_context(|| format!("failed to create store path {}", store_path.display()))?;
    let key = identity::Keypair::generate_ed25519();
    let bytes = key
        .to_protobuf_encoding()
        .context("failed to encode Kademlia identity")?;
    fs::write(&path, bytes)
        .with_context(|| format!("failed to write Kademlia identity {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod 0600 {}", path.display()))?;
    }
    Ok(key)
}

async fn configure_relay_peers(
    swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>,
    state: &Arc<NodeState>,
) {
    for raw in &state.config.kademlia_relay_peers {
        match parse_bootstrap_multiaddr(raw) {
            Ok(ParsedBootstrapPeer {
                peer_id: Some(peer_id),
                address,
            }) => {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, address.clone());
                let relay_address = address.with(Protocol::P2p(peer_id));
                if let Err(err) = swarm.dial(relay_address.clone()) {
                    tracing::debug!(peer = raw, error = %err, "failed to dial Kademlia relay peer");
                    record_dht_event("relay_dial_error");
                } else {
                    record_dht_event("relay_dial");
                }
                if let Err(err) = swarm.listen_on(relay_address.with(Protocol::P2pCircuit)) {
                    tracing::warn!(peer = raw, error = %err, "failed to reserve Kademlia relay circuit");
                    record_dht_event("relay_reservation_error");
                } else {
                    record_dht_event("relay_reservation_requested");
                    record_maintenance_success(
                        state,
                        "kademlia",
                        "Hybrid Kademlia discovery",
                        Some(format!("requested relay reservation via {peer_id}")),
                    )
                    .await;
                }
            }
            Ok(ParsedBootstrapPeer { peer_id: None, .. }) => {
                tracing::warn!(
                    peer = raw,
                    "Kademlia relay peer must include /p2p/<relay-peer-id>"
                );
                record_dht_event("relay_invalid");
            }
            Err(err) => {
                tracing::warn!(peer = raw, error = %err, "invalid Kademlia relay peer");
                record_dht_event("relay_invalid");
            }
        }
    }
}

async fn publish_snapshot(swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>, state: &Arc<NodeState>) {
    if let Some(record) = build_self_peer_record(state).await {
        publish_payload(
            swarm,
            peer_record_key(&record),
            ConfidISDhtPayload::Peer(record),
        );
    }

    let provider_lists = {
        let now = Utc::now();
        let records = state.provider_records.read().await;
        records
            .iter()
            .filter_map(|(shard_id, records)| {
                let mut fresh = records
                    .iter()
                    .filter(|record| record.expires_at.is_some_and(|expires_at| now < expires_at))
                    .filter(|record| verify_shard_provider_record(record).is_ok())
                    .cloned()
                    .collect::<Vec<_>>();
                fresh.sort_by_key(|record| std::cmp::Reverse(record.issued_at));
                fresh.truncate(MAX_DHT_PROVIDER_LIST);
                (!fresh.is_empty()).then(|| (shard_id.clone(), fresh))
            })
            .collect::<Vec<_>>()
    };
    for (shard_id, records) in provider_lists {
        publish_payload(
            swarm,
            provider_record_key(&shard_id),
            ConfidISDhtPayload::ProviderList(records),
        );
    }

    let cellule_records = {
        let now = Utc::now();
        let records = state.cellule_records.read().await;
        records
            .values()
            .filter(|record| now < record.expires_at)
            .filter(|record| verify_cellule_public_record(record).is_ok())
            .cloned()
            .collect::<Vec<_>>()
    };
    for record in cellule_records {
        publish_payload(
            swarm,
            cellule_record_key(&record.cellule_id.0),
            ConfidISDhtPayload::Cellule(record),
        );
    }

    let index = build_dht_index(state).await;
    let current_slot = dht_index_slot(Utc::now());
    for slot in [current_slot, current_slot - 1] {
        publish_payload(
            swarm,
            dht_index_key(slot),
            ConfidISDhtPayload::Index(index.clone()),
        );
    }
    record_dht_event("publish_snapshot");
}

async fn query_known_records(swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>, state: &Arc<NodeState>) {
    let peer_keys = {
        let table = state.routing_table.read().await;
        table.values().map(peer_record_key).collect::<Vec<_>>()
    };
    let provider_keys = {
        let records = state.provider_records.read().await;
        records
            .keys()
            .map(|key| provider_record_key(key))
            .collect::<Vec<_>>()
    };
    let cellule_keys = {
        let records = state.cellule_records.read().await;
        records
            .keys()
            .map(|key| cellule_record_key(key))
            .collect::<Vec<_>>()
    };

    for key in peer_keys
        .into_iter()
        .chain(provider_keys)
        .chain(cellule_keys)
    {
        swarm.behaviour_mut().kademlia.get_record(key);
    }
    query_dht_index_records(swarm);
    record_dht_event("query_snapshot");
}

fn query_dht_index_records(swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>) {
    let current_slot = dht_index_slot(Utc::now());
    for offset in 0..DHT_INDEX_LOOKBACK_SLOTS {
        swarm
            .behaviour_mut()
            .kademlia
            .get_record(dht_index_key(current_slot - offset));
    }
}

async fn handle_swarm_event(
    event: SwarmEvent<ConfidISDhtEvent>,
    swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>,
    state: &Arc<NodeState>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::info!(address = %address, "Kademlia listening");
            record_dht_event("listen_addr");
            record_maintenance_success(
                state,
                "kademlia",
                "Hybrid Kademlia discovery",
                Some(format!("listening on {address}")),
            )
            .await;
        }
        SwarmEvent::Behaviour(ConfidISDhtEvent::Kademlia(kad::Event::OutboundQueryProgressed {
            result: QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(record))),
            ..
        })) => {
            import_dht_record(record.record.value, swarm, state).await;
        }
        SwarmEvent::Behaviour(ConfidISDhtEvent::Kademlia(kad::Event::OutboundQueryProgressed {
            result: QueryResult::PutRecord(Ok(_)),
            ..
        })) => {
            tracing::debug!("published Kademlia record");
            record_dht_event("put_record_ok");
        }
        SwarmEvent::Behaviour(ConfidISDhtEvent::Kademlia(kad::Event::OutboundQueryProgressed {
            result: QueryResult::Bootstrap(Ok(_)),
            ..
        })) => {
            tracing::debug!("Kademlia bootstrap progressed");
            record_dht_event("bootstrap_ok");
        }
        SwarmEvent::Behaviour(ConfidISDhtEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            let listen_addr_count = info.listen_addrs.len();
            for address in info.listen_addrs {
                tracing::debug!(peer = %peer_id, address = %address, "learned Kademlia peer address via Identify");
                // Rust-libp2p intentionally keeps Identify separate from Kademlia;
                // feed signed/self-reported listen addresses into the DHT routing table.
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, address);
            }
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
            record_dht_event("identify_received");
            record_maintenance_success(
                state,
                "kademlia",
                "Hybrid Kademlia discovery",
                Some(format!(
                    "identified peer {peer_id} with {} listen address(es)",
                    listen_addr_count
                )),
            )
            .await;
        }
        SwarmEvent::Behaviour(ConfidISDhtEvent::Relay(event)) => {
            tracing::debug!(?event, "Kademlia relay client event");
            record_dht_event("relay_event");
        }
        _ => {}
    }
}

fn publish_payload(
    swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>,
    key: RecordKey,
    payload: ConfidISDhtPayload,
) {
    let Ok(value) = serde_json::to_vec(&payload) else {
        return;
    };
    if value.len() > MAX_DHT_RECORD_BYTES {
        tracing::warn!(bytes = value.len(), "skipping oversized Kademlia record");
        record_dht_event("put_record_oversized");
        return;
    }
    if let Err(err) = swarm
        .behaviour_mut()
        .kademlia
        .put_record(Record::new(key, value), Quorum::One)
    {
        tracing::debug!(error = %err, "failed to publish Kademlia record");
        record_dht_event("put_record_error");
    }
}

async fn import_dht_record(
    value: Vec<u8>,
    swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>,
    state: &Arc<NodeState>,
) {
    if value.len() > MAX_DHT_RECORD_BYTES {
        return;
    }
    let Ok(payload) = serde_json::from_slice::<ConfidISDhtPayload>(&value) else {
        return;
    };
    match payload {
        ConfidISDhtPayload::Peer(record) => import_peer_record(record, state).await,
        ConfidISDhtPayload::ProviderList(records) => import_provider_records(records, state).await,
        ConfidISDhtPayload::Cellule(record) => import_cellule_record(record, state).await,
        ConfidISDhtPayload::Index(index) => import_dht_index(index, swarm, state).await,
    }
}

async fn import_peer_record(record: PeerRecord, state: &Arc<NodeState>) {
    if !is_fresh_signed_peer_record(&record) {
        return;
    }
    if let Some(my_endpoint) = &state.config.public_endpoint
        && normalize_endpoint(&record.endpoint) == normalize_endpoint(my_endpoint)
    {
        return;
    }
    let key = normalize_endpoint(&record.endpoint);
    let issued_at = record.issued_at;
    let mut table = state.routing_table.write().await;
    if table.len() >= MAX_ROUTING_TABLE_SIZE && !table.contains_key(&key) {
        return;
    }
    table.insert(key, record);
    let snapshot = table.values().cloned().collect::<Vec<_>>();
    drop(table);
    if let Some(issued_at) = issued_at {
        record_dht_import("peer", Some(propagation_lag_ms(issued_at)));
    } else {
        record_dht_import("peer", None);
    }
    if let Err(err) = crate::peer_cache::persist_peer_cache(
        &state.config.store_path,
        snapshot,
        state.config.public_endpoint.as_deref(),
    )
    .await
    {
        tracing::warn!(error = %err, "failed to persist DHT-imported peer cache");
    }
}

async fn import_provider_records(records: Vec<ShardProviderRecord>, state: &Arc<NodeState>) {
    let mut accepted_lags = Vec::new();
    let snapshot = {
        let mut changed = false;
        let mut registry = state.provider_records.write().await;
        let now = Utc::now();
        for record in records {
            if verify_shard_provider_record(&record).is_err() {
                continue;
            }
            let shard_id = record.shard_id.0.clone();
            if !registry.contains_key(&shard_id) && registry.len() >= MAX_PROVIDER_RECORD_SHARDS {
                continue;
            }
            accepted_lags.push(propagation_lag_ms(record.issued_at));
            let entry = registry.entry(shard_id).or_default();
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
            changed = true;
        }
        changed.then(|| {
            registry
                .values()
                .flat_map(|records| records.iter().cloned())
                .collect::<Vec<_>>()
        })
    };
    for lag_ms in accepted_lags {
        record_dht_import("provider", Some(lag_ms));
    }
    if let Some(snapshot) = snapshot
        && let Err(err) =
            crate::provider_cache::persist_provider_cache(&state.config.store_path, snapshot).await
    {
        tracing::warn!(error = %err, "failed to persist DHT-imported provider cache");
    }
}

async fn import_cellule_record(record: CellulePublicRecord, state: &Arc<NodeState>) {
    if verify_cellule_public_record(&record).is_err() {
        return;
    }
    let snapshot = {
        let mut records = state.cellule_records.write().await;
        let cellule_id = record.cellule_id.0.clone();
        if !records.contains_key(&cellule_id) && records.len() >= MAX_CELLULE_RECORDS {
            return;
        }
        if let Some(existing) = records.get(&cellule_id)
            && record.sequence < existing.sequence
        {
            return;
        }
        records.insert(cellule_id, record);
        records.values().cloned().collect::<Vec<_>>()
    };
    record_dht_import("cellule", None);
    if let Err(err) = crate::cellule_record_cache::persist_cellule_record_cache(
        &state.config.store_path,
        snapshot,
    )
    .await
    {
        tracing::warn!(error = %err, "failed to persist DHT-imported Cellule record cache");
    }
}

async fn import_dht_index(
    index: ConfidISDhtIndex,
    swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>,
    state: &Arc<NodeState>,
) {
    if !is_fresh_dht_index(&index) {
        return;
    }
    let total_keys = index.peer_keys.len() + index.provider_keys.len() + index.cellule_keys.len();
    if total_keys == 0 {
        return;
    }
    for key in index
        .peer_keys
        .into_iter()
        .chain(index.provider_keys)
        .chain(index.cellule_keys)
        .filter(|key| is_indexed_dht_key(key))
    {
        swarm
            .behaviour_mut()
            .kademlia
            .get_record(RecordKey::new(&key));
    }
    record_dht_import("index", Some(propagation_lag_ms(index.issued_at)));
    record_maintenance_success(
        state,
        "kademlia",
        "Hybrid Kademlia discovery",
        Some(format!("imported DHT index with {total_keys} key(s)")),
    )
    .await;
}

async fn build_self_peer_record(state: &Arc<NodeState>) -> Option<PeerRecord> {
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

fn is_fresh_signed_peer_record(record: &PeerRecord) -> bool {
    let (Some(public_key), Some(issued_at), Some(expires_at), Some(signature)) = (
        record.public_key.as_deref(),
        record.issued_at,
        record.expires_at,
        record.signature.as_deref(),
    ) else {
        return false;
    };
    if expires_at <= issued_at {
        return false;
    }
    let now = Utc::now();
    if now >= expires_at
        || issued_at > now + chrono::Duration::minutes(5)
        || now - issued_at > chrono::Duration::minutes(15)
    {
        return false;
    }
    let Ok(key) = verifying_key_from_hex(public_key) else {
        return false;
    };
    let Ok(payload) = peer_record_signing_payload(record) else {
        return false;
    };
    verify_hex(&key, &payload, signature).is_ok()
}

fn is_fresh_dht_index(index: &ConfidISDhtIndex) -> bool {
    if index.peer_keys.len() > MAX_DHT_INDEX_KEYS_PER_KIND
        || index.provider_keys.len() > MAX_DHT_INDEX_KEYS_PER_KIND
        || index.cellule_keys.len() > MAX_DHT_INDEX_KEYS_PER_KIND
    {
        return false;
    }
    let now = Utc::now();
    index.issued_at <= now + chrono::Duration::minutes(5)
        && now - index.issued_at <= chrono::Duration::minutes(20)
}

async fn build_dht_index(state: &Arc<NodeState>) -> ConfidISDhtIndex {
    let mut peer_keys = Vec::new();
    if let Some(record) = build_self_peer_record(state).await {
        peer_keys.push(record_key_to_string(peer_record_key(&record)));
    }
    {
        let table = state.routing_table.read().await;
        peer_keys.extend(
            table
                .values()
                .map(|record| record_key_to_string(peer_record_key(record))),
        );
    }
    peer_keys.sort();
    peer_keys.dedup();
    peer_keys.truncate(MAX_DHT_INDEX_KEYS_PER_KIND);

    let mut provider_keys = {
        let records = state.provider_records.read().await;
        records
            .keys()
            .map(|key| record_key_to_string(provider_record_key(key)))
            .collect::<Vec<_>>()
    };
    provider_keys.sort();
    provider_keys.dedup();
    provider_keys.truncate(MAX_DHT_INDEX_KEYS_PER_KIND);

    let mut cellule_keys = {
        let records = state.cellule_records.read().await;
        records
            .keys()
            .map(|key| record_key_to_string(cellule_record_key(key)))
            .collect::<Vec<_>>()
    };
    cellule_keys.sort();
    cellule_keys.dedup();
    cellule_keys.truncate(MAX_DHT_INDEX_KEYS_PER_KIND);

    ConfidISDhtIndex {
        issued_at: Utc::now(),
        peer_keys,
        provider_keys,
        cellule_keys,
    }
}

fn record_key_to_string(key: RecordKey) -> String {
    String::from_utf8_lossy(&key.to_vec()).to_string()
}

fn is_indexed_dht_key(key: &str) -> bool {
    key.starts_with("confidis/v1/peer/")
        || key.starts_with("confidis/v1/provider/")
        || key.starts_with("confidis/v1/cellule/")
}

fn dht_index_slot(now: DateTime<Utc>) -> i64 {
    now.timestamp().div_euclid(DHT_INDEX_SLOT_SECS)
}

fn dht_index_key(slot: i64) -> RecordKey {
    dht_key(&format!("index/{slot}"))
}

fn propagation_lag_ms(issued_at: DateTime<Utc>) -> u64 {
    (Utc::now() - issued_at).num_milliseconds().max(0) as u64
}

fn dht_interval_secs(env_name: &str, default_secs: u64) -> u64 {
    std::env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(default_secs)
}

fn record_dht_event(event_type: &str) {
    if let Some(metrics) = crate::metrics::ConfidISMetrics::global() {
        metrics.record_dht_event(event_type);
    }
}

fn record_dht_import(kind: &str, propagation_lag_ms: Option<u64>) {
    if let Some(metrics) = crate::metrics::ConfidISMetrics::global() {
        metrics.record_dht_import(kind, propagation_lag_ms);
    }
}

fn parse_bootstrap_multiaddr(raw: &str) -> Result<ParsedBootstrapPeer> {
    let mut address: Multiaddr = raw.parse().context("invalid multiaddr")?;
    let peer_id = match address.iter().last() {
        Some(Protocol::P2p(peer_id)) => {
            let _ = address.pop();
            Some(peer_id)
        }
        Some(_) => None,
        None => bail!("bootstrap multiaddr must not be empty"),
    };
    Ok(ParsedBootstrapPeer { peer_id, address })
}

fn peer_record_key(record: &PeerRecord) -> RecordKey {
    let identity = record
        .public_key
        .as_deref()
        .unwrap_or(record.endpoint.as_str());
    dht_key(&format!(
        "peer/{}",
        blake3::hash(identity.as_bytes()).to_hex()
    ))
}

fn provider_record_key(shard_id: &str) -> RecordKey {
    dht_key(&format!("provider/{shard_id}"))
}

fn cellule_record_key(cellule_id: &str) -> RecordKey {
    dht_key(&format!("cellule/{cellule_id}"))
}

fn dht_key(suffix: &str) -> RecordKey {
    RecordKey::new(&format!("confidis/v1/{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use libp2p::kad::store::RecordStore;

    #[test]
    fn parses_bootstrap_multiaddr_with_peer_id() {
        let peer_id = PeerId::random();
        let raw = format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer_id}");
        let parsed = parse_bootstrap_multiaddr(&raw).expect("multiaddr");
        assert_eq!(parsed.peer_id, Some(peer_id));
        assert_eq!(parsed.address.to_string(), "/ip4/127.0.0.1/tcp/4001");
    }

    #[test]
    fn parses_bootstrap_multiaddr_without_peer_id() {
        let parsed = parse_bootstrap_multiaddr("/dns4/confidis-bootstrap/tcp/4001")
            .expect("multiaddr without peer id");
        assert_eq!(parsed.peer_id, None);
        assert_eq!(parsed.address.to_string(), "/dns4/confidis-bootstrap/tcp/4001");
    }

    #[test]
    fn dht_keys_are_namespaced() {
        let key = cellule_record_key("abc").to_vec();
        let key = String::from_utf8(key).expect("utf8");
        assert_eq!(key, "confidis/v1/cellule/abc");
    }

    #[test]
    fn index_keys_accept_only_record_namespaces() {
        assert!(is_indexed_dht_key("confidis/v1/peer/abc"));
        assert!(is_indexed_dht_key("confidis/v1/provider/abc"));
        assert!(is_indexed_dht_key("confidis/v1/cellule/abc"));
        assert!(!is_indexed_dht_key("confidis/v1/index/123"));
        assert!(!is_indexed_dht_key("other/v1/peer/abc"));
    }

    #[test]
    fn kademlia_identity_persists_peer_id() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let first = load_or_create_kademlia_identity(temp.path())?;
        let second = load_or_create_kademlia_identity(temp.path())?;
        assert_eq!(first.public().to_peer_id(), second.public().to_peer_id());
        Ok(())
    }

    #[tokio::test]
    async fn kademlia_swarm_roundtrips_record_between_two_peers() -> Result<()> {
        let mut source = build_kademlia_swarm(identity::Keypair::generate_ed25519())?;
        let mut sink = build_kademlia_swarm(identity::Keypair::generate_ed25519())?;
        let source_peer_id = *source.local_peer_id();

        source.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
        let source_addr = wait_for_listen_addr(&mut source).await?;

        sink.behaviour_mut()
            .kademlia
            .add_address(&source_peer_id, source_addr.clone());
        sink.dial(source_addr.with(Protocol::P2p(source_peer_id)))?;

        let key = dht_key("test/runtime-roundtrip");
        let value = b"confidis-kademlia-runtime-proof".to_vec();
        source
            .behaviour_mut()
            .kademlia
            .store_mut()
            .put(Record::new(key.clone(), value.clone()))?;
        sink.behaviour_mut().kademlia.get_record(key);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = source.select_next_some() => {
                        let _ = event;
                    }
                    event = sink.select_next_some() => {
                        if let SwarmEvent::Behaviour(ConfidISDhtEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                            result: QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(record))),
                            ..
                        })) = event
                            && record.record.value == value
                        {
                            return Ok(());
                        }
                    }
                }
            }
        })
        .await
        .context("timed out waiting for Kademlia runtime roundtrip")?
    }

    async fn wait_for_listen_addr(
        swarm: &mut libp2p::Swarm<ConfidISDhtBehaviour>,
    ) -> Result<Multiaddr> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    return Ok(address);
                }
            }
        })
        .await
        .context("timed out waiting for Kademlia listen address")?
    }
}
