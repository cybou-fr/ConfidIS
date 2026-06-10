//! Peer admission and routing-table request handlers.
//!
//! Contains the HTTP handler functions for peer discovery and gossip:
//! `GET /peers`, `PUT /peers/announce`, `GET /uptime`, `PUT /uptime/announce`.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use chrono::Utc;
use confidis_crypto::{verify_hex, verifying_key_from_hex, verifying_key_to_hex};
use confidis_protocol::{NodeUptimeRecord, PeerList, PeerRecord, verify_uptime_record};

use crate::error::ApiError;
use crate::node_info_service::HealthResponse;
use crate::security_events::{SecurityEvent, SecurityEventSeverity, emit_security_event};
use crate::signing::sign_peer_record;
use crate::state::{MAX_ROUTING_TABLE_SIZE, NodeState};
use crate::util::normalize_endpoint;
use crate::validate::{ED25519_PUBKEY_HEX_LEN, ED25519_SIG_HEX_LEN, check_hex_len, check_str_len};

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /peers` — list all known peers (self + routing table).
pub(crate) async fn peers(State(state): State<Arc<NodeState>>) -> Json<PeerList> {
    let mut peers = Vec::new();
    if let Some(endpoint) = &state.config.public_endpoint {
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
        if let Err(err) = sign_peer_record(&mut record, state.config.signing_key.as_ref()) {
            tracing::warn!(error = %err, "failed to sign self peer record");
        }
        peers.push(record);
    }

    let now = Utc::now();
    let table = state.routing_table.read().await;
    for peer in table.values() {
        if peers.iter().any(|p| p.endpoint == peer.endpoint) {
            continue;
        }
        // Skip expired entries; keep bootstrap stubs (no expires_at)
        if peer.expires_at.is_some_and(|exp| now >= exp) {
            continue;
        }
        peers.push(peer.clone());
    }

    Json(PeerList {
        version: 1,
        issued_at: Utc::now(),
        peers,
    })
}

/// `GET /uptime` — return all known node uptime records (self + gossiped).
pub(crate) async fn uptime(State(state): State<Arc<NodeState>>) -> Json<Vec<NodeUptimeRecord>> {
    let table = state.uptime_table.read().await;
    Json(table.values().cloned().collect())
}

/// `PUT /uptime/announce` — receive a gossiped uptime record from a peer.
pub(crate) async fn announce_uptime(
    State(state): State<Arc<NodeState>>,
    Json(rec): Json<NodeUptimeRecord>,
) -> Result<Json<HealthResponse>, ApiError> {
    // Guard against unbounded string fields before signature verification.
    check_str_len(&rec.node_id, "node_id")?;
    check_str_len(&rec.endpoint, "endpoint")?;
    check_hex_len(
        &rec.ed25519_pubkey,
        "ed25519_pubkey",
        ED25519_PUBKEY_HEX_LEN,
    )?;
    if let Some(ref sig) = rec.signature {
        check_hex_len(sig, "signature", ED25519_SIG_HEX_LEN)?;
    }
    // Verify the record's self-signature before storing.
    verify_uptime_record(&rec)
        .map_err(|_| ApiError::unauthorized("invalid uptime record signature"))?;

    let mut table = state.uptime_table.write().await;
    let key = rec.node_id.clone();
    if table.len() < crate::state::MAX_UPTIME_TABLE_SIZE || table.contains_key(&key) {
        let entry = table.entry(key).or_insert_with(|| rec.clone());
        if rec.recorded_at > entry.recorded_at {
            *entry = rec;
        }
    }

    Ok(Json(ack_health(&state)))
}

/// Minimal `HealthResponse` acknowledgement returned by gossip/announce endpoints.
fn ack_health(state: &Arc<NodeState>) -> HealthResponse {
    HealthResponse {
        status: "ok",
        node_id: state.config.node_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        shard_count: 0,
        peer_count: 0,
        discovery_backend: state.config.discovery_backend.clone(),
        kademlia_enabled: state.config.discovery_backend == "hybrid_kademlia",
        ban_verification_enabled: state.config.confidis_root_pubkey.is_some(),
        noise_sessions: 0,
        node_ban_list_present: false,
        node_banned: false,
        trust_root_source: state.config.confidis_root_source.clone(),
        listen_port: state.config.listen_addr.port(),
        webui_enabled: state.config.webui_path.is_some(),
        content_dir_enabled: state.config.content_dir.is_some(),
        ui_auth_required: !state.config.production_profile && state.config.ui_token.is_some(),
        ui_cors_restricted: state.config.ui_allowed_origin.is_some(),
        operator_ui_enabled: !state.config.production_profile,
        public_ui_only: state.config.production_profile,
    }
}

/// `PUT /peers/announce` — receive a signed peer record and admit it to the routing table.
pub(crate) async fn announce_peer(
    State(state): State<Arc<NodeState>>,
    Json(record): Json<PeerRecord>,
) -> Result<Json<HealthResponse>, ApiError> {
    if record.endpoint.is_empty() {
        return Err(ApiError::bad_request("empty endpoint"));
    }
    // Guard against unbounded string fields before any crypto or table operations.
    check_str_len(&record.endpoint, "endpoint")?;
    if let Some(nid) = record.node_id.as_ref() {
        check_str_len(&nid.0, "node_id")?;
    }
    if let Some(ref pk) = record.public_key {
        check_hex_len(pk, "public_key", ED25519_PUBKEY_HEX_LEN)?;
    }
    if let Some(ref sig) = record.signature {
        check_hex_len(sig, "signature", ED25519_SIG_HEX_LEN)?;
    }
    if let Some(ref r) = record.region {
        check_str_len(r, "region")?;
    }
    if let Some(ref fd) = record.failure_domain {
        check_str_len(fd, "failure_domain")?;
    }
    // Anti-abuse: every announced peer record must be self-signed. This is NOT
    // an admission gate — anyone can generate a keypair and self-sign, so join
    // stays permissionless — but it stops trivial anonymous routing-table
    // poisoning by requiring a verifiable identity to bind/overwrite an entry.
    let (Some(pub_key), Some(sig)) = (&record.public_key, &record.signature) else {
        return Err(ApiError::unauthorized(
            "peer record must include public_key and signature (anonymous records are rejected)",
        ));
    };
    let key = verifying_key_from_hex(pub_key)
        .map_err(|_| ApiError::unauthorized("invalid public key hex"))?;
    let payload = confidis_protocol::peer_record_signing_payload(&record)
        .map_err(|_| ApiError::bad_request("invalid payload"))?;
    verify_hex(&key, &payload, sig).map_err(|_| ApiError::unauthorized("invalid signature"))?;

    let now = Utc::now();

    // Reject already-expired records.
    if let Some(expires_at) = record.expires_at
        && now >= expires_at
    {
        return Err(ApiError::bad_request("peer record has already expired"));
    }

    // Reject records with issued_at too far in the past (replay protection, 15-minute window).
    if let Some(issued_at) = record.issued_at {
        if now - issued_at > chrono::Duration::minutes(15) {
            return Err(ApiError::bad_request("peer record is too old"));
        }
        // Also reject issued_at suspiciously far in the future.
        if issued_at > now + chrono::Duration::minutes(5) {
            return Err(ApiError::bad_request(
                "peer record issued_at is in the future",
            ));
        }
    }

    // --- Peer admission ---
    // Node participation is PERMISSIONLESS: any signed peer record is admitted.
    // There is no membership certificate and no authority approval gate. The
    // only reactive control is the authority-signed node ban list: a peer whose
    // public key is banned/quarantined is refused. Economic access control
    if let Some(root_key) = &state.config.confidis_root_pubkey
        && let Some(record_pubkey) = record.public_key.as_deref()
    {
        let ban_list = state.node_ban_list.read().await;
        if let Some(list) = ban_list.as_ref()
            && confidis_protocol::verify_node_ban_list(list, root_key, now).is_ok()
            && list.is_banned(record_pubkey)
        {
            emit_security_event(
                &state,
                SecurityEvent::new(
                    &state,
                    "peer.admission_rejected",
                    SecurityEventSeverity::Warning,
                    "peer admission rejected: node is banned by CONFIDIS authority",
                )
                .with_context("endpoint", &record.endpoint)
                .with_context("pubkey", record_pubkey),
            );
            return Err(ApiError::forbidden(
                "node is banned/quarantined by the CONFIDIS authority",
            ));
        }
    }

    let key = normalize_endpoint(&record.endpoint);
    let mut table = state.routing_table.write().await;
    if table.len() >= MAX_ROUTING_TABLE_SIZE && !table.contains_key(&key) {
        return Err(ApiError::bad_request("routing table is full"));
    }
    table.insert(key, record);

    Ok(Json(ack_health(&state)))
}
