use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post, put};
use tokio::sync::watch;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::auth::{require_compliance_token, require_ui_token, security_headers};
use crate::cellule_record_service::{announce_cellule_record, cellule_record};
use crate::compliance_service::compliance_security_events;
use crate::config_manager::ConfidISConfig;
use crate::dht::start_kademlia_worker;
use crate::manifest_blob_service::{get_manifest_blob, put_manifest_blob};
use crate::middleware::{correlation_middleware, rate_limit_check};
use crate::node_info_service::{
    capacity, evidence_pack, evidence_pack_zip, health, list_cellules, maintenance_status, metrics,
    readiness,
};
use crate::noise_service::{noise_complete, noise_initiate};
use crate::operator_shared_service::{operator_shared_cellule, operator_shared_cellules};
use crate::owner_report_service::{owner_report_challenge, owner_report_verify};
use crate::peer_service::{announce_peer, announce_uptime, peers, uptime};
use crate::provider_service::{announce_provider_record, providers_for_shard};
use crate::public_info_service::{list_receipts, node_info};
use crate::rate_limit::RateLimiter;
use crate::read_access_service::{
    read_access_cellule_record, read_access_challenge, read_access_field_package,
    read_access_verify,
};
use crate::secure_shard_service::{get_shard_secure, put_shard_secure};
use crate::shard_service::{
    delete_shard, get_shard, put_shard, shard_status, shard_upload_receipt,
};
use crate::state::MAX_ROUTING_TABLE_SIZE;
use crate::state::NodeState;
use crate::util::normalize_endpoint;
use crate::wallet_cellule_service::{
    wallet_cellules_create, wallet_cellules_delete, wallet_cellules_renew, wallet_index,
};
use crate::wallet_package_service::{
    wallet_packages_create, wallet_packages_index, wallet_packages_remove,
};
use crate::workers::{
    start_audit_worker, start_cellule_record_gossip_worker, start_deletion_convergence_worker,
    start_discovery_worker, start_expiry_worker, start_integrity_worker,
    start_node_ban_list_worker, start_noise_cleanup_worker, start_provider_gossip_worker,
    start_rebalance_worker, start_repair_worker, start_uptime_gossip_worker,
};
use confidis_protocol::TransportPolicy;

/// Sustained requests per second allowed per server instance (global, not per-IP).
const RATE_LIMIT_PER_SECOND: u32 = 200;
/// Burst requests allowed at the start of a fresh window.
const RATE_LIMIT_BURST: u32 = 50;

pub async fn serve(config: ConfidISConfig) -> Result<()> {
    // Convert to legacy config format for backward compatibility
    let legacy_config = config.to_node_server_config()?;

    // Fail fast: validate config before allocating any resources.
    legacy_config.validate()?;

    // Initialize local tracing.
    crate::telemetry::init_telemetry("confidis-node", env!("CARGO_PKG_VERSION"))?;

    // Initialize metrics
    let _metrics = crate::metrics::init_metrics();

    // Initialize storage backend
    let storage_config = config.to_storage_config()?;
    let store = crate::storage_backend::StorageFactory::create(storage_config)?;

    let state = Arc::new(NodeState::new(
        legacy_config.clone(),
        store,
        Arc::new(RateLimiter::new(RATE_LIMIT_PER_SECOND, RATE_LIMIT_BURST)),
    ));

    {
        let mut table = state.routing_table.write().await;
        for endpoint in &legacy_config.bootstrap_peers {
            let endpoint = normalize_endpoint(endpoint);
            table.insert(
                endpoint.clone(),
                confidis_protocol::PeerRecord {
                    endpoint,
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
        for peer in crate::peer_cache::load_peer_cache(
            &legacy_config.store_path,
            legacy_config.public_endpoint.as_deref(),
        )
        .await
        {
            if table.len() >= MAX_ROUTING_TABLE_SIZE {
                break;
            }
            table
                .entry(normalize_endpoint(&peer.endpoint))
                .or_insert(peer);
        }
    }
    {
        let loaded = crate::provider_cache::load_provider_cache(&legacy_config.store_path).await;
        if !loaded.is_empty() {
            *state.provider_records.write().await = loaded;
        }
    }
    {
        let loaded =
            crate::cellule_record_cache::load_cellule_record_cache(&legacy_config.store_path).await;
        if !loaded.is_empty() {
            *state.cellule_records.write().await = loaded;
        }
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    start_expiry_worker(state.clone(), shutdown_rx.clone());
    start_integrity_worker(state.clone(), shutdown_rx.clone());
    start_repair_worker(state.clone(), shutdown_rx.clone());
    start_rebalance_worker(state.clone(), shutdown_rx.clone());
    start_deletion_convergence_worker(state.clone(), shutdown_rx.clone());
    start_discovery_worker(state.clone(), shutdown_rx.clone());
    start_node_ban_list_worker(state.clone(), shutdown_rx.clone());
    start_uptime_gossip_worker(state.clone(), shutdown_rx.clone());
    start_provider_gossip_worker(state.clone(), shutdown_rx.clone());
    start_cellule_record_gossip_worker(state.clone(), shutdown_rx.clone());
    start_kademlia_worker(state.clone(), shutdown_rx.clone());
    start_noise_cleanup_worker(state.clone(), shutdown_rx.clone());
    start_audit_worker(state.clone(), shutdown_rx);

    // CORS — restrict to configured origin in production; wildcard only in dev mode.
    let cors = if let Some(ref allowed_origin) = legacy_config.ui_allowed_origin {
        let origin_hv = axum::http::HeaderValue::from_str(allowed_origin)
            .context("invalid ui_allowed_origin value")?;
        CorsLayer::new()
            .allow_origin(origin_hv)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
    } else {
        CorsLayer::new()
            .allow_origin(tower_http::cors::Any)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ])
            .allow_headers(tower_http::cors::Any)
    };

    // 64 MiB per-shard upload limit — a 20+10 erasure scheme over ~1 GB input
    // produces ~51 MB per shard (1 GB / 20 data shards), so 64 MiB leaves headroom
    // while bounding DoS attack surface.
    const SHARD_BODY_LIMIT: usize = 64 * 1024 * 1024;

    // Public browser routes either expose already-public node data or require
    // owner/recipient signatures in their handler before any mutation or
    // protected delivery. In production a bearer shipped in a public SPA is
    // deliberately not treated as an authentication boundary.
    let public_ui_routes = Router::new()
        .route("/health", get(health))
        .route("/capacity", get(capacity))
        .route("/cellules", get(list_cellules))
        .route("/owner/report/challenge", post(owner_report_challenge))
        .route("/owner/report/verify", post(owner_report_verify))
        .route("/wallet/cellules", post(wallet_cellules_create))
        .route("/wallet/index", get(wallet_index))
        .route(
            "/wallet/cellules/{cellule_id}/renew",
            post(wallet_cellules_renew),
        )
        .route(
            "/wallet/cellules/{cellule_id}/delete",
            post(wallet_cellules_delete),
        )
        .route("/wallet/packages", post(wallet_packages_create))
        .route(
            "/wallet/packages/{package_id}/remove",
            post(wallet_packages_remove),
        );

    let public_ui_routes = if state.config.production_profile {
        public_ui_routes
    } else {
        public_ui_routes.route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_ui_token,
        ))
    };

    // Local/development management routes currently use the UI bearer. They
    // remain useful for local operation and tests, but are explicitly absent
    // from the production public surface until operator/authority
    // authentication is independent from the public SPA.

    let management_routes = if state.config.production_profile {
        Router::new()
            .route("/maintenance", get(production_management_route_disabled))
            .route("/readiness", get(production_management_route_disabled))
            .route("/evidence-pack", get(production_management_route_disabled))
            .route(
                "/evidence-pack.zip",
                get(production_management_route_disabled),
            )
            .route("/metrics", get(production_management_route_disabled))
            .route("/receipts", get(production_management_route_disabled))
            .route("/ledger/balance", get(production_management_route_disabled))
            .route(
                "/ledger/transfer",
                post(production_management_route_disabled),
            )
            .route("/ledger/debit", post(production_management_route_disabled))
            .route(
                "/ledger/set-balance",
                post(production_management_route_disabled),
            )
            .route(
                "/wallet/packages",
                get(production_management_route_disabled),
            )
            .route(
                "/operator/shared-cellules",
                get(production_management_route_disabled),
            )
            .route(
                "/operator/shared-cellules/{package_id}",
                get(production_management_route_disabled),
            )
    } else {
        let routes = Router::new()
            .route("/maintenance", get(maintenance_status))
            .route("/readiness", get(readiness))
            .route("/evidence-pack", get(evidence_pack))
            .route("/evidence-pack.zip", get(evidence_pack_zip))
            .route("/metrics", get(metrics))
            .route("/receipts", get(list_receipts))
            .route("/wallet/packages", get(wallet_packages_index))
            .route("/operator/shared-cellules", get(operator_shared_cellules))
            .route(
                "/operator/shared-cellules/{package_id}",
                get(operator_shared_cellule),
            )
            .route("/ledger/balance", get(production_management_route_disabled))
            .route(
                "/ledger/transfer",
                post(production_management_route_disabled),
            )
            .route("/ledger/debit", post(production_management_route_disabled))
            .route(
                "/ledger/set-balance",
                post(production_management_route_disabled),
            );
        routes.route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_ui_token,
        ))
    };

    // Inter-node protocol routes — no UI-token auth (nodes use their own signed
    // protocol messages and/or Noise transport sessions for authentication).
    let protocol_routes = Router::new()
        .route("/peers", get(peers))
        .route("/peers/announce", put(announce_peer))
        .route("/cellule-records/announce", put(announce_cellule_record))
        .route("/cellule-records/{cellule_id}", get(cellule_record))
        .route(
            "/manifests/{cid}",
            put(put_manifest_blob).get(get_manifest_blob),
        )
        .route("/providers/announce", put(announce_provider_record))
        .route("/providers/{shard_id}", get(providers_for_shard))
        .route("/uptime", get(uptime))
        .route("/uptime/announce", put(announce_uptime))
        .route("/noise/initiate", post(noise_initiate))
        .route("/noise/complete", post(noise_complete))
        .route("/access/read/challenge", post(read_access_challenge))
        .route("/access/read/verify", post(read_access_verify))
        .route(
            "/access/read/cellule-record",
            post(read_access_cellule_record),
        )
        .route(
            "/access/read/field-package",
            post(read_access_field_package),
        )
        .route(
            "/shards/{shard_id}/secure",
            put(put_shard_secure).get(get_shard_secure),
        );

    let protocol_routes = protocol_routes.route(
        "/authority/spend",
        post(production_management_route_disabled),
    );

    // Conditionally add plain HTTP shard endpoints based on transport policy.
    let protocol_routes = match state.config.transport_policy {
        TransportPolicy::Development => protocol_routes.route(
            "/shards/{shard_id}",
            put(put_shard).get(get_shard).delete(delete_shard),
        ),
        TransportPolicy::NoiseSecureOnly | TransportPolicy::HttpsReverseProxy => {
            // Plain HTTP shard endpoints are disabled in secure transport modes.
            protocol_routes
        }
    }
    .route_layer(DefaultBodyLimit::max(SHARD_BODY_LIMIT))
    .route("/shards/{shard_id}/status", get(shard_status))
    .route(
        "/shards/{shard_id}/upload-receipt",
        get(shard_upload_receipt),
    )
    .route("/node-info", get(node_info));

    let protocol_routes =
        protocol_routes.route("/pricing", get(production_management_route_disabled));

    // Compliance routes — require compliance_token when configured.
    let compliance_routes = Router::new()
        .route(
            "/compliance/security-events",
            get(compliance_security_events),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_compliance_token,
        ));

    let app = Router::new()
        .merge(public_ui_routes)
        .merge(management_routes)
        .merge(protocol_routes)
        .merge(compliance_routes);

    // Optional static file serving.
    // The web-UI SPA (marketing landing + operator dashboard) is served at the root.
    // API routes registered above always take precedence; any unmatched path
    // (e.g. /dashboard, /vault) falls back to index.html for client-side routing.
    // An optional content_dir can override / for operators who deploy custom content.
    // axum 0.8 disallows nesting at "/": use `fallback_service` so any path not
    // matched by an API route is served from the static dir (SPA), with
    // index.html as the client-side-routing fallback.
    let app = if let Some(content) = &legacy_config.content_dir {
        let index = content.join("index.html");
        app.fallback_service(ServeDir::new(content).fallback(ServeFile::new(index)))
    } else if let Some(webui) = &legacy_config.webui_path {
        let index = webui.join("index.html");
        app.fallback_service(ServeDir::new(webui).fallback(ServeFile::new(index)))
    } else {
        app
    };

    let app = app
        // Rate limiting — applied after route matching so the limiter covers all routes.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_check,
        ))
        // Correlation ID middleware for request tracing
        .layer(middleware::from_fn(correlation_middleware))
        // Security headers on every response (X-Frame-Options, X-Content-Type-Options, …).
        .layer(middleware::from_fn(security_headers))
        // Structured request tracing: method, path, status, latency per request.
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(state.config.listen_addr)
        .await
        .context("failed to bind node listener")?;

    tracing::info!(
        listen_addr = %legacy_config.listen_addr,
        node_id = %legacy_config.node_id.0,
        region = %legacy_config.region,
        "node server started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await
        .context("node server failed")?;

    tracing::info!("node server shut down cleanly");
    Ok(())
}

async fn production_management_route_disabled() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Resolves when SIGTERM or SIGINT (Ctrl-C) is received, allowing axum to
/// drain in-flight requests before the process exits.
async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received Ctrl-C, shutting down"); },
        _ = terminate => { tracing::info!("received SIGTERM, shutting down"); },
    }

    let _ = shutdown_tx.send(true);
}
