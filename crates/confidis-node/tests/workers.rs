use chrono::Utc;
use confidis_crypto::{generate_signing_key, sign_hex, signing_key_to_hex, verifying_key_to_hex};
use confidis_node::ConfidISConfig;
use confidis_protocol::{NodeId, PeerList, PeerRecord, peer_record_signing_payload};
use reqwest::StatusCode;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn start_test_node() -> (SocketAddr, String, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    drop(listener); // release port for axum

    let signing_key = generate_signing_key();
    let mut config = ConfidISConfig::default();
    config.node.node_id = "test-node-01".to_string();
    config.node.region = "test-region".to_string();
    config.node.failure_domain = "test-fd".to_string();
    config.node.max_bytes = 1024 * 1024 * 100;
    config.node.private_key = Some(signing_key_to_hex(&signing_key));
    config.network.listen_addr = addr.to_string();
    config.network.public_endpoint = Some(format!("http://127.0.0.1:{}", port));
    config.network.transport_policy = "plain".to_string();
    config.storage.store_path = temp_dir.path().to_path_buf();
    config.storage_backend.backend_type = "filesystem".to_string();
    config.storage_backend.filesystem_root = Some(temp_dir.path().to_path_buf());

    tokio::spawn(async move {
        confidis_node::serve(config).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (addr, format!("http://127.0.0.1:{}", port), temp_dir)
}

#[tokio::test]
async fn test_maintenance_status_endpoint() {
    let (_addr, base_url, _temp_dir) = start_test_node().await;
    let client = reqwest::Client::new();

    // Test that maintenance status endpoint works
    let response = client
        .get(format!("{}/maintenance", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let status: serde_json::Value = response.json().await.unwrap();
    assert!(status.get("version").is_some());
    assert!(status.get("jobs").is_some());
}

fn signed_peer_record(endpoint: &str) -> PeerRecord {
    let signing_key = generate_signing_key();
    let now = Utc::now();
    let mut record = PeerRecord {
        endpoint: endpoint.to_string(),
        node_id: Some(NodeId("cached-peer".to_string())),
        public_key: Some(verifying_key_to_hex(&signing_key.verifying_key())),
        region: Some("eu-fr".to_string()),
        failure_domain: Some("cached-fd".to_string()),
        issued_at: Some(now),
        expires_at: Some(now + chrono::Duration::minutes(10)),
        signature: None,
    };
    let payload = peer_record_signing_payload(&record).expect("payload");
    record.signature = Some(sign_hex(&signing_key, &payload));
    record
}

#[tokio::test]
async fn test_node_boots_with_signed_peer_cache_when_seed_peer_is_unavailable() {
    let temp_dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();
    drop(listener);

    let cached_peer = signed_peer_record("http://127.0.0.1:39001");
    let cache_dir = temp_dir.path().join("peers");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(
        cache_dir.join("routing-cache.json"),
        serde_json::to_vec_pretty(&vec![cached_peer.clone()]).unwrap(),
    )
    .unwrap();

    let signing_key = generate_signing_key();
    let mut config = ConfidISConfig::default();
    config.node.node_id = "cache-restart-node".to_string();
    config.node.region = "test-region".to_string();
    config.node.failure_domain = "test-fd".to_string();
    config.node.max_bytes = 1024 * 1024 * 100;
    config.node.private_key = Some(signing_key_to_hex(&signing_key));
    config.network.listen_addr = addr.to_string();
    config.network.public_endpoint = Some(format!("http://127.0.0.1:{}", port));
    config.network.bootstrap_peers = vec!["http://127.0.0.1:9".to_string()];
    config.network.transport_policy = "plain".to_string();
    config.storage.store_path = temp_dir.path().to_path_buf();
    config.storage_backend.backend_type = "filesystem".to_string();
    config.storage_backend.filesystem_root = Some(temp_dir.path().to_path_buf());

    tokio::spawn(async move {
        confidis_node::serve(config).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let peers: PeerList = reqwest::get(format!("http://127.0.0.1:{}/peers", port))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(
        peers
            .peers
            .iter()
            .any(|peer| peer.endpoint == cached_peer.endpoint
                && peer.public_key == cached_peer.public_key),
        "cached signed peer should survive startup without seed peer: {peers:#?}"
    );
}
