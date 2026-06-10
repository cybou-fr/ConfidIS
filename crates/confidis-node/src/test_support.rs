use std::path::PathBuf;
use std::sync::Arc;

use confidis_protocol::{NodeId, PlacementPolicy, TransportPolicy};

/// Process-global sync mutex for tests that mutate or read the CONFIDIS authority
/// key env vars (`CONFIDIS_AUTHORITY_PRIVATE_KEY[S]`). Both the async
/// `authority_service::tests::*` and sync `config::tests::*` acquire this so a
/// parallel run does not see a half-set env var.
pub(crate) fn env_sync_lock() -> &'static std::sync::Mutex<()> {
    static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(()))
}

use crate::config::NodeServerConfig;
use crate::rate_limit::RateLimiter;
use crate::state::NodeState;
use crate::storage_backend::FilesystemStorage;

pub(crate) struct TestNodeStateOptions {
    pub(crate) node_id: &'static str,
    pub(crate) registry_path: Option<PathBuf>,
    pub(crate) read_access_revocations_path: Option<PathBuf>,
    pub(crate) packages_path: Option<PathBuf>,
    pub(crate) min_expiry_days: u32,
    pub(crate) max_expiry_days: u32,
    pub(crate) authorized_operator_pubkeys: Vec<String>,
}

impl Default for TestNodeStateOptions {
    fn default() -> Self {
        Self {
            node_id: "test-node",
            registry_path: None,
            read_access_revocations_path: None,
            packages_path: None,
            min_expiry_days: 1,
            max_expiry_days: confidis_protocol::MAX_CELLULE_LIFETIME_DAYS as u32,
            authorized_operator_pubkeys: Vec::new(),
        }
    }
}

pub(crate) fn test_node_state(
    temp: &tempfile::TempDir,
    options: TestNodeStateOptions,
) -> Arc<NodeState> {
    let config = NodeServerConfig {
        node_id: NodeId(options.node_id.to_string()),
        production_profile: false,
        transport_policy: TransportPolicy::Development,
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        public_endpoint: None,
        bootstrap_peers: Vec::new(),
        discovery_backend: "federation_gossip".to_string(),
        kademlia_listen_addr: None,
        kademlia_bootstrap_peers: Vec::new(),
        kademlia_relay_peers: Vec::new(),
        store_path: temp.path().to_path_buf(),
        region: "eu-fr".to_string(),
        failure_domain: "fd-test".to_string(),
        max_bytes: 1024 * 1024,
        signing_key: None,
        placement_policy: PlacementPolicy::default(),
        node_ban_list_path: None,
        authority_private_key_path: None,
        node_ban_list_url: None,
        confidis_root_pubkey: None,
        confidis_root_source: "missing".to_string(),
        node_ban_list: None,
        x25519_static_key: None,
        registry_path: options.registry_path,
        read_access_revocations_path: options.read_access_revocations_path,
        packages_path: options.packages_path,
        ui_token: None,
        ui_allowed_origin: None,
        min_expiry_days: options.min_expiry_days,
        max_expiry_days: options.max_expiry_days,
        max_shards_per_owner_per_hour: 0,
        max_cellules_per_owner: 0,
        authorized_operator_pubkeys: options.authorized_operator_pubkeys,
        webui_path: None,
        content_dir: None,
        security_event_webhook_urls: Vec::new(),
        compliance_token: None,
    };
    let store = Arc::new(FilesystemStorage::new(config.store_path.clone()).expect("store"));
    Arc::new(NodeState::new(
        config,
        store,
        Arc::new(RateLimiter::new(10, 0)),
    ))
}
