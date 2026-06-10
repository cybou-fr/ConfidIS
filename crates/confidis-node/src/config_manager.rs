use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::storage_backend::StorageConfig;

use crate::config::NodeServerConfig;

fn is_zero_f64(value: &f64) -> bool {
    *value == 0.0
}

/// Unified configuration system with validation, environment variable support,
/// and hot-reload capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidISConfig {
    pub node: NodeConfigSection,
    pub storage: StorageConfigSection,
    pub network: NetworkConfigSection,
    pub security: SecurityConfigSection,
    pub usage: UsageConfigSection,
    pub ui: UiConfigSection,
    pub monitoring: MonitoringConfigSection,
    pub storage_backend: StorageBackendConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfigSection {
    pub node_id: String,
    pub production_profile: bool,
    pub region: String,
    pub failure_domain: String,
    pub max_bytes: u64,
    pub private_key: Option<String>,
    pub x25519_secret_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfigSection {
    pub store_path: PathBuf,
    pub registry_path: Option<PathBuf>,
    pub read_access_revocations_path: Option<PathBuf>,
    pub packages_path: Option<PathBuf>,
    pub node_ban_list_path: Option<PathBuf>,
    pub authority_private_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfigSection {
    pub listen_addr: String,
    pub public_endpoint: Option<String>,
    pub bootstrap_peers: Vec<String>,
    /// Discovery backend: `"federation_gossip"` (default) or `"hybrid_kademlia"`.
    #[serde(default = "default_discovery_backend")]
    pub discovery_backend: String,
    /// libp2p/Kademlia listen multiaddr, e.g. `/ip4/0.0.0.0/tcp/4001`.
    #[serde(default)]
    pub kademlia_listen_addr: Option<String>,
    /// libp2p bootstrap peers, e.g. `/ip4/10.0.0.2/tcp/4001/p2p/<peer-id>`.
    #[serde(default)]
    pub kademlia_bootstrap_peers: Vec<String>,
    /// Optional libp2p circuit-relay peers, e.g. `/ip4/10.0.0.3/tcp/4001/p2p/<relay-id>`.
    #[serde(default)]
    pub kademlia_relay_peers: Vec<String>,
    pub transport_policy: String, // "plain", "noise_secure_only", "https_reverse_proxy"
    pub node_ban_list_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidis_root_pubkey: Option<String>,
}

fn default_discovery_backend() -> String {
    "federation_gossip".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfigSection {
    pub authorized_operator_pubkeys: Vec<String>,
    pub compliance_token: Option<String>,
    pub security_event_webhook_urls: Vec<String>,
    pub ui_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageConfigSection {
    pub min_expiry_days: u32,
    pub max_expiry_days: u32,
    pub max_shards_per_owner_per_hour: u32,
    pub max_cellules_per_owner: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfigSection {
    pub ui_allowed_origin: Option<String>,
    pub webui_path: Option<PathBuf>,
    pub content_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfigSection {
    pub metrics_enabled: bool,
    pub health_check_interval_secs: u64,
    pub maintenance_job_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBackendConfig {
    pub backend_type: String,
    pub filesystem_root: Option<PathBuf>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    pub s3_endpoint: Option<String>,
}

impl ConfidISConfig {
    /// Load configuration from multiple sources with priority:
    /// 1. Environment variables (highest priority)
    /// 2. Configuration file
    /// 3. Defaults (lowest priority)
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let mut config = Self::default();

        // Load from file if provided
        if let Some(path) = config_path
            && path.exists()
        {
            let content = fs::read_to_string(path)
                .context(format!("Failed to read config file: {}", path.display()))?;
            let file_config: ConfidISConfig =
                serde_json::from_str(&content).context("Failed to parse config file")?;
            config = Self::merge(config, file_config);
        }

        // Override with environment variables
        config = config.load_from_env()?;

        // Validate the final configuration
        config.validate()?;

        Ok(config)
    }

    /// Load configuration from environment variables
    fn load_from_env(mut self) -> Result<Self> {
        // Node configuration
        if let Ok(node_id) = env::var("CONFIDIS_NODE_ID") {
            self.node.node_id = node_id;
        }
        if let Ok(production) = env::var("CONFIDIS_PRODUCTION_PROFILE") {
            self.node.production_profile = production.parse().unwrap_or(false);
        }
        if let Ok(region) = env::var("CONFIDIS_REGION") {
            self.node.region = region;
        }
        if let Ok(failure_domain) = env::var("CONFIDIS_FAILURE_DOMAIN") {
            self.node.failure_domain = failure_domain;
        }
        if let Ok(max_bytes) = env::var("CONFIDIS_MAX_BYTES") {
            self.node.max_bytes = max_bytes.parse().unwrap_or(100 * 1024 * 1024);
        }

        // Network configuration
        if let Ok(listen_addr) = env::var("CONFIDIS_LISTEN_ADDR") {
            self.network.listen_addr = listen_addr;
        }
        if let Ok(public_endpoint) = env::var("CONFIDIS_PUBLIC_ENDPOINT") {
            self.network.public_endpoint = Some(public_endpoint);
        }
        if let Ok(bootstrap_peers) = env::var("CONFIDIS_BOOTSTRAP_PEERS") {
            self.network.bootstrap_peers = bootstrap_peers
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
        }
        if let Ok(discovery_backend) = env::var("CONFIDIS_DISCOVERY_BACKEND") {
            self.network.discovery_backend = discovery_backend;
        }
        if let Ok(kademlia_listen_addr) = env::var("CONFIDIS_KADEMLIA_LISTEN_ADDR") {
            self.network.kademlia_listen_addr = Some(kademlia_listen_addr);
        }
        if let Ok(kademlia_bootstrap_peers) = env::var("CONFIDIS_KADEMLIA_BOOTSTRAP_PEERS") {
            self.network.kademlia_bootstrap_peers = kademlia_bootstrap_peers
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect();
        }
        if let Ok(kademlia_relay_peers) = env::var("CONFIDIS_KADEMLIA_RELAY_PEERS") {
            self.network.kademlia_relay_peers = kademlia_relay_peers
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect();
        }

        // Storage configuration
        if let Ok(store_path) = env::var("CONFIDIS_STORE_PATH") {
            self.storage.store_path = PathBuf::from(store_path);
        }

        // Security configuration
        if let Ok(ui_token) = env::var("CONFIDIS_UI_TOKEN") {
            self.security.ui_token = Some(ui_token);
        }
        if let Ok(compliance_token) = env::var("CONFIDIS_COMPLIANCE_TOKEN") {
            self.security.compliance_token = Some(compliance_token);
        }

        Ok(self)
    }

    /// Merge two configurations, with the second taking precedence
    fn merge(base: Self, override_config: Self) -> Self {
        Self {
            node: NodeConfigSection {
                node_id: override_config.node.node_id,
                production_profile: override_config.node.production_profile
                    || base.node.production_profile,
                region: override_config.node.region,
                failure_domain: override_config.node.failure_domain,
                max_bytes: override_config.node.max_bytes,
                private_key: override_config.node.private_key.or(base.node.private_key),
                x25519_secret_key: override_config
                    .node
                    .x25519_secret_key
                    .or(base.node.x25519_secret_key),
            },
            storage: StorageConfigSection {
                store_path: override_config.storage.store_path,
                registry_path: override_config
                    .storage
                    .registry_path
                    .or(base.storage.registry_path),
                read_access_revocations_path: override_config
                    .storage
                    .read_access_revocations_path
                    .or(base.storage.read_access_revocations_path),
                packages_path: override_config
                    .storage
                    .packages_path
                    .or(base.storage.packages_path),
                node_ban_list_path: override_config
                    .storage
                    .node_ban_list_path
                    .or(base.storage.node_ban_list_path),
                authority_private_key_path: override_config
                    .storage
                    .authority_private_key_path
                    .or(base.storage.authority_private_key_path),
            },
            network: NetworkConfigSection {
                listen_addr: override_config.network.listen_addr,
                public_endpoint: override_config
                    .network
                    .public_endpoint
                    .or(base.network.public_endpoint),
                bootstrap_peers: if override_config.network.bootstrap_peers.is_empty() {
                    base.network.bootstrap_peers
                } else {
                    override_config.network.bootstrap_peers
                },
                discovery_backend: if override_config.network.discovery_backend.is_empty() {
                    base.network.discovery_backend
                } else {
                    override_config.network.discovery_backend
                },
                kademlia_listen_addr: override_config
                    .network
                    .kademlia_listen_addr
                    .or(base.network.kademlia_listen_addr),
                kademlia_bootstrap_peers: if override_config
                    .network
                    .kademlia_bootstrap_peers
                    .is_empty()
                {
                    base.network.kademlia_bootstrap_peers
                } else {
                    override_config.network.kademlia_bootstrap_peers
                },
                kademlia_relay_peers: if override_config.network.kademlia_relay_peers.is_empty() {
                    base.network.kademlia_relay_peers
                } else {
                    override_config.network.kademlia_relay_peers
                },
                transport_policy: override_config.network.transport_policy,
                node_ban_list_url: override_config
                    .network
                    .node_ban_list_url
                    .or(base.network.node_ban_list_url),
                confidis_root_pubkey: override_config
                    .network
                    .confidis_root_pubkey
                    .or(base.network.confidis_root_pubkey),
            },
            security: SecurityConfigSection {
                authorized_operator_pubkeys: if override_config
                    .security
                    .authorized_operator_pubkeys
                    .is_empty()
                {
                    base.security.authorized_operator_pubkeys
                } else {
                    override_config.security.authorized_operator_pubkeys
                },
                compliance_token: override_config
                    .security
                    .compliance_token
                    .or(base.security.compliance_token),
                security_event_webhook_urls: if override_config
                    .security
                    .security_event_webhook_urls
                    .is_empty()
                {
                    base.security.security_event_webhook_urls
                } else {
                    override_config.security.security_event_webhook_urls
                },
                ui_token: override_config.security.ui_token.or(base.security.ui_token),
            },
            usage: UsageConfigSection {
                min_expiry_days: if override_config.usage.min_expiry_days > 0 {
                    override_config.usage.min_expiry_days
                } else {
                    base.usage.min_expiry_days
                },
                max_expiry_days: if override_config.usage.max_expiry_days > 0 {
                    override_config.usage.max_expiry_days
                } else {
                    base.usage.max_expiry_days
                },
                max_shards_per_owner_per_hour: if override_config
                    .usage
                    .max_shards_per_owner_per_hour
                    > 0
                {
                    override_config.usage.max_shards_per_owner_per_hour
                } else {
                    base.usage.max_shards_per_owner_per_hour
                },
                max_cellules_per_owner: if override_config.usage.max_cellules_per_owner > 0 {
                    override_config.usage.max_cellules_per_owner
                } else {
                    base.usage.max_cellules_per_owner
                },
            },
            ui: UiConfigSection {
                ui_allowed_origin: override_config
                    .ui
                    .ui_allowed_origin
                    .or(base.ui.ui_allowed_origin),
                webui_path: override_config.ui.webui_path.or(base.ui.webui_path),
                content_dir: override_config.ui.content_dir.or(base.ui.content_dir),
            },
            monitoring: MonitoringConfigSection {
                metrics_enabled: override_config.monitoring.metrics_enabled
                    || base.monitoring.metrics_enabled,
                health_check_interval_secs: if override_config.monitoring.health_check_interval_secs
                    > 0
                {
                    override_config.monitoring.health_check_interval_secs
                } else {
                    base.monitoring.health_check_interval_secs
                },
                maintenance_job_interval_secs: if override_config
                    .monitoring
                    .maintenance_job_interval_secs
                    > 0
                {
                    override_config.monitoring.maintenance_job_interval_secs
                } else {
                    base.monitoring.maintenance_job_interval_secs
                },
            },
            storage_backend: StorageBackendConfig {
                backend_type: if override_config.storage_backend.backend_type.is_empty() {
                    base.storage_backend.backend_type
                } else {
                    override_config.storage_backend.backend_type
                },
                filesystem_root: override_config
                    .storage_backend
                    .filesystem_root
                    .or(base.storage_backend.filesystem_root),
                s3_bucket: override_config
                    .storage_backend
                    .s3_bucket
                    .or(base.storage_backend.s3_bucket),
                s3_region: override_config
                    .storage_backend
                    .s3_region
                    .or(base.storage_backend.s3_region),
                s3_access_key: override_config
                    .storage_backend
                    .s3_access_key
                    .or(base.storage_backend.s3_access_key),
                s3_secret_key: override_config
                    .storage_backend
                    .s3_secret_key
                    .or(base.storage_backend.s3_secret_key),
                s3_endpoint: override_config
                    .storage_backend
                    .s3_endpoint
                    .or(base.storage_backend.s3_endpoint),
            },
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate node configuration
        if self.node.node_id.trim().is_empty() {
            bail!("node_id cannot be empty");
        }
        if self.node.region.trim().is_empty() {
            bail!("region cannot be empty");
        }
        if self.node.failure_domain.trim().is_empty() {
            bail!("failure_domain cannot be empty");
        }
        if self.node.max_bytes == 0 {
            bail!("max_bytes must be greater than 0");
        }

        // Validate network configuration
        self.network
            .listen_addr
            .parse::<SocketAddr>()
            .context("listen_addr must be a valid socket address")?;
        match self.network.discovery_backend.as_str() {
            "federation_gossip" | "bootstrap_gossip" | "hybrid_kademlia" => {}
            other => bail!(
                "invalid discovery_backend={other:?}; expected 'federation_gossip' or 'hybrid_kademlia'"
            ),
        }

        // Validate storage configuration. A freshly initialized node may point
        // at an empty data directory that has not been created yet.
        if !self.storage.store_path.exists() {
            fs::create_dir_all(&self.storage.store_path).with_context(|| {
                format!(
                    "store_path '{}' does not exist and could not be created",
                    self.storage.store_path.display()
                )
            })?;
        }

        // Validate usage configuration
        if self.usage.min_expiry_days > self.usage.max_expiry_days {
            bail!("min_expiry_days cannot be greater than max_expiry_days");
        }
        if self.usage.min_expiry_days == 0 {
            bail!("min_expiry_days must be at least 1");
        }
        if self.usage.max_expiry_days > confidis_protocol::MAX_CELLULE_LIFETIME_DAYS as u32 {
            bail!(
                "max_expiry_days cannot exceed {} days",
                confidis_protocol::MAX_CELLULE_LIFETIME_DAYS
            );
        }

        // Validate monitoring configuration
        if self.monitoring.health_check_interval_secs == 0 {
            bail!("health_check_interval_secs must be greater than 0");
        }
        if self.monitoring.maintenance_job_interval_secs == 0 {
            bail!("maintenance_job_interval_secs must be greater than 0");
        }

        Ok(())
    }

    /// Convert storage backend configuration to StorageConfig.
    pub fn to_storage_config(&self) -> Result<StorageConfig> {
        match self.storage_backend.backend_type.as_str() {
            "filesystem" => {
                let root_path = self
                    .storage_backend
                    .filesystem_root
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("./data"));
                Ok(StorageConfig::Filesystem { root_path })
            }
            "memory" => Ok(StorageConfig::Memory),
            "s3" => {
                let bucket = self
                    .storage_backend
                    .s3_bucket
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("s3_bucket is required for S3 backend"))?;
                let region = self
                    .storage_backend
                    .s3_region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_string());
                let access_key =
                    self.storage_backend.s3_access_key.clone().ok_or_else(|| {
                        anyhow::anyhow!("s3_access_key is required for S3 backend")
                    })?;
                let secret_key =
                    self.storage_backend.s3_secret_key.clone().ok_or_else(|| {
                        anyhow::anyhow!("s3_secret_key is required for S3 backend")
                    })?;

                Ok(StorageConfig::S3 {
                    bucket,
                    region,
                    access_key,
                    secret_key,
                    endpoint: self.storage_backend.s3_endpoint.clone(),
                })
            }
            _ => bail!(
                "Unknown storage backend type: {}",
                self.storage_backend.backend_type
            ),
        }
    }

    /// Convert to the legacy NodeServerConfig format for backward compatibility
    pub fn to_node_server_config(&self) -> Result<NodeServerConfig> {
        use crate::config::NodeServerConfig;
        use confidis_protocol::{NodeConfig, NodeId, PlacementPolicy, TransportPolicy};

        let transport_policy = match self.network.transport_policy.as_str() {
            "plain" | "development" => TransportPolicy::Development,
            "noise_secure_only" => TransportPolicy::NoiseSecureOnly,
            "https_reverse_proxy" => TransportPolicy::HttpsReverseProxy,
            _ => bail!(
                "Invalid transport_policy: {}",
                self.network.transport_policy
            ),
        };

        let placement_policy = if self.node.production_profile {
            PlacementPolicy::production()
        } else {
            PlacementPolicy::default()
        };

        let mut node_config = NodeServerConfig::from_protocol(NodeConfig {
            node_id: NodeId(self.node.node_id.clone()),
            production_profile: self.node.production_profile,
            transport_policy,
            listen_addr: self.network.listen_addr.clone(),
            public_endpoint: self.network.public_endpoint.clone(),
            bootstrap_peers: self.network.bootstrap_peers.clone(),
            store_path: self.storage.store_path.display().to_string(),
            region: self.node.region.clone(),
            failure_domain: self.node.failure_domain.clone(),
            max_bytes: self.node.max_bytes,
            private_key: self.node.private_key.clone(),
            x25519_secret_key: self.node.x25519_secret_key.clone(),
            node_ban_list_path: self
                .storage
                .node_ban_list_path
                .as_ref()
                .map(|path| path.display().to_string()),
            authority_private_key_path: self
                .storage
                .authority_private_key_path
                .as_ref()
                .map(|path| path.display().to_string()),
            node_ban_list_url: self.network.node_ban_list_url.clone(),
            authority_spend_url: None,
            payer_mode: confidis_protocol::PayerMode::NodeSelf,
            confidis_root_pubkey: self.network.confidis_root_pubkey.clone(),
            placement_policy,
            registry_path: self
                .storage
                .registry_path
                .as_ref()
                .map(|path| path.display().to_string()),
            read_access_revocations_path: self
                .storage
                .read_access_revocations_path
                .as_ref()
                .map(|path| path.display().to_string()),
            packages_path: self
                .storage
                .packages_path
                .as_ref()
                .map(|path| path.display().to_string()),
            ui_token: self.security.ui_token.clone(),
            ui_allowed_origin: self.ui.ui_allowed_origin.clone(),
            min_expiry_days: self.usage.min_expiry_days,
            max_expiry_days: self.usage.max_expiry_days,
            max_shards_per_owner_per_hour: self.usage.max_shards_per_owner_per_hour,
            max_cellules_per_owner: self.usage.max_cellules_per_owner,
            authorized_operator_pubkeys: self.security.authorized_operator_pubkeys.clone(),
            webui_path: self
                .ui
                .webui_path
                .as_ref()
                .map(|path| path.display().to_string()),
            content_dir: self
                .ui
                .content_dir
                .as_ref()
                .map(|path| path.display().to_string()),
            security_event_webhook_urls: self.security.security_event_webhook_urls.clone(),
            compliance_token: self.security.compliance_token.clone(),
        })?;
        node_config.discovery_backend = self.network.discovery_backend.clone();
        node_config.kademlia_listen_addr = self.network.kademlia_listen_addr.clone();
        node_config.kademlia_bootstrap_peers = self.network.kademlia_bootstrap_peers.clone();
        node_config.kademlia_relay_peers = self.network.kademlia_relay_peers.clone();
        Ok(node_config)
    }
}

impl Default for ConfidISConfig {
    fn default() -> Self {
        Self {
            node: NodeConfigSection {
                node_id: "".to_string(),
                production_profile: false,
                region: "default".to_string(),
                failure_domain: "default".to_string(),
                max_bytes: 100 * 1024 * 1024, // 100MB
                private_key: None,
                x25519_secret_key: None,
            },
            storage: StorageConfigSection {
                store_path: PathBuf::from("./data"),
                registry_path: None,
                read_access_revocations_path: None,
                packages_path: None,
                node_ban_list_path: None,
                authority_private_key_path: None,
            },
            network: NetworkConfigSection {
                listen_addr: "127.0.0.1:4433".to_string(),
                public_endpoint: None,
                bootstrap_peers: Vec::new(),
                discovery_backend: default_discovery_backend(),
                kademlia_listen_addr: None,
                kademlia_bootstrap_peers: Vec::new(),
                kademlia_relay_peers: Vec::new(),
                transport_policy: "plain".to_string(),
                node_ban_list_url: Some(
                    "https://confidis.fr/governance/node_ban_list.json".to_string(),
                ),
                confidis_root_pubkey: None,
            },
            security: SecurityConfigSection {
                authorized_operator_pubkeys: vec![],
                compliance_token: None,
                security_event_webhook_urls: vec![],
                ui_token: None,
            },
            usage: UsageConfigSection {
                min_expiry_days: 1,
                max_expiry_days: 365,
                max_shards_per_owner_per_hour: 0,
                max_cellules_per_owner: 0,
            },
            ui: UiConfigSection {
                ui_allowed_origin: None,
                webui_path: None,
                content_dir: None,
            },
            monitoring: MonitoringConfigSection {
                metrics_enabled: true,
                health_check_interval_secs: 30,
                maintenance_job_interval_secs: 300,
            },
            storage_backend: StorageBackendConfig {
                backend_type: "filesystem".to_string(),
                filesystem_root: Some(PathBuf::from("./data")),
                s3_bucket: None,
                s3_region: None,
                s3_access_key: None,
                s3_secret_key: None,
                s3_endpoint: None,
            },
        }
    }
}

/// Hot-reload capable configuration manager
pub struct ConfigManager {
    config: Arc<RwLock<ConfidISConfig>>,
    config_path: Option<PathBuf>,
}

impl ConfigManager {
    pub fn new(config: ConfidISConfig, config_path: Option<PathBuf>) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            config_path,
        }
    }

    pub async fn get_config(&self) -> ConfidISConfig {
        self.config.read().await.clone()
    }

    /// Reload configuration from file and environment variables
    pub async fn reload(&self) -> Result<()> {
        let new_config = ConfidISConfig::load(self.config_path.as_deref())?;
        *self.config.write().await = new_config;
        Ok(())
    }

    /// Start a background task that periodically checks for configuration changes
    pub fn start_hot_reload(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                if let Err(err) = self.reload().await {
                    tracing::warn!("Failed to reload configuration: {}", err);
                } else {
                    tracing::info!("Configuration reloaded successfully");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut config = ConfidISConfig::default();
        config.node.node_id = "test-node".to_string();
        config.storage.store_path = temp.path().to_path_buf();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_node_id() {
        let mut config = ConfidISConfig::default();
        config.node.node_id = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_merge() {
        let base = ConfidISConfig::default();
        let mut override_config = ConfidISConfig::default();
        override_config.node.node_id = "override-node".to_string();
        override_config.node.production_profile = true;

        let merged = ConfidISConfig::merge(base, override_config);
        assert_eq!(merged.node.node_id, "override-node");
        assert!(merged.node.production_profile);
    }

    #[tokio::test]
    async fn test_config_manager() {
        let config = ConfidISConfig::default();
        let manager = ConfigManager::new(config, None);

        let retrieved = manager.get_config().await;
        assert_eq!(retrieved.node.node_id, "");
    }

}
