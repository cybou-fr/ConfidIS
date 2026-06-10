use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use confidis_protocol::PlacementPolicy;

const PRODUCTION_DEFAULT_MAX_SHARDS_PER_OWNER_PER_HOUR: u32 = 1000;
const PRODUCTION_DEFAULT_MAX_CELLULES_PER_OWNER: u32 = 100;
const PRODUCTION_DEFAULT_WEBUI_PATH: &str = "/usr/share/confidis/webui";

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub(crate) enum NodeCommand {
    InitConfig {
        #[arg(long)]
        node_id: String,
        /// Enable strict production readiness checks on startup.
        #[arg(long, default_value_t = false)]
        production_profile: bool,
        /// Transport security policy for shard I/O endpoints.
        /// Options: development (default), noise_secure_only, https_reverse_proxy.
        #[arg(long, default_value = "development")]
        transport_policy: String,
        #[arg(long, default_value = "127.0.0.1:4433")]
        listen_addr: String,
        #[arg(long)]
        public_endpoint: Option<String>,
        #[arg(long = "peer")]
        bootstrap_peers: Vec<String>,
        #[arg(long)]
        store_path: PathBuf,
        #[arg(long, default_value = "eu-fr")]
        region: String,
        #[arg(long, default_value = "local-dev")]
        failure_domain: String,
        #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024)]
        max_bytes: u64,
        #[arg(long)]
        private_key: Option<String>,
        /// X25519 secret key (hex) for inter-node Noise transport. Leave empty to omit.
        #[arg(long)]
        x25519_secret_key: Option<String>,
        /// Path to the locally cached CONFIDIS authority-signed node ban list.
        /// Nodes refuse shards/data to/from banned pubkeys. Reactive sanction
        /// only — joining the network is permissionless.
        #[arg(long)]
        node_ban_list_path: Option<PathBuf>,
        /// Path to a 0600 file with a CONFIDIS authority Ed25519 private key
        /// (hex). Labs/isolated signer only; rejected by production public nodes.
        /// Env `CONFIDIS_AUTHORITY_PRIVATE_KEY` takes precedence.
        #[arg(long)]
        authority_private_key_path: Option<PathBuf>,
        /// Optional explicit CONFIDIS node ban list feed URL.
        #[arg(long)]
        node_ban_list_url: Option<String>,
        /// Optional CONFIDIS authority root public key (hex, 32 bytes) for signed
        /// node ban lists. Does not gate admission.
        #[arg(long)]
        confidis_root_pubkey: Option<String>,
        /// Path to the local Cellule registry JSON (served via GET /cellules to the web UI).
        #[arg(long)]
        registry_path: Option<PathBuf>,
        #[arg(long)]
        /// Path to the local recipient packages registry JSON (served via GET /wallet/packages to the web UI).
        #[arg(long)]
        packages_path: Option<PathBuf>,
        /// Static bearer token for web UI authentication (hex, 32 bytes).
        /// Generate one with: `confidis node gen-token`
        #[arg(long)]
        ui_token: Option<String>,
        /// Allowed CORS origin for the web UI (e.g. `https://ui.confidis.eu`).
        /// When set, CORS is restricted to this exact origin. Requires `--ui-token`.
        #[arg(long)]
        ui_allowed_origin: Option<String>,
        /// Operator public keys allowed to view package inventory metadata.
        #[arg(long = "authorized-operator-pubkey")]
        authorized_operator_pubkeys: Vec<String>,
        /// Maximum shards any single owner (identified by delete-authority hash) may upload
        /// per hour on this node. 0 = unlimited (default). Non-zero values mitigate
        /// fill-storage attacks from a single wallet holding many keys.
        #[arg(long, default_value_t = 0)]
        max_shards_per_owner_per_hour: u32,
        /// Maximum cellules any single owner may create on this node. 0 = unlimited (default).
        #[arg(long, default_value_t = 0)]
        max_cellules_per_owner: u32,
        /// Path to bundled web UI assets served at /ui.
        #[arg(long)]
        webui_path: Option<PathBuf>,
        /// Path to public marketing/docs content served at /.
        #[arg(long)]
        content_dir: Option<PathBuf>,
        output: PathBuf,
    },
    /// Validate a node config file without starting the server.
    CheckConfig {
        config: PathBuf,
    },
    /// Manage placement policies.
    PlacementPolicy {
        #[command(subcommand)]
        command: PlacementPolicyCommand,
    },
    Serve {
        config: PathBuf,
    },
    /// Generate a secure random bearer token for web UI authentication.
    /// Print the token to stdout; add it to your node config as `ui_token`
    /// and set `VITE_UI_TOKEN=<token>` in the web UI environment.
    GenToken,
    /// Generate a secure random bearer token for SOC/compliance viewer access.
    /// Print the token to stdout; add it to your node config as `compliance_token`
    /// to enable `/compliance/*` endpoints for security event viewing.
    GenComplianceToken,
    /// Show local node health, capacity, and autonomous maintenance status.
    Status {
        /// Node base URL, e.g. http://127.0.0.1:4433.
        #[arg(long, default_value = "http://127.0.0.1:4433")]
        node: String,
        /// Bearer token for UI-protected node endpoints when the node has ui_token configured.
        #[arg(long)]
        ui_token: Option<String>,
        /// Emit raw combined JSON instead of the human-readable operator summary.
        #[arg(long)]
        json: bool,
    },
    /// Print node role metadata from `GET /node-info`.
    Info {
        /// Node base URL, e.g. http://127.0.0.1:4433.
        #[arg(long, default_value = "http://127.0.0.1:4433")]
        node: String,
        /// Emit raw JSON instead of the human-readable summary.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum PlacementPolicyCommand {
    /// Print the development (unconstrained) placement policy JSON template.
    InitDev,
    /// Print the production placement policy JSON template for a 20+10 cluster.
    InitProduction,
    /// Pretty-print a placement policy file as a human-readable table.
    Show { file: PathBuf },
    /// Validate a placement policy file — errors if any field is out of range.
    Validate { file: PathBuf },
}

pub(crate) async fn node(command: NodeCommand) -> Result<()> {
    match command {
        NodeCommand::InitConfig {
            node_id,
            production_profile,
            transport_policy: transport_policy_arg,
            listen_addr,
            public_endpoint,
            bootstrap_peers,
            store_path,
            region,
            failure_domain,
            max_bytes,
            private_key,
            x25519_secret_key,
            node_ban_list_path,
            authority_private_key_path,
            node_ban_list_url,
            confidis_root_pubkey,
            registry_path,
            packages_path,
            ui_token,
            ui_allowed_origin,
            authorized_operator_pubkeys,
            max_shards_per_owner_per_hour,
            max_cellules_per_owner,
            webui_path,
            content_dir,
            output,
        } => {
            fs::create_dir_all(&store_path)
                .with_context(|| format!("failed to create store path {}", store_path.display()))?;
            let filesystem_root = Some(store_path.clone());
            let max_shards_per_owner_per_hour =
                if production_profile && max_shards_per_owner_per_hour == 0 {
                    PRODUCTION_DEFAULT_MAX_SHARDS_PER_OWNER_PER_HOUR
                } else {
                    max_shards_per_owner_per_hour
                };
            let max_cellules_per_owner = if production_profile && max_cellules_per_owner == 0 {
                PRODUCTION_DEFAULT_MAX_CELLULES_PER_OWNER
            } else {
                max_cellules_per_owner
            };
            let transport_policy_arg =
                if production_profile && transport_policy_arg == "development" {
                    "noise_secure_only".to_string()
                } else {
                    transport_policy_arg
                };
            let webui_path = if webui_path.is_none() && production_profile {
                Some(PathBuf::from(PRODUCTION_DEFAULT_WEBUI_PATH))
            } else {
                webui_path
            };
            let config = confidis_node::ConfidISConfig {
                node: confidis_node::NodeConfigSection {
                    node_id,
                    production_profile,
                    region,
                    failure_domain,
                    max_bytes,
                    private_key,
                    x25519_secret_key,
                },
                storage: confidis_node::StorageConfigSection {
                    store_path,
                    registry_path,
                    read_access_revocations_path: None,
                    packages_path,
                    node_ban_list_path,
                    authority_private_key_path,
                },
                network: confidis_node::NetworkConfigSection {
                    listen_addr,
                    public_endpoint,
                    bootstrap_peers,
                    discovery_backend: "federation_gossip".to_string(),
                    kademlia_listen_addr: None,
                    kademlia_bootstrap_peers: Vec::new(),
                    kademlia_relay_peers: Vec::new(),
                    transport_policy: transport_policy_arg,
                    node_ban_list_url,
                    confidis_root_pubkey,
                },
                security: confidis_node::SecurityConfigSection {
                    authorized_operator_pubkeys,
                    compliance_token: None,
                    security_event_webhook_urls: vec![],
                    ui_token,
                },
                usage: confidis_node::UsageConfigSection {
                    min_expiry_days: 1,
                    max_expiry_days: 365,
                    max_shards_per_owner_per_hour,
                    max_cellules_per_owner,
                },
                ui: confidis_node::UiConfigSection {
                    ui_allowed_origin,
                    webui_path,
                    content_dir,
                },
                monitoring: confidis_node::MonitoringConfigSection {
                    metrics_enabled: true,
                    health_check_interval_secs: 30,
                    maintenance_job_interval_secs: 300,
                },
                storage_backend: confidis_node::StorageBackendConfig {
                    backend_type: "filesystem".to_string(),
                    filesystem_root,
                    s3_bucket: None,
                    s3_region: None,
                    s3_access_key: None,
                    s3_secret_key: None,
                    s3_endpoint: None,
                },
            };
            let mut value = serde_json::to_value(&config)?;
            if let Some(object) = value.as_object_mut() {
                let placement_policy = if config.node.production_profile {
                    confidis_protocol::PlacementPolicy::production()
                } else {
                    confidis_protocol::PlacementPolicy::default()
                };
                object.insert(
                    "node_id".to_string(),
                    serde_json::to_value(&config.node.node_id)?,
                );
                object.insert(
                    "production_profile".to_string(),
                    serde_json::to_value(config.node.production_profile)?,
                );
                object.insert(
                    "store_path".to_string(),
                    serde_json::to_value(config.storage.store_path.display().to_string())?,
                );
                object.insert(
                    "placement_policy".to_string(),
                    serde_json::to_value(placement_policy)?,
                );
                object.insert(
                    "node_ban_list_path".to_string(),
                    serde_json::to_value(
                        config
                            .storage
                            .node_ban_list_path
                            .as_ref()
                            .map(|path| path.display().to_string()),
                    )?,
                );
                object.insert(
                    "authority_private_key_path".to_string(),
                    serde_json::to_value(
                        config
                            .storage
                            .authority_private_key_path
                            .as_ref()
                            .map(|path| path.display().to_string()),
                    )?,
                );
                object.insert(
                    "node_ban_list_url".to_string(),
                    serde_json::to_value(&config.network.node_ban_list_url)?,
                );
                object.insert(
                    "authorized_operator_pubkeys".to_string(),
                    serde_json::to_value(&config.security.authorized_operator_pubkeys)?,
                );
                object.insert(
                    "ui_token".to_string(),
                    serde_json::to_value(&config.security.ui_token)?,
                );
                object.insert(
                    "ui_allowed_origin".to_string(),
                    serde_json::to_value(&config.ui.ui_allowed_origin)?,
                );
                object.insert(
                    "webui_path".to_string(),
                    serde_json::to_value(
                        config
                            .ui
                            .webui_path
                            .as_ref()
                            .map(|path| path.display().to_string()),
                    )?,
                );
                object.insert(
                    "content_dir".to_string(),
                    serde_json::to_value(
                        config
                            .ui
                            .content_dir
                            .as_ref()
                            .map(|path| path.display().to_string()),
                    )?,
                );
            }
            fs::write(&output, serde_json::to_vec_pretty(&value)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
            Ok(())
        }
        NodeCommand::CheckConfig { config } => {
            let config = confidis_node::ConfidISConfig::load(Some(&config))
                .with_context(|| format!("failed to load config from {}", config.display()))?;
            config
                .to_node_server_config()
                .context("failed to resolve node server config")?
                .validate()
                .context("invalid node config")?;
            println!("Configuration loaded successfully");
            println!("node_id={}", config.node.node_id);
            println!("production_profile={}", config.node.production_profile);
            println!("listen_addr={}", config.network.listen_addr);
            println!("region={}", config.node.region);
            println!("failure_domain={}", config.node.failure_domain);
            println!("max_bytes={}", config.node.max_bytes);
            println!("ok");
            Ok(())
        }
        NodeCommand::PlacementPolicy { command } => placement_policy(command),
        NodeCommand::Serve { config } => {
            // Initialize structured logging. Respects the RUST_LOG env var
            // (e.g. RUST_LOG=confidis_node=debug,info). Defaults to INFO level.
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .with_target(true)
                .with_thread_ids(false)
                .with_file(false)
                .try_init();

            let config = confidis_node::ConfidISConfig::load(Some(&config))
                .with_context(|| format!("failed to load config from {}", config.display()))?;
            confidis_node::serve(config).await
        }
        NodeCommand::GenToken => {
            use rand_core::{OsRng, RngCore};
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let token = hex::encode(bytes);
            println!("{token}");
            Ok(())
        }
        NodeCommand::GenComplianceToken => {
            use rand_core::{OsRng, RngCore};
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let token = hex::encode(bytes);
            println!("{token}");
            Ok(())
        }
        NodeCommand::Status {
            node,
            ui_token,
            json,
        } => status(node, ui_token, json).await,
        NodeCommand::Info { node, json } => info(node, json).await,
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoteNodeInfo {
    node_role: String,
    production_profile: bool,
}

async fn info(node: String, json: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .with_context(|| "failed to build HTTP client")?;
    let url = format!("{}/node-info", node.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to reach {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("node returned {} for /node-info", resp.status());
    }
    let info: RemoteNodeInfo = resp
        .json()
        .await
        .with_context(|| "invalid /node-info JSON")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    // Human summary — short, color-free (CLI portability).
    let role_label = match info.node_role.as_str() {
        "authority" => "Authority signer",
        "company" => "Company / enterprise",
        other => other,
    };
    println!("Node mode for {node}");
    println!("  node_role          : {role_label}");
    println!(
        "  production_profile : {}",
        if info.production_profile { "yes" } else { "no" }
    );
    Ok(())
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoteHealthStatus {
    status: String,
    node_id: serde_json::Value,
    version: String,
    uptime_secs: u64,
    shard_count: u64,
    peer_count: usize,
    #[serde(default)]
    ban_verification_enabled: bool,
    noise_sessions: usize,
    #[serde(default)]
    node_ban_list_present: bool,
    #[serde(default)]
    node_banned: bool,
    #[serde(default = "default_trust_root_source")]
    trust_root_source: String,
}

fn default_trust_root_source() -> String {
    "unknown".to_string()
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoteCapacityStatus {
    free_bytes: u64,
    used_bytes: u64,
    max_bytes: u64,
    region: String,
    failure_domain: String,
    health_score: f32,
    current_shard_count: u64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoteMaintenanceStatus {
    updated_at: DateTime<Utc>,
    persisted_path: String,
    jobs: Vec<RemoteMaintenanceJob>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RemoteMaintenanceJob {
    job_id: String,
    label: String,
    status: String,
    last_started_at: Option<DateTime<Utc>>,
    last_finished_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    runs: u64,
    attention: bool,
    detail: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct RemoteNodeStatus {
    node_url: String,
    health: RemoteHealthStatus,
    capacity: Option<RemoteCapacityStatus>,
    maintenance: Option<RemoteMaintenanceStatus>,
}

async fn status(node: String, ui_token: Option<String>, json: bool) -> Result<()> {
    let node = crate::network::normalize_endpoint(&node);
    let client = crate::network::network_client()?;
    let health: RemoteHealthStatus = get_json(&client, &node, "/health", ui_token.as_deref())
        .await
        .context("failed to fetch /health")?;
    let capacity = get_json(&client, &node, "/capacity", ui_token.as_deref())
        .await
        .ok();
    let maintenance = get_json(&client, &node, "/maintenance", ui_token.as_deref())
        .await
        .ok();

    let combined = RemoteNodeStatus {
        node_url: node,
        health,
        capacity,
        maintenance,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&combined)?);
    } else {
        print_node_status(&combined);
    }
    Ok(())
}

async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    node: &str,
    path: &str,
    ui_token: Option<&str>,
) -> Result<T> {
    let mut request = client.get(format!("{node}{path}"));
    if let Some(token) = ui_token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        anyhow::bail!("{path} returned {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("invalid JSON from {path}"))
}

fn print_node_status(status: &RemoteNodeStatus) {
    println!("node: {}", status.node_url);
    println!("node_id: {}", node_id_to_string(&status.health.node_id));
    println!("version: {}", status.health.version);
    println!("process: {}", status.health.status);
    println!("uptime: {}s", status.health.uptime_secs);
    println!("local_shards: {}", status.health.shard_count);
    println!("peers: {}", status.health.peer_count);
    println!("noise_sessions: {}", status.health.noise_sessions);
    println!("participation: permissionless (writes gated by local quotas/federation policy)");
    println!(
        "ban_verification_enabled: {}",
        status.health.ban_verification_enabled
    );
    println!("trust_root_source: {}", status.health.trust_root_source);
    println!(
        "node_ban_list: {}",
        if status.health.node_ban_list_present {
            "present"
        } else {
            "absent"
        }
    );
    println!(
        "node_status: {}",
        if status.health.node_banned {
            "BANNED/QUARANTINED by CONFIDIS authority"
        } else {
            "not banned"
        }
    );

    if let Some(capacity) = &status.capacity {
        println!("capacity_used_bytes: {}", capacity.used_bytes);
        println!("capacity_free_bytes: {}", capacity.free_bytes);
        println!("capacity_max_bytes: {}", capacity.max_bytes);
        println!("capacity_health_score: {:.4}", capacity.health_score);
        println!("region: {}", capacity.region);
        println!("failure_domain: {}", capacity.failure_domain);
        println!("capacity_shards: {}", capacity.current_shard_count);
    } else {
        println!("capacity: unavailable");
    }

    if let Some(maintenance) = &status.maintenance {
        let attention = maintenance
            .jobs
            .iter()
            .filter(|job| job.attention || job.status == "attention")
            .count();
        println!(
            "maintenance_updated_at: {}",
            maintenance.updated_at.to_rfc3339()
        );
        println!("maintenance_persisted_path: {}", maintenance.persisted_path);
        println!("maintenance_attention: {}", attention);
        for job in &maintenance.jobs {
            let last_run = job
                .last_finished_at
                .or(job.last_started_at)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "never".to_string());
            println!(
                "maintenance_job: {} status={} runs={} last_run={} detail={}",
                job.job_id,
                job.status,
                job.runs,
                last_run,
                job.detail.as_deref().unwrap_or("-")
            );
            if let Some(error) = &job.last_error {
                println!("maintenance_error: {} {}", job.job_id, error);
            }
        }
    } else {
        println!("maintenance: unavailable");
    }
}

fn node_id_to_string(value: &serde_json::Value) -> String {
    value
        .get("0")
        .and_then(|v| v.as_str())
        .or_else(|| value.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn validate_placement_policy(policy: &PlacementPolicy) -> Result<()> {
    if policy.health_score_floor < 0.0 || policy.health_score_floor > 1.0 {
        anyhow::bail!(
            "health_score_floor must be in [0.0, 1.0], got {}",
            policy.health_score_floor
        );
    }
    Ok(())
}

fn print_placement_policy_table(policy: &PlacementPolicy) {
    println!(
        "{:<28} {}",
        "health_score_floor:", policy.health_score_floor
    );
    println!(
        "{:<28} {}",
        "min_failure_domains:", policy.min_failure_domains
    );
    println!("{:<28} {}", "min_unique_nodes:", policy.min_unique_nodes);
    if policy.is_unconstrained() {
        println!("status: unconstrained (development mode — no limits enforced)");
    } else {
        println!("status: constrained (production limits active)");
    }
}

fn placement_policy(command: PlacementPolicyCommand) -> Result<()> {
    match command {
        PlacementPolicyCommand::InitDev => {
            let policy = PlacementPolicy::default();
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        PlacementPolicyCommand::InitProduction => {
            let policy = PlacementPolicy::production();
            println!("{}", serde_json::to_string_pretty(&policy)?);
            Ok(())
        }
        PlacementPolicyCommand::Show { file } => {
            let bytes =
                fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
            let policy: PlacementPolicy =
                serde_json::from_slice(&bytes).context("invalid placement policy JSON")?;
            print_placement_policy_table(&policy);
            Ok(())
        }
        PlacementPolicyCommand::Validate { file } => {
            let bytes =
                fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
            let policy: PlacementPolicy =
                serde_json::from_slice(&bytes).context("invalid placement policy JSON")?;
            validate_placement_policy(&policy)?;
            println!("ok");
            Ok(())
        }
    }
}
