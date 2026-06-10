use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use confidis_crypto::{
    generate_signing_key, signing_key_from_hex, signing_key_to_hex, verifying_key_to_hex,
    x25519_generate,
};
use confidis_protocol::{
    MAX_CELLULE_LIFETIME_DAYS, NodeBanList, NodeConfig, NodeId, PRODUCTION_HEALTH_SCORE_FLOOR,
    PRODUCTION_MIN_FAILURE_DOMAINS, PRODUCTION_MIN_UNIQUE_NODES, PlacementPolicy, TransportPolicy,
    genesis_root_pubkey_source, get_genesis_root_pubkey, verify_node_ban_list,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

const ALLOW_AUTHORITY_SIGNER_NETWORK_BIND_ENV: &str = "CONFIDIS_ALLOW_AUTHORITY_SIGNER_NETWORK_BIND";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalNodeIdentity {
    version: u16,
    node_id: String,
    private_key: String,
    x25519_secret_key: String,
}

#[derive(Debug, Clone)]
pub struct NodeServerConfig {
    pub node_id: NodeId,
    pub production_profile: bool,
    pub transport_policy: TransportPolicy,
    pub listen_addr: SocketAddr,
    pub public_endpoint: Option<String>,
    pub bootstrap_peers: Vec<String>,
    /// Discovery backend selector. Defaults to the signed HTTP federation
    /// path. `"hybrid_kademlia"` starts an additional libp2p Kademlia worker
    /// while preserving signed HTTP discovery as a compatibility plane.
    pub discovery_backend: String,
    /// libp2p multiaddr to listen on when `discovery_backend=hybrid_kademlia`.
    pub kademlia_listen_addr: Option<String>,
    /// Kademlia seed peers as multiaddrs. A trailing `/p2p/<peer-id>` is
    /// preferred, but DNS/socket-only multiaddrs are accepted and upgraded after
    /// Identify reports the remote peer id.
    pub kademlia_bootstrap_peers: Vec<String>,
    /// Optional libp2p circuit-relay peers as `/ip4/.../tcp/.../p2p/<relay-id>`
    /// multiaddrs. Nodes dial these peers and request relay reservations through
    /// `/p2p/<relay-id>/p2p-circuit`.
    pub kademlia_relay_peers: Vec<String>,
    pub store_path: PathBuf,
    pub region: String,
    pub failure_domain: String,
    pub max_bytes: u64,
    pub signing_key: Option<SigningKey>,
    pub placement_policy: PlacementPolicy,
    pub node_ban_list_path: Option<PathBuf>,
    /// Path to an authority Ed25519 private-key file (hex, 0600).
    /// Labs/isolated signer only; rejected on production public nodes.
    /// Env `CONFIDIS_AUTHORITY_PRIVATE_KEY` takes precedence.
    pub authority_private_key_path: Option<PathBuf>,
    pub node_ban_list_url: Option<String>,
    /// Legacy single CONFIDIS root verifying key. Used to verify the signed node
    /// ban list. Production paid shard-write authorizations are verified
    pub confidis_root_pubkey: Option<VerifyingKey>,
    pub confidis_root_source: String,
    /// CONFIDIS authority-signed node ban/quarantine list loaded from disk on
    /// startup. Nodes refuse shards/data to or from banned node pubkeys.
    pub node_ban_list: Option<NodeBanList>,
    /// X25519 static key (32 bytes) for Noise_XX transport sessions.
    /// Derived from `NodeConfig.x25519_secret_key`. When `None`, Noise
    /// endpoints generate an ephemeral key per-session (no mutual auth).
    pub x25519_static_key: Option<[u8; 32]>,
    /// Path to the local Cellule registry JSON file (served via GET /cellules).
    pub registry_path: Option<PathBuf>,
    /// Path to owner-signed read-access revocation log JSON.
    pub read_access_revocations_path: Option<PathBuf>,
    /// Path to recipient packages registry JSON file.
    pub packages_path: Option<PathBuf>,
    /// Static bearer token for local/development web UI management routes.
    /// A production public SPA must not rely on this value for privilege:
    /// management routes are not mounted in its public surface.
    pub ui_token: Option<String>,
    /// Allowed CORS origin for the web UI (e.g. `"https://ui.confidis.eu"`).
    /// When `Some`, CORS is restricted to this exact origin and only the necessary
    /// headers are allowed. When `None`, CORS uses wildcard `*` (dev mode).
    pub ui_allowed_origin: Option<String>,
    /// Deprecated legacy operator pricing field.
    /// Deprecated legacy operator pricing field.
    /// Minimum Cellule lifetime in days.
    pub min_expiry_days: u32,
    /// Maximum Cellule lifetime in days.
    pub max_expiry_days: u32,
    /// Maximum shards per owner per hour.  0 = unlimited.
    pub max_shards_per_owner_per_hour: u32,
    /// Maximum cellules per owner.  0 = unlimited.
    pub max_cellules_per_owner: u32,
    /// Operator wallet public keys allowed to run authenticated operator-side operations.
    /// Hex-encoded Ed25519 public keys, parsed at config load.
    pub authorized_operator_pubkeys: Vec<String>,
    /// Path to the bundled web-UI dist directory, served at `/ui`.
    /// Defaults to `./webui/` if the directory exists, otherwise UI is disabled.
    pub webui_path: Option<PathBuf>,
    /// Optional path to a static content directory served at `/`.
    /// Use this to turn the node into a marketing/docs website (e.g. confidis.fr).
    pub content_dir: Option<PathBuf>,
    /// Webhook URLs for security event export (JSON format).
    /// Events will be POSTed to each URL with Content-Type: application/json.
    pub security_event_webhook_urls: Vec<String>,
    /// Static bearer token for SOC/compliance viewer access.
    /// When set, enables `/compliance/*` endpoints for security event viewing and audit logs.
    pub compliance_token: Option<String>,
}

impl NodeServerConfig {
    pub fn from_protocol(config: NodeConfig) -> Result<Self> {
        if config.min_expiry_days == 0 {
            bail!("min_expiry_days must be at least 1");
        }
        if config.min_expiry_days > config.max_expiry_days {
            bail!("min_expiry_days cannot be greater than max_expiry_days");
        }
        if config.max_expiry_days > MAX_CELLULE_LIFETIME_DAYS as u32 {
            bail!(
                "max_expiry_days cannot exceed {} days",
                MAX_CELLULE_LIFETIME_DAYS
            );
        }

        let store_path = PathBuf::from(&config.store_path);
        let local_identity = load_or_create_local_identity(&store_path, &config)?;
        let resolved_node_id = if config.node_id.0.trim().is_empty() {
            NodeId(local_identity.node_id.clone())
        } else {
            config.node_id.clone()
        };
        let resolved_private_key = config
            .private_key
            .as_deref()
            .unwrap_or(&local_identity.private_key);
        let resolved_x25519_secret_key = config
            .x25519_secret_key
            .as_deref()
            .unwrap_or(&local_identity.x25519_secret_key);
        let node_ban_list_path = config.node_ban_list_path.map(PathBuf::from);
        let authority_private_key_path = config.authority_private_key_path.map(PathBuf::from);

        // Try to load the authority-signed node ban list from disk (best-effort).
        let node_ban_list = node_ban_list_path
            .as_deref()
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<NodeBanList>(&s).ok());

        // Parse the optional CONFIDIS root public key from config, falling back to the
        // genesis key embedded in the binary. This ensures enforcement mode is always
        // active in production builds without requiring manual config.
        let explicit_root = config.confidis_root_pubkey.is_some();
        let confidis_root_pubkey = config
            .confidis_root_pubkey
            .as_deref()
            .map(|hex_str| {
                let bytes = hex::decode(hex_str).context("invalid confidis_root_pubkey hex")?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("confidis_root_pubkey must be 32 bytes"))?;
                VerifyingKey::from_bytes(&arr).context("invalid confidis_root_pubkey")
            })
            .transpose()?
            .or_else(get_genesis_root_pubkey); // fall back to genesis key if no override
        let confidis_root_source = if explicit_root {
            "config"
        } else {
            genesis_root_pubkey_source()
        }
        .to_string();

        // Parse the optional X25519 static key for Noise transport.
        let x25519_static_key = config
            .x25519_secret_key
            .as_deref()
            .or(Some(resolved_x25519_secret_key))
            .map(|hex_str| {
                let bytes = hex::decode(hex_str).context("invalid x25519_secret_key hex")?;
                bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("x25519_secret_key must be 32 bytes"))
            })
            .transpose()?;

        Ok(Self {
            node_id: resolved_node_id,
            production_profile: config.production_profile,
            transport_policy: config.transport_policy,
            listen_addr: config
                .listen_addr
                .parse()
                .context("invalid node listen address")?,
            public_endpoint: config.public_endpoint,
            bootstrap_peers: config.bootstrap_peers,
            discovery_backend: "federation_gossip".to_string(),
            kademlia_listen_addr: None,
            kademlia_bootstrap_peers: Vec::new(),
            kademlia_relay_peers: Vec::new(),
            store_path,
            region: config.region,
            failure_domain: config.failure_domain,
            max_bytes: config.max_bytes,
            signing_key: Some(signing_key_from_hex(resolved_private_key)?),
            placement_policy: config.placement_policy,
            node_ban_list_path,
            authority_private_key_path,
            node_ban_list_url: config.node_ban_list_url,
            confidis_root_pubkey,
            confidis_root_source,
            node_ban_list,
            x25519_static_key,
            registry_path: config.registry_path.map(PathBuf::from),
            read_access_revocations_path: config.read_access_revocations_path.map(PathBuf::from),
            packages_path: config.packages_path.map(PathBuf::from),
            ui_token: config.ui_token,
            ui_allowed_origin: config.ui_allowed_origin,
            min_expiry_days: config.min_expiry_days,
            max_expiry_days: config.max_expiry_days,
            max_shards_per_owner_per_hour: config.max_shards_per_owner_per_hour,
            max_cellules_per_owner: config.max_cellules_per_owner,
            authorized_operator_pubkeys: config.authorized_operator_pubkeys,
            webui_path: config.webui_path.map(PathBuf::from).or_else(|| {
                // Default: look for ./webui/ adjacent to the working directory.
                let p = PathBuf::from("webui");
                if p.exists() { Some(p) } else { None }
            }),
            content_dir: config.content_dir.map(PathBuf::from),
            security_event_webhook_urls: config.security_event_webhook_urls,
            compliance_token: config.compliance_token,
        })
    }

    /// Validate the resolved config.
    ///
    /// Hard errors (return `Err`) prevent the node from starting at all.
    /// Soft warnings are logged via `tracing::warn!` but do not abort startup.
    pub fn validate(&self) -> Result<()> {
        // --- Hard checks ---
        if self.node_id.0.is_empty() {
            bail!("node_id must not be empty");
        }
        if self.max_bytes == 0 {
            bail!("max_bytes must be greater than zero");
        }
        let production_errors = self.production_readiness_errors();
        if !production_errors.is_empty() {
            bail!(
                "production profile is not satisfied:\n- {}",
                production_errors.join("\n- ")
            );
        }
        let authority_key_sources = self.authority_private_key_sources();
        if !authority_key_sources.is_empty()
            && !self.listen_addr.ip().is_loopback()
            && !env_var_truthy(ALLOW_AUTHORITY_SIGNER_NETWORK_BIND_ENV)
        {
            bail!(
                "authority signer key material is configured ({}) but listen_addr={} is not loopback; \
                 bind the signer to 127.0.0.1/::1 or set {ALLOW_AUTHORITY_SIGNER_NETWORK_BIND_ENV}=1 \
                 only inside an isolated private signer network",
                authority_key_sources.join(", "),
                self.listen_addr
            );
        }

        // Ensure the shard store directory exists (create it if possible).
        if !self.store_path.exists() {
            fs::create_dir_all(&self.store_path).with_context(|| {
                format!(
                    "store_path '{}' does not exist and could not be created",
                    self.store_path.display()
                )
            })?;
        }
        // Verify the store_path is writable by creating and removing a probe file.
        let probe = self.store_path.join(".confidis_write_probe");
        fs::write(&probe, b"probe").with_context(|| {
            format!("store_path '{}' is not writable", self.store_path.display())
        })?;
        let _ = fs::remove_file(&probe);

        // --- Soft warnings ---
        if self.bootstrap_peers.is_empty() {
            tracing::warn!(
                "no federation peers configured — node will start isolated; \
                 set trusted federation peers in the config"
            );
        }
        match self.discovery_backend.as_str() {
            "federation_gossip" | "bootstrap_gossip" | "hybrid_kademlia" => {}
            other => bail!(
                "invalid discovery_backend={other:?}; expected 'federation_gossip' or 'hybrid_kademlia'"
            ),
        }
        if self.discovery_backend == "hybrid_kademlia" && self.kademlia_listen_addr.is_none() {
            tracing::warn!(
                "discovery_backend=hybrid_kademlia but kademlia_listen_addr is not set; \
                 using /ip4/0.0.0.0/tcp/0"
            );
        }
        if self.signing_key.is_none() {
            tracing::warn!(
                "private_key not set — node receipts will be unsigned; \
                 run `node init-config --private-key <hex>` to add a signing key"
            );
        }
        if self.node_ban_list_path.is_none() {
            tracing::warn!(
                "node_ban_list_path not configured — this node will not enforce \
                 CONFIDIS authority bans/quarantines (node participation stays \
                 permissionless regardless)"
            );
        } else if self.node_ban_list.is_none() {
            tracing::warn!(
                "node ban list file not found or invalid — \
                 check node_ban_list_path in the config"
            );
        }
        // The CONFIDIS authority root key verifies the signed node ban list. It does
        // NOT gate admission (participation is permissionless). Still require a
        // real root in release builds so authority governance material can be
        // verified at all.
        if self.confidis_root_pubkey.is_none() {
            #[cfg(not(debug_assertions))]
            bail!(
                "confidis_root_pubkey is not set — CONFIDIS authority governance material \
                 (node ban list) cannot be verified. Build with a real CONFIDIS genesis \
                 root or set confidis_root_pubkey before starting a production node."
            );
            #[cfg(debug_assertions)]
            tracing::warn!(
                "⚠️  confidis_root_pubkey is not set — authority ban-list verification \
                 is DISABLED. Do NOT treat this node as production-ready."
            );
        }

        if self.placement_policy.is_unconstrained() {
            tracing::warn!(
                "placement_policy has no constraints (all zeros) — \
                 for production set health_score_floor≥{PRODUCTION_HEALTH_SCORE_FLOOR}, \
                 min_failure_domains≥{PRODUCTION_MIN_FAILURE_DOMAINS}, \
                 min_unique_nodes≥{PRODUCTION_MIN_UNIQUE_NODES}"
            );
        }
        if self.max_bytes < 1024 * 1024 {
            tracing::warn!(
                max_bytes = self.max_bytes,
                "max_bytes is less than 1 MiB — this is unusually small"
            );
        }
        if !self.production_profile && self.ui_token.is_none() {
            tracing::warn!(
                "ui_token not configured — local management UI endpoints are unauthenticated; \
                 run `confidis node gen-token` and set ui_token in your node config"
            );
        }

        // In production mode, require secure transport policy.
        if self.production_profile {
            match self.transport_policy {
                TransportPolicy::Development => {
                    bail!(
                        "production_profile=true but transport_policy=development — \
                         production deployments must use either 'noise_secure_only' or \
                         'https_reverse_proxy' to prevent plain HTTP shard exposure"
                    );
                }
                TransportPolicy::NoiseSecureOnly | TransportPolicy::HttpsReverseProxy => {
                    // These are acceptable for production.
                    Ok(())
                }
            }
        } else if matches!(
            self.transport_policy,
            TransportPolicy::NoiseSecureOnly | TransportPolicy::HttpsReverseProxy
        ) {
            tracing::warn!(
                "transport_policy is set to secure mode but production_profile=false — \
                 this will disable plain HTTP shard endpoints even in development"
            );
            Ok(())
        } else {
            Ok(())
        }
    }

    pub fn production_readiness_errors(&self) -> Vec<String> {
        if !self.production_profile {
            return Vec::new();
        }

        let mut errors = Vec::new();
        if self.signing_key.is_none() {
            errors.push(
                "private_key is required so node receipts and peer records are signed".to_string(),
            );
        }
        if self.x25519_static_key.is_none() {
            errors.push(
                "x25519_secret_key is required for authenticated Noise transport".to_string(),
            );
        }
        // CONFIDIS OS v1 production admission is quota/federation based. A
        let authority_key_sources = self.authority_private_key_sources();
        if !authority_key_sources.is_empty() {
            errors.push(format!(
                "production_profile public nodes must not load CONFIDIS authority private key material ({}) — run any legacy signer flow on an isolated host/quorum ceremony",
                authority_key_sources.join(", ")
            ));
        }
        if self.max_expiry_days > MAX_CELLULE_LIFETIME_DAYS as u32 {
            errors.push(format!(
                "max_expiry_days must not exceed {} days in production",
                MAX_CELLULE_LIFETIME_DAYS
            ));
        }
        if self.ui_allowed_origin.is_none() {
            errors.push(
                "ui_allowed_origin is required so production CORS is not wildcard".to_string(),
            );
        }
        match self.public_endpoint.as_deref() {
            Some(endpoint) => {
                if let Some(err) = production_public_endpoint_error(endpoint) {
                    errors.push(err);
                }
            }
            None => {
                errors.push(
                    "public_endpoint is required for peer records and operator diagnostics"
                        .to_string(),
                );
            }
        }
        if self.placement_policy.is_unconstrained() {
            errors.push(format!(
                "placement_policy must be constrained (recommended: health_score_floor={PRODUCTION_HEALTH_SCORE_FLOOR}, min_failure_domains={PRODUCTION_MIN_FAILURE_DOMAINS}, min_unique_nodes={PRODUCTION_MIN_UNIQUE_NODES})"
            ));
        }
        if self.max_shards_per_owner_per_hour == 0 {
            errors.push("max_shards_per_owner_per_hour must be non-zero".to_string());
        }
        if self.max_cellules_per_owner == 0 {
            errors.push("max_cellules_per_owner must be non-zero".to_string());
        }
        if self.authorized_operator_pubkeys.iter().any(|key| {
            key.len() != 64 || !key.chars().all(|character| character.is_ascii_hexdigit())
        }) {
            errors.push(
                "authorized_operator_pubkeys entries must be 32-byte public keys encoded as hex; \
                 production public routes do not expose operator inventory until signed \
                 operator authentication is implemented"
                    .to_string(),
            );
        }
        if self.webui_path.is_none() && self.content_dir.is_none() {
            errors.push("webui_path or content_dir is required so the node ships a public landing/docs/UI surface".to_string());
        }

        // If a node ban list is present it must verify against the authority
        // root. Its absence is acceptable — bans are a reactive sanction, not a
        // launch precondition.
        if let (Some(list), Some(root)) = (&self.node_ban_list, &self.confidis_root_pubkey)
            && let Err(err) = verify_node_ban_list(list, root, Utc::now())
        {
            errors.push(format!("node ban list verification failed: {err}"));
        }

        errors
    }

    fn authority_private_key_sources(&self) -> Vec<String> {
        let mut sources = Vec::new();
        if self.authority_private_key_path.is_some() {
            sources.push("authority_private_key_path".to_string());
        }
        sources
    }
}

fn production_public_endpoint_error(endpoint: &str) -> Option<String> {
    let parsed = match reqwest::Url::parse(endpoint) {
        Ok(parsed) => parsed,
        Err(_) => {
            return Some(
                "public_endpoint must be a valid absolute HTTPS URL such as https://node.example.com"
                    .to_string(),
            );
        }
    };
    if parsed.scheme() != "https" {
        return Some(
            "public_endpoint must use https in production; terminate TLS at Nginx/reverse proxy"
                .to_string(),
        );
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Some(
            "public_endpoint must be a clean public origin without credentials, query or fragment"
                .to_string(),
        );
    }
    let Some(host) = parsed.host_str() else {
        return Some("public_endpoint must include a host".to_string());
    };
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Some(
            "public_endpoint must be externally routable in production; localhost is only valid before exposure"
                .to_string(),
        );
    }
    if host.ends_with(".local") {
        return Some(
            "public_endpoint must be externally routable in production; .local names are not valid beta peer endpoints"
                .to_string(),
        );
    }
    if let Ok(ip) = host.parse::<IpAddr>()
        && !is_publicly_routable_ip(ip)
    {
        return Some(
            "public_endpoint must be externally routable in production; private, loopback, link-local, multicast and unspecified IPs require a future relay/NAT story"
                .to_string(),
        );
    }
    None
}

fn is_publicly_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || ip.is_unspecified())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
    }
}

fn env_var_has_value(name: &str) -> bool {
    std::env::var(name)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn env_var_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn load_or_create_local_identity(
    store_path: &Path,
    config: &NodeConfig,
) -> Result<LocalNodeIdentity> {
    let identity_path = store_path.join("identity").join("local-node-identity.json");
    let legacy_identity_path = store_path
        .join("identity")
        .join("bootstrap-node-identity.json");
    let existing = fs::read_to_string(&identity_path)
        .or_else(|_| fs::read_to_string(&legacy_identity_path))
        .ok()
        .and_then(|body| serde_json::from_str::<LocalNodeIdentity>(&body).ok());

    let private_key = config
        .private_key
        .clone()
        .or_else(|| {
            existing
                .as_ref()
                .map(|identity| identity.private_key.clone())
        })
        .unwrap_or_else(|| signing_key_to_hex(&generate_signing_key()));
    let signing_key =
        signing_key_from_hex(&private_key).context("invalid local or configured private_key")?;

    let x25519_secret_key = config
        .x25519_secret_key
        .clone()
        .or_else(|| {
            existing
                .as_ref()
                .map(|identity| identity.x25519_secret_key.clone())
        })
        .unwrap_or_else(|| x25519_generate().0);

    let node_id = if !config.node_id.0.trim().is_empty() {
        config.node_id.0.clone()
    } else if let Some(existing) = &existing {
        existing.node_id.clone()
    } else {
        let pubkey = verifying_key_to_hex(&signing_key.verifying_key());
        format!("tofu-{}", &pubkey[..16])
    };

    let identity = LocalNodeIdentity {
        version: 1,
        node_id,
        private_key,
        x25519_secret_key,
    };

    if config.node_id.0.trim().is_empty()
        || config.private_key.is_none()
        || config.x25519_secret_key.is_none()
        || existing.is_none()
    {
        persist_local_identity(&identity_path, &identity)?;
    }

    Ok(identity)
}

fn persist_local_identity(path: &Path, identity: &LocalNodeIdentity) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let bytes =
        serde_json::to_vec_pretty(identity).context("failed to serialize local identity")?;
    fs::write(&tmp_path, bytes)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| format!("failed to write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_protocol_config(store_path: String) -> NodeConfig {
        NodeConfig {
            node_id: NodeId("config-test-node".to_string()),
            production_profile: false,
            listen_addr: "127.0.0.1:0".to_string(),
            public_endpoint: None,
            bootstrap_peers: Vec::new(),
            store_path,
            region: "eu-fr".to_string(),
            failure_domain: "fd-test".to_string(),
            max_bytes: 1024 * 1024,
            private_key: None,
            x25519_secret_key: None,
            node_ban_list_path: None,
            authority_private_key_path: None,
            node_ban_list_url: None,
            authority_spend_url: None,
            payer_mode: confidis_protocol::PayerMode::NodeSelf,
            confidis_root_pubkey: None,
            placement_policy: PlacementPolicy::default(),
            registry_path: None,
            read_access_revocations_path: None,
            packages_path: None,
            ui_token: None,
            ui_allowed_origin: None,
            min_expiry_days: 1,
            max_expiry_days: MAX_CELLULE_LIFETIME_DAYS as u32,
            max_shards_per_owner_per_hour: 0,
            max_cellules_per_owner: 0,
            authorized_operator_pubkeys: Vec::new(),
            webui_path: None,
            content_dir: None,
            transport_policy: TransportPolicy::Development,
            security_event_webhook_urls: Vec::new(),
            compliance_token: None,
        }
    }

    #[test]
    fn from_protocol_applies_static_defaults() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let config = NodeServerConfig::from_protocol(base_protocol_config(
            temp_dir.path().display().to_string(),
        ))
        .expect("node server config");

        assert!(config.webui_path.is_none());
        assert!(config.content_dir.is_none());
    }

    #[test]
    fn from_protocol_creates_stable_local_identity_when_config_is_empty() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let store_path = temp_dir.path().join("store").display().to_string();
        let mut protocol = base_protocol_config(store_path.clone());
        protocol.node_id = NodeId(String::new());

        let first = NodeServerConfig::from_protocol(protocol.clone()).expect("first config");
        let second = NodeServerConfig::from_protocol(protocol).expect("second config");

        assert!(first.node_id.0.starts_with("tofu-"));
        assert_eq!(first.node_id, second.node_id);
        assert!(first.signing_key.is_some());
        assert!(first.x25519_static_key.is_some());
        assert!(
            temp_dir
                .path()
                .join("store/identity/local-node-identity.json")
                .exists()
        );
    }

    #[test]
    fn from_protocol_preserves_operator_and_static_overrides() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let webui = temp_dir.path().join("webui");
        let content = temp_dir.path().join("content");
        let mut protocol =
            base_protocol_config(temp_dir.path().join("store").display().to_string());
        protocol.authorized_operator_pubkeys = vec!["operator-pubkey".to_string()];
        protocol.webui_path = Some(webui.display().to_string());
        protocol.content_dir = Some(content.display().to_string());

        let config = NodeServerConfig::from_protocol(protocol).expect("node server config");

        assert_eq!(config.authorized_operator_pubkeys, vec!["operator-pubkey"]);
        assert_eq!(config.webui_path.as_deref(), Some(webui.as_path()));
        assert_eq!(config.content_dir.as_deref(), Some(content.as_path()));
    }

    #[test]
    fn production_profile_reports_missing_required_controls() {
        // Acquire the crate-wide env lock — `production_readiness_errors()`
        // reads `CONFIDIS_AUTHORITY_PRIVATE_KEY[S]`, and parallel
        // `authority_service::tests::*` mutate those env vars.
        let _env = crate::test_support::env_sync_lock().lock().unwrap();

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut protocol = base_protocol_config(temp_dir.path().display().to_string());
        protocol.production_profile = true;

        let config = NodeServerConfig::from_protocol(protocol).expect("node server config");
        let errors = config.production_readiness_errors();

        assert!(!errors.iter().any(|e| e.contains("private_key is required")));
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("x25519_secret_key is required"))
        );
        assert!(!errors.iter().any(|e| e.contains("genesis root public key")));
        assert!(!errors.iter().any(|e| e.contains("ui_token")));
        assert!(errors.iter().any(|e| e.contains("ui_allowed_origin")));
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("authorized_operator_pubkeys"))
        );
        assert!(errors.iter().any(|e| e.contains("placement_policy")));
        assert!(
            errors
                .iter()
                .any(|e| e.contains("public landing/docs/UI surface"))
        );
    }

    #[test]
    fn production_profile_rejects_authority_private_key_material() {
        let _env = crate::test_support::env_sync_lock().lock().unwrap();

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut protocol = base_protocol_config(temp_dir.path().display().to_string());
        protocol.production_profile = true;
        protocol.authority_private_key_path = Some("/etc/confidis/authority.key".to_string());

        let config = NodeServerConfig::from_protocol(protocol).expect("node server config");
        let errors = config.production_readiness_errors();

        assert!(
            errors.iter().any(|e| e.contains(
                "production_profile public nodes must not load CONFIDIS authority private key material"
            )),
            "expected authority key material error, got {errors:?}"
        );
    }

    #[test]
    fn production_profile_rejects_non_routable_public_endpoint() {
        let _env = crate::test_support::env_sync_lock().lock().unwrap();
        unsafe { std::env::remove_var(ALLOW_AUTHORITY_SIGNER_NETWORK_BIND_ENV) };

        for endpoint in [
            "http://node.example.com",
            "https://localhost",
            "https://node.local",
            "https://127.0.0.1",
            "https://10.0.0.12",
            "https://172.16.0.12",
            "https://192.168.1.12",
            "https://169.254.1.10",
        ] {
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let mut protocol = production_ready_protocol(
                temp_dir.path().join("store").display().to_string(),
                endpoint,
            );

            let config =
                NodeServerConfig::from_protocol(protocol.clone()).expect("node server config");
            let errors = config.production_readiness_errors();
            assert!(
                errors.iter().any(|e| e.contains("public_endpoint")),
                "expected public endpoint error for {endpoint}, got {errors:?}"
            );

            protocol.public_endpoint = Some("https://node.example.com".to_string());
            let config = NodeServerConfig::from_protocol(protocol).expect("node server config");
            let errors = config.production_readiness_errors();
            assert!(
                !errors.iter().any(|e| e.contains("public_endpoint")),
                "expected routable https endpoint to pass, got {errors:?}"
            );
        }
    }

    #[test]
    fn authority_signer_key_material_requires_loopback_bind_by_default() {
        let _env = crate::test_support::env_sync_lock().lock().unwrap();
        unsafe { std::env::remove_var(ALLOW_AUTHORITY_SIGNER_NETWORK_BIND_ENV) };

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut protocol =
            base_protocol_config(temp_dir.path().join("store").display().to_string());
        protocol.listen_addr = "0.0.0.0:4444".to_string();
        protocol.authority_private_key_path = Some("/secure/authority-1.key".to_string());

        let config = NodeServerConfig::from_protocol(protocol).expect("node server config");
        let err = config
            .validate()
            .expect_err("network signer bind must fail");
        assert!(
            err.to_string()
                .contains("authority signer key material is configured"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn authority_signer_network_bind_requires_explicit_override() {
        let _env = crate::test_support::env_sync_lock().lock().unwrap();
        unsafe { std::env::set_var(ALLOW_AUTHORITY_SIGNER_NETWORK_BIND_ENV, "1") };

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let mut protocol =
            base_protocol_config(temp_dir.path().join("store").display().to_string());
        protocol.listen_addr = "0.0.0.0:4444".to_string();
        protocol.authority_private_key_path = Some("/secure/authority-1.key".to_string());

        let config = NodeServerConfig::from_protocol(protocol).expect("node server config");
        config.validate().expect("explicit isolated bind override");

        unsafe { std::env::remove_var(ALLOW_AUTHORITY_SIGNER_NETWORK_BIND_ENV) };
    }

    fn production_ready_protocol(store_path: String, endpoint: &str) -> NodeConfig {
        let mut protocol = base_protocol_config(store_path);
        let root = generate_signing_key();
        protocol.production_profile = true;
        protocol.transport_policy = TransportPolicy::HttpsReverseProxy;
        protocol.public_endpoint = Some(endpoint.to_string());
        protocol.confidis_root_pubkey = Some(verifying_key_to_hex(&root.verifying_key()));
        protocol.ui_allowed_origin = Some(endpoint.to_string());
        protocol.placement_policy = PlacementPolicy::production();
        protocol.max_shards_per_owner_per_hour = 1000;
        protocol.max_cellules_per_owner = 100;
        protocol.webui_path = Some("/usr/share/confidis/webui".to_string());
        protocol
    }
}
