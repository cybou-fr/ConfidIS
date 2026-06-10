use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_DATA_SHARDS: usize = 20;
pub const DEFAULT_PARITY_SHARDS: usize = 10;
pub const MAX_CELLULE_LIFETIME_DAYS: i64 = 365;
pub const RENEWAL_NOTICE_DAYS: i64 = 30;

/// Public-testnet (beta) hard ceiling for a single `cellule put` input.
///
/// `cellule put` splits the input into independent `CELLULE_SEGMENT_SIZE_BYTES`
/// Reed–Solomon segments and streams encode work segment-by-segment to the
/// local shard workdir instead of keeping plaintext or encoded segments in
/// memory. Inputs are still rejected above this size *before* opening the file:
/// the remaining ceiling is a public-testnet load/stress guard, not the final
/// protocol capacity. Lifting it requires production-size evidence for large
/// files, quotas, disk pressure and upload recovery; until then this is the
/// honest, enforced beta limit.
pub const BETA_MAX_CELLULE_INPUT_BYTES: u64 = 256 * 1024 * 1024;

/// Fixed streaming segment size. `cellule put` encodes the input as
/// `ceil(len / CELLULE_SEGMENT_SIZE_BYTES)` independent Reed–Solomon segments
/// (one segment for any input ≤ this size — byte-identical to the pre-streaming
/// single-segment path). Stored in `Manifest::segment_size_bytes`.
pub const CELLULE_SEGMENT_SIZE_BYTES: u64 = 8 * 1024 * 1024;

/// Original (pre-encoding) byte length of segment `segment_index` given the
/// whole input length and the segment size. All segments are full except the
/// last. Works for legacy single-segment manifests too (segment 0 ⇒ full len).
pub fn segment_original_len(total_len: u64, segment_size: u64, segment_index: u32) -> u64 {
    if segment_size == 0 {
        return total_len;
    }
    let start = (segment_index as u64).saturating_mul(segment_size);
    total_len.saturating_sub(start).min(segment_size)
}

/// Number of streaming segments for a given input length and segment size.
pub fn segment_count(total_len: u64, segment_size: u64) -> u32 {
    if segment_size == 0 || total_len == 0 {
        return 1;
    }
    total_len.div_ceil(segment_size).max(1) as u32
}
pub const SHARD_DELETE_OPERATION: &str = "shard.delete";
pub const CELLULE_READ_GRANT_OPERATION: &str = "cellule.read.grant";
pub const CELLULE_READ_GRANT_REVOCATION_OPERATION: &str = "cellule.read.grant.revoke";
pub const CELLULE_READ_PROOF_OPERATION: &str = "cellule.read.proof";
pub const CELLULE_OWNER_REPORT_PROOF_OPERATION: &str = "cellule.owner.report.proof";
pub const CELLULE_OWNER_CLAIM_OPERATION: &str = "cellule.owner.claim";
pub const CELLULE_OWNER_CREATE_OPERATION: &str = "cellule.owner.create";
pub const CELLULE_OWNER_RENEW_OPERATION: &str = "cellule.owner.renew";
pub const CELLULE_OWNER_DELETE_OPERATION: &str = "cellule.owner.delete";
pub const STORAGE_FEE_AUTHORIZATION_OPERATION: &str = "storage.fee.authorization";
pub const RECIPIENT_PACKAGE_CREATE_OPERATION: &str = "recipient.package.create";
pub const RECIPIENT_PACKAGE_REMOVE_OPERATION: &str = "recipient.package.remove";
pub const SHARD_PROVIDER_RECORD_FUTURE_GRACE_MINUTES: i64 = 5;
pub const CELLULE_READ_PROOF_TTL_MINUTES: i64 = 5;
/// Maximum age accepted for a `CelluleOwnerClaim.claimed_at` relative to `now`.
/// Bounds replay of an intercepted owner-signed lifecycle payload.
pub const CELLULE_OWNER_CLAIM_TTL_MINUTES: i64 = 15;

/// CONFIDIS network genesis authority public key (Ed25519, hex-encoded).
///
/// This key is the CONFIDIS root of trust — equivalent to a browser CA bundle.
/// It is embedded in every node binary so that every node can independently
/// verify CONFIDIS authority-signed governance material (e.g. the node ban list).
/// It does NOT gate network admission: node participation is permissionless.
///
/// To rotate: publish a new binary with an updated key + a signed transition notice.
///
/// **For development/testing set `CONFIDIS_ROOT_PUBKEY` env-var or `confidis_root_pubkey` in
/// node config to override this value.**
///
/// The default placeholder is all-zeros. Production builds must set the
/// `CONFIDIS_GENESIS_ROOT_PUBKEY_HEX` build-time environment variable to the real
/// root public key generated with `confidis authority init-keypair`.
const CONFIDIS_GENESIS_ROOT_PUBKEY_HEX_DEFAULT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub const CONFIDIS_GENESIS_ROOT_PUBKEY_HEX: &str = match option_env!("CONFIDIS_GENESIS_ROOT_PUBKEY_HEX") {
    Some(value) => value,
    None => CONFIDIS_GENESIS_ROOT_PUBKEY_HEX_DEFAULT,
};

pub fn is_placeholder_genesis_root_pubkey() -> bool {
    CONFIDIS_GENESIS_ROOT_PUBKEY_HEX.len() != 64
        || CONFIDIS_GENESIS_ROOT_PUBKEY_HEX.chars().all(|c| c == '0')
}

pub fn genesis_root_pubkey_source() -> &'static str {
    if is_placeholder_genesis_root_pubkey() {
        "missing"
    } else {
        "embedded"
    }
}

/// Returns the genesis CONFIDIS root [`VerifyingKey`], or `None` when the embedded key is the
/// all-zeros placeholder (development builds where no real authority has been minted yet).
pub fn get_genesis_root_pubkey() -> Option<VerifyingKey> {
    if is_placeholder_genesis_root_pubkey() {
        return None; // placeholder — dev mode
    }
    let bytes = hex::decode(CONFIDIS_GENESIS_ROOT_PUBKEY_HEX).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn verifying_key_from_hex(encoded: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(encoded).context("invalid verifying key hex")?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("verifying key must be 32 bytes")?;
    VerifyingKey::from_bytes(&key_bytes).context("invalid verifying key")
}

/// Recommended production placement threshold: reject nodes below 10% health.
pub const PRODUCTION_HEALTH_SCORE_FLOOR: f32 = 0.1;
/// Recommended production placement threshold: require at least 6 distinct failure domains.
/// With a 20+10 erasure scheme this tolerates losing an entire failure domain
/// while still holding at least 20 data shards.
pub const PRODUCTION_MIN_FAILURE_DOMAINS: usize = 6;
/// Recommended production placement threshold: require at least 20 distinct nodes.
/// Matches the data-shard count so no single node holds two data shards.
pub const PRODUCTION_MIN_UNIQUE_NODES: usize = 20;

/// Production-safety parameters applied before and after placement scoring.
///
/// All limits default to 0/0.0 (disabled) to preserve backward compatibility
/// with development clusters that have fewer than 30 independent nodes.
/// Use [`PlacementPolicy::production()`] for a ready-made production configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementPolicy {
    /// Reject candidate nodes with health_score below this value before scoring.
    /// 0.0 = accept all candidates.
    #[serde(default)]
    pub health_score_floor: f32,
    /// Fail the plan if the result spans fewer than this many unique failure domains.
    /// 0 = no enforcement.
    #[serde(default)]
    pub min_failure_domains: usize,
    /// Fail the plan if the result uses fewer than this many unique nodes.
    /// 0 = no enforcement.
    #[serde(default)]
    pub min_unique_nodes: usize,
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        Self {
            health_score_floor: 0.0,
            min_failure_domains: 0,
            min_unique_nodes: 0,
        }
    }
}

impl PlacementPolicy {
    /// Returns a policy suitable for a 20+10 production cluster:
    /// - `health_score_floor`: [`PRODUCTION_HEALTH_SCORE_FLOOR`] (0.1)
    /// - `min_failure_domains`: [`PRODUCTION_MIN_FAILURE_DOMAINS`] (6)
    /// - `min_unique_nodes`: [`PRODUCTION_MIN_UNIQUE_NODES`] (20)
    pub fn production() -> Self {
        Self {
            health_score_floor: PRODUCTION_HEALTH_SCORE_FLOOR,
            min_failure_domains: PRODUCTION_MIN_FAILURE_DOMAINS,
            min_unique_nodes: PRODUCTION_MIN_UNIQUE_NODES,
        }
    }

    /// Returns `true` when all constraints are disabled (all-zero default).
    pub fn is_unconstrained(&self) -> bool {
        self.health_score_floor == 0.0
            && self.min_failure_domains == 0
            && self.min_unique_nodes == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CelluleId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WalletAddress(pub String);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErasurePolicy {
    pub data_shards: usize,
    pub parity_shards: usize,
}

impl Default for ErasurePolicy {
    fn default() -> Self {
        Self {
            data_shards: DEFAULT_DATA_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
        }
    }
}

impl ErasurePolicy {
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacityReport {
    pub node_id: NodeId,
    #[serde(default)]
    pub public_key: Option<String>,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub max_bytes: u64,
    pub reserved_bytes: u64,
    pub region: String,
    pub failure_domain: String,
    pub health_score: f32,
    pub current_shard_count: u64,
    pub issued_at: DateTime<Utc>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub endpoint: String,
    pub node_id: Option<NodeId>,
    pub public_key: Option<String>,
    pub region: Option<String>,
    pub failure_domain: Option<String>,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerList {
    pub version: u16,
    pub issued_at: DateTime<Utc>,
    pub peers: Vec<PeerRecord>,
}

fn default_min_expiry_days() -> u32 {
    1
}
fn default_max_expiry_days() -> u32 {
    MAX_CELLULE_LIFETIME_DAYS as u32
}

fn is_default_payer_mode(mode: &PayerMode) -> bool {
    *mode == PayerMode::NodeSelf
}

fn is_zero_f64(value: &f64) -> bool {
    *value == 0.0
}

/// See `NodeConfig.payer_mode` for the full semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PayerMode {
    /// The node operator's wallet pays for every data-add operation submitted
    /// through this node. Canonical mode on company/enterprise nodes — operating
    /// the node is the operator's consent to be debited for its clients' adds.
    #[default]
    NodeSelf,
    /// The end-user's own wallet pays — self-pay. Reserved for future
    /// owner-paid federation flows where each user signs with their own owner
    /// key and pays from their personal balance.
    UserOwner,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportPolicy {
    /// Allow both plain HTTP and Noise-secure shard endpoints.
    /// Suitable for development clusters only.
    #[default]
    Development,
    /// Require Noise-secure shard endpoints for all node-to-node shard I/O.
    /// Plain HTTP shard endpoints are disabled.
    NoiseSecureOnly,
    /// HTTPS/mTLS reverse-proxy profile: plain HTTP shard endpoints disabled,
    /// all traffic expected to be TLS-terminated by reverse proxy.
    HttpsReverseProxy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: NodeId,
    /// Enables strict production readiness checks at node startup.
    ///
    /// Development defaults are intentionally permissive so local clusters can run
    /// with a handful of nodes. Production deployments should set this to `true`
    /// so missing trust material, UI authentication, quotas, and placement
    /// constraints become hard startup errors instead of warnings.
    #[serde(default)]
    pub production_profile: bool,
    /// Transport security policy for shard I/O endpoints.
    ///
    /// In production, either `noise_secure_only` or `https_reverse_proxy` must be set
    /// to prevent accidental exposure of plain HTTP shard endpoints.
    #[serde(default)]
    pub transport_policy: TransportPolicy,
    pub listen_addr: String,
    #[serde(default)]
    pub public_endpoint: Option<String>,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    pub store_path: String,
    pub region: String,
    pub failure_domain: String,
    pub max_bytes: u64,
    pub private_key: Option<String>,
    /// X25519 secret key (hex-encoded). Used for inter-node Noise transport
    /// encryption; kept alongside the Ed25519 key.
    #[serde(default)]
    pub x25519_secret_key: Option<String>,
    /// Path to the locally cached CONFIDIS authority-signed node ban list.
    /// Nodes use this to refuse shard storage and data operations to/from
    /// banned or quarantined node public keys. This is a reactive sanction
    /// surface only — node participation is permissionless and never gated by
    /// admission certificates.
    #[serde(default)]
    pub node_ban_list_path: Option<String>,
    /// Path to a 0600 file holding a CONFIDIS authority Ed25519 private key (hex).
    /// Supported for labs/isolated signer processes only; production public
    /// nodes reject authority private key material. The raw secret is never
    /// inlined in config — only this path. Env `CONFIDIS_AUTHORITY_PRIVATE_KEY`
    /// takes precedence when both are set.
    #[serde(default)]
    pub authority_private_key_path: Option<String>,
    /// Optional explicit URL for the CONFIDIS authority node ban list feed.
    #[serde(default)]
    pub node_ban_list_url: Option<String>,
    /// leave unset only for local development or the isolated signer itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_spend_url: Option<String>,
    /// data-add operations going through this node:
    /// - `NodeSelf` (default on company-nodes): the node operator's wallet is
    ///   debited. The node signs the `/authority/spend` request with its own
    ///   identity key (`x-confidis-node-pubkey == node_public_key`), and sets
    ///   `payer_pubkey = node_public_key` on the spend.
    /// - `UserOwner`: the end-user's own wallet is debited (self-pay). Each
    ///   user signs with their own owner key.
    ///
    /// On an authority node the local spend path is taken regardless; this
    /// setting matters for non-authority nodes that POST to
    /// `authority_spend_url`.
    #[serde(default, skip_serializing_if = "is_default_payer_mode")]
    pub payer_mode: PayerMode,
    /// CONFIDIS authority root Ed25519 public key (hex-encoded). When set, the node
    /// verifies the signed node ban list against this key. It does NOT gate
    /// admission — joining the network is permissionless; the only access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidis_root_pubkey: Option<String>,
    #[serde(default)]
    pub placement_policy: PlacementPolicy,
    /// Path to the local Cellule registry JSON file.
    /// When set, `GET /cellules` serves the registry to the web UI.
    #[serde(default)]
    pub registry_path: Option<String>,
    /// Path to owner-signed read-access revocation log JSON.
    /// When set, nodes deny grant IDs that have an owner-signed revocation event.
    #[serde(default)]
    pub read_access_revocations_path: Option<String>,
    /// Path to recipient packages registry JSON file.
    /// When set, stores recipient package records for owner management.
    #[serde(default)]
    pub packages_path: Option<String>,
    /// Static bearer token for web UI → node authentication.
    /// When set, all UI-facing endpoints (`/health`, `/capacity`, `/metrics`,
    /// Generate a token with: `confidis node gen-token`
    /// Leave unset only for local development without a web UI.
    #[serde(default)]
    pub ui_token: Option<String>,
    /// Allowed CORS origin for the web UI (e.g. `"https://ui.confidis.eu"`).
    /// When set (with `ui_token`), CORS is restricted to this exact origin and only
    /// `Authorization`/`Content-Type` headers are allowed.
    /// When unset, CORS allows any origin (suitable for local dev only).
    #[serde(default)]
    pub ui_allowed_origin: Option<String>,
    /// Minimum Cellule lifetime in days enforced at registration time.
    /// Default: 1.
    #[serde(default = "default_min_expiry_days")]
    pub min_expiry_days: u32,
    /// Maximum Cellule lifetime in days enforced at registration time.
    /// Default: 365 (one year).
    #[serde(default = "default_max_expiry_days")]
    pub max_expiry_days: u32,
    /// Maximum shards any single owner (identified by `x-confidis-delete-authority-hash`)
    /// may upload per hour.  0 = unlimited (default).
    ///
    /// When non-zero this prevents a single wallet with many keys from filling all
    /// available node storage before the health score drops low enough to exclude
    /// the node from placement.
    #[serde(default)]
    pub max_shards_per_owner_per_hour: u32,
    /// Maximum cellules any single owner may create.  0 = unlimited (default).
    ///
    /// When non-zero this prevents a single wallet from creating unlimited cellules
    /// and consuming registry storage or creating operational overhead.
    #[serde(default)]
    pub max_cellules_per_owner: u32,

    /// Ed25519 public keys (hex) of operator wallets allowed to run authenticated
    /// operator-side operations.
    #[serde(default)]
    pub authorized_operator_pubkeys: Vec<String>,

    // -----------------------------------------------------------------------
    // Static file serving
    // -----------------------------------------------------------------------
    /// Path to the bundled web-UI dist directory. When set, the node serves
    /// the dashboard SPA at `/ui/**`. Defaults to `./webui/` relative to the
    /// working directory; the .deb package installs it at `/usr/share/confidis/webui`.
    #[serde(default)]
    pub webui_path: Option<String>,

    /// Path to an operator-supplied content directory for marketing, FAQ, or
    /// documentation pages. When set, the node serves those static files at
    /// the root `/`. Useful for running a public-facing website directly from
    /// a CONFIDIS node (e.g. confidis.fr). The web-UI dashboard remains at `/ui`.
    #[serde(default)]
    pub content_dir: Option<String>,

    // -----------------------------------------------------------------------
    // Security Event Export Configuration
    // -----------------------------------------------------------------------
    /// Webhook URLs for security event export (JSON format).
    /// Events will be POSTed to each URL with Content-Type: application/json.
    /// Example: ["https://siem.company.com/api/events", "https://splunk.company.com/services/collector"]
    #[serde(default)]
    pub security_event_webhook_urls: Vec<String>,

    // -----------------------------------------------------------------------
    // SOC/Compliance Viewer Configuration
    // -----------------------------------------------------------------------
    /// Static bearer token for SOC/compliance viewer access.
    /// When set, enables `/compliance/*` endpoints for security event viewing and audit logs.
    /// SOC teams can access security events and compliance evidence without owner data access.
    /// Generate a token with: `confidis node gen-compliance-token`
    /// Leave unset to disable compliance viewer access.
    #[serde(default)]
    pub compliance_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCandidate {
    pub node_id: NodeId,
    #[serde(default)]
    pub public_key: Option<String>,
    pub endpoint: String,
    pub free_bytes: u64,
    pub used_bytes: u64,
    pub max_bytes: u64,
    pub region: String,
    pub failure_domain: String,
    pub health_score: f32,
    pub current_shard_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardPlacement {
    pub shard_index: usize,
    pub shard_id: ShardId,
    pub node_id: NodeId,
    #[serde(default)]
    pub node_public_key: Option<String>,
    pub endpoint: String,
    pub failure_domain: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementPlan {
    pub version: u16,
    pub group_id: String,
    pub erasure_policy: ErasurePolicy,
    pub placements: Vec<ShardPlacement>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDescriptor {
    pub shard_id: ShardId,
    pub shard_index: usize,
    /// Streaming segment this shard belongs to. A Cellule is encoded as one or
    /// more fixed-size segments (`Manifest::segment_size_bytes`); shards are
    /// identified by the `(segment_index, shard_index)` pair. Defaults to `0`
    /// so single-segment manifests written before multi-segment streaming
    /// deserialize unchanged (byte-identical behaviour for small inputs).
    #[serde(default)]
    pub segment_index: u32,
    pub size_bytes: u64,
    pub provider_hints: Vec<String>,
    /// Region label of the node that accepted this shard at upload time (e.g. "eu-fr").
    #[serde(default)]
    pub region: Option<String>,
    /// Failure domain of the node that accepted this shard at upload time.
    #[serde(default)]
    pub failure_domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u16,
    pub manifest_id: Uuid,
    pub cellule_id: CelluleId,
    pub group_id: String,
    pub erasure_policy: ErasurePolicy,
    pub original_size_bytes: u64,
    pub segment_size_bytes: u64,
    pub shards: Vec<ShardDescriptor>,
    pub created_at: DateTime<Utc>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellulePublicRecord {
    pub version: u16,
    pub cellule_id: CelluleId,
    pub cellule_public_key: String,
    pub manifest_cid: String,
    pub sequence: u64,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleRecordList {
    pub version: u16,
    pub issued_at: DateTime<Utc>,
    pub records: Vec<CellulePublicRecord>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CelluleLifecycleState {
    Active,
    ExpiringSoon,
    Expired,
}

impl CellulePublicRecord {
    pub fn lifecycle_state_at(&self, now: DateTime<Utc>) -> CelluleLifecycleState {
        if now >= self.expires_at {
            return CelluleLifecycleState::Expired;
        }

        let renewal_notice_at = self.expires_at - chrono::Duration::days(RENEWAL_NOTICE_DAYS);
        if now >= renewal_notice_at {
            CelluleLifecycleState::ExpiringSoon
        } else {
            CelluleLifecycleState::Active
        }
    }

    pub fn deletion_due_at(&self, now: DateTime<Utc>) -> bool {
        self.lifecycle_state_at(now) == CelluleLifecycleState::Expired
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardReceipt {
    pub version: u16,
    pub receipt_id: Uuid,
    pub receipt_type: ShardReceiptType,
    pub node_id: NodeId,
    #[serde(default)]
    pub public_key: Option<String>,
    pub shard_id: ShardId,
    pub issued_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardProviderRecord {
    pub version: u16,
    pub provider_record_id: Uuid,
    pub cellule_id: CelluleId,
    pub manifest_id: Uuid,
    pub shard_id: ShardId,
    pub shard_index: usize,
    #[serde(default)]
    pub segment_index: u32,
    pub node_id: NodeId,
    pub public_key: String,
    pub endpoint: String,
    pub region: String,
    pub failure_domain: String,
    pub receipt_id: Uuid,
    pub receipt_signature: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardProviderList {
    pub version: u16,
    pub issued_at: DateTime<Utc>,
    pub shard_id: ShardId,
    pub providers: Vec<ShardProviderRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaidShardAuthorization {
    pub shard_id: ShardId,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritySignature {
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageFeeAuthorization {
    pub version: u16,
    pub authorization_id: Uuid,
    pub operation: String,
    pub op_id: String,
    pub wallet_address: WalletAddress,
    pub fee_entry_id: Uuid,
    pub fee_entry_hash: String,
    pub fee_policy_version: u16,
    pub fee_policy_hash: String,
    pub total_added_encoded_bytes: u64,
    pub paid_shards: Vec<PaidShardAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_shards_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_public_keys: Vec<String>,
    #[serde(default)]
    pub authority_threshold: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_signatures: Vec<AuthoritySignature>,
    /// Legacy single-signer field. Kept for development/compatibility; the
    /// production path verifies `authority_signatures` against the genesis
    /// M-of-N authority set.
    pub authority_public_key: String,
    /// Legacy single-signature field. Kept for development/compatibility.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDeleteRequest {
    pub version: u16,
    pub request_id: Uuid,
    pub operation: String,
    pub shard_id: ShardId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CelluleAccessGrantStatus {
    Active,
    Revoked,
}

fn default_grant_status() -> CelluleAccessGrantStatus {
    CelluleAccessGrantStatus::Active
}

/// Owner-signed read-only access grant for a recipient identity/public key.
///
/// This grant is authorization metadata only. It does not carry a Cellule key,
/// wallet authority, deletion authority, renewal authority, or onward-delegation
/// authority. A reader that already received plaintext can still copy it outside
/// CONFIDIS, so revocation applies to future CONFIDIS-mediated reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleReadAccessGrant {
    pub version: u16,
    pub grant_id: Uuid,
    pub operation: String,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub recipient_public_key: String,
    /// Field/data scope. Use "*" only for full-Cellule read access.
    pub scope: Vec<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    pub issued_at: DateTime<Utc>,
    #[serde(default)]
    pub not_after: Option<DateTime<Utc>>,
    #[serde(default = "default_grant_status")]
    pub status: CelluleAccessGrantStatus,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleReadAccessGrantRevocation {
    pub version: u16,
    pub revocation_id: Uuid,
    pub operation: String,
    pub grant_id: Uuid,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub recipient_public_key: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleReadAccessRevocationLog {
    pub version: u16,
    #[serde(default)]
    pub revocations: Vec<CelluleReadAccessGrantRevocation>,
}

/// Owner-signed authorization to permanently delete the Cellule ownership record.
/// Shards expire by their own TTL; this removes the ownership registration and grants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleDeleteAuthorization {
    pub version: u16,
    pub operation: String,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

/// Recipient-signed proof that the reader controls the private key named in a grant.///
/// The proof is short-lived and bound to a caller-provided challenge. It should be checked
/// together with the owner-signed grant before CONFIDIS-mediated read access is allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleReadAccessProof {
    pub version: u16,
    pub proof_id: Uuid,
    pub operation: String,
    pub grant_id: Uuid,
    pub cellule_id: CelluleId,
    pub recipient_public_key: String,
    /// Requested field/data scope for this read. Must be covered by the grant scope.
    pub requested_scope: Vec<String>,
    /// Server/client challenge nonce, hex encoded.
    pub challenge: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

/// Owner-signed proof that unlocks an owner-only Cellule report flow.
///
/// This proof gates access to report metadata, but it does not carry a Cellule key
/// or manifest plaintext. Full placement reports still require owner-side manifest context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleOwnerReportProof {
    pub version: u16,
    pub proof_id: Uuid,
    pub operation: String,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub requested_scope: Vec<String>,
    /// Server/client challenge nonce, hex encoded.
    pub challenge: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

/// Owner-signed claim that binds a freshly generated owner public key to a Cellule.
///
/// Owner-signed proof that a wallet controls a Cellule lifecycle action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleOwnerClaim {
    pub version: u16,
    pub operation: String,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub claimed_at: DateTime<Utc>,
    pub signature: String,
}

/// Owner-signed request to create a new Cellule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleOwnerCreate {
    pub version: u16,
    pub operation: String,
    pub cellule_id: CelluleId,
    pub label: String,
    pub owner_public_key: String,
    pub retention_days: i64,
    /// `fixed_base + reserved_bytes × global_per_byte_fee`; retention duration
    /// is not a price factor. Part of the signed payload, so the reservation is
    /// owner-authorized and tamper-evident.
    #[serde(default)]
    pub reserved_bytes: u64,
    /// Optional BLAKE3 hash of the canonical paid shard list committed by the
    /// owner. Required by production billing when paid_shards are supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_shards_hash: Option<String>,
    /// Optional BLAKE3 hash of the original plaintext content committed by the
    /// owner before encoding/upload. Required by production billing when
    /// paid_shards are supplied by `cellule put`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Optional BLAKE3 hash of the owner-signed manifest plaintext. Required
    /// by production billing when the final manifest is available before
    /// upload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub storage_profile: Option<String>,
    pub funding_reference: Option<String>,
    /// Optional public key of the wallet that will be debited for the data-add
    /// fee. When `None` (or equal to `owner_public_key`): self-pay — the wallet
    /// derived from `owner_public_key` is debited. When `Some(p)` and `p` differs
    /// from `owner_public_key`: operator-sponsored — the wallet derived from `p`
    /// is debited, and the HTTP request to `/authority/spend` MUST carry a
    /// node-key Ed25519 signature where `x-confidis-node-pubkey == p`. Owner-signed
    /// so a third party cannot retarget the debit to someone else's wallet.
    /// Phase 1c (payment-model separation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer_pubkey: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

/// Owner-signed request to renew a Cellule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleOwnerRenew {
    pub version: u16,
    pub operation: String,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub new_expiry: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

/// Owner-signed request to delete a Cellule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleOwnerDelete {
    pub version: u16,
    pub operation: String,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

/// Record of a recipient-encrypted package created by the owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPackageRecord {
    pub package_id: Uuid,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub recipient_public_key: String,
    pub recipient_x25519_pubkey: String,
    pub fields: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: RecipientPackageStatus,
    pub package_hash: String,
    pub owner_signature: String,
    pub delivery_receipts: Vec<RecipientPackageDeliveryReceipt>,
}

/// Status of a recipient package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecipientPackageStatus {
    Active,
    Removed,
    Expired,
}

/// Receipt for delivery of a recipient package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPackageDeliveryReceipt {
    pub delivered_at: DateTime<Utc>,
    pub recipient_challenge: String,
    pub node_signature: String,
}

pub fn recipient_package_record_signing_payload(
    record: &RecipientPackageRecord,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = record.clone();
    unsigned.owner_signature.clear();
    serde_json::to_vec(&unsigned)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleFieldEnvelope {
    pub field: String,
    pub content_type: String,
    pub ciphertext_hex: String,
    pub plaintext_blake3: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleFieldContainer {
    pub version: u16,
    pub container_id: Uuid,
    pub cellule_id: CelluleId,
    pub fields: Vec<CelluleFieldEnvelope>,
    pub created_at: DateTime<Utc>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleFieldAccessEnvelope {
    pub field: String,
    pub content_type: String,
    pub recipient_x25519_pubkey: String,
    pub ephemeral_x25519_pubkey: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CelluleFieldAccessPackage {
    pub version: u16,
    pub package_id: Uuid,
    pub grant_id: Uuid,
    pub cellule_id: CelluleId,
    pub owner_public_key: String,
    pub recipient_public_key: String,
    pub recipient_x25519_pubkey: String,
    pub fields: Vec<CelluleFieldAccessEnvelope>,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

impl CelluleReadAccessProof {
    pub fn generate_challenge() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
}

impl CelluleOwnerReportProof {
    pub fn generate_challenge() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShardReceiptType {
    Stored,
    Fetched,
    Deleted,
    IntegrityChecked,
    PlacementFailed,
}

pub fn cellule_expiry_is_valid_at(now: DateTime<Utc>, expires_at: DateTime<Utc>) -> bool {
    expires_at > now && expires_at <= now + chrono::Duration::days(MAX_CELLULE_LIFETIME_DAYS)
}

// ── CONFIDIS node ban list ──────────────────────────────────────────────────────
//
// Node participation is PERMISSIONLESS: a node spins up and joins the network
// freely. There is no membership certificate and no admission gate. CONFIDIS OS
// v1 controls writes with local quotas and explicit federation agreements. A
// signed ban list, when configured, is purely REACTIVE: peers refuse shards/data
// to or from a banned node. This is never an entry gate.

/// Signed ban lists are stale after this much clock skew into the future.
pub const CONFIDIS_BAN_LIST_FUTURE_GRACE_MINUTES: i64 = 2;

/// Service tier of a node within the CONFIDIS network.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeTier {
    /// Standard SME-grade node.
    Standard,
    /// Verified enterprise-grade node with enhanced uptime SLA commitment.
    Verified,
    /// Sovereign node operating under specific regulatory or jurisdictional requirements.
    Sovereign,
}

/// One banned node entry in a CONFIDIS-signed node ban list.
///
/// Identifies a node solely by its Ed25519 public key. Being on the list is a
/// reactive sanction applied to an already-participating node — never a
/// precondition for joining.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeBan {
    /// Ed25519 public key (hex-encoded) of the banned node.
    pub ed25519_pubkey: String,
    /// UTC timestamp when CONFIDIS banned this node.
    pub banned_at: DateTime<Utc>,
    /// Whether the sanction is a full ban or a temporary quarantine.
    #[serde(default)]
    pub quarantine: bool,
    /// Human-readable reason code, safe for operator/admin UI.
    #[serde(default)]
    pub reason: Option<String>,
}

/// CONFIDIS authority-signed node ban/quarantine list.
///
/// Distributed to nodes so they refuse shard storage and data operations to or
/// from banned/quarantined node public keys. The `confidis_signature` covers all
/// other fields (after setting `confidis_signature = None`) serialized as compact
/// JSON, and is verified against the CONFIDIS authority root public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBanList {
    /// Protocol version. Must be 1.
    pub version: u8,
    /// UTC timestamp when the list was issued by the CONFIDIS authority.
    pub issued_at: DateTime<Utc>,
    /// UTC timestamp after which this list must not be trusted.
    pub expires_at: DateTime<Utc>,
    /// Banned/quarantined node bindings.
    #[serde(default)]
    pub banned_nodes: Vec<NodeBan>,
    /// CONFIDIS authority root Ed25519 signature over the canonical payload.
    #[serde(default)]
    pub confidis_signature: Option<String>,
}

impl NodeBanList {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Returns `true` when the given node Ed25519 pubkey is banned or quarantined.
    pub fn is_banned(&self, ed25519_pubkey: &str) -> bool {
        self.banned_nodes
            .iter()
            .any(|ban| ban.ed25519_pubkey == ed25519_pubkey)
    }
}

/// Uptime record gossiped between nodes in the P2P mesh.
///
/// Each node builds and signs its own uptime record, then distributes it through peer gossip.
/// Any node receiving a record can verify the signature independently — no central authority
/// server is required at runtime.
///
/// The `signature` covers all other fields (with `signature = None`) as compact JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeUptimeRecord {
    /// Protocol version. Must be 1.
    pub version: u8,
    /// Unique node identifier.
    pub node_id: String,
    /// Ed25519 public key (hex-encoded). Used to verify `signature`.
    pub ed25519_pubkey: String,
    /// Public endpoint of this node (e.g. "https://node.example.com:4433").
    pub endpoint: String,
    /// Approximate uptime in whole seconds since the node last started.
    pub uptime_seconds: u64,
    /// UTC timestamp when this record was produced.
    pub recorded_at: DateTime<Utc>,
    /// Ed25519 signature over all other fields (set to `None` when computing the payload).
    #[serde(default)]
    pub signature: Option<String>,
}

/// Canonical JSON signing payload for a [`NodeUptimeRecord`].
pub fn uptime_record_signing_payload(rec: &NodeUptimeRecord) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = rec.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned)
}

/// Verify a [`NodeUptimeRecord`] self-signature.
///
/// Returns `Ok(())` if the record's `ed25519_pubkey` signed the canonical payload.
pub fn verify_uptime_record(rec: &NodeUptimeRecord) -> anyhow::Result<()> {
    use ed25519_dalek::{Verifier, VerifyingKey};

    let sig_hex = rec
        .signature
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("uptime record has no signature"))?;
    let sig_bytes = hex::decode(sig_hex).context("invalid signature hex")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_arr);

    let pubkey_bytes = hex::decode(&rec.ed25519_pubkey).context("invalid ed25519_pubkey hex")?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519_pubkey must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pubkey_arr).context("invalid ed25519_pubkey")?;

    let payload = uptime_record_signing_payload(rec).context("failed to build payload")?;
    vk.verify(&payload, &sig)
        .context("uptime record signature invalid")
}

/// Canonical JSON signing payload for a [`NodeBanList`].
///
/// Sets `confidis_signature` to `None` before serialising so the signature field
/// is excluded from the payload it signs.
pub fn node_ban_list_signing_payload(list: &NodeBanList) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = list.clone();
    unsigned.confidis_signature = None;
    serde_json::to_vec(&unsigned)
}

/// Verify a CONFIDIS authority-signed node ban list.
///
/// Checks: `version == 1`, the list is not expired, `issued_at` is not too far
/// in the future, and `confidis_signature` verifies against the CONFIDIS authority
/// root public key. Membership in the network is permissionless — this list is
/// only a reactive sanction surface, never an admission gate.
pub fn verify_node_ban_list(
    list: &NodeBanList,
    confidis_root_pubkey: &VerifyingKey,
    now: DateTime<Utc>,
) -> Result<()> {
    if list.version != 1 {
        bail!("unsupported node ban list version: {}", list.version);
    }
    if list.is_expired(now) {
        bail!("node ban list has expired");
    }
    if list.issued_at > now + chrono::Duration::minutes(CONFIDIS_BAN_LIST_FUTURE_GRACE_MINUTES) {
        bail!("node ban list issued_at is too far in the future");
    }

    let sig_hex = list
        .confidis_signature
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing confidis_signature"))?;
    let payload = node_ban_list_signing_payload(list)
        .context("failed to construct node ban list signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .context("invalid confidis_signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("confidis_signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);

    confidis_root_pubkey
        .verify(&payload, &signature)
        .context("confidis_signature verification failed")?;

    Ok(())
}

/// Canonical signing payload for a node shard-access identity proof.
///
/// Binds the requesting node's Ed25519 pubkey to a specific shard operation and
/// a freshness timestamp. The serving node verifies the signature, checks the
/// timestamp window, then rejects the request if `node_pubkey` is on the
/// authority-signed [`NodeBanList`]. Presenting this proof is optional in
/// development (participation is permissionless); a node running with
/// `production_profile` requires it on inter-node shard read/write so that
/// authority bans actually bind to data operations, not just peer gossip.
pub fn shard_access_proof_payload(
    node_pubkey: &str,
    method: &str,
    shard_id: &str,
    issued_at: DateTime<Utc>,
) -> Vec<u8> {
    format!(
        "confidis-shard-access-v1\n{node_pubkey}\n{method}\n{shard_id}\n{}",
        issued_at.to_rfc3339()
    )
    .into_bytes()
}

/// Maximum accepted age / future skew for a shard-access identity proof.
pub const SHARD_ACCESS_PROOF_TTL_MINUTES: i64 = 5;

/// Payload signed by the node-key when calling `/authority/spend` with
/// `payer_pubkey` different from the owner (operator-sponsored mode). Binds the
/// signature to the specific (node, op_id, timestamp) so it cannot be replayed
/// for a different spend operation. The signing key MUST be the node-identity
/// key whose public key equals `node_pubkey` and equals the `payer_pubkey` of
/// the spend request — i.e. the operator consents to debit its own wallet by
/// signing this proof from its node.
pub fn authority_spend_node_proof_payload(
    node_pubkey: &str,
    op_id: &str,
    issued_at: DateTime<Utc>,
) -> Vec<u8> {
    format!(
        "confidis-authority-spend-v1\n{node_pubkey}\n{op_id}\n{}",
        issued_at.to_rfc3339()
    )
    .into_bytes()
}

/// Maximum accepted age / future skew for an authority-spend node-identity
/// proof — same window as the shard proof since they share the same trust model.
pub const AUTHORITY_SPEND_NODE_PROOF_TTL_MINUTES: i64 = 5;

pub fn shard_delete_request_signing_payload(
    request: &ShardDeleteRequest,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn cellule_read_access_grant_signing_payload(
    grant: &CelluleReadAccessGrant,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = grant.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn cellule_read_access_grant_revocation_signing_payload(
    revocation: &CelluleReadAccessGrantRevocation,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = revocation.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn cellule_read_access_proof_signing_payload(
    proof: &CelluleReadAccessProof,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = proof.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn cellule_owner_report_proof_signing_payload(
    proof: &CelluleOwnerReportProof,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = proof.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn cellule_owner_claim_signing_payload(
    claim: &CelluleOwnerClaim,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = claim.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn cellule_delete_authorization_signing_payload(
    auth: &CelluleDeleteAuthorization,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = auth.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

/// Verify a `CelluleOwnerClaim` used as a renew request. Same verification rules
/// as `verify_cellule_owner_claim` but expects `CELLULE_OWNER_RENEW_OPERATION`.
pub fn verify_cellule_owner_renew(
    claim: &CelluleOwnerClaim,
    expected_cellule_id: &CelluleId,
    expected_owner_public_key: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    if claim.version != 1 {
        bail!("unsupported owner renew version: {}", claim.version);
    }
    if claim.operation != CELLULE_OWNER_RENEW_OPERATION {
        bail!("unsupported owner renew operation: {}", claim.operation);
    }
    if &claim.cellule_id != expected_cellule_id {
        bail!("owner renew cellule_id does not match record");
    }
    if claim.owner_public_key != expected_owner_public_key {
        bail!("owner renew public key does not match registered owner");
    }
    let max_skew = chrono::Duration::minutes(1);
    if claim.claimed_at < now - chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES) {
        bail!("owner renew claimed_at is too old (replay window)");
    }
    if claim.claimed_at > now + max_skew {
        bail!("owner renew claimed_at is dated in the future");
    }
    let owner_key =
        verifying_key_from_hex(&claim.owner_public_key).context("invalid owner_public_key")?;
    let payload = cellule_owner_claim_signing_payload(claim)
        .context("failed to construct owner renew signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&claim.signature)
        .context("invalid owner renew signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("owner renew signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("owner renew signature verification failed")?;
    Ok(())
}

/// Verify a `CelluleDeleteAuthorization`. Confirms version, operation tag,
/// cellule_id match, owner_public_key match, freshness, and signature.
pub fn verify_cellule_delete_authorization(
    auth: &CelluleDeleteAuthorization,
    expected_cellule_id: &CelluleId,
    expected_owner_public_key: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    if auth.version != 1 {
        bail!("unsupported delete authorization version: {}", auth.version);
    }
    if auth.operation != CELLULE_OWNER_DELETE_OPERATION {
        bail!(
            "unsupported delete authorization operation: {}",
            auth.operation
        );
    }
    if &auth.cellule_id != expected_cellule_id {
        bail!("delete authorization cellule_id does not match record");
    }
    if auth.owner_public_key != expected_owner_public_key {
        bail!("delete authorization public key does not match registered owner");
    }
    if auth.issued_at < now - chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES) {
        bail!("delete authorization is too old (replay window)");
    }
    if auth.issued_at > now + chrono::Duration::minutes(1) {
        bail!("delete authorization issued_at is dated in the future");
    }
    let owner_key =
        verifying_key_from_hex(&auth.owner_public_key).context("invalid owner_public_key")?;
    let payload = cellule_delete_authorization_signing_payload(auth)
        .context("failed to construct delete authorization signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&auth.signature)
        .context("invalid delete authorization signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("delete authorization signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("delete authorization signature verification failed")?;
    Ok(())
}

/// Verify a `CelluleOwnerClaim` against the supplied `now` clock and the expected
/// `cellule_id` from the expected lifecycle record. Returns `Ok` only when:
/// - version matches, operation domain tag matches,
/// - the embedded `cellule_id` matches `expected_cellule_id`,
/// - `claimed_at` is within `[now - CELLULE_OWNER_CLAIM_TTL_MINUTES, now + 1 min]`
///   (the small future window absorbs minor clock skew),
/// - the signature verifies against `owner_public_key` over the canonical payload.
pub fn verify_cellule_owner_claim(
    claim: &CelluleOwnerClaim,
    expected_cellule_id: &CelluleId,
    now: DateTime<Utc>,
) -> Result<()> {
    if claim.version != 1 {
        bail!("unsupported owner claim version: {}", claim.version);
    }
    if claim.operation != CELLULE_OWNER_CLAIM_OPERATION {
        bail!("unsupported owner claim operation: {}", claim.operation);
    }
    if &claim.cellule_id != expected_cellule_id {
        bail!("owner claim cellule_id does not match record");
    }
    let max_age = chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES);
    let max_skew = chrono::Duration::minutes(1);
    if claim.claimed_at < now - max_age {
        bail!("owner claim is too old (replay window)");
    }
    if claim.claimed_at > now + max_skew {
        bail!("owner claim is dated in the future");
    }

    let owner_key =
        verifying_key_from_hex(&claim.owner_public_key).context("invalid owner_public_key")?;
    let payload = cellule_owner_claim_signing_payload(claim)
        .context("failed to construct owner claim signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&claim.signature)
        .context("invalid owner claim signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("owner claim signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("owner claim signature verification failed")?;
    Ok(())
}

pub fn cellule_owner_create_signing_payload(
    create: &CelluleOwnerCreate,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = create.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn paid_shards_commitment_hash(
    shards: &[PaidShardAuthorization],
) -> serde_json::Result<String> {
    let payload = serde_json::json!({
        "version": 1,
        "paid_shards": shards,
    });
    serde_json::to_vec(&payload).map(|bytes| blake3::hash(&bytes).to_hex().to_string())
}

pub fn cellule_owner_renew_signing_payload(
    renew: &CelluleOwnerRenew,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = renew.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn cellule_owner_delete_signing_payload(
    delete: &CelluleOwnerDelete,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = delete.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

/// Verify a `CelluleOwnerCreate` request.
///
/// Checks:
/// - version is 1
/// - operation is correct
/// - retention_days is valid
/// - issued_at is within TTL window
/// - signature verifies against owner_public_key
pub fn verify_cellule_owner_create(create: &CelluleOwnerCreate, now: DateTime<Utc>) -> Result<()> {
    if create.version != 1 {
        bail!("unsupported owner create version: {}", create.version);
    }
    if create.operation != CELLULE_OWNER_CREATE_OPERATION {
        bail!("unsupported owner create operation: {}", create.operation);
    }
    if create.retention_days < 1 || create.retention_days > MAX_CELLULE_LIFETIME_DAYS {
        bail!(
            "retention_days must be between 1 and {}",
            MAX_CELLULE_LIFETIME_DAYS
        );
    }
    let max_age = chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES);
    let max_skew = chrono::Duration::minutes(1);
    if create.issued_at < now - max_age {
        bail!("owner create is too old (replay window)");
    }
    if create.issued_at > now + max_skew {
        bail!("owner create is dated in the future");
    }

    let owner_key =
        verifying_key_from_hex(&create.owner_public_key).context("invalid owner_public_key")?;
    let payload = cellule_owner_create_signing_payload(create)
        .context("failed to construct owner create signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&create.signature)
        .context("invalid owner create signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("owner create signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("owner create signature verification failed")?;
    Ok(())
}

/// Verify a `CelluleOwnerRenew` request.
///
/// Checks:
/// - version is 1
/// - operation is correct
/// - new_expiry is valid
/// - issued_at is within TTL window
/// - signature verifies against owner_public_key
pub fn verify_cellule_owner_renew_request(
    renew: &CelluleOwnerRenew,
    expected_cellule_id: &CelluleId,
    now: DateTime<Utc>,
) -> Result<()> {
    if renew.version != 1 {
        bail!("unsupported owner renew version: {}", renew.version);
    }
    if renew.operation != CELLULE_OWNER_RENEW_OPERATION {
        bail!("unsupported owner renew operation: {}", renew.operation);
    }
    if &renew.cellule_id != expected_cellule_id {
        bail!("owner renew cellule_id does not match record");
    }
    if !cellule_expiry_is_valid_at(now, renew.new_expiry) {
        bail!("new_expiry is not valid");
    }
    let max_age = chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES);
    let max_skew = chrono::Duration::minutes(1);
    if renew.issued_at < now - max_age {
        bail!("owner renew is too old (replay window)");
    }
    if renew.issued_at > now + max_skew {
        bail!("owner renew is dated in the future");
    }

    let owner_key =
        verifying_key_from_hex(&renew.owner_public_key).context("invalid owner_public_key")?;
    let payload = cellule_owner_renew_signing_payload(renew)
        .context("failed to construct owner renew signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&renew.signature)
        .context("invalid owner renew signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("owner renew signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("owner renew signature verification failed")?;
    Ok(())
}

/// Verify a `CelluleOwnerDelete` request.
///
/// Checks:
/// - version is 1
/// - operation is correct
/// - issued_at is within TTL window
/// - signature verifies against owner_public_key
pub fn verify_cellule_owner_delete(
    delete: &CelluleOwnerDelete,
    expected_cellule_id: &CelluleId,
    now: DateTime<Utc>,
) -> Result<()> {
    if delete.version != 1 {
        bail!("unsupported owner delete version: {}", delete.version);
    }
    if delete.operation != CELLULE_OWNER_DELETE_OPERATION {
        bail!("unsupported owner delete operation: {}", delete.operation);
    }
    if &delete.cellule_id != expected_cellule_id {
        bail!("owner delete cellule_id does not match record");
    }
    let max_age = chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES);
    let max_skew = chrono::Duration::minutes(1);
    if delete.issued_at < now - max_age {
        bail!("owner delete is too old (replay window)");
    }
    if delete.issued_at > now + max_skew {
        bail!("owner delete is dated in the future");
    }

    let owner_key =
        verifying_key_from_hex(&delete.owner_public_key).context("invalid owner_public_key")?;
    let payload = cellule_owner_delete_signing_payload(delete)
        .context("failed to construct owner delete signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&delete.signature)
        .context("invalid owner delete signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("owner delete signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("owner delete signature verification failed")?;
    Ok(())
}

pub fn cellule_field_container_signing_payload(
    container: &CelluleFieldContainer,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = container.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned)
}

pub fn cellule_field_access_package_signing_payload(
    package: &CelluleFieldAccessPackage,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = package.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn verify_cellule_read_access_grant(
    grant: &CelluleReadAccessGrant,
    now: DateTime<Utc>,
) -> Result<()> {
    if grant.version != 1 {
        bail!("unsupported access grant version: {}", grant.version);
    }
    if grant.operation != CELLULE_READ_GRANT_OPERATION {
        bail!("unsupported access grant operation: {}", grant.operation);
    }
    if grant.scope.is_empty() {
        bail!("access grant scope must not be empty");
    }
    if grant.status != CelluleAccessGrantStatus::Active {
        bail!("access grant is not active");
    }
    if grant.not_after.is_some_and(|expires_at| now > expires_at) {
        bail!("access grant has expired");
    }

    let owner_key =
        verifying_key_from_hex(&grant.owner_public_key).context("invalid owner_public_key")?;
    verifying_key_from_hex(&grant.recipient_public_key).context("invalid recipient_public_key")?;
    let payload = cellule_read_access_grant_signing_payload(grant)
        .context("failed to construct access grant signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&grant.signature)
        .context("invalid access grant signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("access grant signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("access grant signature verification failed")?;

    Ok(())
}

pub fn verify_cellule_read_access_grant_revocation(
    revocation: &CelluleReadAccessGrantRevocation,
    grant: &CelluleReadAccessGrant,
    now: DateTime<Utc>,
) -> Result<()> {
    if revocation.version != 1 {
        bail!(
            "unsupported access grant revocation version: {}",
            revocation.version
        );
    }
    if revocation.operation != CELLULE_READ_GRANT_REVOCATION_OPERATION {
        bail!(
            "unsupported access grant revocation operation: {}",
            revocation.operation
        );
    }
    if revocation.grant_id != grant.grant_id {
        bail!("access grant revocation grant_id does not match grant");
    }
    if revocation.cellule_id != grant.cellule_id {
        bail!("access grant revocation cellule_id does not match grant");
    }
    if revocation.owner_public_key != grant.owner_public_key {
        bail!("access grant revocation owner_public_key does not match grant");
    }
    if revocation.recipient_public_key != grant.recipient_public_key {
        bail!("access grant revocation recipient_public_key does not match grant");
    }
    if revocation.issued_at > now + chrono::Duration::minutes(1) {
        bail!("access grant revocation issued_at is too far in the future");
    }

    let owner_key = verifying_key_from_hex(&revocation.owner_public_key)
        .context("invalid revocation owner_public_key")?;
    let payload = cellule_read_access_grant_revocation_signing_payload(revocation)
        .context("failed to construct access grant revocation signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&revocation.signature)
        .context("invalid access grant revocation signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("access grant revocation signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("access grant revocation signature verification failed")?;

    Ok(())
}

pub fn verify_cellule_owner_report_proof(
    record: &CellulePublicRecord,
    proof: &CelluleOwnerReportProof,
    expected_challenge: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    if proof.version != 1 {
        bail!("unsupported owner report proof version: {}", proof.version);
    }
    if proof.operation != CELLULE_OWNER_REPORT_PROOF_OPERATION {
        bail!(
            "unsupported owner report proof operation: {}",
            proof.operation
        );
    }
    if proof.cellule_id != record.cellule_id {
        bail!("owner report proof cellule_id does not match record");
    }
    if proof.owner_public_key != record.cellule_public_key {
        bail!("owner report proof owner_public_key does not match record");
    }
    if proof.challenge != expected_challenge {
        bail!("owner report proof challenge does not match expected challenge");
    }
    let challenge_bytes =
        hex::decode(&proof.challenge).context("invalid owner report proof challenge hex")?;
    if challenge_bytes.len() != 32 {
        bail!("owner report proof challenge must be 32 bytes");
    }
    let ttl = chrono::Duration::minutes(CELLULE_READ_PROOF_TTL_MINUTES);
    if proof.issued_at < now - ttl {
        bail!("owner report proof has expired");
    }
    if proof.issued_at > now + chrono::Duration::minutes(1) {
        bail!("owner report proof issued_at is too far in the future");
    }
    if proof.requested_scope.is_empty() {
        bail!("owner report proof requested_scope must not be empty");
    }
    if !proof
        .requested_scope
        .iter()
        .all(|scope| scope == "*" || scope == "cellule.report")
    {
        bail!("owner report proof requested_scope is not supported");
    }

    let owner_key =
        verifying_key_from_hex(&proof.owner_public_key).context("invalid owner_public_key")?;
    let payload = cellule_owner_report_proof_signing_payload(proof)
        .context("failed to construct owner report proof signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&proof.signature)
        .context("invalid owner report proof signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("owner report proof signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("owner report proof signature verification failed")?;

    Ok(())
}

pub fn verify_cellule_read_access(
    grant: &CelluleReadAccessGrant,
    proof: &CelluleReadAccessProof,
    expected_challenge: &str,
    now: DateTime<Utc>,
) -> Result<()> {
    verify_cellule_read_access_grant(grant, now)?;

    if proof.version != 1 {
        bail!("unsupported access proof version: {}", proof.version);
    }
    if proof.operation != CELLULE_READ_PROOF_OPERATION {
        bail!("unsupported access proof operation: {}", proof.operation);
    }
    if proof.grant_id != grant.grant_id {
        bail!("access proof grant_id does not match grant");
    }
    if proof.cellule_id != grant.cellule_id {
        bail!("access proof cellule_id does not match grant");
    }
    if proof.recipient_public_key != grant.recipient_public_key {
        bail!("access proof recipient does not match grant");
    }
    if proof.challenge != expected_challenge {
        bail!("access proof challenge does not match expected challenge");
    }
    let challenge_bytes =
        hex::decode(&proof.challenge).context("invalid access proof challenge hex")?;
    if challenge_bytes.len() != 32 {
        bail!("access proof challenge must be 32 bytes");
    }
    let ttl = chrono::Duration::minutes(CELLULE_READ_PROOF_TTL_MINUTES);
    if proof.issued_at < now - ttl {
        bail!("access proof has expired");
    }
    if proof.issued_at > now + chrono::Duration::minutes(1) {
        bail!("access proof issued_at is too far in the future");
    }
    if proof.requested_scope.is_empty() {
        bail!("access proof requested_scope must not be empty");
    }
    if !scope_covers(&grant.scope, &proof.requested_scope) {
        bail!("access proof requested_scope is outside the grant scope");
    }

    let recipient_key = verifying_key_from_hex(&proof.recipient_public_key)
        .context("invalid proof recipient_public_key")?;
    let payload = cellule_read_access_proof_signing_payload(proof)
        .context("failed to construct access proof signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&proof.signature)
        .context("invalid access proof signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("access proof signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    recipient_key
        .verify(&payload, &signature)
        .context("access proof signature verification failed")?;

    Ok(())
}

pub fn verify_cellule_field_access_package(
    package: &CelluleFieldAccessPackage,
    grant: &CelluleReadAccessGrant,
) -> Result<()> {
    if package.version != 1 {
        bail!(
            "unsupported field access package version: {}",
            package.version
        );
    }
    if package.grant_id != grant.grant_id {
        bail!("field access package grant_id does not match grant");
    }
    if package.cellule_id != grant.cellule_id {
        bail!("field access package cellule_id does not match grant");
    }
    if package.owner_public_key != grant.owner_public_key {
        bail!("field access package owner_public_key does not match grant");
    }
    if package.recipient_public_key != grant.recipient_public_key {
        bail!("field access package recipient_public_key does not match grant");
    }
    if package.fields.is_empty() {
        bail!("field access package fields must not be empty");
    }
    let delivered_scope: Vec<String> = package
        .fields
        .iter()
        .map(|envelope| envelope.field.clone())
        .collect();
    if !scope_covers(&grant.scope, &delivered_scope) {
        bail!("field access package fields are outside the grant scope");
    }
    for envelope in &package.fields {
        if envelope.field.trim().is_empty() {
            bail!("field access package field name must not be empty");
        }
        if envelope.recipient_x25519_pubkey != package.recipient_x25519_pubkey {
            bail!("field access package envelope recipient_x25519_pubkey mismatch");
        }
        let recipient_pubkey = hex::decode(&envelope.recipient_x25519_pubkey)
            .context("invalid envelope recipient_x25519_pubkey hex")?;
        if recipient_pubkey.len() != 32 {
            bail!("envelope recipient_x25519_pubkey must be 32 bytes");
        }
        let ephemeral_pubkey = hex::decode(&envelope.ephemeral_x25519_pubkey)
            .context("invalid envelope ephemeral_x25519_pubkey hex")?;
        if ephemeral_pubkey.len() != 32 {
            bail!("envelope ephemeral_x25519_pubkey must be 32 bytes");
        }
        hex::decode(&envelope.ciphertext_hex).context("invalid envelope ciphertext hex")?;
    }
    let package_recipient_pubkey = hex::decode(&package.recipient_x25519_pubkey)
        .context("invalid package recipient_x25519_pubkey hex")?;
    if package_recipient_pubkey.len() != 32 {
        bail!("package recipient_x25519_pubkey must be 32 bytes");
    }

    let owner_key = verifying_key_from_hex(&package.owner_public_key)
        .context("invalid package owner_public_key")?;
    let payload = cellule_field_access_package_signing_payload(package)
        .context("failed to construct field access package signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&package.signature)
        .context("invalid field access package signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("field access package signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("field access package signature verification failed")?;

    Ok(())
}

pub fn scope_covers(grant_scope: &[String], requested_scope: &[String]) -> bool {
    grant_scope.iter().any(|scope| scope == "*")
        || requested_scope
            .iter()
            .all(|requested| grant_scope.iter().any(|scope| scope == requested))
}

pub fn capacity_report_signing_payload(report: &NodeCapacityReport) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = report.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned)
}

pub fn shard_receipt_signing_payload(receipt: &ShardReceipt) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = receipt.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned)
}

pub fn cellule_record_id_from_public_key(public_key: &str) -> Result<CelluleId> {
    let _ = verifying_key_from_hex(public_key)?;
    Ok(CelluleId(
        blake3::hash(public_key.as_bytes()).to_hex().to_string(),
    ))
}

pub fn cellule_record_signing_payload(record: &CellulePublicRecord) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = record.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

pub fn verify_cellule_public_record_at(
    record: &CellulePublicRecord,
    now: DateTime<Utc>,
) -> Result<()> {
    verify_cellule_public_record_signature(record)?;
    if !cellule_expiry_is_valid_at(now, record.expires_at) {
        bail!(
            "Cellule record expires_at must be in the future and no more than {} days from now",
            MAX_CELLULE_LIFETIME_DAYS
        );
    }
    Ok(())
}

pub fn verify_cellule_public_record_signature(record: &CellulePublicRecord) -> Result<()> {
    if record.version != 1 {
        bail!("unsupported Cellule record version {}", record.version);
    }
    if record.manifest_cid.trim().is_empty() {
        bail!("Cellule record manifest_cid is empty");
    }
    let expected = cellule_record_id_from_public_key(&record.cellule_public_key)?;
    if expected != record.cellule_id {
        bail!(
            "Cellule ID mismatch: expected {}, got {}",
            expected.0,
            record.cellule_id.0
        );
    }
    let key = verifying_key_from_hex(&record.cellule_public_key)
        .context("invalid Cellule record public key")?;
    let payload = cellule_record_signing_payload(record)
        .context("failed to build Cellule record signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&record.signature)
        .context("invalid Cellule record signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Cellule record signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&payload, &signature)
        .context("Cellule record signature verification failed")?;
    Ok(())
}

pub fn verify_cellule_public_record(record: &CellulePublicRecord) -> Result<()> {
    verify_cellule_public_record_at(record, Utc::now())
}

pub fn shard_provider_record_signing_payload(
    record: &ShardProviderRecord,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = record.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned)
}

pub fn verify_shard_provider_record_at(
    record: &ShardProviderRecord,
    now: DateTime<Utc>,
) -> Result<()> {
    if record.version != 1 {
        bail!("unsupported provider record version {}", record.version);
    }
    if record.provider_record_id == Uuid::nil() {
        bail!("provider_record_id must not be nil");
    }
    if record.endpoint.trim().is_empty() {
        bail!("provider record endpoint is empty");
    }
    if record.issued_at
        > now + chrono::Duration::minutes(SHARD_PROVIDER_RECORD_FUTURE_GRACE_MINUTES)
    {
        bail!("provider record issued_at is too far in the future");
    }
    let Some(expires_at) = record.expires_at else {
        bail!("provider record expires_at is required");
    };
    if expires_at <= record.issued_at {
        bail!("provider record expires_at must be after issued_at");
    }
    if now >= expires_at {
        bail!("provider record is expired");
    }
    let signature = record
        .signature
        .as_deref()
        .context("provider record missing signature")?;
    let key =
        verifying_key_from_hex(&record.public_key).context("invalid provider record public_key")?;
    let payload = shard_provider_record_signing_payload(record)
        .context("failed to build provider record signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(signature)
        .context("invalid provider record signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("provider record signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    key.verify(&payload, &signature)
        .context("provider record signature verification failed")?;
    Ok(())
}

pub fn verify_shard_provider_record(record: &ShardProviderRecord) -> Result<()> {
    verify_shard_provider_record_at(record, Utc::now())
}

pub fn storage_fee_authorization_signing_payload(
    authorization: &StorageFeeAuthorization,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = authorization.clone();
    unsigned.signature.clear();
    unsigned.authority_signatures.clear();
    serde_json::to_vec(&unsigned)
}

pub struct StorageFeeAuthorizationExpectations<'a> {
    pub trusted_authority_public_key: Option<&'a str>,
    pub trusted_authority_set: Option<(&'a [String], u32)>,
    pub op_id: Option<&'a str>,
    pub shard_id: &'a ShardId,
    pub size_bytes: u64,
    pub policy_version: u16,
    pub policy_hash: &'a str,
    pub now: DateTime<Utc>,
}

pub fn verify_storage_fee_authorization(
    authorization: &StorageFeeAuthorization,
    expected: StorageFeeAuthorizationExpectations<'_>,
) -> Result<()> {
    if authorization.version != 1 {
        bail!(
            "unsupported storage fee authorization version: {}",
            authorization.version
        );
    }
    if authorization.operation != STORAGE_FEE_AUTHORIZATION_OPERATION {
        bail!(
            "unsupported storage fee authorization operation: {}",
            authorization.operation
        );
    }
    if let Some(expected_op_id) = expected.op_id
        && authorization.op_id != expected_op_id
    {
        bail!("storage fee authorization operation id mismatch");
    }
    let payload = storage_fee_authorization_signing_payload(authorization)
        .context("failed to construct storage fee authorization signing payload")?;
    if let Some((trusted_keys, threshold)) = expected.trusted_authority_set {
        if threshold == 0 {
            bail!("trusted authority threshold must be at least 1");
        }
        if authorization.authority_threshold != threshold {
            bail!("storage fee authorization authority threshold mismatch");
        }
        if authorization.authority_public_keys != trusted_keys {
            bail!("storage fee authorization authority set mismatch");
        }
        let mut seen = std::collections::HashSet::new();
        let mut valid_signatures = 0u32;
        for sig in &authorization.authority_signatures {
            if !trusted_keys.iter().any(|key| key == &sig.public_key) {
                bail!("storage fee authorization signature from non-authority key");
            }
            if !seen.insert(sig.public_key.clone()) {
                bail!("duplicate storage fee authorization authority signature");
            }
            let key = verifying_key_from_hex(&sig.public_key)
                .context("invalid storage fee authorization signer public_key")?;
            let sig_bytes: [u8; 64] = hex::decode(&sig.signature)
                .context("invalid storage fee authorization signature hex")?
                .try_into()
                .map_err(|_| {
                    anyhow::anyhow!("storage fee authorization signature must be 64 bytes")
                })?;
            let signature = Signature::from_bytes(&sig_bytes);
            key.verify(&payload, &signature)
                .context("storage fee authorization signature verification failed")?;
            valid_signatures += 1;
        }
        if valid_signatures < threshold {
            bail!(
                "storage fee authorization has {} valid signature(s), requires {}",
                valid_signatures,
                threshold
            );
        }
    } else if let Some(trusted) = expected.trusted_authority_public_key
        && authorization.authority_public_key != trusted
    {
        bail!("storage fee authorization signer is not the trusted CONFIDIS authority");
    }
    if authorization.fee_policy_version != expected.policy_version {
        bail!("storage fee authorization policy version mismatch");
    }
    if authorization.fee_policy_hash != expected.policy_hash {
        bail!("storage fee authorization policy hash mismatch");
    }
    if let Some(committed) = authorization.paid_shards_hash.as_deref() {
        let expected = paid_shards_commitment_hash(&authorization.paid_shards)
            .context("failed to hash storage fee paid_shards")?;
        if committed != expected {
            bail!("storage fee authorization paid_shards_hash mismatch");
        }
    }
    validate_optional_blake3_hex(
        authorization.paid_shards_hash.as_deref(),
        "paid_shards_hash",
    )?;
    validate_optional_blake3_hex(authorization.content_hash.as_deref(), "content_hash")?;
    validate_optional_blake3_hex(authorization.manifest_hash.as_deref(), "manifest_hash")?;
    let max_age = chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES);
    let max_skew = chrono::Duration::minutes(1);
    if authorization.issued_at < expected.now - max_age {
        bail!("storage fee authorization is too old (replay window)");
    }
    if authorization.issued_at > expected.now + max_skew {
        bail!("storage fee authorization is dated in the future");
    }
    let authorized_total = authorization
        .paid_shards
        .iter()
        .try_fold(0u64, |acc, shard| acc.checked_add(shard.size_bytes))
        .context("storage fee authorization shard byte total overflow")?;
    if authorized_total > authorization.total_added_encoded_bytes {
        bail!("storage fee authorization shard bytes exceed paid byte total");
    }
    let paid = authorization
        .paid_shards
        .iter()
        .find(|shard| shard.shard_id == *expected.shard_id)
        .context("shard is not covered by storage fee authorization")?;
    if paid.size_bytes != expected.size_bytes {
        bail!(
            "storage fee authorization shard size mismatch: expected {}, got {}",
            paid.size_bytes,
            expected.size_bytes
        );
    }
    if expected.trusted_authority_set.is_none() {
        let authority_key = verifying_key_from_hex(&authorization.authority_public_key)
            .context("invalid storage fee authorization authority_public_key")?;
        let sig_bytes: [u8; 64] = hex::decode(&authorization.signature)
            .context("invalid storage fee authorization signature hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("storage fee authorization signature must be 64 bytes"))?;
        let signature = Signature::from_bytes(&sig_bytes);
        authority_key
            .verify(&payload, &signature)
            .context("storage fee authorization signature verification failed")?;
    }
    Ok(())
}

fn validate_optional_blake3_hex(hash: Option<&str>, name: &str) -> Result<()> {
    if let Some(hash) = hash
        && (hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()))
    {
        bail!("{name} must be a 64-character BLAKE3 hex digest");
    }
    Ok(())
}

pub fn peer_record_signing_payload(record: &PeerRecord) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = record.clone();
    unsigned.signature = None;
    serde_json::to_vec(&unsigned)
}

/// Verify a recipient package record signature and validity.
/// Checks:
/// - package_id is valid UUID
/// - cellule_id is valid
/// - owner_public_key is valid hex Ed25519 key
/// - recipient_public_key is valid hex Ed25519 key
/// - recipient_x25519_pubkey is valid hex X25519 key
/// - fields is not empty
/// - issued_at is within TTL window
/// - expires_at is optional but if present, must be after issued_at
/// - status is Active
/// - package_hash is valid hex
/// - signature verifies against owner_public_key
pub fn verify_recipient_package_record(
    record: &RecipientPackageRecord,
    now: DateTime<Utc>,
) -> Result<()> {
    if record.package_id == Uuid::nil() {
        bail!("package_id cannot be nil");
    }
    if record.cellule_id.0.is_empty() {
        bail!("cellule_id cannot be empty");
    }
    if record.fields.is_empty() {
        bail!("fields cannot be empty");
    }
    if record.status != RecipientPackageStatus::Active {
        bail!("package status must be active for creation");
    }

    // Validate public keys
    verifying_key_from_hex(&record.owner_public_key).context("invalid owner_public_key")?;
    verifying_key_from_hex(&record.recipient_public_key).context("invalid recipient_public_key")?;
    if record.recipient_x25519_pubkey.len() != 64 {
        bail!("recipient_x25519_pubkey must be 64 hex characters");
    }
    hex::decode(&record.recipient_x25519_pubkey).context("invalid recipient_x25519_pubkey hex")?;

    // Validate package hash
    if record.package_hash.len() != 64 {
        bail!("package_hash must be 64 hex characters");
    }
    hex::decode(&record.package_hash).context("invalid package_hash hex")?;

    // Validate timestamps
    let max_age = chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES);
    let max_skew = chrono::Duration::minutes(1);
    if record.issued_at < now - max_age {
        bail!("recipient package is too old (replay window)");
    }
    if record.issued_at > now + max_skew {
        bail!("recipient package is dated in the future");
    }
    if let Some(expires_at) = record.expires_at
        && expires_at <= record.issued_at
    {
        bail!("expires_at must be after issued_at");
    }

    // Verify signature
    let owner_key = verifying_key_from_hex(&record.owner_public_key)
        .context("invalid owner_public_key for verification")?;
    let payload = recipient_package_record_signing_payload(record)
        .context("failed to construct recipient package signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&record.owner_signature)
        .context("invalid recipient package signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("recipient package signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("recipient package signature verification failed")?;
    Ok(())
}

/// Request to remove a recipient package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPackageRemove {
    pub version: u16,
    pub operation: String,
    pub package_id: Uuid,
    pub owner_public_key: String,
    pub issued_at: DateTime<Utc>,
    pub signature: String,
}

/// Construct the canonical signing payload for a recipient package remove request.
pub fn recipient_package_remove_signing_payload(
    remove: &RecipientPackageRemove,
) -> serde_json::Result<Vec<u8>> {
    let mut unsigned = remove.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
}

/// Verify a recipient package remove request.
/// Checks:
/// - version is 1
/// - operation is RECIPIENT_PACKAGE_REMOVE_OPERATION
/// - package_id is valid UUID
/// - owner_public_key is valid hex Ed25519 key
/// - issued_at is within TTL window
/// - signature verifies against owner_public_key
pub fn verify_recipient_package_remove(
    remove: &RecipientPackageRemove,
    expected_package_id: &Uuid,
    now: DateTime<Utc>,
) -> Result<()> {
    if remove.version != 1 {
        bail!(
            "unsupported recipient package remove version: {}",
            remove.version
        );
    }
    if remove.operation != RECIPIENT_PACKAGE_REMOVE_OPERATION {
        bail!(
            "unsupported recipient package remove operation: {}",
            remove.operation
        );
    }
    if remove.package_id != *expected_package_id {
        bail!(
            "package_id mismatch: expected {}, got {}",
            expected_package_id,
            remove.package_id
        );
    }

    // Validate public key
    verifying_key_from_hex(&remove.owner_public_key).context("invalid owner_public_key")?;

    // Validate timestamp
    let max_age = chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES);
    let max_skew = chrono::Duration::minutes(1);
    if remove.issued_at < now - max_age {
        bail!("recipient package remove is too old (replay window)");
    }
    if remove.issued_at > now + max_skew {
        bail!("recipient package remove is dated in the future");
    }

    // Verify signature
    let owner_key = verifying_key_from_hex(&remove.owner_public_key)
        .context("invalid owner_public_key for verification")?;
    let payload = recipient_package_remove_signing_payload(remove)
        .context("failed to construct recipient package remove signing payload")?;
    let sig_bytes: [u8; 64] = hex::decode(&remove.signature)
        .context("invalid recipient package remove signature hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("recipient package remove signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    owner_key
        .verify(&payload, &signature)
        .context("recipient package remove signature verification failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_math_is_exact() {
        // Single segment (legacy): segment 0 == whole length.
        assert_eq!(segment_count(100, 256), 1);
        assert_eq!(segment_original_len(100, 256, 0), 100);
        // Exact multiple.
        assert_eq!(segment_count(512, 256), 2);
        assert_eq!(segment_original_len(512, 256, 0), 256);
        assert_eq!(segment_original_len(512, 256, 1), 256);
        // Ragged last segment.
        assert_eq!(segment_count(600, 256), 3);
        assert_eq!(segment_original_len(600, 256, 0), 256);
        assert_eq!(segment_original_len(600, 256, 1), 256);
        assert_eq!(segment_original_len(600, 256, 2), 88);
        // Past-the-end / zero / degenerate.
        assert_eq!(segment_original_len(600, 256, 5), 0);
        assert_eq!(segment_count(0, 256), 1);
        assert_eq!(segment_original_len(100, 0, 0), 100);
    }

    fn record(expires_at: DateTime<Utc>) -> CellulePublicRecord {
        CellulePublicRecord {
            version: 1,
            cellule_id: CelluleId("cellule".to_string()),
            cellule_public_key: "public".to_string(),
            manifest_cid: "manifest".to_string(),
            sequence: 1,
            expires_at,
            signature: "signature".to_string(),
        }
    }

    #[test]
    fn expiry_means_deletion_is_due_immediately() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let record = record(now);

        assert_eq!(
            record.lifecycle_state_at(now),
            CelluleLifecycleState::Expired
        );
        assert!(record.deletion_due_at(now));
    }

    #[test]
    fn renewal_notice_is_before_expiry_not_after() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let record = record(now + chrono::Duration::days(10));

        assert_eq!(
            record.lifecycle_state_at(now),
            CelluleLifecycleState::ExpiringSoon
        );
        assert!(!record.deletion_due_at(now));
    }

    #[test]
    fn new_cellule_expiry_must_be_future_and_within_one_year() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        assert!(!cellule_expiry_is_valid_at(now, now));
        assert!(cellule_expiry_is_valid_at(
            now,
            now + chrono::Duration::days(365)
        ));
        assert!(!cellule_expiry_is_valid_at(
            now,
            now + chrono::Duration::days(366)
        ));
    }

    #[test]
    fn delete_request_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut request = ShardDeleteRequest {
            version: 1,
            request_id: Uuid::nil(),
            operation: SHARD_DELETE_OPERATION.to_string(),
            shard_id: ShardId("shard".to_string()),
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
            signer_public_key: "public".to_string(),
            signature: "signature-a".to_string(),
        };
        let payload_a = shard_delete_request_signing_payload(&request).unwrap();
        request.signature = "signature-b".to_string();
        let payload_b = shard_delete_request_signing_payload(&request).unwrap();

        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn read_access_grant_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut grant = CelluleReadAccessGrant {
            version: 1,
            grant_id: Uuid::nil(),
            operation: CELLULE_READ_GRANT_OPERATION.to_string(),
            cellule_id: CelluleId("cellule".to_string()),
            owner_public_key: "owner".to_string(),
            recipient_public_key: "recipient".to_string(),
            scope: vec!["identity.company_name".to_string()],
            purpose: Some("bank onboarding".to_string()),
            issued_at: now,
            not_after: None,
            status: CelluleAccessGrantStatus::Active,
            signature: "signature-a".to_string(),
        };
        let payload_a = cellule_read_access_grant_signing_payload(&grant).unwrap();
        grant.signature = "signature-b".to_string();
        let payload_b = cellule_read_access_grant_signing_payload(&grant).unwrap();

        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn verifies_owner_signed_read_access_grant() {
        use ed25519_dalek::Signer;

        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let recipient_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let mut grant = CelluleReadAccessGrant {
            version: 1,
            grant_id: Uuid::nil(),
            operation: CELLULE_READ_GRANT_OPERATION.to_string(),
            cellule_id: CelluleId("cellule".to_string()),
            owner_public_key: hex::encode(owner_key.verifying_key().to_bytes()),
            recipient_public_key: hex::encode(recipient_key.verifying_key().to_bytes()),
            scope: vec!["identity.company_name".to_string()],
            purpose: None,
            issued_at: now,
            not_after: Some(now + chrono::Duration::days(90)),
            status: CelluleAccessGrantStatus::Active,
            signature: String::new(),
        };
        let payload = cellule_read_access_grant_signing_payload(&grant).unwrap();
        grant.signature = hex::encode(owner_key.sign(&payload).to_bytes());

        verify_cellule_read_access_grant(&grant, now).unwrap();

        grant.scope = vec!["identity.company_name".to_string(), "kyc.tin".to_string()];
        assert!(verify_cellule_read_access_grant(&grant, now).is_err());
    }

    #[test]
    fn verifies_owner_signed_read_access_grant_revocation() {
        use ed25519_dalek::Signer;

        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let recipient_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let mut grant = CelluleReadAccessGrant {
            version: 1,
            grant_id: Uuid::nil(),
            operation: CELLULE_READ_GRANT_OPERATION.to_string(),
            cellule_id: CelluleId("cellule".to_string()),
            owner_public_key: hex::encode(owner_key.verifying_key().to_bytes()),
            recipient_public_key: hex::encode(recipient_key.verifying_key().to_bytes()),
            scope: vec!["kyc.status".to_string()],
            purpose: None,
            issued_at: now,
            not_after: None,
            status: CelluleAccessGrantStatus::Active,
            signature: String::new(),
        };
        let grant_payload = cellule_read_access_grant_signing_payload(&grant).unwrap();
        grant.signature = hex::encode(owner_key.sign(&grant_payload).to_bytes());

        let mut revocation = CelluleReadAccessGrantRevocation {
            version: 1,
            revocation_id: Uuid::new_v4(),
            operation: CELLULE_READ_GRANT_REVOCATION_OPERATION.to_string(),
            grant_id: grant.grant_id,
            cellule_id: grant.cellule_id.clone(),
            owner_public_key: grant.owner_public_key.clone(),
            recipient_public_key: grant.recipient_public_key.clone(),
            reason: Some("user revoked company access".to_string()),
            issued_at: now,
            signature: String::new(),
        };
        let payload = cellule_read_access_grant_revocation_signing_payload(&revocation).unwrap();
        revocation.signature = hex::encode(owner_key.sign(&payload).to_bytes());

        verify_cellule_read_access_grant_revocation(&revocation, &grant, now).unwrap();

        revocation.recipient_public_key = hex::encode(owner_key.verifying_key().to_bytes());
        assert!(verify_cellule_read_access_grant_revocation(&revocation, &grant, now).is_err());
    }

    #[test]
    fn verifies_recipient_read_access_proof_with_scope() {
        use ed25519_dalek::Signer;

        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let recipient_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let challenge = CelluleReadAccessProof::generate_challenge();
        let mut grant = CelluleReadAccessGrant {
            version: 1,
            grant_id: Uuid::nil(),
            operation: CELLULE_READ_GRANT_OPERATION.to_string(),
            cellule_id: CelluleId("cellule".to_string()),
            owner_public_key: hex::encode(owner_key.verifying_key().to_bytes()),
            recipient_public_key: hex::encode(recipient_key.verifying_key().to_bytes()),
            scope: vec![
                "identity.company_name".to_string(),
                "kyc.status".to_string(),
            ],
            purpose: Some("company onboarding".to_string()),
            issued_at: now,
            not_after: None,
            status: CelluleAccessGrantStatus::Active,
            signature: String::new(),
        };
        let grant_payload = cellule_read_access_grant_signing_payload(&grant).unwrap();
        grant.signature = hex::encode(owner_key.sign(&grant_payload).to_bytes());

        let mut proof = CelluleReadAccessProof {
            version: 1,
            proof_id: Uuid::nil(),
            operation: CELLULE_READ_PROOF_OPERATION.to_string(),
            grant_id: grant.grant_id,
            cellule_id: grant.cellule_id.clone(),
            recipient_public_key: grant.recipient_public_key.clone(),
            requested_scope: vec!["kyc.status".to_string()],
            challenge: challenge.clone(),
            issued_at: now,
            signature: String::new(),
        };
        let proof_payload = cellule_read_access_proof_signing_payload(&proof).unwrap();
        proof.signature = hex::encode(recipient_key.sign(&proof_payload).to_bytes());

        verify_cellule_read_access(&grant, &proof, &challenge, now).unwrap();

        proof.requested_scope = vec!["kyc.tin".to_string()];
        assert!(verify_cellule_read_access(&grant, &proof, &challenge, now).is_err());
    }

    #[test]
    fn verifies_owner_report_proof_for_cellule_record() {
        use ed25519_dalek::Signer;

        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let challenge = CelluleOwnerReportProof::generate_challenge();
        let record = CellulePublicRecord {
            version: 1,
            cellule_id: CelluleId("cellule".to_string()),
            cellule_public_key: hex::encode(owner_key.verifying_key().to_bytes()),
            manifest_cid: "manifest".to_string(),
            sequence: 1,
            expires_at: now + chrono::Duration::days(90),
            signature: "record-signature".to_string(),
        };
        let mut proof = CelluleOwnerReportProof {
            version: 1,
            proof_id: Uuid::new_v4(),
            operation: CELLULE_OWNER_REPORT_PROOF_OPERATION.to_string(),
            cellule_id: record.cellule_id.clone(),
            owner_public_key: record.cellule_public_key.clone(),
            requested_scope: vec!["cellule.report".to_string()],
            challenge: challenge.clone(),
            issued_at: now,
            signature: String::new(),
        };
        let payload = cellule_owner_report_proof_signing_payload(&proof).unwrap();
        proof.signature = hex::encode(owner_key.sign(&payload).to_bytes());

        verify_cellule_owner_report_proof(&record, &proof, &challenge, now).unwrap();

        proof.requested_scope = vec!["wallet.spend".to_string()];
        assert!(verify_cellule_owner_report_proof(&record, &proof, &challenge, now).is_err());
    }

    #[test]
    fn field_container_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut container = CelluleFieldContainer {
            version: 1,
            container_id: Uuid::nil(),
            cellule_id: CelluleId("cellule".to_string()),
            fields: vec![CelluleFieldEnvelope {
                field: "identity.company_name".to_string(),
                content_type: "application/json".to_string(),
                ciphertext_hex: "00".to_string(),
                plaintext_blake3: "hash".to_string(),
                updated_at: now,
            }],
            created_at: now,
            signature: Some("signature-a".to_string()),
        };
        let payload_a = cellule_field_container_signing_payload(&container).unwrap();
        container.signature = Some("signature-b".to_string());
        let payload_b = cellule_field_container_signing_payload(&container).unwrap();

        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn field_access_package_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut package = CelluleFieldAccessPackage {
            version: 1,
            package_id: Uuid::nil(),
            grant_id: Uuid::nil(),
            cellule_id: CelluleId("cellule".to_string()),
            owner_public_key: "owner".to_string(),
            recipient_public_key: "recipient".to_string(),
            recipient_x25519_pubkey: "x25519".to_string(),
            fields: vec![CelluleFieldAccessEnvelope {
                field: "kyc.status".to_string(),
                content_type: "application/json".to_string(),
                recipient_x25519_pubkey: "x25519".to_string(),
                ephemeral_x25519_pubkey: "ephemeral".to_string(),
                ciphertext_hex: "00".to_string(),
            }],
            issued_at: now,
            signature: "signature-a".to_string(),
        };
        let payload_a = cellule_field_access_package_signing_payload(&package).unwrap();
        package.signature = "signature-b".to_string();
        let payload_b = cellule_field_access_package_signing_payload(&package).unwrap();

        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn verifies_owner_signed_field_access_package() {
        use ed25519_dalek::Signer;

        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let recipient_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let recipient_x25519_pubkey = "11".repeat(32);
        let grant_id = Uuid::new_v4();
        let cellule_id = CelluleId("cellule".to_string());
        let mut grant = CelluleReadAccessGrant {
            version: 1,
            grant_id,
            operation: CELLULE_READ_GRANT_OPERATION.to_string(),
            cellule_id: cellule_id.clone(),
            owner_public_key: hex::encode(owner_key.verifying_key().to_bytes()),
            recipient_public_key: hex::encode(recipient_key.verifying_key().to_bytes()),
            scope: vec!["kyc.status".to_string()],
            purpose: None,
            issued_at: now,
            not_after: None,
            status: CelluleAccessGrantStatus::Active,
            signature: String::new(),
        };
        let grant_payload = cellule_read_access_grant_signing_payload(&grant).unwrap();
        grant.signature = hex::encode(owner_key.sign(&grant_payload).to_bytes());
        let mut package = CelluleFieldAccessPackage {
            version: 1,
            package_id: Uuid::new_v4(),
            grant_id,
            cellule_id,
            owner_public_key: grant.owner_public_key.clone(),
            recipient_public_key: grant.recipient_public_key.clone(),
            recipient_x25519_pubkey: recipient_x25519_pubkey.clone(),
            fields: vec![CelluleFieldAccessEnvelope {
                field: "kyc.status".to_string(),
                content_type: "application/json".to_string(),
                recipient_x25519_pubkey,
                ephemeral_x25519_pubkey: "22".repeat(32),
                ciphertext_hex: "33".repeat(16),
            }],
            issued_at: now,
            signature: String::new(),
        };
        let package_payload = cellule_field_access_package_signing_payload(&package).unwrap();
        package.signature = hex::encode(owner_key.sign(&package_payload).to_bytes());

        verify_cellule_field_access_package(&package, &grant).unwrap();

        package.fields[0].field = "kyc.tin".to_string();
        assert!(verify_cellule_field_access_package(&package, &grant).is_err());
    }

    #[test]
    fn peer_record_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut record = PeerRecord {
            endpoint: "http://127.0.0.1:4433".to_string(),
            node_id: Some(NodeId("node".to_string())),
            public_key: Some("public".to_string()),
            region: Some("eu-fr".to_string()),
            failure_domain: Some("fd".to_string()),
            issued_at: Some(now),
            expires_at: Some(now + chrono::Duration::hours(1)),
            signature: Some("signature-a".to_string()),
        };
        let payload_a = peer_record_signing_payload(&record).unwrap();
        record.signature = Some("signature-b".to_string());
        let payload_b = peer_record_signing_payload(&record).unwrap();

        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn capacity_report_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut report = NodeCapacityReport {
            node_id: NodeId("node".to_string()),
            public_key: Some("public".to_string()),
            free_bytes: 10,
            used_bytes: 2,
            max_bytes: 12,
            reserved_bytes: 0,
            region: "eu-fr".to_string(),
            failure_domain: "fd".to_string(),
            health_score: 1.0,
            current_shard_count: 3,
            issued_at: now,
            signature: Some("signature-a".to_string()),
        };
        let payload_a = capacity_report_signing_payload(&report).unwrap();
        report.signature = Some("signature-b".to_string());
        let payload_b = capacity_report_signing_payload(&report).unwrap();

        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn shard_receipt_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-04-29T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut receipt = ShardReceipt {
            version: 1,
            receipt_id: Uuid::nil(),
            receipt_type: ShardReceiptType::Stored,
            node_id: NodeId("node".to_string()),
            public_key: Some("public".to_string()),
            shard_id: ShardId("shard".to_string()),
            issued_at: now,
            size_bytes: 10,
            expires_at: None,
            signature: Some("signature-a".to_string()),
        };
        let payload_a = shard_receipt_signing_payload(&receipt).unwrap();
        receipt.signature = Some("signature-b".to_string());
        let payload_b = shard_receipt_signing_payload(&receipt).unwrap();

        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn placement_policy_default_is_unconstrained() {
        let p = PlacementPolicy::default();
        assert!(p.is_unconstrained());
        assert_eq!(p.health_score_floor, 0.0);
        assert_eq!(p.min_failure_domains, 0);
        assert_eq!(p.min_unique_nodes, 0);
    }

    #[test]
    fn placement_policy_production_matches_constants() {
        let p = PlacementPolicy::production();
        assert!(!p.is_unconstrained());
        assert_eq!(p.health_score_floor, PRODUCTION_HEALTH_SCORE_FLOOR);
        assert_eq!(p.min_failure_domains, PRODUCTION_MIN_FAILURE_DOMAINS);
        assert_eq!(p.min_unique_nodes, PRODUCTION_MIN_UNIQUE_NODES);
    }

    #[test]
    fn placement_policy_production_roundtrips_json() {
        let p = PlacementPolicy::production();
        let json = serde_json::to_string(&p).unwrap();
        let p2: PlacementPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p.health_score_floor, p2.health_score_floor);
        assert_eq!(p.min_failure_domains, p2.min_failure_domains);
        assert_eq!(p.min_unique_nodes, p2.min_unique_nodes);
    }

    // ── Node ban list tests ──────────────────────────────────────────────────

    fn signed_ban_list(
        root: &ed25519_dalek::SigningKey,
        now: DateTime<Utc>,
        banned_pubkey: &str,
    ) -> NodeBanList {
        use ed25519_dalek::Signer;
        let mut list = NodeBanList {
            version: 1,
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            banned_nodes: vec![NodeBan {
                ed25519_pubkey: banned_pubkey.to_string(),
                banned_at: now,
                quarantine: false,
                reason: Some("abuse".to_string()),
            }],
            confidis_signature: None,
        };
        let payload = node_ban_list_signing_payload(&list).unwrap();
        list.confidis_signature = Some(hex::encode(root.sign(&payload).to_bytes()));
        list
    }

    #[test]
    fn node_ban_list_verifies_and_detects_banned_node() {
        let now = Utc::now();
        let root = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let banned = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let banned_hex = hex::encode(banned.verifying_key().to_bytes());
        let list = signed_ban_list(&root, now, &banned_hex);
        verify_node_ban_list(&list, &root.verifying_key(), now).unwrap();
        assert!(list.is_banned(&banned_hex));
        assert!(!list.is_banned("deadbeef"));
    }

    #[test]
    fn node_ban_list_rejects_bad_signature_and_expiry() {
        let now = Utc::now();
        let root = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let other = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let list = signed_ban_list(&root, now, "abcd");
        let err = verify_node_ban_list(&list, &other.verifying_key(), now).unwrap_err();
        assert!(
            err.to_string().contains("verification failed"),
            "got: {err}"
        );
        let expired = signed_ban_list(&root, now - chrono::Duration::hours(2), "abcd");
        let err = verify_node_ban_list(&expired, &root.verifying_key(), now).unwrap_err();
        assert!(err.to_string().contains("expired"), "got: {err}");
    }

    #[test]
    fn placeholder_genesis_root_is_reported_missing() {
        if CONFIDIS_GENESIS_ROOT_PUBKEY_HEX.chars().all(|c| c == '0') {
            assert!(is_placeholder_genesis_root_pubkey());
            assert_eq!(genesis_root_pubkey_source(), "missing");
            assert!(get_genesis_root_pubkey().is_none());
        }
    }

    fn signed_owner_claim(
        owner: &ed25519_dalek::SigningKey,
        cellule_id: &CelluleId,
        claimed_at: DateTime<Utc>,
    ) -> CelluleOwnerClaim {
        use ed25519_dalek::Signer;
        let mut claim = CelluleOwnerClaim {
            version: 1,
            operation: CELLULE_OWNER_CLAIM_OPERATION.to_string(),
            cellule_id: cellule_id.clone(),
            owner_public_key: hex::encode(owner.verifying_key().to_bytes()),
            claimed_at,
            signature: String::new(),
        };
        let payload = cellule_owner_claim_signing_payload(&claim).unwrap();
        claim.signature = hex::encode(owner.sign(&payload).to_bytes());
        claim
    }

    #[test]
    fn owner_claim_payload_excludes_signature() {
        let now = DateTime::parse_from_rfc3339("2026-05-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut claim = CelluleOwnerClaim {
            version: 1,
            operation: CELLULE_OWNER_CLAIM_OPERATION.to_string(),
            cellule_id: CelluleId("cellule".to_string()),
            owner_public_key: "owner".to_string(),
            claimed_at: now,
            signature: "signature-a".to_string(),
        };
        let payload_a = cellule_owner_claim_signing_payload(&claim).unwrap();
        claim.signature = "signature-b".to_string();
        let payload_b = cellule_owner_claim_signing_payload(&claim).unwrap();
        assert_eq!(payload_a, payload_b);
    }

    #[test]
    fn owner_claim_verifies_with_owner_signature() {
        let now = DateTime::parse_from_rfc3339("2026-05-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let cellule_id = CelluleId("cellule-abc".to_string());
        let claim = signed_owner_claim(&owner, &cellule_id, now);
        verify_cellule_owner_claim(&claim, &cellule_id, now).unwrap();
    }

    #[test]
    fn owner_claim_rejects_wrong_cellule_id() {
        let now = DateTime::parse_from_rfc3339("2026-05-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let claim = signed_owner_claim(&owner, &CelluleId("cellule-x".to_string()), now);
        let err = verify_cellule_owner_claim(&claim, &CelluleId("cellule-y".to_string()), now)
            .unwrap_err();
        assert!(format!("{err}").contains("does not match record"));
    }

    #[test]
    fn owner_claim_rejects_stale_claimed_at() {
        let now = DateTime::parse_from_rfc3339("2026-05-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let cellule_id = CelluleId("cellule-abc".to_string());
        let stale_at = now - chrono::Duration::minutes(CELLULE_OWNER_CLAIM_TTL_MINUTES + 1);
        let claim = signed_owner_claim(&owner, &cellule_id, stale_at);
        let err = verify_cellule_owner_claim(&claim, &cellule_id, now).unwrap_err();
        assert!(format!("{err}").contains("too old"));
    }

    #[test]
    fn owner_claim_rejects_future_claimed_at() {
        let now = DateTime::parse_from_rfc3339("2026-05-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let cellule_id = CelluleId("cellule-abc".to_string());
        let future_at = now + chrono::Duration::minutes(5);
        let claim = signed_owner_claim(&owner, &cellule_id, future_at);
        let err = verify_cellule_owner_claim(&claim, &cellule_id, now).unwrap_err();
        assert!(format!("{err}").contains("future"));
    }

    #[test]
    fn owner_claim_rejects_tampered_owner_pubkey() {
        let now = DateTime::parse_from_rfc3339("2026-05-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let attacker = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let cellule_id = CelluleId("cellule-abc".to_string());
        let mut claim = signed_owner_claim(&owner, &cellule_id, now);
        // Substitute attacker's public key without re-signing — signature must fail.
        claim.owner_public_key = hex::encode(attacker.verifying_key().to_bytes());
        let err = verify_cellule_owner_claim(&claim, &cellule_id, now).unwrap_err();
        assert!(format!("{err}").contains("verification failed"));
    }

    #[test]
    fn paid_shards_commitment_hash_is_ordered_and_deterministic() {
        let shards = vec![
            PaidShardAuthorization {
                shard_id: ShardId("shard-a".to_string()),
                size_bytes: 10,
            },
            PaidShardAuthorization {
                shard_id: ShardId("shard-b".to_string()),
                size_bytes: 20,
            },
        ];
        let same = paid_shards_commitment_hash(&shards).unwrap();
        assert_eq!(same, paid_shards_commitment_hash(&shards).unwrap());

        let mut reversed = shards.clone();
        reversed.reverse();
        assert_ne!(same, paid_shards_commitment_hash(&reversed).unwrap());
    }
}
