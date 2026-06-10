#[cfg(any())]
use confidis_ledger::Ledger;
use confidis_protocol::{NodeId, ShardId, ShardReceipt};
use serde::Serialize;
use std::path::PathBuf;
#[cfg(any())]
#[derive(Debug, Serialize)]
pub(crate) struct CellulePutOutput {
    pub(crate) cellule_id: confidis_protocol::CelluleId,
    pub(crate) manifest_cid: String,
    pub(crate) placement_path: String,
    pub(crate) manifest_path: String,
    pub(crate) encrypted_manifest_path: String,
    pub(crate) record_path: String,
    pub(crate) provider_records_path: String,
    pub(crate) original_len: u64,
    pub(crate) content_hash: String,
    pub(crate) manifest_hash: String,
    pub(crate) shard_count: usize,
    pub(crate) receipt_count: usize,
    pub(crate) funding_wallet: Option<String>,
    pub(crate) required_cyb: u128,
    pub(crate) funding_balance: Option<u128>,
    pub(crate) funding_debited: bool,
    pub(crate) funding_ledger_output: Option<String>,
    #[cfg(any())]
    pub(crate) price_quote: Option<StoragePriceQuoteOutput>,
}
#[cfg(any())]
#[derive(Debug, Serialize)]
pub(crate) struct StoragePriceQuoteOutput {
    pub(crate) original_bytes: u64,
    pub(crate) encoded_bytes: u64,
    pub(crate) retention_days: u64,
    pub(crate) fixed_fee_cyb: u128,
    pub(crate) storage_byte_day_cyb: u128,
    pub(crate) policy_version: u16,
    pub(crate) policy_hash: String,
    pub(crate) total_cyb: u128,
}
#[cfg(any())]
impl From<confidis_ledger::StoragePriceQuote> for StoragePriceQuoteOutput {
    fn from(quote: confidis_ledger::StoragePriceQuote) -> Self {
        Self {
            original_bytes: quote.original_bytes,
            encoded_bytes: quote.encoded_bytes,
            retention_days: quote.retention_days,
            fixed_fee_cyb: quote.fixed_fee_cyb,
            storage_byte_day_cyb: quote.storage_byte_day_cyb,
            policy_version: quote.policy_version,
            policy_hash: quote.policy_hash,
            total_cyb: quote.total_cyb,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleDeleteOutput {
    pub(crate) cellule_id: String,
    pub(crate) manifest_cid: String,
    pub(crate) status: String,
    pub(crate) deleted_shards: usize,
    pub(crate) failed_shards: usize,
    pub(crate) manifest_deleted: bool,
    pub(crate) record_deleted: bool,
    pub(crate) deletion_receipts: Vec<ShardReceipt>,
    pub(crate) failures: Vec<ShardDeleteFailure>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRepairOutput {
    pub(crate) cellule_id: String,
    pub(crate) old_manifest_cid: String,
    pub(crate) new_manifest_cid: String,
    pub(crate) status: String,
    pub(crate) repaired_shards: Vec<usize>,
    pub(crate) before: AvailabilitySummary,
    pub(crate) after: AvailabilitySummary,
    pub(crate) receipt_count: usize,
    pub(crate) sequence: u64,
    pub(crate) manifest_path: Option<String>,
    pub(crate) encrypted_manifest_path: Option<String>,
    pub(crate) record_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRepairScanOutput {
    pub(crate) scanned: usize,
    pub(crate) repaired: usize,
    pub(crate) healthy: usize,
    pub(crate) expired: usize,
    pub(crate) unrecoverable: usize,
    pub(crate) failed: usize,
    pub(crate) results: Vec<CelluleRepairScanResult>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRepairWatchOutput {
    pub(crate) interval_seconds: u64,
    pub(crate) max_runs: Option<u64>,
    pub(crate) runs_completed: u64,
    pub(crate) last_run: Option<CelluleRepairScanOutput>,
    pub(crate) history: Vec<CelluleRepairScanSummary>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRebalancePlanOutput {
    pub(crate) cellule_id: String,
    pub(crate) manifest_cid: String,
    pub(crate) sequence: u64,
    pub(crate) total_shards: usize,
    pub(crate) proposed_moves: usize,
    pub(crate) current_failure_domains: usize,
    pub(crate) target_failure_domains: usize,
    pub(crate) moves: Vec<ShardRebalanceMove>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRebalanceOutput {
    pub(crate) cellule_id: String,
    pub(crate) old_manifest_cid: String,
    pub(crate) new_manifest_cid: String,
    pub(crate) planned_moves: usize,
    pub(crate) moved_shards: usize,
    pub(crate) delete_failures: usize,
    pub(crate) sequence: u64,
    pub(crate) moves: Vec<ShardRebalanceMoveResult>,
    pub(crate) manifest_path: Option<String>,
    pub(crate) encrypted_manifest_path: Option<String>,
    pub(crate) record_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRebalanceWatchOutput {
    pub(crate) interval_seconds: u64,
    pub(crate) max_runs: Option<u64>,
    pub(crate) runs_completed: u64,
    pub(crate) last_run: Option<CelluleRebalanceScanOutput>,
    pub(crate) history: Vec<CelluleRebalanceScanSummary>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRebalanceScanOutput {
    pub(crate) scanned: usize,
    pub(crate) rebalanced: usize,
    pub(crate) unchanged: usize,
    pub(crate) failed: usize,
    pub(crate) results: Vec<CelluleRebalanceScanResult>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRebalanceScanSummary {
    pub(crate) scanned: usize,
    pub(crate) rebalanced: usize,
    pub(crate) unchanged: usize,
    pub(crate) failed: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRebalanceScanResult {
    pub(crate) cellule_id: String,
    pub(crate) status: String,
    pub(crate) rebalance: Option<CelluleRebalanceOutput>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ShardRebalanceMove {
    pub(crate) segment_index: u32,
    pub(crate) shard_index: usize,
    pub(crate) shard_id: ShardId,
    pub(crate) current_endpoint: Option<String>,
    pub(crate) current_node_id: Option<NodeId>,
    pub(crate) current_failure_domain: Option<String>,
    pub(crate) target_endpoint: String,
    pub(crate) target_node_id: NodeId,
    pub(crate) target_failure_domain: String,
    pub(crate) reason: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ShardRebalanceMoveResult {
    pub(crate) segment_index: u32,
    pub(crate) shard_index: usize,
    pub(crate) shard_id: ShardId,
    pub(crate) from_endpoint: String,
    pub(crate) to_endpoint: String,
    pub(crate) receipt: ShardReceipt,
    pub(crate) old_deleted: bool,
    pub(crate) delete_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRepairScanSummary {
    pub(crate) scanned: usize,
    pub(crate) repaired: usize,
    pub(crate) healthy: usize,
    pub(crate) expired: usize,
    pub(crate) unrecoverable: usize,
    pub(crate) failed: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRepairScanResult {
    pub(crate) cellule_id: String,
    pub(crate) status: String,
    pub(crate) availability: Option<AvailabilitySummary>,
    pub(crate) repair: Option<CelluleRepairOutput>,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct AvailabilitySummary {
    pub(crate) available_shards: usize,
    pub(crate) missing_shards: usize,
    pub(crate) repair_needed: bool,
    pub(crate) restore_possible: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleAvailabilityOutput {
    pub(crate) cellule_id: String,
    pub(crate) manifest_cid: String,
    pub(crate) sequence: u64,
    pub(crate) data_shards: usize,
    pub(crate) parity_shards: usize,
    pub(crate) total_shards: usize,
    pub(crate) available_shards: usize,
    pub(crate) missing_shards: usize,
    pub(crate) repair_needed: bool,
    pub(crate) restore_possible: bool,
    pub(crate) shards: Vec<ShardAvailability>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ShardAvailability {
    pub(crate) shard_index: usize,
    pub(crate) shard_id: ShardId,
    pub(crate) available: bool,
    pub(crate) providers: Vec<ProviderAvailability>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProviderAvailability {
    pub(crate) endpoint: String,
    pub(crate) present: bool,
    pub(crate) status: Option<u16>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ShardDeleteFailure {
    pub(crate) shard_id: ShardId,
    pub(crate) shard_index: usize,
    pub(crate) providers: Vec<String>,
    pub(crate) reason: String,
}
#[cfg(any())]
pub(crate) struct CellulePutArgs {
    pub(crate) nodes: Vec<String>,
    pub(crate) input: PathBuf,
    pub(crate) work_dir: PathBuf,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) public_key: String,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    pub(crate) expires_at: String,
    pub(crate) sequence: u64,
    pub(crate) funding_ledger: Option<PathBuf>,
    pub(crate) funding_wallet: Option<String>,
    pub(crate) required_cyb: u128,
    pub(crate) quote_cyb: bool,
    pub(crate) funding_public_key: Option<String>,
    pub(crate) funding_private_key: Option<String>,
    pub(crate) funding_ledger_output: Option<PathBuf>,
    /// Optional path to a JSON file containing a `PlacementPolicy` override.
    pub(crate) placement_policy_file: Option<PathBuf>,
    /// Optional path to a JSON file containing a `PricingPolicy` override.
    pub(crate) pricing_policy_file: Option<PathBuf>,
}
#[cfg(any())]
pub(crate) struct CelluleFunding {
    pub(crate) balance: Option<u128>,
    pub(crate) debited_ledger: Option<Ledger>,
    pub(crate) ledger_output: Option<PathBuf>,
}

pub(crate) struct CelluleGetArgs {
    pub(crate) nodes: Vec<String>,
    pub(crate) cellule_id: String,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
}

pub(crate) struct CelluleRepairArgs {
    pub(crate) nodes: Vec<String>,
    pub(crate) cellule_id: String,
    pub(crate) work_dir: PathBuf,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
}

#[derive(Clone)]
pub(crate) struct CelluleRepairScanArgs {
    pub(crate) nodes: Vec<String>,
    pub(crate) work_dir: PathBuf,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
}

pub(crate) struct CelluleRepairWatchArgs {
    pub(crate) scan: CelluleRepairScanArgs,
    pub(crate) interval_seconds: u64,
    pub(crate) max_runs: Option<u64>,
    pub(crate) output: PathBuf,
}

pub(crate) struct CelluleRebalancePlanArgs {
    pub(crate) nodes: Vec<String>,
    pub(crate) cellule_id: String,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    /// Optional path to a JSON `PlacementPolicy` file. When `None`, defaults to
    /// `PlacementPolicy::default()` (unconstrained).
    pub(crate) placement_policy_file: Option<PathBuf>,
}

pub(crate) struct CelluleRebalanceArgs {
    pub(crate) nodes: Vec<String>,
    pub(crate) cellule_id: String,
    pub(crate) work_dir: PathBuf,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    /// Optional path to a JSON `PlacementPolicy` file.
    pub(crate) placement_policy_file: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct CelluleRebalanceScanArgs {
    pub(crate) nodes: Vec<String>,
    pub(crate) work_dir: PathBuf,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    /// Optional path to a JSON `PlacementPolicy` file.
    pub(crate) placement_policy_file: Option<PathBuf>,
}

pub(crate) struct CelluleRebalanceWatchArgs {
    pub(crate) scan: CelluleRebalanceScanArgs,
    pub(crate) interval_seconds: u64,
    pub(crate) max_runs: Option<u64>,
    pub(crate) output: PathBuf,
}

pub(crate) struct CelluleRenewArgs {
    pub(crate) cellule_id: String,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    pub(crate) expires_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleRenewOutput {
    pub(crate) cellule_id: String,
    pub(crate) old_expires_at: String,
    pub(crate) new_expires_at: String,
    pub(crate) old_manifest_cid: String,
    pub(crate) new_manifest_cid: String,
    pub(crate) sequence: u64,
    pub(crate) renewed_shards: usize,
    pub(crate) failed_shards: usize,
    pub(crate) failures: Vec<String>,
}

pub(crate) struct CelluleShareArgs {
    pub(crate) cellule_id: String,
    pub(crate) registry: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    pub(crate) nodes: Vec<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) allow_raw_key_export: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleShareOutput {
    pub(crate) cellule_id: String,
    pub(crate) expires_at: String,
    pub(crate) mnemonic: String,
    pub(crate) access_url: String,
    pub(crate) qr_data: String,
    pub(crate) access_bundle_base64: String,
}

pub(crate) struct CelluleReportProofArgs {
    pub(crate) cellule_id: String,
    pub(crate) registry: PathBuf,
    pub(crate) owner_private_key: String,
    pub(crate) challenge: String,
    pub(crate) scope: Vec<String>,
}

pub(crate) struct CelluleReportExportArgs {
    pub(crate) cellule_id: String,
    pub(crate) registry: PathBuf,
    pub(crate) blob_store: PathBuf,
    pub(crate) owner_private_key: String,
    pub(crate) cellule_key: PathBuf,
    pub(crate) proof: PathBuf,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleReportProofOutput {
    pub(crate) proof: confidis_protocol::CelluleOwnerReportProof,
    pub(crate) cellule_id: confidis_protocol::CelluleId,
    pub(crate) requested_scope: Vec<String>,
    pub(crate) warning: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleOwnerReportOutput {
    pub(crate) report_id: uuid::Uuid,
    pub(crate) generated_at: chrono::DateTime<chrono::Utc>,
    pub(crate) proof_id: uuid::Uuid,
    pub(crate) cellule_id: confidis_protocol::CelluleId,
    pub(crate) owner_public_key: String,
    pub(crate) manifest_cid: String,
    pub(crate) sequence: u64,
    pub(crate) lifecycle: String,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
    pub(crate) days_remaining: i64,
    pub(crate) manifest: OwnerReportManifestSummary,
    pub(crate) availability: AvailabilitySummary,
    pub(crate) providers: Vec<String>,
    pub(crate) regions: Vec<String>,
    pub(crate) failure_domains: Vec<String>,
    pub(crate) shards: Vec<OwnerReportShard>,
    pub(crate) warning: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct OwnerReportManifestSummary {
    pub(crate) version: u16,
    pub(crate) manifest_id: uuid::Uuid,
    pub(crate) group_id: String,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) original_size_bytes: u64,
    pub(crate) segment_size_bytes: u64,
    pub(crate) data_shards: usize,
    pub(crate) parity_shards: usize,
    pub(crate) total_shards: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct OwnerReportShard {
    pub(crate) shard_index: usize,
    pub(crate) shard_id: confidis_protocol::ShardId,
    pub(crate) size_bytes: u64,
    pub(crate) region: Option<String>,
    pub(crate) failure_domain: Option<String>,
    pub(crate) provider_hints: Vec<String>,
    pub(crate) available: bool,
    pub(crate) providers: Vec<ProviderAvailability>,
}

pub(crate) struct CelluleFieldsSealArgs {
    pub(crate) cellule_id: String,
    pub(crate) input: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleFieldsSealOutput {
    pub(crate) container: confidis_protocol::CelluleFieldContainer,
    pub(crate) field_count: usize,
}

pub(crate) struct CelluleFieldsOpenArgs {
    pub(crate) container: PathBuf,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    pub(crate) scope: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleFieldsOpenOutput {
    pub(crate) cellule_id: confidis_protocol::CelluleId,
    pub(crate) fields: serde_json::Map<String, serde_json::Value>,
}

pub(crate) struct CelluleFieldsExportArgs {
    pub(crate) container: PathBuf,
    pub(crate) recipient_public_key: Option<String>,
    pub(crate) private_key: String,
    pub(crate) cellule_key: PathBuf,
    pub(crate) recipient_x25519_pubkey: String,
    pub(crate) scope: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleFieldsExportOutput {
    pub(crate) package: confidis_protocol::CelluleFieldAccessPackage,
    pub(crate) field_count: usize,
    pub(crate) warning: String,
}

pub(crate) struct CelluleFieldsRecipientOpenArgs {
    pub(crate) package: PathBuf,
    pub(crate) recipient_x25519_secret: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CelluleFieldsRecipientOpenOutput {
    pub(crate) grant_id: uuid::Uuid,
    pub(crate) cellule_id: confidis_protocol::CelluleId,
    pub(crate) fields: serde_json::Map<String, serde_json::Value>,
}
