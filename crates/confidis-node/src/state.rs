use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use confidis_protocol::{
    CellulePublicRecord, NodeBanList, NodeUptimeRecord, PeerRecord, ShardProviderRecord,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::config::NodeServerConfig;
use crate::maintenance_status_store::load_maintenance_jobs_from_disk;
use crate::noise_session::NoiseServerSession;
use crate::rate_limit::RateLimiter;
use crate::storage_backend::StorageBackend;

pub(crate) const MAX_ROUTING_TABLE_SIZE: usize = 256;
/// Maximum number of uptime records retained (one per distinct node_id).
pub(crate) const MAX_UPTIME_TABLE_SIZE: usize = 256;
pub(crate) const MAX_PROVIDER_RECORDS_PER_SHARD: usize = 32;
pub(crate) const MAX_PROVIDER_RECORD_SHARDS: usize = 4096;
pub(crate) const MAX_CELLULE_RECORDS: usize = 4096;
/// Noise sessions older than this are evicted by the cleanup worker.
pub(crate) const NOISE_SESSION_TTL_SECS: u64 = 300;
/// Circuit opens after this many consecutive failures to a peer.
pub(crate) const CIRCUIT_OPEN_THRESHOLD: u32 = 5;

/// Per-peer circuit-breaker state tracked by the discovery worker.
#[derive(Debug, Clone)]
pub(crate) struct PeerCircuit {
    /// How many consecutive contact failures have been observed.
    pub(crate) consecutive_failures: u32,
    /// If `Some`, the peer is in the open state and should not be contacted
    /// until the contained instant has passed.
    pub(crate) skip_until: Option<Instant>,
}

impl PeerCircuit {
    pub(crate) fn is_open(&self) -> bool {
        self.skip_until.is_some_and(|t| Instant::now() < t)
    }

    /// Called on a successful contact. Returns `true` if the circuit was
    /// previously open (so the caller can log recovery).
    pub(crate) fn record_success(&mut self) -> bool {
        let was_open = self.consecutive_failures >= CIRCUIT_OPEN_THRESHOLD;
        self.consecutive_failures = 0;
        self.skip_until = None;
        was_open
    }

    /// Called on a failed contact. Opens the circuit if the threshold is reached.
    pub(crate) fn record_failure(&mut self) -> Option<std::time::Duration> {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= CIRCUIT_OPEN_THRESHOLD {
            // Back off exponentially: 60 s × 2^(extra failures), capped at 10 min.
            let extra = self.consecutive_failures - CIRCUIT_OPEN_THRESHOLD;
            let secs = (60u64 * (1u64 << extra.min(4))).min(600);
            let backoff = std::time::Duration::from_secs(secs);
            self.skip_until = Some(Instant::now() + backoff);
            Some(backoff)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub(crate) struct NodeState {
    pub(crate) store: Arc<dyn StorageBackend>,
    pub(crate) config: NodeServerConfig,
    pub(crate) routing_table: RwLock<HashMap<String, PeerRecord>>,
    pub(crate) uptime_table: RwLock<HashMap<String, NodeUptimeRecord>>,
    pub(crate) provider_records: RwLock<HashMap<String, Vec<ShardProviderRecord>>>,
    pub(crate) cellule_records: RwLock<HashMap<String, CellulePublicRecord>>,
    pub(crate) started_at: Instant,
    pub(crate) noise_sessions: RwLock<HashMap<Uuid, std::sync::Arc<NoiseServerSession>>>,
    pub(crate) peer_circuit: RwLock<HashMap<String, PeerCircuit>>,
    pub(crate) rate_limiter: Arc<RateLimiter>,
    #[cfg(any())]
    pub(crate) ledger_write_lock: Mutex<()>,
    pub(crate) fee_acceptance_lock: Mutex<()>,
    pub(crate) cellule_registry_write_lock: Mutex<()>,
    pub(crate) package_registry_write_lock: Mutex<()>,
    pub(crate) owner_upload_windows: RwLock<HashMap<String, OwnerUploadWindow>>,
    pub(crate) read_access_challenges: RwLock<HashMap<String, DateTime<Utc>>>,
    pub(crate) owner_report_challenges: RwLock<HashMap<String, DateTime<Utc>>>,
    pub(crate) maintenance_jobs: RwLock<HashMap<String, MaintenanceJobStatus>>,
    pub(crate) node_ban_list: RwLock<Option<NodeBanList>>,
    pub(crate) deletion_convergence: RwLock<HashMap<String, DeletionConvergenceState>>,
}

impl NodeState {
    pub(crate) fn new(
        config: NodeServerConfig,
        store: Arc<dyn StorageBackend>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            maintenance_jobs: RwLock::new(load_maintenance_jobs_from_disk(&config.store_path)),
            node_ban_list: RwLock::new(config.node_ban_list.clone()),
            store,
            config,
            routing_table: RwLock::new(HashMap::new()),
            uptime_table: RwLock::new(HashMap::new()),
            provider_records: RwLock::new(HashMap::new()),
            cellule_records: RwLock::new(HashMap::new()),
            started_at: Instant::now(),
            noise_sessions: RwLock::new(HashMap::new()),
            peer_circuit: RwLock::new(HashMap::new()),
            rate_limiter,
            #[cfg(any())]
            ledger_write_lock: Mutex::new(()),
            fee_acceptance_lock: Mutex::new(()),
            cellule_registry_write_lock: Mutex::new(()),
            package_registry_write_lock: Mutex::new(()),
            owner_upload_windows: RwLock::new(HashMap::new()),
            read_access_challenges: RwLock::new(HashMap::new()),
            owner_report_challenges: RwLock::new(HashMap::new()),
            deletion_convergence: RwLock::new(HashMap::new()),
        }
    }
}

/// Tracks convergence of a cellule deletion across the network.
/// When a cellule is deleted, we track which nodes still owe deletion receipts.
#[derive(Debug, Clone)]
pub(crate) struct DeletionConvergenceState {
    /// The cellule ID being deleted.
    #[allow(dead_code)]
    pub(crate) cellule_id: String,
    /// When the deletion was initiated.
    pub(crate) initiated_at: DateTime<Utc>,
    /// Set of node endpoints that still owe deletion receipts for this cellule's shards.
    pub(crate) pending_nodes: HashSet<String>,
    /// Last time we attempted to contact pending nodes.
    pub(crate) last_attempt: DateTime<Utc>,
    /// Number of retry attempts made.
    pub(crate) retry_count: u32,
}

/// Sliding-window upload counter for one owner (wallet / delete-authority).
#[derive(Debug, Clone)]
pub(crate) struct OwnerUploadWindow {
    /// When the current 1-hour window started.
    pub(crate) window_start: Instant,
    /// Number of shards accepted in this window.
    pub(crate) count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MaintenanceJobStatus {
    pub(crate) job_id: String,
    pub(crate) label: String,
    pub(crate) status: String,
    pub(crate) last_started_at: Option<DateTime<Utc>>,
    pub(crate) last_finished_at: Option<DateTime<Utc>>,
    pub(crate) last_error: Option<String>,
    pub(crate) runs: u64,
    /// Number of runs that ended in an error / attention state.
    pub(crate) error_runs: u64,
    /// Duration of the last completed run in milliseconds.
    pub(crate) last_duration_ms: Option<u64>,
    pub(crate) attention: bool,
    pub(crate) detail: Option<String>,
}

impl MaintenanceJobStatus {
    pub(crate) fn new(job_id: &str, label: &str) -> Self {
        Self {
            job_id: job_id.to_string(),
            label: label.to_string(),
            status: "idle".to_string(),
            last_started_at: None,
            last_finished_at: None,
            last_error: None,
            runs: 0,
            error_runs: 0,
            last_duration_ms: None,
            attention: false,
            detail: None,
        }
    }

    pub(crate) fn initial_jobs() -> HashMap<String, Self> {
        [
            ("audit", "Signed audit export"),
            ("expiry", "Retention expiry"),
            ("integrity", "Shard integrity"),
            ("repair", "Data repair"),
            ("rebalance", "Data rebalance"),
            ("deletion_convergence", "Deletion convergence"),
            ("discovery", "Peer discovery"),
            ("node_ban_list", "CONFIDIS node ban list refresh"),
            ("uptime", "Uptime gossip"),
            ("provider_gossip", "Provider record gossip"),
            ("cellule_record_gossip", "Cellule record gossip"),
            ("kademlia", "Hybrid Kademlia discovery"),
            ("noise_cleanup", "Secure session cleanup"),
        ]
        .into_iter()
        .map(|(job_id, label)| (job_id.to_string(), Self::new(job_id, label)))
        .collect()
    }
}
