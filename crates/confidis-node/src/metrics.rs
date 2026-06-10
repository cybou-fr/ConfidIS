use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::state::MaintenanceJobStatus;
use crate::storage_backend::ShardStoreStats;

static METRICS: OnceLock<ConfidISMetrics> = OnceLock::new();

/// Core CONFIDIS node metrics.
///
/// This intentionally stays dependency-free for the public-testnet node: the
/// `/metrics` endpoint emits Prometheus text from local atomics and small label
/// maps, while keeping the door open for a richer metrics crate later.
#[derive(Debug, Default)]
pub struct ConfidISMetrics {
    http_requests: Mutex<HashMap<(String, u16), u64>>,
    http_request_duration_ms_total: AtomicU64,
    shard_operations: Mutex<HashMap<(String, bool), u64>>,
    security_events: Mutex<HashMap<String, u64>>,
    dht_events: Mutex<HashMap<String, u64>>,
    dht_imports: Mutex<HashMap<String, u64>>,
    dht_import_lag_ms_total: Mutex<HashMap<String, u64>>,
    dht_import_lag_observations: Mutex<HashMap<String, u64>>,
    shard_uploads_total: AtomicU64,
    shard_upload_bytes_total: AtomicU64,
}

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub http_requests: Vec<((String, u16), u64)>,
    pub http_request_duration_ms_total: u64,
    pub shard_operations: Vec<((String, bool), u64)>,
    pub security_events: Vec<(String, u64)>,
    pub dht_events: Vec<(String, u64)>,
    pub dht_imports: Vec<(String, u64)>,
    pub dht_import_lag_ms_total: Vec<(String, u64)>,
    pub dht_import_lag_observations: Vec<(String, u64)>,
    pub shard_uploads_total: u64,
    pub shard_upload_bytes_total: u64,
}

impl ConfidISMetrics {
    /// Get the global metrics instance after [`init_metrics`] has been called.
    pub fn global() -> Option<&'static Self> {
        METRICS.get()
    }

    /// Record an HTTP request.
    pub fn record_http_request(&self, method: &str, status: u16, duration_secs: f64) {
        increment_map(&self.http_requests, (method.to_string(), status));
        self.http_request_duration_ms_total.fetch_add(
            duration_secs.mul_add(1000.0, 0.0).round().max(0.0) as u64,
            Ordering::Relaxed,
        );
    }

    /// Record a shard operation.
    pub fn record_shard_operation(&self, operation: &str, success: bool) {
        increment_map(&self.shard_operations, (operation.to_string(), success));
    }

    /// Record a security event.
    pub fn record_security_event(&self, event_type: &str) {
        increment_map(&self.security_events, event_type.to_string());
    }

    /// Record a DHT worker event.
    pub fn record_dht_event(&self, event_type: &str) {
        increment_map(&self.dht_events, event_type.to_string());
    }

    /// Record a DHT-imported signed record and optional propagation lag.
    pub fn record_dht_import(&self, kind: &str, propagation_lag_ms: Option<u64>) {
        increment_map(&self.dht_imports, kind.to_string());
        if let Some(ms) = propagation_lag_ms {
            add_map(&self.dht_import_lag_ms_total, kind.to_string(), ms);
            increment_map(&self.dht_import_lag_observations, kind.to_string());
        }
    }

    /// Record a shard upload.
    pub fn record_shard_upload(&self, size_bytes: u64) {
        self.shard_uploads_total.fetch_add(1, Ordering::Relaxed);
        self.shard_upload_bytes_total
            .fetch_add(size_bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let mut http_requests = snapshot_map(&self.http_requests);
        http_requests.sort_by(|a, b| a.0.cmp(&b.0));

        let mut shard_operations = snapshot_map(&self.shard_operations);
        shard_operations.sort_by(|a, b| a.0.cmp(&b.0));

        let mut security_events = snapshot_map(&self.security_events);
        security_events.sort_by(|a, b| a.0.cmp(&b.0));

        let mut dht_events = snapshot_map(&self.dht_events);
        dht_events.sort_by(|a, b| a.0.cmp(&b.0));

        let mut dht_imports = snapshot_map(&self.dht_imports);
        dht_imports.sort_by(|a, b| a.0.cmp(&b.0));

        let mut dht_import_lag_ms_total = snapshot_map(&self.dht_import_lag_ms_total);
        dht_import_lag_ms_total.sort_by(|a, b| a.0.cmp(&b.0));

        let mut dht_import_lag_observations = snapshot_map(&self.dht_import_lag_observations);
        dht_import_lag_observations.sort_by(|a, b| a.0.cmp(&b.0));

        MetricsSnapshot {
            http_requests,
            http_request_duration_ms_total: self
                .http_request_duration_ms_total
                .load(Ordering::Relaxed),
            shard_operations,
            security_events,
            dht_events,
            dht_imports,
            dht_import_lag_ms_total,
            dht_import_lag_observations,
            shard_uploads_total: self.shard_uploads_total.load(Ordering::Relaxed),
            shard_upload_bytes_total: self.shard_upload_bytes_total.load(Ordering::Relaxed),
        }
    }
}

/// Initialize local metrics and return the process-wide registry.
pub fn init_metrics() -> &'static ConfidISMetrics {
    METRICS.get_or_init(ConfidISMetrics::default)
}

pub fn render_prometheus(
    node_id: &str,
    max_bytes: u64,
    peer_count: usize,
    stats: ShardStoreStats,
    jobs: &[MaintenanceJobStatus],
    snapshot: MetricsSnapshot,
) -> String {
    let free_bytes = max_bytes.saturating_sub(stats.used_bytes);
    let health_score = if max_bytes == 0 {
        1.0_f32
    } else {
        let usage_ratio = stats.used_bytes as f32 / max_bytes as f32;
        (1.0 - usage_ratio).clamp(0.0, 1.0)
    };
    let node = escape_label(node_id);
    let mut body = format!(
        "# HELP confidis_shard_count Number of shards currently stored\n\
         # TYPE confidis_shard_count gauge\n\
         confidis_shard_count{{node=\"{node}\"}} {shard_count}\n\
         # HELP confidis_used_bytes Bytes of shard data currently stored\n\
         # TYPE confidis_used_bytes gauge\n\
         confidis_used_bytes{{node=\"{node}\"}} {used_bytes}\n\
         # HELP confidis_free_bytes Bytes available for new shards\n\
         # TYPE confidis_free_bytes gauge\n\
         confidis_free_bytes{{node=\"{node}\"}} {free_bytes}\n\
         # HELP confidis_max_bytes Configured storage capacity in bytes\n\
         # TYPE confidis_max_bytes gauge\n\
         confidis_max_bytes{{node=\"{node}\"}} {max_bytes}\n\
         # HELP confidis_health_score Node health score (0.0 = full, 1.0 = empty)\n\
         # TYPE confidis_health_score gauge\n\
         confidis_health_score{{node=\"{node}\"}} {health_score:.4}\n\
         # HELP confidis_routing_table_size Number of peers in the routing table\n\
         # TYPE confidis_routing_table_size gauge\n\
         confidis_routing_table_size{{node=\"{node}\"}} {peer_count}\n",
        node = node,
        shard_count = stats.shard_count,
        used_bytes = stats.used_bytes,
        free_bytes = free_bytes,
        max_bytes = max_bytes,
        health_score = health_score,
        peer_count = peer_count,
    );

    body.push_str(
        "# HELP confidis_worker_runs_total Total number of completed maintenance worker runs\n\
         # TYPE confidis_worker_runs_total counter\n",
    );
    for job in jobs {
        body.push_str(&format!(
            "confidis_worker_runs_total{{node=\"{node}\",job=\"{job_id}\"}} {runs}\n",
            node = node,
            job_id = escape_label(&job.job_id),
            runs = job.runs,
        ));
    }

    body.push_str(
        "# HELP confidis_worker_error_runs_total Total maintenance worker runs that ended in error\n\
         # TYPE confidis_worker_error_runs_total counter\n",
    );
    for job in jobs {
        body.push_str(&format!(
            "confidis_worker_error_runs_total{{node=\"{node}\",job=\"{job_id}\"}} {error_runs}\n",
            node = node,
            job_id = escape_label(&job.job_id),
            error_runs = job.error_runs,
        ));
    }

    body.push_str(
        "# HELP confidis_worker_last_duration_ms Duration of the last completed maintenance worker run in milliseconds\n\
         # TYPE confidis_worker_last_duration_ms gauge\n",
    );
    for job in jobs {
        if let Some(ms) = job.last_duration_ms {
            body.push_str(&format!(
                "confidis_worker_last_duration_ms{{node=\"{node}\",job=\"{job_id}\"}} {ms}\n",
                node = node,
                job_id = escape_label(&job.job_id),
                ms = ms,
            ));
        }
    }

    body.push_str(
        "# HELP confidis_http_requests_total Total HTTP requests handled by method and status\n\
         # TYPE confidis_http_requests_total counter\n",
    );
    for ((method, status), count) in snapshot.http_requests {
        body.push_str(&format!(
            "confidis_http_requests_total{{node=\"{node}\",method=\"{method}\",status=\"{status}\"}} {count}\n",
            node = node,
            method = escape_label(&method),
            status = status,
            count = count,
        ));
    }

    body.push_str(
        "# HELP confidis_http_request_duration_ms_total Sum of HTTP request durations in milliseconds\n\
         # TYPE confidis_http_request_duration_ms_total counter\n",
    );
    body.push_str(&format!(
        "confidis_http_request_duration_ms_total{{node=\"{node}\"}} {duration}\n",
        node = node,
        duration = snapshot.http_request_duration_ms_total,
    ));

    body.push_str(
        "# HELP confidis_shard_operations_total Total shard operations by operation and result\n\
         # TYPE confidis_shard_operations_total counter\n",
    );
    for ((operation, success), count) in snapshot.shard_operations {
        body.push_str(&format!(
            "confidis_shard_operations_total{{node=\"{node}\",operation=\"{operation}\",success=\"{success}\"}} {count}\n",
            node = node,
            operation = escape_label(&operation),
            success = success,
            count = count,
        ));
    }

    body.push_str(
        "# HELP confidis_shard_uploads_total Total successful shard uploads\n\
         # TYPE confidis_shard_uploads_total counter\n",
    );
    body.push_str(&format!(
        "confidis_shard_uploads_total{{node=\"{node}\"}} {uploads}\n",
        node = node,
        uploads = snapshot.shard_uploads_total,
    ));
    body.push_str(
        "# HELP confidis_shard_upload_bytes_total Total bytes accepted through shard uploads\n\
         # TYPE confidis_shard_upload_bytes_total counter\n",
    );
    body.push_str(&format!(
        "confidis_shard_upload_bytes_total{{node=\"{node}\"}} {bytes}\n",
        node = node,
        bytes = snapshot.shard_upload_bytes_total,
    ));

    body.push_str(
        "# HELP confidis_security_events_total Total security events by type\n\
         # TYPE confidis_security_events_total counter\n",
    );
    for (event_type, count) in snapshot.security_events {
        body.push_str(&format!(
            "confidis_security_events_total{{node=\"{node}\",event_type=\"{event_type}\"}} {count}\n",
            node = node,
            event_type = escape_label(&event_type),
            count = count,
        ));
    }

    body.push_str(
        "# HELP confidis_dht_events_total Total DHT worker events by type\n\
         # TYPE confidis_dht_events_total counter\n",
    );
    for (event_type, count) in snapshot.dht_events {
        body.push_str(&format!(
            "confidis_dht_events_total{{node=\"{node}\",event_type=\"{event_type}\"}} {count}\n",
            node = node,
            event_type = escape_label(&event_type),
            count = count,
        ));
    }

    body.push_str(
        "# HELP confidis_dht_imports_total Total signed records imported through the DHT by kind\n\
         # TYPE confidis_dht_imports_total counter\n",
    );
    for (kind, count) in snapshot.dht_imports {
        body.push_str(&format!(
            "confidis_dht_imports_total{{node=\"{node}\",kind=\"{kind}\"}} {count}\n",
            node = node,
            kind = escape_label(&kind),
            count = count,
        ));
    }

    body.push_str(
        "# HELP confidis_dht_import_propagation_lag_ms_total Sum of DHT import propagation lag in milliseconds by record kind\n\
         # TYPE confidis_dht_import_propagation_lag_ms_total counter\n",
    );
    for (kind, lag_ms) in snapshot.dht_import_lag_ms_total {
        body.push_str(&format!(
            "confidis_dht_import_propagation_lag_ms_total{{node=\"{node}\",kind=\"{kind}\"}} {lag_ms}\n",
            node = node,
            kind = escape_label(&kind),
            lag_ms = lag_ms,
        ));
    }
    body.push_str(
        "# HELP confidis_dht_import_propagation_lag_observations_total Count of DHT import propagation lag observations by record kind\n\
         # TYPE confidis_dht_import_propagation_lag_observations_total counter\n",
    );
    for (kind, observations) in snapshot.dht_import_lag_observations {
        body.push_str(&format!(
            "confidis_dht_import_propagation_lag_observations_total{{node=\"{node}\",kind=\"{kind}\"}} {observations}\n",
            node = node,
            kind = escape_label(&kind),
            observations = observations,
        ));
    }

    body
}

fn increment_map<K>(mutex: &Mutex<HashMap<K, u64>>, key: K)
where
    K: Eq + std::hash::Hash,
{
    if let Ok(mut values) = mutex.lock() {
        *values.entry(key).or_default() += 1;
    }
}

fn add_map<K>(mutex: &Mutex<HashMap<K, u64>>, key: K, amount: u64)
where
    K: Eq + std::hash::Hash,
{
    if let Ok(mut values) = mutex.lock() {
        let value = values.entry(key).or_default();
        *value = value.saturating_add(amount);
    }
}

fn snapshot_map<K>(mutex: &Mutex<HashMap<K, u64>>) -> Vec<(K, u64)>
where
    K: Clone,
{
    mutex
        .lock()
        .map(|values| {
            values
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect()
        })
        .unwrap_or_default()
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}
