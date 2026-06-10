use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::NodeState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecurityEventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SecurityEvent {
    pub(crate) version: u16,
    pub(crate) event_id: Uuid,
    pub(crate) event_type: String,
    pub(crate) severity: SecurityEventSeverity,
    pub(crate) node_id: String,
    pub(crate) occurred_at: DateTime<Utc>,
    pub(crate) message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) context: BTreeMap<String, String>,
}

impl SecurityEvent {
    pub(crate) fn new(
        state: &NodeState,
        event_type: impl Into<String>,
        severity: SecurityEventSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            version: 1,
            event_id: Uuid::new_v4(),
            event_type: event_type.into(),
            severity,
            node_id: state.config.node_id.0.clone(),
            occurred_at: Utc::now(),
            message: message.into(),
            context: BTreeMap::new(),
        }
    }

    pub(crate) fn with_context(mut self, key: &str, value: impl ToString) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

pub(crate) fn emit_security_event(state: &Arc<NodeState>, event: SecurityEvent) {
    // Record metrics for security events
    if let Some(metrics) = crate::metrics::ConfidISMetrics::global() {
        metrics.record_security_event(&event.event_type);
    }

    let store_path = state.config.store_path.clone();
    let webhook_urls = state.config.security_event_webhook_urls.clone();
    let event_type = event.event_type.clone();

    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(move || {
                export_security_event(&store_path, &webhook_urls, &event);
            });
        }
        Err(_) => {
            tracing::debug!(event_type = %event_type, "exporting security event without tokio runtime");
            export_security_event(&store_path, &webhook_urls, &event);
        }
    }
}

fn export_security_event(store_path: &Path, webhook_urls: &[String], event: &SecurityEvent) {
    if let Err(err) = append_security_event(store_path, event) {
        tracing::warn!(error = %err, event_type = %event.event_type, "failed to write security event to file");
    }

    for url in webhook_urls {
        if let Err(err) = send_to_webhook(url, event) {
            tracing::warn!(error = %err, url = %url, event_type = %event.event_type, "failed to send security event to webhook");
        }
    }

    // Send to syslog (best effort)
    let _ = send_to_syslog(event);
}

fn append_security_event(store_path: &Path, event: &SecurityEvent) -> std::io::Result<()> {
    let dir = store_path.join("security");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("events.jsonl");
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, event).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn send_to_syslog(event: &SecurityEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Simple syslog over UDP to localhost:514
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_nonblocking(true)?;

    let priority = match event.severity {
        SecurityEventSeverity::Info => 134, // LOG_USER | LOG_INFO = 8*16 + 6 = 134
        SecurityEventSeverity::Warning => 132, // LOG_USER | LOG_WARNING = 8*16 + 4 = 132
        SecurityEventSeverity::Critical => 128, // LOG_USER | LOG_CRIT = 8*16 + 2 = 128
    };

    let timestamp = event.occurred_at.format("%b %e %H:%M:%S");
    let hostname = hostname::get()?
        .into_string()
        .unwrap_or_else(|_| "confidis-node".to_string());
    let message = format!(
        "<{}>{} {} confidis-node[{}]: CONFIDIS security event: {} - {} (node: {}, event_id: {})",
        priority,
        timestamp,
        hostname,
        std::process::id(),
        event.event_type,
        event.message,
        event.node_id,
        event.event_id
    );

    // Try to send, but don't fail if syslog is not available
    let _ = socket.send_to(message.as_bytes(), "127.0.0.1:514");
    Ok(())
}

fn send_to_webhook(
    url: &str,
    event: &SecurityEvent,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Send JSON event to webhook URL
    // This is a fire-and-forget operation - we don't wait for response
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let json = serde_json::to_string(event)?;
    let _response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "confidis-node/1.0")
        .body(json)
        .send()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeServerConfig;
    use crate::rate_limit::RateLimiter;
    use crate::state::NodeState;
    use crate::storage_backend::FilesystemStorage;
    use confidis_protocol::{NodeId, PlacementPolicy};
    use std::sync::Arc;

    #[test]
    fn security_event_exporter_writes_jsonl() {
        let temp = tempfile::tempdir().expect("temp dir");
        let config = NodeServerConfig {
            node_id: NodeId("security-test-node".to_string()),
            production_profile: false,
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
            registry_path: None,
            read_access_revocations_path: None,
            ui_token: None,
            ui_allowed_origin: None,
            min_expiry_days: 1,
            max_expiry_days: confidis_protocol::MAX_CELLULE_LIFETIME_DAYS as u32,
            max_shards_per_owner_per_hour: 0,
            max_cellules_per_owner: 0,
            authorized_operator_pubkeys: Vec::new(),
            webui_path: None,
            content_dir: None,
            transport_policy: confidis_protocol::TransportPolicy::Development,
            packages_path: None,
            security_event_webhook_urls: Vec::new(),
            compliance_token: None,
        };
        let store = Arc::new(FilesystemStorage::new(config.store_path.clone()).expect("store"));
        let state = Arc::new(NodeState::new(
            config,
            store,
            Arc::new(RateLimiter::new(10, 0)),
        ));

        emit_security_event(
            &state,
            SecurityEvent::new(
                &state,
                "auth.failure",
                SecurityEventSeverity::Warning,
                "bad token",
            )
            .with_context("path", "/health"),
        );

        let body =
            std::fs::read_to_string(temp.path().join("security/events.jsonl")).expect("events");
        let line = body.lines().next().expect("event line");
        let parsed: SecurityEvent = serde_json::from_str(line).expect("event json");
        assert_eq!(parsed.event_type, "auth.failure");
        assert_eq!(parsed.node_id, "security-test-node");
        assert_eq!(parsed.context["path"], "/health");
    }
}
