use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use chrono::Utc;

use crate::error::ApiError;
use crate::security_events::{SecurityEvent, SecurityEventSeverity, emit_security_event};
use crate::state::NodeState;

/// GET /compliance/security-events
///
/// Returns security events and audit logs for SOC/SIEM consumption.
/// Only includes events that don't expose owner data or operational secrets.
/// Requires compliance_token authentication.
///
/// Query parameters:
/// - `since` (optional): ISO 8601 timestamp to filter events after this time
/// - `limit` (optional): Maximum number of events to return (default: 1000, max: 10000)
///
/// Response: JSON array of security events with metadata but no sensitive data.
pub(crate) async fn compliance_security_events(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let since = if let Some(since_str) = params.get("since") {
        Some(
            chrono::DateTime::parse_from_rfc3339(since_str)
                .map_err(|e| ApiError::bad_request(format!("invalid since parameter: {e}")))?
                .with_timezone(&Utc),
        )
    } else {
        None
    };

    let limit = params
        .get("limit")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|e| ApiError::bad_request(format!("invalid limit parameter: {e}")))?
        .unwrap_or(1000)
        .min(10000);

    let events_path = std::path::Path::new(&state.config.store_path)
        .join("security")
        .join("events.jsonl");

    let mut events = Vec::new();
    if tokio::fs::try_exists(&events_path)
        .await
        .map_err(|e| ApiError::internal(format!("failed to check security events path: {e}")))?
    {
        let content = tokio::fs::read_to_string(&events_path)
            .await
            .map_err(|e| ApiError::internal(format!("failed to read security events: {e}")))?;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let event: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| ApiError::internal(format!("failed to parse security event: {e}")))?;

            let event_type = event.get("event_type").and_then(|v| v.as_str());
            let include_event = matches!(
                event_type,
                Some("auth.failure")
                    | Some("compliance.auth.failure")
                    | Some("rate_limit.exceeded")
                    | Some("shard.access.denied")
                    | Some("cellule.access.denied")
                    | Some("membership.cert.invalid")
                    | Some("membership.cert.expired")
                    | Some("membership.cert.revoked")
                    | Some("noise.session.failed")
                    | Some("transport.policy.violation")
                    | Some("quota.exceeded")
                    | Some("maintenance.job.failed")
                    | Some("integrity.check.failed")
                    | Some("repair.failed")
                    | Some("rebalance.failed")
                    | Some("deletion.failed")
                    | Some("audit.violation")
            );

            if include_event {
                let mut filtered_event = event.clone();
                if let Some(obj) = filtered_event.as_object_mut() {
                    obj.remove("owner_public_key");
                    obj.remove("cellule_id");
                    obj.remove("package_id");
                    obj.remove("shard_id");
                    obj.remove("private_key");
                    obj.remove("signature");

                    if let Some(context) = obj.get_mut("context")
                        && let Some(context_obj) = context.as_object_mut()
                    {
                        context_obj.remove("client_ip");
                        context_obj.remove("remote_addr");
                    }
                }

                if let Some(since_ts) = since
                    && let Some(event_ts) = event.get("timestamp").and_then(|v| v.as_str())
                    && let Ok(event_dt) = chrono::DateTime::parse_from_rfc3339(event_ts)
                    && event_dt.with_timezone(&Utc) < since_ts
                {
                    continue;
                }

                events.push(filtered_event);

                if events.len() >= limit {
                    break;
                }
            }
        }
    }

    emit_security_event(
        &state,
        SecurityEvent::new(
            &state,
            "compliance.access",
            SecurityEventSeverity::Info,
            "Compliance security events accessed",
        )
        .with_context("events_returned", events.len().to_string())
        .with_context("since", params.get("since").cloned().unwrap_or_default())
        .with_context("limit", limit.to_string()),
    );

    Ok(Json(events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestNodeStateOptions, test_node_state};

    #[tokio::test]
    async fn compliance_security_events_filters_and_redacts_exported_events() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "compliance-test-node",
                ..Default::default()
            },
        );
        let security_dir = temp.path().join("security");
        std::fs::create_dir_all(&security_dir).expect("security dir");
        let events_path = security_dir.join("events.jsonl");
        let old_ts = (Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
        let new_ts = Utc::now().to_rfc3339();
        let lines = [
            serde_json::json!({
                "event_type": "auth.failure",
                "timestamp": old_ts,
                "owner_public_key": "owner-secret",
                "cellule_id": "cellule-secret",
                "context": {
                    "client_ip": "192.0.2.10",
                    "uri": "/health"
                }
            }),
            serde_json::json!({
                "event_type": "cellule.created",
                "timestamp": new_ts,
                "owner_public_key": "owner-secret"
            }),
            serde_json::json!({
                "event_type": "rate_limit.exceeded",
                "timestamp": new_ts,
                "package_id": "package-secret",
                "signature": "signature-secret",
                "context": {
                    "remote_addr": "198.51.100.42",
                    "uri": "/metrics"
                }
            }),
        ]
        .into_iter()
        .map(|event| event.to_string())
        .collect::<Vec<_>>()
        .join("\n");
        std::fs::write(&events_path, format!("{lines}\n")).expect("events jsonl");

        let since = (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        let mut params = HashMap::new();
        params.insert("since".to_string(), since);
        params.insert("limit".to_string(), "1".to_string());

        let Json(events) = compliance_security_events(State(state), Query(params))
            .await
            .expect("compliance events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_type"], "rate_limit.exceeded");
        assert!(events[0].get("package_id").is_none());
        assert!(events[0].get("signature").is_none());
        assert_eq!(events[0]["context"]["uri"], "/metrics");
        assert!(events[0]["context"].get("remote_addr").is_none());
    }
}
