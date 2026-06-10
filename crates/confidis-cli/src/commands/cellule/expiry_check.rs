use anyhow::Result;
use confidis_protocol::CelluleLifecycleState;
use serde::Serialize;
use std::path::Path;

use super::helpers::read_registry;

#[derive(Debug, Serialize)]
pub(super) struct ExpiryCheckOutput {
    pub(super) checked_at: chrono::DateTime<chrono::Utc>,
    pub(super) days_window: Option<i64>,
    pub(super) total: usize,
    pub(super) active: usize,
    pub(super) expiring_soon: usize,
    pub(super) expired: usize,
    pub(super) results: Vec<CelluleExpiryEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CelluleExpiryEntry {
    pub(super) cellule_id: String,
    pub(super) expires_at: String,
    pub(super) days_remaining: i64,
    pub(super) lifecycle: String,
}

pub(super) fn cellule_expiry_check(
    registry: &Path,
    days_window: Option<i64>,
) -> Result<ExpiryCheckOutput> {
    let records = read_registry(registry)?;
    let now = chrono::Utc::now();
    let mut output = ExpiryCheckOutput {
        checked_at: now,
        days_window,
        total: records.len(),
        active: 0,
        expiring_soon: 0,
        expired: 0,
        results: Vec::new(),
    };

    for record in &records {
        let state = record.lifecycle_state_at(now);
        let days_remaining = (record.expires_at - now).num_days();
        let lifecycle = match &state {
            CelluleLifecycleState::Active => {
                output.active += 1;
                "active"
            }
            CelluleLifecycleState::ExpiringSoon => {
                output.expiring_soon += 1;
                "expiring_soon"
            }
            CelluleLifecycleState::Expired => {
                output.expired += 1;
                "expired"
            }
        };

        let include = match days_window {
            Some(window) => days_remaining <= window,
            None => true,
        };

        if include {
            output.results.push(CelluleExpiryEntry {
                cellule_id: record.cellule_id.0.clone(),
                expires_at: record.expires_at.to_rfc3339(),
                days_remaining,
                lifecycle: lifecycle.to_string(),
            });
        }
    }

    output.results.sort_by_key(|e| e.days_remaining);
    Ok(output)
}
