use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use serde::Serialize;

use crate::error::ApiError;
use crate::state::NodeState;
use crate::storage_backend::run_storage_task;

/// `GET /receipts[?limit=N]`
///
/// Returns all shard receipts stored on this node, sorted newest-first.
/// The optional `limit` query parameter caps the result (default 200, max 1000).
pub(crate) async fn list_receipts(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
        .min(1000);

    let receipts = run_storage_task(&state, |store| store.read_all_receipts())
        .await
        .map_err(ApiError::from)?;

    let page: Vec<_> = receipts.into_iter().take(limit).collect();
    Ok(Json(
        serde_json::json!({ "receipts": page, "count": page.len() }),
    ))
}

#[cfg(any())]
#[derive(Debug, Serialize)]
pub(crate) struct PricingResponse {
    /// Deprecated compatibility field. Authoritative pricing is global and
    /// does not use byte-days.
    /// Deprecated compatibility field.
    pub fee_policy_version: u16,
    pub fee_policy_hash: String,
    pub fixed_base_fee_cyb: u128,
    pub per_added_byte_fee_cyb: u128,
    /// Minimum Cellule lifetime in days.
    pub min_expiry_days: u32,
    /// Maximum Cellule lifetime in days.
    pub max_expiry_days: u32,
}

/// Public node-mode descriptor. Lets the Web UI pick the right surface
/// (authority vs company-node) without any privileged endpoint.
#[derive(Debug, Serialize)]
pub(crate) struct NodeInfoResponse {
    /// Node role derived from configuration: `"authority"` for an isolated
    /// authority/signer surface, `"company"` otherwise (operator + user space).
    /// Production public nodes must delegate authority signing to an isolated
    /// signer instead of holding private key material themselves.
    pub node_role: &'static str,
    /// `production_profile` of the node — UI uses this to render a stronger
    /// warning when keys/credentials are not configured.
    pub production_profile: bool,
}

/// `GET /node-info`
///
/// Public, unauthenticated descriptor used by the Web UI (and any tooling) to
/// know which surface to render.
pub(crate) async fn node_info(State(state): State<Arc<NodeState>>) -> Json<NodeInfoResponse> {
    let node_role = if false {
        "authority"
    } else {
        "company"
    };
    Json(NodeInfoResponse {
        node_role,
        production_profile: state.config.production_profile,
    })
}

/// `GET /pricing`
///
/// Returns the node's pricing rules.  This endpoint is **public** (no UI token
/// required) so the CLI and external tools can query it before committing a
/// Cellule registration.
#[cfg(any())]
pub(crate) async fn pricing(State(state): State<Arc<NodeState>>) -> Json<PricingResponse> {
    Json(PricingResponse {
        fee_policy_version: 0,
        fee_policy_hash: String::new(),
        fixed_base_fee_cyb: 0,
        per_added_byte_fee_cyb: 0,
        min_expiry_days: state.config.min_expiry_days,
        max_expiry_days: state.config.max_expiry_days,
    })
}
