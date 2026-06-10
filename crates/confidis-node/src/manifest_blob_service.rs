//! Encrypted manifest availability endpoints.
//!
//! Nodes store only encrypted, content-addressed manifest bytes. The plaintext
//! manifest and Cellule key stay client-side; the network uses this blob solely
//! to recover the shard map when the owner's local blob cache is unavailable.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use confidis_protocol::cellule_expiry_is_valid_at;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::node_info_service::HealthResponse;
use crate::state::NodeState;

const MAX_ENCRYPTED_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManifestBlobMetadata {
    version: u16,
    cid: String,
    expires_at: DateTime<Utc>,
    size_bytes: u64,
}

pub(crate) async fn put_manifest_blob(
    State(state): State<Arc<NodeState>>,
    AxumPath(cid): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<HealthResponse>, ApiError> {
    validate_cid(&cid)?;
    if body.is_empty() {
        return Err(ApiError::bad_request("encrypted manifest body is empty"));
    }
    if body.len() > MAX_ENCRYPTED_MANIFEST_BYTES {
        return Err(ApiError::status(
            StatusCode::PAYLOAD_TOO_LARGE,
            "manifest_too_large",
            "encrypted manifest exceeds the beta size limit",
        ));
    }
    let actual = confidis_crypto::blake3_hex(&body);
    if actual != cid {
        return Err(ApiError::bad_request(format!(
            "manifest CID mismatch: expected {cid}, got {actual}"
        )));
    }
    let expires_at = required_datetime_header(&headers, "x-confidis-expires-at")?;
    let now = Utc::now();
    if !cellule_expiry_is_valid_at(now, expires_at) {
        return Err(ApiError::bad_request(
            "x-confidis-expires-at must be in the future and no more than 365 days from now",
        ));
    }

    persist_manifest_blob(
        &state.config.store_path,
        &cid,
        &body,
        ManifestBlobMetadata {
            version: 1,
            cid: cid.clone(),
            expires_at,
            size_bytes: body.len() as u64,
        },
    )
    .await?;

    Ok(axum::Json(HealthResponse {
        status: "ok",
        node_id: state.config.node_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        shard_count: 0,
        peer_count: state.routing_table.read().await.len(),
        discovery_backend: state.config.discovery_backend.clone(),
        kademlia_enabled: state.config.discovery_backend == "hybrid_kademlia",
        ban_verification_enabled: state.config.confidis_root_pubkey.is_some(),
        noise_sessions: state.noise_sessions.read().await.len(),
        node_ban_list_present: state.node_ban_list.read().await.is_some(),
        node_banned: false,
        trust_root_source: state.config.confidis_root_source.clone(),
        listen_port: state.config.listen_addr.port(),
        webui_enabled: state.config.webui_path.is_some(),
        content_dir_enabled: state.config.content_dir.is_some(),
        ui_auth_required: !state.config.production_profile && state.config.ui_token.is_some(),
        ui_cors_restricted: state.config.ui_allowed_origin.is_some(),
        operator_ui_enabled: !state.config.production_profile,
        public_ui_only: state.config.production_profile,
    }))
}

pub(crate) async fn get_manifest_blob(
    State(state): State<Arc<NodeState>>,
    AxumPath(cid): AxumPath<String>,
) -> Result<Response, ApiError> {
    validate_cid(&cid)?;
    let metadata = read_manifest_metadata(&state.config.store_path, &cid).await?;
    if Utc::now() >= metadata.expires_at {
        return Err(ApiError::not_found("encrypted manifest expired"));
    }
    let path = manifest_blob_path(&state.config.store_path, &cid);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| ApiError::internal(format!("failed to read encrypted manifest: {e}")))?;
    let actual = confidis_crypto::blake3_hex(&bytes);
    if actual != cid {
        return Err(ApiError::internal(format!(
            "stored encrypted manifest CID mismatch: expected {cid}, got {actual}"
        )));
    }
    Ok((StatusCode::OK, bytes).into_response())
}

fn validate_cid(cid: &str) -> Result<(), ApiError> {
    if cid.len() != 64 || !cid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "manifest CID must be a 64-char hex BLAKE3 hash",
        ));
    }
    Ok(())
}

fn required_datetime_header(headers: &HeaderMap, name: &str) -> Result<DateTime<Utc>, ApiError> {
    let value = headers
        .get(name)
        .ok_or_else(|| ApiError::bad_request(format!("missing required header {name}")))?
        .to_str()
        .map_err(|_| ApiError::bad_request(format!("invalid header {name}")))?;
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ApiError::bad_request(format!("invalid RFC3339 header {name}")))
}

async fn persist_manifest_blob(
    store_path: &Path,
    cid: &str,
    bytes: &[u8],
    metadata: ManifestBlobMetadata,
) -> Result<(), ApiError> {
    let blob_path = manifest_blob_path(store_path, cid);
    let metadata_path = manifest_metadata_path(store_path, cid);
    if let Some(parent) = blob_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::internal(format!("failed to create manifest dir: {e}")))?;
    }
    if let Some(parent) = metadata_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            ApiError::internal(format!("failed to create manifest metadata dir: {e}"))
        })?;
    }
    tokio::fs::write(&blob_path, bytes)
        .await
        .map_err(|e| ApiError::internal(format!("failed to write encrypted manifest: {e}")))?;
    let metadata_bytes = serde_json::to_vec_pretty(&metadata)
        .map_err(|e| ApiError::internal(format!("failed to serialize manifest metadata: {e}")))?;
    tokio::fs::write(&metadata_path, metadata_bytes)
        .await
        .map_err(|e| ApiError::internal(format!("failed to write manifest metadata: {e}")))?;
    Ok(())
}

async fn read_manifest_metadata(
    store_path: &Path,
    cid: &str,
) -> Result<ManifestBlobMetadata, ApiError> {
    let path = manifest_metadata_path(store_path, cid);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError::not_found("encrypted manifest not found"))?;
    let metadata: ManifestBlobMetadata = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::internal(format!("invalid manifest metadata: {e}")))?;
    if metadata.version != 1 || metadata.cid != cid {
        return Err(ApiError::internal("invalid manifest metadata identity"));
    }
    Ok(metadata)
}

fn manifest_blob_path(store_path: &Path, cid: &str) -> PathBuf {
    let prefix = cid.get(0..2).unwrap_or("xx");
    store_path
        .join("manifests")
        .join("blobs")
        .join(prefix)
        .join(cid)
}

fn manifest_metadata_path(store_path: &Path, cid: &str) -> PathBuf {
    let prefix = cid.get(0..2).unwrap_or("xx");
    store_path
        .join("manifests")
        .join("metadata")
        .join(prefix)
        .join(format!("{cid}.json"))
}

#[cfg(test)]
mod tests {
    use axum::body::{Bytes, to_bytes};
    use axum::extract::State;
    use axum::http::HeaderMap;
    use chrono::Utc;

    use super::{get_manifest_blob, put_manifest_blob};
    use crate::test_support::{TestNodeStateOptions, test_node_state};

    #[tokio::test]
    async fn manifest_blob_roundtrips_by_cid_until_expiry() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state = test_node_state(&temp, TestNodeStateOptions::default());
        let body = b"encrypted-manifest-bytes".to_vec();
        let cid = confidis_crypto::blake3_hex(&body);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-confidis-expires-at",
            (Utc::now() + chrono::Duration::days(30))
                .to_rfc3339()
                .parse()
                .expect("header"),
        );

        let _ = put_manifest_blob(
            State(state.clone()),
            axum::extract::Path(cid.clone()),
            headers,
            body.clone().into(),
        )
        .await
        .expect("put manifest");

        let response = get_manifest_blob(State(state), axum::extract::Path(cid))
            .await
            .expect("get manifest");
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec();
        assert_eq!(bytes, body);
    }

    #[tokio::test]
    async fn manifest_blob_rejects_cid_mismatch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state = test_node_state(&temp, TestNodeStateOptions::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-confidis-expires-at",
            (Utc::now() + chrono::Duration::days(30))
                .to_rfc3339()
                .parse()
                .expect("header"),
        );

        let err = put_manifest_blob(
            State(state),
            axum::extract::Path("a".repeat(64)),
            headers,
            Bytes::from_static(b"different"),
        )
        .await
        .expect_err("cid mismatch rejected");
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
    }
}
