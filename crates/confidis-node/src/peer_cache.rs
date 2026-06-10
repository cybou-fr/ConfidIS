use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use confidis_crypto::{verify_hex, verifying_key_from_hex};
use confidis_protocol::{PeerRecord, peer_record_signing_payload};

use crate::state::MAX_ROUTING_TABLE_SIZE;
use crate::util::normalize_endpoint;

const PEER_CACHE_RELATIVE_PATH: &[&str] = &["peers", "routing-cache.json"];

fn peer_cache_path(store_path: &Path) -> PathBuf {
    PEER_CACHE_RELATIVE_PATH
        .iter()
        .fold(store_path.to_path_buf(), |path, segment| path.join(segment))
}

pub(crate) async fn load_peer_cache(
    store_path: &Path,
    self_endpoint: Option<&str>,
) -> Vec<PeerRecord> {
    let path = peer_cache_path(store_path);
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return Vec::new();
    };
    let Ok(records) = serde_json::from_slice::<Vec<PeerRecord>>(&bytes) else {
        tracing::warn!(path = %path.display(), "peer cache is invalid JSON; ignoring");
        return Vec::new();
    };
    let self_endpoint = self_endpoint.map(normalize_endpoint);
    let mut loaded = Vec::new();
    for mut record in records {
        record.endpoint = normalize_endpoint(&record.endpoint);
        if self_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint == &record.endpoint)
        {
            continue;
        }
        if !is_fresh_signed_peer_record(&record) {
            continue;
        }
        loaded.push(record);
        if loaded.len() >= MAX_ROUTING_TABLE_SIZE {
            break;
        }
    }
    loaded
}

pub(crate) async fn persist_peer_cache(
    store_path: &Path,
    records: impl IntoIterator<Item = PeerRecord>,
    self_endpoint: Option<&str>,
) -> Result<usize> {
    let self_endpoint = self_endpoint.map(normalize_endpoint);
    let mut cache = Vec::new();
    for mut record in records {
        record.endpoint = normalize_endpoint(&record.endpoint);
        if self_endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint == &record.endpoint)
        {
            continue;
        }
        if !is_fresh_signed_peer_record(&record) {
            continue;
        }
        cache.push(record);
        if cache.len() >= MAX_ROUTING_TABLE_SIZE {
            break;
        }
    }

    let path = peer_cache_path(store_path);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, serde_json::to_vec_pretty(&cache)?)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("failed to move peer cache into {}", path.display()))?;
    Ok(cache.len())
}

fn is_fresh_signed_peer_record(record: &PeerRecord) -> bool {
    let (Some(public_key), Some(issued_at), Some(expires_at), Some(signature)) = (
        record.public_key.as_deref(),
        record.issued_at,
        record.expires_at,
        record.signature.as_deref(),
    ) else {
        return false;
    };
    if expires_at <= issued_at {
        return false;
    }
    let now = Utc::now();
    if now >= expires_at || issued_at > now + chrono::Duration::minutes(5) {
        return false;
    }
    let Ok(key) = verifying_key_from_hex(public_key) else {
        return false;
    };
    let Ok(payload) = peer_record_signing_payload(record) else {
        return false;
    };
    verify_hex(&key, &payload, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex};
    use confidis_protocol::{NodeId, PeerRecord, peer_record_signing_payload};

    use super::{load_peer_cache, persist_peer_cache};

    fn signed_record(endpoint: &str) -> PeerRecord {
        let signing_key = generate_signing_key();
        let now = Utc::now();
        let mut record = PeerRecord {
            endpoint: endpoint.to_string(),
            node_id: Some(NodeId("peer-1".to_string())),
            public_key: Some(verifying_key_to_hex(&signing_key.verifying_key())),
            region: Some("eu-fr".to_string()),
            failure_domain: Some("fd-1".to_string()),
            issued_at: Some(now),
            expires_at: Some(now + chrono::Duration::hours(1)),
            signature: None,
        };
        let payload = peer_record_signing_payload(&record).expect("payload");
        record.signature = Some(sign_hex(&signing_key, &payload));
        record
    }

    #[tokio::test]
    async fn roundtrips_only_fresh_signed_peer_records() {
        let temp = tempfile::tempdir().expect("temp dir");
        let good = signed_record("http://127.0.0.1:3001");
        let mut unsigned = good.clone();
        unsigned.endpoint = "http://127.0.0.1:3002".to_string();
        unsigned.signature = None;
        let mut expired = signed_record("http://127.0.0.1:3003");
        expired.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));

        let stored = persist_peer_cache(
            temp.path(),
            vec![good.clone(), unsigned, expired],
            Some("http://127.0.0.1:3009"),
        )
        .await
        .expect("persist");
        assert_eq!(stored, 1);

        let loaded = load_peer_cache(temp.path(), Some("http://127.0.0.1:3009")).await;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].endpoint, "http://127.0.0.1:3001");
        assert_eq!(loaded[0].public_key, good.public_key);
    }

    #[tokio::test]
    async fn skips_self_endpoint_on_load() {
        let temp = tempfile::tempdir().expect("temp dir");
        let own = signed_record("http://127.0.0.1:3001");
        persist_peer_cache(temp.path(), vec![own], None)
            .await
            .expect("persist");

        let loaded = load_peer_cache(temp.path(), Some("http://127.0.0.1:3001")).await;
        assert!(loaded.is_empty());
    }
}
