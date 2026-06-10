use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use confidis_protocol::{ShardProviderRecord, verify_shard_provider_record};

use crate::state::{MAX_PROVIDER_RECORD_SHARDS, MAX_PROVIDER_RECORDS_PER_SHARD};
use crate::util::normalize_endpoint;

const PROVIDER_CACHE_RELATIVE_PATH: &[&str] = &["providers", "provider-records.json"];

fn provider_cache_path(store_path: &Path) -> PathBuf {
    PROVIDER_CACHE_RELATIVE_PATH
        .iter()
        .fold(store_path.to_path_buf(), |path, segment| path.join(segment))
}

pub(crate) async fn load_provider_cache(
    store_path: &Path,
) -> HashMap<String, Vec<ShardProviderRecord>> {
    let path = provider_cache_path(store_path);
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return HashMap::new();
    };
    let Ok(records) = serde_json::from_slice::<Vec<ShardProviderRecord>>(&bytes) else {
        tracing::warn!(path = %path.display(), "provider cache is invalid JSON; ignoring");
        return HashMap::new();
    };

    build_provider_map(records)
}

pub(crate) async fn persist_provider_cache(
    store_path: &Path,
    records: impl IntoIterator<Item = ShardProviderRecord>,
) -> Result<usize> {
    let records = flatten_provider_map(build_provider_map(records));
    let path = provider_cache_path(store_path);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, serde_json::to_vec_pretty(&records)?)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("failed to move provider cache into {}", path.display()))?;
    Ok(records.len())
}

fn build_provider_map(
    records: impl IntoIterator<Item = ShardProviderRecord>,
) -> HashMap<String, Vec<ShardProviderRecord>> {
    let mut map: HashMap<String, Vec<ShardProviderRecord>> = HashMap::new();
    let now = Utc::now();
    for mut record in records {
        record.endpoint = normalize_endpoint(&record.endpoint);
        if record.expires_at.is_none_or(|expires_at| now >= expires_at) {
            continue;
        }
        if verify_shard_provider_record(&record).is_err() {
            continue;
        }
        let shard_id = record.shard_id.0.clone();
        if !map.contains_key(&shard_id) && map.len() >= MAX_PROVIDER_RECORD_SHARDS {
            continue;
        }
        let entry = map.entry(shard_id).or_default();
        entry.retain(|existing| {
            existing.provider_record_id != record.provider_record_id
                && !(existing.shard_id == record.shard_id
                    && existing.node_id == record.node_id
                    && existing.endpoint == record.endpoint)
        });
        entry.push(record);
        entry.sort_by_key(|record| std::cmp::Reverse(record.issued_at));
        entry.truncate(MAX_PROVIDER_RECORDS_PER_SHARD);
    }
    map
}

fn flatten_provider_map(
    mut map: HashMap<String, Vec<ShardProviderRecord>>,
) -> Vec<ShardProviderRecord> {
    let mut records = Vec::new();
    let mut shard_ids = map.keys().cloned().collect::<Vec<_>>();
    shard_ids.sort();
    for shard_id in shard_ids {
        if let Some(mut entries) = map.remove(&shard_id) {
            entries.sort_by_key(|record| std::cmp::Reverse(record.issued_at));
            records.extend(entries);
        }
    }
    records
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex};
    use confidis_protocol::{
        CelluleId, NodeId, ShardId, ShardProviderRecord, shard_provider_record_signing_payload,
    };
    use uuid::Uuid;

    use super::{load_provider_cache, persist_provider_cache};

    fn signed_provider_record(endpoint: &str, shard_id: &str) -> ShardProviderRecord {
        let key = generate_signing_key();
        let now = Utc::now();
        let mut record = ShardProviderRecord {
            version: 1,
            provider_record_id: Uuid::new_v4(),
            cellule_id: CelluleId("cellule-test".to_string()),
            manifest_id: Uuid::new_v4(),
            shard_id: ShardId(shard_id.to_string()),
            shard_index: 0,
            segment_index: 0,
            node_id: NodeId("provider-node".to_string()),
            public_key: verifying_key_to_hex(&key.verifying_key()),
            endpoint: endpoint.to_string(),
            region: "eu-fr".to_string(),
            failure_domain: "fd-1".to_string(),
            receipt_id: Uuid::new_v4(),
            receipt_signature: "00".repeat(64),
            issued_at: now,
            expires_at: Some(now + chrono::Duration::minutes(10)),
            signature: None,
        };
        let payload = shard_provider_record_signing_payload(&record).expect("payload");
        record.signature = Some(sign_hex(&key, &payload));
        record
    }

    #[tokio::test]
    async fn roundtrips_only_fresh_signed_provider_records() {
        let temp = tempfile::tempdir().expect("temp dir");
        let good = signed_provider_record("http://127.0.0.1:3001", "shard-1");
        let mut unsigned = signed_provider_record("http://127.0.0.1:3002", "shard-2");
        unsigned.signature = None;
        let mut expired = signed_provider_record("http://127.0.0.1:3003", "shard-3");
        expired.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));

        let stored = persist_provider_cache(temp.path(), vec![good.clone(), unsigned, expired])
            .await
            .expect("persist");
        assert_eq!(stored, 1);

        let loaded = load_provider_cache(temp.path()).await;
        let records = loaded.get("shard-1").expect("shard providers");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].endpoint, "http://127.0.0.1:3001");
        assert_eq!(records[0].signature, good.signature);
        assert!(!loaded.contains_key("shard-2"));
        assert!(!loaded.contains_key("shard-3"));
    }
}
