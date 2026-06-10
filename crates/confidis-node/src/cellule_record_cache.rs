use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use confidis_protocol::{CellulePublicRecord, verify_cellule_public_record_at};

use crate::state::MAX_CELLULE_RECORDS;

const CELLULE_RECORD_CACHE_RELATIVE_PATH: &[&str] = &["cellules", "cellule-records.json"];

fn cellule_record_cache_path(store_path: &Path) -> PathBuf {
    CELLULE_RECORD_CACHE_RELATIVE_PATH
        .iter()
        .fold(store_path.to_path_buf(), |path, segment| path.join(segment))
}

pub(crate) async fn load_cellule_record_cache(
    store_path: &Path,
) -> HashMap<String, CellulePublicRecord> {
    let path = cellule_record_cache_path(store_path);
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return HashMap::new();
    };
    let Ok(records) = serde_json::from_slice::<Vec<CellulePublicRecord>>(&bytes) else {
        tracing::warn!(path = %path.display(), "Cellule record cache is invalid JSON; ignoring");
        return HashMap::new();
    };

    build_cellule_record_map(records)
}

pub(crate) async fn persist_cellule_record_cache(
    store_path: &Path,
    records: impl IntoIterator<Item = CellulePublicRecord>,
) -> Result<usize> {
    let records = flatten_cellule_record_map(build_cellule_record_map(records));
    let path = cellule_record_cache_path(store_path);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp, serde_json::to_vec_pretty(&records)?)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, &path).await.with_context(|| {
        format!(
            "failed to move Cellule record cache into {}",
            path.display()
        )
    })?;
    Ok(records.len())
}

fn build_cellule_record_map(
    records: impl IntoIterator<Item = CellulePublicRecord>,
) -> HashMap<String, CellulePublicRecord> {
    let mut map = HashMap::new();
    let now = Utc::now();
    for record in records {
        if map.len() >= MAX_CELLULE_RECORDS && !map.contains_key(&record.cellule_id.0) {
            continue;
        }
        if verify_cellule_public_record_at(&record, now).is_err() {
            continue;
        }
        let cellule_id = record.cellule_id.0.clone();
        let replace = map
            .get(&cellule_id)
            .is_none_or(|existing: &CellulePublicRecord| record.sequence >= existing.sequence);
        if replace {
            map.insert(cellule_id, record);
        }
    }
    map
}

fn flatten_cellule_record_map(
    mut map: HashMap<String, CellulePublicRecord>,
) -> Vec<CellulePublicRecord> {
    let mut ids = map.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    ids.into_iter().filter_map(|id| map.remove(&id)).collect()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex};
    use confidis_protocol::{
        CellulePublicRecord, cellule_record_id_from_public_key, cellule_record_signing_payload,
    };

    use super::{load_cellule_record_cache, persist_cellule_record_cache};

    fn signed_record(sequence: u64, manifest_cid: &str) -> CellulePublicRecord {
        let key = generate_signing_key();
        let public_key = verifying_key_to_hex(&key.verifying_key());
        let mut record = CellulePublicRecord {
            version: 1,
            cellule_id: cellule_record_id_from_public_key(&public_key).expect("cellule id"),
            cellule_public_key: public_key,
            manifest_cid: manifest_cid.to_string(),
            sequence,
            expires_at: Utc::now() + chrono::Duration::days(30),
            signature: String::new(),
        };
        let payload = cellule_record_signing_payload(&record).expect("payload");
        record.signature = sign_hex(&key, &payload);
        record
    }

    #[tokio::test]
    async fn roundtrips_only_fresh_signed_cellule_records() {
        let temp = tempfile::tempdir().expect("temp dir");
        let good = signed_record(1, &"a".repeat(64));
        let mut unsigned = signed_record(1, &"b".repeat(64));
        unsigned.signature.clear();
        let mut expired = signed_record(1, &"c".repeat(64));
        expired.expires_at = Utc::now() - chrono::Duration::seconds(1);

        let stored =
            persist_cellule_record_cache(temp.path(), vec![good.clone(), unsigned, expired])
                .await
                .expect("persist");
        assert_eq!(stored, 1);

        let loaded = load_cellule_record_cache(temp.path()).await;
        let record = loaded
            .get(&good.cellule_id.0)
            .expect("cached Cellule record");
        assert_eq!(record.signature, good.signature);
        assert_eq!(record.manifest_cid, good.manifest_cid);
    }
}
