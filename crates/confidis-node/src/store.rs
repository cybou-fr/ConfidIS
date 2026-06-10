use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use confidis_crypto::{blake3_hex, sign_hex, verifying_key_to_hex};
use confidis_error::{ConfidISError, Result};
use confidis_protocol::{
    NodeId, ShardId, ShardReceipt, ShardReceiptType, shard_receipt_signing_payload,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ShardStore {
    root: PathBuf,
}

impl ShardStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("shards"))
            .map_err(|e| ConfidISError::internal(format!("failed to create shard store: {e}")))?;
        fs::create_dir_all(root.join("metadata"))
            .map_err(|e| ConfidISError::internal(format!("failed to create metadata store: {e}")))?;
        fs::create_dir_all(root.join("receipts"))
            .map_err(|e| ConfidISError::internal(format!("failed to create receipt store: {e}")))?;
        Ok(Self { root })
    }

    pub fn put(
        &self,
        node_id: NodeId,
        bytes: &[u8],
        expires_at: Option<DateTime<Utc>>,
        delete_authority_hash: String,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt> {
        let shard_id = ShardId(blake3_hex(bytes));
        let path = self.shard_path(&shard_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                ConfidISError::internal(format!("failed to create shard directory: {e}"))
            })?;
        }
        fs::write(&path, bytes).map_err(|e| {
            ConfidISError::internal(format!("failed to write shard {}: {e}", shard_id.0))
        })?;
        self.write_metadata(&ShardMetadata {
            version: 1,
            shard_id: shard_id.clone(),
            delete_authority_hash,
            expires_at,
        })?;
        let mut receipt = self.receipt(
            node_id,
            shard_id,
            ShardReceiptType::Stored,
            bytes.len(),
            expires_at,
        );
        self.sign_receipt(&mut receipt, signing_key)?;
        self.write_receipt(&receipt)?;
        Ok(receipt)
    }

    pub fn get(&self, shard_id: &ShardId) -> Result<Vec<u8>> {
        let metadata = self.read_metadata(shard_id)?;
        if let Some(expires_at) = metadata.expires_at
            && Utc::now() >= expires_at
        {
            return Err(ConfidISError::expired(format!(
                "shard {} expired at {}",
                shard_id.0, expires_at
            )));
        }
        let bytes = fs::read(self.shard_path(shard_id)).map_err(|e| {
            ConfidISError::internal(format!("failed to read shard {}: {e}", shard_id.0))
        })?;
        let actual = blake3_hex(&bytes);
        if actual != shard_id.0 {
            return Err(ConfidISError::validation(format!(
                "shard hash mismatch: expected {}, got {}",
                shard_id.0, actual
            )));
        }
        Ok(bytes)
    }

    pub fn delete(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signer_public_key: &str,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt> {
        self.verify_delete_authority(shard_id, signer_public_key)?;
        self.delete_unchecked(node_id, shard_id, signing_key, false)
    }

    pub fn delete_expired(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>> {
        let mut receipts = Vec::new();
        for metadata in self.read_all_metadata()? {
            let Some(expires_at) = metadata.expires_at else {
                continue;
            };
            if now >= expires_at && self.exists(&metadata.shard_id) {
                receipts.push(self.delete_unchecked(
                    node_id.clone(),
                    &metadata.shard_id,
                    signing_key,
                    true,
                )?);
            }
        }
        Ok(receipts)
    }

    /// Return shards whose expiry is in the future but within `within` of `now`.
    /// Used by the expiry worker to emit structured warnings before deletion occurs.
    pub(crate) fn expiring_soon(
        &self,
        now: DateTime<Utc>,
        within: chrono::Duration,
    ) -> Result<Vec<(ShardId, DateTime<Utc>)>> {
        let threshold = now + within;
        let mut out = Vec::new();
        for metadata in self.read_all_metadata()? {
            let Some(expires_at) = metadata.expires_at else {
                continue;
            };
            if expires_at > now && expires_at <= threshold {
                out.push((metadata.shard_id, expires_at));
            }
        }
        Ok(out)
    }

    pub fn check_integrity(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>> {
        let mut receipts = Vec::new();
        for metadata in self.read_all_metadata()? {
            if let Some(expires_at) = metadata.expires_at
                && now >= expires_at
            {
                continue;
            }
            let path = self.shard_path(&metadata.shard_id);
            if !path.exists() {
                continue;
            }
            let bytes = fs::read(&path).map_err(|e| {
                ConfidISError::internal(format!("failed to read shard {}: {e}", metadata.shard_id.0))
            })?;
            let actual = blake3_hex(&bytes);
            if actual != metadata.shard_id.0 {
                return Err(ConfidISError::validation(format!(
                    "shard hash mismatch: expected {}, got {}",
                    metadata.shard_id.0, actual
                )));
            }
            let mut receipt = self.receipt(
                node_id.clone(),
                metadata.shard_id,
                ShardReceiptType::IntegrityChecked,
                bytes.len(),
                metadata.expires_at,
            );
            self.sign_receipt(&mut receipt, signing_key)?;
            self.write_receipt(&receipt)?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub(crate) fn delete_unchecked(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signing_key: Option<&SigningKey>,
        remove_metadata: bool,
    ) -> Result<ShardReceipt> {
        let metadata = self.read_metadata(shard_id).ok();
        let path = self.shard_path(shard_id);
        let size = match fs::metadata(&path) {
            Ok(meta) => meta.len() as usize,
            Err(_) => 0,
        };
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                ConfidISError::internal(format!("failed to delete shard {}: {e}", shard_id.0))
            })?;
        }
        let metadata_path = self.metadata_path(shard_id);
        if remove_metadata && metadata_path.exists() {
            fs::remove_file(&metadata_path).map_err(|e| {
                ConfidISError::internal(format!("failed to delete metadata {}: {e}", shard_id.0))
            })?;
        }
        let mut receipt = self.receipt(
            node_id,
            shard_id.clone(),
            ShardReceiptType::Deleted,
            size,
            metadata.and_then(|metadata| metadata.expires_at),
        );
        self.sign_receipt(&mut receipt, signing_key)?;
        self.write_receipt(&receipt)?;
        Ok(receipt)
    }

    fn verify_delete_authority(&self, shard_id: &ShardId, signer_public_key: &str) -> Result<()> {
        let metadata = self.read_metadata(shard_id)?;
        let signer_hash = blake3_hex(signer_public_key.as_bytes());
        if signer_hash != metadata.delete_authority_hash {
            return Err(ConfidISError::forbidden(format!(
                "delete signer is not authorized for shard {}",
                shard_id.0
            )));
        }
        Ok(())
    }

    pub fn exists(&self, shard_id: &ShardId) -> bool {
        self.shard_path(shard_id).exists()
    }

    pub(crate) fn status(&self, shard_id: &ShardId) -> ShardLocalStatus {
        match self.read_metadata(shard_id) {
            Ok(metadata) => {
                if let Some(expires_at) = metadata.expires_at
                    && Utc::now() >= expires_at
                {
                    return ShardLocalStatus {
                        present: false,
                        valid: false,
                        error: Some(format!("shard expired at {expires_at}")),
                    };
                }
            }
            Err(err) => {
                return ShardLocalStatus {
                    present: false,
                    valid: false,
                    error: Some(format!("metadata unavailable: {err}")),
                };
            }
        }

        let path = self.shard_path(shard_id);
        if !path.exists() {
            return ShardLocalStatus {
                present: false,
                valid: false,
                error: None,
            };
        }
        match fs::read(&path) {
            Ok(bytes) => {
                let actual = blake3_hex(&bytes);
                if actual == shard_id.0 {
                    ShardLocalStatus {
                        present: true,
                        valid: true,
                        error: None,
                    }
                } else {
                    ShardLocalStatus {
                        present: false,
                        valid: false,
                        error: Some(format!(
                            "shard hash mismatch: expected {}, got {}",
                            shard_id.0, actual
                        )),
                    }
                }
            }
            Err(err) => ShardLocalStatus {
                present: false,
                valid: false,
                error: Some(format!("failed to read shard: {err}")),
            },
        }
    }

    pub fn stats(&self) -> Result<ShardStoreStats> {
        let shard_root = self.root.join("shards");
        let mut used_bytes = 0u64;
        let mut shard_count = 0u64;
        if shard_root.exists() {
            collect_stats(&shard_root, &mut used_bytes, &mut shard_count)?;
        }
        Ok(ShardStoreStats {
            used_bytes,
            shard_count,
        })
    }

    fn receipt(
        &self,
        node_id: NodeId,
        shard_id: ShardId,
        receipt_type: ShardReceiptType,
        size: usize,
        expires_at: Option<DateTime<Utc>>,
    ) -> ShardReceipt {
        ShardReceipt {
            version: 1,
            receipt_id: Uuid::new_v4(),
            receipt_type,
            node_id,
            public_key: None,
            shard_id,
            issued_at: Utc::now(),
            size_bytes: size as u64,
            expires_at,
            signature: None,
        }
    }

    fn write_receipt(&self, receipt: &ShardReceipt) -> Result<()> {
        let path = self
            .root
            .join("receipts")
            .join(format!("{}.json", receipt.receipt_id));
        let json = serde_json::to_vec_pretty(receipt)
            .map_err(|e| ConfidISError::internal(format!("failed to serialize receipt: {e}")))?;
        fs::write(path, json)
            .map_err(|e| ConfidISError::internal(format!("failed to write receipt: {e}")))
    }

    fn write_metadata(&self, metadata: &ShardMetadata) -> Result<()> {
        let path = self.metadata_path(&metadata.shard_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                ConfidISError::internal(format!("failed to create metadata directory: {e}"))
            })?;
        }
        let json = serde_json::to_vec_pretty(metadata)
            .map_err(|e| ConfidISError::internal(format!("failed to serialize metadata: {e}")))?;
        fs::write(path, json)
            .map_err(|e| ConfidISError::internal(format!("failed to write shard metadata: {e}")))
    }

    fn read_metadata(&self, shard_id: &ShardId) -> Result<ShardMetadata> {
        let path = self.metadata_path(shard_id);
        let bytes = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfidISError::not_found(format!("failed to read shard metadata {}", shard_id.0))
            } else {
                ConfidISError::internal(format!("failed to read shard metadata {}: {e}", shard_id.0))
            }
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|e| ConfidISError::validation(format!("invalid shard metadata: {e}")))
    }

    pub(crate) fn read_all_metadata(&self) -> Result<Vec<ShardMetadata>> {
        let mut metadata = Vec::new();
        let root = self.root.join("metadata");
        if root.exists() {
            collect_metadata(&root, &mut metadata)?;
        }
        Ok(metadata)
    }

    /// Read all shard receipts from the receipts directory, sorted newest-first.
    pub fn read_all_receipts(&self) -> Result<Vec<ShardReceipt>> {
        let root = self.root.join("receipts");
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut receipts = Vec::new();
        for entry in fs::read_dir(&root)
            .map_err(|e| ConfidISError::internal(format!("failed to read receipts dir: {e}")))?
        {
            let entry = entry.map_err(|e| {
                ConfidISError::internal(format!("failed to read receipt dir entry: {e}"))
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match fs::read(&path) {
                    Ok(bytes) => match serde_json::from_slice::<ShardReceipt>(&bytes) {
                        Ok(r) => receipts.push(r),
                        Err(e) => {
                            tracing::warn!(path = %path.display(), err = %e, "skipping malformed receipt")
                        }
                    },
                    Err(e) => {
                        tracing::warn!(path = %path.display(), err = %e, "failed to read receipt")
                    }
                }
            }
        }
        receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt.issued_at));
        Ok(receipts)
    }

    fn sign_receipt(
        &self,
        receipt: &mut ShardReceipt,
        signing_key: Option<&SigningKey>,
    ) -> Result<()> {
        let Some(signing_key) = signing_key else {
            return Ok(());
        };
        receipt.signature = None;
        receipt.public_key = Some(verifying_key_to_hex(&signing_key.verifying_key()));
        let payload = shard_receipt_signing_payload(receipt).map_err(|e| {
            ConfidISError::internal(format!("failed to serialize receipt for signing: {e}"))
        })?;
        receipt.signature = Some(sign_hex(signing_key, &payload));
        Ok(())
    }

    fn shard_path(&self, shard_id: &ShardId) -> PathBuf {
        let prefix = shard_id.0.get(0..2).unwrap_or("xx");
        self.root.join("shards").join(prefix).join(&shard_id.0)
    }

    fn metadata_path(&self, shard_id: &ShardId) -> PathBuf {
        let prefix = shard_id.0.get(0..2).unwrap_or("xx");
        self.root
            .join("metadata")
            .join(prefix)
            .join(format!("{}.json", shard_id.0))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ShardMetadata {
    pub(crate) version: u16,
    pub(crate) shard_id: ShardId,
    pub(crate) delete_authority_hash: String,
    pub(crate) expires_at: Option<DateTime<Utc>>,
}

pub fn ensure_store_path(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .map_err(|e| ConfidISError::internal(format!("failed to create store path: {e}")))
}

#[derive(Debug, Clone, Copy)]
pub struct ShardStoreStats {
    pub used_bytes: u64,
    pub shard_count: u64,
}

pub(crate) struct ShardLocalStatus {
    pub(crate) present: bool,
    pub(crate) valid: bool,
    pub(crate) error: Option<String>,
}

fn collect_stats(path: &Path, used_bytes: &mut u64, shard_count: &mut u64) -> Result<()> {
    for entry in fs::read_dir(path)
        .map_err(|e| ConfidISError::internal(format!("failed to read {}: {e}", path.display())))?
    {
        let entry =
            entry.map_err(|e| ConfidISError::internal(format!("failed to read dir entry: {e}")))?;
        let meta = entry
            .metadata()
            .map_err(|e| ConfidISError::internal(format!("failed to read metadata: {e}")))?;
        if meta.is_dir() {
            collect_stats(&entry.path(), used_bytes, shard_count)?;
        } else if meta.is_file() {
            *used_bytes += meta.len();
            *shard_count += 1;
        }
    }
    Ok(())
}

fn collect_metadata(path: &Path, metadata: &mut Vec<ShardMetadata>) -> Result<()> {
    for entry in fs::read_dir(path)
        .map_err(|e| ConfidISError::internal(format!("failed to read {}: {e}", path.display())))?
    {
        let entry =
            entry.map_err(|e| ConfidISError::internal(format!("failed to read dir entry: {e}")))?;
        let meta = entry
            .metadata()
            .map_err(|e| ConfidISError::internal(format!("failed to read metadata: {e}")))?;
        if meta.is_dir() {
            collect_metadata(&entry.path(), metadata)?;
        } else if meta.is_file() {
            let bytes = fs::read(entry.path())
                .map_err(|e| ConfidISError::internal(format!("failed to read shard metadata: {e}")))?;
            metadata.push(
                serde_json::from_slice(&bytes)
                    .map_err(|e| ConfidISError::validation(format!("invalid shard metadata: {e}")))?,
            );
        }
    }
    Ok(())
}
