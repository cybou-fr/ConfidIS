use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use confidis_error::{ConfidISError, Result};
use confidis_protocol::{NodeId, ShardId, ShardReceipt};
use ed25519_dalek::SigningKey;

fn lock_poisoned() -> ConfidISError {
    ConfidISError::internal("memory storage lock poisoned")
}

/// Abstract storage backend trait for pluggable storage implementations.
/// Supports both filesystem and in-memory backends for testing and production use.
pub trait StorageBackend: Send + Sync + std::fmt::Debug {
    /// Store a shard with associated metadata and create a receipt.
    fn put(
        &self,
        node_id: NodeId,
        bytes: &[u8],
        expires_at: Option<DateTime<Utc>>,
        delete_authority_hash: String,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt>;

    /// Retrieve a shard by its ID.
    fn get(&self, shard_id: &ShardId) -> Result<Vec<u8>>;

    /// Delete a shard with authorization check.
    fn delete(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signer_public_key: &str,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt>;

    /// Delete expired shards.
    fn delete_expired(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>>;

    /// Find shards expiring soon (within the given duration).
    fn expiring_soon(
        &self,
        now: DateTime<Utc>,
        within: chrono::Duration,
    ) -> Result<Vec<(ShardId, DateTime<Utc>)>>;

    /// Check integrity of all stored shards.
    fn check_integrity(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>>;

    /// Check if a shard exists.
    fn exists(&self, shard_id: &ShardId) -> Result<bool>;

    /// Get detailed status of a shard.
    fn status(&self, shard_id: &ShardId) -> Result<ShardLocalStatus>;

    /// Get storage statistics.
    fn stats(&self) -> Result<ShardStoreStats>;

    /// Read all receipts.
    fn read_all_receipts(&self) -> Result<Vec<ShardReceipt>>;

    fn read_all_metadata(&self) -> Result<Vec<StorageShardMetadata>>;

    fn delete_unchecked(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signing_key: Option<&SigningKey>,
        remove_metadata: bool,
    ) -> Result<ShardReceipt>;

    /// Health check for the storage backend.
    fn health_check(&self) -> Result<StorageHealth>;
}

#[derive(Debug, Clone)]
pub struct StorageShardMetadata {
    pub shard_id: ShardId,
    pub delete_authority_hash: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Storage health status.
#[derive(Debug, Clone)]
pub struct StorageHealth {
    pub healthy: bool,
    pub message: String,
    pub details: HashMap<String, String>,
}

/// Local status of a shard in storage.
#[derive(Debug, Clone)]
pub struct ShardLocalStatus {
    pub present: bool,
    pub valid: bool,
    pub error: Option<String>,
}

/// Storage statistics.
#[derive(Debug, Clone, Copy)]
pub struct ShardStoreStats {
    pub used_bytes: u64,
    pub shard_count: u64,
}

/// Configuration for storage backends.
#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// Filesystem-based storage.
    Filesystem { root_path: PathBuf },
    /// In-memory storage for testing.
    Memory,
    /// S3-compatible object storage.
    S3 {
        bucket: String,
        region: String,
        access_key: String,
        secret_key: String,
        endpoint: Option<String>,
    },
}

/// Factory for creating storage backends.
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend from configuration.
    pub fn create(config: StorageConfig) -> Result<Arc<dyn StorageBackend>> {
        match config {
            StorageConfig::Filesystem { root_path } => {
                let backend = FilesystemStorage::new(root_path)?;
                Ok(Arc::new(backend))
            }
            StorageConfig::Memory => {
                let backend = MemoryStorage::new();
                Ok(Arc::new(backend))
            }
            StorageConfig::S3 { .. } => Err(ConfidISError::internal(
                "S3 storage backend not yet implemented",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_backend_is_explicitly_not_implemented() {
        let err = StorageFactory::create(StorageConfig::S3 {
            bucket: "confidis-test".to_string(),
            region: "eu-west-3".to_string(),
            access_key: "access".to_string(),
            secret_key: "secret".to_string(),
            endpoint: Some("https://s3.example.test".to_string()),
        })
        .expect_err("S3 backend must fail until implemented and tested");

        assert_eq!(err.code(), "internal_error");
        assert!(
            err.to_string()
                .contains("S3 storage backend not yet implemented")
        );
    }
}

/// Run a synchronous storage backend operation on Tokio's blocking pool.
pub(crate) async fn run_storage_task<T, F>(
    state: &Arc<crate::state::NodeState>,
    operation: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Arc<dyn StorageBackend>) -> Result<T> + Send + 'static,
{
    let store = Arc::clone(&state.store);
    tokio::task::spawn_blocking(move || operation(store))
        .await
        .map_err(|err| ConfidISError::internal(format!("storage task failed: {err}")))?
}

/// Filesystem-based storage backend implementation.
#[derive(Debug)]
pub struct FilesystemStorage {
    inner: crate::store::ShardStore,
}

impl FilesystemStorage {
    pub fn new(root_path: PathBuf) -> Result<Self> {
        let store = crate::store::ShardStore::open(root_path)?;
        Ok(Self { inner: store })
    }
}

impl StorageBackend for FilesystemStorage {
    fn put(
        &self,
        node_id: NodeId,
        bytes: &[u8],
        expires_at: Option<DateTime<Utc>>,
        delete_authority_hash: String,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt> {
        self.inner.put(
            node_id,
            bytes,
            expires_at,
            delete_authority_hash,
            signing_key,
        )
    }

    fn get(&self, shard_id: &ShardId) -> Result<Vec<u8>> {
        self.inner.get(shard_id)
    }

    fn delete(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signer_public_key: &str,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt> {
        self.inner
            .delete(node_id, shard_id, signer_public_key, signing_key)
    }

    fn delete_expired(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>> {
        self.inner.delete_expired(node_id, now, signing_key)
    }

    fn expiring_soon(
        &self,
        now: DateTime<Utc>,
        within: chrono::Duration,
    ) -> Result<Vec<(ShardId, DateTime<Utc>)>> {
        self.inner.expiring_soon(now, within)
    }

    fn check_integrity(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>> {
        self.inner.check_integrity(node_id, now, signing_key)
    }

    fn exists(&self, shard_id: &ShardId) -> Result<bool> {
        Ok(self.inner.exists(shard_id))
    }

    fn status(&self, shard_id: &ShardId) -> Result<ShardLocalStatus> {
        let status = self.inner.status(shard_id);
        Ok(ShardLocalStatus {
            present: status.present,
            valid: status.valid,
            error: status.error,
        })
    }

    fn stats(&self) -> Result<ShardStoreStats> {
        let stats = self.inner.stats()?;
        Ok(ShardStoreStats {
            used_bytes: stats.used_bytes,
            shard_count: stats.shard_count,
        })
    }

    fn read_all_receipts(&self) -> Result<Vec<ShardReceipt>> {
        self.inner.read_all_receipts()
    }

    fn read_all_metadata(&self) -> Result<Vec<StorageShardMetadata>> {
        let items = self
            .inner
            .read_all_metadata()?
            .into_iter()
            .map(|m| StorageShardMetadata {
                shard_id: m.shard_id,
                delete_authority_hash: m.delete_authority_hash,
                expires_at: m.expires_at,
            })
            .collect();
        Ok(items)
    }

    fn delete_unchecked(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signing_key: Option<&SigningKey>,
        remove_metadata: bool,
    ) -> Result<ShardReceipt> {
        self.inner
            .delete_unchecked(node_id, shard_id, signing_key, remove_metadata)
    }

    fn health_check(&self) -> Result<StorageHealth> {
        // Basic health check - try to get stats
        match self.inner.stats() {
            Ok(stats) => Ok(StorageHealth {
                healthy: true,
                message: "Filesystem storage is healthy".to_string(),
                details: HashMap::from([
                    ("used_bytes".to_string(), stats.used_bytes.to_string()),
                    ("shard_count".to_string(), stats.shard_count.to_string()),
                ]),
            }),
            Err(e) => Ok(StorageHealth {
                healthy: false,
                message: format!("Filesystem storage health check failed: {}", e),
                details: HashMap::new(),
            }),
        }
    }
}

/// In-memory storage backend for testing.
#[derive(Debug)]
pub struct MemoryStorage {
    shards: RwLock<HashMap<String, Vec<u8>>>,
    metadata: RwLock<HashMap<String, ShardMetadata>>,
    receipts: RwLock<Vec<ShardReceipt>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            shards: RwLock::new(HashMap::new()),
            metadata: RwLock::new(HashMap::new()),
            receipts: RwLock::new(Vec::new()),
        }
    }
}

impl StorageBackend for MemoryStorage {
    fn put(
        &self,
        node_id: NodeId,
        bytes: &[u8],
        expires_at: Option<DateTime<Utc>>,
        delete_authority_hash: String,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt> {
        use confidis_crypto::{blake3_hex, sign_hex, verifying_key_to_hex};
        use confidis_protocol::{ShardReceiptType, shard_receipt_signing_payload};
        use uuid::Uuid;

        let shard_id = ShardId(blake3_hex(bytes));

        // Store the shard
        self.shards
            .write()
            .map_err(|_| lock_poisoned())?
            .insert(shard_id.0.clone(), bytes.to_vec());

        // Store metadata
        let metadata = ShardMetadata {
            _version: 1,
            _shard_id: shard_id.clone(),
            delete_authority_hash,
            expires_at,
        };
        self.metadata
            .write()
            .map_err(|_| lock_poisoned())?
            .insert(shard_id.0.clone(), metadata);

        // Create receipt
        let mut receipt = ShardReceipt {
            version: 1,
            receipt_id: Uuid::new_v4(),
            receipt_type: ShardReceiptType::Stored,
            node_id,
            public_key: None,
            shard_id,
            issued_at: Utc::now(),
            size_bytes: bytes.len() as u64,
            expires_at,
            signature: None,
        };

        // Sign receipt if signing key provided
        if let Some(signing_key) = signing_key {
            receipt.signature = None;
            receipt.public_key = Some(verifying_key_to_hex(&signing_key.verifying_key()));
            let payload = shard_receipt_signing_payload(&receipt)
                .map_err(|e| ConfidISError::internal(e.to_string()))?;
            receipt.signature = Some(sign_hex(signing_key, &payload));
        }

        // Store receipt
        self.receipts
            .write()
            .map_err(|_| lock_poisoned())?
            .push(receipt.clone());

        Ok(receipt)
    }

    fn get(&self, shard_id: &ShardId) -> Result<Vec<u8>> {
        // Check expiry
        if let Some(metadata) = self
            .metadata
            .read()
            .map_err(|_| lock_poisoned())?
            .get(&shard_id.0)
            && let Some(expires_at) = metadata.expires_at
            && Utc::now() >= expires_at
        {
            return Err(ConfidISError::expired(format!(
                "shard {} expired at {}",
                shard_id.0, expires_at
            )));
        }

        // Return shard data
        self.shards
            .read()
            .map_err(|_| lock_poisoned())?
            .get(&shard_id.0)
            .cloned()
            .ok_or_else(|| ConfidISError::not_found(format!("shard {} not found", shard_id.0)))
    }

    fn delete(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signer_public_key: &str,
        signing_key: Option<&SigningKey>,
    ) -> Result<ShardReceipt> {
        // Verify delete authority
        if let Some(metadata) = self
            .metadata
            .read()
            .map_err(|_| lock_poisoned())?
            .get(&shard_id.0)
        {
            let signer_hash = confidis_crypto::blake3_hex(signer_public_key.as_bytes());
            if signer_hash != metadata.delete_authority_hash {
                return Err(ConfidISError::forbidden(format!(
                    "delete signer is not authorized for shard {}",
                    shard_id.0
                )));
            }
        }

        self.delete_unchecked(node_id, shard_id, signing_key, false)
    }

    fn delete_expired(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>> {
        let metadata = self.metadata.read().map_err(|_| lock_poisoned())?;
        let shards = self.shards.read().map_err(|_| lock_poisoned())?;
        let expired_shards: Vec<ShardId> = metadata
            .iter()
            .filter_map(|(id, item)| match item.expires_at {
                Some(expires_at) if now >= expires_at && shards.contains_key(id) => {
                    Some(ShardId(id.clone()))
                }
                _ => None,
            })
            .collect();
        drop(shards);
        drop(metadata);

        let mut receipts = Vec::new();
        for shard_id in expired_shards {
            receipts.push(self.delete_unchecked(node_id.clone(), &shard_id, signing_key, false)?);
        }

        Ok(receipts)
    }

    fn expiring_soon(
        &self,
        now: DateTime<Utc>,
        within: chrono::Duration,
    ) -> Result<Vec<(ShardId, DateTime<Utc>)>> {
        let threshold = now + within;
        let mut result = Vec::new();

        for (shard_id, metadata) in self.metadata.read().map_err(|_| lock_poisoned())?.iter() {
            if let Some(expires_at) = metadata.expires_at
                && expires_at > now
                && expires_at <= threshold
            {
                result.push((ShardId(shard_id.clone()), expires_at));
            }
        }

        Ok(result)
    }

    fn check_integrity(
        &self,
        node_id: NodeId,
        now: DateTime<Utc>,
        signing_key: Option<&SigningKey>,
    ) -> Result<Vec<ShardReceipt>> {
        use confidis_crypto::{blake3_hex, sign_hex, verifying_key_to_hex};
        use confidis_protocol::{ShardReceiptType, shard_receipt_signing_payload};
        use uuid::Uuid;

        let mut receipts = Vec::new();

        let metadata = self.metadata.read().map_err(|_| lock_poisoned())?;
        let mut receipts_to_add = Vec::new();
        for (shard_key, metadata) in metadata.iter() {
            let shard_id = ShardId(shard_key.clone());
            // Skip expired shards
            if let Some(expires_at) = metadata.expires_at
                && now >= expires_at
            {
                continue;
            }

            // Check if shard exists
            let shards = self.shards.read().map_err(|_| lock_poisoned())?;
            let Some(bytes) = shards.get(shard_key) else {
                continue;
            };

            // Verify hash
            let actual = blake3_hex(bytes);
            if actual != shard_id.0 {
                return Err(ConfidISError::validation(format!(
                    "shard hash mismatch: expected {}, got {}",
                    shard_id.0, actual
                )));
            }

            // Create integrity receipt
            let mut receipt = ShardReceipt {
                version: 1,
                receipt_id: Uuid::new_v4(),
                receipt_type: ShardReceiptType::IntegrityChecked,
                node_id: node_id.clone(),
                public_key: None,
                shard_id: shard_id.clone(),
                issued_at: Utc::now(),
                size_bytes: bytes.len() as u64,
                expires_at: metadata.expires_at,
                signature: None,
            };

            // Sign receipt if signing key provided
            if let Some(signing_key) = signing_key {
                receipt.signature = None;
                receipt.public_key = Some(verifying_key_to_hex(&signing_key.verifying_key()));
                let payload = shard_receipt_signing_payload(&receipt)
                    .map_err(|e| ConfidISError::internal(e.to_string()))?;
                receipt.signature = Some(sign_hex(signing_key, &payload));
            }

            receipts.push(receipt.clone());
            receipts_to_add.push(receipt);
        }
        drop(metadata);
        self.receipts
            .write()
            .map_err(|_| lock_poisoned())?
            .extend(receipts_to_add);

        Ok(receipts)
    }

    fn exists(&self, shard_id: &ShardId) -> Result<bool> {
        Ok(self
            .shards
            .read()
            .map_err(|_| lock_poisoned())?
            .contains_key(&shard_id.0))
    }

    fn status(&self, shard_id: &ShardId) -> Result<ShardLocalStatus> {
        // Check metadata first
        let metadata = self
            .metadata
            .read()
            .map_err(|_| lock_poisoned())?
            .get(&shard_id.0)
            .cloned();
        let Some(metadata) = metadata else {
            return Ok(ShardLocalStatus {
                present: false,
                valid: false,
                error: Some("metadata unavailable".to_string()),
            });
        };
        if let Some(expires_at) = metadata.expires_at
            && Utc::now() >= expires_at
        {
            return Ok(ShardLocalStatus {
                present: false,
                valid: false,
                error: Some(format!("shard expired at {expires_at}")),
            });
        }

        // Check if shard exists
        if !self
            .shards
            .read()
            .map_err(|_| lock_poisoned())?
            .contains_key(&shard_id.0)
        {
            return Ok(ShardLocalStatus {
                present: false,
                valid: false,
                error: None,
            });
        }

        // Verify integrity
        if let Some(bytes) = self
            .shards
            .read()
            .map_err(|_| lock_poisoned())?
            .get(&shard_id.0)
        {
            let actual = confidis_crypto::blake3_hex(bytes);
            if actual == shard_id.0 {
                Ok(ShardLocalStatus {
                    present: true,
                    valid: true,
                    error: None,
                })
            } else {
                Ok(ShardLocalStatus {
                    present: false,
                    valid: false,
                    error: Some(format!(
                        "shard hash mismatch: expected {}, got {}",
                        shard_id.0, actual
                    )),
                })
            }
        } else {
            Ok(ShardLocalStatus {
                present: false,
                valid: false,
                error: Some("failed to read shard".to_string()),
            })
        }
    }

    fn stats(&self) -> Result<ShardStoreStats> {
        let shards = self.shards.read().map_err(|_| lock_poisoned())?;
        let used_bytes = shards.values().map(|bytes| bytes.len() as u64).sum();
        let shard_count = shards.len() as u64;

        Ok(ShardStoreStats {
            used_bytes,
            shard_count,
        })
    }

    fn read_all_receipts(&self) -> Result<Vec<ShardReceipt>> {
        let mut receipts = self.receipts.read().map_err(|_| lock_poisoned())?.clone();
        receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt.issued_at));
        Ok(receipts)
    }

    fn read_all_metadata(&self) -> Result<Vec<StorageShardMetadata>> {
        let items = self
            .metadata
            .read()
            .map_err(|_| lock_poisoned())?
            .iter()
            .map(|(id, m)| StorageShardMetadata {
                shard_id: ShardId(id.clone()),
                delete_authority_hash: m.delete_authority_hash.clone(),
                expires_at: m.expires_at,
            })
            .collect();
        Ok(items)
    }

    fn delete_unchecked(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signing_key: Option<&SigningKey>,
        remove_metadata: bool,
    ) -> Result<ShardReceipt> {
        self.delete_unchecked_impl(node_id, shard_id, signing_key, remove_metadata)
    }

    fn health_check(&self) -> Result<StorageHealth> {
        Ok(StorageHealth {
            healthy: true,
            message: "Memory storage is always healthy".to_string(),
            details: HashMap::new(),
        })
    }
}

impl MemoryStorage {
    fn delete_unchecked_impl(
        &self,
        node_id: NodeId,
        shard_id: &ShardId,
        signing_key: Option<&SigningKey>,
        remove_metadata: bool,
    ) -> Result<ShardReceipt> {
        use confidis_crypto::{sign_hex, verifying_key_to_hex};
        use confidis_protocol::{ShardReceiptType, shard_receipt_signing_payload};
        use uuid::Uuid;

        // Get metadata for expiry info
        let expires_at = self
            .metadata
            .read()
            .map_err(|_| lock_poisoned())?
            .get(&shard_id.0)
            .and_then(|metadata| metadata.expires_at);

        // Get size
        let size = self
            .shards
            .read()
            .map_err(|_| lock_poisoned())?
            .get(&shard_id.0)
            .map(|bytes| bytes.len() as u64)
            .unwrap_or(0);

        // Remove shard and metadata
        self.shards
            .write()
            .map_err(|_| lock_poisoned())?
            .remove(&shard_id.0);
        if remove_metadata {
            self.metadata
                .write()
                .map_err(|_| lock_poisoned())?
                .remove(&shard_id.0);
        }

        // Create receipt
        let mut receipt = ShardReceipt {
            version: 1,
            receipt_id: Uuid::new_v4(),
            receipt_type: ShardReceiptType::Deleted,
            node_id,
            public_key: None,
            shard_id: shard_id.clone(),
            issued_at: Utc::now(),
            size_bytes: size,
            expires_at,
            signature: None,
        };

        // Sign receipt if signing key provided
        if let Some(signing_key) = signing_key {
            receipt.signature = None;
            receipt.public_key = Some(verifying_key_to_hex(&signing_key.verifying_key()));
            let payload = shard_receipt_signing_payload(&receipt)
                .map_err(|e| ConfidISError::internal(e.to_string()))?;
            receipt.signature = Some(sign_hex(signing_key, &payload));
        }

        // Store receipt
        self.receipts
            .write()
            .map_err(|_| lock_poisoned())?
            .push(receipt.clone());

        Ok(receipt)
    }
}

#[derive(Debug, Clone)]
struct ShardMetadata {
    _version: u16,
    _shard_id: ShardId,
    delete_authority_hash: String,
    expires_at: Option<DateTime<Utc>>,
}
