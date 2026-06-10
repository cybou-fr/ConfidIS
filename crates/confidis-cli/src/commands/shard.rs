use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use confidis_crypto::{signing_key_from_hex, verifying_key_to_hex};
use confidis_node::ShardStore;
use confidis_protocol::{ErasurePolicy, NodeId, ShardId};

use crate::commands::cellule::delete_authority_hash;

#[derive(Debug, Subcommand)]
pub(crate) enum ShardCommand {
    Put {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        private_key: Option<String>,
        file: PathBuf,
    },
    Get {
        #[arg(long)]
        store: PathBuf,
        shard_id: String,
        output: PathBuf,
    },
    Delete {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        private_key: Option<String>,
        shard_id: String,
    },
    Status {
        #[arg(long)]
        store: PathBuf,
        shard_id: String,
    },
}

pub(crate) fn shard(command: ShardCommand) -> Result<()> {
    match command {
        ShardCommand::Put {
            store,
            node_id,
            private_key,
            file,
        } => {
            let bytes =
                fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
            let store = ShardStore::open(store)?;
            let key = private_key
                .as_deref()
                .map(signing_key_from_hex)
                .transpose()?;
            let delete_authority_hash = key
                .as_ref()
                .map(|key| delete_authority_hash(&verifying_key_to_hex(&key.verifying_key())))
                .unwrap_or_else(|| delete_authority_hash(&node_id));
            let receipt = store.put(
                NodeId(node_id),
                &bytes,
                None,
                delete_authority_hash,
                key.as_ref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        ShardCommand::Get {
            store,
            shard_id,
            output,
        } => {
            let store = ShardStore::open(store)?;
            let bytes = store.get(&ShardId(shard_id))?;
            fs::write(&output, bytes)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        ShardCommand::Delete {
            store,
            node_id,
            private_key,
            shard_id,
        } => {
            let store = ShardStore::open(store)?;
            let key = private_key
                .as_deref()
                .map(signing_key_from_hex)
                .transpose()?;
            let signer_public_key = key
                .as_ref()
                .map(|key| verifying_key_to_hex(&key.verifying_key()))
                .unwrap_or_else(|| node_id.clone());
            let receipt = store.delete(
                NodeId(node_id),
                &ShardId(shard_id),
                &signer_public_key,
                key.as_ref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        ShardCommand::Status { store, shard_id } => {
            let store = ShardStore::open(store)?;
            println!(
                "{}",
                if store.exists(&ShardId(shard_id)) {
                    "present"
                } else {
                    "missing"
                }
            );
        }
    }
    Ok(())
}

pub(crate) fn read_shard_ids(
    group_id: Option<String>,
    shard_dir: &Path,
) -> Result<(String, Vec<ShardId>)> {
    let policy = ErasurePolicy::default();
    let mut ids = Vec::with_capacity(policy.total_shards());
    let mut group_hasher = blake3::Hasher::new();
    for index in 0..policy.total_shards() {
        let path = shard_dir.join(format!("shard-{index:02}.bin"));
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        let id = confidis_crypto::blake3_hex(&bytes);
        group_hasher.update(id.as_bytes());
        ids.push(ShardId(id));
    }
    let group_id = group_id.unwrap_or_else(|| group_hasher.finalize().to_hex().to_string());
    Ok((group_id, ids))
}
