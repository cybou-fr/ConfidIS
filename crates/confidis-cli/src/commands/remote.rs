use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use confidis_protocol::{ShardId, ShardReceiptType};

use crate::commands::cellule::{
    create_delete_request, delete_authority_hash_from_private_key, validated_expires_at,
};
use crate::network::{network_client, print_response};
use crate::verify::parse_and_verify_receipt;

#[derive(Debug, Subcommand)]
pub(crate) enum RemoteCommand {
    Put {
        #[arg(long)]
        node: String,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        expires_at: String,
        file: PathBuf,
    },
    Get {
        #[arg(long)]
        node: String,
        shard_id: String,
        /// Node Ed25519 private key (hex) for the signed shard-access proof.
        /// Optional in development; required when the target node runs
        /// `production_profile`.
        #[arg(long)]
        private_key: Option<String>,
        output: PathBuf,
    },
    Delete {
        #[arg(long)]
        node: String,
        #[arg(long)]
        private_key: String,
        shard_id: String,
    },
    Status {
        #[arg(long)]
        node: String,
        shard_id: String,
    },
    Capacity {
        #[arg(long)]
        node: String,
    },
    Peers {
        #[arg(long)]
        node: String,
    },
}

pub(crate) async fn remote(command: RemoteCommand) -> Result<()> {
    let client = network_client()?;
    match command {
        RemoteCommand::Put {
            node,
            private_key,
            expires_at,
            file,
        } => {
            let bytes =
                fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
            let shard_id = confidis_crypto::blake3_hex(&bytes);
            let url = format!("{}/shards/{}", node.trim_end_matches('/'), shard_id);
            let proof = crate::network::node_access_proof_headers(&private_key, "PUT", &shard_id)?;
            let mut req = client
                .put(url)
                .header(
                    "x-confidis-delete-authority-hash",
                    delete_authority_hash_from_private_key(&private_key)?,
                )
                .header("x-confidis-expires-at", validated_expires_at(&expires_at)?);
            for (k, v) in &proof {
                req = req.header(*k, v);
            }
            let response = req.body(bytes).send().await?;
            let status = response.status();
            let text = response.text().await?;
            if !status.is_success() {
                bail!("remote put failed: {status} {text}");
            }
            let receipt = parse_and_verify_receipt(
                &text,
                &ShardId(shard_id),
                ShardReceiptType::Stored,
                None,
                None,
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        RemoteCommand::Get {
            node,
            shard_id,
            private_key,
            output,
        } => {
            let url = format!("{}/shards/{}", node.trim_end_matches('/'), shard_id);
            let mut req = client.get(url);
            if let Some(pk) = private_key.as_deref() {
                for (k, v) in &crate::network::node_access_proof_headers(pk, "GET", &shard_id)? {
                    req = req.header(*k, v);
                }
            }
            let response = req.send().await?;
            let status = response.status();
            let bytes = response.bytes().await?;
            if !status.is_success() {
                bail!(
                    "remote get failed: {status} {}",
                    String::from_utf8_lossy(&bytes)
                );
            }
            fs::write(&output, bytes)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        RemoteCommand::Delete {
            node,
            private_key,
            shard_id,
        } => {
            let url = format!("{}/shards/{}", node.trim_end_matches('/'), shard_id);
            let request = create_delete_request(ShardId(shard_id), &private_key)?;
            let response = client.delete(url).json(&request).send().await?;
            let status = response.status();
            let text = response.text().await?;
            if !status.is_success() {
                bail!("remote delete failed: {status} {text}");
            }
            let receipt = parse_and_verify_receipt(
                &text,
                &request.shard_id,
                ShardReceiptType::Deleted,
                None,
                None,
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        RemoteCommand::Status { node, shard_id } => {
            let url = format!("{}/shards/{}/status", node.trim_end_matches('/'), shard_id);
            print_response(client.get(url).send().await?).await?;
        }
        RemoteCommand::Capacity { node } => {
            let url = format!("{}/capacity", node.trim_end_matches('/'));
            print_response(client.get(url).send().await?).await?;
        }
        RemoteCommand::Peers { node } => {
            let url = format!("{}/peers", node.trim_end_matches('/'));
            print_response(client.get(url).send().await?).await?;
        }
    }
    Ok(())
}
