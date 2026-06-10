use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use confidis_crypto::signing_key_from_hex;
use confidis_protocol::CelluleId;

use crate::commands::cellule::{manifest_from_segments, read_sealed_cellule_key};
use crate::commands::placement::PlacementUploadOutput;

#[derive(Debug, Subcommand)]
pub(crate) enum ManifestCommand {
    Create {
        #[arg(long)]
        placement: PathBuf,
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        original_len: u64,
        #[arg(long)]
        segment_len: u64,
        #[arg(long)]
        private_key: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Encrypt {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: Option<PathBuf>,
        input: PathBuf,
        output: PathBuf,
    },
    Decrypt {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: Option<PathBuf>,
        input: PathBuf,
        output: PathBuf,
    },
}

pub(crate) fn manifest(command: ManifestCommand) -> Result<()> {
    match command {
        ManifestCommand::Create {
            placement,
            cellule_id,
            original_len,
            segment_len,
            private_key,
            output,
        } => {
            let bytes = fs::read(&placement)
                .with_context(|| format!("failed to read {}", placement.display()))?;
            let upload: PlacementUploadOutput =
                serde_json::from_slice(&bytes).context("invalid placement upload file")?;
            // The `manifest` dev tool consumes a flat placement.json as a
            // single segment (segment 0). Multi-segment manifests are produced
            // by `cellule put` directly.
            let mut manifest = manifest_from_segments(
                &[(0, upload)],
                CelluleId(cellule_id),
                original_len,
                segment_len,
            );
            if let Some(private_key) = private_key {
                let key = signing_key_from_hex(&private_key)?;
                manifest.signature = None;
                let payload =
                    serde_json::to_vec(&manifest).context("failed to serialize manifest")?;
                manifest.signature = Some(confidis_crypto::sign_hex(&key, &payload));
            }
            fs::write(&output, serde_json::to_vec_pretty(&manifest)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        ManifestCommand::Encrypt {
            private_key,
            cellule_key,
            input,
            output,
        } => {
            let plaintext =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let encrypted = if let Some(cellule_key) = cellule_key {
                let key = read_sealed_cellule_key(&private_key, &cellule_key)?;
                confidis_crypto::encrypt_with_cellule_key(&key, &plaintext)?
            } else {
                confidis_crypto::encrypt_manifest_bytes(&private_key, &plaintext)?
            };
            fs::write(&output, encrypted)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        ManifestCommand::Decrypt {
            private_key,
            cellule_key,
            input,
            output,
        } => {
            let encrypted =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let plaintext = if let Some(cellule_key) = cellule_key {
                let key = read_sealed_cellule_key(&private_key, &cellule_key)?;
                confidis_crypto::decrypt_with_cellule_key(&key, &encrypted)?
            } else {
                confidis_crypto::decrypt_manifest_bytes(&private_key, &encrypted)?
            };
            fs::write(&output, plaintext)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
    }
    Ok(())
}
