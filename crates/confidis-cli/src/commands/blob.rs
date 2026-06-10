use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub(crate) enum BlobCommand {
    Put {
        #[arg(long)]
        store: PathBuf,
        input: PathBuf,
    },
    Get {
        #[arg(long)]
        store: PathBuf,
        cid: String,
        output: PathBuf,
    },
}

pub(crate) fn blob(command: BlobCommand) -> Result<()> {
    match command {
        BlobCommand::Put { store, input } => {
            let bytes =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            let cid = confidis_crypto::blake3_hex(&bytes);
            write_blob(&store, &cid, &bytes)?;
            println!("{cid}");
        }
        BlobCommand::Get { store, cid, output } => {
            let bytes = read_blob(&store, &cid)?;
            let actual = confidis_crypto::blake3_hex(&bytes);
            if actual != cid {
                bail!("blob hash mismatch: expected {cid}, got {actual}");
            }
            fs::write(&output, bytes)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
    }
    Ok(())
}

pub(crate) fn write_blob(store: &Path, cid: &str, bytes: &[u8]) -> Result<()> {
    let path = blob_path(store, cid);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

pub(crate) fn read_blob(store: &Path, cid: &str) -> Result<Vec<u8>> {
    fs::read(blob_path(store, cid)).with_context(|| format!("failed to read blob {cid}"))
}

pub(crate) fn delete_blob(store: &Path, cid: &str) -> Result<bool> {
    let path = blob_path(store, cid);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to delete blob {cid}"))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) fn blob_path(store: &Path, cid: &str) -> PathBuf {
    let prefix = cid.get(0..2).unwrap_or("xx");
    store.join(prefix).join(cid)
}
