use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use confidis_erasure::{encode_segment, reconstruct_segment};
use confidis_protocol::ErasurePolicy;

#[derive(Debug, Subcommand)]
pub(crate) enum ErasureCommand {
    Encode {
        input: PathBuf,
        output_dir: PathBuf,
    },
    Decode {
        #[arg(long)]
        original_len: usize,
        #[arg(long)]
        output: PathBuf,
        shard_files: Vec<PathBuf>,
    },
}

pub(crate) fn erasure(command: ErasureCommand) -> Result<()> {
    match command {
        ErasureCommand::Encode { input, output_dir } => {
            let bytes =
                fs::read(&input).with_context(|| format!("failed to read {}", input.display()))?;
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("failed to create {}", output_dir.display()))?;
            let policy = ErasurePolicy::default();
            let encoded = encode_segment(&bytes, &policy)?;
            for (index, shard) in encoded.shards.iter().enumerate() {
                let path = output_dir.join(format!("shard-{index:02}.bin"));
                fs::write(path, shard).context("failed to write shard")?;
            }
            println!(
                "encoded {} bytes into {} shards ({}+{}, shard_len={})",
                encoded.original_len,
                encoded.shards.len(),
                encoded.policy.data_shards,
                encoded.policy.parity_shards,
                encoded.shard_len
            );
        }
        ErasureCommand::Decode {
            original_len,
            output,
            shard_files,
        } => {
            let policy = ErasurePolicy::default();
            let mut shards = vec![None; policy.total_shards()];
            if shard_files.len() < policy.data_shards {
                bail!("need at least {} shards", policy.data_shards);
            }

            for file in shard_files {
                let name = file
                    .file_name()
                    .and_then(|value| value.to_str())
                    .context("invalid shard file name")?;
                let index = parse_shard_index(name)?;
                if index >= policy.total_shards() {
                    bail!("shard index {index} outside policy");
                }
                shards[index] = Some(
                    fs::read(&file)
                        .with_context(|| format!("failed to read {}", file.display()))?,
                );
            }

            let restored = reconstruct_segment(&policy, original_len, shards)?;
            fs::write(&output, restored)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
    }
    Ok(())
}

fn parse_shard_index(name: &str) -> Result<usize> {
    let raw = name
        .strip_prefix("shard-")
        .and_then(|value| value.strip_suffix(".bin"))
        .context("expected shard file named shard-XX.bin")?;
    raw.parse().context("invalid shard index")
}
