use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;
use confidis_protocol::ShardReceipt;

#[derive(Debug, Subcommand)]
pub(crate) enum ReceiptsCommand {
    /// Export local shard receipts to stdout (JSON array or NDJSON) or a file.
    ///
    /// Reads all `{store-path}/receipts/*.json` files produced by the CONFIDIS node
    /// during store, delete and get operations, and writes them as a single JSON
    /// array (default) or newline-delimited JSON (`--ndjson`) for pipeline use.
    ///
    /// Example:
    ///   confidis receipts export --store-path ~/.confidis/store > receipts.json
    ///   confidis receipts export --store-path ~/.confidis/store --ndjson | grep '"Stored"'
    Export {
        /// Path to the CONFIDIS node store directory (must contain a `receipts/` sub-directory).
        #[arg(long, default_value = "~/.confidis/store")]
        store_path: PathBuf,

        /// Write output to a file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Output newline-delimited JSON (one receipt per line) instead of a JSON array.
        #[arg(long)]
        ndjson: bool,

        /// Filter: only include receipts of this type (`Stored`, `Deleted`, `Get`).
        #[arg(long)]
        receipt_type: Option<String>,

        /// Maximum number of receipts to export (default: all).
        #[arg(long)]
        limit: Option<usize>,

        /// Pretty-print JSON output (only applies to JSON array mode, not NDJSON).
        #[arg(long)]
        pretty: bool,
    },
}

pub(crate) fn receipts(cmd: ReceiptsCommand) -> Result<()> {
    match cmd {
        ReceiptsCommand::Export {
            store_path,
            output,
            ndjson,
            receipt_type,
            limit,
            pretty,
        } => receipts_export(store_path, output, ndjson, receipt_type, limit, pretty),
    }
}

fn receipts_export(
    store_path: PathBuf,
    output: Option<PathBuf>,
    ndjson: bool,
    filter_type: Option<String>,
    limit: Option<usize>,
    pretty: bool,
) -> Result<()> {
    // Expand tilde in store_path.
    let store_path = expand_tilde(store_path);
    let receipts_dir = store_path.join("receipts");

    if !receipts_dir.exists() {
        anyhow::bail!(
            "receipts directory not found: {}\n  hint: ensure --store-path points to a running CONFIDIS node's store directory",
            receipts_dir.display()
        );
    }

    let mut receipts: Vec<ShardReceipt> = fs::read_dir(&receipts_dir)
        .with_context(|| {
            format!(
                "failed to read receipts directory: {}",
                receipts_dir.display()
            )
        })?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                return None;
            }
            let bytes = fs::read(&path).ok()?;
            match serde_json::from_slice::<ShardReceipt>(&bytes) {
                Ok(r) => Some(r),
                Err(err) => {
                    eprintln!("⚠  skipping malformed receipt {}: {err}", path.display());
                    None
                }
            }
        })
        .collect();

    // Sort newest-first by issued_at.
    receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt.issued_at));

    // Apply type filter.
    if let Some(ref filter) = filter_type {
        let filter_lower = filter.to_lowercase();
        receipts.retain(|r| format!("{:?}", r.receipt_type).to_lowercase() == filter_lower);
    }

    // Apply limit.
    if let Some(n) = limit {
        receipts.truncate(n);
    }

    eprintln!(
        "✓ exporting {} receipt(s) from {}",
        receipts.len(),
        receipts_dir.display()
    );

    // Produce output bytes.
    let bytes = if ndjson {
        let mut buf = Vec::new();
        for r in &receipts {
            serde_json::to_writer(&mut buf, r).context("failed to serialize receipt")?;
            buf.push(b'\n');
        }
        buf
    } else if pretty {
        serde_json::to_vec_pretty(&receipts).context("failed to serialize receipts")?
    } else {
        serde_json::to_vec(&receipts).context("failed to serialize receipts")?
    };

    // Write to file or stdout.
    match output {
        Some(path) => {
            fs::write(&path, &bytes)
                .with_context(|| format!("failed to write output to {}", path.display()))?;
            eprintln!("✓ written to {}", path.display());
        }
        None => {
            io::stdout()
                .write_all(&bytes)
                .context("failed to write to stdout")?;
            // Ensure a trailing newline for terminal friendliness.
            if !bytes.ends_with(b"\n") {
                println!();
            }
        }
    }

    Ok(())
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return PathBuf::from(home).join(stripped);
    }
    path
}
