use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use confidis_error::ConfidISError;

mod commands;
mod network;
mod verify;
#[cfg(any())]
use crate::commands::authority::{AuthorityCommand, authority};
use crate::commands::blob::{BlobCommand, blob};
use crate::commands::cellule::{CelluleCommand, cellule};
use crate::commands::erasure::{ErasureCommand, erasure};
use crate::commands::init_key::init_key;
use crate::commands::manifest::{ManifestCommand, manifest};
use crate::commands::node::{NodeCommand, node};
use crate::commands::placement::{PlacementCommand, placement};
use crate::commands::receipts::{ReceiptsCommand, receipts};
use crate::commands::remote::{RemoteCommand, remote};
use crate::commands::shard::{ShardCommand, shard};
use crate::commands::up::up;
use crate::commands::wallet::{WalletCommand, wallet};
use crate::network::{NETWORK_CONFIG, NetworkConfig};

#[derive(Debug, Parser)]
#[command(name = "confidis")]
#[command(about = "CONFIDIS node-first MVP CLI")]
struct Cli {
    #[arg(long, global = true)]
    trusted_ca: Vec<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start a CONFIDIS OS node with the bundled Web UI in one command.
    /// First run writes a localhost config + identity under ~/.confidis; later
    /// Running `confidis` with no subcommand does the same thing.
    Up,
    InitKey,
    #[cfg(any())]
    Authority {
        #[command(subcommand)]
        command: AuthorityCommand,
    },
    Shard {
        #[command(subcommand)]
        command: ShardCommand,
    },
    Erasure {
        #[command(subcommand)]
        command: ErasureCommand,
    },
    #[cfg(any())]
    Ledger {
        #[command(subcommand)]
        command: LedgerCommand,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    Placement {
        #[command(subcommand)]
        command: PlacementCommand,
    },
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    Blob {
        #[command(subcommand)]
        command: BlobCommand,
    },
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
    Cellule {
        #[command(subcommand)]
        command: CelluleCommand,
    },
    /// Export local node shard receipts.
    Receipts {
        #[command(subcommand)]
        command: ReceiptsCommand,
    },
}

/// Print an anyhow error chain to stderr in a structured, user-friendly format,
/// then suggest a remediation hint when the error matches a known pattern.
fn print_error(err: &anyhow::Error) {
    // Print the top-level message.
    eprintln!("✗ error: {err}");

    // Print the cause chain when there is more than one level.
    let mut chain = err.chain().skip(1).peekable();
    if chain.peek().is_some() {
        for cause in chain {
            eprintln!("  cause: {cause}");
        }
    }

    if let Some(code) = find_error_code(err) {
        eprintln!("  code: {code}");
    }

    // Offer a contextual remediation hint based on well-known error patterns.
    let full = format!("{err:#}");
    if full.contains("No such file or directory") || full.contains("cannot find the path") {
        eprintln!("  hint:  check that the file path exists and you have read permission");
    } else if full.contains("Connection refused") || full.contains("error sending request") {
        eprintln!(
            "  hint:  the node may not be running — verify the --node URL and try `node serve`"
        );
    } else if full.contains("authority signer key material is configured") {
        eprintln!(
            "  hint:  bind the authority signer to 127.0.0.1/::1, or set CONFIDIS_ALLOW_AUTHORITY_SIGNER_NETWORK_BIND=1 only inside an isolated signer network"
        );
    } else if full.contains("expected value") || full.contains("trailing comma") {
        eprintln!(
            "  hint:  the config file is not valid JSON — re-run `node init-config` to regenerate"
        );
    } else if full.contains("invalid node config") {
        eprintln!("  hint:  review the config field named in the cause above");
    } else if full.contains("invalid listen") || full.contains("invalid address") {
        eprintln!("  hint:  check listen_addr format: must be host:port (e.g. 127.0.0.1:4433)");
    } else if full.contains("private_key") || full.contains("Ed25519") || full.contains("hex") {
        eprintln!(
            "  hint:  generate a fresh key with `confidis init-key` and pass --private-key <hex>"
        );
    } else if full.contains("permission denied") || full.contains("Permission denied") {
        eprintln!("  hint:  check file and directory permissions");
    } else if full.contains("store_path") || full.contains("not writable") {
        eprintln!("  hint:  ensure store_path exists and is writable by this process");
    } else if full.contains("quota") || full.contains("insufficient") || full.contains("not enough")
    {
        eprintln!("  hint:  review the node quotas, storage limits, and federation agreement");
    } else if full.contains("registry") || full.contains("cellule not found") {
        eprintln!(
            "  hint:  check --registry path and ensure the Cellule ID exists in the registry"
        );
    } else if full.contains("membership") || full.contains("certificate") {
        eprintln!(
            "  hint:  node membership certificates were removed; verify federation peers, node keys, and the authority NodeBanList instead"
        );
    }
}

fn find_error_code(err: &anyhow::Error) -> Option<&'static str> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<ConfidISError>().map(ConfidISError::code))
}

#[tokio::main]
async fn main() {
    // Initialize local tracing for CLI operations.
    let _ = confidis_node::telemetry::init_telemetry("confidis-cli", env!("CARGO_PKG_VERSION"));

    let cli = Cli::parse();
    let _ = NETWORK_CONFIG.set(NetworkConfig {
        trusted_ca: cli.trusted_ca.clone(),
    });
    let result = match cli.command {
        None | Some(Command::Up) => up().await,
        Some(Command::InitKey) => init_key(),
        #[cfg(any())]
        Some(Command::Authority { command }) => authority(command).await,
        Some(Command::Shard { command }) => shard(command),
        Some(Command::Erasure { command }) => erasure(command),
        Some(Command::Node { command }) => node(command).await,
        Some(Command::Remote { command }) => remote(command).await,
        Some(Command::Placement { command }) => placement(command).await,
        Some(Command::Manifest { command }) => manifest(command),
        Some(Command::Blob { command }) => blob(command),
        Some(Command::Wallet { command }) => wallet(command),
        Some(Command::Cellule { command }) => cellule(command).await,
        Some(Command::Receipts { command }) => receipts(command),
    };
    if let Err(err) = result {
        print_error(&err);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_direct_confidis_error_code() {
        let err = anyhow::Error::new(ConfidISError::expired("expired shard"));
        assert_eq!(find_error_code(&err), Some("expired"));
    }

    #[test]
    fn finds_context_wrapped_confidis_error_code() {
        let err = anyhow::Error::new(ConfidISError::forbidden("denied")).context("top level");
        assert_eq!(find_error_code(&err), Some("forbidden"));
    }

    #[test]
    fn returns_none_for_non_confidis_errors() {
        let err = anyhow::anyhow!("plain anyhow error");
        assert_eq!(find_error_code(&err), None);
    }
}
