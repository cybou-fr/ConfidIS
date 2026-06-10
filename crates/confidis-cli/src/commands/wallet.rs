use anyhow::Result;
use clap::Subcommand;
use confidis_crypto::{generate_signing_key, signing_key_to_hex, verifying_key_to_hex};
use confidis_protocol::WalletAddress;

#[derive(Debug, Subcommand)]
pub(crate) enum WalletCommand {
    Create,
    Address {
        #[arg(long)]
        public_key: String,
    },
}

pub(crate) fn wallet(command: WalletCommand) -> Result<()> {
    match command {
        WalletCommand::Create => {
            let key = generate_signing_key();
            let public_key = verifying_key_to_hex(&key.verifying_key());
            let address = wallet_address_from_public_key(&public_key)?;
            println!("private_key={}", signing_key_to_hex(&key));
            println!("public_key={public_key}");
            println!("wallet_address={}", address.0);
        }
        WalletCommand::Address { public_key } => {
            println!("{}", wallet_address_from_public_key(&public_key)?.0);
        }
    }
    Ok(())
}

fn wallet_address_from_public_key(public_key: &str) -> Result<WalletAddress> {
    confidis_crypto::verifying_key_from_hex(public_key)?;
    Ok(WalletAddress(confidis_crypto::blake3_hex(
        public_key.as_bytes(),
    )))
}
