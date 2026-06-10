use anyhow::Result;
use confidis_crypto::{generate_signing_key, signing_key_to_hex, verifying_key_to_hex};

pub(crate) fn init_key() -> Result<()> {
    let key = generate_signing_key();
    let public = key.verifying_key();
    println!("private_key={}", signing_key_to_hex(&key));
    println!("public_key={}", verifying_key_to_hex(&public));
    Ok(())
}
