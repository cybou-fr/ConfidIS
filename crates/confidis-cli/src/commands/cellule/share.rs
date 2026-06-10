use anyhow::{Context, Result, bail};
use base64::Engine;
use bip39::Mnemonic;
use serde::{Deserialize, Serialize};

use super::helpers::{read_registry, read_sealed_cellule_key};
use super::types::{CelluleShareArgs, CelluleShareOutput};

/// Legacy access bundle embedded in the share URL fragment.
/// It contains the raw Cellule key and is therefore disabled for normal UX.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessBundle {
    pub v: u8,
    pub cid: String,
    pub k: String,
    pub nodes: Vec<String>,
}

pub(super) fn cellule_share(args: CelluleShareArgs) -> Result<CelluleShareOutput> {
    if !args.allow_raw_key_export {
        bail!(
            "raw Cellule-key sharing is disabled by default. Use the wallet shared-copy flow or recipient-package tooling to create a scoped recipient-encrypted access package; pass --allow-raw-key-export only for legacy/dev recovery flows."
        );
    }

    let records = read_registry(&args.registry)?;
    let record = records
        .into_iter()
        .find(|r| r.cellule_id.0 == args.cellule_id)
        .context("Cellule not found in registry")?;

    let now = chrono::Utc::now();
    if record.deletion_due_at(now) {
        bail!(
            "Cellule expired at {}; sharing an expired Cellule is not permitted",
            record.expires_at.to_rfc3339()
        );
    }

    let cellule_key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;

    // BIP39: 32 bytes of entropy → 24 English words
    let mnemonic = Mnemonic::from_entropy(&cellule_key)
        .context("failed to encode cellule key as BIP39 mnemonic")?;
    let mnemonic_phrase = mnemonic.to_string();

    let bundle = AccessBundle {
        v: 1,
        cid: record.cellule_id.0.clone(),
        k: hex::encode(cellule_key),
        nodes: args.nodes,
    };
    let bundle_json = serde_json::to_string(&bundle)?;
    let bundle_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bundle_json.as_bytes());

    let base_url = args
        .base_url
        .unwrap_or_else(|| "https://confidis.fr/access".to_string());
    let access_url = format!("{}#{}", base_url, bundle_b64);

    Ok(CelluleShareOutput {
        cellule_id: args.cellule_id,
        expires_at: record.expires_at.to_rfc3339(),
        mnemonic: mnemonic_phrase,
        access_url: access_url.clone(),
        qr_data: access_url,
        access_bundle_base64: bundle_b64,
    })
}
