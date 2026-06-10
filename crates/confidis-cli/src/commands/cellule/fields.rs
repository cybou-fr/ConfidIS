use std::fs;

use anyhow::{Context, Result, bail};
use confidis_protocol::{
    CelluleFieldAccessEnvelope, CelluleFieldAccessPackage, CelluleFieldContainer,
    CelluleFieldEnvelope, CelluleId, cellule_field_access_package_signing_payload,
    cellule_field_container_signing_payload,
};
use serde::Deserialize;
use uuid::Uuid;

use super::helpers::read_sealed_cellule_key;
use super::types::{
    CelluleFieldsExportArgs, CelluleFieldsExportOutput, CelluleFieldsOpenArgs,
    CelluleFieldsOpenOutput, CelluleFieldsRecipientOpenArgs, CelluleFieldsRecipientOpenOutput,
    CelluleFieldsSealArgs, CelluleFieldsSealOutput,
};

pub(super) fn cellule_fields_seal(args: CelluleFieldsSealArgs) -> Result<CelluleFieldsSealOutput> {
    let input = fs::read(&args.input)
        .with_context(|| format!("failed to read {}", args.input.display()))?;
    let fields: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&input).context("field input must be a JSON object")?;
    if fields.is_empty() {
        bail!("field input must contain at least one field");
    }

    let cellule_key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;
    let now = chrono::Utc::now();
    let mut envelopes = Vec::with_capacity(fields.len());
    for (field, value) in fields {
        let plaintext = serde_json::to_vec(&value)?;
        let encrypted = confidis_crypto::encrypt_cellule_field(&cellule_key, &field, &plaintext)?;
        envelopes.push(CelluleFieldEnvelope {
            field,
            content_type: "application/json".to_string(),
            ciphertext_hex: hex::encode(encrypted),
            plaintext_blake3: confidis_crypto::blake3_hex(&plaintext),
            updated_at: now,
        });
    }
    envelopes.sort_by(|a, b| a.field.cmp(&b.field));

    let mut container = CelluleFieldContainer {
        version: 1,
        container_id: Uuid::new_v4(),
        cellule_id: CelluleId(args.cellule_id),
        fields: envelopes,
        created_at: now,
        signature: None,
    };
    let signing_key = confidis_crypto::signing_key_from_hex(&args.private_key)?;
    let payload = cellule_field_container_signing_payload(&container)?;
    container.signature = Some(confidis_crypto::sign_hex(&signing_key, &payload));
    let field_count = container.fields.len();

    Ok(CelluleFieldsSealOutput {
        container,
        field_count,
    })
}

pub(super) fn cellule_fields_open(args: CelluleFieldsOpenArgs) -> Result<CelluleFieldsOpenOutput> {
    let bytes = fs::read(&args.container)
        .with_context(|| format!("failed to read {}", args.container.display()))?;
    let container = read_field_container(&bytes)?;
    let cellule_key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;
    let scope = normalize_scope(args.scope);
    if scope.is_empty() {
        bail!("at least one --scope value is required; use --scope '*' to open all fields");
    }

    let mut fields = serde_json::Map::new();
    for envelope in &container.fields {
        if !scope.iter().any(|s| s == "*" || s == &envelope.field) {
            continue;
        }
        let ciphertext = hex::decode(&envelope.ciphertext_hex)
            .with_context(|| format!("invalid ciphertext hex for {}", envelope.field))?;
        let plaintext =
            confidis_crypto::decrypt_cellule_field(&cellule_key, &envelope.field, &ciphertext)
                .with_context(|| format!("failed to decrypt field {}", envelope.field))?;
        let actual = confidis_crypto::blake3_hex(&plaintext);
        if actual != envelope.plaintext_blake3 {
            bail!("field {} plaintext hash mismatch", envelope.field);
        }
        let value = serde_json::from_slice(&plaintext)
            .with_context(|| format!("invalid JSON value in field {}", envelope.field))?;
        fields.insert(envelope.field.clone(), value);
    }

    Ok(CelluleFieldsOpenOutput {
        cellule_id: container.cellule_id,
        fields,
    })
}

pub(super) fn cellule_fields_export(
    args: CelluleFieldsExportArgs,
) -> Result<CelluleFieldsExportOutput> {
    let container_bytes = fs::read(&args.container)
        .with_context(|| format!("failed to read {}", args.container.display()))?;
    let container = read_field_container(&container_bytes)?;
    let now = chrono::Utc::now();
    let scope = normalize_scope(args.scope);
    if scope.is_empty() {
        bail!("at least one --scope value is required");
    }
    let owner_key = confidis_crypto::signing_key_from_hex(&args.private_key)?;
    let owner_public_key = confidis_crypto::verifying_key_to_hex(&owner_key.verifying_key());
    let recipient_public_key = args
        .recipient_public_key
        .clone()
        .unwrap_or_else(|| args.recipient_x25519_pubkey.clone());

    let cellule_key = read_sealed_cellule_key(&args.private_key, &args.cellule_key)?;
    let mut envelopes = Vec::new();
    for envelope in &container.fields {
        if !scope.iter().any(|s| s == "*" || s == &envelope.field) {
            continue;
        }
        let ciphertext = hex::decode(&envelope.ciphertext_hex)
            .with_context(|| format!("invalid ciphertext hex for {}", envelope.field))?;
        let plaintext =
            confidis_crypto::decrypt_cellule_field(&cellule_key, &envelope.field, &ciphertext)
                .with_context(|| format!("failed to decrypt field {}", envelope.field))?;
        let (ephemeral_x25519_pubkey, recipient_ciphertext) =
            confidis_crypto::x25519_seal(&args.recipient_x25519_pubkey, &plaintext)?;
        envelopes.push(CelluleFieldAccessEnvelope {
            field: envelope.field.clone(),
            content_type: envelope.content_type.clone(),
            recipient_x25519_pubkey: args.recipient_x25519_pubkey.clone(),
            ephemeral_x25519_pubkey,
            ciphertext_hex: hex::encode(recipient_ciphertext),
        });
    }
    if envelopes.is_empty() {
        bail!("requested export scope matched no fields in container");
    }

    let package_id = Uuid::new_v4();
    let mut package = CelluleFieldAccessPackage {
        version: 1,
        package_id,
        grant_id: package_id,
        cellule_id: container.cellule_id,
        owner_public_key,
        recipient_public_key,
        recipient_x25519_pubkey: args.recipient_x25519_pubkey,
        fields: envelopes,
        issued_at: now,
        signature: String::new(),
    };
    let payload = cellule_field_access_package_signing_payload(&package)?;
    package.signature = confidis_crypto::sign_hex(&owner_key, &payload);
    let field_count = package.fields.len();

    Ok(CelluleFieldsExportOutput {
        package,
        field_count,
        warning: "Package contains only selected fields encrypted to recipient X25519 key. Exported plaintext cannot be technically clawed back after recipient decrypts it.".to_string(),
    })
}

pub(super) fn cellule_fields_recipient_open(
    args: CelluleFieldsRecipientOpenArgs,
) -> Result<CelluleFieldsRecipientOpenOutput> {
    let bytes = fs::read(&args.package)
        .with_context(|| format!("failed to read {}", args.package.display()))?;
    let package = read_field_access_package(&bytes)?;
    let derived_pubkey =
        confidis_crypto::x25519_pubkey_from_secret_hex(&args.recipient_x25519_secret)?;
    if derived_pubkey != package.recipient_x25519_pubkey {
        bail!("recipient X25519 secret does not match package recipient public key");
    }

    let mut fields = serde_json::Map::new();
    for envelope in &package.fields {
        let ciphertext = hex::decode(&envelope.ciphertext_hex)
            .with_context(|| format!("invalid ciphertext hex for {}", envelope.field))?;
        let plaintext = confidis_crypto::x25519_open(
            &args.recipient_x25519_secret,
            &envelope.ephemeral_x25519_pubkey,
            &ciphertext,
        )
        .with_context(|| format!("failed to decrypt recipient field {}", envelope.field))?;
        let value = serde_json::from_slice(&plaintext)
            .with_context(|| format!("invalid JSON value in field {}", envelope.field))?;
        fields.insert(envelope.field.clone(), value);
    }

    Ok(CelluleFieldsRecipientOpenOutput {
        grant_id: package.grant_id,
        cellule_id: package.cellule_id,
        fields,
    })
}

#[derive(Debug, Deserialize)]
struct FieldContainerEnvelope {
    container: CelluleFieldContainer,
}

#[derive(Debug, Deserialize)]
struct FieldAccessPackageEnvelope {
    package: CelluleFieldAccessPackage,
}

fn read_field_container(bytes: &[u8]) -> Result<CelluleFieldContainer> {
    if let Ok(container) = serde_json::from_slice::<CelluleFieldContainer>(bytes) {
        return Ok(container);
    }
    let envelope: FieldContainerEnvelope =
        serde_json::from_slice(bytes).context("invalid Cellule field container")?;
    Ok(envelope.container)
}

fn read_field_access_package(bytes: &[u8]) -> Result<CelluleFieldAccessPackage> {
    if let Ok(package) = serde_json::from_slice::<CelluleFieldAccessPackage>(bytes) {
        return Ok(package);
    }
    let envelope: FieldAccessPackageEnvelope =
        serde_json::from_slice(bytes).context("invalid Cellule field access package")?;
    Ok(envelope.package)
}

fn normalize_scope(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        for part in value.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}
