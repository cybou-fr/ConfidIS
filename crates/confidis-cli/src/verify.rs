use anyhow::{Context, Result, bail};
use confidis_protocol::{
    CelluleId, NodeCapacityReport, NodeId, ShardId, ShardPlacement, ShardProviderRecord,
    ShardReceipt, ShardReceiptType, capacity_report_signing_payload,
    shard_provider_record_signing_payload, shard_receipt_signing_payload,
};
use uuid::Uuid;

use crate::network::DiscoveredNode;

pub(crate) fn verify_capacity_report_if_signed(report: &NodeCapacityReport) -> Result<()> {
    let Some(signature) = report.signature.as_deref() else {
        return Ok(());
    };
    let public_key = report
        .public_key
        .as_deref()
        .context("signed capacity report missing public_key")?;
    if report.issued_at > chrono::Utc::now() + chrono::Duration::minutes(5) {
        bail!("signed capacity report issued_at is too far in the future");
    }
    if report.issued_at < chrono::Utc::now() - chrono::Duration::minutes(10) {
        bail!("signed capacity report is stale");
    }
    let key = confidis_crypto::verifying_key_from_hex(public_key)?;
    let payload = capacity_report_signing_payload(report)?;
    confidis_crypto::verify_hex(&key, &payload, signature)
}

pub(crate) fn verify_capacity_matches_discovery(
    endpoint: &str,
    report: &NodeCapacityReport,
    discovered: &DiscoveredNode,
) -> Result<()> {
    if let Some(expected_public_key) = &discovered.public_key {
        let actual_public_key = report
            .public_key
            .as_deref()
            .context("capacity report missing public_key required by peer record")?;
        if actual_public_key != expected_public_key {
            bail!("capacity public_key does not match signed peer record for {endpoint}");
        }
        if report.signature.is_none() {
            bail!("capacity report from {endpoint} must be signed because peer record is signed");
        }
    }
    if let Some(expected_node_id) = &discovered.node_id
        && report.node_id != *expected_node_id
    {
        bail!("capacity node_id does not match signed peer record for {endpoint}");
    }
    Ok(())
}

pub(crate) fn parse_and_verify_receipt(
    text: &str,
    expected_shard_id: &ShardId,
    expected_type: ShardReceiptType,
    expected_node_id: Option<&NodeId>,
    expected_public_key: Option<&str>,
) -> Result<ShardReceipt> {
    let receipt: ShardReceipt = serde_json::from_str(text).context("invalid shard receipt")?;
    verify_receipt(
        &receipt,
        expected_shard_id,
        expected_type,
        expected_node_id,
        expected_public_key,
    )?;
    Ok(receipt)
}

pub(crate) fn verify_receipt(
    receipt: &ShardReceipt,
    expected_shard_id: &ShardId,
    expected_type: ShardReceiptType,
    expected_node_id: Option<&NodeId>,
    expected_public_key: Option<&str>,
) -> Result<()> {
    if receipt.version != 1 {
        bail!("unsupported receipt version {}", receipt.version);
    }
    if receipt.receipt_type != expected_type {
        bail!(
            "unexpected receipt type: expected {:?}, got {:?}",
            expected_type,
            receipt.receipt_type
        );
    }
    if receipt.shard_id != *expected_shard_id {
        bail!(
            "receipt shard id mismatch: expected {}, got {}",
            expected_shard_id.0,
            receipt.shard_id.0
        );
    }
    if let Some(expected_node_id) = expected_node_id
        && receipt.node_id != *expected_node_id
    {
        bail!(
            "receipt node id mismatch: expected {}, got {}",
            expected_node_id.0,
            receipt.node_id.0
        );
    }
    if let Some(expected_public_key) = expected_public_key {
        let receipt_public_key = receipt
            .public_key
            .as_deref()
            .context("signed placement receipt missing public_key")?;
        if receipt_public_key != expected_public_key {
            bail!("receipt public_key does not match placement node key");
        }
        if receipt.signature.is_none() {
            bail!("placement receipt must be signed because node key is known");
        }
    }
    verify_receipt_signature_if_signed(receipt)?;
    Ok(())
}

pub(crate) fn verify_receipt_signature_if_signed(receipt: &ShardReceipt) -> Result<()> {
    let Some(signature) = receipt.signature.as_deref() else {
        return Ok(());
    };
    let public_key = receipt
        .public_key
        .as_deref()
        .context("signed receipt missing public_key")?;
    if receipt.issued_at > chrono::Utc::now() + chrono::Duration::minutes(5) {
        bail!("signed receipt issued_at is too far in the future");
    }
    let key = confidis_crypto::verifying_key_from_hex(public_key)?;
    let payload = shard_receipt_signing_payload(receipt)?;
    confidis_crypto::verify_hex(&key, &payload, signature)
}

pub(crate) fn verify_provider_record(
    record: &ShardProviderRecord,
    expected_cellule_id: &CelluleId,
    expected_manifest_id: Uuid,
    expected_segment_index: u32,
    placement: &ShardPlacement,
    receipt: &ShardReceipt,
) -> Result<()> {
    if record.version != 1 {
        bail!("unsupported provider record version {}", record.version);
    }
    if record.cellule_id != *expected_cellule_id {
        bail!("provider record cellule_id mismatch");
    }
    if record.manifest_id != expected_manifest_id {
        bail!("provider record manifest_id mismatch");
    }
    if record.shard_id != placement.shard_id || record.shard_id != receipt.shard_id {
        bail!("provider record shard_id mismatch");
    }
    if record.shard_index != placement.shard_index {
        bail!("provider record shard_index mismatch");
    }
    if record.segment_index != expected_segment_index {
        bail!("provider record segment_index mismatch");
    }
    if record.node_id != placement.node_id || record.node_id != receipt.node_id {
        bail!("provider record node_id mismatch");
    }
    if Some(record.public_key.as_str()) != placement.node_public_key.as_deref()
        || Some(record.public_key.as_str()) != receipt.public_key.as_deref()
    {
        bail!("provider record public_key mismatch");
    }
    if record.endpoint != placement.endpoint {
        bail!("provider record endpoint mismatch");
    }
    if record.region != placement.region || record.failure_domain != placement.failure_domain {
        bail!("provider record topology mismatch");
    }
    if record.receipt_id != receipt.receipt_id {
        bail!("provider record receipt_id mismatch");
    }
    if Some(record.receipt_signature.as_str()) != receipt.signature.as_deref() {
        bail!("provider record receipt_signature mismatch");
    }
    if record.expires_at != receipt.expires_at {
        bail!("provider record expires_at mismatch");
    }
    let signature = record
        .signature
        .as_deref()
        .context("provider record missing signature")?;
    if record.issued_at > chrono::Utc::now() + chrono::Duration::minutes(5) {
        bail!("provider record issued_at is too far in the future");
    }
    let key = confidis_crypto::verifying_key_from_hex(&record.public_key)?;
    let payload = shard_provider_record_signing_payload(record)?;
    confidis_crypto::verify_hex(&key, &payload, signature)
}
