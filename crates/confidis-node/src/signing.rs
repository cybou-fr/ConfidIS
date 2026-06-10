use anyhow::{Context, Result};
use confidis_crypto::sign_hex;
use confidis_protocol::{
    NodeCapacityReport, PeerRecord, capacity_report_signing_payload, peer_record_signing_payload,
};
use ed25519_dalek::SigningKey;

pub(crate) fn sign_capacity_report(
    report: &mut NodeCapacityReport,
    signing_key: Option<&SigningKey>,
) -> Result<()> {
    let Some(signing_key) = signing_key else {
        return Ok(());
    };
    report.signature = None;
    let payload =
        capacity_report_signing_payload(report).context("failed to serialize capacity report")?;
    report.signature = Some(sign_hex(signing_key, &payload));
    Ok(())
}

pub(crate) fn sign_peer_record(
    record: &mut PeerRecord,
    signing_key: Option<&SigningKey>,
) -> Result<()> {
    let Some(signing_key) = signing_key else {
        return Ok(());
    };
    record.signature = None;
    let payload = peer_record_signing_payload(record).context("failed to serialize peer record")?;
    record.signature = Some(sign_hex(signing_key, &payload));
    Ok(())
}
