use std::path::Path;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, header};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use confidis_crypto::verifying_key_to_hex;
use confidis_protocol::{NodeCapacityReport, NodeId, verify_node_ban_list};
use serde::Serialize;

use crate::error::ApiError;
use crate::registry_service::load_cellule_registry;
use crate::signing::sign_capacity_report;
use crate::state::{MaintenanceJobStatus, NodeState};
use crate::storage_backend::run_storage_task;

#[derive(Debug, Serialize)]
pub(crate) struct ReadinessResponse {
    version: u8,
    generated_at: DateTime<Utc>,
    node_id: NodeId,
    status: &'static str,
    summary: String,
    pass_count: usize,
    warning_count: usize,
    fail_count: usize,
    checks: Vec<ReadinessCheck>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidencePackResponse {
    version: u8,
    generated_at: DateTime<Utc>,
    node_id: NodeId,
    package_type: &'static str,
    index_markdown: String,
    included: Vec<&'static str>,
    missing: Vec<EvidenceMissingArtifact>,
    checksums: Vec<EvidenceArtifactChecksum>,
    compliance_alignment: EvidenceComplianceAlignment,
    hardening_checklist: EvidenceHardeningChecklist,
    node: EvidenceNodeMetadata,
    readiness: ReadinessResponse,
    audit_latest: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceHardeningChecklist {
    profile: &'static str,
    status: &'static str,
    items: Vec<EvidenceHardeningItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceHardeningItem {
    id: &'static str,
    title: &'static str,
    status: &'static str,
    evidence: String,
    remediation: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceComplianceAlignment {
    claim_policy: &'static str,
    certification_status: &'static str,
    frameworks: Vec<EvidenceComplianceFramework>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceComplianceFramework {
    framework: &'static str,
    status: &'static str,
    supported_by: Vec<&'static str>,
    remaining_work: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceNodeMetadata {
    version: &'static str,
    production_profile: bool,
    region: String,
    failure_domain: String,
    public_endpoint_configured: bool,
    transport_policy: String,
    discovery_backend: String,
    webui_enabled: bool,
    content_dir_enabled: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceMissingArtifact {
    artifact: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceArtifactChecksum {
    artifact: &'static str,
    blake3: String,
    bytes: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadinessCheck {
    id: &'static str,
    title: &'static str,
    status: &'static str,
    detail: String,
    remediation: Option<&'static str>,
}

/// Shared response type used by health, capacity, and peer announcement endpoints.
#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: &'static str,
    pub(crate) node_id: NodeId,
    pub(crate) version: &'static str,
    pub(crate) uptime_secs: u64,
    pub(crate) shard_count: u64,
    pub(crate) peer_count: usize,
    pub(crate) discovery_backend: String,
    pub(crate) kademlia_enabled: bool,
    /// True when a CONFIDIS authority root key is configured to verify the signed
    /// node ban list. This is NOT an admission gate — participation is
    pub(crate) ban_verification_enabled: bool,
    pub(crate) noise_sessions: usize,
    /// True when a valid authority-signed node ban list is loaded.
    pub(crate) node_ban_list_present: bool,
    /// True when this node's own public key is banned/quarantined by the
    /// authority-signed ban list.
    pub(crate) node_banned: bool,
    pub(crate) trust_root_source: String,
    pub(crate) listen_port: u16,
    pub(crate) webui_enabled: bool,
    pub(crate) content_dir_enabled: bool,
    pub(crate) ui_auth_required: bool,
    pub(crate) ui_cors_restricted: bool,
    /// False on every production public surface until signed operator
    /// authentication exists, and false on an authority node in
    /// development. Operator actions on those surfaces are CLI/local-only.
    pub(crate) operator_ui_enabled: bool,
    /// True when privileged UI routes are excluded from the public router.
    pub(crate) public_ui_only: bool,
}

pub(crate) async fn health(State(state): State<Arc<NodeState>>) -> Json<HealthResponse> {
    let shard_count = run_storage_task(&state, |store| store.stats())
        .await
        .ok()
        .map(|s| s.shard_count)
        .unwrap_or(0);
    let peer_count = state.routing_table.read().await.len();
    let uptime_secs = state.started_at.elapsed().as_secs();
    let ban_verification_enabled = state.config.confidis_root_pubkey.is_some();
    let noise_sessions = state.noise_sessions.read().await.len();
    let now = Utc::now();
    let ban_list = state.node_ban_list.read().await.clone();
    let own_pubkey = state
        .config
        .signing_key
        .as_ref()
        .map(|key| verifying_key_to_hex(&key.verifying_key()));
    let (node_ban_list_present, node_banned) =
        match (&ban_list, &state.config.confidis_root_pubkey, &own_pubkey) {
            (Some(list), Some(root_key), own) => {
                let valid = verify_node_ban_list(list, root_key, now).is_ok();
                let banned = valid && own.as_deref().is_some_and(|pk| list.is_banned(pk));
                (valid, banned)
            }
            _ => (false, false),
        };

    Json(HealthResponse {
        status: "ok",
        node_id: state.config.node_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs,
        shard_count,
        peer_count,
        discovery_backend: state.config.discovery_backend.clone(),
        kademlia_enabled: state.config.discovery_backend == "hybrid_kademlia",
        ban_verification_enabled,
        noise_sessions,
        node_ban_list_present,
        node_banned,
        trust_root_source: state.config.confidis_root_source.clone(),
        listen_port: state.config.listen_addr.port(),
        webui_enabled: state.config.webui_path.is_some(),
        content_dir_enabled: state.config.content_dir.is_some(),
        ui_auth_required: !state.config.production_profile && state.config.ui_token.is_some(),
        ui_cors_restricted: state.config.ui_allowed_origin.is_some(),
        operator_ui_enabled: !state.config.production_profile,
        public_ui_only: state.config.production_profile,
    })
}

pub(crate) async fn capacity(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<NodeCapacityReport>, ApiError> {
    let stats = run_storage_task(&state, |store| store.stats())
        .await
        .map_err(ApiError::from)?;
    let free_bytes = state.config.max_bytes.saturating_sub(stats.used_bytes);
    let health_score = if state.config.max_bytes == 0 {
        1.0_f32
    } else {
        let usage_ratio = stats.used_bytes as f32 / state.config.max_bytes as f32;
        (1.0 - usage_ratio).clamp(0.0, 1.0)
    };
    let mut report = NodeCapacityReport {
        node_id: state.config.node_id.clone(),
        public_key: state
            .config
            .signing_key
            .as_ref()
            .map(|key| verifying_key_to_hex(&key.verifying_key())),
        free_bytes,
        used_bytes: stats.used_bytes,
        max_bytes: state.config.max_bytes,
        reserved_bytes: 0,
        region: state.config.region.clone(),
        failure_domain: state.config.failure_domain.clone(),
        health_score,
        current_shard_count: stats.shard_count,
        issued_at: Utc::now(),
        signature: None,
    };
    sign_capacity_report(&mut report, state.config.signing_key.as_ref())?;
    Ok(Json(report))
}

#[derive(Debug, Serialize)]
pub(crate) struct MaintenanceStatusResponse {
    version: u8,
    updated_at: DateTime<Utc>,
    persisted_path: String,
    jobs: Vec<MaintenanceJobStatus>,
}

/// GET /maintenance — UI-facing status of autonomous node maintenance workers.
///
/// This is local node health only. It deliberately does not expose owner manifest
/// placement data or private-key context.
pub(crate) async fn maintenance_status(
    State(state): State<Arc<NodeState>>,
) -> Json<MaintenanceStatusResponse> {
    let mut jobs = state
        .maintenance_jobs
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    jobs.sort_by(|a, b| a.job_id.cmp(&b.job_id));

    Json(MaintenanceStatusResponse {
        version: 1,
        updated_at: Utc::now(),
        persisted_path: state
            .config
            .store_path
            .join("maintenance")
            .join("status.json")
            .display()
            .to_string(),
        jobs,
    })
}

/// GET /readiness — operator-facing CONFIDIS OS readiness report.
///
/// This endpoint is mounted only on the local/development management surface.
/// It intentionally returns configuration posture and runtime health, but no
/// private keys, tokens, owner data, or shard content.
pub(crate) async fn readiness(State(state): State<Arc<NodeState>>) -> Json<ReadinessResponse> {
    Json(build_readiness_response(&state).await)
}

async fn build_readiness_response(state: &Arc<NodeState>) -> ReadinessResponse {
    let stats = run_storage_task(&state, |store| store.stats()).await;
    let peer_count = state.routing_table.read().await.len();
    let maintenance_jobs = state
        .maintenance_jobs
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let production_errors = state.config.production_readiness_errors();

    let mut checks = Vec::new();
    checks.push(ReadinessCheck {
        id: "production_profile",
        title: "Production profile",
        status: if production_errors.is_empty() {
            "pass"
        } else {
            "fail"
        },
        detail: if production_errors.is_empty() {
            "Production profile controls are satisfied or this node is running in local mode."
                .to_string()
        } else {
            format!(
                "{} production control(s) must be fixed before public exposure: {}",
                production_errors.len(),
                production_errors.join("; ")
            )
        },
        remediation: if production_errors.is_empty() {
            None
        } else {
            Some("Review node.json, set secure transport, quotas, public endpoint, UI origin, and remove authority private key material from public nodes.")
        },
    });
    checks.push(ReadinessCheck {
        id: "storage",
        title: "Storage backend",
        status: if stats.is_ok() { "pass" } else { "fail" },
        detail: match &stats {
            Ok(stats) => format!(
                "Storage is reachable: {} bytes used across {} shard(s), with {} bytes configured.",
                stats.used_bytes, stats.shard_count, state.config.max_bytes
            ),
            Err(err) => format!("Storage backend check failed: {err}"),
        },
        remediation: if stats.is_ok() {
            None
        } else {
            Some("Verify store_path or storage backend credentials and file permissions, then restart the node.")
        },
    });
    checks.push(ReadinessCheck {
        id: "quotas",
        title: "Local quotas",
        status: if state.config.max_bytes > 0
            && state.config.max_expiry_days <= confidis_protocol::MAX_CELLULE_LIFETIME_DAYS as u32
            && state.config.max_shards_per_owner_per_hour > 0
            && state.config.max_cellules_per_owner > 0
        {
            "pass"
        } else {
            "fail"
        },
        detail: format!(
            "max_bytes={}, max_expiry_days={}, max_shards_per_owner_per_hour={}, max_cellules_per_owner={}",
            state.config.max_bytes,
            state.config.max_expiry_days,
            state.config.max_shards_per_owner_per_hour,
            state.config.max_cellules_per_owner
        ),
        remediation: Some("Set non-zero owner write and Cellule quotas, keep retention at or below 365 days, and size max_bytes for the pilot.")
            .filter(|_| {
                !(state.config.max_bytes > 0
                    && state.config.max_expiry_days
                        <= confidis_protocol::MAX_CELLULE_LIFETIME_DAYS as u32
                    && state.config.max_shards_per_owner_per_hour > 0
                    && state.config.max_cellules_per_owner > 0)
            }),
    });
    checks.push(ReadinessCheck {
        id: "web_surface",
        title: "Web surface",
        status: if state.config.webui_path.is_some() || state.config.content_dir.is_some() {
            "pass"
        } else {
            "warning"
        },
        detail: format!(
            "webui_path={}, content_dir={}, ui_allowed_origin={}",
            state
                .config
                .webui_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "not configured".to_string()),
            state
                .config
                .content_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "not configured".to_string()),
            state
                .config
                .ui_allowed_origin
                .as_deref()
                .unwrap_or("not configured")
        ),
        remediation: if state.config.webui_path.is_some() || state.config.content_dir.is_some() {
            None
        } else {
            Some("Configure webui_path or content_dir so the appliance serves a usable local UI.")
        },
    });
    checks.push(ReadinessCheck {
        id: "federation",
        title: "Federation peers",
        status: if peer_count > 0 { "pass" } else { "warning" },
        detail: format!("{peer_count} peer(s) currently known in the routing table."),
        remediation: if peer_count > 0 {
            None
        } else {
            Some("For a federated pilot, configure trusted federation peers or agreements and verify peer discovery.")
        },
    });
    let attention_jobs = maintenance_jobs
        .iter()
        .filter(|job| job.attention || job.status == "error")
        .count();
    checks.push(ReadinessCheck {
        id: "maintenance",
        title: "Maintenance workers",
        status: if attention_jobs == 0 { "pass" } else { "warning" },
        detail: format!(
            "{} maintenance job(s) tracked, {} requiring attention.",
            maintenance_jobs.len(),
            attention_jobs
        ),
        remediation: if attention_jobs == 0 {
            None
        } else {
            Some("Open the maintenance panel, review failing jobs, and rerun lifecycle or restore checks before pilot use.")
        },
    });
    checks.push(ReadinessCheck {
        id: "compliance_france",
        title: "RGPD / NIS2 / ANSSI alignment",
        status: "warning",
        detail: "The product exposes technical controls useful for French compliance work, but formal RGPD/NIS2 compliance and ANSSI certification or qualification are not claimed by the software alone.".to_string(),
        remediation: Some("Attach DPA, DPIA starter, ANSSI hardening checklist, incident playbook, restore evidence, federation agreements and legal review before any sensitive French pilot."),
    });

    let fail_count = checks.iter().filter(|check| check.status == "fail").count();
    let warning_count = checks
        .iter()
        .filter(|check| check.status == "warning")
        .count();
    let pass_count = checks.len() - fail_count - warning_count;
    let status = if fail_count > 0 {
        "fail"
    } else if warning_count > 0 {
        "warning"
    } else {
        "pass"
    };
    let summary = match (fail_count, warning_count) {
        (0, 0) => "Ready for CONFIDIS OS pilot operation.".to_string(),
        (0, warnings) => format!(
            "Usable locally, with {warnings} warning(s) to address before public pilot exposure."
        ),
        (fails, warnings) => format!(
            "Not ready: {fails} blocking check(s) and {warnings} warning(s) require attention."
        ),
    };

    ReadinessResponse {
        version: 1,
        generated_at: Utc::now(),
        node_id: state.config.node_id.clone(),
        status,
        summary,
        pass_count,
        warning_count,
        fail_count,
        checks,
    }
}

/// GET /evidence-pack — minimal JSON evidence bundle for CONFIDIS OS pilots.
///
/// This is intentionally local/operator-only. It does not include shard bytes,
/// owner payloads, private keys or bearer tokens.
pub(crate) async fn evidence_pack(
    State(state): State<Arc<NodeState>>,
) -> Json<EvidencePackResponse> {
    Json(build_evidence_pack_response(&state).await)
}

/// GET /evidence-pack.zip — downloadable ZIP bundle for CONFIDIS OS pilots.
///
/// The archive uses stored files (no compression) to avoid adding a packaging
/// dependency to the node binary. Integrity is carried by the included BLAKE3
/// checksums and by the ZIP CRC32 fields.
pub(crate) async fn evidence_pack_zip(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    let evidence = build_evidence_pack_response(&state).await;
    let zip = build_evidence_zip(&evidence).unwrap_or_else(|err| {
        serde_json::to_vec(&serde_json::json!({
            "error": "failed to build evidence ZIP",
            "detail": err.to_string(),
        }))
        .unwrap_or_default()
    });
    let filename = format!("confidis-evidence-pack-{}.zip", evidence.node_id.0);
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            ),
        ],
        zip,
    )
}

async fn build_evidence_pack_response(state: &Arc<NodeState>) -> EvidencePackResponse {
    let readiness = build_readiness_response(&state).await;
    let audit_path = state
        .config
        .store_path
        .join("maintenance")
        .join("audit")
        .join("latest.json");
    let audit_latest = match tokio::fs::read(&audit_path).await {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes).ok(),
        Err(_) => None,
    };

    let mut included = vec!["readiness", "node_metadata"];
    let mut missing = Vec::new();
    if audit_latest.is_some() {
        included.push("audit_latest");
    } else {
        missing.push(EvidenceMissingArtifact {
            artifact: "audit_latest",
            detail: format!(
                "No signed audit snapshot found at {} yet.",
                audit_path.display()
            ),
        });
    }
    let node = EvidenceNodeMetadata {
        version: env!("CARGO_PKG_VERSION"),
        production_profile: state.config.production_profile,
        region: state.config.region.clone(),
        failure_domain: state.config.failure_domain.clone(),
        public_endpoint_configured: state.config.public_endpoint.is_some(),
        transport_policy: format!("{:?}", state.config.transport_policy),
        discovery_backend: state.config.discovery_backend.clone(),
        webui_enabled: state.config.webui_path.is_some(),
        content_dir_enabled: state.config.content_dir.is_some(),
    };
    let compliance_alignment = compliance_alignment();
    included.push("compliance_alignment");
    let hardening_checklist = hardening_checklist(state, &readiness);
    included.push("hardening_checklist");
    let checksums = evidence_checksums(
        &readiness,
        &node,
        &compliance_alignment,
        &hardening_checklist,
        audit_latest.as_ref(),
    )
    .unwrap_or_default();
    let index_markdown = evidence_index_markdown(
        &state.config.node_id,
        &readiness,
        &included,
        &missing,
        &checksums,
    );

    EvidencePackResponse {
        version: 1,
        generated_at: Utc::now(),
        node_id: state.config.node_id.clone(),
        package_type: "confidis-os-evidence-pack",
        index_markdown,
        included,
        missing,
        checksums,
        compliance_alignment,
        hardening_checklist,
        node,
        readiness,
        audit_latest,
    }
}

fn evidence_index_markdown(
    node_id: &NodeId,
    readiness: &ReadinessResponse,
    included: &[&'static str],
    missing: &[EvidenceMissingArtifact],
    checksums: &[EvidenceArtifactChecksum],
) -> String {
    let mut body = String::new();
    body.push_str("# CONFIDIS OS Evidence Pack\n\n");
    body.push_str(&format!("- Node: `{}`\n", node_id.0));
    body.push_str(&format!("- Readiness status: `{}`\n", readiness.status));
    body.push_str(&format!("- Summary: {}\n\n", readiness.summary));
    body.push_str("## Compliance Claim Policy\n\n");
    body.push_str("CONFIDIS OS supports GDPR/NIS2/ANSSI-aligned deployments, but this evidence pack is not a legal compliance certificate, ANSSI certification, ANSSI qualification or SecNumCloud qualification.\n\n");

    body.push_str("## Included Artifacts\n\n");
    for artifact in included {
        body.push_str(&format!("- `{artifact}`\n"));
    }
    if included.is_empty() {
        body.push_str("- None\n");
    }

    body.push_str("\n## Missing Artifacts\n\n");
    if missing.is_empty() {
        body.push_str("- None\n");
    } else {
        for artifact in missing {
            body.push_str(&format!("- `{}`: {}\n", artifact.artifact, artifact.detail));
        }
    }

    body.push_str("\n## Checksums\n\n");
    body.push_str("| Artifact | BLAKE3 | Bytes |\n");
    body.push_str("|---|---:|---:|\n");
    for checksum in checksums {
        body.push_str(&format!(
            "| `{}` | `{}` | {} |\n",
            checksum.artifact, checksum.blake3, checksum.bytes
        ));
    }

    body.push_str(
        "\nThis pack excludes private keys, bearer tokens, shard bytes and plaintext owner data.\n",
    );
    body
}

fn evidence_checksums(
    readiness: &ReadinessResponse,
    node: &EvidenceNodeMetadata,
    compliance: &EvidenceComplianceAlignment,
    hardening: &EvidenceHardeningChecklist,
    audit_latest: Option<&serde_json::Value>,
) -> serde_json::Result<Vec<EvidenceArtifactChecksum>> {
    let mut checksums = Vec::new();
    push_checksum(&mut checksums, "readiness", readiness)?;
    push_checksum(&mut checksums, "node_metadata", node)?;
    push_checksum(&mut checksums, "compliance_alignment", compliance)?;
    push_checksum(&mut checksums, "hardening_checklist", hardening)?;
    if let Some(audit) = audit_latest {
        push_checksum(&mut checksums, "audit_latest", audit)?;
    }
    Ok(checksums)
}

fn compliance_alignment() -> EvidenceComplianceAlignment {
    EvidenceComplianceAlignment {
        claim_policy: "CONFIDIS OS supports GDPR/NIS2/ANSSI-aligned deployments but does not claim legal compliance, ANSSI certification, ANSSI qualification or SecNumCloud qualification unless a formal evaluation grants it for a defined scope.",
        certification_status: "not_certified_not_qualified",
        frameworks: vec![
            EvidenceComplianceFramework {
                framework: "RGPD/GDPR",
                status: "alignment_support",
                supported_by: vec![
                    "local-first deployment",
                    "client-side encryption",
                    "user-owned Cellule keys",
                    "bounded retention",
                    "delete/expiry workflow",
                    "recipient-scoped packages",
                    "audit/evidence exports",
                ],
                remaining_work: vec![
                    "DPA template",
                    "DPIA starter",
                    "data subject rights playbook",
                    "incident notification playbook",
                    "federation/reserve-node clauses",
                ],
            },
            EvidenceComplianceFramework {
                framework: "NIS2",
                status: "alignment_support",
                supported_by: vec![
                    "readiness report",
                    "security events",
                    "maintenance jobs",
                    "backup/restore scripts",
                    "operator/public surface separation",
                    "evidence pack checksums",
                ],
                remaining_work: vec![
                    "incident handling playbook",
                    "restore evidence in pack",
                    "supply-chain evidence",
                    "release signing",
                    "third-party/federation risk register",
                ],
            },
            EvidenceComplianceFramework {
                framework: "ANSSI",
                status: "recommendations_alignment_only",
                supported_by: vec![
                    "local appliance model",
                    "admin/user surface separation",
                    "secure transport policy",
                    "audit logging",
                    "checksummed evidence pack",
                    "no public anonymous upload",
                ],
                remaining_work: vec![
                    "ANSSI hygiene checklist mapping",
                    "hardening checklist",
                    "external security review",
                    "CSPN/PAMS/SecNumCloud applicability decision",
                    "formal certification/qualification process if required",
                ],
            },
        ],
    }
}

fn hardening_checklist(
    state: &Arc<NodeState>,
    readiness: &ReadinessResponse,
) -> EvidenceHardeningChecklist {
    let secure_transport = matches!(
        state.config.transport_policy,
        confidis_protocol::TransportPolicy::NoiseSecureOnly
            | confidis_protocol::TransportPolicy::HttpsReverseProxy
    );
    let quotas_configured = state.config.max_bytes > 0
        && state.config.max_shards_per_owner_per_hour > 0
        && state.config.max_cellules_per_owner > 0;
    let retention_bounded =
        state.config.max_expiry_days <= confidis_protocol::MAX_CELLULE_LIFETIME_DAYS as u32;
    let systemd_evidence = first_existing_path(&[
        "/etc/systemd/system/confidis.service",
        "/etc/systemd/system/confidis-node.service",
        "/lib/systemd/system/confidis.service",
        "packaging/confidis.service",
        "deploy/systemd/confidis-node.service",
    ]);
    let nginx_evidence = first_existing_path(&[
        "/etc/nginx/sites-enabled/confidis.conf",
        "/etc/nginx/sites-available/confidis.conf",
        "deploy/nginx/confidis.conf",
    ]);
    let backup_evidence = first_existing_path(&[
        "scripts/backup-restore.sh",
        "scripts/backup-restore-exercise.sh",
    ]);
    let patch_evidence = first_existing_path(&[
        "scripts/check.sh",
        "scripts/build-deb.sh",
        "scripts/g2-5-deb-rehearsal.sh",
    ]);
    let firewall_evidence = first_existing_path(&[
        "/etc/ufw/user.rules",
        "/etc/nftables.conf",
        "/etc/iptables/rules.v4",
    ]);

    let mut items = vec![
        EvidenceHardeningItem {
            id: "systemd_hardening",
            title: "Systemd service hardening profile available",
            status: if systemd_evidence.is_some() {
                "pass"
            } else {
                "warning"
            },
            evidence: systemd_evidence.clone().unwrap_or_else(|| {
                "No systemd unit evidence found at expected deployed/reference paths".to_string()
            }),
            remediation: if systemd_evidence.is_some() {
                None
            } else {
                Some(
                    "Install CONFIDIS through the Debian package or provide the hardened systemd unit in the evidence pack.",
                )
            },
        },
        EvidenceHardeningItem {
            id: "nginx_tls_boundary",
            title: "Nginx/TLS reverse-proxy boundary documented",
            status: if nginx_evidence.is_some() {
                "pass"
            } else {
                "warning"
            },
            evidence: nginx_evidence.clone().unwrap_or_else(|| {
                "No Nginx/TLS configuration evidence found at expected deployed/reference paths"
                    .to_string()
            }),
            remediation: if nginx_evidence.is_some() {
                None
            } else {
                Some(
                    "Attach the production Nginx/TLS virtual host and certificate-renewal evidence.",
                )
            },
        },
        EvidenceHardeningItem {
            id: "firewall_policy",
            title: "Firewall policy evidence",
            status: if firewall_evidence.is_some() {
                "pass"
            } else {
                "warning"
            },
            evidence: firewall_evidence.clone().unwrap_or_else(|| {
                "No firewall rules evidence found; expected UFW, nftables or iptables artifact."
                    .to_string()
            }),
            remediation: if firewall_evidence.is_some() {
                None
            } else {
                Some(
                    "Attach firewall evidence proving only required public ports are exposed and the node backend remains localhost/private.",
                )
            },
        },
        EvidenceHardeningItem {
            id: "backup_restore_policy",
            title: "Backup/restore tooling evidence",
            status: if backup_evidence.is_some() {
                "pass"
            } else {
                "warning"
            },
            evidence: backup_evidence
                .clone()
                .unwrap_or_else(|| "No backup/restore script evidence found.".to_string()),
            remediation: if backup_evidence.is_some() {
                None
            } else {
                Some("Attach backup/restore procedure and latest restore-test evidence.")
            },
        },
        EvidenceHardeningItem {
            id: "patch_policy",
            title: "Patch and release verification evidence",
            status: if patch_evidence.is_some() {
                "pass"
            } else {
                "warning"
            },
            evidence: patch_evidence.clone().unwrap_or_else(|| {
                "No patch/release verification script evidence found.".to_string()
            }),
            remediation: if patch_evidence.is_some() {
                None
            } else {
                Some(
                    "Attach patch cadence, release verification, dependency audit and rollback evidence.",
                )
            },
        },
        EvidenceHardeningItem {
            id: "admin_public_surface",
            title: "Administration surface is not public in production",
            status: if state.config.production_profile {
                "pass"
            } else {
                "warning"
            },
            evidence: format!(
                "production_profile={}, operator routes are blocked on production public surface",
                state.config.production_profile
            ),
            remediation: if state.config.production_profile {
                None
            } else {
                Some(
                    "For public exposure, enable production_profile and keep operator routes local or behind signed operator authentication.",
                )
            },
        },
        EvidenceHardeningItem {
            id: "secure_transport",
            title: "Secure transport policy",
            status: if secure_transport { "pass" } else { "fail" },
            evidence: format!("{:?}", state.config.transport_policy),
            remediation: if secure_transport {
                None
            } else {
                Some("Use https_reverse_proxy or noise_secure_only before public exposure.")
            },
        },
        EvidenceHardeningItem {
            id: "cors_origin",
            title: "Browser origin restriction",
            status: if state.config.ui_allowed_origin.is_some() {
                "pass"
            } else {
                "warning"
            },
            evidence: state
                .config
                .ui_allowed_origin
                .clone()
                .unwrap_or_else(|| "ui_allowed_origin not configured".to_string()),
            remediation: if state.config.ui_allowed_origin.is_some() {
                None
            } else {
                Some("Set ui_allowed_origin to the exact HTTPS origin serving the UI.")
            },
        },
        EvidenceHardeningItem {
            id: "retention_limit",
            title: "Retention bounded to 365 days or less",
            status: if retention_bounded { "pass" } else { "fail" },
            evidence: format!("max_expiry_days={}", state.config.max_expiry_days),
            remediation: if retention_bounded {
                None
            } else {
                Some("Set max_expiry_days to 365 or less.")
            },
        },
        EvidenceHardeningItem {
            id: "quotas",
            title: "Owner and node quotas configured",
            status: if quotas_configured { "pass" } else { "fail" },
            evidence: format!(
                "max_bytes={}, max_shards_per_owner_per_hour={}, max_cellules_per_owner={}",
                state.config.max_bytes,
                state.config.max_shards_per_owner_per_hour,
                state.config.max_cellules_per_owner
            ),
            remediation: if quotas_configured {
                None
            } else {
                Some("Configure non-zero storage, upload-rate and Cellule-count quotas.")
            },
        },
        EvidenceHardeningItem {
            id: "authority_key_isolation",
            title: "Authority private keys absent from public node",
            status: if state.config.authority_private_key_path.is_none() {
                "pass"
            } else {
                "fail"
            },
            evidence: if state.config.authority_private_key_path.is_some() {
                "authority_private_key_path configured".to_string()
            } else {
                "no authority_private_key_path configured".to_string()
            },
            remediation: if state.config.authority_private_key_path.is_none() {
                None
            } else {
                Some(
                    "Move authority signer material to an isolated signer host or remove it from this node.",
                )
            },
        },
        EvidenceHardeningItem {
            id: "evidence_export",
            title: "Readiness and evidence export available",
            status: "pass",
            evidence: format!(
                "readiness_status={}, checks={}",
                readiness.status,
                readiness.checks.len()
            ),
            remediation: None,
        },
    ];
    let fail_count = items.iter().filter(|item| item.status == "fail").count();
    let warning_count = items.iter().filter(|item| item.status == "warning").count();
    let status = if fail_count > 0 {
        "fail"
    } else if warning_count > 0 {
        "warning"
    } else {
        "pass"
    };
    items.sort_by(|a, b| a.id.cmp(b.id));
    EvidenceHardeningChecklist {
        profile: "france-rgpd-nis2-anssi-prequalification",
        status,
        items,
    }
}

fn first_existing_path(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find(|path| Path::new(path).exists())
        .map(|path| (*path).to_string())
}

fn push_checksum<T: Serialize>(
    checksums: &mut Vec<EvidenceArtifactChecksum>,
    artifact: &'static str,
    value: &T,
) -> serde_json::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    checksums.push(EvidenceArtifactChecksum {
        artifact,
        blake3: blake3::hash(&bytes).to_hex().to_string(),
        bytes: bytes.len(),
    });
    Ok(())
}

fn build_evidence_zip(evidence: &EvidencePackResponse) -> serde_json::Result<Vec<u8>> {
    let mut files = Vec::new();
    files.push((
        "INDEX.md".to_string(),
        evidence.index_markdown.as_bytes().to_vec(),
    ));
    files.push((
        "readiness.json".to_string(),
        serde_json::to_vec_pretty(&evidence.readiness)?,
    ));
    files.push((
        "node_metadata.json".to_string(),
        serde_json::to_vec_pretty(&evidence.node)?,
    ));
    files.push((
        "compliance_alignment.json".to_string(),
        serde_json::to_vec_pretty(&evidence.compliance_alignment)?,
    ));
    files.push((
        "hardening_checklist.json".to_string(),
        serde_json::to_vec_pretty(&evidence.hardening_checklist)?,
    ));
    files.push((
        "checksums.json".to_string(),
        serde_json::to_vec_pretty(&evidence.checksums)?,
    ));
    if let Some(audit) = &evidence.audit_latest {
        files.push((
            "audit_latest.json".to_string(),
            serde_json::to_vec_pretty(audit)?,
        ));
    }
    files.push((
        "evidence-pack.json".to_string(),
        serde_json::to_vec_pretty(evidence)?,
    ));
    Ok(zip_store(files))
}

fn zip_store(files: Vec<(String, Vec<u8>)>) -> Vec<u8> {
    struct CentralRecord {
        name: Vec<u8>,
        crc32: u32,
        size: u32,
        offset: u32,
    }

    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, bytes) in files {
        let name = name.into_bytes();
        let crc32 = crc32(&bytes);
        let size = bytes.len() as u32;
        let offset = out.len() as u32;
        write_u32(&mut out, 0x0403_4b50);
        write_u16(&mut out, 20);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 33);
        write_u32(&mut out, crc32);
        write_u32(&mut out, size);
        write_u32(&mut out, size);
        write_u16(&mut out, name.len() as u16);
        write_u16(&mut out, 0);
        out.extend_from_slice(&name);
        out.extend_from_slice(&bytes);
        central.push(CentralRecord {
            name,
            crc32,
            size,
            offset,
        });
    }

    let central_offset = out.len() as u32;
    for record in &central {
        write_u32(&mut out, 0x0201_4b50);
        write_u16(&mut out, 20);
        write_u16(&mut out, 20);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 33);
        write_u32(&mut out, record.crc32);
        write_u32(&mut out, record.size);
        write_u32(&mut out, record.size);
        write_u16(&mut out, record.name.len() as u16);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u32(&mut out, 0);
        write_u32(&mut out, record.offset);
        out.extend_from_slice(&record.name);
    }
    let central_size = out.len() as u32 - central_offset;

    write_u32(&mut out, 0x0605_4b50);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, central.len() as u16);
    write_u16(&mut out, central.len() as u16);
    write_u32(&mut out, central_size);
    write_u32(&mut out, central_offset);
    write_u16(&mut out, 0);
    out
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) async fn metrics(
    State(state): State<Arc<NodeState>>,
) -> Result<impl IntoResponse, ApiError> {
    let stats = run_storage_task(&state, |store| store.stats())
        .await
        .map_err(ApiError::from)?;
    let jobs = state
        .maintenance_jobs
        .read()
        .await
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let peer_count = state.routing_table.read().await.len();
    let snapshot = crate::metrics::ConfidISMetrics::global()
        .map(|metrics| metrics.snapshot())
        .unwrap_or_default();
    let body = crate::metrics::render_prometheus(
        &state.config.node_id.0,
        state.config.max_bytes,
        peer_count,
        stats,
        &jobs,
        snapshot,
    );
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

/// GET /cellules — serve the local Cellule registry as JSON.
///
/// Requires `registry_path` to be set in `NodeConfig`.  Returns an empty
/// array when the registry file does not exist yet (first run).
pub(crate) async fn list_cellules(
    State(state): State<Arc<NodeState>>,
) -> Result<axum::response::Response, ApiError> {
    use axum::http::{HeaderValue, header};

    let body = load_cellule_registry(&state).await?;

    let json = serde_json::to_vec(&body)
        .map_err(|e| ApiError::internal(format!("serialization error: {e}")))?;

    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        json,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::{TestNodeStateOptions, test_node_state};
    use axum::body::to_bytes;
    use axum::http::{StatusCode, header};

    #[tokio::test]
    async fn list_cellules_returns_empty_json_when_registry_file_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "node-info-test-node",
                registry_path: Some(temp.path().join("missing-registry.json")),
                ..Default::default()
            },
        );

        let response = list_cellules(State(state)).await.expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"[]");
    }

    #[tokio::test]
    async fn list_cellules_requires_registry_path() {
        let temp = tempfile::tempdir().unwrap();
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "node-info-test-node",
                registry_path: None,
                ..Default::default()
            },
        );

        let err = list_cellules(State(state)).await.expect_err("missing path");

        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert!(err.message.contains("registry_path not configured"));
    }

    #[tokio::test]
    async fn readiness_reports_missing_local_quotas_as_blocking() {
        let temp = tempfile::tempdir().unwrap();
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "readiness-test-node",
                ..Default::default()
            },
        );

        let response = readiness(State(state)).await.0;

        assert_eq!(response.status, "fail");
        assert!(response.fail_count >= 1);
        assert!(
            response
                .checks
                .iter()
                .any(|check| check.id == "quotas" && check.status == "fail")
        );
    }

    #[tokio::test]
    async fn evidence_pack_includes_readiness_and_reports_missing_audit() {
        let temp = tempfile::tempdir().unwrap();
        let state = test_node_state(
            &temp,
            TestNodeStateOptions {
                node_id: "evidence-pack-test-node",
                ..Default::default()
            },
        );

        let response = evidence_pack(State(state)).await.0;

        assert_eq!(response.package_type, "confidis-os-evidence-pack");
        assert!(response.index_markdown.contains("# CONFIDIS OS Evidence Pack"));
        assert!(response.index_markdown.contains("`readiness`"));
        assert!(response.index_markdown.contains("BLAKE3"));
        assert_eq!(
            response.compliance_alignment.certification_status,
            "not_certified_not_qualified"
        );
        assert!(
            response
                .compliance_alignment
                .frameworks
                .iter()
                .any(|framework| framework.framework == "ANSSI")
        );
        assert_eq!(response.readiness.node_id.0, "evidence-pack-test-node");
        assert_eq!(
            response.hardening_checklist.profile,
            "france-rgpd-nis2-anssi-prequalification"
        );
        assert!(
            response
                .hardening_checklist
                .items
                .iter()
                .any(|item| item.id == "secure_transport")
        );
        assert!(response.included.contains(&"readiness"));
        assert!(response.included.contains(&"node_metadata"));
        assert!(response.included.contains(&"compliance_alignment"));
        assert!(response.included.contains(&"hardening_checklist"));
        assert!(
            response
                .checksums
                .iter()
                .any(|checksum| checksum.artifact == "readiness"
                    && checksum.blake3.len() == 64
                    && checksum.bytes > 0)
        );
        assert!(
            response
                .checksums
                .iter()
                .any(|checksum| checksum.artifact == "node_metadata"
                    && checksum.blake3.len() == 64
                    && checksum.bytes > 0)
        );
        assert!(
            response
                .checksums
                .iter()
                .any(|checksum| checksum.artifact == "compliance_alignment"
                    && checksum.blake3.len() == 64
                    && checksum.bytes > 0)
        );
        assert!(
            response
                .checksums
                .iter()
                .any(|checksum| checksum.artifact == "hardening_checklist"
                    && checksum.blake3.len() == 64
                    && checksum.bytes > 0)
        );
        assert!(response.audit_latest.is_none());
        assert!(
            response
                .missing
                .iter()
                .any(|artifact| artifact.artifact == "audit_latest")
        );

        let zip = build_evidence_zip(&response).expect("zip");
        assert!(zip.starts_with(b"PK\x03\x04"));
        let zip_text = String::from_utf8_lossy(&zip);
        assert!(zip_text.contains("INDEX.md"));
        assert!(zip_text.contains("readiness.json"));
        assert!(zip_text.contains("node_metadata.json"));
        assert!(zip_text.contains("compliance_alignment.json"));
        assert!(zip_text.contains("hardening_checklist.json"));
        assert!(zip_text.contains("checksums.json"));
    }
}
