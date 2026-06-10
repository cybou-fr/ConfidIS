use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;

mod audit_export;
mod availability;
mod delete;
mod expiry_check;
mod expiry_watch;
mod fields;
mod get;
mod helpers;
#[cfg(any())]
mod put;
mod rebalance;
mod renew;
mod repair;
mod report;
mod share;
mod types;

pub(crate) use delete::{
    create_delete_request, delete_authority_hash, delete_authority_hash_from_private_key,
};
pub(crate) use helpers::{manifest_from_segments, read_sealed_cellule_key, validated_expires_at};
pub(crate) use types::{
    CelluleGetArgs, CelluleRebalanceArgs, CelluleRebalancePlanArgs, CelluleRebalanceScanArgs,
    CelluleRebalanceWatchArgs, CelluleRepairArgs, CelluleRepairScanArgs, CelluleRepairWatchArgs,
};
#[cfg(any())]
pub(crate) use types::{CellulePutArgs, StoragePriceQuoteOutput};

use audit_export::cellule_audit_export;
use availability::cellule_availability;
use delete::cellule_delete;
use expiry_check::cellule_expiry_check;
use expiry_watch::cellule_expiry_watch;
use fields::{
    cellule_fields_export, cellule_fields_open, cellule_fields_recipient_open, cellule_fields_seal,
};
use get::cellule_get;
use helpers::{
    cellule_id_from_public_key, create_cellule_record, publish_record, read_registry,
    verify_cellule_record,
};
#[cfg(any())]
use put::cellule_put;
use rebalance::{cellule_rebalance, cellule_rebalance_plan, cellule_rebalance_watch};
use renew::cellule_renew;
use repair::{cellule_repair, cellule_repair_scan, cellule_repair_watch};
use report::{cellule_report_export, cellule_report_proof};
use share::cellule_share;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub(crate) enum CelluleCommand {
    Id {
        #[arg(long)]
        public_key: String,
    },
    SignCreate {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_id: String,
        #[arg(long, default_value = "")]
        label: String,
        #[arg(long, default_value_t = 30)]
        retention_days: i64,
        #[arg(long)]
        reserved_bytes: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Record {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value_t = 1)]
        sequence: u64,
        #[arg(long)]
        output: PathBuf,
    },
    Publish {
        #[arg(long)]
        registry: PathBuf,
        record: PathBuf,
    },
    Resolve {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        cellule_id: String,
    },
    Keygen {
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        output: PathBuf,
    },
    #[cfg(any())]
    Put {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        expires_at: String,
        #[arg(long, default_value_t = 1)]
        sequence: u64,
        #[arg(long)]
        funding_ledger: Option<PathBuf>,
        #[arg(long)]
        funding_wallet: Option<String>,
        #[arg(long, default_value_t = 0)]
        required_cyb: u128,
        #[arg(long)]
        quote_cyb: bool,
        #[arg(long)]
        funding_public_key: Option<String>,
        #[arg(long)]
        funding_private_key: Option<String>,
        #[arg(long)]
        funding_ledger_output: Option<PathBuf>,
        #[arg(long)]
        placement_policy_file: Option<PathBuf>,
        #[arg(long)]
        pricing_policy_file: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    Get {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Availability {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Delete {
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Repair {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    RepairScan {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    RepairWatch {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long, default_value_t = 60)]
        interval_seconds: u64,
        #[arg(long)]
        max_runs: Option<u64>,
        #[arg(long)]
        output: PathBuf,
    },
    RebalancePlan {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Path to a JSON `PlacementPolicy` file. When omitted, uses the default unconstrained policy.
        #[arg(long)]
        placement_policy_file: Option<PathBuf>,
    },
    Rebalance {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Path to a JSON `PlacementPolicy` file. When omitted, uses the default unconstrained policy.
        #[arg(long)]
        placement_policy_file: Option<PathBuf>,
    },
    RebalanceWatch {
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(long)]
        work_dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long, default_value_t = 300)]
        interval_seconds: u64,
        #[arg(long)]
        max_runs: Option<u64>,
        #[arg(long)]
        output: PathBuf,
        /// Path to a JSON `PlacementPolicy` file. When omitted, uses the default unconstrained policy.
        #[arg(long)]
        placement_policy_file: Option<PathBuf>,
    },
    ExpiryCheck {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        days: Option<i64>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    ExpiryWatch {
        #[arg(long)]
        registry: PathBuf,
        /// Days threshold — warn when a Cellule expires within this many days (default: 30).
        #[arg(long, default_value_t = 30)]
        days: i64,
        /// Seconds between scans (default: 86400 = 1 day).
        #[arg(long, default_value_t = 86400)]
        interval_seconds: u64,
        /// Stop after this many runs (omit to run indefinitely).
        #[arg(long)]
        max_runs: Option<u64>,
        /// JSON file path to write daemon status after each run.
        #[arg(long)]
        output: PathBuf,
        /// Automatically renew expiring-soon Cellules each cycle.
        #[arg(long)]
        auto_renew: bool,
        /// Days to extend from now when auto-renewing (default: 90).
        #[arg(long, default_value_t = 90)]
        extend_days: u32,
        /// Blob-store path (required when --auto-renew is set).
        #[arg(long)]
        blob_store: Option<PathBuf>,
        /// Private key hex (required when --auto-renew is set).
        #[arg(long)]
        private_key: Option<String>,
        /// Cellule key path (required when --auto-renew is set).
        #[arg(long)]
        cellule_key: Option<PathBuf>,
    },
    AuditExport {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Renew {
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Share {
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long = "node")]
        nodes: Vec<String>,
        #[arg(
            long,
            help = "Base URL for the access link (default: https://confidis.fr/access)"
        )]
        base_url: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Legacy/dev-only: export the raw Cellule key into portable share artifacts"
        )]
        allow_raw_key_export: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    ReportProof {
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        owner_private_key: String,
        #[arg(long)]
        challenge: String,
        #[arg(
            long = "scope",
            default_value = "cellule.report",
            help = "Owner report scope. Use cellule.report for full Cellule report authorization."
        )]
        scope: Vec<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    ReportExport {
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        blob_store: PathBuf,
        #[arg(long)]
        owner_private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    FieldsSeal {
        #[arg(long)]
        cellule_id: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    FieldsOpen {
        #[arg(long)]
        container: PathBuf,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(
            long = "scope",
            help = "Field scope to decrypt. Repeat or comma-separate values; use '*' to open all fields."
        )]
        scope: Vec<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    FieldsExport {
        #[arg(long)]
        container: PathBuf,
        #[arg(long)]
        recipient_public_key: Option<String>,
        #[arg(long)]
        private_key: String,
        #[arg(long)]
        cellule_key: PathBuf,
        #[arg(long)]
        recipient_x25519_pubkey: String,
        #[arg(
            long = "scope",
            help = "Field scope to export into the recipient-encrypted package."
        )]
        scope: Vec<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    FieldsRecipientOpen {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        recipient_x25519_secret: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

pub(crate) async fn cellule(command: CelluleCommand) -> Result<()> {
    match command {
        CelluleCommand::Id { public_key } => {
            let id = cellule_id_from_public_key(&public_key)?;
            println!("{}", id.0);
        }
        CelluleCommand::SignCreate {
            public_key,
            private_key,
            cellule_id,
            label,
            retention_days,
            reserved_bytes,
            output,
        } => {
            if retention_days < 1 || retention_days > confidis_protocol::MAX_CELLULE_LIFETIME_DAYS {
                anyhow::bail!(
                    "retention_days must be between 1 and {}",
                    confidis_protocol::MAX_CELLULE_LIFETIME_DAYS
                );
            }
            let mut create = confidis_protocol::CelluleOwnerCreate {
                version: 1,
                operation: confidis_protocol::CELLULE_OWNER_CREATE_OPERATION.to_string(),
                cellule_id: confidis_protocol::CelluleId(cellule_id),
                label,
                owner_public_key: public_key,
                retention_days,
                reserved_bytes,
                paid_shards_hash: None,
                content_hash: None,
                manifest_hash: None,
                storage_profile: None,
                funding_reference: None,
                payer_pubkey: None,
                issued_at: chrono::Utc::now(),
                signature: String::new(),
            };
            let signing_key = confidis_crypto::signing_key_from_hex(&private_key)
                .context("invalid owner private key")?;
            let payload = confidis_protocol::cellule_owner_create_signing_payload(&create)
                .context("failed to build owner-create signing payload")?;
            create.signature = confidis_crypto::sign_hex(&signing_key, &payload);
            fs::write(&output, serde_json::to_vec_pretty(&create)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        CelluleCommand::Record {
            public_key,
            private_key,
            manifest,
            expires_at,
            sequence,
            output,
        } => {
            let manifest_bytes = fs::read(&manifest)
                .with_context(|| format!("failed to read {}", manifest.display()))?;
            let manifest_cid = confidis_crypto::blake3_hex(&manifest_bytes);
            let record = create_cellule_record(
                public_key,
                &private_key,
                manifest_cid,
                &expires_at,
                sequence,
            )?;
            fs::write(&output, serde_json::to_vec_pretty(&record)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        CelluleCommand::Publish { registry, record } => {
            let bytes = fs::read(&record)
                .with_context(|| format!("failed to read {}", record.display()))?;
            let record: confidis_protocol::CellulePublicRecord =
                serde_json::from_slice(&bytes).context("invalid Cellule record")?;
            publish_record(&registry, record)?;
        }
        CelluleCommand::Resolve {
            registry,
            cellule_id,
        } => {
            let records = read_registry(&registry)?;
            let record = records
                .into_iter()
                .find(|record| record.cellule_id.0 == cellule_id)
                .context("Cellule record not found")?;
            verify_cellule_record(&record)?;
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
        CelluleCommand::Keygen {
            private_key,
            output,
        } => {
            let cellule_key = confidis_crypto::generate_cellule_key();
            let sealed = confidis_crypto::seal_cellule_key(&private_key, &cellule_key)?;
            fs::write(&output, sealed)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        #[cfg(any())]
        CelluleCommand::Put {
            nodes,
            input,
            work_dir,
            registry,
            blob_store,
            public_key,
            private_key,
            cellule_key,
            expires_at,
            sequence,
            funding_ledger,
            funding_wallet,
            required_cyb,
            quote_cyb,
            funding_public_key,
            funding_private_key,
            funding_ledger_output,
            placement_policy_file,
            pricing_policy_file,
            output,
        } => {
            let summary = cellule_put(CellulePutArgs {
                nodes,
                input,
                work_dir,
                registry,
                blob_store,
                public_key,
                private_key,
                cellule_key,
                expires_at,
                sequence,
                funding_ledger,
                funding_wallet,
                required_cyb,
                quote_cyb,
                funding_public_key,
                funding_private_key,
                funding_ledger_output,
                placement_policy_file,
                pricing_policy_file,
            })
            .await?;
            fs::write(&output, serde_json::to_vec_pretty(&summary)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        CelluleCommand::Get {
            nodes,
            cellule_id,
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
        } => {
            let restored = cellule_get(CelluleGetArgs {
                nodes,
                cellule_id,
                registry,
                blob_store,
                private_key,
                cellule_key,
            })
            .await?;
            fs::write(&output, restored)
                .with_context(|| format!("failed to write {}", output.display()))?;
        }
        CelluleCommand::Availability {
            nodes,
            cellule_id,
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
        } => {
            let summary = cellule_availability(CelluleGetArgs {
                nodes,
                cellule_id,
                registry,
                blob_store,
                private_key,
                cellule_key,
            })
            .await?;
            let json = serde_json::to_vec_pretty(&summary)?;
            if let Some(output) = output {
                fs::write(&output, json)
                    .with_context(|| format!("failed to write {}", output.display()))?;
            } else {
                println!("{}", String::from_utf8(json)?);
            }
        }
        CelluleCommand::Delete {
            cellule_id,
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
        } => {
            let summary = cellule_delete(CelluleGetArgs {
                nodes: Vec::new(),
                cellule_id,
                registry,
                blob_store,
                private_key,
                cellule_key,
            })
            .await?;
            let json = serde_json::to_vec_pretty(&summary)?;
            if let Some(output) = output {
                fs::write(&output, json)
                    .with_context(|| format!("failed to write {}", output.display()))?;
            } else {
                println!("{}", String::from_utf8(json)?);
            }
        }
        CelluleCommand::Repair {
            nodes,
            cellule_id,
            work_dir,
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
        } => {
            let summary = cellule_repair(CelluleRepairArgs {
                nodes,
                cellule_id,
                work_dir,
                registry,
                blob_store,
                private_key,
                cellule_key,
            })
            .await?;
            fs::write(&output, serde_json::to_vec_pretty(&summary)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        CelluleCommand::RepairScan {
            nodes,
            work_dir,
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
        } => {
            let summary = cellule_repair_scan(CelluleRepairScanArgs {
                nodes,
                work_dir,
                registry,
                blob_store,
                private_key,
                cellule_key,
            })
            .await?;
            fs::write(&output, serde_json::to_vec_pretty(&summary)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        CelluleCommand::RepairWatch {
            nodes,
            work_dir,
            registry,
            blob_store,
            private_key,
            cellule_key,
            interval_seconds,
            max_runs,
            output,
        } => {
            cellule_repair_watch(CelluleRepairWatchArgs {
                scan: CelluleRepairScanArgs {
                    nodes,
                    work_dir,
                    registry,
                    blob_store,
                    private_key,
                    cellule_key,
                },
                interval_seconds,
                max_runs,
                output,
            })
            .await?;
        }
        CelluleCommand::RebalancePlan {
            nodes,
            cellule_id,
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
            placement_policy_file,
        } => {
            let plan = cellule_rebalance_plan(CelluleRebalancePlanArgs {
                nodes,
                cellule_id,
                registry,
                blob_store,
                private_key,
                cellule_key,
                placement_policy_file,
            })
            .await?;
            let json = serde_json::to_vec_pretty(&plan)?;
            if let Some(output) = output {
                fs::write(&output, json)
                    .with_context(|| format!("failed to write {}", output.display()))?;
            } else {
                println!("{}", String::from_utf8(json)?);
            }
        }
        CelluleCommand::Rebalance {
            nodes,
            cellule_id,
            work_dir,
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
            placement_policy_file,
        } => {
            let summary = cellule_rebalance(CelluleRebalanceArgs {
                nodes,
                cellule_id,
                work_dir,
                registry,
                blob_store,
                private_key,
                cellule_key,
                placement_policy_file,
            })
            .await?;
            fs::write(&output, serde_json::to_vec_pretty(&summary)?)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        CelluleCommand::RebalanceWatch {
            nodes,
            work_dir,
            registry,
            blob_store,
            private_key,
            cellule_key,
            interval_seconds,
            max_runs,
            output,
            placement_policy_file,
        } => {
            cellule_rebalance_watch(CelluleRebalanceWatchArgs {
                scan: CelluleRebalanceScanArgs {
                    nodes,
                    work_dir,
                    registry,
                    blob_store,
                    private_key,
                    cellule_key,
                    placement_policy_file,
                },
                interval_seconds,
                max_runs,
                output,
            })
            .await?;
        }
        CelluleCommand::ExpiryCheck {
            registry,
            days,
            output,
        } => {
            let result = cellule_expiry_check(&registry, days)?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::ExpiryWatch {
            registry,
            days,
            interval_seconds,
            max_runs,
            output,
            auto_renew,
            extend_days,
            blob_store,
            private_key,
            cellule_key,
        } => {
            let auto_renew_args = if auto_renew {
                let blob_store = blob_store.ok_or_else(|| {
                    anyhow::anyhow!("--blob-store is required when --auto-renew is set")
                })?;
                let private_key = private_key.ok_or_else(|| {
                    anyhow::anyhow!("--private-key is required when --auto-renew is set")
                })?;
                let cellule_key = cellule_key.ok_or_else(|| {
                    anyhow::anyhow!("--cellule-key is required when --auto-renew is set")
                })?;
                Some(expiry_watch::AutoRenewArgs {
                    blob_store,
                    private_key,
                    cellule_key,
                    extend_days,
                })
            } else {
                None
            };
            cellule_expiry_watch(expiry_watch::ExpiryWatchArgs {
                registry,
                days,
                interval_seconds,
                max_runs,
                output,
                auto_renew: auto_renew_args,
            })
            .await?;
        }
        CelluleCommand::AuditExport {
            registry,
            blob_store,
            private_key,
            cellule_key,
            output,
        } => {
            let result = cellule_audit_export(&registry, &blob_store, &private_key, &cellule_key)?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::Renew {
            cellule_id,
            registry,
            blob_store,
            private_key,
            cellule_key,
            expires_at,
            output,
        } => {
            use types::CelluleRenewArgs;
            let result = cellule_renew(CelluleRenewArgs {
                cellule_id,
                registry,
                blob_store,
                private_key,
                cellule_key,
                expires_at,
            })
            .await?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::Share {
            cellule_id,
            registry,
            private_key,
            cellule_key,
            nodes,
            base_url,
            allow_raw_key_export,
            output,
        } => {
            use types::CelluleShareArgs;
            let result = cellule_share(CelluleShareArgs {
                cellule_id,
                registry,
                private_key,
                cellule_key,
                nodes,
                base_url,
                allow_raw_key_export,
            })?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::ReportProof {
            cellule_id,
            registry,
            owner_private_key,
            challenge,
            scope,
            output,
        } => {
            use types::CelluleReportProofArgs;
            let result = cellule_report_proof(CelluleReportProofArgs {
                cellule_id,
                registry,
                owner_private_key,
                challenge,
                scope,
            })?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::ReportExport {
            cellule_id,
            registry,
            blob_store,
            owner_private_key,
            cellule_key,
            proof,
            output,
        } => {
            use types::CelluleReportExportArgs;
            let result = cellule_report_export(CelluleReportExportArgs {
                cellule_id,
                registry,
                blob_store,
                owner_private_key,
                cellule_key,
                proof,
            })
            .await?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::FieldsSeal {
            cellule_id,
            input,
            private_key,
            cellule_key,
            output,
        } => {
            use types::CelluleFieldsSealArgs;
            let result = cellule_fields_seal(CelluleFieldsSealArgs {
                cellule_id,
                input,
                private_key,
                cellule_key,
            })?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::FieldsOpen {
            container,
            private_key,
            cellule_key,
            scope,
            output,
        } => {
            use types::CelluleFieldsOpenArgs;
            let result = cellule_fields_open(CelluleFieldsOpenArgs {
                container,
                private_key,
                cellule_key,
                scope,
            })?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::FieldsExport {
            container,
            recipient_public_key,
            private_key,
            cellule_key,
            recipient_x25519_pubkey,
            scope,
            output,
        } => {
            use types::CelluleFieldsExportArgs;
            let result = cellule_fields_export(CelluleFieldsExportArgs {
                container,
                recipient_public_key,
                private_key,
                cellule_key,
                recipient_x25519_pubkey,
                scope,
            })?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
        CelluleCommand::FieldsRecipientOpen {
            package,
            recipient_x25519_secret,
            output,
        } => {
            use types::CelluleFieldsRecipientOpenArgs;
            let result = cellule_fields_recipient_open(CelluleFieldsRecipientOpenArgs {
                package,
                recipient_x25519_secret,
            })?;
            let json = serde_json::to_vec_pretty(&result)?;
            if let Some(path) = output {
                fs::write(&path, &json)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            println!("{}", String::from_utf8(json)?);
        }
    }
    Ok(())
}
