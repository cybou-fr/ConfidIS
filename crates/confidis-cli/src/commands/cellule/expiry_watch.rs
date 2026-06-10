use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;

use super::expiry_check::{CelluleExpiryEntry, ExpiryCheckOutput, cellule_expiry_check};
use super::renew::cellule_renew;
use super::types::CelluleRenewArgs;

pub(super) struct ExpiryWatchArgs {
    pub(super) registry: PathBuf,
    pub(super) days: i64,
    pub(super) interval_seconds: u64,
    pub(super) max_runs: Option<u64>,
    pub(super) output: PathBuf,
    pub(super) auto_renew: Option<AutoRenewArgs>,
}

pub(super) struct AutoRenewArgs {
    pub(super) blob_store: PathBuf,
    pub(super) private_key: String,
    pub(super) cellule_key: PathBuf,
    pub(super) extend_days: u32,
}

#[derive(Debug, Serialize)]
pub(super) struct ExpiryWatchOutput {
    pub(super) interval_seconds: u64,
    pub(super) max_runs: Option<u64>,
    pub(super) runs_completed: u64,
    pub(super) last_run: Option<ExpiryWatchRunOutput>,
    pub(super) history: Vec<ExpiryWatchRunSummary>,
}

#[derive(Debug, Serialize)]
pub(super) struct ExpiryWatchRunOutput {
    pub(super) check: ExpiryCheckOutput,
    pub(super) renewals: Vec<RenewalResult>,
    pub(super) renewed: usize,
    pub(super) renewal_failed: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct RenewalResult {
    pub(super) cellule_id: String,
    pub(super) days_remaining: i64,
    pub(super) status: String,
    pub(super) new_expires_at: Option<String>,
    pub(super) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct ExpiryWatchRunSummary {
    pub(super) checked_at: chrono::DateTime<Utc>,
    pub(super) total: usize,
    pub(super) active: usize,
    pub(super) expiring_soon: usize,
    pub(super) expired: usize,
    pub(super) renewed: usize,
    pub(super) renewal_failed: usize,
}

pub(super) async fn cellule_expiry_watch(args: ExpiryWatchArgs) -> Result<()> {
    let mut output = ExpiryWatchOutput {
        interval_seconds: args.interval_seconds,
        max_runs: args.max_runs,
        runs_completed: 0,
        last_run: None,
        history: Vec::new(),
    };

    loop {
        let run = run_once(&args).await?;
        let summary = ExpiryWatchRunSummary {
            checked_at: run.check.checked_at,
            total: run.check.total,
            active: run.check.active,
            expiring_soon: run.check.expiring_soon,
            expired: run.check.expired,
            renewed: run.renewed,
            renewal_failed: run.renewal_failed,
        };

        output.runs_completed += 1;
        output.history.push(summary);
        output.last_run = Some(run);

        let json = serde_json::to_vec_pretty(&output)
            .context("failed to serialize expiry-watch output")?;
        std::fs::write(&args.output, &json)
            .with_context(|| format!("failed to write {}", args.output.display()))?;
        println!("{}", String::from_utf8(json)?);

        if args
            .max_runs
            .is_some_and(|max| output.runs_completed >= max)
        {
            break;
        }

        tokio::time::sleep(Duration::from_secs(args.interval_seconds)).await;
    }

    Ok(())
}

async fn run_once(args: &ExpiryWatchArgs) -> Result<ExpiryWatchRunOutput> {
    let check = cellule_expiry_check(&args.registry, Some(args.days))?;
    let mut renewals = Vec::new();
    let mut renewed_count = 0usize;
    let mut failed_count = 0usize;

    if let Some(auto_renew) = &args.auto_renew {
        let expiring_soon: Vec<CelluleExpiryEntry> = check
            .results
            .iter()
            .filter(|e| e.lifecycle == "expiring_soon")
            .cloned()
            .collect();

        for entry in expiring_soon {
            let new_expires_at_str =
                (Utc::now() + chrono::Duration::days(auto_renew.extend_days as i64)).to_rfc3339();

            let renew_result = cellule_renew(CelluleRenewArgs {
                cellule_id: entry.cellule_id.clone(),
                registry: args.registry.clone(),
                blob_store: auto_renew.blob_store.clone(),
                private_key: auto_renew.private_key.clone(),
                cellule_key: auto_renew.cellule_key.clone(),
                expires_at: new_expires_at_str.clone(),
            })
            .await;

            match renew_result {
                Ok(out) => {
                    renewed_count += 1;
                    renewals.push(RenewalResult {
                        cellule_id: entry.cellule_id,
                        days_remaining: entry.days_remaining,
                        status: "renewed".to_string(),
                        new_expires_at: Some(out.new_expires_at),
                        error: None,
                    });
                }
                Err(err) => {
                    failed_count += 1;
                    renewals.push(RenewalResult {
                        cellule_id: entry.cellule_id,
                        days_remaining: entry.days_remaining,
                        status: "failed".to_string(),
                        new_expires_at: None,
                        error: Some(err.to_string()),
                    });
                }
            }
        }
    }

    Ok(ExpiryWatchRunOutput {
        check,
        renewals,
        renewed: renewed_count,
        renewal_failed: failed_count,
    })
}
