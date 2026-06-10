use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use serde::Deserialize;

use crate::state::MaintenanceJobStatus;

#[derive(Debug, Deserialize)]
struct MaintenanceStatusDisk {
    jobs: Vec<MaintenanceJobStatus>,
}

pub(crate) fn load_maintenance_jobs_from_disk(
    store_path: &Path,
) -> HashMap<String, MaintenanceJobStatus> {
    let mut jobs = MaintenanceJobStatus::initial_jobs();
    let path = store_path.join("maintenance").join("status.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return jobs;
    };
    let Ok(snapshot) = serde_json::from_slice::<MaintenanceStatusDisk>(&bytes) else {
        tracing::warn!(path = %path.display(), "failed to load persisted maintenance status");
        return jobs;
    };
    for job in snapshot.jobs {
        jobs.insert(job.job_id.clone(), job);
    }
    jobs
}

pub(crate) async fn persist_maintenance_status(store_path: &Path, jobs: Vec<MaintenanceJobStatus>) {
    let dir = store_path.join("maintenance");
    let path = dir.join("status.json");
    let tmp_path = dir.join(format!("status.{}.tmp", uuid::Uuid::new_v4()));
    let body = serde_json::json!({
        "version": 1,
        "updated_at": Utc::now(),
        "jobs": jobs,
    });

    if let Err(err) = tokio::fs::create_dir_all(&dir).await {
        tracing::warn!(error = %err, path = %path.display(), "failed to create maintenance dir");
        return;
    }

    let json_bytes = match serde_json::to_vec_pretty(&body) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(error = %err, "failed to serialize maintenance status");
            return;
        }
    };

    if let Err(err) = tokio::fs::write(&tmp_path, &json_bytes).await {
        tracing::warn!(error = %err, path = %tmp_path.display(), "failed to write maintenance status");
        return;
    }

    if let Err(err) = tokio::fs::rename(&tmp_path, &path).await {
        tracing::warn!(error = %err, path = %path.display(), "failed to rename maintenance status");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_maintenance_jobs_reloads_persisted_runs() {
        let temp = tempfile::tempdir().expect("temp dir");
        let maintenance_dir = temp.path().join("maintenance");
        std::fs::create_dir_all(&maintenance_dir).expect("maintenance dir");
        let mut audit = MaintenanceJobStatus::new("audit", "Signed audit export");
        audit.status = "ok".to_string();
        audit.runs = 7;
        std::fs::write(
            maintenance_dir.join("status.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "jobs": [audit],
            }))
            .expect("status json"),
        )
        .expect("write status");

        let jobs = load_maintenance_jobs_from_disk(temp.path());

        assert_eq!(jobs["audit"].runs, 7);
        assert!(jobs.contains_key("expiry"));
        assert!(jobs.contains_key("integrity"));
    }

    #[tokio::test]
    async fn persist_maintenance_status_writes_snapshot_atomically() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut audit = MaintenanceJobStatus::new("audit", "Signed audit export");
        audit.status = "ok".to_string();
        audit.runs = 2;

        persist_maintenance_status(temp.path(), vec![audit]).await;

        let path = temp.path().join("maintenance").join("status.json");
        let bytes = std::fs::read(path).expect("status");
        let snapshot: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(snapshot["jobs"][0]["job_id"], "audit");
        assert_eq!(snapshot["jobs"][0]["runs"], 2);
    }
}
