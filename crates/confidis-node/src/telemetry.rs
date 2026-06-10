use anyhow::Result;

/// Initialize local tracing.
pub fn init_telemetry(_service_name: &str, _service_version: &str) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    Ok(())
}

/// Shutdown tracing.
pub async fn shutdown() {}
