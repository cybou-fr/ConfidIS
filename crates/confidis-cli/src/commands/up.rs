use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use confidis_crypto::{generate_signing_key, signing_key_to_hex, x25519_generate};

/// Default local listen address for the guided company-node path.
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4433";
const DEFAULT_PUBLIC_ENDPOINT: &str = "http://127.0.0.1:4433";

/// Guided default company-node runner (`confidis` with no subcommand, or
/// `confidis up`). First run writes a localhost company-node config + identity
/// under `~/.confidis`; subsequent runs reuse it. This path NEVER creates a
/// genesis/authority keyset or ledger — legacy authority ceremonies are
/// explicit lab-only operations.
pub(crate) async fn up() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        .try_init();

    let config_path = resolve_config_path()?;

    if config_path.exists() {
        println!("✓ reusing existing node config: {}", config_path.display());
    } else {
        first_run_setup(&config_path)?;
    }

    let config = confidis_node::ConfidISConfig::load(Some(&config_path))
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;

    print_posture(&config);
    confidis_node::serve(config).await
}

/// `$CONFIDIS_CONFIG` if set, otherwise `~/.confidis/node.json`.
fn resolve_config_path() -> Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("CONFIDIS_CONFIG") {
        return Ok(PathBuf::from(explicit));
    }
    Ok(confidis_home()?.join("node.json"))
}

fn confidis_home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from).context(
        "cannot determine home directory (HOME unset); set CONFIDIS_CONFIG to a config path",
    )?;
    Ok(home.join(".confidis"))
}

/// Locate the bundled web UI assets. Honors `$CONFIDIS_WEBUI_PATH`, then falls
/// back to the common dev and packaged install locations. Returns `None` when
/// no bundle is found (the node still serves the API; the UI is just absent).
fn resolve_webui_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("CONFIDIS_WEBUI_PATH") {
        let path = PathBuf::from(explicit);
        if path.is_dir() {
            return Some(path);
        }
    }
    for candidate in [
        "./web-ui/dist",
        "/usr/share/confidis/webui",
        "/var/www/confidis-ui",
    ] {
        let path = PathBuf::from(candidate);
        if path.is_dir() {
            return Some(path);
        }
    }
    None
}

fn first_run_setup(config_path: &Path) -> Result<()> {
    let home = confidis_home()?;
    let store_path = home.join("store");
    ensure_private_dir(&home)?;
    ensure_private_dir(&store_path)
        .with_context(|| format!("failed to create store path {}", store_path.display()))?;
    if let Some(parent) = config_path.parent() {
        ensure_private_dir(parent)
            .with_context(|| format!("failed to create config dir {}", parent.display()))?;
    }

    let signing_key = generate_signing_key();
    let private_key = signing_key_to_hex(&signing_key);
    let (x25519_secret, _x25519_pub) = x25519_generate();

    let mut rng_bytes = [0u8; 4];
    {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut rng_bytes);
    }
    let node_id = format!("node-{}", hex::encode(rng_bytes));

    let webui_path = resolve_webui_path();

    // Company-node defaults: localhost bind, no public seed peer, no
    // genesis/authority/ledger.
    let mut config = confidis_node::ConfidISConfig::default();
    config.node.node_id = node_id.clone();
    config.node.production_profile = false;
    config.node.private_key = Some(private_key);
    config.node.x25519_secret_key = Some(x25519_secret);
    config.storage.store_path = store_path.clone();
    config.storage_backend.filesystem_root = Some(store_path.clone());
    config.network.listen_addr = DEFAULT_LISTEN_ADDR.to_string();
    config.network.public_endpoint = Some(DEFAULT_PUBLIC_ENDPOINT.to_string());
    config.ui.webui_path = webui_path.clone();

    let json = serde_json::to_vec_pretty(&config)?;
    write_private_file(config_path, &json)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("✓ first-run setup complete (company node — not an authority node)");
    println!("  node id     : {node_id}");
    println!("  config      : {}", config_path.display());
    println!("  store       : {}", store_path.display());
    println!(
        "  identity    : ed25519 + x25519 generated and saved in the config (keep it private)"
    );
    match &webui_path {
        Some(path) => println!("  web ui      : {}", path.display()),
        None => println!(
            "  web ui      : not found — set CONFIDIS_WEBUI_PATH or build web-ui/ (API still serves)"
        ),
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to chmod 0700 {}", path.display()))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("failed to create {}", tmp_path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
        fs::rename(&tmp_path, path)
            .with_context(|| format!("failed to move {} into place", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod 0600 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp_path, bytes)
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        fs::rename(&tmp_path, path)
            .with_context(|| format!("failed to move {} into place", path.display()))?;
    }
    Ok(())
}

fn print_posture(config: &confidis_node::ConfidISConfig) {
    let listen = &config.network.listen_addr;
    let is_localhost = listen.starts_with("127.0.0.1:") || listen.starts_with("localhost:");
    let posture = if config.node.production_profile {
        "production profile (fail-closed controls enforced)"
    } else if is_localhost {
        "local development — bound to localhost only, unauthenticated"
    } else {
        "protected local — non-localhost bind WITHOUT production profile; \
         set ui_token + ui_allowed_origin before exposing"
    };

    let url_base = config
        .network
        .public_endpoint
        .clone()
        .unwrap_or_else(|| format!("http://{listen}"));

    println!();
    println!("CONFIDIS node starting (one-command mode)");
    println!("  security    : {posture}");
    if !config.network.bootstrap_peers.is_empty() {
        println!(
            "  federation  : {}",
            config.network.bootstrap_peers.join(", ")
        );
    }
    if config.ui.webui_path.is_some() {
        println!("  web ui      : {url_base}/ui/");
    }
    println!("  node api    : {url_base}/health");
    println!("  stop        : Ctrl-C");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn one_command_setup_writes_private_config_and_dirs() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_test_dir("confidis-up-private");
        let config_dir = root.join(".confidis");
        let store_dir = config_dir.join("store");
        let config_path = config_dir.join("node.json");

        ensure_private_dir(&config_dir).expect("config dir");
        ensure_private_dir(&store_dir).expect("store dir");
        write_private_file(&config_path, br#"{"secret":"node-private-key"}"#)
            .expect("private config");

        assert_eq!(
            fs::metadata(&config_dir)
                .expect("config dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&store_dir)
                .expect("store dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&config_path)
                .expect("config metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(test)]
    fn unique_test_dir(prefix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
