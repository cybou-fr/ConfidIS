use chrono::Utc;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn node_tokens_are_32_byte_hex_values() {
    let confidis = confidis_bin();

    let ui_token = run(&confidis, &["node", "gen-token"]);
    let compliance_token = run(&confidis, &["node", "gen-compliance-token"]);

    assert_hex_32(ui_token.trim());
    assert_hex_32(compliance_token.trim());
    assert_ne!(ui_token.trim(), compliance_token.trim());
}

#[test]
fn node_init_config_writes_checkable_operator_config() {
    let confidis = confidis_bin();
    let temp = test_dir("confidis-node-init-config");
    fs::create_dir_all(&temp).expect("create temp dir");

    let keys = run(&confidis, &["init-key"]);
    let private_key = parse_key(&keys, "private_key");
    let output = temp.join("node.json");
    let store = temp.join("store");
    let registry = temp.join("cellules.json");
    let packages = temp.join("packages.json");
    let token = run(&confidis, &["node", "gen-token"]);

    run(
        &confidis,
        &[
            "node",
            "init-config",
            "--node-id",
            "operator-test-node",
            "--listen-addr",
            "127.0.0.1:4433",
            "--public-endpoint",
            "https://operator.example.test",
            "--store-path",
            path_str(&store),
            "--private-key",
            &private_key,
            "--registry-path",
            path_str(&registry),
            "--packages-path",
            path_str(&packages),
            "--ui-token",
            token.trim(),
            "--ui-allowed-origin",
            "https://operator.example.test",
            path_str(&output),
        ],
    );

    let config: Value = read_json(&output);
    assert_eq!(config["node"]["node_id"], "operator-test-node");
    assert_eq!(config["node_id"], "operator-test-node");
    assert_eq!(
        config["network"]["public_endpoint"],
        "https://operator.example.test"
    );
    assert_eq!(config["security"]["ui_token"], token.trim());
    assert_eq!(
        config["ui"]["ui_allowed_origin"],
        "https://operator.example.test"
    );
    assert_eq!(config["storage"]["store_path"], store.display().to_string());
    assert_eq!(
        config["storage"]["registry_path"],
        registry.display().to_string()
    );
    assert_eq!(
        config["storage"]["packages_path"],
        packages.display().to_string()
    );
    assert_eq!(config["storage_backend"]["backend_type"], "filesystem");

    let check = run(&confidis, &["node", "check-config", path_str(&output)]);
    assert!(check.contains("Configuration loaded successfully"));
    assert!(check.contains("node_id=operator-test-node"));
    assert!(check.contains("ok"));
}

#[test]
fn node_init_config_production_defaults_quotas_and_webui_path() {
    let confidis = confidis_bin();
    let temp = test_dir("confidis-node-production-defaults");
    fs::create_dir_all(&temp).expect("create temp dir");

    let config_path = temp.join("node.json");
    let store_path = temp.join("store");
    let token = run(&confidis, &["node", "gen-token"]);

    run(
        &confidis,
        &[
            "node",
            "init-config",
            "--node-id",
            "node-prod-defaults",
            "--production-profile",
            "--listen-addr",
            "127.0.0.1:4433",
            "--public-endpoint",
            "https://prod.example.test",
            "--store-path",
            path_str(&store_path),
            "--ui-token",
            token.trim(),
            "--ui-allowed-origin",
            "https://prod.example.test",
            path_str(&config_path),
        ],
    );

    let config = read_json(&config_path);
    assert_eq!(config["production_profile"], true);
    assert_eq!(config["usage"]["max_shards_per_owner_per_hour"], 1000);
    assert_eq!(config["usage"]["max_cellules_per_owner"], 100);
    assert_eq!(config["webui_path"], "/usr/share/confidis/webui");
    assert_eq!(config["ui"]["webui_path"], "/usr/share/confidis/webui");

    let check = run(&confidis, &["node", "check-config", path_str(&config_path)]);
    assert!(check.contains("Configuration loaded successfully"));
    assert!(check.contains("production_profile=true") || check.contains("production_profile=yes"));

    let _ = fs::remove_dir_all(temp);
}

#[test]
fn cellule_sign_create_writes_verifiable_owner_authorization() {
    let confidis = confidis_bin();
    let temp = test_dir("confidis-cellule-sign-create");
    fs::create_dir_all(&temp).expect("create temp dir");
    let wallet = run(&confidis, &["wallet", "create"]);
    let private_key = parse_key(&wallet, "private_key");
    let public_key = parse_key(&wallet, "public_key");
    let output = temp.join("cellule-owner-create.json");

    run(
        &confidis,
        &[
            "cellule",
            "sign-create",
            "--public-key",
            &public_key,
            "--private-key",
            &private_key,
            "--cellule-id",
            "operator-cli-cellule",
            "--label",
            "operator test",
            "--retention-days",
            "30",
            "--reserved-bytes",
            "64",
            "--output",
            path_str(&output),
        ],
    );

    let create: confidis_protocol::CelluleOwnerCreate =
        serde_json::from_value(read_json(&output)).expect("CelluleOwnerCreate JSON");
    assert_eq!(create.cellule_id.0, "operator-cli-cellule");
    assert_eq!(create.owner_public_key, public_key);
    assert_eq!(create.retention_days, 30);
    assert_eq!(create.reserved_bytes, 64);
    assert_eq!(create.signature.len(), 128);
    confidis_protocol::verify_cellule_owner_create(&create, Utc::now()).expect("valid owner create");
}
#[cfg(any())]
#[test]
fn authority_init_keypair_writes_valid_hex_key_files() {
    let confidis = confidis_bin();
    let temp = test_dir("confidis-authority-init-keypair");
    fs::create_dir_all(&temp).expect("create temp dir");
    let pubkey_out = temp.join("authority.pub");
    let privkey_out = temp.join("authority.key");

    let out = run(
        &confidis,
        &[
            "authority",
            "init-keypair",
            "--pubkey-out",
            path_str(&pubkey_out),
            "--privkey-out",
            path_str(&privkey_out),
        ],
    );

    assert!(out.contains("Authority keypair generated."));
    assert_hex_32(fs::read_to_string(pubkey_out).expect("pubkey").trim());
    assert_hex_32(fs::read_to_string(privkey_out).expect("privkey").trim());
}
#[cfg(any())]
#[test]
fn authority_init_keyset_writes_threshold_public_set_and_private_keys() {
    let confidis = confidis_bin();
    let temp = test_dir("confidis-authority-init-keyset");
    fs::create_dir_all(&temp).expect("create temp dir");
    let out_dir = temp.join("authority-keyset");

    let out = run(
        &confidis,
        &[
            "authority",
            "init-keyset",
            "--count",
            "3",
            "--threshold",
            "2",
            "--out-dir",
            path_str(&out_dir),
            "--prefix",
            "genesis",
        ],
    );

    assert!(out.contains("Threshold : 2-of-3"));
    let authority_set: Value = read_json(&out_dir.join("authority-set.json"));
    assert_eq!(authority_set["threshold"], 2);
    let public_keys = authority_set["public_keys"]
        .as_array()
        .expect("public_keys array");
    assert_eq!(public_keys.len(), 3);
    for index in 1..=3 {
        assert_hex_32(
            public_keys[index - 1]
                .as_str()
                .expect("public key string in set"),
        );
        assert_hex_32(
            fs::read_to_string(out_dir.join(format!("genesis-{index}.pub")))
                .expect("pub file")
                .trim(),
        );
        assert_hex_32(
            fs::read_to_string(out_dir.join(format!("genesis-{index}.key")))
                .expect("key file")
                .trim(),
        );
    }
}
#[cfg(any())]
#[test]
fn authority_signs_and_verifies_release_artifact_manifest() {
    let confidis = confidis_bin();
    let temp = test_dir("confidis-authority-release-signature");
    fs::create_dir_all(&temp).expect("create temp dir");
    let pubkey_out = temp.join("release.pub");
    let privkey_out = temp.join("release.key");
    run(
        &confidis,
        &[
            "authority",
            "init-keypair",
            "--pubkey-out",
            path_str(&pubkey_out),
            "--privkey-out",
            path_str(&privkey_out),
        ],
    );

    let artifact = temp.join("confidis-test_0.0.0_amd64.deb");
    fs::write(&artifact, b"not a real deb, just a signed test artifact").expect("artifact");
    let signature = temp.join("confidis-test_0.0.0_amd64.deb.sig.json");
    let out = run(
        &confidis,
        &[
            "authority",
            "sign-release",
            "--artifact",
            path_str(&artifact),
            "--privkey",
            path_str(&privkey_out),
            "--out",
            path_str(&signature),
        ],
    );
    assert!(out.contains("Release artifact signed:"));

    let sig_json: Value = read_json(&signature);
    assert_eq!(sig_json["version"], 1);
    assert_eq!(sig_json["context"], "confidis-release-artifact-signature-v1");
    assert_eq!(sig_json["artifact_name"], "confidis-test_0.0.0_amd64.deb");
    assert_hex_32(sig_json["artifact_blake3"].as_str().expect("artifact hash"));
    assert_eq!(
        sig_json["signer_public_key"],
        fs::read_to_string(&pubkey_out).expect("pubkey").trim()
    );
    assert_eq!(
        sig_json["signature"].as_str().expect("signature").len(),
        128
    );

    let verify = run(
        &confidis,
        &[
            "authority",
            "verify-release",
            "--artifact",
            path_str(&artifact),
            "--signature",
            path_str(&signature),
            "--pubkey",
            fs::read_to_string(&pubkey_out).expect("pubkey").trim(),
        ],
    );
    assert!(verify.contains("Release artifact signature is VALID"));
}
#[cfg(any())]
#[test]
fn authority_release_signature_supports_threshold_authority_set() {
    let temp = test_dir("confidis-threshold-release-signature");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).expect("create tempdir");
    let confidis = confidis_bin();
    let keyset_dir = temp.join("authority-keyset");

    run(
        &confidis,
        &[
            "authority",
            "init-keyset",
            "--count",
            "3",
            "--threshold",
            "2",
            "--out-dir",
            path_str(&keyset_dir),
        ],
    );

    let artifact = temp.join("confidis-test_0.0.0_amd64.deb");
    fs::write(&artifact, b"threshold signed release test artifact").expect("artifact");
    let signature = temp.join("confidis-test_0.0.0_amd64.deb.sig.json");
    let authority_set = keyset_dir.join("authority-set.json");
    let key1 = keyset_dir.join("authority-1.key");
    let key2 = keyset_dir.join("authority-2.key");

    let out = run(
        &confidis,
        &[
            "authority",
            "sign-release",
            "--artifact",
            path_str(&artifact),
            "--authority-set",
            path_str(&authority_set),
            "--privkey",
            path_str(&key1),
            "--privkey",
            path_str(&key2),
            "--out",
            path_str(&signature),
        ],
    );
    assert!(out.contains("quorum   : 2-of-3"));

    let sig_json: Value = read_json(&signature);
    assert_eq!(sig_json["version"], 2);
    assert_eq!(sig_json["context"], "confidis-release-artifact-signature-v2");
    assert_eq!(sig_json["authority_threshold"], 2);
    assert_eq!(
        sig_json["authority_public_keys"]
            .as_array()
            .expect("authority public keys")
            .len(),
        3
    );
    assert_eq!(
        sig_json["authority_signatures"]
            .as_array()
            .expect("authority signatures")
            .len(),
        2
    );

    let verify = run(
        &confidis,
        &[
            "authority",
            "verify-release",
            "--artifact",
            path_str(&artifact),
            "--signature",
            path_str(&signature),
            "--authority-set",
            path_str(&authority_set),
        ],
    );
    assert!(verify.contains("Release artifact signature is VALID"));
}

fn confidis_bin() -> PathBuf {
    std::env::var("CARGO_BIN_EXE_confidis")
        .map(PathBuf::from)
        .or_else(|_| {
            option_env!("CARGO_BIN_EXE_confidis")
                .map(PathBuf::from)
                .ok_or(())
        })
        .unwrap_or_else(|_| PathBuf::from("target/debug/confidis"))
}

fn run(confidis: &Path, args: &[&str]) -> String {
    let output = Command::new(confidis)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run confidis {args:?}: {err}"));
    assert_success(args, &output);
    String::from_utf8(output.stdout).expect("stdout utf8")
}

fn assert_success(args: &[&str], output: &Output) {
    if !output.status.success() {
        panic!(
            "confidis {:?} failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn assert_hex_32(value: &str) {
    assert_eq!(value.len(), 64, "expected 32-byte hex, got {value}");
    assert!(
        value.as_bytes().iter().all(|b| b.is_ascii_hexdigit()),
        "expected hex, got {value}"
    );
}

fn parse_key(output: &str, key: &str) -> String {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&format!("{key}:")) {
            return rest.trim().to_string();
        }
        if let Some(rest) = trimmed.strip_prefix(&format!("{key}=")) {
            return rest.trim().to_string();
        }
    }
    panic!("missing {key} in output:\n{output}");
}

fn read_json(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|err| panic!("json {}: {err}", path.display()))
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}

fn test_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}
