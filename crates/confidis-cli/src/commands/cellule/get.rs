use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use confidis_erasure::reconstruct_segment;

use crate::network::{DiscoveredNode, discover_node_endpoints, network_client, normalize_endpoint};

use super::helpers::{
    decrypt_manifest, publish_record, resolve_manifest, verify_cellule_record_signature,
};
use super::types::CelluleGetArgs;

const NETWORK_GET_MAX_ATTEMPTS: usize = 4;

fn is_transient_get_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

pub(super) async fn send_get_with_retry<F>(mut build_request: F) -> Result<reqwest::Response>
where
    F: FnMut() -> Result<reqwest::RequestBuilder>,
{
    for attempt in 0..NETWORK_GET_MAX_ATTEMPTS {
        let response = build_request()?.send().await?;
        let status = response.status();
        if status.is_success()
            || !is_transient_get_status(status)
            || attempt + 1 == NETWORK_GET_MAX_ATTEMPTS
        {
            return Ok(response);
        }
        let delay_ms = 50_u64 * (1_u64 << attempt);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    unreachable!("GET retry loop always returns on its final attempt")
}

pub(super) async fn cellule_get(args: CelluleGetArgs) -> Result<Vec<u8>> {
    let client = network_client()?;
    let (record, manifest) = match resolve_manifest(&args) {
        Ok(resolved) => resolved,
        Err(local_err) => {
            let record = resolve_cellule_record_from_network(&client, &args)
                .await
                .with_context(|| {
                    format!("local Cellule manifest resolution failed: {local_err}")
                })?;
            let encrypted_manifest = resolve_encrypted_manifest_from_network(&client, &args, &record)
                .await
                .with_context(|| {
                    format!(
                        "local Cellule manifest resolution failed and network manifest fetch failed: {local_err}"
                    )
                })?;
            let manifest = decrypt_manifest(&args, &record, &encrypted_manifest)?;
            let _ = publish_record(&args.registry, record.clone());
            crate::commands::blob::write_blob(
                &args.blob_store,
                &record.manifest_cid,
                &encrypted_manifest,
            )?;
            (record, manifest)
        }
    };
    let now = chrono::Utc::now();
    if record.deletion_due_at(now) {
        bail!(
            "Cellule expired at {}; deletion is due immediately and restore is closed",
            record.expires_at.to_rfc3339()
        );
    }
    restore_from_manifest(&manifest, Some(args.private_key.as_str()), &args.nodes).await
}

async fn resolve_cellule_record_from_network(
    client: &reqwest::Client,
    args: &CelluleGetArgs,
) -> Result<confidis_protocol::CellulePublicRecord> {
    for endpoint in resolve_registry_endpoints(client, &args.nodes).await {
        let response = match client
            .get(format!(
                "{}/cellule-records/{}",
                endpoint.trim_end_matches('/'),
                args.cellule_id
            ))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let record: confidis_protocol::CellulePublicRecord = response
            .json()
            .await
            .context("invalid Cellule record response")?;
        if record.cellule_id.0 != args.cellule_id {
            continue;
        }
        verify_cellule_record_signature(&record).context("invalid network Cellule record")?;
        return Ok(record);
    }
    bail!("Cellule record not found in local registry or network nodes")
}

async fn resolve_encrypted_manifest_from_network(
    client: &reqwest::Client,
    args: &CelluleGetArgs,
    record: &confidis_protocol::CellulePublicRecord,
) -> Result<Vec<u8>> {
    for endpoint in resolve_registry_endpoints(client, &args.nodes).await {
        let response = match client
            .get(format!(
                "{}/manifests/{}",
                endpoint.trim_end_matches('/'),
                record.manifest_cid
            ))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => continue,
        };
        if !response.status().is_success() {
            continue;
        }
        let bytes = response.bytes().await?.to_vec();
        let actual = confidis_crypto::blake3_hex(&bytes);
        if actual == record.manifest_cid {
            return Ok(bytes);
        }
    }
    bail!(
        "encrypted manifest {} not found in local blob store or network nodes",
        record.manifest_cid
    )
}

pub(super) async fn restore_from_manifest(
    manifest: &confidis_protocol::Manifest,
    node_private_key: Option<&str>,
    provider_registry_nodes: &[String],
) -> Result<Vec<u8>> {
    let client = network_client()?;
    let total = manifest.erasure_policy.total_shards();
    let segment_count = manifest
        .shards
        .iter()
        .map(|d| d.segment_index)
        .max()
        .map(|m| m + 1)
        .unwrap_or(1);

    let mut output = Vec::with_capacity(manifest.original_size_bytes as usize);
    for si in 0..segment_count {
        let seg_descriptors: Vec<&confidis_protocol::ShardDescriptor> = manifest
            .shards
            .iter()
            .filter(|d| d.segment_index == si)
            .collect();
        let shards = fetch_segment_shards(
            &client,
            &seg_descriptors,
            total,
            node_private_key,
            provider_registry_nodes,
        )
        .await?;
        let fetched = shards.iter().filter(|s| s.is_some()).count();
        if fetched < manifest.erasure_policy.data_shards {
            bail!(
                "segment {si}: not enough valid shards: fetched {}, need {}",
                fetched,
                manifest.erasure_policy.data_shards
            );
        }
        let seg_len = confidis_protocol::segment_original_len(
            manifest.original_size_bytes,
            manifest.segment_size_bytes,
            si,
        ) as usize;
        let mut seg = reconstruct_segment(&manifest.erasure_policy, seg_len, shards)?;
        output.append(&mut seg);
    }
    Ok(output)
}

/// Fetch the shards of one segment, indexed by `shard_index`.
pub(super) async fn fetch_segment_shards(
    client: &reqwest::Client,
    descriptors: &[&confidis_protocol::ShardDescriptor],
    total_shards: usize,
    node_private_key: Option<&str>,
    provider_registry_nodes: &[String],
) -> Result<Vec<Option<Vec<u8>>>> {
    let mut shards = vec![None; total_shards];
    for descriptor in descriptors {
        if descriptor.shard_index >= total_shards || shards[descriptor.shard_index].is_some() {
            continue;
        }
        let endpoints =
            resolve_provider_endpoints(client, descriptor, provider_registry_nodes).await;
        for endpoint in endpoints {
            let endpoint = endpoint.trim_end_matches('/');
            let url = format!("{}/shards/{}", endpoint, descriptor.shard_id.0);
            let proof = match node_private_key {
                Some(pk) => Some(crate::network::node_access_proof_headers(
                    pk,
                    "GET",
                    &descriptor.shard_id.0,
                )?),
                None => None,
            };
            let response = match send_get_with_retry(|| {
                let mut req = client.get(&url);
                if let Some(proof) = &proof {
                    for (k, v) in proof {
                        req = req.header(*k, v);
                    }
                }
                Ok(req)
            })
            .await
            {
                Ok(response) => response,
                Err(_) => continue,
            };
            if !response.status().is_success() {
                continue;
            }
            let bytes = response.bytes().await?.to_vec();
            if confidis_crypto::blake3_hex(&bytes) != descriptor.shard_id.0 {
                continue;
            }
            shards[descriptor.shard_index] = Some(bytes);
            break;
        }
    }
    Ok(shards)
}

pub(super) async fn resolve_provider_endpoints(
    client: &reqwest::Client,
    descriptor: &confidis_protocol::ShardDescriptor,
    provider_registry_nodes: &[String],
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut endpoints = Vec::new();
    let provider_discovery = resolve_provider_registry_nodes(client, provider_registry_nodes).await;

    for node in provider_discovery.registry_nodes {
        let node = node.trim_end_matches('/');
        let url = format!("{node}/providers/{}", descriptor.shard_id.0);
        let response = match send_get_with_retry(|| Ok(client.get(&url))).await {
            Ok(response) if response.status().is_success() => response,
            _ => continue,
        };
        let text = match response.text().await {
            Ok(text) => text,
            Err(_) => continue,
        };
        let list: confidis_protocol::ShardProviderList = match serde_json::from_str(&text) {
            Ok(list) => list,
            Err(_) => continue,
        };
        if list.shard_id != descriptor.shard_id {
            continue;
        }
        for record in list.providers {
            if confidis_protocol::verify_shard_provider_record(&record).is_err() {
                continue;
            }
            if record.shard_id != descriptor.shard_id
                || record.shard_index != descriptor.shard_index
                || record.segment_index != descriptor.segment_index
            {
                continue;
            }
            if !provider_record_matches_discovered_identity(
                &record,
                &provider_discovery.provider_public_keys,
            ) {
                continue;
            }
            if seen.insert(record.endpoint.clone()) {
                endpoints.push(record.endpoint);
            }
        }
    }

    for endpoint in &descriptor.provider_hints {
        if seen.insert(endpoint.clone()) {
            endpoints.push(endpoint.clone());
        }
    }

    endpoints
}

async fn resolve_registry_endpoints(client: &reqwest::Client, seeds: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut endpoints = Vec::new();
    for seed in seeds {
        let endpoint = normalize_endpoint(seed);
        if seen.insert(endpoint.clone()) {
            endpoints.push(endpoint);
        }
    }
    if let Ok(discovered) = discover_node_endpoints(client, seeds).await {
        for node in discovered {
            let endpoint = normalize_endpoint(&node.endpoint);
            if seen.insert(endpoint.clone()) {
                endpoints.push(endpoint);
            }
        }
    }
    endpoints
}

struct ProviderRegistryResolution {
    registry_nodes: Vec<String>,
    provider_public_keys: HashMap<String, String>,
}

async fn resolve_provider_registry_nodes(
    client: &reqwest::Client,
    seeds: &[String],
) -> ProviderRegistryResolution {
    let mut seen = HashSet::new();
    let mut registry_nodes = Vec::new();
    let mut provider_public_keys = HashMap::new();
    for seed in seeds {
        let endpoint = normalize_endpoint(seed);
        if seen.insert(endpoint.clone()) {
            registry_nodes.push(endpoint);
        }
    }
    if let Ok(discovered) = discover_node_endpoints(client, seeds).await {
        for node in &discovered {
            remember_discovered_provider_identity(&mut provider_public_keys, node);
        }
        for node in discovered {
            let endpoint = normalize_endpoint(&node.endpoint);
            if seen.insert(endpoint.clone()) {
                registry_nodes.push(endpoint);
            }
        }
    }
    ProviderRegistryResolution {
        registry_nodes,
        provider_public_keys,
    }
}

fn remember_discovered_provider_identity(
    provider_public_keys: &mut HashMap<String, String>,
    node: &DiscoveredNode,
) {
    let Some(public_key) = node.public_key.as_ref() else {
        return;
    };
    provider_public_keys
        .entry(normalize_endpoint(&node.endpoint))
        .or_insert_with(|| public_key.clone());
}

fn provider_record_matches_discovered_identity(
    record: &confidis_protocol::ShardProviderRecord,
    provider_public_keys: &HashMap<String, String>,
) -> bool {
    let endpoint = normalize_endpoint(&record.endpoint);
    provider_public_keys
        .get(&endpoint)
        .is_none_or(|public_key| public_key == &record.public_key)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex};
    use confidis_protocol::{
        CelluleId, NodeId, PeerList, PeerRecord, ShardDescriptor, ShardId, ShardProviderList,
        ShardProviderRecord, peer_record_signing_payload, shard_provider_record_signing_payload,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    use super::resolve_provider_endpoints;

    fn signed_provider_record(endpoint: &str, shard_id: &ShardId) -> ShardProviderRecord {
        signed_provider_record_with_key(endpoint, shard_id, &generate_signing_key())
    }

    fn signed_provider_record_with_key(
        endpoint: &str,
        shard_id: &ShardId,
        key: &ed25519_dalek::SigningKey,
    ) -> ShardProviderRecord {
        let now = Utc::now();
        let mut record = ShardProviderRecord {
            version: 1,
            provider_record_id: Uuid::new_v4(),
            cellule_id: CelluleId("cellule-test".to_string()),
            manifest_id: Uuid::new_v4(),
            shard_id: shard_id.clone(),
            shard_index: 7,
            segment_index: 2,
            node_id: confidis_protocol::NodeId("provider-node".to_string()),
            public_key: verifying_key_to_hex(&key.verifying_key()),
            endpoint: endpoint.to_string(),
            region: "eu-fr".to_string(),
            failure_domain: "fd-provider".to_string(),
            receipt_id: Uuid::new_v4(),
            receipt_signature: "00".repeat(64),
            issued_at: now,
            expires_at: Some(now + chrono::Duration::minutes(10)),
            signature: None,
        };
        let payload = shard_provider_record_signing_payload(&record).expect("payload");
        record.signature = Some(sign_hex(key, &payload));
        record
    }

    fn signed_peer_record(endpoint: &str) -> PeerRecord {
        signed_peer_record_with_key(endpoint, &generate_signing_key())
    }

    fn signed_peer_record_with_key(endpoint: &str, key: &ed25519_dalek::SigningKey) -> PeerRecord {
        let now = Utc::now();
        let mut record = PeerRecord {
            endpoint: endpoint.to_string(),
            node_id: Some(NodeId("registry-node".to_string())),
            public_key: Some(verifying_key_to_hex(&key.verifying_key())),
            region: Some("eu-fr".to_string()),
            failure_domain: Some("fd-registry".to_string()),
            issued_at: Some(now),
            expires_at: Some(now + chrono::Duration::minutes(10)),
            signature: None,
        };
        let payload = peer_record_signing_payload(&record).expect("peer payload");
        record.signature = Some(sign_hex(key, &payload));
        record
    }

    async fn serve_provider_registry(record: ShardProviderRecord) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut request = [0_u8; 1024];
                let read = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                let (status, body) = if request.starts_with("GET /peers ") {
                    (
                        "200 OK",
                        serde_json::to_string(&PeerList {
                            version: 1,
                            issued_at: Utc::now(),
                            peers: Vec::new(),
                        })
                        .expect("peer list json"),
                    )
                } else if request.starts_with("GET /providers/") {
                    (
                        "200 OK",
                        serde_json::to_string(&ShardProviderList {
                            version: 1,
                            issued_at: Utc::now(),
                            shard_id: record.shard_id.clone(),
                            providers: vec![record.clone()],
                        })
                        .expect("provider list json"),
                    )
                } else {
                    ("404 Not Found", "{}".to_string())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });
        endpoint
    }

    async fn serve_peer_seed(peers: Vec<PeerRecord>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            let body = serde_json::to_string(&PeerList {
                version: 1,
                issued_at: Utc::now(),
                peers,
            })
            .expect("peer list json");
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        endpoint
    }

    #[tokio::test]
    async fn provider_registry_endpoints_precede_manifest_hints() {
        let shard_id = ShardId("shard-1".to_string());
        let provider_endpoint = "http://127.0.0.1:39001";
        let registry =
            serve_provider_registry(signed_provider_record(provider_endpoint, &shard_id)).await;
        let descriptor = ShardDescriptor {
            shard_id,
            shard_index: 7,
            segment_index: 2,
            size_bytes: 12,
            provider_hints: vec!["http://127.0.0.1:39999".to_string()],
            region: Some("eu-fr".to_string()),
            failure_domain: Some("fd-provider".to_string()),
        };

        let endpoints =
            resolve_provider_endpoints(&reqwest::Client::new(), &descriptor, &[registry]).await;

        assert_eq!(endpoints[0], provider_endpoint);
        assert!(endpoints.contains(&"http://127.0.0.1:39999".to_string()));
    }

    #[tokio::test]
    async fn provider_registry_nodes_are_discovered_from_signed_peers() {
        let shard_id = ShardId("shard-2".to_string());
        let provider_endpoint = "http://127.0.0.1:39002";
        let registry =
            serve_provider_registry(signed_provider_record(provider_endpoint, &shard_id)).await;
        let seed = serve_peer_seed(vec![signed_peer_record(&registry)]).await;
        let descriptor = ShardDescriptor {
            shard_id,
            shard_index: 7,
            segment_index: 2,
            size_bytes: 12,
            provider_hints: vec!["http://127.0.0.1:39998".to_string()],
            region: Some("eu-fr".to_string()),
            failure_domain: Some("fd-provider".to_string()),
        };

        let endpoints =
            resolve_provider_endpoints(&reqwest::Client::new(), &descriptor, &[seed]).await;

        assert_eq!(endpoints[0], provider_endpoint);
        assert!(endpoints.contains(&"http://127.0.0.1:39998".to_string()));
    }

    #[tokio::test]
    async fn provider_record_endpoint_identity_must_match_signed_peer_identity() {
        let shard_id = ShardId("shard-3".to_string());
        let provider_endpoint = "http://127.0.0.1:39003";
        let fallback_endpoint = "http://127.0.0.1:39997";
        let honest_provider_key = generate_signing_key();
        let attacker_key = generate_signing_key();
        let registry = serve_provider_registry(signed_provider_record_with_key(
            provider_endpoint,
            &shard_id,
            &attacker_key,
        ))
        .await;
        let seed = serve_peer_seed(vec![signed_peer_record_with_key(
            provider_endpoint,
            &honest_provider_key,
        )])
        .await;
        let descriptor = ShardDescriptor {
            shard_id,
            shard_index: 7,
            segment_index: 2,
            size_bytes: 12,
            provider_hints: vec![fallback_endpoint.to_string()],
            region: Some("eu-fr".to_string()),
            failure_domain: Some("fd-provider".to_string()),
        };

        let endpoints =
            resolve_provider_endpoints(&reqwest::Client::new(), &descriptor, &[registry, seed])
                .await;

        assert_eq!(endpoints, vec![fallback_endpoint.to_string()]);
    }
}
