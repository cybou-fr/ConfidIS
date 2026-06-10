use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use confidis_protocol::{
    NodeCandidate, NodeCapacityReport, NodeId, PeerList, peer_record_signing_payload,
};

use crate::verify::{verify_capacity_matches_discovery, verify_capacity_report_if_signed};

const MAX_DISCOVERY_HOPS: usize = 3;
const MAX_DISCOVERED_ENDPOINTS: usize = 256;
const MIN_USABLE_STORAGE_BYTES: u64 = 1024;

/// Build the signed node shard-access identity proof headers for an inter-node
/// shard request. Optional in development (the serving node allows requests
/// without it); required when the serving node runs `production_profile` so the
/// authority ban list binds to shard operations. Returns
/// `(x-confidis-node-pubkey, x-confidis-node-ts, x-confidis-node-sig)`.
pub(crate) fn node_access_proof_headers(
    private_key_hex: &str,
    method: &str,
    shard_id: &str,
) -> Result<[(&'static str, String); 3]> {
    let signing_key = confidis_crypto::signing_key_from_hex(private_key_hex)
        .context("invalid private key for node access proof")?;
    let pubkey = confidis_crypto::verifying_key_to_hex(&signing_key.verifying_key());
    let issued = chrono::Utc::now();
    let payload = confidis_protocol::shard_access_proof_payload(&pubkey, method, shard_id, issued);
    let sig = confidis_crypto::sign_hex(&signing_key, &payload);
    Ok([
        ("x-confidis-node-pubkey", pubkey),
        ("x-confidis-node-ts", issued.to_rfc3339()),
        ("x-confidis-node-sig", sig),
    ])
}

#[derive(Debug, Clone, Default)]
pub(crate) struct NetworkConfig {
    pub(crate) trusted_ca: Vec<PathBuf>,
}

pub(crate) static NETWORK_CONFIG: OnceLock<NetworkConfig> = OnceLock::new();

#[derive(Debug, Clone)]
pub(crate) struct DiscoveredNode {
    pub(crate) endpoint: String,
    pub(crate) node_id: Option<NodeId>,
    pub(crate) public_key: Option<String>,
}

pub(crate) async fn fetch_candidates(
    client: &reqwest::Client,
    nodes: &[String],
) -> Result<Vec<NodeCandidate>> {
    let discovered = discover_node_endpoints(client, nodes).await?;
    let mut candidates = Vec::with_capacity(discovered.len());
    let mut skipped = Vec::new();
    for discovered_node in discovered {
        let endpoint = discovered_node.endpoint.clone();
        let url = format!("{}/capacity", endpoint);
        let response = match client.get(url).send().await {
            Ok(response) => response,
            Err(err) => {
                skipped.push(format!("{endpoint}: {err}"));
                continue;
            }
        };
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            skipped.push(format!("{endpoint}: {status} {text}"));
            continue;
        }
        let report: NodeCapacityReport =
            serde_json::from_str(&text).context("invalid capacity report")?;
        if let Err(err) = verify_capacity_report_if_signed(&report)
            .with_context(|| format!("invalid signed capacity report from {endpoint}"))
            .and_then(|_| verify_capacity_matches_discovery(&endpoint, &report, &discovered_node))
        {
            skipped.push(format!("{endpoint}: {err:#}"));
            continue;
        }
        if report.max_bytes < MIN_USABLE_STORAGE_BYTES
            || report.free_bytes < MIN_USABLE_STORAGE_BYTES
        {
            skipped.push(format!("{endpoint}: insufficient free storage capacity"));
            continue;
        }
        candidates.push(NodeCandidate {
            node_id: report.node_id,
            public_key: report.public_key,
            endpoint,
            free_bytes: report.free_bytes,
            used_bytes: report.used_bytes,
            max_bytes: report.max_bytes,
            region: report.region,
            failure_domain: report.failure_domain,
            health_score: report.health_score,
            current_shard_count: report.current_shard_count,
        });
    }
    if candidates.is_empty() {
        let detail = if skipped.is_empty() {
            "no endpoints discovered".to_string()
        } else {
            skipped.join("; ")
        };
        bail!("no usable storage nodes found: {detail}");
    }
    Ok(candidates)
}

pub(crate) async fn discover_node_endpoints(
    client: &reqwest::Client,
    seeds: &[String],
) -> Result<Vec<DiscoveredNode>> {
    let mut indexes = HashMap::new();
    let mut endpoints = Vec::new();
    let mut queue = VecDeque::new();
    let mut fetched = HashSet::new();

    for seed in seeds {
        let seed = normalize_endpoint(seed);
        upsert_discovered_node(
            &mut endpoints,
            &mut indexes,
            DiscoveredNode {
                endpoint: seed.clone(),
                node_id: None,
                public_key: None,
            },
        );
        queue.push_back((seed, 0usize));
    }

    while let Some((endpoint, depth)) = queue.pop_front() {
        if !fetched.insert(endpoint.clone()) {
            continue;
        }
        let url = format!("{}/peers", endpoint);
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(peer_list) = response.json::<PeerList>().await else {
            continue;
        };
        for peer in peer_list.peers {
            if !peer_record_is_usable(&peer) {
                continue;
            }
            let normalized = normalize_endpoint(&peer.endpoint);
            upsert_discovered_node(
                &mut endpoints,
                &mut indexes,
                DiscoveredNode {
                    endpoint: normalized.clone(),
                    node_id: peer.node_id.clone(),
                    public_key: peer.public_key.clone(),
                },
            );
            if endpoints.len() >= MAX_DISCOVERED_ENDPOINTS {
                return Ok(endpoints);
            }
            if depth < MAX_DISCOVERY_HOPS && peer_record_is_signed_and_valid(&peer) {
                queue.push_back((normalized, depth + 1));
            }
        }
    }
    Ok(endpoints)
}

pub(crate) fn upsert_discovered_node(
    endpoints: &mut Vec<DiscoveredNode>,
    indexes: &mut HashMap<String, usize>,
    node: DiscoveredNode,
) {
    if let Some(index) = indexes.get(&node.endpoint).copied() {
        let existing = &mut endpoints[index];
        if existing.node_id.is_none() {
            existing.node_id = node.node_id;
        }
        if existing.public_key.is_none() {
            existing.public_key = node.public_key;
        }
        return;
    }
    indexes.insert(node.endpoint.clone(), endpoints.len());
    endpoints.push(node);
}

pub(crate) fn peer_record_is_usable(record: &confidis_protocol::PeerRecord) -> bool {
    if !peer_record_has_signed_fields(record) {
        return true;
    }
    verify_peer_record(record).is_ok()
}

fn peer_record_is_signed_and_valid(record: &confidis_protocol::PeerRecord) -> bool {
    peer_record_has_signed_fields(record) && verify_peer_record(record).is_ok()
}

fn peer_record_has_signed_fields(record: &confidis_protocol::PeerRecord) -> bool {
    record.public_key.is_some()
        || record.issued_at.is_some()
        || record.expires_at.is_some()
        || record.signature.is_some()
}

pub(crate) fn verify_peer_record(record: &confidis_protocol::PeerRecord) -> Result<()> {
    let public_key = record
        .public_key
        .as_deref()
        .context("signed peer record missing public_key")?;
    let issued_at = record
        .issued_at
        .context("signed peer record missing issued_at")?;
    let expires_at = record
        .expires_at
        .context("signed peer record missing expires_at")?;
    let signature = record
        .signature
        .as_deref()
        .context("signed peer record missing signature")?;
    if expires_at <= issued_at {
        bail!("signed peer record expires before issued_at");
    }
    let now = chrono::Utc::now();
    if now > expires_at {
        bail!("signed peer record expired");
    }
    if issued_at > now + chrono::Duration::minutes(5) {
        bail!("signed peer record issued_at is too far in the future");
    }
    let key = confidis_crypto::verifying_key_from_hex(public_key)?;
    let payload = peer_record_signing_payload(record)?;
    confidis_crypto::verify_hex(&key, &payload, signature)
}

pub(crate) fn normalize_endpoint(endpoint: &str) -> String {
    endpoint.trim_end_matches('/').to_string()
}

pub(crate) fn network_client() -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    let config = NETWORK_CONFIG.get().cloned().unwrap_or_default();
    for ca_path in config.trusted_ca {
        let bytes = fs::read(&ca_path)
            .with_context(|| format!("failed to read trusted CA {}", ca_path.display()))?;
        let certificate = reqwest::Certificate::from_pem(&bytes)
            .with_context(|| format!("invalid PEM trusted CA {}", ca_path.display()))?;
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().context("failed to build network client")
}

pub(crate) async fn print_response(response: reqwest::Response) -> Result<()> {
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        bail!("remote request failed: {status} {text}");
    }
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use confidis_crypto::{generate_signing_key, sign_hex, verifying_key_to_hex};
    use confidis_protocol::{
        NodeCapacityReport, NodeId, PeerList, PeerRecord, capacity_report_signing_payload,
        peer_record_signing_payload,
    };
    use ed25519_dalek::SigningKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        discover_node_endpoints, fetch_candidates, peer_record_is_signed_and_valid,
        peer_record_is_usable,
    };

    fn signed_peer(endpoint: &str) -> PeerRecord {
        let key = generate_signing_key();
        signed_peer_with_key(endpoint, "peer-1", &key)
    }

    fn signed_peer_with_key(endpoint: &str, node_id: &str, key: &SigningKey) -> PeerRecord {
        let now = Utc::now();
        let mut record = PeerRecord {
            endpoint: endpoint.to_string(),
            node_id: Some(NodeId(node_id.to_string())),
            public_key: Some(verifying_key_to_hex(&key.verifying_key())),
            region: Some("eu-fr".to_string()),
            failure_domain: Some("fd-1".to_string()),
            issued_at: Some(now),
            expires_at: Some(now + chrono::Duration::minutes(10)),
            signature: None,
        };
        let payload = peer_record_signing_payload(&record).expect("payload");
        record.signature = Some(sign_hex(key, &payload));
        record
    }

    fn signed_capacity(node_id: &str, key: &SigningKey) -> NodeCapacityReport {
        let mut report = NodeCapacityReport {
            node_id: NodeId(node_id.to_string()),
            public_key: Some(verifying_key_to_hex(&key.verifying_key())),
            free_bytes: 1_000_000,
            used_bytes: 0,
            max_bytes: 1_000_000,
            reserved_bytes: 0,
            region: "eu-fr".to_string(),
            failure_domain: "fd-1".to_string(),
            health_score: 1.0,
            current_shard_count: 0,
            issued_at: Utc::now(),
            signature: None,
        };
        let payload = capacity_report_signing_payload(&report).expect("capacity payload");
        report.signature = Some(sign_hex(key, &payload));
        report
    }

    fn tiny_capacity(node_id: &str, key: &SigningKey) -> NodeCapacityReport {
        let mut report = signed_capacity(node_id, key);
        report.free_bytes = 1;
        report.max_bytes = 1;
        report.signature = None;
        let payload = capacity_report_signing_payload(&report).expect("capacity payload");
        report.signature = Some(sign_hex(key, &payload));
        report
    }

    #[test]
    fn unsigned_peer_record_is_usable_but_not_recursive_discovery_material() {
        let record = PeerRecord {
            endpoint: "http://127.0.0.1:3001".to_string(),
            node_id: None,
            public_key: None,
            region: None,
            failure_domain: None,
            issued_at: None,
            expires_at: None,
            signature: None,
        };

        assert!(peer_record_is_usable(&record));
        assert!(!peer_record_is_signed_and_valid(&record));
    }

    #[test]
    fn signed_peer_record_is_recursive_discovery_material() {
        let record = signed_peer("http://127.0.0.1:3001");

        assert!(peer_record_is_usable(&record));
        assert!(peer_record_is_signed_and_valid(&record));
    }

    #[test]
    fn tampered_signed_peer_record_is_not_usable() {
        let mut record = signed_peer("http://127.0.0.1:3001");
        record.endpoint = "http://127.0.0.1:3999".to_string();

        assert!(!peer_record_is_usable(&record));
        assert!(!peer_record_is_signed_and_valid(&record));
    }

    async fn serve_peer_list(peers: Vec<PeerRecord>) -> String {
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

    async fn serve_test_node(
        peers: Vec<PeerRecord>,
        capacity: Option<NodeCapacityReport>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut request = [0_u8; 2048];
                let read = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..read]);
                let body = if request.starts_with("GET /capacity ") {
                    match &capacity {
                        Some(report) => serde_json::to_string(report).expect("capacity json"),
                        None => "{}".to_string(),
                    }
                } else {
                    serde_json::to_string(&PeerList {
                        version: 1,
                        issued_at: Utc::now(),
                        peers: peers.clone(),
                    })
                    .expect("peer list json")
                };
                let status = if request.starts_with("GET /capacity ") && capacity.is_none() {
                    "404 Not Found"
                } else {
                    "200 OK"
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

    #[tokio::test]
    async fn recursive_discovery_follows_signed_peer_records() {
        let peer_c = serve_peer_list(Vec::new()).await;
        let peer_b = serve_peer_list(vec![signed_peer(&peer_c)]).await;
        let seed = serve_peer_list(vec![signed_peer(&peer_b)]).await;
        let client = reqwest::Client::new();

        let discovered = discover_node_endpoints(&client, std::slice::from_ref(&seed))
            .await
            .expect("discover");
        let endpoints = discovered
            .iter()
            .map(|node| node.endpoint.as_str())
            .collect::<Vec<_>>();

        assert!(endpoints.contains(&seed.as_str()));
        assert!(endpoints.contains(&peer_b.as_str()));
        assert!(endpoints.contains(&peer_c.as_str()));
    }

    #[tokio::test]
    async fn fetch_candidates_uses_signed_peer_discovery_for_capacity() {
        let storage_key = generate_signing_key();
        let storage_capacity = signed_capacity("storage-peer", &storage_key);
        let storage_endpoint = serve_test_node(Vec::new(), Some(storage_capacity.clone())).await;
        let seed_key = generate_signing_key();
        let seed = serve_test_node(
            vec![signed_peer_with_key(
                &storage_endpoint,
                "storage-peer",
                &storage_key,
            )],
            Some(tiny_capacity("seed-peer", &seed_key)),
        )
        .await;
        let client = reqwest::Client::new();

        let candidates = fetch_candidates(&client, &[seed])
            .await
            .expect("candidates");

        assert!(candidates.iter().any(|candidate| {
            candidate.endpoint == storage_endpoint
                && candidate.node_id.0 == "storage-peer"
                && candidate.public_key == storage_capacity.public_key
        }));
    }
}
