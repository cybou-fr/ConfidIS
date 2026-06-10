use std::collections::HashSet;

use anyhow::{Result, bail};
use confidis_protocol::{
    ErasurePolicy, NodeCandidate, PlacementPlan, PlacementPolicy, ShardId, ShardPlacement,
};

pub fn build_placement_plan(
    group_id: String,
    erasure_policy: ErasurePolicy,
    shard_ids: &[ShardId],
    candidates: &[NodeCandidate],
    policy: &PlacementPolicy,
) -> Result<PlacementPlan> {
    if candidates.is_empty() {
        bail!("cannot build placement plan without node candidates");
    }
    if shard_ids.len() != erasure_policy.total_shards() {
        bail!(
            "expected {} shard ids for policy, got {}",
            erasure_policy.total_shards(),
            shard_ids.len()
        );
    }

    // Pre-filter: drop candidates below the health floor.
    let eligible: Vec<&NodeCandidate> = if policy.health_score_floor > 0.0 {
        candidates
            .iter()
            .filter(|c| c.health_score >= policy.health_score_floor)
            .collect()
    } else {
        candidates.iter().collect()
    };

    if eligible.is_empty() {
        bail!(
            "no candidates meet the health_score_floor of {}",
            policy.health_score_floor
        );
    }

    let mut used_nodes = HashSet::new();
    let mut used_failure_domains = HashSet::new();
    let mut placements = Vec::with_capacity(shard_ids.len());

    for (shard_index, shard_id) in shard_ids.iter().enumerate() {
        let selected = select_candidate(
            &group_id,
            shard_index,
            &eligible,
            &used_nodes,
            &used_failure_domains,
        );
        used_nodes.insert(selected.node_id.0.clone());
        used_failure_domains.insert(selected.failure_domain.clone());
        placements.push(ShardPlacement {
            shard_index,
            shard_id: shard_id.clone(),
            node_id: selected.node_id.clone(),
            node_public_key: selected.public_key.clone(),
            endpoint: selected.endpoint.clone(),
            failure_domain: selected.failure_domain.clone(),
            region: selected.region.clone(),
        });
    }

    // Post-validate diversity requirements.
    if policy.min_unique_nodes > 0 && used_nodes.len() < policy.min_unique_nodes {
        bail!(
            "placement spans only {} unique nodes; policy requires at least {}",
            used_nodes.len(),
            policy.min_unique_nodes
        );
    }
    if policy.min_failure_domains > 0 && used_failure_domains.len() < policy.min_failure_domains {
        bail!(
            "placement spans only {} failure domains; policy requires at least {}",
            used_failure_domains.len(),
            policy.min_failure_domains
        );
    }

    Ok(PlacementPlan {
        version: 1,
        group_id,
        erasure_policy,
        placements,
        created_at: chrono::Utc::now(),
    })
}

fn select_candidate<'a>(
    group_id: &str,
    shard_index: usize,
    candidates: &[&'a NodeCandidate],
    used_nodes: &HashSet<String>,
    used_failure_domains: &HashSet<String>,
) -> &'a NodeCandidate {
    candidates
        .iter()
        .max_by(|left, right| {
            let left_score = placement_score(
                group_id,
                shard_index,
                left,
                used_nodes,
                used_failure_domains,
            );
            let right_score = placement_score(
                group_id,
                shard_index,
                right,
                used_nodes,
                used_failure_domains,
            );
            left_score.total_cmp(&right_score)
        })
        .expect("candidates checked non-empty")
}

fn placement_score(
    group_id: &str,
    shard_index: usize,
    candidate: &NodeCandidate,
    used_nodes: &HashSet<String>,
    used_failure_domains: &HashSet<String>,
) -> f64 {
    let random = rendezvous_score(group_id, shard_index, &candidate.node_id.0);
    let free_ratio = if candidate.max_bytes == 0 {
        0.0
    } else {
        candidate.free_bytes as f64 / candidate.max_bytes as f64
    };
    let health = candidate.health_score.clamp(0.0, 1.0) as f64;
    let load_penalty = (candidate.current_shard_count as f64).ln_1p() / 100.0;
    let reused_node_penalty = if used_nodes.contains(&candidate.node_id.0) {
        0.35
    } else {
        0.0
    };
    let reused_domain_penalty = if used_failure_domains.contains(&candidate.failure_domain) {
        0.25
    } else {
        0.0
    };

    random + (free_ratio * 0.35) + (health * 0.25)
        - load_penalty
        - reused_node_penalty
        - reused_domain_penalty
}

fn rendezvous_score(group_id: &str, shard_index: usize, node_id: &str) -> f64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(group_id.as_bytes());
    hasher.update(&shard_index.to_be_bytes());
    hasher.update(node_id.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[0..8]);
    u64::from_be_bytes(bytes) as f64 / u64::MAX as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidis_protocol::NodeId;

    fn make_candidates(n: usize) -> Vec<NodeCandidate> {
        (0..n)
            .map(|idx| NodeCandidate {
                node_id: NodeId(format!("node-{idx}")),
                public_key: Some(format!("pk-{idx}")),
                endpoint: format!("http://127.0.0.1:{}", 9000 + idx),
                free_bytes: 1_000_000,
                used_bytes: 0,
                max_bytes: 1_000_000,
                region: "eu-fr".to_string(),
                failure_domain: format!("fd-{}", idx % 10),
                health_score: 1.0,
                current_shard_count: 0,
            })
            .collect()
    }
    fn make_shard_ids(n: usize) -> Vec<ShardId> {
        (0..n).map(|i| ShardId(format!("shard-{i}"))).collect()
    }

    #[test]
    fn builds_plan_for_20_plus_10_no_policy() {
        let candidates = make_candidates(30);
        let shards = make_shard_ids(30);
        let plan = build_placement_plan(
            "group".to_string(),
            ErasurePolicy::default(),
            &shards,
            &candidates,
            &PlacementPolicy::default(),
        )
        .unwrap();
        assert_eq!(plan.placements.len(), 30);
    }

    #[test]
    fn fails_with_no_candidates() {
        let shards = make_shard_ids(30);
        let err = build_placement_plan(
            "g".to_string(),
            ErasurePolicy::default(),
            &shards,
            &[],
            &PlacementPolicy::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("without node candidates"));
    }

    #[test]
    fn fails_wrong_shard_count() {
        let candidates = make_candidates(5);
        let shards = make_shard_ids(5);
        let err = build_placement_plan(
            "g".to_string(),
            ErasurePolicy::default(),
            &shards,
            &candidates,
            &PlacementPolicy::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected 30 shard ids"));
    }

    #[test]
    fn health_floor_filters_unhealthy_candidates() {
        let mut candidates = make_candidates(30);
        // Drop all candidates to health 0.05 — below the floor of 0.1.
        for c in &mut candidates {
            c.health_score = 0.05;
        }
        let shards = make_shard_ids(30);
        let policy = PlacementPolicy {
            health_score_floor: 0.1,
            ..Default::default()
        };
        let err = build_placement_plan(
            "g".to_string(),
            ErasurePolicy::default(),
            &shards,
            &candidates,
            &policy,
        )
        .unwrap_err();
        assert!(err.to_string().contains("health_score_floor"));
    }

    #[test]
    fn health_floor_accepts_healthy_candidates() {
        let mut candidates = make_candidates(30);
        for c in &mut candidates {
            c.health_score = 0.5;
        }
        let shards = make_shard_ids(30);
        let policy = PlacementPolicy {
            health_score_floor: 0.1,
            ..Default::default()
        };
        let plan = build_placement_plan(
            "g".to_string(),
            ErasurePolicy::default(),
            &shards,
            &candidates,
            &policy,
        )
        .unwrap();
        assert_eq!(plan.placements.len(), 30);
    }

    #[test]
    fn min_unique_nodes_enforced() {
        // Only 2 candidates for 30 shards — will reuse nodes heavily.
        let candidates = make_candidates(2);
        let shards = make_shard_ids(30);
        let policy = PlacementPolicy {
            min_unique_nodes: 20,
            ..Default::default()
        };
        let err = build_placement_plan(
            "g".to_string(),
            ErasurePolicy::default(),
            &shards,
            &candidates,
            &policy,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unique nodes"));
        assert!(err.to_string().contains("policy requires at least 20"));
    }

    #[test]
    fn min_failure_domains_enforced() {
        // 30 candidates but all in the same failure domain.
        let mut candidates = make_candidates(30);
        for c in &mut candidates {
            c.failure_domain = "fd-0".to_string();
        }
        let shards = make_shard_ids(30);
        let policy = PlacementPolicy {
            min_failure_domains: 6,
            ..Default::default()
        };
        let err = build_placement_plan(
            "g".to_string(),
            ErasurePolicy::default(),
            &shards,
            &candidates,
            &policy,
        )
        .unwrap_err();
        assert!(err.to_string().contains("failure domains"));
        assert!(err.to_string().contains("policy requires at least 6"));
    }

    #[test]
    fn production_policy_passes_with_adequate_cluster() {
        // 30 nodes, 10 failure domains (3 nodes each) — meets production policy.
        let candidates: Vec<NodeCandidate> = (0..30)
            .map(|idx| NodeCandidate {
                node_id: NodeId(format!("node-{idx}")),
                public_key: Some(format!("pk-{idx}")),
                endpoint: format!("http://127.0.0.1:{}", 9000 + idx),
                free_bytes: 1_000_000,
                used_bytes: 0,
                max_bytes: 1_000_000,
                region: "eu-fr".to_string(),
                failure_domain: format!("fd-{}", idx / 3),
                health_score: 0.9,
                current_shard_count: 0,
            })
            .collect();
        let shards = make_shard_ids(30);
        let policy = PlacementPolicy {
            health_score_floor: 0.1,
            min_failure_domains: 6,
            min_unique_nodes: 20,
        };
        let plan = build_placement_plan(
            "group".to_string(),
            ErasurePolicy::default(),
            &shards,
            &candidates,
            &policy,
        )
        .unwrap();
        assert_eq!(plan.placements.len(), 30);
        let domains: HashSet<_> = plan.placements.iter().map(|p| &p.failure_domain).collect();
        assert!(
            domains.len() >= 6,
            "expected >= 6 failure domains, got {}",
            domains.len()
        );
    }
}
