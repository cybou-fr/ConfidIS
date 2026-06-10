use anyhow::{Context, Result, bail};
use confidis_protocol::ErasurePolicy;
use reed_solomon_erasure::galois_8::ReedSolomon;

pub const DEFAULT_SEGMENT_SIZE: usize = 4 * 1024 * 1024;

/// Default padding block size used by [`encode_segment_padded`].
///
/// Inputs are rounded up to the nearest multiple of this value before encoding.
/// One mebibyte is a practical choice: it limits shard-size leakage to within
/// ±1 MiB of the true input size while adding at most 1 MiB of overhead.
pub const DEFAULT_PADDING_BLOCK_SIZE: usize = 1024 * 1024;

/// Maximum input size for in-memory encoding. Larger inputs should use streaming.
pub const MAX_IN_MEMORY_SIZE: usize = 100 * 1024 * 1024; // 100MB

#[derive(Debug, Clone)]
pub struct EncodedSegment {
    pub policy: ErasurePolicy,
    pub original_len: usize,
    pub shard_len: usize,
    pub shards: Vec<Vec<u8>>,
}

/// Encode `input` with Reed-Solomon after padding it to the nearest multiple of
/// `block_size` bytes with zero bytes.
///
/// The `EncodedSegment` preserves `original_len` so that the caller can
/// truncate to the correct size on reconstruction.  An observer watching the
/// wire sees shards of `ceil(round_up(input, block_size) / data_shards)` bytes
/// rather than the exact input length, reducing file-size leakage.
///
/// `block_size` must be non-zero and at most 64 MiB.  Use
/// [`DEFAULT_PADDING_BLOCK_SIZE`] as a sensible default.
pub fn encode_segment_padded(
    input: &[u8],
    policy: &ErasurePolicy,
    block_size: usize,
) -> Result<EncodedSegment> {
    if block_size == 0 {
        bail!("padding block_size must be greater than zero");
    }
    const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024;
    if block_size > MAX_BLOCK_SIZE {
        bail!("padding block_size ({block_size}) exceeds maximum ({MAX_BLOCK_SIZE})");
    }
    // Round input length up to the next multiple of block_size.
    let padded_len = input.len().div_ceil(block_size) * block_size;
    let padded_len = padded_len.max(block_size); // guarantee at least one block
    let mut padded = vec![0u8; padded_len];
    padded[..input.len()].copy_from_slice(input);
    encode_segment(&padded, policy).map(|mut seg| {
        // Override original_len so reconstruction truncates to the true input length.
        seg.original_len = input.len();
        seg
    })
}

pub fn encode_segment(input: &[u8], policy: &ErasurePolicy) -> Result<EncodedSegment> {
    if policy.data_shards == 0 || policy.parity_shards == 0 {
        bail!("erasure policy must have data and parity shards");
    }

    let reed = ReedSolomon::new(policy.data_shards, policy.parity_shards)
        .map_err(|err| anyhow::anyhow!("invalid Reed-Solomon policy: {err:?}"))?;
    let shard_len = input.len().div_ceil(policy.data_shards).max(1);
    let mut shards = vec![vec![0u8; shard_len]; policy.total_shards()];

    for (index, byte) in input.iter().enumerate() {
        let shard_index = index / shard_len;
        let offset = index % shard_len;
        shards[shard_index][offset] = *byte;
    }

    reed.encode(&mut shards)
        .map_err(|err| anyhow::anyhow!("failed to encode Reed-Solomon shards: {err:?}"))?;

    Ok(EncodedSegment {
        policy: policy.clone(),
        original_len: input.len(),
        shard_len,
        shards,
    })
}

/// Encode large inputs using streaming to avoid loading everything into memory.
/// Processes input in chunks and encodes each chunk separately.
pub fn encode_streaming<R: std::io::Read>(
    mut input: R,
    policy: &ErasurePolicy,
    segment_size: usize,
) -> Result<Vec<EncodedSegment>> {
    if policy.data_shards == 0 || policy.parity_shards == 0 {
        bail!("erasure policy must have data and parity shards");
    }

    let mut segments = Vec::new();
    let mut buffer = vec![0u8; segment_size];

    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let segment_data = if bytes_read < segment_size {
            &buffer[..bytes_read]
        } else {
            &buffer
        };

        let segment = encode_segment(segment_data, policy)?;
        segments.push(segment);
    }

    Ok(segments)
}

pub fn reconstruct_segment(
    policy: &ErasurePolicy,
    original_len: usize,
    shards: Vec<Option<Vec<u8>>>,
) -> Result<Vec<u8>> {
    if shards.len() != policy.total_shards() {
        bail!(
            "expected {} shards, got {}",
            policy.total_shards(),
            shards.len()
        );
    }

    let reed = ReedSolomon::new(policy.data_shards, policy.parity_shards)
        .map_err(|err| anyhow::anyhow!("invalid Reed-Solomon policy: {err:?}"))?;
    let mut shards = shards;
    reed.reconstruct(&mut shards)
        .map_err(|err| anyhow::anyhow!("failed to reconstruct Reed-Solomon shards: {err:?}"))?;

    let mut output = Vec::with_capacity(original_len);
    for shard in shards.iter().take(policy.data_shards) {
        let shard = shard.as_ref().context("missing reconstructed data shard")?;
        output.extend_from_slice(shard);
    }
    output.truncate(original_len);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_multi_segment_roundtrips_with_loss() {
        let policy = ErasurePolicy {
            data_shards: 4,
            parity_shards: 2,
        };
        // 1000 bytes with a 256-byte segment ⇒ 4 segments (256,256,256,232).
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let segments = encode_streaming(std::io::Cursor::new(&data), &policy, 256).unwrap();
        assert_eq!(segments.len(), 4);

        let mut restored = Vec::new();
        for (i, seg) in segments.iter().enumerate() {
            // Expected per-segment original length matches the formula get.rs uses.
            let expected_len = (1000usize - i * 256).min(256);
            assert_eq!(seg.original_len, expected_len);
            // Drop one data + one parity shard per segment; must still rebuild.
            let mut shards: Vec<Option<Vec<u8>>> = seg.shards.iter().cloned().map(Some).collect();
            shards[0] = None;
            shards[policy.data_shards] = None;
            let mut seg_bytes = reconstruct_segment(&policy, seg.original_len, shards).unwrap();
            restored.append(&mut seg_bytes);
        }
        assert_eq!(restored, data);
    }

    #[test]
    fn reconstructs_with_missing_parity_and_data() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data = b"confidis reed solomon segment data";
        let encoded = encode_segment(data, &policy).unwrap();
        let mut shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();

        for idx in [0usize, 3, 5, 8, 13, 20, 21, 22, 23, 24] {
            shards[idx] = None;
        }

        let restored = reconstruct_segment(&policy, encoded.original_len, shards).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_zero_byte_payload() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data: &[u8] = b"";

        let encoded = encode_segment(data, &policy).unwrap();
        assert_eq!(encoded.shard_len, 1);

        let mut shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();
        // Drop up to 10 parity shards
        for idx in 0..10 {
            shards[29 - idx] = None;
        }

        let restored = reconstruct_segment(&policy, encoded.original_len, shards).unwrap();
        assert_eq!(restored, data);
        assert_eq!(restored.len(), 0);
    }

    #[test]
    fn test_large_payload() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data = vec![0x42u8; 10 * 1024 * 1024]; // 10MB

        let encoded = encode_segment(&data, &policy).unwrap();
        let mut shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();

        // Drop 10 data shards
        shards.iter_mut().take(10).for_each(|shard| *shard = None);

        let restored = reconstruct_segment(&policy, encoded.original_len, shards).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn test_corruption_beyond_repair() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data = b"CRITICAL_PAYLOAD_TO_BE_CORRUPTED";
        let encoded = encode_segment(data, &policy).unwrap();
        let mut shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();

        for shard in shards.iter_mut().take(11) {
            *shard = None;
        }

        let result = reconstruct_segment(&policy, encoded.original_len, shards);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to reconstruct Reed-Solomon shards"));
        assert!(err.contains("TooFewShardsPresent"));
    }

    #[test]
    fn encode_rejects_zero_data_shards() {
        let policy = ErasurePolicy {
            data_shards: 0,
            parity_shards: 10,
        };
        assert!(encode_segment(b"hello", &policy).is_err());
    }

    #[test]
    fn encode_rejects_zero_parity_shards() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 0,
        };
        assert!(encode_segment(b"hello", &policy).is_err());
    }

    #[test]
    fn reconstruct_rejects_wrong_shard_count() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let shards = vec![Some(vec![0u8; 1]); 15]; // wrong: expected 30
        let err = reconstruct_segment(&policy, 1, shards)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected 30 shards, got 15"), "got: {err}");
    }

    #[test]
    fn parity_only_loss_still_reconstructs() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data = b"all data shards present, all parity lost";
        let encoded = encode_segment(data, &policy).unwrap();
        let mut shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();
        for shard in shards.iter_mut().skip(20) {
            *shard = None;
        }
        let restored = reconstruct_segment(&policy, encoded.original_len, shards).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn exactly_at_recovery_threshold() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data: Vec<u8> = (0u8..100).collect();
        let encoded = encode_segment(&data, &policy).unwrap();
        let mut shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();
        // drop exactly 10 — right at the limit
        shards.iter_mut().take(10).for_each(|shard| *shard = None);
        let restored = reconstruct_segment(&policy, encoded.original_len, shards).unwrap();
        assert_eq!(restored, data);
    }

    // ── encode_segment_padded tests ───────────────────────────────────────────

    #[test]
    fn padded_encodes_and_reconstructs_correctly() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data = b"secret payload";
        let encoded = encode_segment_padded(data, &policy, 1024).unwrap();

        // original_len must reflect the true input length, not the padded length.
        assert_eq!(encoded.original_len, data.len());

        // Every shard must be the same size (padding makes this uniform).
        let shard_len = encoded.shards[0].len();
        assert!(encoded.shards.iter().all(|s| s.len() == shard_len));

        // Reconstruction must recover the exact original bytes.
        let shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();
        let restored = reconstruct_segment(&policy, encoded.original_len, shards).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn padded_shard_size_hides_exact_input_length() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let block_size = 1024 * 1024; // 1 MiB

        // Two inputs of different sizes within the same 1 MiB block must
        // produce shards of identical length.
        let small = vec![1u8; 100];
        let large = vec![2u8; block_size - 1];

        let enc_small = encode_segment_padded(&small, &policy, block_size).unwrap();
        let enc_large = encode_segment_padded(&large, &policy, block_size).unwrap();

        assert_eq!(
            enc_small.shards[0].len(),
            enc_large.shards[0].len(),
            "shard sizes should be equal for inputs in the same padding block"
        );
    }

    #[test]
    fn padded_with_zero_block_size_errors() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        assert!(encode_segment_padded(b"hi", &policy, 0).is_err());
    }

    #[test]
    fn padded_with_oversized_block_size_errors() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        assert!(encode_segment_padded(b"hi", &policy, 64 * 1024 * 1024 + 1).is_err());
    }

    #[test]
    fn padded_reconstruction_with_missing_shards() {
        let policy = ErasurePolicy {
            data_shards: 20,
            parity_shards: 10,
        };
        let data: Vec<u8> = (0u8..200).collect();
        let encoded = encode_segment_padded(&data, &policy, 4096).unwrap();
        let original_len = encoded.original_len;
        let mut shards: Vec<_> = encoded.shards.into_iter().map(Some).collect();
        // Drop 10 shards — right at the recovery limit.
        for idx in [0, 5, 10, 15, 20, 21, 22, 23, 24, 25] {
            shards[idx] = None;
        }
        let restored = reconstruct_segment(&policy, original_len, shards).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn streaming_encoding_works() {
        let policy = ErasurePolicy {
            data_shards: 4,
            parity_shards: 2,
        };
        let data = b"hello world this is a test of streaming erasure coding";
        let segments = encode_streaming(data.as_slice(), &policy, 10).unwrap();

        // Should have multiple segments since data is larger than segment size
        assert!(!segments.is_empty());

        // Verify each segment can be reconstructed
        for segment in segments {
            let shards: Vec<_> = segment.shards.into_iter().map(Some).collect();
            let restored = reconstruct_segment(&policy, segment.original_len, shards).unwrap();
            assert_eq!(restored.len(), segment.original_len);
        }
    }
}
