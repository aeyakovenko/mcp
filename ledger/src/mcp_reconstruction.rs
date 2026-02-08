use {reed_solomon_erasure::galois_8::ReedSolomon, solana_sha256_hasher::hashv};

pub const MCP_RECON_DATA_SHREDS: usize = 40;
pub const MCP_RECON_CODING_SHREDS: usize = 160;
pub const MCP_RECON_NUM_SHREDS: usize = MCP_RECON_DATA_SHREDS + MCP_RECON_CODING_SHREDS;
pub const MCP_RECON_SHRED_BYTES: usize = 863;
pub const MCP_RECON_MAX_PAYLOAD_BYTES: usize = MCP_RECON_DATA_SHREDS * MCP_RECON_SHRED_BYTES;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum McpReconstructionError {
    #[error("invalid payload length: {0}")]
    InvalidPayloadLength(usize),
    #[error("invalid shard layout: expected {expected}, got {actual}")]
    InvalidShardLayout { expected: usize, actual: usize },
    #[error("insufficient shards: present {present}, required {required}")]
    InsufficientShards { present: usize, required: usize },
    #[error("commitment mismatch")]
    CommitmentMismatch,
    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
}

pub fn reconstruct_payload(
    slot: u64,
    proposer_index: u32,
    payload_len: usize,
    expected_commitment: [u8; 32],
    shards: &mut [Option<[u8; MCP_RECON_SHRED_BYTES]>],
) -> Result<Vec<u8>, McpReconstructionError> {
    if payload_len > MCP_RECON_MAX_PAYLOAD_BYTES {
        return Err(McpReconstructionError::InvalidPayloadLength(payload_len));
    }
    if shards.len() != MCP_RECON_NUM_SHREDS {
        return Err(McpReconstructionError::InvalidShardLayout {
            expected: MCP_RECON_NUM_SHREDS,
            actual: shards.len(),
        });
    }

    let present = shards.iter().filter(|shard| shard.is_some()).count();
    if present < MCP_RECON_DATA_SHREDS {
        return Err(McpReconstructionError::InsufficientShards {
            present,
            required: MCP_RECON_DATA_SHREDS,
        });
    }

    let mut rs_shards: Vec<Option<Vec<u8>>> = shards
        .iter_mut()
        .map(|shard| shard.take().map(Vec::from))
        .collect();
    ReedSolomon::new(MCP_RECON_DATA_SHREDS, MCP_RECON_CODING_SHREDS)
        .map_err(|err| McpReconstructionError::ReedSolomon(err.to_string()))?
        .reconstruct(&mut rs_shards)
        .map_err(|err| McpReconstructionError::ReedSolomon(err.to_string()))?;

    let mut rebuilt = Vec::with_capacity(MCP_RECON_NUM_SHREDS);
    for shard in &rs_shards {
        let Some(shard) = shard else {
            return Err(McpReconstructionError::InsufficientShards {
                present,
                required: MCP_RECON_DATA_SHREDS,
            });
        };
        let mut bytes = [0u8; MCP_RECON_SHRED_BYTES];
        bytes.copy_from_slice(shard);
        rebuilt.push(bytes);
    }

    let computed = commitment_root(slot, proposer_index, &rebuilt);
    if computed != expected_commitment {
        return Err(McpReconstructionError::CommitmentMismatch);
    }

    // Restore caller shards after reconstruction.
    for (index, shard) in rebuilt.iter().copied().enumerate() {
        shards[index] = Some(shard);
    }

    let mut payload = Vec::with_capacity(MCP_RECON_MAX_PAYLOAD_BYTES);
    for shard in rebuilt.into_iter().take(MCP_RECON_DATA_SHREDS) {
        payload.extend_from_slice(&shard);
    }
    payload.truncate(payload_len);
    Ok(payload)
}

pub fn commitment_root(
    slot: u64,
    proposer_index: u32,
    shreds: &[[u8; MCP_RECON_SHRED_BYTES]],
) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = shreds
        .iter()
        .enumerate()
        .map(|(shred_index, shred_data)| {
            hashv(&[
                &[0x00],
                &slot.to_le_bytes(),
                &proposer_index.to_le_bytes(),
                &(shred_index as u32).to_le_bytes(),
                shred_data,
            ])
            .to_bytes()
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(hashv(&[&[0x01], &left, &right]).to_bytes());
        }
        level = next;
    }

    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_payload(payload: &[u8]) -> Vec<[u8; MCP_RECON_SHRED_BYTES]> {
        let mut data = vec![[0u8; MCP_RECON_SHRED_BYTES]; MCP_RECON_DATA_SHREDS];
        for (i, chunk) in payload.chunks(MCP_RECON_SHRED_BYTES).enumerate() {
            data[i][..chunk.len()].copy_from_slice(chunk);
        }

        let mut shards: Vec<Vec<u8>> = data.iter().copied().map(Vec::from).collect();
        shards.extend(std::iter::repeat_n(
            vec![0u8; MCP_RECON_SHRED_BYTES],
            MCP_RECON_CODING_SHREDS,
        ));

        ReedSolomon::new(MCP_RECON_DATA_SHREDS, MCP_RECON_CODING_SHREDS)
            .unwrap()
            .encode(&mut shards)
            .unwrap();

        shards
            .into_iter()
            .map(|shard| {
                let mut out = [0u8; MCP_RECON_SHRED_BYTES];
                out.copy_from_slice(&shard);
                out
            })
            .collect()
    }

    #[test]
    fn test_reconstruct_valid_payload() {
        let payload: Vec<u8> = (0..20_000).map(|i| (i % 255) as u8).collect();
        let shreds = encode_payload(&payload);
        let root = commitment_root(9, 2, &shreds);

        let mut sparse = vec![None; MCP_RECON_NUM_SHREDS];
        for i in (0..20).chain(120..140) {
            sparse[i] = Some(shreds[i]);
        }

        let decoded = reconstruct_payload(9, 2, payload.len(), root, &mut sparse).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_reconstruct_rejects_commitment_mismatch() {
        let payload: Vec<u8> = (0..1000).map(|i| (i % 255) as u8).collect();
        let mut shreds = encode_payload(&payload);
        let root = commitment_root(9, 2, &shreds);
        shreds[3][0] ^= 1;

        let mut sparse = vec![None; MCP_RECON_NUM_SHREDS];
        for i in 0..MCP_RECON_DATA_SHREDS {
            sparse[i] = Some(shreds[i]);
        }

        assert_eq!(
            reconstruct_payload(9, 2, payload.len(), root, &mut sparse).unwrap_err(),
            McpReconstructionError::CommitmentMismatch
        );
    }

    #[test]
    fn test_reconstruct_rejects_insufficient_shards() {
        let payload = vec![7u8; 500];
        let shreds = encode_payload(&payload);
        let root = commitment_root(1, 0, &shreds);

        let mut sparse = vec![None; MCP_RECON_NUM_SHREDS];
        for i in 0..39 {
            sparse[i] = Some(shreds[i]);
        }

        assert_eq!(
            reconstruct_payload(1, 0, payload.len(), root, &mut sparse).unwrap_err(),
            McpReconstructionError::InsufficientShards {
                present: 39,
                required: MCP_RECON_DATA_SHREDS
            }
        );
    }
}
