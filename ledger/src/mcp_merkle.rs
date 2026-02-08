use solana_sha256_hasher::hashv;

const LEAF_DOMAIN: [u8; 1] = [0x00];
const NODE_DOMAIN: [u8; 1] = [0x01];

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum McpMerkleError {
    #[error("commitment root requires at least one shred")]
    EmptyShredSet,
    #[error("too many shreds for u32 indices: {0}")]
    TooManyShreds(usize),
    #[error("invalid witness length: expected {expected}, got {actual}")]
    InvalidWitnessLength { expected: usize, actual: usize },
}

pub const fn witness_len_for_leaf_count(num_leaves: usize) -> usize {
    if num_leaves <= 1 {
        return 0;
    }
    let mut width = 1usize;
    let mut depth = 0usize;
    while width < num_leaves {
        width <<= 1;
        depth += 1;
    }
    depth
}

pub fn commitment_root<const SHRED_DATA_BYTES: usize>(
    slot: u64,
    proposer_index: u32,
    shreds: &[[u8; SHRED_DATA_BYTES]],
) -> Result<[u8; 32], McpMerkleError> {
    if shreds.is_empty() {
        return Err(McpMerkleError::EmptyShredSet);
    }
    if shreds.len() > u32::MAX as usize {
        return Err(McpMerkleError::TooManyShreds(shreds.len()));
    }

    let mut level: Vec<[u8; 32]> = shreds
        .iter()
        .enumerate()
        .map(|(shred_index, shred_data)| {
            let shred_index =
                u32::try_from(shred_index).map_err(|_| McpMerkleError::TooManyShreds(shreds.len()))?;
            Ok(hashv(&[
                &LEAF_DOMAIN,
                &slot.to_le_bytes(),
                &proposer_index.to_le_bytes(),
                &shred_index.to_le_bytes(),
                shred_data,
            ])
            .to_bytes())
        })
        .collect::<Result<Vec<_>, McpMerkleError>>()?;

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(hashv(&[&NODE_DOMAIN, &left, &right]).to_bytes());
        }
        level = next;
    }

    Ok(level[0])
}

pub fn verify_witness<const SHRED_DATA_BYTES: usize>(
    slot: u64,
    proposer_index: u32,
    shred_index: u32,
    shred_data: &[u8; SHRED_DATA_BYTES],
    witness: &[[u8; 32]],
    expected_commitment: &[u8; 32],
    num_leaves: usize,
) -> Result<bool, McpMerkleError> {
    let expected_witness_len = witness_len_for_leaf_count(num_leaves);
    if witness.len() != expected_witness_len {
        return Err(McpMerkleError::InvalidWitnessLength {
            expected: expected_witness_len,
            actual: witness.len(),
        });
    }

    let leaf = hashv(&[
        &LEAF_DOMAIN,
        &slot.to_le_bytes(),
        &proposer_index.to_le_bytes(),
        &shred_index.to_le_bytes(),
        shred_data,
    ])
    .to_bytes();

    let mut node = leaf;
    let mut index = shred_index as usize;
    for sibling in witness {
        node = if index & 1 == 0 {
            hashv(&[&NODE_DOMAIN, &node, sibling]).to_bytes()
        } else {
            hashv(&[&NODE_DOMAIN, sibling, &node]).to_bytes()
        };
        index >>= 1;
    }
    Ok(&node == expected_commitment)
}
