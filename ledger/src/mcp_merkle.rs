use solana_sha256_hasher::hashv;

const LEAF_DOMAIN: [u8; 1] = [0x00];
const NODE_DOMAIN: [u8; 1] = [0x01];

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum McpMerkleError {
    #[error("commitment root requires at least one shred")]
    EmptyShredSet,
    #[error("too many shreds for u32 indices: {0}")]
    TooManyShreds(usize),
    #[error("invalid leaf index {index} for {num_leaves} leaves")]
    InvalidLeafIndex { index: usize, num_leaves: usize },
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

pub fn witness_for_leaf<const SHRED_DATA_BYTES: usize>(
    slot: u64,
    proposer_index: u32,
    shreds: &[[u8; SHRED_DATA_BYTES]],
    leaf_index: usize,
) -> Result<([u8; 32], Vec<[u8; 32]>), McpMerkleError> {
    if shreds.is_empty() {
        return Err(McpMerkleError::EmptyShredSet);
    }
    if shreds.len() > u32::MAX as usize {
        return Err(McpMerkleError::TooManyShreds(shreds.len()));
    }
    if leaf_index >= shreds.len() {
        return Err(McpMerkleError::InvalidLeafIndex {
            index: leaf_index,
            num_leaves: shreds.len(),
        });
    }

    let mut levels = vec![shreds
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
        .collect::<Result<Vec<_>, McpMerkleError>>()?];

    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len().div_ceil(2));
        for pair in prev.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(hashv(&[&NODE_DOMAIN, &left, &right]).to_bytes());
        }
        levels.push(next);
    }

    let mut witness = Vec::with_capacity(levels.len().saturating_sub(1));
    let mut index = leaf_index;
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling_index = index ^ 1;
        let sibling = level.get(sibling_index).copied().unwrap_or(level[index]);
        witness.push(sibling);
        index >>= 1;
    }

    Ok((levels.last().unwrap()[0], witness))
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
    if shred_index as usize >= num_leaves {
        return Err(McpMerkleError::InvalidLeafIndex {
            index: shred_index as usize,
            num_leaves,
        });
    }
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_len_for_leaf_count() {
        assert_eq!(witness_len_for_leaf_count(1), 0);
        assert_eq!(witness_len_for_leaf_count(2), 1);
        assert_eq!(witness_len_for_leaf_count(3), 2);
        assert_eq!(witness_len_for_leaf_count(200), 8);
    }

    #[test]
    fn test_commitment_root_changes_when_shred_changes() {
        let mut shreds = vec![[0u8; 4]; 4];
        let root_1 = commitment_root(1, 2, &shreds).unwrap();
        shreds[0][0] = 1;
        let root_2 = commitment_root(1, 2, &shreds).unwrap();
        assert_ne!(root_1, root_2);
    }

    #[test]
    fn test_verify_witness_rejects_wrong_witness_len() {
        let shred = [7u8; 4];
        let err = verify_witness(1, 2, 0, &shred, &[], &[0u8; 32], 4).unwrap_err();
        assert_eq!(
            err,
            McpMerkleError::InvalidWitnessLength {
                expected: 2,
                actual: 0
            }
        );
    }

    #[test]
    fn test_witness_generation_and_positive_verification() {
        let shreds = vec![[9u8; 4], [8u8; 4], [7u8; 4], [6u8; 4]];
        let leaf_index = 2usize;
        let (root, witness) = witness_for_leaf(5, 1, &shreds, leaf_index).unwrap();
        assert!(
            verify_witness(
                5,
                1,
                leaf_index as u32,
                &shreds[leaf_index],
                &witness,
                &root,
                shreds.len(),
            )
            .unwrap()
        );
    }

    #[test]
    fn test_witness_rejects_out_of_range_leaf_index() {
        let shreds = vec![[1u8; 4], [2u8; 4], [3u8; 4], [4u8; 4]];
        let err = witness_for_leaf(1, 1, &shreds, shreds.len()).unwrap_err();
        assert_eq!(
            err,
            McpMerkleError::InvalidLeafIndex {
                index: shreds.len(),
                num_leaves: shreds.len(),
            }
        );
    }
}
