use {
    solana_clock::Slot,
    solana_hash::{Hash, HASH_BYTES},
    solana_pubkey::Pubkey,
    solana_signature::{Signature, SIGNATURE_BYTES},
    solana_signer::Signer,
};

pub const CONSENSUS_BLOCK_V1: u8 = 1;
const HEADER_LEN: usize = 1 + 8 + 4 + 4 + 4;
const TRAILER_LEN: usize = HASH_BYTES + SIGNATURE_BYTES;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsensusBlock {
    pub version: u8,
    pub slot: Slot,
    pub leader_index: u32,
    pub aggregate_bytes: Vec<u8>,
    pub consensus_meta: Vec<u8>,
    pub delayed_bankhash: Hash,
    pub leader_signature: Signature,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ConsensusBlockError {
    #[error("unknown consensus block version: {0}")]
    UnknownVersion(u8),
    #[error("aggregate bytes length exceeds u32::MAX: {0}")]
    AggregateLengthOverflow(usize),
    #[error("consensus_meta length exceeds u32::MAX: {0}")]
    ConsensusMetaLengthOverflow(usize),
    #[error("consensus block is truncated")]
    Truncated,
    #[error("consensus block has trailing bytes")]
    TrailingBytes,
}

impl ConsensusBlock {
    pub fn new_unsigned(
        slot: Slot,
        leader_index: u32,
        aggregate_bytes: Vec<u8>,
        consensus_meta: Vec<u8>,
        delayed_bankhash: Hash,
    ) -> Result<Self, ConsensusBlockError> {
        if aggregate_bytes.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::AggregateLengthOverflow(
                aggregate_bytes.len(),
            ));
        }
        if consensus_meta.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::ConsensusMetaLengthOverflow(
                consensus_meta.len(),
            ));
        }

        Ok(Self {
            version: CONSENSUS_BLOCK_V1,
            slot,
            leader_index,
            aggregate_bytes,
            consensus_meta,
            delayed_bankhash,
            leader_signature: Signature::default(),
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ConsensusBlockError> {
        if self.aggregate_bytes.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::AggregateLengthOverflow(
                self.aggregate_bytes.len(),
            ));
        }
        if self.consensus_meta.len() > u32::MAX as usize {
            return Err(ConsensusBlockError::ConsensusMetaLengthOverflow(
                self.consensus_meta.len(),
            ));
        }

        let mut out = Vec::with_capacity(
            HEADER_LEN + self.aggregate_bytes.len() + self.consensus_meta.len() + HASH_BYTES,
        );
        out.push(self.version);
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.leader_index.to_le_bytes());
        out.extend_from_slice(&(self.aggregate_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.aggregate_bytes);
        out.extend_from_slice(&(self.consensus_meta.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.consensus_meta);
        out.extend_from_slice(self.delayed_bankhash.as_ref());
        Ok(out)
    }

    pub fn to_wire_bytes(&self) -> Result<Vec<u8>, ConsensusBlockError> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(self.leader_signature.as_ref());
        Ok(bytes)
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ConsensusBlockError> {
        if bytes.len() < HEADER_LEN + TRAILER_LEN {
            return Err(ConsensusBlockError::Truncated);
        }

        let mut cursor = 0usize;
        let version = read_u8(bytes, &mut cursor)?;
        if version != CONSENSUS_BLOCK_V1 {
            return Err(ConsensusBlockError::UnknownVersion(version));
        }

        let slot = read_u64_le(bytes, &mut cursor)?;
        let leader_index = read_u32_le(bytes, &mut cursor)?;
        let aggregate_len = read_u32_le(bytes, &mut cursor)? as usize;
        let aggregate_bytes = read_vec(bytes, &mut cursor, aggregate_len)?;
        let consensus_meta_len = read_u32_le(bytes, &mut cursor)? as usize;
        let consensus_meta = read_vec(bytes, &mut cursor, consensus_meta_len)?;
        let delayed_bankhash = Hash::new_from_array(read_array::<HASH_BYTES>(bytes, &mut cursor)?);
        let leader_signature = Signature::from(read_array::<SIGNATURE_BYTES>(bytes, &mut cursor)?);

        if cursor != bytes.len() {
            return Err(ConsensusBlockError::TrailingBytes);
        }

        Ok(Self {
            version,
            slot,
            leader_index,
            aggregate_bytes,
            consensus_meta,
            delayed_bankhash,
            leader_signature,
        })
    }

    pub fn sign_leader<T: Signer>(&mut self, signer: &T) -> Result<(), ConsensusBlockError> {
        let signing_bytes = self.signing_bytes()?;
        self.leader_signature = signer.sign_message(&signing_bytes);
        Ok(())
    }

    pub fn verify_leader_signature(&self, leader_pubkey: &Pubkey) -> bool {
        let Ok(signing_bytes) = self.signing_bytes() else {
            return false;
        };
        self.leader_signature
            .verify(leader_pubkey.as_ref(), &signing_bytes)
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ConsensusBlockError> {
    if *cursor + 1 > bytes.len() {
        return Err(ConsensusBlockError::Truncated);
    }
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u32_le(bytes: &[u8], cursor: &mut usize) -> Result<u32, ConsensusBlockError> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor)?))
}

fn read_u64_le(bytes: &[u8], cursor: &mut usize) -> Result<u64, ConsensusBlockError> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>, ConsensusBlockError> {
    if *cursor + len > bytes.len() {
        return Err(ConsensusBlockError::Truncated);
    }
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ConsensusBlockError> {
    if *cursor + N > bytes.len() {
        return Err(ConsensusBlockError::Truncated);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use {super::*, solana_keypair::Keypair};

    #[test]
    fn test_roundtrip_and_signature_verification() {
        let leader = Keypair::new();
        let mut block = ConsensusBlock::new_unsigned(
            88,
            7,
            vec![1, 2, 3, 4],
            vec![9, 8, 7],
            Hash::new_unique(),
        )
        .unwrap();
        block.sign_leader(&leader).unwrap();

        let bytes = block.to_wire_bytes().unwrap();
        let decoded = ConsensusBlock::from_wire_bytes(&bytes).unwrap();

        assert_eq!(decoded, block);
        assert!(decoded.verify_leader_signature(&leader.pubkey()));
    }

    #[test]
    fn test_signature_verification_fails_after_tamper() {
        let leader = Keypair::new();
        let mut block =
            ConsensusBlock::new_unsigned(1, 2, vec![5, 6, 7], vec![10, 11], Hash::new_unique())
                .unwrap();
        block.sign_leader(&leader).unwrap();
        assert!(block.verify_leader_signature(&leader.pubkey()));

        block.consensus_meta.push(99);
        assert!(!block.verify_leader_signature(&leader.pubkey()));
    }

    #[test]
    fn test_unknown_version_rejected() {
        let bytes = vec![2u8; HEADER_LEN + TRAILER_LEN];
        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::UnknownVersion(2)
        );
    }

    #[test]
    fn test_trailing_bytes_rejected() {
        let leader = Keypair::new();
        let mut block =
            ConsensusBlock::new_unsigned(1, 2, vec![5, 6, 7], vec![10, 11], Hash::new_unique())
                .unwrap();
        block.sign_leader(&leader).unwrap();

        let mut bytes = block.to_wire_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            ConsensusBlock::from_wire_bytes(&bytes).unwrap_err(),
            ConsensusBlockError::TrailingBytes
        );
    }
}
