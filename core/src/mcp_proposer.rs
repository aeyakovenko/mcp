use {
    solana_clock::Slot,
    solana_pubkey::Pubkey,
    solana_sha256_hasher::hashv,
    solana_signature::{Signature, SIGNATURE_BYTES},
    thiserror::Error,
};

pub const MCP_NUM_RELAYS: usize = 200;
pub const MCP_SHRED_DATA_BYTES: usize = 863;
pub const MCP_WITNESS_LEN: usize = mcp_witness_len(MCP_NUM_RELAYS);

pub const MCP_SHRED_MESSAGE_SIZE: usize = std::mem::size_of::<Slot>()
    + std::mem::size_of::<u32>() // proposer_index
    + std::mem::size_of::<u32>() // shred_index
    + 32 // commitment
    + MCP_SHRED_DATA_BYTES
    + 1 // witness_len
    + (32 * MCP_WITNESS_LEN)
    + SIGNATURE_BYTES;

const LEAF_DOMAIN: [u8; 1] = [0x00];
const NODE_DOMAIN: [u8; 1] = [0x01];

const fn mcp_witness_len(num_relays: usize) -> usize {
    let mut width = 1usize;
    let mut depth = 0usize;
    while width < num_relays {
        width <<= 1;
        depth += 1;
    }
    depth
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum McpProposerError {
    #[error("relay list size mismatch: expected {expected}, got {actual}")]
    RelayCountMismatch { expected: usize, actual: usize },
    #[error("shred list size mismatch: expected {expected}, got {actual}")]
    ShredCountMismatch { expected: usize, actual: usize },
    #[error("witness list size mismatch: expected {expected}, got {actual}")]
    WitnessCountMismatch { expected: usize, actual: usize },
    #[error("invalid MCP shred message size: expected {expected}, got {actual}")]
    InvalidMessageSize { expected: usize, actual: usize },
    #[error("invalid witness length: expected {expected}, got {actual}")]
    InvalidWitnessLength { expected: usize, actual: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpShredMessage {
    pub slot: Slot,
    pub proposer_index: u32,
    pub shred_index: u32,
    pub commitment: [u8; 32],
    pub shred_data: [u8; MCP_SHRED_DATA_BYTES],
    pub witness: [[u8; 32]; MCP_WITNESS_LEN],
    pub proposer_signature: Signature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayUnicast {
    pub relay_pubkey: Pubkey,
    pub message: McpShredMessage,
}

impl McpShredMessage {
    pub fn to_bytes(&self) -> [u8; MCP_SHRED_MESSAGE_SIZE] {
        let mut data = [0u8; MCP_SHRED_MESSAGE_SIZE];
        let mut offset = 0usize;

        data[offset..offset + std::mem::size_of::<Slot>()]
            .copy_from_slice(&self.slot.to_le_bytes());
        offset += std::mem::size_of::<Slot>();
        data[offset..offset + std::mem::size_of::<u32>()]
            .copy_from_slice(&self.proposer_index.to_le_bytes());
        offset += std::mem::size_of::<u32>();
        data[offset..offset + std::mem::size_of::<u32>()]
            .copy_from_slice(&self.shred_index.to_le_bytes());
        offset += std::mem::size_of::<u32>();
        data[offset..offset + 32].copy_from_slice(&self.commitment);
        offset += 32;
        data[offset..offset + MCP_SHRED_DATA_BYTES].copy_from_slice(&self.shred_data);
        offset += MCP_SHRED_DATA_BYTES;
        data[offset] = MCP_WITNESS_LEN as u8;
        offset += 1;
        for sibling in &self.witness {
            data[offset..offset + 32].copy_from_slice(sibling);
            offset += 32;
        }
        data[offset..offset + SIGNATURE_BYTES].copy_from_slice(self.proposer_signature.as_ref());

        data
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, McpProposerError> {
        if data.len() != MCP_SHRED_MESSAGE_SIZE {
            return Err(McpProposerError::InvalidMessageSize {
                expected: MCP_SHRED_MESSAGE_SIZE,
                actual: data.len(),
            });
        }
        let witness_len_offset = std::mem::size_of::<Slot>()
            + std::mem::size_of::<u32>()
            + std::mem::size_of::<u32>()
            + 32
            + MCP_SHRED_DATA_BYTES;
        let witness_len = data[witness_len_offset] as usize;
        if witness_len != MCP_WITNESS_LEN {
            return Err(McpProposerError::InvalidWitnessLength {
                expected: MCP_WITNESS_LEN,
                actual: witness_len,
            });
        }

        let mut offset = 0usize;
        let slot = Slot::from_le_bytes(
            data[offset..offset + std::mem::size_of::<Slot>()]
                .try_into()
                .unwrap(),
        );
        offset += std::mem::size_of::<Slot>();
        let proposer_index = u32::from_le_bytes(
            data[offset..offset + std::mem::size_of::<u32>()]
                .try_into()
                .unwrap(),
        );
        offset += std::mem::size_of::<u32>();
        let shred_index = u32::from_le_bytes(
            data[offset..offset + std::mem::size_of::<u32>()]
                .try_into()
                .unwrap(),
        );
        offset += std::mem::size_of::<u32>();

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut shred_data = [0u8; MCP_SHRED_DATA_BYTES];
        shred_data.copy_from_slice(&data[offset..offset + MCP_SHRED_DATA_BYTES]);
        offset += MCP_SHRED_DATA_BYTES;

        // witness_len is validated above.
        offset += 1;

        let mut witness = [[0u8; 32]; MCP_WITNESS_LEN];
        for sibling in &mut witness {
            sibling.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
        }

        let proposer_signature = Signature::from(
            <[u8; SIGNATURE_BYTES]>::try_from(&data[offset..offset + SIGNATURE_BYTES]).unwrap(),
        );

        Ok(Self {
            slot,
            proposer_index,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature,
        })
    }

    pub fn verify_for_relay(&self, relay_index: u32, proposer_pubkey: &Pubkey) -> bool {
        self.shred_index == relay_index
            && self
                .proposer_signature
                .verify(proposer_pubkey.as_ref(), &self.commitment)
            && self.verify_witness()
    }

    fn verify_witness(&self) -> bool {
        let leaf = hashv(&[
            &LEAF_DOMAIN,
            &self.slot.to_le_bytes(),
            &self.proposer_index.to_le_bytes(),
            &self.shred_index.to_le_bytes(),
            &self.shred_data,
        ])
        .to_bytes();

        let mut node = leaf;
        let mut index = self.shred_index as usize;
        for sibling in &self.witness {
            node = if index & 1 == 0 {
                hashv(&[&NODE_DOMAIN, &node, sibling]).to_bytes()
            } else {
                hashv(&[&NODE_DOMAIN, sibling, &node]).to_bytes()
            };
            index >>= 1;
        }

        node == self.commitment
    }
}

pub fn build_relay_unicasts(
    slot: Slot,
    proposer_index: u32,
    commitment: [u8; 32],
    shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
    witnesses: &[[[u8; 32]; MCP_WITNESS_LEN]],
    proposer_signature: Signature,
    relays: &[Pubkey],
) -> Result<Vec<RelayUnicast>, McpProposerError> {
    if relays.len() != MCP_NUM_RELAYS {
        return Err(McpProposerError::RelayCountMismatch {
            expected: MCP_NUM_RELAYS,
            actual: relays.len(),
        });
    }
    if shreds.len() != MCP_NUM_RELAYS {
        return Err(McpProposerError::ShredCountMismatch {
            expected: MCP_NUM_RELAYS,
            actual: shreds.len(),
        });
    }
    if witnesses.len() != MCP_NUM_RELAYS {
        return Err(McpProposerError::WitnessCountMismatch {
            expected: MCP_NUM_RELAYS,
            actual: witnesses.len(),
        });
    }

    Ok(relays
        .iter()
        .copied()
        .enumerate()
        .map(|(i, relay_pubkey)| RelayUnicast {
            relay_pubkey,
            message: McpShredMessage {
                slot,
                proposer_index,
                shred_index: i as u32,
                commitment,
                shred_data: shreds[i],
                witness: witnesses[i],
                proposer_signature,
            },
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use {super::*, solana_keypair::Keypair, solana_signer::Signer, std::collections::HashSet};

    fn derive_commitment_and_witnesses(
        slot: Slot,
        proposer_index: u32,
        shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
    ) -> ([u8; 32], Vec<[[u8; 32]; MCP_WITNESS_LEN]>) {
        assert_eq!(shreds.len(), MCP_NUM_RELAYS);

        let mut levels = vec![shreds
            .iter()
            .enumerate()
            .map(|(i, shred_data)| {
                hashv(&[
                    &LEAF_DOMAIN,
                    &slot.to_le_bytes(),
                    &proposer_index.to_le_bytes(),
                    &(i as u32).to_le_bytes(),
                    shred_data,
                ])
                .to_bytes()
            })
            .collect::<Vec<[u8; 32]>>()];

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0usize;
            while i < prev.len() {
                let left = prev[i];
                let right = prev.get(i + 1).copied().unwrap_or(left);
                next.push(hashv(&[&NODE_DOMAIN, &left, &right]).to_bytes());
                i += 2;
            }
            levels.push(next);
        }

        let commitment = levels.last().unwrap()[0];
        let mut witnesses = vec![[[0u8; 32]; MCP_WITNESS_LEN]; MCP_NUM_RELAYS];
        for (leaf_index, witness) in witnesses.iter_mut().enumerate() {
            let mut index = leaf_index;
            for depth in 0..MCP_WITNESS_LEN {
                let level = &levels[depth];
                let sibling_index = index ^ 1;
                witness[depth] = level.get(sibling_index).copied().unwrap_or(level[index]);
                index >>= 1;
            }
        }

        (commitment, witnesses)
    }

    fn make_shreds() -> Vec<[u8; MCP_SHRED_DATA_BYTES]> {
        (0..MCP_NUM_RELAYS)
            .map(|i| {
                let mut bytes = [0u8; MCP_SHRED_DATA_BYTES];
                bytes.fill(i as u8);
                bytes
            })
            .collect()
    }

    #[test]
    fn test_build_relay_unicasts_one_per_relay() {
        let slot = 42;
        let proposer_index = 5;
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let relays: Vec<Pubkey> = (0..MCP_NUM_RELAYS).map(|_| Pubkey::new_unique()).collect();
        let proposer = Keypair::new();
        let proposer_signature = proposer.sign_message(&commitment);

        let unicasts = build_relay_unicasts(
            slot,
            proposer_index,
            commitment,
            &shreds,
            &witnesses,
            proposer_signature,
            &relays,
        )
        .unwrap();

        assert_eq!(unicasts.len(), MCP_NUM_RELAYS);
        let mut relay_set = HashSet::with_capacity(MCP_NUM_RELAYS);
        for (relay_index, unicast) in unicasts.iter().enumerate() {
            assert!(relay_set.insert(unicast.relay_pubkey));
            assert_eq!(unicast.relay_pubkey, relays[relay_index]);
            assert_eq!(unicast.message.shred_index, relay_index as u32);
            assert!(unicast
                .message
                .verify_for_relay(relay_index as u32, &proposer.pubkey()));
        }
    }

    #[test]
    fn test_mcp_shred_message_roundtrip() {
        let slot = 13;
        let proposer_index = 2;
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let proposer = Keypair::new();
        let proposer_signature = proposer.sign_message(&commitment);

        let message = McpShredMessage {
            slot,
            proposer_index,
            shred_index: 77,
            commitment,
            shred_data: shreds[77],
            witness: witnesses[77],
            proposer_signature,
        };

        let encoded = message.to_bytes();
        let decoded = McpShredMessage::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, message);
        assert!(decoded.verify_for_relay(77, &proposer.pubkey()));
    }

    #[test]
    fn test_verify_for_relay_rejects_wrong_index() {
        let slot = 99;
        let proposer_index = 1;
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let proposer = Keypair::new();
        let proposer_signature = proposer.sign_message(&commitment);

        let message = McpShredMessage {
            slot,
            proposer_index,
            shred_index: 4,
            commitment,
            shred_data: shreds[4],
            witness: witnesses[4],
            proposer_signature,
        };

        assert!(!message.verify_for_relay(5, &proposer.pubkey()));
        assert!(message.verify_for_relay(4, &proposer.pubkey()));
    }
}
