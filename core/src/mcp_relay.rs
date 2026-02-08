use {
    solana_clock::Slot,
    solana_pubkey::Pubkey,
    solana_sha256_hasher::hashv,
    solana_signature::{Signature, SIGNATURE_BYTES},
    std::collections::HashMap,
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
pub enum McpRelayError {
    #[error("invalid MCP shred message size: expected {expected}, got {actual}")]
    InvalidMessageSize { expected: usize, actual: usize },
    #[error("invalid witness length: expected {expected}, got {actual}")]
    InvalidWitnessLength { expected: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpDropReason {
    DecodeError,
    WrongRelayIndex,
    InvalidProposerSignature,
    InvalidWitness,
    ConflictingShred,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpRelayOutcome {
    Dropped(McpDropReason),
    Duplicate,
    StoredAndBroadcast {
        slot: Slot,
        proposer_index: u32,
        shred_index: u32,
        payload: Vec<u8>,
    },
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

    pub fn from_bytes(data: &[u8]) -> Result<Self, McpRelayError> {
        if data.len() != MCP_SHRED_MESSAGE_SIZE {
            return Err(McpRelayError::InvalidMessageSize {
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
            return Err(McpRelayError::InvalidWitnessLength {
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

        // witness_len already validated.
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

    fn verify_signature(&self, proposer_pubkey: &Pubkey) -> bool {
        self.proposer_signature
            .verify(proposer_pubkey.as_ref(), &self.commitment)
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

#[derive(Default)]
pub struct McpRelayProcessor {
    shreds: HashMap<(Slot, u32, u32), Vec<u8>>,
}

impl McpRelayProcessor {
    pub fn stored_count(&self) -> usize {
        self.shreds.len()
    }

    pub fn prune_below_slot(&mut self, root_slot: Slot) {
        self.shreds.retain(|(slot, _, _), _| *slot >= root_slot);
    }

    pub fn process_shred(
        &mut self,
        payload: &[u8],
        relay_index: u32,
        proposer_pubkey: &Pubkey,
    ) -> McpRelayOutcome {
        let message = match McpShredMessage::from_bytes(payload) {
            Ok(message) => message,
            Err(_) => return McpRelayOutcome::Dropped(McpDropReason::DecodeError),
        };

        if message.shred_index != relay_index {
            return McpRelayOutcome::Dropped(McpDropReason::WrongRelayIndex);
        }
        if !message.verify_signature(proposer_pubkey) {
            return McpRelayOutcome::Dropped(McpDropReason::InvalidProposerSignature);
        }
        if !message.verify_witness() {
            return McpRelayOutcome::Dropped(McpDropReason::InvalidWitness);
        }

        let key = (message.slot, message.proposer_index, message.shred_index);
        if let Some(stored) = self.shreds.get(&key) {
            if stored == payload {
                return McpRelayOutcome::Duplicate;
            }
            return McpRelayOutcome::Dropped(McpDropReason::ConflictingShred);
        }

        let payload = payload.to_vec();
        self.shreds.insert(key, payload.clone());
        McpRelayOutcome::StoredAndBroadcast {
            slot: message.slot,
            proposer_index: message.proposer_index,
            shred_index: message.shred_index,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_keypair::Keypair, solana_signer::Signer};

    fn make_shreds() -> Vec<[u8; MCP_SHRED_DATA_BYTES]> {
        (0..MCP_NUM_RELAYS)
            .map(|i| {
                let mut shred = [0u8; MCP_SHRED_DATA_BYTES];
                shred.fill(i as u8);
                shred
            })
            .collect()
    }

    fn derive_commitment_and_witnesses(
        slot: Slot,
        proposer_index: u32,
        shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
    ) -> ([u8; 32], Vec<[[u8; 32]; MCP_WITNESS_LEN]>) {
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

    fn build_message(
        slot: Slot,
        proposer_index: u32,
        shred_index: u32,
        commitment: [u8; 32],
        shred_data: [u8; MCP_SHRED_DATA_BYTES],
        witness: [[u8; 32]; MCP_WITNESS_LEN],
        signer: &Keypair,
    ) -> Vec<u8> {
        McpShredMessage {
            slot,
            proposer_index,
            shred_index,
            commitment,
            shred_data,
            witness,
            proposer_signature: signer.sign_message(&commitment),
        }
        .to_bytes()
        .to_vec()
    }

    #[test]
    fn test_valid_shred_is_stored_and_broadcast() {
        let slot = 11;
        let proposer_index = 3;
        let relay_index = 17u32;
        let proposer = Keypair::new();
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, relay_index, &proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::StoredAndBroadcast {
                slot,
                proposer_index,
                shred_index: relay_index,
                payload: payload.clone(),
            }
        );
        assert_eq!(relay.stored_count(), 1);

        let duplicate = relay.process_shred(&payload, relay_index, &proposer.pubkey());
        assert_eq!(duplicate, McpRelayOutcome::Duplicate);
    }

    #[test]
    fn test_invalid_signature_is_dropped() {
        let slot = 12;
        let proposer_index = 4;
        let relay_index = 2u32;
        let honest_proposer = Keypair::new();
        let attacker = Keypair::new();
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &attacker,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, relay_index, &honest_proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::Dropped(McpDropReason::InvalidProposerSignature)
        );
        assert_eq!(relay.stored_count(), 0);
    }

    #[test]
    fn test_wrong_relay_index_is_dropped() {
        let slot = 13;
        let proposer_index = 2;
        let proposer = Keypair::new();
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            9,
            commitment,
            shreds[9],
            witnesses[9],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, 10, &proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::Dropped(McpDropReason::WrongRelayIndex)
        );
        assert_eq!(relay.stored_count(), 0);
    }

    #[test]
    fn test_invalid_witness_is_dropped() {
        let slot = 14;
        let proposer_index = 8;
        let relay_index = 6u32;
        let proposer = Keypair::new();
        let shreds = make_shreds();
        let (commitment, mut witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        witnesses[relay_index as usize][0][0] ^= 1;

        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let outcome = relay.process_shred(&payload, relay_index, &proposer.pubkey());
        assert_eq!(
            outcome,
            McpRelayOutcome::Dropped(McpDropReason::InvalidWitness)
        );
        assert_eq!(relay.stored_count(), 0);
    }

    #[test]
    fn test_conflicting_shred_is_dropped_without_overwrite() {
        let slot = 15;
        let proposer_index = 10;
        let relay_index = 5u32;
        let proposer = Keypair::new();
        let shreds = make_shreds();
        let (commitment, witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &shreds);
        let payload = build_message(
            slot,
            proposer_index,
            relay_index,
            commitment,
            shreds[relay_index as usize],
            witnesses[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        let first = relay.process_shred(&payload, relay_index, &proposer.pubkey());
        assert!(matches!(first, McpRelayOutcome::StoredAndBroadcast { .. }));
        assert_eq!(relay.stored_count(), 1);

        let mut alternate_shreds = shreds.clone();
        alternate_shreds[relay_index as usize][0] ^= 1;
        let (alt_commitment, alt_witnesses) =
            derive_commitment_and_witnesses(slot, proposer_index, &alternate_shreds);
        let conflicting = build_message(
            slot,
            proposer_index,
            relay_index,
            alt_commitment,
            alternate_shreds[relay_index as usize],
            alt_witnesses[relay_index as usize],
            &proposer,
        );
        let conflict_outcome = relay.process_shred(&conflicting, relay_index, &proposer.pubkey());
        assert_eq!(
            conflict_outcome,
            McpRelayOutcome::Dropped(McpDropReason::ConflictingShred)
        );
        assert_eq!(relay.stored_count(), 1);
    }

    #[test]
    fn test_prune_below_slot_discards_old_entries() {
        let proposer = Keypair::new();
        let proposer_index = 1;
        let relay_index = 0u32;
        let shreds = make_shreds();

        let (commitment_a, witnesses_a) =
            derive_commitment_and_witnesses(20, proposer_index, &shreds);
        let payload_a = build_message(
            20,
            proposer_index,
            relay_index,
            commitment_a,
            shreds[relay_index as usize],
            witnesses_a[relay_index as usize],
            &proposer,
        );

        let (commitment_b, witnesses_b) =
            derive_commitment_and_witnesses(21, proposer_index, &shreds);
        let payload_b = build_message(
            21,
            proposer_index,
            relay_index,
            commitment_b,
            shreds[relay_index as usize],
            witnesses_b[relay_index as usize],
            &proposer,
        );

        let mut relay = McpRelayProcessor::default();
        assert!(matches!(
            relay.process_shred(&payload_a, relay_index, &proposer.pubkey()),
            McpRelayOutcome::StoredAndBroadcast { .. }
        ));
        assert!(matches!(
            relay.process_shred(&payload_b, relay_index, &proposer.pubkey()),
            McpRelayOutcome::StoredAndBroadcast { .. }
        ));
        assert_eq!(relay.stored_count(), 2);

        relay.prune_below_slot(21);
        assert_eq!(relay.stored_count(), 1);
    }
}
