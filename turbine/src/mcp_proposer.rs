use {
    solana_ledger::{
        mcp,
        mcp_erasure::{encode_fec_set, McpErasureError, MCP_MAX_PAYLOAD_BYTES},
    },
    solana_clock::Slot,
    solana_keypair::Keypair,
    solana_sha256_hasher::hashv,
    solana_signature::{Signature, SIGNATURE_BYTES},
    solana_signer::Signer,
    thiserror::Error,
};

pub(crate) const MCP_NUM_RELAYS: usize = mcp::NUM_RELAYS;
pub(crate) const MCP_SHRED_DATA_BYTES: usize = mcp::SHRED_DATA_BYTES;
pub(crate) const MCP_WITNESS_LEN: usize = mcp::MCP_WITNESS_LEN;
pub(crate) const MCP_MAX_PAYLOAD_SIZE: usize = MCP_MAX_PAYLOAD_BYTES;
pub(crate) const MCP_SHRED_MESSAGE_SIZE: usize = std::mem::size_of::<Slot>()
    + std::mem::size_of::<u32>() // proposer_index
    + std::mem::size_of::<u32>() // shred_index
    + 32 // commitment
    + MCP_SHRED_DATA_BYTES
    + 1 // witness_len
    + (32 * MCP_WITNESS_LEN)
    + SIGNATURE_BYTES;

const LEAF_DOMAIN: [u8; 1] = [0x00];
const NODE_DOMAIN: [u8; 1] = [0x01];

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum McpProposerError {
    #[error("shred list size mismatch: expected {expected}, got {actual}")]
    ShredCountMismatch { expected: usize, actual: usize },
    #[error("failed to encode MCP RS shreds: {0}")]
    Erasure(McpErasureError),
}

pub(crate) fn encode_payload_to_mcp_shreds(
    payload: &[u8],
) -> Result<Vec<[u8; MCP_SHRED_DATA_BYTES]>, McpProposerError> {
    encode_fec_set(payload).map_err(McpProposerError::Erasure)
}

pub(crate) fn build_shred_messages(
    slot: Slot,
    proposer_index: u32,
    shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
    proposer_keypair: &Keypair,
) -> Result<Vec<[u8; MCP_SHRED_MESSAGE_SIZE]>, McpProposerError> {
    if shreds.len() != MCP_NUM_RELAYS {
        return Err(McpProposerError::ShredCountMismatch {
            expected: MCP_NUM_RELAYS,
            actual: shreds.len(),
        });
    }

    let (commitment, witnesses) = derive_commitment_and_witnesses(slot, proposer_index, shreds);
    let proposer_signature = proposer_keypair.sign_message(&commitment);
    let mut messages = Vec::with_capacity(MCP_NUM_RELAYS);

    for (relay_index, (shred_data, witness)) in shreds.iter().zip(witnesses).enumerate() {
        let message = serialize_shred_message(
            slot,
            proposer_index,
            relay_index as u32,
            commitment,
            *shred_data,
            witness,
            proposer_signature,
        );
        messages.push(message);
    }

    Ok(messages)
}

fn derive_commitment_and_witnesses(
    slot: Slot,
    proposer_index: u32,
    shreds: &[[u8; MCP_SHRED_DATA_BYTES]],
) -> ([u8; 32], Vec<[[u8; 32]; MCP_WITNESS_LEN]>) {
    let mut levels = vec![shreds
        .iter()
        .enumerate()
        .map(|(index, shred_data)| {
            hashv(&[
                &LEAF_DOMAIN,
                &slot.to_le_bytes(),
                &proposer_index.to_le_bytes(),
                &(index as u32).to_le_bytes(),
                shred_data,
            ])
            .to_bytes()
        })
        .collect::<Vec<_>>()];

    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let next = prev
            .chunks(2)
            .map(|pair| {
                let left = pair[0];
                let right = if pair.len() == 2 { pair[1] } else { pair[0] };
                hashv(&[&NODE_DOMAIN, &left, &right]).to_bytes()
            })
            .collect::<Vec<_>>();
        levels.push(next);
    }

    let commitment = levels.last().unwrap()[0];
    let mut witnesses = vec![[[0u8; 32]; MCP_WITNESS_LEN]; MCP_NUM_RELAYS];
    for (shred_index, witness) in witnesses.iter_mut().enumerate() {
        let mut index = shred_index;
        for (depth, level) in levels[..MCP_WITNESS_LEN].iter().enumerate() {
            let sibling = if index & 1 == 0 {
                level.get(index + 1).copied().unwrap_or(level[index])
            } else {
                level[index - 1]
            };
            witness[depth] = sibling;
            index >>= 1;
        }
    }

    (commitment, witnesses)
}

fn serialize_shred_message(
    slot: Slot,
    proposer_index: u32,
    shred_index: u32,
    commitment: [u8; 32],
    shred_data: [u8; MCP_SHRED_DATA_BYTES],
    witness: [[u8; 32]; MCP_WITNESS_LEN],
    proposer_signature: Signature,
) -> [u8; MCP_SHRED_MESSAGE_SIZE] {
    let mut data = [0u8; MCP_SHRED_MESSAGE_SIZE];
    let mut offset = 0usize;

    data[offset..offset + std::mem::size_of::<Slot>()].copy_from_slice(&slot.to_le_bytes());
    offset += std::mem::size_of::<Slot>();
    data[offset..offset + std::mem::size_of::<u32>()]
        .copy_from_slice(&proposer_index.to_le_bytes());
    offset += std::mem::size_of::<u32>();
    data[offset..offset + std::mem::size_of::<u32>()].copy_from_slice(&shred_index.to_le_bytes());
    offset += std::mem::size_of::<u32>();
    data[offset..offset + 32].copy_from_slice(&commitment);
    offset += 32;
    data[offset..offset + MCP_SHRED_DATA_BYTES].copy_from_slice(&shred_data);
    offset += MCP_SHRED_DATA_BYTES;
    data[offset] = MCP_WITNESS_LEN as u8;
    offset += 1;
    for sibling in witness {
        data[offset..offset + 32].copy_from_slice(&sibling);
        offset += 32;
    }
    data[offset..offset + SIGNATURE_BYTES].copy_from_slice(proposer_signature.as_ref());
    data
}

#[cfg(test)]
mod tests {
    use {super::*, solana_pubkey::Pubkey};

    fn verify_message(message: &[u8], relay_index: u32, proposer_pubkey: &Pubkey) -> bool {
        if message.len() != MCP_SHRED_MESSAGE_SIZE {
            return false;
        }
        let mut offset = 0usize;

        let slot = Slot::from_le_bytes(
            message[offset..offset + std::mem::size_of::<Slot>()]
                .try_into()
                .unwrap(),
        );
        offset += std::mem::size_of::<Slot>();

        let proposer_index = u32::from_le_bytes(
            message[offset..offset + std::mem::size_of::<u32>()]
                .try_into()
                .unwrap(),
        );
        offset += std::mem::size_of::<u32>();

        let shred_index = u32::from_le_bytes(
            message[offset..offset + std::mem::size_of::<u32>()]
                .try_into()
                .unwrap(),
        );
        offset += std::mem::size_of::<u32>();

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&message[offset..offset + 32]);
        offset += 32;

        let mut shred_data = [0u8; MCP_SHRED_DATA_BYTES];
        shred_data.copy_from_slice(&message[offset..offset + MCP_SHRED_DATA_BYTES]);
        offset += MCP_SHRED_DATA_BYTES;

        let witness_len = message[offset] as usize;
        if witness_len != MCP_WITNESS_LEN {
            return false;
        }
        offset += 1;

        let mut witness = [[0u8; 32]; MCP_WITNESS_LEN];
        for sibling in &mut witness {
            sibling.copy_from_slice(&message[offset..offset + 32]);
            offset += 32;
        }

        let proposer_signature = Signature::from(
            <[u8; SIGNATURE_BYTES]>::try_from(&message[offset..offset + SIGNATURE_BYTES]).unwrap(),
        );

        if shred_index != relay_index {
            return false;
        }
        if !proposer_signature.verify(proposer_pubkey.as_ref(), &commitment) {
            return false;
        }

        let leaf = hashv(&[
            &LEAF_DOMAIN,
            &slot.to_le_bytes(),
            &proposer_index.to_le_bytes(),
            &shred_index.to_le_bytes(),
            &shred_data,
        ])
        .to_bytes();
        let mut node = leaf;
        let mut index = shred_index as usize;
        for sibling in &witness {
            node = if index & 1 == 0 {
                hashv(&[&NODE_DOMAIN, &node, sibling]).to_bytes()
            } else {
                hashv(&[&NODE_DOMAIN, sibling, &node]).to_bytes()
            };
            index >>= 1;
        }
        node == commitment
    }

    fn make_shreds() -> Vec<[u8; MCP_SHRED_DATA_BYTES]> {
        (0..MCP_NUM_RELAYS)
            .map(|index| {
                let mut shred = [0u8; MCP_SHRED_DATA_BYTES];
                shred.fill(index as u8);
                shred
            })
            .collect()
    }

    #[test]
    fn test_build_shred_messages_one_per_relay() {
        let keypair = Keypair::new();
        let slot = 42;
        let proposer_index = 7;
        let shreds = make_shreds();
        let messages = build_shred_messages(slot, proposer_index, &shreds, &keypair).unwrap();

        assert_eq!(messages.len(), MCP_NUM_RELAYS);
        for (relay_index, message) in messages.iter().enumerate() {
            assert!(verify_message(
                message,
                relay_index as u32,
                &keypair.pubkey(),
            ));
        }
    }

    #[test]
    fn test_encode_payload_to_mcp_shreds_emits_200_shards() {
        let payload = vec![9u8; MCP_MAX_PAYLOAD_SIZE];
        let shreds = encode_payload_to_mcp_shreds(&payload).unwrap();
        assert_eq!(shreds.len(), MCP_NUM_RELAYS);
        assert!(shreds.iter().all(|shred| shred.len() == MCP_SHRED_DATA_BYTES));
    }
}
