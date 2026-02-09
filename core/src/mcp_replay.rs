use {
    crate::mcp_vote_gate::{
        Commitment, RelayAttestationObservation, RelayProposerEntry, VoteGateInput,
    },
    solana_clock::Slot,
    solana_ledger::{
        blockstore::Blockstore, leader_schedule_cache::LeaderScheduleCache, mcp,
        mcp_aggregate_attestation::AggregateAttestation, mcp_consensus_block::ConsensusBlock,
        shred::mcp_shred::McpShred,
    },
    solana_pubkey::Pubkey,
    solana_runtime::{bank::Bank, bank_forks::BankForks},
    std::{
        collections::{BTreeSet, HashMap},
        sync::{Arc, RwLock},
    },
};

pub(crate) type McpConsensusBlockStore = Arc<RwLock<HashMap<Slot, Vec<u8>>>>;
const MCP_CONSENSUS_BLOCK_RETENTION_SLOTS: Slot = 512;

fn load_proposer_schedule(
    slot: Slot,
    bank: &Bank,
    root_bank: &Bank,
    leader_schedule_cache: &LeaderScheduleCache,
) -> Vec<Pubkey> {
    leader_schedule_cache
        .proposers_at_slot(slot, Some(bank))
        .or_else(|| leader_schedule_cache.proposers_at_slot(slot, Some(root_bank)))
        .or_else(|| leader_schedule_cache.proposers_at_slot(slot, None))
        .unwrap_or_default()
}

fn load_relay_schedule(
    slot: Slot,
    bank: &Bank,
    root_bank: &Bank,
    leader_schedule_cache: &LeaderScheduleCache,
) -> Vec<Pubkey> {
    leader_schedule_cache
        .relays_at_slot(slot, Some(bank))
        .or_else(|| leader_schedule_cache.relays_at_slot(slot, Some(root_bank)))
        .or_else(|| leader_schedule_cache.relays_at_slot(slot, None))
        .unwrap_or_default()
}

fn derive_selected_commitments(
    aggregate: &[RelayAttestationObservation],
) -> HashMap<u32, Commitment> {
    let mut by_proposer: HashMap<u32, HashMap<Commitment, BTreeSet<u32>>> = HashMap::new();
    for relay in aggregate.iter().filter(|relay| relay.relay_signature_valid) {
        for entry in relay
            .entries
            .iter()
            .filter(|entry| entry.proposer_signature_valid)
        {
            by_proposer
                .entry(entry.proposer_index)
                .or_default()
                .entry(entry.commitment)
                .or_default()
                .insert(relay.relay_index);
        }
    }

    by_proposer
        .into_iter()
        .filter_map(|(proposer_index, commitments)| {
            if commitments.len() != 1 {
                return None;
            }
            let (commitment, relays) = commitments.into_iter().next().unwrap();
            if relays.len() < mcp::REQUIRED_INCLUSIONS {
                return None;
            }
            Some((proposer_index, commitment))
        })
        .collect()
}

fn count_local_valid_shreds_for_commitment(
    blockstore: &Blockstore,
    slot: Slot,
    proposer_index: u32,
    proposer_pubkey: &Pubkey,
    commitment: Commitment,
) -> usize {
    (0..mcp::NUM_RELAYS)
        .filter_map(|shred_index| {
            blockstore
                .get_mcp_shred_data(slot, proposer_index, u32::try_from(shred_index).ok()?)
                .ok()
                .flatten()
        })
        .filter_map(|bytes| McpShred::from_bytes(&bytes).ok())
        .filter(|mcp_shred| {
            mcp_shred.commitment == commitment
                && mcp_shred.verify_signature(proposer_pubkey)
                && mcp_shred.verify_witness()
        })
        .count()
}

fn build_vote_gate_input(
    slot: Slot,
    bank: &Bank,
    root_bank: &Bank,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    consensus_block: &ConsensusBlock,
    delayed_bankhash_available: bool,
    delayed_bankhash_matches: bool,
) -> Option<VoteGateInput> {
    if consensus_block.slot != slot {
        return None;
    }

    let proposers = load_proposer_schedule(slot, bank, root_bank, leader_schedule_cache);
    if proposers.is_empty() {
        return None;
    }
    let relays = load_relay_schedule(slot, bank, root_bank, leader_schedule_cache);
    if relays.len() < mcp::NUM_RELAYS {
        return None;
    }

    let leader_pubkey = proposers
        .get(consensus_block.leader_index as usize)
        .copied();
    let leader_signature_valid = leader_pubkey
        .as_ref()
        .is_some_and(|leader_pubkey| consensus_block.verify_leader_signature(leader_pubkey));
    let leader_index_matches = leader_pubkey.is_some_and(|leader_pubkey| {
        leader_schedule_cache
            .slot_leader_at(slot, Some(bank))
            .or_else(|| leader_schedule_cache.slot_leader_at(slot, Some(root_bank)))
            .or_else(|| leader_schedule_cache.slot_leader_at(slot, None))
            .is_some_and(|expected_leader| expected_leader == leader_pubkey)
    });

    let aggregate_attestation =
        AggregateAttestation::from_wire_bytes(&consensus_block.aggregate_bytes).ok()?;
    if aggregate_attestation.slot != slot
        || aggregate_attestation.leader_index != consensus_block.leader_index
    {
        return None;
    }

    let filtered = aggregate_attestation
        .canonical_filtered(
            |relay_index| relays.get(relay_index as usize).copied(),
            |proposer_index| proposers.get(proposer_index as usize).copied(),
        )
        .ok()?;

    let aggregate: Vec<RelayAttestationObservation> = filtered
        .relay_entries
        .into_iter()
        .map(|relay_entry| RelayAttestationObservation {
            relay_index: relay_entry.relay_index,
            relay_signature_valid: true,
            entries: relay_entry
                .entries
                .into_iter()
                .map(|entry| RelayProposerEntry {
                    proposer_index: entry.proposer_index,
                    commitment: entry.commitment.to_bytes(),
                    proposer_signature_valid: true,
                })
                .collect(),
        })
        .collect();

    let selected_commitments = derive_selected_commitments(&aggregate);
    let local_valid_shreds = selected_commitments
        .into_iter()
        .filter_map(|(proposer_index, commitment)| {
            let proposer_pubkey = proposers.get(proposer_index as usize)?;
            Some((
                proposer_index,
                count_local_valid_shreds_for_commitment(
                    blockstore,
                    slot,
                    proposer_index,
                    proposer_pubkey,
                    commitment,
                ),
            ))
        })
        .collect();

    let proposer_indices = (0..proposers.len())
        .filter_map(|proposer_index| u32::try_from(proposer_index).ok())
        .collect();

    Some(VoteGateInput {
        leader_signature_valid,
        leader_index_matches,
        delayed_bankhash_available,
        delayed_bankhash_matches,
        aggregate,
        proposer_indices,
        local_valid_shreds,
    })
}

pub(crate) fn refresh_vote_gate_input(
    slot: Slot,
    bank: &Bank,
    bank_forks: &RwLock<BankForks>,
    blockstore: &Blockstore,
    leader_schedule_cache: &LeaderScheduleCache,
    mcp_consensus_blocks: &McpConsensusBlockStore,
    mcp_vote_gate_inputs: &RwLock<HashMap<Slot, VoteGateInput>>,
) {
    let (root_bank, root_slot, local_delayed_bankhash) = {
        let bank_forks = bank_forks.read().unwrap();
        (
            bank_forks.root_bank(),
            bank_forks.root(),
            // Until consensus metadata explicitly carries delayed-slot semantics, use the
            // immediately delayed slot as the local availability gate.
            bank_forks
                .get(slot.saturating_sub(1))
                .map(|bank| bank.hash()),
        )
    };

    let consensus_block = {
        let Ok(consensus_blocks) = mcp_consensus_blocks.read() else {
            return;
        };
        let Some(payload) = consensus_blocks.get(&slot) else {
            return;
        };
        let Ok(consensus_block) = ConsensusBlock::from_wire_bytes(payload) else {
            drop(consensus_blocks);
            if let Ok(mut consensus_blocks) = mcp_consensus_blocks.write() {
                consensus_blocks.remove(&slot);
            }
            return;
        };
        consensus_block
    };

    let delayed_bankhash_available = local_delayed_bankhash.is_some();
    let delayed_bankhash_matches =
        local_delayed_bankhash.is_some_and(|bankhash| bankhash == consensus_block.delayed_bankhash);

    let Some(vote_gate_input) = build_vote_gate_input(
        slot,
        bank,
        &root_bank,
        blockstore,
        leader_schedule_cache,
        &consensus_block,
        delayed_bankhash_available,
        delayed_bankhash_matches,
    ) else {
        return;
    };

    if let Ok(mut inputs) = mcp_vote_gate_inputs.write() {
        let min_slot = root_slot.saturating_sub(MCP_CONSENSUS_BLOCK_RETENTION_SLOTS);
        inputs.retain(|tracked_slot, _| *tracked_slot >= min_slot);
        inputs.insert(slot, vote_gate_input);
    }

    if let Ok(mut consensus_blocks) = mcp_consensus_blocks.write() {
        let min_slot = root_slot.saturating_sub(MCP_CONSENSUS_BLOCK_RETENTION_SLOTS);
        consensus_blocks.retain(|tracked_slot, _| *tracked_slot >= min_slot);
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::mcp_vote_gate::{RelayAttestationObservation, RelayProposerEntry},
    };

    fn relay_with_entry(
        relay_index: u32,
        proposer_index: u32,
        commitment: Commitment,
    ) -> RelayAttestationObservation {
        RelayAttestationObservation {
            relay_index,
            relay_signature_valid: true,
            entries: vec![RelayProposerEntry {
                proposer_index,
                commitment,
                proposer_signature_valid: true,
            }],
        }
    }

    #[test]
    fn test_derive_selected_commitments_requires_unique_commitment() {
        let commitment_a = [1u8; 32];
        let commitment_b = [2u8; 32];
        let aggregate = (0..mcp::REQUIRED_INCLUSIONS)
            .map(|relay_index| relay_with_entry(relay_index as u32, 0, commitment_a))
            .chain((0..mcp::REQUIRED_INCLUSIONS).map(|relay_index| {
                relay_with_entry(
                    (relay_index + mcp::REQUIRED_INCLUSIONS) as u32,
                    0,
                    commitment_b,
                )
            }))
            .collect::<Vec<_>>();

        let selected = derive_selected_commitments(&aggregate);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_derive_selected_commitments_includes_unique_threshold_commitment() {
        let commitment = [7u8; 32];
        let aggregate = (0..mcp::REQUIRED_INCLUSIONS)
            .map(|relay_index| relay_with_entry(relay_index as u32, 3, commitment))
            .collect::<Vec<_>>();

        let selected = derive_selected_commitments(&aggregate);
        assert_eq!(selected.get(&3), Some(&commitment));
    }
}
