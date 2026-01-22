use {
    crate::mcp::{NUM_PROPOSERS, NUM_RELAYS},
    rand::distributions::{Distribution, WeightedIndex},
    rand::Rng,
    rand_chacha::{rand_core::SeedableRng, ChaChaRng},
    solana_clock::Epoch,
    solana_pubkey::Pubkey,
    std::{collections::HashMap, convert::identity, ops::Index, sync::Arc},
};

mod identity_keyed;
mod vote_keyed;
pub use {
    identity_keyed::LeaderSchedule as IdentityKeyedLeaderSchedule,
    vote_keyed::LeaderSchedule as VoteKeyedLeaderSchedule,
};


// ============================================================================
// MCP (Multiple Concurrent Proposers) Schedule Types
// ============================================================================

/// Proposer ID type (0-15 for regular proposers, 0xFF for consensus payload)
pub type ProposerId = u8;

/// Relay ID type (0-199)
pub type RelayId = u16;

/// MCP schedule for proposers in an epoch.
///
/// Each slot has NUM_PROPOSERS active proposers. The schedule rotates
/// one proposer per slot to ensure fair participation.
#[derive(Debug, Clone)]
pub struct ProposerSchedule {
    /// Base proposer set for the epoch (stake-weighted selection of validators).
    proposer_pool: Vec<Pubkey>,
    /// Number of slots in this epoch
    num_slots: u64,
    /// Map from pubkey to their position(s) in the pool
    pubkey_to_positions: HashMap<Pubkey, Vec<usize>>,
}

impl ProposerSchedule {
    /// Create a new proposer schedule from stake-weighted validators.
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        let proposer_pool = mcp_stake_weighted_selection(
            keyed_stakes,
            epoch,
            NUM_PROPOSERS as u64,
            0x50524F50, // "PROP" magic
        );

        let pubkey_to_positions = build_mcp_position_map(&proposer_pool);

        Self {
            proposer_pool,
            num_slots,
            pubkey_to_positions,
        }
    }

    /// Get the set of proposers active at the given slot index.
    pub fn get_proposers_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        let pool_len = self.proposer_pool.len();
        let start = (slot_index as usize) % pool_len;

        (0..NUM_PROPOSERS as usize)
            .map(|i| self.proposer_pool[(start + i) % pool_len])
            .collect()
    }

    /// Get the proposer ID for a given pubkey at a given slot index.
    pub fn get_proposer_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<ProposerId> {
        let pool_len = self.proposer_pool.len();
        let start = (slot_index as usize) % pool_len;

        for i in 0..NUM_PROPOSERS as usize {
            if self.proposer_pool[(start + i) % pool_len] == *pubkey {
                return Some(i as ProposerId);
            }
        }
        None
    }

    /// Check if a pubkey is an active proposer at the given slot index.
    pub fn is_proposer_at_slot(&self, slot_index: u64, pubkey: &Pubkey) -> bool {
        self.get_proposer_id(slot_index, pubkey).is_some()
    }

    /// Get all slot indices where the given pubkey is an active proposer.
    pub fn get_proposer_slots(&self, pubkey: &Pubkey) -> Vec<u64> {
        let positions = match self.pubkey_to_positions.get(pubkey) {
            Some(p) => p,
            None => return vec![],
        };

        let pool_len = self.proposer_pool.len();
        let mut slots = Vec::new();

        for slot in 0..self.num_slots {
            let start = (slot as usize) % pool_len;
            for i in 0..NUM_PROPOSERS as usize {
                let pos = (start + i) % pool_len;
                if positions.contains(&pos) {
                    slots.push(slot);
                    break;
                }
            }
        }
        slots
    }

    /// Number of slots in this schedule
    pub fn num_slots(&self) -> u64 {
        self.num_slots
    }
}

/// MCP schedule for relays in an epoch.
///
/// Each slot has NUM_RELAYS active relays. The schedule rotates
/// one relay per slot to ensure fair participation.
#[derive(Debug, Clone)]
pub struct RelaySchedule {
    /// Base relay set for the epoch (stake-weighted selection of validators).
    relay_pool: Vec<Pubkey>,
    /// Number of slots in this epoch
    num_slots: u64,
    /// Map from pubkey to their position(s) in the pool
    pubkey_to_positions: HashMap<Pubkey, Vec<usize>>,
}

impl RelaySchedule {
    /// Create a new relay schedule from stake-weighted validators.
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        let relay_pool = mcp_stake_weighted_selection(
            keyed_stakes,
            epoch,
            NUM_RELAYS as u64,
            0x52454C59, // "RELY" magic
        );

        let pubkey_to_positions = build_mcp_position_map(&relay_pool);

        Self {
            relay_pool,
            num_slots,
            pubkey_to_positions,
        }
    }

    /// Get the set of relays active at the given slot index.
    pub fn get_relays_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        let pool_len = self.relay_pool.len();
        let start = (slot_index as usize) % pool_len;

        (0..NUM_RELAYS as usize)
            .map(|i| self.relay_pool[(start + i) % pool_len])
            .collect()
    }

    /// Get the relay ID for a given pubkey at a given slot index.
    pub fn get_relay_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<RelayId> {
        let pool_len = self.relay_pool.len();
        let start = (slot_index as usize) % pool_len;

        for i in 0..NUM_RELAYS as usize {
            if self.relay_pool[(start + i) % pool_len] == *pubkey {
                return Some(i as RelayId);
            }
        }
        None
    }

    /// Check if a pubkey is an active relay at the given slot index.
    pub fn is_relay_at_slot(&self, slot_index: u64, pubkey: &Pubkey) -> bool {
        self.get_relay_id(slot_index, pubkey).is_some()
    }

    /// Get all slot indices where the given pubkey is an active relay.
    pub fn get_relay_slots(&self, pubkey: &Pubkey) -> Vec<u64> {
        let positions = match self.pubkey_to_positions.get(pubkey) {
            Some(p) => p,
            None => return vec![],
        };

        let mut slots = Vec::new();
        for &pos in positions {
            let first_slot = pos.saturating_sub(NUM_RELAYS as usize - 1);
            let last_slot = pos.min(self.num_slots as usize - 1);

            for slot in first_slot..=last_slot {
                if !slots.contains(&(slot as u64)) {
                    slots.push(slot as u64);
                }
            }
        }
        slots.sort();
        slots.dedup();
        slots
    }

    /// Number of slots in this schedule
    pub fn num_slots(&self) -> u64 {
        self.num_slots
    }
}

/// Combined MCP schedule for an epoch containing both proposer and relay schedules.
#[derive(Debug, Clone)]
pub struct McpSchedule {
    pub proposer_schedule: Arc<ProposerSchedule>,
    pub relay_schedule: Arc<RelaySchedule>,
    epoch: Epoch,
}

impl McpSchedule {
    /// Create a new MCP schedule from stake-weighted validators.
    pub fn new<'a>(
        keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)> + Clone,
        epoch: Epoch,
        num_slots: u64,
    ) -> Self {
        Self {
            proposer_schedule: Arc::new(ProposerSchedule::new(
                keyed_stakes.clone(),
                epoch,
                num_slots,
            )),
            relay_schedule: Arc::new(RelaySchedule::new(keyed_stakes, epoch, num_slots)),
            epoch,
        }
    }

    /// Get the epoch this schedule is for
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Get proposers for a slot
    pub fn get_proposers_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        self.proposer_schedule.get_proposers_at_slot_index(slot_index)
    }

    /// Get relays for a slot
    pub fn get_relays_at_slot_index(&self, slot_index: u64) -> Vec<Pubkey> {
        self.relay_schedule.get_relays_at_slot_index(slot_index)
    }

    /// Get proposer ID for a pubkey at a slot
    pub fn get_proposer_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<ProposerId> {
        self.proposer_schedule.get_proposer_id(slot_index, pubkey)
    }

    /// Get relay ID for a pubkey at a slot
    pub fn get_relay_id(&self, slot_index: u64, pubkey: &Pubkey) -> Option<RelayId> {
        self.relay_schedule.get_relay_id(slot_index, pubkey)
    }
}

/// Generate stake-weighted selection for MCP without replacement.
fn mcp_stake_weighted_selection<'a>(
    keyed_stakes: impl Iterator<Item = (&'a Pubkey, u64)>,
    epoch: Epoch,
    pool_size: u64,
    magic: u32,
) -> Vec<Pubkey> {
    let mut stakes: Vec<_> = keyed_stakes.filter(|(_, stake)| *stake > 0).collect();

    if stakes.is_empty() {
        return vec![];
    }

    sort_stakes(&mut stakes);

    let validators: Vec<_> = stakes.into_iter().collect();

    let mut seed = [0u8; 32];
    seed[0..8].copy_from_slice(&epoch.to_le_bytes());
    seed[8..12].copy_from_slice(&magic.to_le_bytes());

    let rng = &mut ChaChaRng::from_seed(seed);

    let actual_pool_size = if pool_size == 0 {
        validators.len()
    } else {
        pool_size as usize
    };

    let mut pool = Vec::with_capacity(actual_pool_size);

    while pool.len() < actual_pool_size {
        let shuffled = mcp_weighted_shuffle_without_replacement(&validators, rng);

        for pubkey in shuffled {
            if pool.len() >= actual_pool_size {
                break;
            }
            pool.push(pubkey);
        }
    }

    pool
}

/// Perform weighted shuffle without replacement for MCP.
fn mcp_weighted_shuffle_without_replacement(
    validators: &[(&Pubkey, u64)],
    rng: &mut ChaChaRng,
) -> Vec<Pubkey> {
    let mut remaining: Vec<_> = validators.iter().map(|(pk, stake)| (*pk, *stake)).collect();
    let mut result = Vec::with_capacity(remaining.len());

    while !remaining.is_empty() {
        let total_stake: u64 = remaining.iter().map(|(_, s)| s).sum();
        if total_stake == 0 {
            result.extend(remaining.iter().map(|(pk, _)| **pk));
            break;
        }

        let target = rng.gen_range(0..total_stake);

        let mut cumulative = 0u64;
        let mut selected_idx = 0;
        for (i, (_, stake)) in remaining.iter().enumerate() {
            cumulative += stake;
            if cumulative > target {
                selected_idx = i;
                break;
            }
        }

        let (pubkey, _) = remaining.remove(selected_idx);
        result.push(*pubkey);
    }

    result
}

/// Build a map from pubkey to positions in the pool for MCP schedules.
fn build_mcp_position_map(pool: &[Pubkey]) -> HashMap<Pubkey, Vec<usize>> {
    let mut map: HashMap<Pubkey, Vec<usize>> = HashMap::new();
    for (pos, pubkey) in pool.iter().enumerate() {
        map.entry(*pubkey).or_default().push(pos);
    }
    map
}

// ============================================================================
// Leader Schedule Types
// ============================================================================

// Used for testing
#[derive(Clone, Debug)]
pub struct FixedSchedule {
    pub leader_schedule: Arc<LeaderSchedule>,
}

/// Stake-weighted leader schedule for one epoch.
pub type LeaderSchedule = Box<dyn LeaderScheduleVariant>;

pub trait LeaderScheduleVariant:
    std::fmt::Debug + Send + Sync + Index<u64, Output = Pubkey>
{
    fn get_slot_leaders(&self) -> &[Pubkey];
    fn get_leader_slots_map(&self) -> &HashMap<Pubkey, Arc<Vec<usize>>>;

    /// Get the vote account address for the given epoch slot index. This is
    /// guaranteed to be Some if the leader schedule is keyed by vote account
    fn get_vote_key_at_slot_index(&self, _epoch_slot_index: usize) -> Option<&Pubkey> {
        None
    }

    fn get_leader_upcoming_slots(
        &self,
        pubkey: &Pubkey,
        offset: usize, // Starting index.
    ) -> Box<dyn Iterator<Item = usize>> {
        let index = self
            .get_leader_slots_map()
            .get(pubkey)
            .cloned()
            .unwrap_or_default();
        let num_slots = self.num_slots();
        let size = index.len();
        #[allow(clippy::reversed_empty_ranges)]
        let range = if index.is_empty() {
            1..=0 // Intentionally empty range of type RangeInclusive.
        } else {
            let offset = index
                .binary_search(&(offset % num_slots))
                .unwrap_or_else(identity)
                + offset / num_slots * size;
            offset..=usize::MAX
        };
        // The modular arithmetic here and above replicate Index implementation
        // for LeaderSchedule, where the schedule keeps repeating endlessly.
        // The '%' returns where in a cycle we are and the '/' returns how many
        // times the schedule is repeated.
        Box::new(range.map(move |k| index[k % size] + k / size * num_slots))
    }

    fn num_slots(&self) -> usize {
        self.get_slot_leaders().len()
    }
}

// Note: passing in zero keyed stakes will cause a panic.
fn stake_weighted_slot_leaders(
    mut keyed_stakes: Vec<(&Pubkey, u64)>,
    epoch: Epoch,
    len: u64,
    repeat: u64,
) -> Vec<Pubkey> {
    sort_stakes(&mut keyed_stakes);
    let (keys, stakes): (Vec<_>, Vec<_>) = keyed_stakes.into_iter().unzip();
    let weighted_index = WeightedIndex::new(stakes).unwrap();
    let mut seed = [0u8; 32];
    seed[0..8].copy_from_slice(&epoch.to_le_bytes());
    let rng = &mut ChaChaRng::from_seed(seed);
    let mut current_slot_leader = Pubkey::default();
    (0..len)
        .map(|i| {
            if i % repeat == 0 {
                current_slot_leader = keys[weighted_index.sample(rng)];
            }
            current_slot_leader
        })
        .collect()
}

fn sort_stakes(stakes: &mut Vec<(&Pubkey, u64)>) {
    // Sort first by stake. If stakes are the same, sort by pubkey to ensure a
    // deterministic result.
    // Note: Use unstable sort, because we dedup right after to remove the equal elements.
    stakes.sort_unstable_by(|(l_pubkey, l_stake), (r_pubkey, r_stake)| {
        if r_stake == l_stake {
            r_pubkey.cmp(l_pubkey)
        } else {
            r_stake.cmp(l_stake)
        }
    });

    // Now that it's sorted, we can do an O(n) dedup.
    stakes.dedup();
}

#[cfg(test)]
mod tests {
    use {super::*, itertools::Itertools, rand::Rng, std::iter::repeat_with};

    #[test]
    fn test_get_leader_upcoming_slots() {
        const NUM_SLOTS: usize = 97;
        let mut rng = rand::thread_rng();
        let pubkeys: Vec<_> = repeat_with(Pubkey::new_unique).take(4).collect();
        let schedule: Vec<_> = repeat_with(|| pubkeys[rng.gen_range(0..3)])
            .take(19)
            .collect();
        let schedule = IdentityKeyedLeaderSchedule::new_from_schedule(schedule);
        let leaders = (0..NUM_SLOTS)
            .map(|i| (schedule[i as u64], i))
            .into_group_map();
        for pubkey in &pubkeys {
            let index = leaders.get(pubkey).cloned().unwrap_or_default();
            for offset in 0..NUM_SLOTS {
                let schedule: Vec<_> = schedule
                    .get_leader_upcoming_slots(pubkey, offset)
                    .take_while(|s| *s < NUM_SLOTS)
                    .collect();
                let index: Vec<_> = index.iter().copied().skip_while(|s| *s < offset).collect();
                assert_eq!(schedule, index);
            }
        }
    }

    #[test]
    fn test_sort_stakes_basic() {
        let pubkey0 = solana_pubkey::new_rand();
        let pubkey1 = solana_pubkey::new_rand();
        let mut stakes = vec![(&pubkey0, 1), (&pubkey1, 2)];
        sort_stakes(&mut stakes);
        assert_eq!(stakes, vec![(&pubkey1, 2), (&pubkey0, 1)]);
    }

    #[test]
    fn test_sort_stakes_with_dup() {
        let pubkey0 = solana_pubkey::new_rand();
        let pubkey1 = solana_pubkey::new_rand();
        let mut stakes = vec![(&pubkey0, 1), (&pubkey1, 2), (&pubkey0, 1)];
        sort_stakes(&mut stakes);
        assert_eq!(stakes, vec![(&pubkey1, 2), (&pubkey0, 1)]);
    }

    #[test]
    fn test_sort_stakes_with_equal_stakes() {
        let pubkey0 = Pubkey::default();
        let pubkey1 = solana_pubkey::new_rand();
        let mut stakes = vec![(&pubkey0, 1), (&pubkey1, 1)];
        sort_stakes(&mut stakes);
        assert_eq!(stakes, vec![(&pubkey1, 1), (&pubkey0, 1)]);
    }
}
