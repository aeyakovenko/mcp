# MCP Architectural Decisions for Agave Integration

This document outlines least-disruptive architectural decisions for completing MCP integration with Agave, based on analysis of current codebase patterns.

## Table of Contents
1. [Attestation Receiving Socket](#1-attestation-receiving-socket)
2. [MCP Consensus Block Distribution](#2-mcp-consensus-block-distribution)
3. [Vote Format Integration](#3-vote-format-integration)
4. [Transaction Wire Format](#4-transaction-wire-format)
5. [Bankless Leader](#5-bankless-leader)
6. [Implementation Priority](#6-implementation-priority)

---

## 1. Attestation Receiving Socket

### Current State
- `mcp_attestation_receiver: None` in tvu.rs:433
- Attestation sending is wired (window_service.rs)
- ReplayStage has processing logic ready (replay_stage.rs:944-989)

### Recommended Approach: Follow ShredFetchStage Pattern

**Why**: Agave has a well-established pattern for UDP socket reception. ShredFetchStage demonstrates the canonical approach used for shred ingestion.

### Implementation Steps (~50-60 lines total)

**Step 1: Add Socket Tag** (gossip/src/contact_info.rs)
```rust
// Around line 45, add new tag
const SOCKET_TAG_MCP_ATTESTATION: u8 = 14;
// Increment SOCKET_CACHE_SIZE from 14 to 15

// Add accessor macros (around line 300)
get_socket!(mcp_attestation, SOCKET_TAG_MCP_ATTESTATION);
set_socket!(set_mcp_attestation, SOCKET_TAG_MCP_ATTESTATION);
```

**Step 2: Add to Sockets Struct** (gossip/src/cluster_info.rs)
```rust
// In Sockets struct around line 2380
pub mcp_attestation: UdpSocket,
```

**Step 3: Bind Socket in Node** (gossip/src/node.rs)
```rust
// In new_with_external_ip, after other bindings (~line 250)
let (_, mcp_attestation) = bind_in_range_with_config(
    bind_ip_addr, port_range, socket_config
).expect("mcp_attestation bind");

// Advertise in ContactInfo (~line 310)
info.set_mcp_attestation((advertised_ip, mcp_attestation_port)).unwrap();
```

**Step 4: Add to TvuSockets** (core/src/tvu.rs:110-116)
```rust
pub struct TvuSockets {
    pub fetch: Vec<UdpSocket>,
    pub repair: UdpSocket,
    pub retransmit: Vec<UdpSocket>,
    pub ancestor_hashes_requests: UdpSocket,
    pub alpenglow_quic: UdpSocket,
    pub mcp_attestation: UdpSocket,  // NEW
}
```

**Step 5: Wire in Validator** (core/src/validator.rs:1643-1649)
```rust
TvuSockets {
    // ... existing ...
    mcp_attestation: node.sockets.mcp_attestation,
}
```

**Step 6: Create Receiver Thread** (core/src/tvu.rs, in Tvu::new)
```rust
// After other socket setup (~line 250)
let (attestation_sender, mcp_attestation_receiver) = unbounded();
let attestation_socket = Arc::new(sockets.mcp_attestation);
let attestation_exit = exit.clone();

let attestation_thread = Builder::new()
    .name("solMcpAttest".to_string())
    .spawn(move || {
        let mut buf = vec![0u8; 2048];
        attestation_socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
        while !attestation_exit.load(Ordering::Relaxed) {
            match attestation_socket.recv(&mut buf) {
                Ok(size) => {
                    if let Ok(attestation) = RelayAttestation::deserialize(&buf[..size]) {
                        let _ = attestation_sender.send(attestation);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => debug!("Attestation recv error: {}", e),
            }
        }
    })?;
```

**Step 7: Connect to ReplayStage** (core/src/tvu.rs:433)
```rust
mcp_attestation_receiver: Some(mcp_attestation_receiver),
```

### Why This Approach
- Follows existing patterns exactly (ShredFetchStage, repair socket)
- No changes to channel types or processing logic
- ReplayStage already has attestation handling code
- Minimal surface area for bugs

---

## 2. MCP Consensus Block Distribution

### Current State
- ConsensusBlock created in replay_stage.rs:2960-2970
- mcp_block_receiver wired to retransmit_stage (lines 686-698)
- TODO at retransmit_stage.rs:693 for actual distribution

### Recommended Approach: Gossip Push for Block Metadata + Shred Turbine for Data

**Why**: MCP consensus blocks serve two purposes:
1. **Metadata** (which proposers are included) - needs fast, reliable delivery
2. **Data** (the actual shred content) - already distributed via turbine

### Design Decision: Add CrdsData Variant for ConsensusBlockSummary

The full ConsensusBlock is large (contains all relay attestations). Instead, broadcast a **summary** via gossip:

```rust
// gossip/src/crds_data.rs - new variant
pub struct ConsensusBlockSummary {
    pub slot: Slot,
    pub leader_index: u32,
    pub included_proposers: Vec<u32>,  // Which proposers made it
    pub block_hash: Hash,               // Hash of full block for verification
    pub leader_signature: [u8; 64],
}
```

### Implementation Steps

**Step 1: Add CrdsData Variant** (gossip/src/crds_data.rs)
```rust
pub enum CrdsData {
    // ... existing variants ...
    ConsensusBlockSummary(ConsensusBlockSummary),
}
```

**Step 2: Add Push Method** (gossip/src/cluster_info.rs)
```rust
pub fn push_consensus_block_summary(&self, summary: ConsensusBlockSummary) {
    let now = timestamp();
    let entry = CrdsEntry::new(
        CrdsData::ConsensusBlockSummary(summary),
        now,
    );
    self.local_message_pending_push_queue
        .lock()
        .unwrap()
        .push((entry, now));
}
```

**Step 3: Modify ReplayStage** (core/src/replay_stage.rs:2975-2997)
```rust
// After storing consensus_block
if consensus_block.serialize(&mut block_bytes).is_ok() {
    // ... existing storage logic ...

    // Push summary to gossip for fast propagation
    let summary = ConsensusBlockSummary {
        slot,
        leader_index,
        included_proposers: consensus_block.compute_implied_blocks()
            .iter().map(|(id, _)| *id).collect(),
        block_hash: block_id,
        leader_signature: consensus_block.leader_signature,
    };
    cluster_info.push_consensus_block_summary(summary);
}
```

**Step 4: Remove retransmit_stage TODO** (turbine/src/retransmit_stage.rs:686-698)
The shred data is already distributed via turbine. The mcp_block_receiver can be removed or repurposed for local coordination only.

### Why This Approach
- Gossip has 9-node fanout, reaches all validators in ~4 hops
- Summary is small (~200 bytes), fits in single gossip message
- Validators can verify they have the shreds using included_proposers list
- No changes to turbine tree or shred distribution
- Repair service already handles missing shreds

### Alternative Considered: Full Block via Turbine
- Would require fragmenting block into packets
- Adds complexity to turbine deduplication
- No benefit since shred data already distributed
- **Rejected**: More disruptive, no advantage

---

## 3. Vote Format Integration

### Current State
- MCP votes exist in mcp_consensus_block.rs (McpVoteV1)
- Vote signing is spec-compliant (no domain prefix)
- Not wired to consensus vote flow

### Recommended Approach: Parallel Vote Path with Shared Tracking

**Why**: Agave has two voting paths already (Tower and Alpenglow/BLS). MCP can follow the Alpenglow pattern.

### Design: MCP Vote Flow

```
ReplayStage
    |
    +-- Tower votes (existing) --> VotingService --> Gossip
    |
    +-- MCP votes (new) --> mcp_vote_sender --> MCP Consensus Pool
```

### Implementation Steps

**Step 1: Add MCP Vote Channel** (core/src/replay_stage.rs)
```rust
// In ReplaySenders struct (~line 330)
pub mcp_vote_sender: Option<Sender<McpVoteV1>>,
```

**Step 2: Create MCP Vote When Building Block** (core/src/replay_stage.rs)
The vote should be created when the validator is ready to vote on a slot that has an MCP consensus block:

```rust
// After processing MCP block in replay
if let Some(sender) = &mcp_vote_sender {
    let vote = McpVoteV1::new_unsigned(slot, leader_index, block_id);
    vote.sign(identity_keypair);
    let _ = sender.send(vote);
}
```

**Step 3: Add MCP Vote Aggregation Service** (new file: core/src/mcp_vote_service.rs)
```rust
pub struct McpVoteService {
    receiver: Receiver<McpVoteV1>,
    cluster_info: Arc<ClusterInfo>,
}

impl McpVoteService {
    pub fn run(&self) {
        while let Ok(vote) = self.receiver.recv() {
            // Aggregate votes, check for 2/3 threshold
            // When threshold met, slot can be considered finalized
        }
    }
}
```

**Step 4: Wire in TVU** (core/src/tvu.rs)
```rust
let (mcp_vote_sender, mcp_vote_receiver) = unbounded();
// Pass sender to ReplayStage
// Create McpVoteService with receiver
```

### Why This Approach
- Follows existing Alpenglow BLS vote pattern exactly
- Existing VoteTracker can track MCP votes for confirmation
- No changes to tower voting, fork choice, or gossip voting
- MCP votes are separate consensus layer, doesn't interfere

### Alternative Considered: Integrate with VotingService
- Would require modifying VoteOp enum
- Mixes different signature schemes (ED25519 vs MCP)
- **Rejected**: Higher risk, no benefit

---

## 4. Transaction Wire Format

### Current State
- Spec defines TransactionConfigMask with inclusion_fee, ordering_fee, priority_fee
- SDK uses bincode serialization without MCP fields
- mcp.rs:206 has unused MCP config

### Recommended Approach: Proposer-Side Wrapper, Not SDK Changes

**Why**: Changing SDK transaction format is highly disruptive. MCP transactions are only parsed by proposers and validators during replay, not by wallets or RPC.

### Design: MCP Transaction Envelope

```rust
// ledger/src/mcp_transaction.rs
pub struct McpTransactionEnvelope {
    pub version: u8,           // MCP envelope version
    pub config_mask: u32,      // Which MCP fields present
    pub inclusion_fee: Option<u64>,
    pub ordering_fee: Option<u64>,
    pub priority_fee: Option<u64>,
    pub transaction: Vec<u8>,  // Standard serialized transaction
}
```

### Implementation Steps

**Step 1: Define Envelope Type** (ledger/src/mcp_transaction.rs)
```rust
impl McpTransactionEnvelope {
    pub fn wrap(tx: &Transaction, ordering_fee: u64) -> Self {
        Self {
            version: 1,
            config_mask: 0b010, // ordering_fee present
            inclusion_fee: None,
            ordering_fee: Some(ordering_fee),
            priority_fee: None,
            transaction: bincode::serialize(tx).unwrap(),
        }
    }

    pub fn unwrap(&self) -> Result<Transaction, Error> {
        bincode::deserialize(&self.transaction)
    }
}
```

**Step 2: Use in Proposer Payload** (turbine/src/broadcast_stage/standard_broadcast_run.rs)
```rust
// When building proposer payload, wrap transactions
let wrapped: Vec<McpTransactionEnvelope> = transactions
    .iter()
    .map(|tx| McpTransactionEnvelope::wrap(tx, extract_ordering_fee(tx)))
    .collect();
```

**Step 3: Parse in Reconstruction** (core/src/mcp_replay_reconstruction.rs)
The reconstruction already handles MCP payload format. Add envelope parsing.

### Why This Approach
- Zero changes to SDK, wallets, RPC
- MCP-specific parsing only in proposer/validator code
- Backward compatible - can fall back to raw transaction
- Envelope is internal to MCP pipeline

### Alternative Considered: SDK Transaction Format Change
- Would require coordinating with all downstream users
- Breaking change to wire format
- **Rejected**: Too disruptive for the benefit

---

## 5. Bankless Leader

### Current State
- broadcast_stage derives shreds from executed entries (lines 664-670)
- Spec requires shreds produced without executing bank

### Recommended Approach: Phased Migration, Not Immediate Change

**Why**: Bankless leader is a fundamental architectural change. It requires:
1. Transaction validation without execution
2. Shred creation from unexecuted transactions
3. Deferred execution in replay

This is not a "wire it up" task - it's a multi-month engineering effort.

### Interim Design: Proposer-Only Bankless

For MCP activation, only **proposers** need to be bankless. The **leader** can still execute because:
1. Leader aggregates proposer shreds, doesn't create transaction content
2. Leader's job is attestation aggregation and consensus block creation
3. Execution can happen after leader builds consensus block

```
Current Flow:
  Transactions → Bank Execution → Entries → Shreds → Broadcast

MCP Proposer Flow:
  Transactions → Validation Only → MCP Shreds → Relay Distribution

MCP Leader Flow:
  Collect Attestations → Build ConsensusBlock → Broadcast Summary
  Later: Replay executes using reconstructed proposer data
```

### Implementation Steps for Proposer-Only Bankless

**Step 1: Add Proposer Validation Mode** (banking_stage or new service)
```rust
pub fn validate_for_mcp(transaction: &Transaction) -> Result<(), Error> {
    // Signature verification
    // Account existence checks
    // Basic validity (not expired, correct blockhash)
    // NO execution
}
```

**Step 2: Create MCP Proposer Service** (new: core/src/mcp_proposer_service.rs)
```rust
pub struct McpProposerService {
    transaction_receiver: Receiver<Vec<Transaction>>,
    shred_sender: Sender<Vec<McpShredV1>>,
}

impl McpProposerService {
    pub fn run(&self, slot: Slot, proposer_index: u32, keypair: &Keypair) {
        // Receive transactions
        // Validate (not execute)
        // Build MCP shreds with Merkle commitments
        // Send to relay distribution
    }
}
```

**Step 3: Parallel to Existing Banking**
- MCP proposer service runs alongside banking_stage
- Both receive transactions from TPU
- Banking continues for non-MCP slots
- MCP proposer handles MCP slots

### Why This Approach
- Leader execution path unchanged
- Only proposers need modification
- Can be feature-flagged per slot
- Gradual migration possible

### Full Bankless Leader (Future)
This requires deeper changes:
- POH entries without execution
- Transaction replay ordering from consensus
- State commitment from replay, not leader
- **Timeline**: Estimate 3-6 months of dedicated work

---

## 6. Implementation Priority

### Phase 1: Wiring (1-2 weeks)
1. **Attestation receiving socket** - 50-60 lines, follows existing pattern
2. **ConsensusBlockSummary gossip** - 100-150 lines, standard CrdsData addition

### Phase 2: Vote Integration (2-3 weeks)
3. **MCP vote channel and service** - New service, follows Alpenglow pattern
4. **Vote aggregation for finality** - Threshold checking

### Phase 3: Transaction Format (1-2 weeks)
5. **McpTransactionEnvelope** - Wrapper type, no SDK changes
6. **Proposer payload encoding** - Use envelope in broadcast

### Phase 4: Proposer Bankless (1-2 months)
7. **Validation-only mode** - Transaction checks without execution
8. **MCP proposer service** - Parallel to banking_stage

### Phase 5: Full Bankless Leader (3-6 months)
9. **POH without execution** - Major architectural change
10. **Replay-based state commitment** - Deferred execution

---

## Summary

| Issue | Approach | Disruption Level | Effort |
|-------|----------|------------------|--------|
| Attestation Socket | Follow ShredFetchStage pattern | Low | 1-2 days |
| Block Distribution | Gossip summary + existing turbine | Low | 2-3 days |
| Vote Integration | Parallel vote path | Medium | 1-2 weeks |
| Transaction Format | Envelope wrapper | Low | 3-5 days |
| Bankless Proposer | New proposer service | Medium | 1-2 months |
| Bankless Leader | Deferred execution | High | 3-6 months |

The key insight is that MCP can be **incrementally activated** without requiring full bankless operation on day one. Proposer-only bankless with leader execution is sufficient for initial MCP activation.
