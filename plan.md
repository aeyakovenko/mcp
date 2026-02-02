# MCP Implementation Plan

Spec: `docs/src/proposals/mcp-protocol-spec.md`

## Constraints

- Reuse existing TPU/TVU pipelines, sigverify, window_service, blockstore, replay_stage, and execution paths.
- No new stages. Only add small, targeted modules where no equivalent exists.
- All MCP paths gated by `feature_set::mcp_protocol_v1::id()`.
- Do NOT modify `ShredVariant`, `ShredCommonHeader`, or existing shred pipeline types.
- MCP shreds use their own wire format and dedicated column families, separate from Agave shreds.

## Agave Reuse Map

| MCP concept | Agave component | Reusable? | Key location |
|---|---|---|---|
| Schedule generation algo | `stake_weighted_slot_leaders()` | YES | `leader_schedule.rs:72` — same ChaChaRng/WeightedIndex pattern, different seed |
| Schedule cache pattern | `LeaderScheduleCache` | YES | `leader_schedule_cache.rs:30` — add parallel caches for proposer/relay |
| Column trait | `Column` trait | YES | `column.rs:308` — 3-tuple index supported (`AlternateShredData` at `column.rs:742`) |
| Blockstore struct pattern | `Blockstore` | YES | `blockstore.rs:252` — add `LedgerColumn` fields; register in `cf_descriptors()` at `blockstore_db.rs:176` |
| Window service `run_insert()` | `run_insert()` | YES | `window_service.rs:190` — partition MCP before Agave deserialization at line 220 |
| Replay main loop | `ReplayStage` | YES | `replay_stage.rs:823` — add `mcp_attestation_receiver` to `ReplayReceivers` at line 330 |
| confirm_slot pipeline | `confirm_slot()` | PARTIAL | `blockstore_processor.rs:1485` — reuse `process_entries()` for Phase B with Bank-level fee flag |
| validate_fee_payer | `validate_fee_payer()` | PARTIAL | `account_loader.rs:370` — needs MCP multiplier check via Bank-level flag, not a rewrite |
| Voting path | `Tower::record_vote()` | YES | `consensus.rs:717` — unchanged |
| Gossip sockets | `SOCKET_TAG_*` constants | YES | `contact_info.rs:34-47` — 14 tags (0-13), cache size 14 |
| CRDS data | `CrdsData` enum | YES | `crds_data.rs:44-65` — 14 variants, last: `RestartHeaviestFork` at line 64 |
| TVU sockets | `TvuSockets` | YES | `tvu.rs:110-116` — fetch, repair, retransmit, ancestor_hashes, alpenglow_quic |
| TPU pipeline | `Tpu` | YES | `tpu.rs:71-82` — FetchStage -> SigVerify -> BankingStage -> Broadcast |

**NOT reusable (MCP must implement its own):**

| Agave component | Location | Why not reusable |
|---|---|---|
| `MerkleTree` | `merkle_tree.rs:37` | `pub(crate)`; Agave uses 28-byte domain-separated prefixes (`\x00SOLANA_MERKLE_SHREDS_LEAF`), MCP spec section 6 uses 1-byte `0x00`/`0x01` prefixes; Agave `MerkleProofEntry` is 20 bytes, MCP needs 32-byte witness entries; `join_nodes()` at line 100 truncates to 20 bytes |
| `get_merkle_root()` | `merkle_tree.rs:108` | Uses 20-byte `MerkleProofEntry`, incompatible with MCP 32-byte entries |
| `MERKLE_HASH_PREFIX_*` | `merkle_tree.rs:17-18` | Agave: `b"\x00SOLANA_MERKLE_SHREDS_LEAF"` (28 bytes); MCP: `0x00` (1 byte) |
| `ReedSolomonCache::get()` | `shredder.rs:276` | `pub(crate)`, no public constructor; use `reed_solomon_erasure::ReedSolomon::new()` directly |

---

## Pass 1 — Feature Gate + Constants + Wire Types

**Goal:** MCP types compile and serialize. No behavioral change.

### 1.1 Feature gate

`feature-set/src/lib.rs` — model after existing feature declarations.

- Declare `pub mod mcp_protocol_v1 { declare_id!("..."); }`.
- Register in `FEATURE_NAMES` map.

### 1.2 Constants and wire types

Create `ledger/src/mcp.rs`. Spec section 4, section 3.1, section 7.3-7.5, section 8.

Constants:
```
NUM_PROPOSERS = 16        NUM_RELAYS = 200
DATA_SHREDS   = 40        CODING_SHREDS = 160
SHRED_DATA_BYTES = 1228   // spec §4: max shred payload bytes (fits in PACKET_DATA_SIZE=1232 with 4-byte header overhead)
ATTESTATION_THRESHOLD  = 0.60  -> ceil = 120 relays
INCLUSION_THRESHOLD    = 0.40  -> ceil =  80 relays
RECONSTRUCTION_THRESHOLD = 0.20 -> ceil = 40 relays (= DATA_SHREDS)
MAX_PROPOSER_PAYLOAD = NUM_RELAYS * SHRED_DATA_BYTES  // 245,600 bytes per proposer
```

Types (all with serialize/deserialize/sign/verify):
- `McpPayload` — `tx_count:u32 + [tx_len:u32, tx_bytes]...` (section 3.1). Trailing zero padding ignored.
- `RelayAttestation` — version:1 + slot:8 + relay_index:4 + entries_len:1 + entries[proposer_index:4 + commitment:32 + proposer_sig:64] + relay_sig:64 (section 7.3).
- `AggregateAttestation` — version:1 + slot:8 + leader_index:4 + relays_len:2 + relay_entries sorted by relay_index (section 7.4).
- `ConsensusBlock` — version:1 + slot:8 + leader_index:4 + aggregate_len:4 + aggregate + consensus_meta_len:4 + consensus_meta + delayed_bankhash:32 + leader_sig:64 (section 7.5).
- `reconstruct_batch()` — RS decode via `reed_solomon_erasure::ReedSolomon::new(40, 160)` (NOT `ReedSolomonCache` — it is `pub(crate)`), re-encode, verify commitment matches (section 3.6).
- `order_transactions()` — concat by proposer_index ascending, sort by ordering_fee desc, ties broken by position in concatenated list (section 3.6). Ordering_fee is derived from the transaction's `compute_unit_price` (see section 5.2).

### 1.3 MCP Merkle tree

Create `ledger/src/mcp_merkle.rs`. Spec section 6.

MCP uses a different Merkle construction than Agave's shred Merkle tree and CANNOT reuse it:
- Agave uses 28-byte domain-separated prefixes (`b"\x00SOLANA_MERKLE_SHREDS_LEAF"`) and 20-byte proof entries (`MerkleProofEntry = [u8; 20]`), with `join_nodes()` truncating to 20 bytes before hashing.
- MCP spec section 6 defines: leaf = `SHA-256(0x00 || slot || proposer_index || shred_index || shred_data)`, internal = `SHA-256(0x01 || left || right)`, with 32-byte witness entries.

Implement:
```
pub const MCP_MERKLE_LEAF_PREFIX: u8 = 0x00;
pub const MCP_MERKLE_NODE_PREFIX: u8 = 0x01;
pub type McpMerkleProofEntry = [u8; 32];

pub fn mcp_leaf_hash(slot: u64, proposer_index: u32, shred_index: u32, shred_data: &[u8]) -> Hash
pub fn mcp_node_hash(left: &[u8; 32], right: &[u8; 32]) -> Hash
pub fn mcp_merkle_tree(leaves: &[Hash]) -> Vec<Hash>   // returns flat array, root is last element
pub fn mcp_merkle_proof(tree: &[Hash], num_leaves: usize, leaf_index: usize) -> Vec<McpMerkleProofEntry>
pub fn mcp_verify_proof(leaf: Hash, index: usize, proof: &[McpMerkleProofEntry], expected_root: &Hash) -> bool
```

### 1.4 MCP shred wire format

Create `ledger/src/shred/mcp_shred.rs`. Spec section 7.2.

MCP shred format (separate from ShredVariant — do NOT touch `shred.rs:227`):
```
slot:8 + proposer_index:4 + shred_index:4 + commitment:32
+ shred_data:SHRED_DATA_BYTES + witness_len:1 + witness:32*witness_len
+ proposer_sig:64
```

Functions:
- `is_mcp_shred_packet(packet) -> bool` — detect MCP shred by size/header pattern, distinguishing from Agave shreds which start with 64-byte signature then variant byte at offset 64.
- `McpShred::from_bytes(data) -> Result<McpShred>` — parse and validate field ranges.
- `McpShred::to_bytes(&self) -> Vec<u8>` — serialize.
- `McpShred::verify_signature(&self, proposer_pubkey) -> bool` — verify proposer_sig over commitment.
- `McpShred::verify_witness(&self) -> bool` — compute leaf hash via `mcp_leaf_hash()` from `mcp_merkle.rs`, walk witness via `mcp_verify_proof()`, compare with commitment. Uses MCP-specific 32-byte proof entries and 1-byte prefixes (NOT Agave's `MERKLE_HASH_PREFIX_*`).

### 1.5 Tests

- Round-trip serialization of every wire type.
- MCP Merkle tree: leaf hash matches spec section 6 construction.
- MCP Merkle tree: proof generation and verification round-trip for various tree sizes.
- MCP Merkle tree: wrong leaf/index fails verification.
- `is_mcp_shred_packet()` correctly distinguishes MCP from Agave shreds.
- SHRED_DATA_BYTES fits within PACKET_DATA_SIZE constraints.

---

## Pass 2 — Schedules

**Goal:** Given a slot, any node can deterministically derive `Proposers[s]`, `Relays[s]`.

### 2.1 Domain-separated schedule generation

`ledger/src/leader_schedule.rs` — add alongside `stake_weighted_slot_leaders()` at line 72:

```
fn stake_weighted_slot_schedule(keyed_stakes, epoch, len, domain: &[u8]) -> Vec<Pubkey>
```

Same algorithm (sort, WeightedIndex, ChaChaRng) but seed = `SHA-256(domain || epoch.to_le_bytes())`, `repeat = 1`. Domains: `b"mcp:proposer"`, `b"mcp:relay"` (spec section 5).

Per spec section 5: `Proposers[s]` = sliding window of 16 entries at slot index within epoch with wrap. `Relays[s]` = sliding window of 200 entries with wrap.

### 2.2 Schedule cache

`ledger/src/leader_schedule_cache.rs` — add fields alongside `cached_schedules` at line 32:

```
cached_proposer_schedules: RwLock<(HashMap<Epoch, Arc<Vec<Pubkey>>>, VecDeque<Epoch>)>
cached_relay_schedules:    RwLock<(HashMap<Epoch, Arc<Vec<Pubkey>>>, VecDeque<Epoch>)>
```

Query methods mirroring `slot_leader_at()` at line 95:
- `proposers_at_slot(slot, bank) -> Option<Vec<Pubkey>>` — returns 16-element window.
- `relays_at_slot(slot, bank) -> Option<Vec<Pubkey>>` — returns 200-element window.
- `proposer_index_at_slot(slot, pubkey, bank) -> Option<u8>` — lookup by identity.
- `relay_index_at_slot(slot, pubkey, bank) -> Option<u16>` — lookup by identity.

### 2.3 Schedule utils

`ledger/src/leader_schedule_utils.rs` — add:
- `mcp_proposer_schedule(epoch, bank) -> Option<Arc<Vec<Pubkey>>>`
- `mcp_relay_schedule(epoch, bank) -> Option<Arc<Vec<Pubkey>>>`

### 2.4 Tests

- Domain separation produces different schedules from leader schedule for same epoch.
- `proposers_at_slot()` returns 16-element window.
- `relays_at_slot()` returns 200-element window.
- Wrap-around at epoch boundary.

---

## Pass 3 — Storage + Sigverify

**Goal:** MCP shreds can be stored in blockstore and verified by sigverify. No pipeline wiring yet.

### 3.1 MCP column families

`ledger/src/blockstore/column.rs` — add new column types after existing definitions:

- `McpShredData` — index: `(Slot, u8, u32)` (slot, proposer_index, shred_index), value: `Vec<u8>`, name: `"mcp_data_shred"`.
- `McpRelayAttestation` — index: `(Slot, u16)` (slot, relay_index), value: `Vec<u8>`, name: `"mcp_relay_attestation"`.

### 3.2 Blockstore MCP APIs

`ledger/src/blockstore.rs` — add fields to `Blockstore` struct after line 261:

```
mcp_data_shred_cf: LedgerColumn<cf::McpShredData>,
mcp_relay_attestation_cf: LedgerColumn<cf::McpRelayAttestation>,
```

Add methods:
- `put_mcp_data_shred(slot, proposer_index, shred_index, data) -> Result<()>`
- `get_mcp_data_shreds_for_proposer(slot, proposer_index) -> Result<Vec<(u32, Vec<u8>)>>`
- `put_mcp_relay_attestation(slot, relay_index, data) -> Result<()>`
- `get_mcp_relay_attestations(slot) -> Result<Vec<(u16, Vec<u8>)>>`

### 3.3 Sigverify integration

`turbine/src/sigverify_shreds.rs` — modify `run_shred_sigverify()` at line 162 (packet receipt point).

**Critical:** MCP shreds CANNOT be in the same GPU batch as Agave shreds. Agave's GPU batch verification (`verify_shreds_gpu` at line 269) requires signature at bytes 0-63 and variant at byte 64. MCP shreds have slot at bytes 0-7 and proposer_index at bytes 8-11 — incompatible wire format.

Fix: Partition BEFORE GPU batching:
1. At packet receipt (line 162 in `run_shred_sigverify`), scan each packet with `is_mcp_shred_packet()` and partition into MCP vs Agave packet batches.
2. Agave packets proceed through existing GPU batch path (`verify_shreds_gpu` at line 269).
3. MCP packets go through a **CPU-only** verification path:
   - Parse via `McpShred::from_bytes()`.
   - Look up proposer pubkey via `leader_schedule_cache.proposers_at_slot(slot)[proposer_index]` (requires Pass 2 schedule cache).
   - Verify `proposer_signature` (Ed25519 over commitment).
   - Verify `witness` (Merkle proof via `mcp_verify_proof()` from `mcp_merkle.rs`).
   - Discard on any failure.
4. Send both Agave-verified and MCP-verified packets into the same `verified_sender` channel.

### 3.4 Tests

- MCP shred stored and retrieved from blockstore via MCP CFs.
- Sigverify accepts valid MCP shred, rejects bad signature, rejects bad witness.
- MCP shreds correctly partitioned away from GPU batch (no GPU errors from MCP wire format).

---

## Pass 4 — Window Service + Relay Attestations + Retransmit

**Goal:** MCP shreds flow through window_service, are stored, tracked, relays produce attestations and retransmit shreds to all validators.

### 4.1 MCP shred handling in window_service

`core/src/window_service.rs` — modify `run_insert()` at line 190.

**Critical:** The partition MUST happen at the raw `Payload` byte level, BEFORE Agave deserialization at line 220 (`Shred::new_from_serialized_shred(shred).ok()?`). MCP shreds fail the `ShredVariant` check at byte 64 and are silently discarded by `.ok()?`.

Fix: Between lines 212-213 (where raw `Payload` bytes are received, before the `handle_shred` closure that calls `Shred::new_from_serialized_shred`):
1. Examine raw `Payload` bytes with `is_mcp_shred_packet()`.
2. MCP payloads: route to separate MCP handling path using `McpShred::from_bytes()`.
3. Non-MCP payloads: proceed through existing Agave path (deserialization at line 220, blockstore insert at line 233).

MCP handling path:
- Parse via `McpShred::from_bytes()`.
- Store via `blockstore.put_mcp_data_shred()`.
- Track per-(slot, proposer_index) shred counts for reconstruction readiness.
- Record for relay attestation (see 4.2).

### 4.2 Relay attestation tracking

Add attestation state to `run_insert()` or a small helper struct:

Per-slot `HashMap<u8, (Hash, Signature)>`: `proposer_index -> (commitment, proposer_sig)`.
- If a proposer sends conflicting commitments -> mark equivocation, do not attest (spec section 3.3).
- At most one entry per proposer per slot.

At relay deadline for slot s:
1. Look up `relay_index_at_slot(slot, &my_pubkey)`.
2. If this node is a relay: collect non-equivocating entries sorted by proposer_index.
3. Build + sign `RelayAttestation` (from `ledger/src/mcp.rs`).
4. Send to Leader[s] via QUIC (see 4.3).
5. At most one attestation per slot.

### 4.3 MCP attestation transport via QUIC

**Critical:** A `RelayAttestation` with 16 proposer entries is 1+8+4+1+16*(4+32+64)+64 = 1,678 bytes. This exceeds `PACKET_DATA_SIZE` (1,232 bytes) and UDP MTU (1,280 bytes). UDP transport will silently drop these packets.

Fix: Use QUIC for attestation transport. Reuse the existing `alpenglow_quic` socket infrastructure (`tvu.rs:110-116`, lines 260-273 show QUIC usage for BLS traffic).

`gossip/src/contact_info.rs` — add after `SOCKET_TAG_ALPENGLOW = 13` at line 47:
```
SOCKET_TAG_MCP_ATTESTATION: u8 = 14
```
Bump `SOCKET_CACHE_SIZE` at line 49 from 14 to 15.

`core/src/tvu.rs` — add MCP attestation QUIC endpoint alongside existing alpenglow_quic setup:
- Spawn a "solMcpAttest" receiver thread that accepts QUIC connections, deserializes `RelayAttestation` messages, and sends them to replay_stage via a new channel.
- Attestation sender (relay side in 4.2) connects to Leader[s]'s MCP attestation QUIC endpoint to send `RelayAttestation`.

### 4.4 MCP shred retransmit

**Critical:** Spec section 3.3 requires relays to broadcast the same Shred message to all validators. The plan must specify how.

Fix: After a relay receives and verifies MCP shreds from a proposer:
1. Relay looks up all validator TVU addresses via `ClusterInfo`.
2. Relay broadcasts each verified MCP shred to all validators via their TVU fetch sockets (existing UDP infrastructure, MCP shreds fit within `PACKET_DATA_SIZE`).
3. This is simpler than adapting turbine trees (which are slot-leader-specific) and matches the spec's "relay MUST broadcast" requirement.
4. Duplicate shred detection at receivers: `blockstore.put_mcp_data_shred()` is idempotent (same key overwrites with same data).

### 4.5 Tests

- MCP shreds stored via window_service path (partition before deserialization).
- Relay attests to valid single-commitment proposers.
- Relay does not attest to equivocating proposer.
- One attestation per slot enforced.
- Attestation serialized size fits QUIC (no PACKET_DATA_SIZE limit).
- Retransmit path sends to all validators.

---

## Pass 5 — Proposer Pipeline

**Goal:** A proposer node collects sig-verified txs, encodes MCP shreds, sends one per relay. Bankless.

### 5.1 Clone sender in sigverify

`core/src/tpu.rs` — add an optional `Sender<Vec<PacketBatch>>` for MCP proposer packets.

When `mcp_protocol_v1` active and `leader_schedule_cache.proposers_at_slot(slot)` includes this node's pubkey, clone the sig-verified packet batch into the MCP sender. This taps into the existing TPU pipeline after SigVerify (line 288-293) but before BankingStage.

### 5.2 Proposer loop

`core/src/tpu.rs` — add an MCP proposer thread:

1. Receive cloned packets from 5.1.
2. Extract ordering_fee from each transaction's existing `compute_unit_price` field (the priority fee set via `SetComputeUnitPrice` instruction). **Note:** Standard Solana wire-format transactions do NOT contain a `TransactionConfigMask` or dedicated `ordering_fee` field. The MCP spec section 7.1 `TransactionConfigMask` is a future extension; for initial implementation, `ordering_fee = compute_unit_price` from the transaction's compute budget instructions. Transactions without a `SetComputeUnitPrice` instruction have `ordering_fee = 0`.
3. Sort by ordering_fee descending, ties by position.
4. Serialize to `McpPayload` (max `NUM_RELAYS * SHRED_DATA_BYTES` = 245,600 bytes).
5. RS encode via `reed_solomon_erasure::ReedSolomon::new(40, 160)` directly (NOT `ReedSolomonCache` — it is `pub(crate)` and has no public constructor). Cache the `ReedSolomon` instance locally in the proposer thread since the parameters are fixed.
6. Compute Merkle commitment per spec section 6 using `mcp_merkle_tree()` from `mcp_merkle.rs`.
7. Build `McpShred` for each relay index (0..199) with witness from `mcp_merkle_proof()` + proposer_signature.
8. Look up relay addresses via `relays_at_slot()` + `ClusterInfo::lookup_contact_info()`.
9. Send one shred per relay to their TVU address.

No bank, no PoH — this is bankless per spec section 9.

### 5.3 Per-proposer CU budgets

`core/src/banking_stage/qos_service.rs` — when `mcp_protocol_v1` active, divide block-level limits by `NUM_PROPOSERS` (16):
- `block_cost_limit /= 16`
- `account_cost_limit /= 16`

### 5.4 Tests

- Proposer produces 200 shreds (one per relay).
- Payload size within `NUM_RELAYS * SHRED_DATA_BYTES`.
- RS encode -> decode round-trip.
- CU budget enforcement at 1/16th.
- ordering_fee correctly extracted from compute_unit_price.
- Transactions without SetComputeUnitPrice get ordering_fee=0.

---

## Pass 6 — Leader Aggregation + ConsensusBlock

**Goal:** The leader collects relay attestations, builds the aggregate, broadcasts ConsensusBlock.

### 6.1 Receive attestations

MCP attestation packets arrive via the "solMcpAttest" QUIC thread from Pass 4.3. Add `mcp_attestation_receiver` to `ReplayReceivers` at `replay_stage.rs:330`.

### 6.2 Verify and aggregate

`core/src/replay_stage.rs` — in the main loop at line 823, drain attestations each iteration:

1. Verify relay_signature; discard message if invalid (spec section 3.4).
2. Verify each proposer_signature against commitment; drop invalid entries.
3. Accumulate into per-slot `AggregateAttestation`.

### 6.3 Build ConsensusBlock

When this node is Leader[s] and aggregation deadline is reached:

1. If relay count < 120 (ATTESTATION_THRESHOLD) -> submit empty result (spec section 3.4).
2. Build AggregateAttestation with relay entries sorted by relay_index.
3. Construct ConsensusBlock with aggregate + consensus_meta + delayed_bankhash.
4. Sign the ConsensusBlock.

### 6.4 ConsensusBlock distribution

**Primary mechanism: direct broadcast via QUIC.**
Leader broadcasts the full `ConsensusBlock` to all validators via their TVU QUIC endpoints. ConsensusBlocks can be large (aggregate with 120+ relay entries), so QUIC is required to avoid UDP size limits.

**Fallback: gossip summary.**
`gossip/src/crds_data.rs` — add `McpConsensusBlockSummary` variant to `CrdsData` enum after line 64. This contains: slot, leader_index, block_hash, relay_count (compact, fits gossip). Validators that miss the direct broadcast can detect via gossip that a ConsensusBlock exists.

**Missed block recovery:**
Validators that see a gossip summary but lack the full ConsensusBlock send a request to the leader (or any peer that has it) via the existing repair socket infrastructure. The response is the serialized ConsensusBlock sent via QUIC.

### 6.5 Tests

- Threshold enforcement: <120 relays -> empty.
- Invalid relay sig -> entire message dropped.
- Invalid proposer sig -> entry dropped, rest kept.
- ConsensusBlock signature verifies.
- Direct broadcast delivers to all validators.
- Gossip summary propagates for missed blocks.

---

## Pass 7 — Vote Gate + Reconstruct + Replay

**Goal:** Validators verify ConsensusBlock, reconstruct batches, execute with two-phase fees, and vote.

### 7.1 ConsensusBlock validation (vote gate)

`core/src/replay_stage.rs` — on receiving ConsensusBlock for slot s (spec section 3.5):

1. Verify leader_signature, leader_index matches Leader[s].
2. Verify delayed_bankhash against local bank hash.
3. Verify every relay_signature and proposer_signature in aggregate.
4. Compute implied proposers:
   - 2+ distinct commitments -> equivocating -> exclude.
   - 1 commitment with >=80 relay attestations (INCLUSION_THRESHOLD) -> include.
5. For each included proposer: count locally stored shreds with valid witness >=40 (RECONSTRUCTION_THRESHOLD).
6. Any included proposer below 40 -> do not vote.

### 7.2 Reconstruct

For each included proposer:

1. Gather >=40 MCP shreds from blockstore via `get_mcp_data_shreds_for_proposer()`.
2. `reconstruct_batch()` from `ledger/src/mcp.rs` — RS decode via `reed_solomon_erasure::ReedSolomon::new(40, 160)` (NOT `ReedSolomonCache` — it is `pub(crate)`). Re-encode, recompute commitment via `mcp_merkle_tree()`. Discard if mismatch (spec section 3.6).
3. Parse `McpPayload` -> transactions.

### 7.3 Order and execute

1. `order_transactions()` from `ledger/src/mcp.rs` — concat by proposer_index ascending, sort by ordering_fee desc (where ordering_fee = compute_unit_price), ties by position.
2. Two-phase execution via new `confirm_slot_mcp()` in `ledger/src/blockstore_processor.rs`:

**Phase A (fees):** Pre-process fee deduction directly on the Bank, BEFORE entering the standard execution pipeline. For each transaction in order:
- Validate fee payer can cover `fee * NUM_PROPOSERS` (spec section 8).
- Directly debit fee payer accounts on the Bank via `bank.withdraw()` or equivalent.
- Track per-slot cumulative per-payer fees to prevent over-commitment.
- Collect the list of fee-valid transactions for Phase B.

This avoids threading a flag through 12 layers of execution (process_entries -> process_batches -> execute_batches -> execute_batches_internal -> execute_batch -> load_execute_and_commit_transactions -> do_load_execute_and_commit_transactions -> load_and_execute_transactions -> load_and_execute_sanitized_transactions -> validate_transaction_nonce_and_fee_payer -> validate_transaction_fee_payer -> validate_fee_payer).

**Phase B (execution):** Set a Bank-level flag `bank.set_mcp_fee_mode(true)` that causes `validate_fee_payer()` at `account_loader.rs:370` to skip fee deduction (fees already deducted in Phase A). Then execute ordered txs via existing `process_entries()` at `blockstore_processor.rs:649`. This requires 2-3 changes:
1. Add `mcp_fee_mode: AtomicBool` field to `Bank` (similar to existing `vote_only_bank`, `check_program_modification_slot` flags).
2. In `validate_fee_payer()` at `account_loader.rs:370`: if MCP fee mode is set, skip the `checked_sub_lamports(fee)` at line 406.
3. `confirm_slot_mcp()` sets the flag before calling `process_entries()` and clears it after.

3. Freeze bank. Set `bank.block_id()` from ConsensusBlock.

### 7.4 Vote

```
tower.record_vote(slot, block_id)   // existing path at consensus.rs:717 — unchanged
```

### 7.5 Empty slot

Consensus outputs empty result -> freeze bank with no transactions.

### 7.6 Tests

- Vote gate rejects: bad leader sig, bad bankhash, equivocating proposer, insufficient shreds.
- Reconstruction round-trip: shred -> reconstruct -> verify commitment.
- Ordering: ordering_fee sort is deterministic.
- Fee multiplier: payer needs 16x balance.
- Bank-level fee flag correctly skips re-deduction in Phase B.
- End-to-end in `core/tests/mcp_integration.rs`.

---

## New Files

| File | Contents |
|---|---|
| `ledger/src/mcp.rs` | Constants (including SHRED_DATA_BYTES), wire types (McpPayload, RelayAttestation, AggregateAttestation, ConsensusBlock), reconstruct_batch(), order_transactions() |
| `ledger/src/mcp_merkle.rs` | MCP-specific Merkle tree with 1-byte prefixes (0x00/0x01) and 32-byte proof entries per spec section 6 |
| `ledger/src/shred/mcp_shred.rs` | MCP shred wire format, parse/serialize, is_mcp_shred_packet(), verify signature + witness |

## Modified Files

| File | Change |
|---|---|
| `feature-set/src/lib.rs` | `mcp_protocol_v1` feature ID + FEATURE_NAMES |
| `ledger/src/leader_schedule.rs` | `stake_weighted_slot_schedule()` with domain-separated seed |
| `ledger/src/leader_schedule_cache.rs` | proposer/relay schedule caches + query methods |
| `ledger/src/leader_schedule_utils.rs` | `mcp_proposer_schedule()`, `mcp_relay_schedule()` |
| `ledger/src/blockstore/column.rs` | `McpShredData`, `McpRelayAttestation` column types |
| `ledger/src/blockstore.rs` | MCP column fields + put/get APIs |
| `turbine/src/sigverify_shreds.rs` | Partition MCP packets at receipt (line 162) BEFORE GPU batching; CPU-only MCP verification path |
| `core/src/window_service.rs` | Partition at raw Payload bytes (lines 212-213) BEFORE Agave deserialization at line 220; MCP storage + tracking |
| `gossip/src/contact_info.rs` | `SOCKET_TAG_MCP_ATTESTATION = 14`, bump cache size to 15 |
| `gossip/src/crds_data.rs` | `McpConsensusBlockSummary` variant |
| `core/src/tvu.rs` | MCP attestation QUIC endpoint + "solMcpAttest" thread + channel to replay |
| `core/src/tpu.rs` | MCP proposer clone sender + proposer loop thread |
| `core/src/banking_stage/qos_service.rs` | CU limits / NUM_PROPOSERS |
| `core/src/replay_stage.rs` | Attestation aggregation, ConsensusBlock building, direct QUIC broadcast, vote gate, reconstruction dispatch |
| `ledger/src/blockstore_processor.rs` | `confirm_slot_mcp()` with two-phase fee execution (Phase A direct debit + Phase B with Bank flag) |
| `runtime/src/bank.rs` | `mcp_fee_mode: AtomicBool` flag + setter/getter |
| `svm/src/account_loader.rs` | Check MCP fee mode flag in `validate_fee_payer()` to skip re-deduction |

## Dependency Graph

```
Pass 1 (types+merkle) ──┐
Pass 2 (schedules)  ────┤── can parallelize
Pass 3.1-3.2 (storage)──┘
       │
Pass 3.3 (sigverify) ── depends on Pass 1 + Pass 2 (needs schedule cache for proposer pubkey lookup)
       │
Pass 4 (window+relay+retransmit) -> Pass 5 (proposer) -> Pass 6 (leader) -> Pass 7 (vote+replay)
```

Note: Pass 3 is split. Storage (3.1-3.2) can parallelize with Pass 1 and 2. Sigverify (3.3) depends on both Pass 1 (MCP types + Merkle verification) and Pass 2 (schedule cache for `proposers_at_slot()` lookup).
