# MCP Implementation Plan

Spec: `docs/src/proposals/mcp-protocol-spec.md`

## Constraints

- Reuse existing TPU/TVU pipelines, sigverify, window_service, blockstore, replay_stage, and execution paths.
- No new stages. Only add small, targeted modules where no equivalent exists.
- All MCP paths gated by `feature_set::mcp_protocol_v1::id()`.
- Do NOT modify `ShredVariant`, `ShredCommonHeader`, or existing shred pipeline types.
- MCP shreds use their own wire format and dedicated column families, separate from Agave shreds.

## Agave Reuse Map

| MCP concept | Agave component | Key location |
|---|---|---|
| Erasure coding cache | `ReedSolomonCache` | `shredder.rs:276` — `.get(data, parity)` returns `Arc<ReedSolomon>` |
| Merkle tree | `MerkleTree` | `merkle_tree.rs:37` — `try_new()`, `root()`, `make_merkle_proof()` |
| Merkle verification | `get_merkle_root()` | `merkle_tree.rs:108` — recomputes root from leaf + proof |
| Merkle hash prefixes | `MERKLE_HASH_PREFIX_{LEAF,NODE}` | `merkle_tree.rs:17-18` |
| Schedule generation | `stake_weighted_slot_leaders()` | `leader_schedule.rs:72` — ChaChaRng seeded with epoch bytes |
| Schedule cache | `LeaderScheduleCache` | `leader_schedule_cache.rs:29` — `cached_schedules`, `slot_leader_at()` at line 95 |
| Shred sigverify | `spawn_shred_sigverify()` | `sigverify_shreds.rs:79` — pubkey lookup via `get_slot_leaders()` at line 446 |
| Window insert | `run_insert()` | `window_service.rs:190` — receives verified shreds, stores in blockstore |
| Blockstore storage | `data_shred_cf` / `code_shred_cf` | `blockstore.rs:260-261` — keyed by `(Slot, u64)` |
| Column definitions | `Column` trait | `column.rs:308` — `type Index`, `type Key`, `key()`, `index()` |
| Shred column names | `ShredData` / `ShredCode` | `column.rs:157,164` — `"data_shred"`, `"code_shred"` |
| Replay main loop | `ReplayStage` | `replay_stage.rs:823` — main loop, 10246 lines total |
| Bank confirmation | `confirm_slot()` | `blockstore_processor.rs:1485` — loads entries, calls `confirm_slot_entries()` at line 1604 |
| Entry execution | `process_entries()` | `blockstore_processor.rs:649` — converts entries to batches, executes |
| Fee validation | `validate_fee_payer()` | `account_loader.rs:370` — checks balance, deducts fee at line 406 |
| Gossip sockets | `SOCKET_TAG_*` constants | `contact_info.rs:34-47` — 14 tags (0-13), cache size 14 |
| CRDS data | `CrdsData` enum | `crds_data.rs:44-65` — 14 variants, last: `RestartHeaviestFork` at line 64 |
| TVU sockets | `TvuSockets` | `tvu.rs:110-116` — fetch, repair, retransmit, ancestor_hashes, alpenglow_quic |
| TPU pipeline | `Tpu` | `tpu.rs:71-82` — FetchStage → SigVerify → BankingStage → Broadcast |
| Voting | `Tower::record_vote()` | `consensus.rs:717` — unchanged |

---

## Pass 1 — Feature Gate + Constants + Wire Types

**Goal:** MCP types compile and serialize. No behavioral change.

### 1.1 Feature gate

`feature-set/src/lib.rs` — model after existing feature declarations.

- Declare `pub mod mcp_protocol_v1 { declare_id!("..."); }`.
- Register in `FEATURE_NAMES` map.

### 1.2 Constants and wire types

Create `ledger/src/mcp.rs`. Spec §4, §3.1, §7.3–§7.5, §8.

Constants:
```
NUM_PROPOSERS = 16        NUM_RELAYS = 200
DATA_SHREDS   = 40        CODING_SHREDS = 160
ATTESTATION_THRESHOLD  = 0.60  → ceil = 120 relays
INCLUSION_THRESHOLD    = 0.40  → ceil =  80 relays
RECONSTRUCTION_THRESHOLD = 0.20 → ceil = 40 relays (= DATA_SHREDS)
```

Types (all with serialize/deserialize/sign/verify):
- `McpPayload` — `tx_count:u32 + [tx_len:u32, tx_bytes]...` (§3.1). Trailing zero padding ignored.
- `TransactionConfigMask` parser — bits 0–5: inclusion_fee, ordering_fee, cu_limit, data_limit, heap, target_proposer (§7.1).
- `RelayAttestation` — version:1 + slot:8 + relay_index:4 + entries_len:1 + entries[proposer_index:4 + commitment:32 + proposer_sig:64] + relay_sig:64 (§7.3).
- `AggregateAttestation` — version:1 + slot:8 + leader_index:4 + relays_len:2 + relay_entries sorted by relay_index (§7.4).
- `ConsensusBlock` — version:1 + slot:8 + leader_index:4 + aggregate_len:4 + aggregate + consensus_meta_len:4 + consensus_meta + delayed_bankhash:32 + leader_sig:64 (§7.5).
- `reconstruct_batch()` — RS decode via `ReedSolomonCache.get(40, 160)`, re-encode, verify commitment matches (§3.6).
- `order_transactions()` — concat by proposer_index ascending, sort by ordering_fee desc, ties broken by position in concatenated list (§3.6).

### 1.3 MCP shred wire format

Create `ledger/src/shred/mcp_shred.rs`. Spec §7.2.

MCP shred format (separate from ShredVariant — do NOT touch `shred.rs:227`):
```
slot:8 + proposer_index:4 + shred_index:4 + commitment:32
+ shred_data:SHRED_DATA_BYTES + witness_len:1 + witness:32*witness_len
+ proposer_sig:64
```

Functions:
- `is_mcp_shred_packet(packet) -> bool` — detect MCP shred by size/header pattern, distinguishing from Agave shreds which start with 64-byte signature then variant byte.
- `McpShred::from_bytes(data) -> Result<McpShred>` — parse and validate field ranges.
- `McpShred::to_bytes(&self) -> Vec<u8>` — serialize.
- `McpShred::verify_signature(&self, proposer_pubkey) -> bool` — verify proposer_sig over commitment.
- `McpShred::verify_witness(&self) -> bool` — recompute leaf hash per §6 (`SHA-256(0x00 || slot || proposer_index || shred_index || shred_data)`), walk witness to root, compare with commitment. Use `MERKLE_HASH_PREFIX_NODE` from `merkle_tree.rs:18` for internal nodes, but use MCP-specific leaf hash (§6) instead of Agave's `MERKLE_HASH_PREFIX_LEAF`.

### 1.4 Tests

- Round-trip serialization of every wire type.
- MCP leaf hash matches spec §6 construction.
- `is_mcp_shred_packet()` correctly distinguishes MCP from Agave shreds.

---

## Pass 2 — Schedules

**Goal:** Given a slot, any node can deterministically derive `Proposers[s]`, `Relays[s]`.

### 2.1 Domain-separated schedule generation

`ledger/src/leader_schedule.rs` — add alongside `stake_weighted_slot_leaders()` at line 72:

```
fn stake_weighted_slot_schedule(keyed_stakes, epoch, len, domain: &[u8]) -> Vec<Pubkey>
```

Same algorithm (sort, WeightedIndex, ChaChaRng) but seed = `SHA-256(domain || epoch.to_le_bytes())`, `repeat = 1`. Domains: `b"mcp:proposer"`, `b"mcp:relay"` (spec §5).

Per spec §5: `Proposers[s]` = sliding window of 16 entries at slot index within epoch with wrap. `Relays[s]` = sliding window of 200 entries with wrap.

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

`turbine/src/sigverify_shreds.rs` — extend `spawn_shred_sigverify()` at line 79.

In the verification loop, before existing Agave shred verification:
1. Call `is_mcp_shred_packet()` to detect MCP shreds.
2. For MCP shreds: parse via `McpShred::from_bytes()`, look up proposer pubkey via `leader_schedule_cache.proposers_at_slot(slot)[proposer_index]`, verify `proposer_signature` and `witness`. Discard on failure.
3. Pass verified MCP shreds through `verified_sender` alongside Agave shreds.

Modify `get_slot_leaders()` at line 446 to handle MCP shreds — for MCP, resolve pubkey from `proposers_at_slot()` instead of `slot_leader_at()`.

### 3.4 Tests

- MCP shred stored and retrieved from blockstore via MCP CFs.
- Sigverify accepts valid MCP shred, rejects bad signature, rejects bad witness.

---

## Pass 4 — Window Service + Relay Attestations

**Goal:** MCP shreds flow through window_service, are stored, tracked, and relays produce attestations.

### 4.1 MCP shred handling in window_service

`core/src/window_service.rs` — modify `run_insert()` at line 190.

After receiving verified shreds from `verified_receiver`:
1. Partition into MCP and Agave shreds using `is_mcp_shred_packet()`.
2. Agave shreds follow existing path (blockstore insert at line 233).
3. MCP shreds:
   - Parse via `McpShred::from_bytes()`.
   - Store via `blockstore.put_mcp_data_shred()`.
   - Track per-(slot, proposer_index) shred counts for reconstruction readiness.
   - Record for relay attestation (see 4.2).

### 4.2 Relay attestation tracking

Add attestation state to `run_insert()` or a small helper struct:

Per-slot `HashMap<u8, (Hash, Signature)>`: `proposer_index → (commitment, proposer_sig)`.
- If a proposer sends conflicting commitments → mark equivocation, do not attest (spec §3.3).
- At most one entry per proposer per slot.

At relay deadline for slot s:
1. Look up `relay_index_at_slot(slot, &my_pubkey)`.
2. If this node is a relay: collect non-equivocating entries sorted by proposer_index.
3. Build + sign `RelayAttestation` (from `ledger/src/mcp.rs`).
4. Send to Leader[s] via MCP attestation socket (see 4.3).
5. At most one attestation per slot.

### 4.3 MCP attestation socket

`gossip/src/contact_info.rs` — add after `SOCKET_TAG_ALPENGLOW = 13` at line 47:
```
SOCKET_TAG_MCP_ATTESTATION: u8 = 14
```
Bump `SOCKET_CACHE_SIZE` at line 49 from 14 to 15.

`core/src/tvu.rs` — add `mcp_attestation: UdpSocket` to `TvuSockets` at line 110. Spawn a "solMcpAttest" receiver thread that deserializes `RelayAttestation` messages and sends them to replay_stage via a new channel.

### 4.4 Tests

- MCP shreds stored via window_service path.
- Relay attests to valid single-commitment proposers.
- Relay does not attest to equivocating proposer.
- One attestation per slot enforced.

---

## Pass 5 — Proposer Pipeline

**Goal:** A proposer node collects sig-verified txs, encodes MCP shreds, sends one per relay. Bankless.

### 5.1 Clone sender in sigverify

`core/src/tpu.rs` — add an optional `Sender<Vec<PacketBatch>>` for MCP proposer packets.

When `mcp_protocol_v1` active and `leader_schedule_cache.proposers_at_slot(slot)` includes this node's pubkey, clone the sig-verified packet batch into the MCP sender. This taps into the existing TPU pipeline after SigVerify (line 288-293) but before BankingStage.

### 5.2 Proposer loop

`core/src/tpu.rs` — add an MCP proposer thread:

1. Receive cloned packets from 5.1.
2. Parse `TransactionConfigMask` per tx (from `ledger/src/mcp.rs`).
3. Sort by ordering_fee descending, ties by position.
4. Serialize to `McpPayload` (max `200 * SHRED_DATA_BYTES` bytes).
5. RS encode via `ReedSolomonCache.get(40, 160)` (same cache at `shredder.rs:276`).
6. Compute Merkle commitment per spec §6.
7. Build `McpShred` for each relay index (0..199) with witness + proposer_signature.
8. Look up relay addresses via `relays_at_slot()` + `ClusterInfo::lookup_contact_info()`.
9. Send one shred per relay to their TVU address.

No bank, no PoH — this is bankless per spec §9.

### 5.3 Per-proposer CU budgets

`core/src/banking_stage/qos_service.rs` — when `mcp_protocol_v1` active, divide block-level limits by `NUM_PROPOSERS` (16):
- `block_cost_limit /= 16`
- `account_cost_limit /= 16`

### 5.4 Tests

- Proposer produces 200 shreds (one per relay).
- Payload size within `NUM_RELAYS * SHRED_DATA_BYTES`.
- RS encode → decode round-trip.
- CU budget enforcement at 1/16th.

---

## Pass 6 — Leader Aggregation + ConsensusBlock

**Goal:** The leader collects relay attestations, builds the aggregate, broadcasts ConsensusBlock.

### 6.1 Receive attestations

MCP attestation packets arrive via the "solMcpAttest" thread from Pass 4.3. Add `mcp_attestation_receiver` to `ReplayReceivers` at `replay_stage.rs:330`.

### 6.2 Verify and aggregate

`core/src/replay_stage.rs` — in the main loop at line 823, drain attestations each iteration:

1. Verify relay_signature; discard message if invalid (spec §3.4).
2. Verify each proposer_signature against commitment; drop invalid entries.
3. Accumulate into per-slot `AggregateAttestation`.

### 6.3 Build ConsensusBlock

When this node is Leader[s] and aggregation deadline is reached:

1. If relay count < 120 (ATTESTATION_THRESHOLD) → submit empty result (spec §3.4).
2. Build AggregateAttestation with relay entries sorted by relay_index.
3. Construct ConsensusBlock with aggregate + consensus_meta + delayed_bankhash.
4. Sign and broadcast to all validators.

### 6.4 ConsensusBlock gossip

`gossip/src/crds_data.rs` — add `McpConsensusBlockSummary` variant to `CrdsData` enum after line 64 for distribution via gossip.

### 6.5 Tests

- Threshold enforcement: <120 relays → empty.
- Invalid relay sig → entire message dropped.
- Invalid proposer sig → entry dropped, rest kept.
- ConsensusBlock signature verifies.

---

## Pass 7 — Vote Gate + Reconstruct + Replay

**Goal:** Validators verify ConsensusBlock, reconstruct batches, execute with two-phase fees, and vote.

### 7.1 ConsensusBlock validation (vote gate)

`core/src/replay_stage.rs` — on receiving ConsensusBlock for slot s (spec §3.5):

1. Verify leader_signature, leader_index matches Leader[s].
2. Verify delayed_bankhash against local bank hash.
3. Verify every relay_signature and proposer_signature in aggregate.
4. Compute implied proposers:
   - 2+ distinct commitments → equivocating → exclude.
   - 1 commitment with ≥80 relay attestations (INCLUSION_THRESHOLD) → include.
5. For each included proposer: count locally stored shreds with valid witness ≥40 (RECONSTRUCTION_THRESHOLD).
6. Any included proposer below 40 → do not vote.

### 7.2 Reconstruct

For each included proposer:

1. Gather ≥40 MCP shreds from blockstore via `get_mcp_data_shreds_for_proposer()`.
2. `reconstruct_batch()` from `ledger/src/mcp.rs` — RS decode via `ReedSolomonCache.get(40, 160)`, re-encode, recompute commitment. Discard if mismatch (spec §3.6).
3. Parse `McpPayload` → transactions.

### 7.3 Order and execute

1. `order_transactions()` from `ledger/src/mcp.rs` — concat by proposer_index ascending, sort by ordering_fee desc, ties by position.
2. Two-phase execution via new `confirm_slot_mcp()` in `ledger/src/blockstore_processor.rs`:

**Phase A (fees):** For each transaction in order, validate fee payer can cover `fee * NUM_PROPOSERS` (spec §8). Deduct fees for all valid txs, even if execution will fail. Track per-slot cumulative per-payer fees to prevent over-commitment. Modify `validate_fee_payer()` at `account_loader.rs:370` to accept an MCP flag for the multiplied fee requirement.

**Phase B (execution):** Execute ordered txs via existing `process_entries()` at `blockstore_processor.rs:649` with a flag to skip fee re-charging (fees already deducted in Phase A).

3. Freeze bank. Set `bank.block_id()` from ConsensusBlock.

### 7.4 Vote

```
tower.record_vote(slot, block_id)   // existing path at consensus.rs:717 — unchanged
```

### 7.5 Empty slot

Consensus outputs empty result → freeze bank with no transactions.

### 7.6 Tests

- Vote gate rejects: bad leader sig, bad bankhash, equivocating proposer, insufficient shreds.
- Reconstruction round-trip: shred → reconstruct → verify commitment.
- Ordering: ordering_fee sort is deterministic.
- Fee multiplier: payer needs 16x balance.
- End-to-end in `core/tests/mcp_integration.rs`.

---

## New Files

| File | Contents |
|---|---|
| `ledger/src/mcp.rs` | Constants, wire types (McpPayload, RelayAttestation, AggregateAttestation, ConsensusBlock, TransactionConfigMask), reconstruct_batch(), order_transactions() |
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
| `turbine/src/sigverify_shreds.rs` | Detect MCP shreds, verify against proposer pubkey |
| `core/src/window_service.rs` | MCP shred partition, storage, tracking, relay attestation |
| `gossip/src/contact_info.rs` | `SOCKET_TAG_MCP_ATTESTATION = 14`, bump cache size |
| `gossip/src/crds_data.rs` | `McpConsensusBlockSummary` variant |
| `core/src/tvu.rs` | `mcp_attestation` socket + "solMcpAttest" thread + channel to replay |
| `core/src/tpu.rs` | MCP proposer clone sender + proposer loop thread |
| `core/src/banking_stage/qos_service.rs` | CU limits / NUM_PROPOSERS |
| `core/src/replay_stage.rs` | Attestation aggregation, ConsensusBlock building, vote gate, reconstruction dispatch |
| `ledger/src/blockstore_processor.rs` | `confirm_slot_mcp()` with two-phase fee execution |
| `svm/src/account_loader.rs` | MCP fee multiplier in `validate_fee_payer()` |

## Dependency Graph

```
Pass 1 (types)  ──┐
Pass 2 (schedules)┤── can parallelize
Pass 3 (storage)──┘
       │
Pass 4 (window+relay) ─→ Pass 5 (proposer) ─→ Pass 6 (leader) ─→ Pass 7 (vote+replay)
```
