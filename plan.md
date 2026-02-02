# MCP Implementation Plan (Delta Only)

Spec: `docs/src/proposals/mcp-protocol-spec.md`

This plan covers only the remaining wiring and integration work. It does NOT reimplement any existing MCP module.

## Existing MCP Modules (reference, do not modify unless noted)

| Module | Status | Location |
|---|---|---|
| Constants + wire types | Complete | `ledger/src/mcp.rs` |
| MCP shred format (McpShredV1) | Complete | `ledger/src/shred/mcp_shred.rs` |
| Merkle tree (spec §6) | Complete | `ledger/src/mcp_merkle.rs` |
| Reed-Solomon RS(40,160) | Complete | `ledger/src/mcp_reed_solomon.rs` |
| Relay attestation wire format | Complete | `ledger/src/mcp_attestation.rs` |
| Storage schema (spec §14) | Spec only | `ledger/src/mcp_storage.rs` |
| MCP column families | Wired | `ledger/src/blockstore.rs:264-266` — `mcp_data_shred_cf`, `mcp_code_shred_cf` |
| MCP blockstore CRUD | Wired | `ledger/src/blockstore.rs` — `put_mcp_data_shred`, `get_mcp_data_shreds_for_proposer` |
| Schedules (proposer/relay) | Wired | `ledger/src/leader_schedule.rs`, `leader_schedule_utils.rs`, `leader_schedule_cache.rs` |
| MCP shred detection | Wired | `core/src/window_service.rs:287` — `is_mcp_shred_packet()` partitions MCP from regular shreds |
| MCP shred storage in window | Wired | `core/src/window_service.rs:321` — calls `blockstore.put_mcp_data_shred()` |
| McpSlotTracker | Wired | `core/src/window_service.rs:65-107` — tracks per-(slot, proposer) shred counts |
| Relay attestation service | Wired | `core/src/window_service.rs:332-378` — `record_shred()`, `check_attestation_ready()`, `submit_attestation()` |
| MCP reconstruction | Wired | `core/src/window_service.rs:432-524` — `try_mcp_reconstruction()` calls `reconstruct_proposer_payload()` |
| Attestation aggregation | Wired | `core/src/replay_stage.rs:842` — `AttestationAggregator::new(32)` |
| Attestation receiver drain | Wired | `core/src/replay_stage.rs:945-959` — drains `mcp_attestation_receiver` each iteration |
| ConsensusBlock building | Wired | `core/src/replay_stage.rs:2910-2919` — `try_build_mcp_block()` |
| MCP attestation socket | Wired | `gossip/src/contact_info.rs:48` — `SOCKET_TAG_MCP_ATTESTATION = 14` |
| MCP attestation thread | Wired | `core/src/tvu.rs:257` — "solMcpAttest" thread, channels at line 249, 349 |
| MCP block broadcast channel | Wired | `core/src/tvu.rs:349` — `mcp_block_sender`/`mcp_block_receiver` |
| MCP shred sigverify | Wired | `turbine/src/sigverify_shreds.rs:900-930` — `is_mcp_shred()`, `verify_mcp_shred_packet()` |
| ConsensusBlock gossip | Wired | `gossip/src/crds_data.rs:67` — `McpConsensusBlockSummary` variant |
| Proposer logic | **Unwired** | `core/src/mcp_proposer.rs` — `McpProposer::process_transactions()` |
| Relay shred verifier | **Unwired** | `core/src/mcp_relay_ops.rs` — `ShredVerifier`, `RelayOperations` |
| Two-phase fee processor | **Partially wired** | `core/src/mcp_fee_mechanics.rs` — `TwoPhaseProcessor` initialized in replay_stage but TODO at line 2833 |
| MCP replay reconstruction | **Broken tests** | `core/src/mcp_replay_reconstruction.rs:725` — test uses non-existent McpPayload fields |
| MCP fee validation (SVM) | **Unwired** | `svm/src/account_loader.rs:47-347` — `validate_mcp_fee_payer()`, `execute_fee_phase()` |

---

## Pass 1 — Feature Gate

**Goal:** All MCP code paths gated on a feature flag. No behavioral change.

### 1.1 Declare feature

`feature-set/src/lib.rs` — model after `alpenglow` at line 1101.

- Declare `pub mod mcp_protocol_v1 { declare_id!("..."); }` after line 1106.
- Register in `FEATURE_NAMES` map near line 2025.

### 1.2 Gate existing MCP code paths

Add `if !feature_set.is_active(&feature_set::mcp_protocol_v1::id())` early-returns to:
- `core/src/window_service.rs:287` — the MCP shred partition branch
- `core/src/replay_stage.rs:945` — the attestation drain loop
- `core/src/replay_stage.rs:2910` — `try_build_mcp_block()`
- `core/src/tvu.rs:257` — skip spawning "solMcpAttest" thread when inactive

### 1.3 Tests

- Feature inactive → MCP shreds dropped at window_service
- Feature active → MCP shreds processed normally

---

## Pass 2 — Wire Proposer into TPU

**Goal:** When this node is an MCP proposer for the current slot, sig-verified transactions are cloned to `McpProposer`, which emits MCP shreds to relays.

### 2.1 Clone sender in sigverify

`turbine/src/sigverify_shreds.rs` or `core/src/tpu.rs` — add an optional `Sender<Vec<PacketBatch>>` for MCP proposer packets.

When `mcp_protocol_v1` active and `leader_schedule_cache.get_proposers_at_slot(slot)` includes this node's pubkey:
- Clone the sig-verified packet batch into the MCP sender.

This keeps the proposer bankless — no PoH, no bank execution.

### 2.2 Proposer loop in TPU

`core/src/tpu.rs` — add an MCP proposer thread (or extend existing thread):

1. Receive cloned packets from the sender in 2.1.
2. Parse `TransactionConfigMask` per tx (use `ledger/src/mcp.rs`).
3. Build `Vec<OrderedTransaction>` for `McpProposer`.
4. Call `McpProposer::process_transactions()` → produces `Vec<McpShred>`.
5. Look up relay addresses via `leader_schedule_cache.get_relays_at_slot(slot)` + `ClusterInfo::lookup_contact_info()`.
6. Send one shred per relay to their TVU address.

### 2.3 Per-proposer CU budgets

`core/src/banking_stage/qos_service.rs` — when `mcp_protocol_v1` active, divide block-level limits by `NUM_PROPOSERS` (16):
- `block_cost_limit /= 16`
- `account_cost_limit /= 16`

### 2.4 Tests

- Proposer produces 200 shreds (one per relay)
- McpShred round-trips through `McpShredV1::from_bytes()` / `to_bytes()`
- CU budget enforced at 1/16th

---

## Pass 3 — Wire Relay Ops into Window Service

**Goal:** MCP shreds pass through `ShredVerifier` (spec §9.1 six-step verification) before storage and attestation.

### 3.1 Integrate ShredVerifier

`core/src/window_service.rs` — in the MCP branch of `run_insert()` (after line 287 partition):

Currently, MCP shreds go directly to `blockstore.put_mcp_data_shred()`. Insert `mcp_relay_ops::ShredVerifier::verify()` before storage:

1. Import `mcp_relay_ops::{ShredVerifier, RelayOperations}`.
2. Create a per-slot `RelayOperations` instance (or reuse across iterations via a slot-keyed map).
3. For each MCP shred: call `relay_ops.process_shred(shred, &proposer_pubkey)`.
4. Only store and attest shreds that pass verification.
5. Equivocation detection is built into `RelayOperations` — equivocating proposers are automatically excluded from attestation via `get_attestable_proposers()`.

### 3.2 Tests

- Valid shreds pass ShredVerifier and are stored
- Invalid merkle witness → shred rejected, not stored
- Equivocating proposer (two different commitments) → excluded from attestation

---

## Pass 4 — Close the Execution TODO

**Goal:** MCP reconstructed transactions are executed via two-phase fee processing in the existing confirm_slot pipeline.

This is the critical gap. The TODO is at `core/src/replay_stage.rs:2833-2837`:
```
// TODO: Integrate mcp_processor with blockstore_processor::confirm_slot
// to execute transactions using two-phase fee mechanics:
// - Phase A: Deduct fees using mcp_processor.process_phase_a()
// - Phase B: Execute transactions that passed Phase A
```

### 4.1 Add MCP execution path in blockstore_processor

`ledger/src/blockstore_processor.rs` — currently has zero MCP code. Add:

```
fn confirm_slot_mcp(
    slot: Slot,
    bank: &Arc<Bank>,
    ordered_transactions: Vec<OrderedTransaction>,
    mcp_fee_processor: &mut TwoPhaseProcessor,
) -> Result<()>
```

This function:
1. **Phase A (fees):** For each transaction in order, call `mcp_fee_processor.execute_fee_phase_on_account()` to deduct fees. Transactions that fail fee deduction are dropped.
2. **Phase B (execution):** Convert surviving transactions to `Entry` structs. Feed into existing `process_entries_with_callback()` with a flag to skip fee re-charging (fees already deducted in Phase A).
3. Freeze bank with the resulting state.

The "skip fee re-charge" flag needs to thread through `process_entries()` → `process_transactions()` in `blockstore_processor.rs` to the SVM execution layer. Use the existing `validate_mcp_fee_payer()` in `svm/src/account_loader.rs` which already has `MCP_NUM_PROPOSERS` and fee tracking logic.

### 4.2 Call from replay_stage

`core/src/replay_stage.rs` — replace the TODO block at lines 2833-2837:

1. When MCP reconstruction succeeds (line 2824), call `confirm_slot_mcp()` instead of the standard `confirm_slot()`.
2. Pass the `TwoPhaseProcessor` that is already initialized at line 2828.
3. On success, set `bank.block_id()` from the ConsensusBlock and proceed to vote via existing `Tower::record_bank_vote()` (unchanged).

### 4.3 Wire SVM fee validation

`svm/src/account_loader.rs` — the existing `validate_mcp_fee_payer()` and `execute_fee_phase()` (lines 47-347) need to be called from the Phase A path in 4.1. These functions already implement:
- `required_fee = fee * NUM_PROPOSERS` (spec §8)
- Per-slot cumulative fee tracking via `SlotFeePayerTracker`

The integration point is `confirm_slot_mcp()` calling `execute_fee_phase()` during Phase A.

### 4.4 Tests

- Phase A deducts fees correctly (fee * 16 per proposer)
- Phase B executes without re-charging fees
- Transaction that fails fee check is dropped but others proceed
- End-to-end: MCP shreds → reconstruct → two-phase execute → bank frozen → vote

---

## Pass 5 — Fix Broken Tests

**Goal:** All existing MCP tests compile and pass.

### 5.1 Fix mcp_replay_reconstruction test

`core/src/mcp_replay_reconstruction.rs:725` — `test_ordered_transaction_dedup` constructs `McpPayload` with fields that don't exist (`payload_version`, `slot`, `proposer_index`, `payload_len`). The actual struct (lines 54-59) only has `tx_count` and `tx_data`.

Fix the test to match the actual struct definition.

### 5.2 Run full test suite

Run all MCP-related tests:
- `cargo test -p solana-ledger mcp`
- `cargo test -p solana-core mcp`
- `cargo test -p solana-svm mcp`

---

## Files Modified (Delta Only)

| File | Change |
|---|---|
| `feature-set/src/lib.rs` | Add `mcp_protocol_v1` feature ID + FEATURE_NAMES entry |
| `core/src/window_service.rs` | Gate MCP branch on feature flag; integrate `ShredVerifier` before storage |
| `core/src/replay_stage.rs` | Gate attestation drain + block build on feature flag; replace TODO with `confirm_slot_mcp()` call |
| `core/src/tvu.rs` | Gate "solMcpAttest" thread on feature flag; add MCP proposer thread |
| `core/src/tpu.rs` | Add MCP proposer packet sender; spawn proposer loop calling `McpProposer` |
| `turbine/src/sigverify_shreds.rs` | Add optional MCP clone sender for proposer packets |
| `ledger/src/blockstore_processor.rs` | Add `confirm_slot_mcp()` with two-phase fee execution |
| `svm/src/account_loader.rs` | Wire existing `execute_fee_phase()` into confirm_slot_mcp path |
| `core/src/banking_stage/qos_service.rs` | Divide CU limits by NUM_PROPOSERS when MCP active |
| `core/src/mcp_replay_reconstruction.rs` | Fix broken test at line 725 |

## Files NOT Modified (already complete)

- `ledger/src/mcp.rs` — constants, wire types, config
- `ledger/src/shred/mcp_shred.rs` — MCP shred format
- `ledger/src/mcp_merkle.rs` — Merkle tree
- `ledger/src/mcp_reed_solomon.rs` — RS(40,160)
- `ledger/src/mcp_attestation.rs` — attestation wire format
- `ledger/src/blockstore.rs` — MCP column families + CRUD
- `ledger/src/leader_schedule.rs` — MCP schedule generation
- `ledger/src/leader_schedule_utils.rs` — MCP schedule helpers
- `ledger/src/leader_schedule_cache.rs` — MCP schedule cache
- `core/src/mcp_proposer.rs` — proposer logic (used, not modified)
- `core/src/mcp_relay_attestation.rs` — relay attestation service (used, not modified)
- `core/src/mcp_consensus_block.rs` — consensus block building (used, not modified)
- `core/src/mcp_fee_mechanics.rs` — TwoPhaseProcessor (used, not modified)
- `core/src/mcp_relay_ops.rs` — ShredVerifier (used, not modified)
- `gossip/src/contact_info.rs` — MCP attestation socket tag
- `gossip/src/crds_data.rs` — McpConsensusBlockSummary

## Dependency Graph

```
Pass 1 (feature gate) ─→ Pass 2 (proposer wiring)
                      ─→ Pass 3 (relay ops wiring)
                      ─→ Pass 4 (execution TODO)
                      ─→ Pass 5 (fix tests)
```

Passes 2-5 depend on Pass 1 but are independent of each other and can be parallelized across ICs.
