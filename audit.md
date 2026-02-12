# MCP Adversarial Audit — Reachability Focus (Master)

Date: 2026-02-12
Branch: `master` (commit `c95a559d1e`)
Perspective: Principal engineer + security researcher, assuming adversarial/lazy developer.
Scope: **Production call-path reachability** of every MCP subsystem vs plan.md, NOT just code existence.

---

## Executive Summary

This audit **corrects the prior Correction Addendum**. All 5 claimed "wiring gaps" are **CLOSED** in the current codebase. The addendum's line-number references and descriptions matched an earlier code snapshot that has since been updated. The prior audit methodology over-weighted plan.md's self-reported gap notes (which are now stale) and under-weighted tracing actual call graphs.

**All major MCP production paths are LIVE and reachable.** The one genuine structural gap is that MCP shred repair has no automatic trigger — only an admin-RPC entry point.

### Verdicts

| Area | Status |
|------|--------|
| Implementation vs plan.md | **PASS** (all plan items implemented; plan.md gap notes at lines 30-37, 83 are STALE) |
| Addendum claim 1 (McpFeePayerTracker dead) | **REFUTED** — live via 3 scheduler paths |
| Addendum claim 2 (validate_fee_payer_for_mcp dead) | **REFUTED** — called from claim 1's path |
| Addendum claim 3 (per-proposer dedup missing) | **REFUTED** — per-proposer state maintained |
| Addendum claim 4 (ordering-fee fallback wrong) | **REFUTED** — `ordering_fee_with_fallback()` in all paths |
| Addendum claim 5 (replay drops fee components) | **REFUTED** — `set_mcp_fee_components` at line 1831 |
| Local-cluster e2e test | **PASS** (80.49s, all artifacts verified) |
| MCP repair automatic trigger | **GAP** — admin-RPC only, no automatic repair loop |
| Security attack surface | **ACCEPTABLE** (no critical/high vulnerabilities) |
| Code quality (zero stubs/TODOs) | **PASS** |
| Test coverage (193 tests) | **GOOD** |

---

## 1. Addendum Corrections — All 5 Claims Refuted

### Claim 1: "McpFeePayerTracker path is dead"

**REFUTED.** The routing function `check_fee_payer_unlocked_admission` at `core/src/banking_stage/consumer.rs:598-613` is called from **3 production scheduler paths**:

| Caller | File:Line |
|--------|-----------|
| `receive_and_buffer` (legacy path) | `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:330` |
| `receive_and_buffer` (view path) | `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:561` |
| `scheduler_controller` | `core/src/banking_stage/transaction_scheduler/scheduler_controller.rs:210` |

The router checks two conditions (`consumer.rs:604-608`):
```
let mcp_feature_active = bank.feature_set
    .activated_slot(&mcp_protocol_v1::id())
    .is_some_and(|activated_slot| bank.slot() >= activated_slot);
if mcp_feature_active && transaction.mcp_fee_components().is_some() {
    Self::check_fee_payer_unlocked_mcp(...)  // MCP path
} else {
    Self::check_fee_payer_unlocked(...)       // legacy path
}
```

The `TransactionView` path at `runtime-transaction/src/runtime_transaction/transaction_view.rs:68-88` correctly extracts `mcp_fee_components` from MCP wire bytes, so the MCP branch IS taken for MCP-format transactions when the feature is active.

`check_fee_payer_unlocked_mcp` (`consumer.rs:541-596`) performs:
- `calculate_fee` → `checked_mul(MCP_NUM_PROPOSERS)` → 16x scaled fee reservation
- `fee_tracker.try_reserve()` → cumulative per-payer tracking
- `validate_fee_payer_for_mcp()` → per-proposer fee validation

**All reachable in production.**

### Claim 2: "validate_fee_payer_for_mcp is effectively dead"

**REFUTED.** Called at `consumer.rs:588` from `check_fee_payer_unlocked_mcp`, which is reachable per Claim 1 above. Also called from `svm/src/account_loader.rs:390` during transaction loading.

### Claim 3: "Per-proposer admission/dedup semantics not implemented"

**REFUTED.** The dispatch state structure at `turbine/src/broadcast_stage/standard_broadcast_run.rs:91-102`:

```rust
struct McpSlotDispatchState {
    proposer_states: HashMap<u32, McpProposerDispatchState>,  // PER-PROPOSER
    ...
}

struct McpProposerDispatchState {
    payload_transactions: Vec<McpPayloadTransaction>,
    payer_fee_reservations: HashMap<Pubkey, u64>,   // PER-PROPOSER fee tracking
    seen_signatures: HashSet<[u8; 64]>,             // PER-PROPOSER dedup
    ...
}
```

Transaction routing at `standard_broadcast_run.rs:854-870`:
- Transactions WITH `target_proposer`: pushed to ONLY that proposer's state (line 857)
- Transactions WITHOUT `target_proposer`: cloned to ALL owned proposer indices (line 864-870), each independently deduped and fee-checked

Each proposer's `try_push_transaction` (`standard_broadcast_run.rs:146-188`) independently:
1. Checks per-proposer `seen_signatures` (dedup, line 147)
2. Computes `base_fee * NUM_PROPOSERS` reservation (line 153)
3. Tracks per-proposer `payer_fee_reservations` (line 162-165)
4. Enforces per-proposer payload size limit (line 177)

At dispatch time (`standard_broadcast_run.rs:941-954`), each proposer's payload is independently ordered via `order_mcp_payload_transactions` which applies the B2 policy.

**Per-proposer dedup, fee reservation, payload accumulation, and ordering are all implemented.**

### Claim 4: "B1 ordering-fee fallback not honored"

**REFUTED.** The method `ordering_fee_with_fallback()` at `transaction-view/src/mcp_transaction.rs:243-251`:

```rust
pub fn ordering_fee_with_fallback(&self) -> u64 {
    self.ordering_fee().map_or_else(
        || {
            self.compute_budget_instruction_details()
                .map_or(0, |details| details.requested_compute_unit_price())
        },
        u64::from,
    )
}
```

When ordering_fee field is absent, falls back to `compute_unit_price`. Only defaults to 0 when BOTH ordering_fee and compute budget instructions are absent (correct — no fee info means 0 priority).

This method is used in **all 4 ordering paths**:

| Path | File:Line |
|------|-----------|
| TPU ingest (TransactionView) | `runtime-transaction/src/runtime_transaction/transaction_view.rs:76` |
| Broadcast dispatch | `turbine/src/broadcast_stage/standard_broadcast_run.rs:227` |
| Replay ordering metadata | `core/src/mcp_replay.rs:336` |
| Replay wire conversion | `ledger/src/blockstore_processor.rs:1781` |

The addendum's claim that these paths use `unwrap_or_default()` is **outdated** — all now use `ordering_fee_with_fallback()`.

### Claim 5: "Replay conversion drops MCP fee-component semantics"

**REFUTED.** The replay conversion at `ledger/src/blockstore_processor.rs:1762-1787` extracts fee components:

```rust
fn versioned_transaction_from_mcp_wire_bytes(...) -> ... {
    ...
    let mcp_fee_components = Some((
        u64::from(mcp_transaction.inclusion_fee().unwrap_or_default()),
        mcp_transaction.ordering_fee_with_fallback(),
    ));
    Ok((mcp_transaction_to_versioned_transaction(mcp_transaction), mcp_fee_components))
}
```

At line 1823-1831, the extracted fee components are restored AFTER `bank.verify_transaction()`:

```rust
let (versioned_tx, mcp_fee_components) =
    versioned_transaction_from_mcp_wire_bytes(slot, tx_index, tx_wire_bytes)?;
let mut transaction = bank.verify_transaction(versioned_tx, verification_mode)...;
transaction.set_mcp_fee_components(mcp_fee_components);  // RESTORES fee metadata
```

Yes, `sdk_transactions.rs:69` sets `mcp_fee_components: None` during `verify_transaction`. But `set_mcp_fee_components` at line 1831 **overwrites** that None with the actual values extracted from MCP wire bytes.

These components then flow through to `runtime/src/bank/check_transactions.rs:113-124`:

```rust
let fee_details = if self.feature_set.is_active(&mcp_protocol_v1::id()) {
    tx.borrow().mcp_fee_components().map_or(
        fee_details,
        |(inclusion_fee, ordering_fee)| {
            apply_mcp_fee_component_values(fee_details, inclusion_fee, ordering_fee)
        },
    )
} ...
```

**MCP fee components ARE preserved and applied during replay.**

### plan.md Staleness

The following plan.md notes describe gaps that are **now closed in code** and should be updated:

| plan.md Line | Claim | Current Code Status |
|-------------|-------|-------------------|
| 31 | "MCP-specific BankingStage admission helper wiring is still incomplete" | CLOSED — `check_fee_payer_unlocked_admission` routes to MCP path from 3 scheduler callers |
| 32 | "payload construction is currently slot-shared across owned proposer indices" | CLOSED — per-proposer state via `HashMap<u32, McpProposerDispatchState>` |
| 37 | "MCP-wire fee component semantics are not fully preserved" | CLOSED — `set_mcp_fee_components` restores them post-verify |
| 83 | "ordering-fee fallback to compute_unit_price is not yet fully wired" | CLOSED — `ordering_fee_with_fallback()` in all 4 paths |

---

## 2. Full Production Reachability Trace

### MCP Shred Ingestion — LIVE

| Stage | Entry Point | Verified At |
|-------|-------------|-------------|
| UDP/QUIC receive | `core/src/shred_fetch_stage.rs` → `handle_packets` | Feature-gated MCP dispatch |
| Sigverify | `turbine/src/sigverify_shreds.rs` → MCP signature verification | Parallel path for MCP format |
| Window insert | `core/src/window_service.rs` → `insert_shred` | MCP shred storage in blockstore |
| Blockstore storage | `ledger/src/blockstore.rs` → `put_mcp_shred_data` | Column family: `MCP_SHRED_DATA_CF` |

### Relay Attestation — LIVE

| Stage | Entry Point | Verified At |
|-------|-------------|-------------|
| Shred processing | `core/src/mcp_relay.rs` → `process_shred` | Merkle+signature verification before storage |
| Reconstruction check | `core/src/mcp_relay.rs` → threshold check (2/3 shreds) | Triggers attestation when threshold met |
| Attestation signing | `core/src/mcp_relay_submit.rs` → `submit_relay_attestation` | Signs and dispatches via QUIC/UDP |
| Attestation receive | `core/src/window_service.rs` → attestation ingestion path | Feature-gated MCP dispatch |
| Aggregate filtering | `ledger/src/mcp_aggregate_attestation.rs` → canonical attestation merge | 25,600 cache bound, sig-verified |

### Consensus Block — LIVE

| Stage | Entry Point | Verified At |
|-------|-------------|-------------|
| Block construction | `ledger/src/mcp_consensus_block.rs` → `build_consensus_block` | Leader path in broadcast stage |
| Block signing | `ledger/src/mcp_consensus_block.rs` → `sign_consensus_block` | Leader keypair signing |
| Block verification | `ledger/src/mcp_consensus_block.rs` → `verify_leader_signature` | Called BEFORE storage |
| Block storage | `core/src/window_service.rs` → consensus block ingestion | Blockstore column family storage |

### Vote Gate — LIVE

| Stage | Entry Point | Verified At |
|-------|-------------|-------------|
| Input refresh | `core/src/mcp_replay.rs:231` → `refresh_vote_gate_input` | Called from 3 replay_stage paths |
| 7-check evaluation | `core/src/mcp_vote_gate.rs` → `evaluate` | All checks are hard rejections |
| Replay integration | `core/src/replay_stage.rs` → B3 deferral guard (lines 4030-4039) | 3-condition guard verified |

### Reconstruction + Replay — LIVE

| Stage | Entry Point | Verified At |
|-------|-------------|-------------|
| Reconstruction trigger | `core/src/mcp_replay.rs` → `maybe_persist_reconstructed_execution_output` | Called from 3 replay_stage paths |
| Reed-Solomon decode | `ledger/src/mcp_erasure.rs` → 40+160=200 erasure coding | Threshold reconstruction |
| Payload decode | `transaction-view/src/mcp_payload.rs` → framed transaction extraction | Length-prefixed wire format |
| Wire → VersionedTx | `ledger/src/blockstore_processor.rs:1762-1787` | MCP+bincode dual-format support |
| Fee component preservation | `ledger/src/blockstore_processor.rs:1831` | `set_mcp_fee_components` call |
| Two-pass fee execution | `ledger/src/blockstore_processor.rs:234-267` | Phase A (fee withdrawal) + Phase B (skip-fee execution) |

### TPU Admission — LIVE

| Stage | Entry Point | Verified At |
|-------|-------------|-------------|
| MCP fee extraction | `runtime-transaction/src/runtime_transaction/transaction_view.rs:68-88` | Extracts inclusion_fee + ordering_fee from MCP wire |
| Admission routing | `core/src/banking_stage/consumer.rs:598-613` | Routes to MCP or legacy based on feature + fee components |
| 16x fee reservation | `core/src/banking_stage/consumer.rs:577-586` | `base_fee.checked_mul(NUM_PROPOSERS)` + `try_reserve` |
| Per-proposer dispatch | `turbine/src/broadcast_stage/standard_broadcast_run.rs:132-188` | Independent dedup/fee/payload per proposer |

### Repair — PARTIALLY WIRED

| Stage | Entry Point | Status |
|-------|-------------|--------|
| Serve side | `core/src/repair/serve_repair.rs` → `run_mcp_window_request` | **LIVE** — responds to MCP window repair requests |
| Request side (admin) | `validator/src/admin_rpc_service.rs:624` → `request_repair_for_mcp_shred_from_peer` | **LIVE** — admin-RPC triggered only |
| Automatic trigger | Main repair loop in `core/src/repair/repair_service.rs` | **MISSING** — no MCP shred awareness in automatic repair |

**This is the ONLY genuine structural gap.** The automatic repair loop does not detect or request missing MCP shreds. Repair can only be triggered via admin RPC. In a production network, MCP shred loss that exceeds the Reed-Solomon erasure threshold (>160 of 200 shreds lost) cannot be automatically recovered.

---

## 3. Integration Test — PASS

```
cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture
```

**Result: PASS** (80.49s, exit code 0)

Verified:
- Root advances past MCP activation (no stall)
- Zero `ReadSizeLimit(2)` errors
- MCP shred + relay attestation + execution artifacts at slot 64
- Non-leader execution output at slot 66
- Consensus block at slot 73 with matching delayed bankhash for slot 72
- 12 transactions decoded, submitted transfer signature found
- Cross-node equality (5 validators, all root at slot 63+)

---

## 4. Prior Fixes — Still Intact

### B3 Deferral (replay_stage.rs:4030-4039)

Three-condition guard verified:
1. MCP feature active for slot
2. `has_mcp_consensus_block_for_slot` (restored precondition)
3. `mcp_authoritative_block_id_for_slot` returns `None`

4 unit tests cover all branches. No regressions.

### BlockComponent Decode (block_component.rs:567-574)

Buffer-length disambiguation verified:
- Exactly 8 bytes with `entry_count == 0` → `EntryBatch(vec![])`
- More bytes with `entry_count == 0` → `BlockMarker`

Round-trip test exists. No regressions.

### infer_is_entry_batch Fix (block_component.rs:509-512)

`entry_count != 0 || data.len() == Self::ENTRY_COUNT_SIZE` — correctly classifies 8-zero-byte payloads as empty entry batch. Matches SchemaRead logic.

---

## 5. Dead Code Inventory

| Item | Location | Status |
|------|----------|--------|
| `order_batches_by_fee_desc` | `ledger/src/mcp_ordering.rs:23` | Test-only (0 production callers, only called from `#[cfg(test)]` blocks) |
| `McpRelayProcessor::stored_count()` | `core/src/mcp_relay.rs:45` | Test-only (only called from `#[cfg(test)]` blocks) |
| `RELAY_ATTESTATION_VERSION_V1` | `core/src/mcp_relay_submit.rs:27` | Re-export constant — used at lines 166, 424 in same file |

All major MCP functions have verified production callers. No dead production code found.

---

## 6. Security — No Critical/High Vulnerabilities

| Area | Status | Notes |
|------|--------|-------|
| MCP shred ingestion | DEFENDED | Sigverify before blockstore insertion |
| Relay attestation | DEFENDED | Merkle root + proposer signature verification before storage |
| Consensus block | DEFENDED | `verify_leader_signature` before storage |
| Vote gate | DEFENDED | 7 hard-rejection checks, all exercised in tests |
| Two-pass fee system | DEFENDED | 16x multiplier with `checked_mul`; rent minimum enforced |
| Fee reservation | DEFENDED | Per-proposer cumulative tracking prevents double-spend across proposers |
| Relay channel flooding | PARTIALLY DEFENDED | Cache bounded (25,600), sig verified, relies on transport-layer SWQoS |
| Repair protocol | PARTIALLY DEFENDED | Nonce-less (mitigated by downstream Merkle+signature verification) |

Prior security findings (MEDIUM, unchanged):
- Nonce-less MCP repair allows structurally valid injection (mitigated by downstream crypto)
- Relay channel flooding lacks per-identity rate limiting (relies on transport-layer SWQoS)

---

## 7. Code Quality — All 18 Files PASS

| # | File | Tests | Verdict |
|---|------|-------|---------|
| 1 | `ledger/src/mcp.rs` | 7 | PASS |
| 2 | `ledger/src/mcp_merkle.rs` | 8 | PASS |
| 3 | `ledger/src/mcp_erasure.rs` | 8 | PASS |
| 4 | `ledger/src/mcp_reconstruction.rs` | 12 | PASS |
| 5 | `ledger/src/mcp_ordering.rs` | 9 | PASS |
| 6 | `ledger/src/mcp_relay_attestation.rs` | 9 | PASS |
| 7 | `ledger/src/mcp_aggregate_attestation.rs` | 18 | PASS |
| 8 | `ledger/src/mcp_consensus_block.rs` | 14 | PASS |
| 9 | `ledger/src/shred/mcp_shred.rs` | 10 | PASS |
| 10 | `ledger/src/mcp_shredder.rs` | 1 | PASS (thin facade) |
| 11 | `core/src/mcp_replay.rs` | 4 | PASS |
| 12 | `core/src/mcp_vote_gate.rs` | 10 | PASS |
| 13 | `core/src/mcp_relay.rs` | 10 | PASS |
| 14 | `core/src/mcp_relay_submit.rs` | 14 | PASS |
| 15 | `core/src/mcp_constant_consistency.rs` | 3 | PASS |
| 16 | `turbine/src/mcp_proposer.rs` | 2 | PASS |
| 17 | `transaction-view/src/mcp_payload.rs` | 6 | PASS |
| 18 | `transaction-view/src/mcp_transaction.rs` | 10 | PASS |

Zero stubs, zero TODOs, zero `unimplemented!()`, zero `#[ignore]`. **193 tests total.**

---

## 8. Test Coverage Gaps

| Gap | Severity | Notes |
|-----|----------|-------|
| Repair negative paths untested | MEDIUM | No test for wrong-slot/wrong-proposer/empty-blockstore repair requests |
| `mcp_replay.rs` thin coverage | MEDIUM | 4 tests for ~430 lines; missing full reconstruction pipeline with real transactions |
| `mcp_merkle.rs` edge cases | MEDIUM | No tests for `EmptyShredSet` error, `TooManyShreds` error |
| Automatic repair trigger missing | HIGH | No production path triggers MCP shred repair automatically |
| `infer_is_entry_batch` edge cases | LOW | No test for too-short (<8 byte) payloads |

---

## 9. Residual Items

| Item | Severity | Status |
|------|----------|--------|
| `finish_prev_slot` uses legacy `make_merkle_shreds_from_entries` | INFO | Works with decode fix; fragile bincode/wincode coupling |
| `consensus-metrics` thread panic on shutdown | INFO | Non-fatal, not MCP-specific |
| Blockstore slot meta consistency errors during shutdown | INFO | Non-fatal, occurs after test assertions pass |
| Snapshot catch-up story | DEFERRED | Separate effort per user decision |
| plan.md gap notes at lines 30-37, 83 are stale | INFO | Code has closed these gaps; plan.md should be updated |

---

## Current Verdict

- Addendum wiring gaps: **ALL 5 REFUTED** (code is live and reachable)
- MCP local-cluster integration: **PASS**
- Implementation completeness vs plan.md: **PASS** (plan.md gap notes are stale)
- Production reachability: **PASS** (all subsystems live except automatic repair trigger)
- Security posture: **ACCEPTABLE** (no critical/high vulnerabilities)
- Test coverage: **GOOD** (193 tests, medium-depth gaps remain)
- One structural gap: **MCP repair has no automatic trigger** (admin-RPC only)
