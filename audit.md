# MCP Implementation Audit Report

**Date:** 2026-02-25
**Commit:** HEAD of `master` branch
**Spec:** `plan.md` (Agave, Minimal-Diff v2)
**Methodology:** Adversarial line-by-line audit assuming lazy/adversarial developer. Every spec requirement traced to code. All constants, offsets, thresholds, and feature gates verified independently.

---

## Executive Summary

The MCP implementation is largely faithful to the spec across all 7 passes. Constants, hash domain separations, wire formats, erasure parameters, ordering policy, and threshold calculations are correct. The feature gate is consistently applied. However, the audit found **1 critical bug**, **1 high-severity gap**, **3 medium issues**, and several low/informational items.

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH     | 1 |
| MEDIUM   | 3 |
| LOW      | 12 |
| INFO     | 20+ |

---

## CRITICAL

### C-001: Sigverify slot extraction reads proposer signature bytes instead of actual slot

**File:** `turbine/src/sigverify_shreds.rs:310`
**Spec:** MCP shred slot lives at `OFFSET_SLOT` (byte 65), after the 64-byte proposer signature and 1-byte discriminator.
**Code:** Reads `data[..8]` (bytes 0-7), which is the first 8 bytes of the proposer signature.

```rust
// Line 310 -- WRONG: reads signature bytes as slot
Slot::from_le_bytes(data[..std::mem::size_of::<Slot>()].try_into().unwrap()),
```

**Correct:** `data[OFFSET_SLOT..OFFSET_SLOT + 8]` (bytes 65-72), as done in `mcp_shred.rs:164` and `shred_fetch_stage.rs:440-448`.

**Impact:** The feature gate check `check_feature_activation(feature_id, slot, root_bank)` uses garbage data (random signature bytes interpreted as u64). Depending on the random value vs the activation slot, MCP packets may be incorrectly partitioned or dropped. The associated test (`test_partition_mcp_packets_uses_layout_prefilter_and_feature_gate` at line 733) is also broken -- it constructs the MCP buffer with slot at bytes 0-7 (matching the bug) and does not set the discriminator at byte 64.

**Fix:** Change line 310 to:
```rust
Slot::from_le_bytes(
    data[OFFSET_SLOT..OFFSET_SLOT + std::mem::size_of::<Slot>()]
        .try_into()
        .unwrap(),
),
```
And fix the test to construct a proper MCP shred wire format.

---

## HIGH

### H-001: Boot-from-ledger replay silently falls back to legacy entries for MCP-active slots

**File:** `ledger/src/blockstore_processor.rs:1861-1862`
**Spec (plan.md line 722):** "strict no-fallback now holds for all MCP-active replay slots: replay input is always sourced from McpExecutionOutput (possibly empty), never from legacy entry transactions."
**Code:** When `mcp_execution_output` is `None` and MCP is active, returns `Ok((replay_entries, default_num_txs))` -- falling back to legacy entries.

```rust
let Some(encoded_output) = mcp_execution_output else {
    return Ok((replay_entries, default_num_txs));  // <-- silent fallback
};
```

**Context:** During online replay, `replay_stage` calls `maybe_prepare_mcp_execution_output_for_replay_slot` which ensures a placeholder exists before reaching this code. But during boot-from-ledger (via `confirm_full_slot`), no such preparation occurs. If a node crashes after partial replay but before execution output persistence, the reboot path silently replays MCP slots using legacy entries, potentially producing a divergent bank hash.

**Fix:** When MCP is active and `mcp_execution_output` is `None`, return an error or write an empty placeholder rather than falling through.

---

## MEDIUM

### M-001: Consensus block sender_pubkey check blocks retransmitted fragments

**File:** `core/src/window_service.rs:939-945`
**Spec:** Consensus blocks should be receivable by validators.
**Code:** `validate_and_store_consensus_block` requires `sender_pubkey == leader_pubkey`. Since `sender_pubkey` comes from the QUIC connection identity, any fragment retransmitted by a non-leader node (e.g., a relay) will be rejected.

```rust
if sender_pubkey != leader_pubkey {
    debug!("dropping MCP ConsensusBlock for slot {} ...", ...);
    return None;
}
```

**Impact:** Consensus block reception is restricted to direct leader-to-validator QUIC connections. If a validator cannot reach the leader directly (firewall, partition), it will never receive the consensus block and cannot vote on MCP slots. There is no gossip/relay fallback for consensus blocks. The leader signature verification (line 946) already provides authentication; the sender identity check is redundant for security but limits propagation.

### M-002: Nonce minimum-rent edge case in MCP two-pass fee path has no dedicated test

**File:** `runtime/src/bank.rs:3565-3578`, `ledger/src/blockstore_processor.rs`
**Spec (plan.md line 757):** "nonce minimum-rent edge case" is explicitly listed as required test coverage.
**Code:** The `withdraw_for_mcp_phase_a_nonce` helper exists and the `collect_fees_only_for_transactions` adds `nonce_min_balance` to the fee. However, no test exercises this path -- specifically the case where Phase A deducts `base_fee + nonce_min_rent` and leaves the nonce payer at zero, then Phase B executes without double-charging.

### M-003: TpuClientNext forwarding fanout hardcoded to NUM_PROPOSERS=16 regardless of MCP activation

**File:** `core/src/forwarding_stage.rs:697-703`
**Spec (plan.md Pass 5.4):** Implement fanout for both forwarding clients.
**Code:** `TpuClientNextClient` always configures `Fanout { send: 16, connect: 16 }`, even pre-MCP. Pre-MCP, only 3 leaders exist, so 16-wide fanout wastes 13 connections. While not a correctness bug, it increases resource consumption on pre-MCP validators.

```rust
leaders_fanout: Fanout {
    send: mcp::NUM_PROPOSERS,     // always 16
    connect: mcp::NUM_PROPOSERS,  // always 16
},
```

---

## LOW

### L-001: Discriminator mismatch returns misleading `InvalidSize` error

**File:** `ledger/src/shred/mcp_shred.rs:142-147`
**Issue:** When discriminator is wrong (not 0x03), returns `McpShredError::InvalidSize` with matching expected/actual sizes, producing "invalid MCP shred size: expected 1232, got 1232".
**Fix:** Add a dedicated `InvalidDiscriminator` error variant.

### L-002: Missing test for truncated/oversized packet rejection

**File:** `ledger/src/shred/mcp_shred.rs` (tests)
**Spec (1.6):** "Truncated packet (< MCP_SHRED_WIRE_SIZE)" and "Oversized packet (> MCP_SHRED_WIRE_SIZE)" are explicitly required test cases. Code handles these correctly (size check at line 95, 134), but the tests are absent.

### L-003: Missing test for wrong shred_index failing witness verification

**File:** `ledger/src/shred/mcp_shred.rs` (tests)
**Spec (1.6):** "Wrong shred_index fails witness verification" is explicitly listed. No test verifies that a witness generated for shred_index=X fails when verified with shred_index=Y.

### L-004: Missing test for full 200-shard commitment recomputation

**File:** `ledger/src/mcp_erasure.rs` (tests)
**Spec (1.6):** "Given all 200 shards, recompute Merkle root and verify it matches commitment." No test exercises the complete shred-to-commitment pipeline for all 200 shards.

### L-005: Feature gate absent in `bank=None` MCP schedule lookup path

**File:** `ledger/src/leader_schedule_cache.rs:282-284`
**Spec (2.3):** "All helpers must check if mcp_protocol_v1 is active for the slot."
**Code:** When `bank` is `None`, `get_epoch_mcp_schedule_no_compute` does not check the feature gate. Mitigated by the cache only being populated when MCP is active.

### L-006: `set_block_id` uses `debug_assert_eq` (no-op in release)

**File:** `runtime/src/bank.rs:5871`
**Spec (7.5):** "If local slot bank with different block_id, treat as fork mismatch."
**Code:** `debug_assert_eq!(*block_id_w, block_id)` is stripped in release builds. A conflicting `block_id` set call is silently ignored.

### L-007: Unfragmented consensus block (0x02) ingestion never triggers finalization candidate

**File:** `core/src/window_service.rs:1060-1071`
**Issue:** The `0x02` path returns `None` after `validate_and_store_consensus_block`, unlike the `0x03` path which returns `Some(slot)` to trigger finalization. The block is stored but finalization is not attempted until a pending retry picks it up. Mitigated because `0x02` is a legacy/test path and `0x03` fragments are the production path.

### L-008: Pending MCP slots limited to most recent 16, earlier slots starved

**File:** `core/src/replay_stage.rs:3040-3051`
**Spec (6.4):** "Retain and retry pending MCP consensus slots."
**Code:** Processes only the last 16 pending slots. Older slots are never retried via `maybe_process_pending_mcp_slots` until they become the heaviest bank.

### L-009: Delayed slot hardcoded to `slot - 1` in leader finalization

**File:** `core/src/window_service.rs:154`
**Code:** `let delayed_slot = slot.saturating_sub(1);` -- always `slot - 1`. The `ConsensusMeta` struct supports arbitrary `delayed_slot`, and the consumer reads it from the block, so this is consistent. But if consensus ever defines a different delayed_slot, only this line needs updating.

### L-010: Double-parse of control frames in shred_fetch_stage hot path

**File:** `core/src/shred_fetch_stage.rs:454-468`
**Issue:** `is_valid_mcp_control_frame` fully deserializes `0x01` and `0x02` frames to validate them, then discards the result. Window service re-parses the same bytes. The comment (line 493) explains this prevents false positives from signature byte aliasing, which is legitimate, but adds CPU cost.

### L-011: Feature gate absent in `is_valid_mcp_control_frame`, only checked downstream

**File:** `core/src/shred_fetch_stage.rs:454-468`
**Issue:** Control frames are not checked for MCP feature activation at the fetch stage level. Pre-MCP frames consume channel capacity before being dropped in window service.

### L-012: Missing TpuClientNext MCP forwarding test

**File:** Test files
**Spec (5.6):** "Forwarding routes to proposer addresses in MCP mode for both forwarding clients."
**Code:** Only `ConnectionCacheClient` forwarding is tested (`test_forward_address_getter_uses_mcp_proposer_schedule_when_effective`). No test for `TpuClientNext` MCP forwarding.

---

## INFO (Verified Correct)

These spec requirements were verified and match the implementation:

| Area | Status | Evidence |
|------|--------|----------|
| Constants (NUM_PROPOSERS=16, NUM_RELAYS=200, thresholds) | CORRECT | `mcp.rs` with compile-time assertions |
| Merkle domain separation (0x00 leaf, 0x01 node) | CORRECT | `mcp_merkle.rs:3-4` |
| Merkle leaf hash (SHA-256(0x00 \|\| slot \|\| pidx \|\| sidx \|\| data)) | CORRECT | `mcp_merkle.rs:49-56` |
| Shred wire format offsets (DISC=64, SLOT=65, ...) | CORRECT | `mcp_shred.rs` with `const_assert_eq!` |
| Erasure RS(40,160) encode/decode | CORRECT | `mcp_erasure.rs` |
| Schedule domain separation (proposer/relay seeds) | CORRECT | `leader_schedule_utils.rs:13-14` |
| Schedule sampling (independent, duplicates allowed) | CORRECT | `leader_schedule.rs` |
| Feature gate registration | CORRECT | `feature-set/src/lib.rs:1139,2056` |
| All MCP CFs in purge paths | CORRECT | `blockstore_purge.rs` |
| Blockstore conflict detection (no silent overwrite) | CORRECT | `blockstore.rs:3169-3215` |
| Sigverify MCP partition before dedup/GPU | CORRECT | `sigverify_shreds.rs:291` (partition correct, but slot extraction wrong per C-001) |
| Relay attestation signing domain (excludes leader_index) | CORRECT | `mcp_relay_attestation.rs:78` |
| ConsensusBlock fragment DoS limits | CORRECT | `mcp_consensus_block.rs:441-570` |
| Channel backpressure (bounded, try_send, counters) | CORRECT | `tvu.rs:340-342` |
| Relay attestation stored as signed bytes | CORRECT | `window_service.rs:1035-1038` |
| Equivocation suppression in relay tracker | CORRECT | `window_service.rs:708-754` |
| Delayed bankhash two-source lookup + retry | CORRECT | `window_service.rs:154-178` |
| B2 ordering policy (MCP-first, fee-desc, sig-tiebreak) | CORRECT | `mcp_ordering.rs` |
| Two-pass fee (Phase A withdraw, Phase B skip-fee) | CORRECT | `blockstore_processor.rs` |
| Duplicate-signature per-occurrence charging | CORRECT | Test at `blockstore_processor.rs:6057-6127` |
| Vote gate 7 checks | CORRECT | `mcp_vote_gate.rs` |
| Reconstruction poison reset | CORRECT | `mcp_reconstruction.rs` |
| `record_bankless` 5 guard checks | CORRECT | `poh_recorder.rs:445-500` |
| Production record path fail-fast on missing bank | CORRECT | `block_creation_loop.rs:442-466` |
| Automatic MCP repair trigger | CORRECT | `repair_service.rs:855-864` |
| MCP repair nonce-less by design | KNOWN | `standard_repair_handler.rs:52-65` |
| Integration test (5-node cluster, cross-node equality) | CORRECT | `local_cluster.rs:7106-8667` |

---

## Spec Arithmetic Error

**plan.md lines 169, 569:** `MAX_PROPOSER_PAYLOAD = DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES = 34,520`
**Actual:** `40 * 862 = 34,480`. The code computes this correctly. The spec doc has a typo.

---

## Test Coverage Summary

| Spec Section | Coverage | Gaps |
|---|---|---|
| 1.6 Wire types | 85% | Missing: truncated/oversized packet, wrong shred_index witness, 200-shard commitment |
| 2.4 Schedules | 100% | -- |
| 3.4 Storage | 95% | -- |
| 4.6 Window/Transport | 80% | Sigverify partition test BROKEN (C-001), no unit test for `ingest_mcp_control_message` |
| 5.6 Proposer | 85% | Missing: TpuClientNext forwarding test |
| 6.5 Aggregation | 90% | -- |
| 7.6 Vote gate/Fees | 85% | Missing: nonce min-rent edge case, boot-from-ledger no-fallback |

---

## Recommended Priority

1. **Fix C-001** (sigverify slot offset) -- correctness bug, any test or production run with non-zero activation slot is affected
2. **Fix H-001** (boot-from-ledger fallback) -- state divergence risk on node restart
3. **Evaluate M-001** (sender_pubkey check) -- may need relaxation or a dedicated consensus block relay mechanism
4. **Add M-002 test** (nonce edge case) -- spec-mandated coverage gap
5. Low/Info items at maintainer discretion
