# MCP Adversarial Audit — Deep Re-Verification (Master)

Date: 2026-02-12
Branch: `master` (commit `e12d4904f9`)
Perspective: Principal engineer + security researcher, assuming adversarial/lazy developer.
Scope: **Verify all claimed N1-N4/N6/N7 fixes are genuine (not lazy relocations), hunt new wiring gaps, compare full plan.md against code, dead code inventory.**

---

## Executive Summary

All claimed fixes (N1, N2, N3, N4, N6, N7) are **genuine and correct**. Repair now scans all 200 shred indices per proposer. The tx_count OOM vector is bounded. Error variants are matched exhaustively with per-variant counters. Serve-side feature gate is correctly placed. The retention constant is unified. Dedup has observability.

This deep re-audit found **0 regressions** from the latest commit, **0 new high-severity findings**, **1 new medium finding** (defense-in-depth gap in `mcp_payload.rs`), **2 medium-severity dead-code findings**, and several low/info items. Plan conformance is strong across all 7 passes. Two architectural gaps remain from prior audits (snapshot catch-up, consensus-block recovery).

### Verdicts

| Area | Status |
|------|--------|
| Local-cluster e2e test | **PASS** (59.91s) |
| N1 fix (repair multi-shred scan) | **CONFIRMED GENUINE** |
| N2 fix (tx_count OOM bounds) | **CONFIRMED GENUINE** |
| N3 fix (per-variant error counters) | **CONFIRMED GENUINE** |
| N4 fix (serve-side feature gate) | **CONFIRMED GENUINE** |
| N6 fix (dedup counter) | **CONFIRMED GENUINE** |
| N7 fix (unified retention constant) | **CONFIRMED GENUINE** |
| Prior fixes (H1, H2, M1, M2, L2, L3) | **ALL INTACT** |
| Plan conformance (7 passes) | **STRONG** (2 minor deviations, 2 architectural gaps) |
| New findings | **0 HIGH, 3 MEDIUM, 9 LOW** |

---

## 1. Fix Verification

### N1: Repair Multi-Shred Scan — CONFIRMED GENUINE

**Evidence:** `repair_service.rs:689-715` — inner loop iterates `0..NUM_RELAYS` (200 shred indices). On `Ok(None)` (missing shred), pushes repair request then `continue`s to next shred index. Only breaks on budget exhaustion (`repairs.len() >= max_new_repairs`) or blockstore I/O error. Outer loop scans all proposers, sharing the global repair budget.

**Test:** `test_identify_mcp_repairs_enqueues_missing_shreds` now asserts all 200 missing shred indices are returned (not just 1). Second call returns empty (dedup via `outstanding_repairs`).

**Key detail:** `ShredRepairType::McpShred` Hash/Eq derives include all 3 fields `(slot, proposer_index, shred_index)`, so requesting shred_index=0 does NOT block shred_index=1.

### N2: tx_count OOM Bounds Check — CONFIRMED GENUINE

**Evidence:** `blockstore_processor.rs:1705-1715` — computes `max_count = remaining / sizeof::<u32>()` (each tx needs at minimum a 4-byte length prefix). Rejects if `tx_count > max_count`. Check is BEFORE `Vec::with_capacity(tx_count)` at line 1717.

**Bound tightness:** MAX_PROPOSER_PAYLOAD = 34,520 bytes, 16 proposers max → ~552KB max execution output. At `remaining / 4`, worst case `max_count ≈ 138K` → allocation ~3.3MB. Not an OOM risk.

**Test:** `test_decode_mcp_execution_output_wire_transactions_rejects_unbounded_tx_count` sends `u32::MAX` tx_count with 0 remaining bytes → correctly rejected.

**Secondary finding (MEDIUM):** `transaction-view/src/mcp_payload.rs:43` has the same `Vec::with_capacity(tx_count)` pattern WITHOUT a bounds check. Input is bounded upstream by `MCP_RECON_MAX_PAYLOAD_BYTES = 34,520`, so not exploitable in practice, but a defense-in-depth gap — see NEW-1 below.

### N3: Per-Variant Error Counters — CONFIRMED GENUINE

**Evidence:** `mcp_replay.rs:516-534` — `Err(err)` (bound, not `Err(_)`) fires aggregate counter, then exhaustive `match err` with 3 arms:
- `MissingSignature` → `mcp-reconstruction-transaction-metadata-drop-missing-signature`
- `InvalidLegacyView` → `mcp-reconstruction-transaction-metadata-drop-invalid-legacy-view`
- `InvalidLegacyRuntimeTransaction` → `mcp-reconstruction-transaction-metadata-drop-invalid-legacy-runtime-transaction`

Match is exhaustive with no wildcard — compiler-enforced. All arms increment distinct counters, then `return None` (correct: observability only, no behavioral change).

### N4: Serve-Side Feature Gate — CONFIRMED GENUINE

**Evidence:** `serve_repair.rs:690-695` — uses `activated_slot(&feature_set::mcp_protocol_v1::id()).is_some_and(|activated_slot| *slot >= activated_slot)`. If feature inactive, returns `None` (skips blockstore lookup). Counter `serve_repair-mcp_window_index-before-feature` fires. Stats still track miss.

**Placement:** Inside `handle_repair()`, after deserialization and signature verification (same architectural pattern as all other handlers — `WindowIndex`, `HighestWindowIndex`, `Orphan`, `ParentAndFecSetCount`). The feature gate saves the blockstore I/O (the dominant cost), not the shared deserialization pipeline.

**Test:** Dual-path test covers deactivated (asserts `None`, miss counted) and activated (asserts `Some`) with real blockstore data.

### N6: Dedup Counter — CONFIRMED GENUINE

**Evidence:** `mcp_replay.rs:537-543` — `if !seen_signatures.insert(signature)` now fires `mcp-reconstruction-transaction-duplicate-signature-drop` before `return None`. Previously silent.

### N7: Unified Retention Constant — CONFIRMED GENUINE

**Evidence:** `ledger/src/mcp.rs:21` defines `pub const CONSENSUS_BLOCK_RETENTION_SLOTS: u64 = 512`. Old `const MCP_CONSENSUS_BLOCK_RETENTION_SLOTS` is fully removed from both `mcp_replay.rs` and `window_service.rs`. Zero duplicate definitions remain. All 4 usage sites (2 in `window_service.rs`, 2 in `mcp_replay.rs`) reference `mcp::CONSENSUS_BLOCK_RETENTION_SLOTS`.

---

## 2. New Findings

### NEW-1. Missing Bounds Check on `Vec::with_capacity` in `mcp_payload.rs` (MEDIUM)

**File:** `transaction-view/src/mcp_payload.rs:43`

`McpPayload::from_bytes()` reads `tx_count` as u32 and calls `Vec::with_capacity(tx_count)` without validating against remaining buffer size. A crafted `tx_count` near `u32::MAX` would attempt ~103GB allocation.

**Mitigation:** Only called from `decode_reconstructed_payload()` which is fed by `reconstruct_payload()` capped at 34,520 bytes. Not exploitable through the current call chain.

**Risk:** If `McpPayload::from_bytes()` were ever called from a new path with larger/untrusted input, the OOM vector would resurface. The fix in `blockstore_processor.rs` shows the developer knows this pattern needs hardening — applying the same `remaining / sizeof::<u32>()` check here would be consistent.

### NEW-2. `McpReconstructionState` and 5 Methods Are Dead Code (MEDIUM)

**File:** `ledger/src/mcp_reconstruction.rs:46-141`

The stateful reconstruction wrapper (`McpReconstructionState::new`, `present_shards`, `insert_shard`, `try_reconstruct`, `insert_and_try_reconstruct`) is `pub` but has zero non-test callers. Production code in `mcp_replay.rs` calls `reconstruct_payload()` directly. ~90 lines of untested-in-production pub API.

### NEW-3. `canonical_filtered` and `filtered_valid_entries` Are Dead Code (MEDIUM)

**File:** `ledger/src/mcp_aggregate_attestation.rs:248,293`

Both pub functions exist but are only called in tests. Production code uses `new_canonical` to build aggregates. These represent canonical filtering logic that should arguably be the production path but is not wired in.

### NEW-4. `mcp_shredder.rs` Entire Module Is Dead (LOW)

**File:** `ledger/src/mcp_shredder.rs`

Declared as `pub mod` in `ledger/src/lib.rs:36` but never imported by any crate. Contains 4 public wrapper functions over `mcp_erasure` and `mcp_merkle`. Zero non-test callers.

### NEW-5. `mcp_erasure::commitment_root` Has No Production Callers (LOW)

**File:** `ledger/src/mcp_erasure.rs:130`

Thin wrapper over `mcp_merkle::commitment_root`. Production code uses `mcp_reconstruction::commitment_root` instead.

### NEW-6. `order_batches_by_fee_desc` Has No External Callers (LOW)

**File:** `ledger/src/mcp_ordering.rs:23`

Only called in tests. Production uses `order_batches_mcp_policy` which calls `concat_batches_by_proposer_index` directly.

### NEW-7. `witness_for_leaf` Has No Production Callers (LOW)

**File:** `ledger/src/mcp_merkle.rs:73`

Only called in tests. Production uses `commitment_and_witnesses`.

### NEW-8. `is_mcp_shred_packet` and `is_mcp_shred_packet_ref` Are Dead (LOW)

**File:** `ledger/src/shred/mcp_shred.rs:96,100`

Only called in tests. Production uses `is_mcp_shred_bytes`.

### NEW-9. `verify_proposer_signatures` on `RelayAttestation` Is Dead (LOW)

**File:** `ledger/src/mcp_relay_attestation.rs:182`

Only called in tests. Production uses entry-level signature checks.

### NEW-10. `InvalidLeafIndex` Arm in `map_merkle_error` Is Unreachable (LOW)

**File:** `ledger/src/mcp_reconstruction.rs:221-223`

`mcp_merkle::commitment_root` never produces `InvalidLeafIndex`. This arm is defensive but could be `unreachable!()`.

### NEW-11. No Tests for Per-Variant Error Counters (LOW)

**File:** `core/src/mcp_replay.rs:519-531`

The 3 per-variant counters and the dedup counter have no test exercising them. No test sends malformed or duplicate transactions through the reconstruction pipeline.

### NEW-12. `blockstore_processor` Fallback to Legacy Entries When MCP Output Missing (LOW)

**File:** `ledger/src/blockstore_processor.rs:1826-1828`

`maybe_override_replay_entries_with_mcp_execution_output` returns original entries when `mcp_execution_output` is `None` for MCP-active slots. The "strict no-fallback" invariant is enforced by `replay_stage.rs` upstream, not at this layer. Architecturally fragile if a new caller bypasses replay_stage's guards.

---

## 3. Plan Conformance

### Pass 5: Proposer Dispatch — CONFORMANT

All plan requirements verified:
- Proposer activation via `proposer_indices_at_slot` ✓
- Duplicate proposer indices handled correctly ✓
- Per-proposer signature dedup ✓
- B2 ordering at output ✓
- `MAX_PROPOSER_PAYLOAD` enforced (34,520 bytes) ✓
- 200 shreds per proposer emitted ✓
- Fee reservation `(base + inclusion + ordering) * 16` ✓
- Slot completion triggers dispatch and removes state ✓

### Pass 7.1: Vote Gate — CONFORMANT

All 7 checks implemented correctly:
1. Leader signature ✓
2. Leader index match ✓
3. Delayed bankhash availability ✓
4. Delayed bankhash match ✓
5. Global relay threshold ≥120 ✓
6. Proposer inclusion ≥80 / equivocation exclusion ✓
7. Local shred availability ≥40 ✓

Thresholds: `ceil(3/5 * 200) = 120`, `ceil(2/5 * 200) = 80`, `ceil(1/5 * 200) = 40` — all correct.

### Pass 7.3: Two-Phase Fees — CONFORMANT

- Phase A calls `collect_fees_only` ✓
- Phase B calls `skip_fee_collection` ✓
- Gating: `block_verification=true` AND `mcp_protocol_v1` active ✓
- Fee failures from Phase A propagated as execution filters for Phase B ✓
- Nonce handling via dedicated helper `withdraw_for_mcp_phase_a_nonce` ✓

### Acceptance Invariants — ALL CONFORMANT

- Deterministic B2 ordering enforced at both proposer output and reconstruction ✓
- Feature gate on all MCP paths ✓
- Standard Solana path unchanged when feature inactive ✓
- Cross-crate constant consistency tests ✓
- Invalid MCP messages dropped deterministically ✓
- Threshold checks use ceil-threshold logic ✓
- Delayed bankhash gating is strict ✓

### Known Architectural Gaps (Unchanged)

1. **No snapshot catch-up story** — A node snapshot-booting into an MCP-active epoch cannot acquire historical MCP execution outputs or consensus blocks. CRITICAL for production.
2. **No consensus-block recovery after partition** — No gossip/repair mechanism to re-request missed consensus blocks.

---

## 4. Dead Code Summary

| File | Dead Items | Severity |
|------|-----------|----------|
| `mcp_shredder.rs` | Entire module (4 pub fns) | LOW |
| `mcp_reconstruction.rs` | `McpReconstructionState` + 5 methods | MEDIUM |
| `mcp_aggregate_attestation.rs` | `canonical_filtered`, `filtered_valid_entries` | MEDIUM |
| `mcp_erasure.rs` | `commitment_root` | LOW |
| `mcp_ordering.rs` | `order_batches_by_fee_desc` | LOW |
| `mcp_merkle.rs` | `witness_for_leaf` | LOW |
| `mcp_shred.rs` | `is_mcp_shred_packet`, `is_mcp_shred_packet_ref` | LOW |
| `mcp_relay_attestation.rs` | `verify_proposer_signatures` | LOW |

---

## 5. Test Coverage Gaps

| Gap | Severity |
|-----|----------|
| No test exercising per-variant error counters in `mcp_replay.rs` | LOW |
| No test for dedup counter `mcp-reconstruction-transaction-duplicate-signature-drop` | LOW |
| No negative test for `build_vote_gate_input` with bad relay/proposer signatures | LOW |
| No test for ambiguous bytes (valid as both MCP and bincode) | LOW |
| No end-to-end banking-stage MCP admission test | LOW |

---

## 6. Prior Concern Status

| ID | Concern | Status |
|----|---------|--------|
| H1 | Vote gate dead code | **FIXED** — verified genuine |
| H2 | Bincode-before-MCP parse | **FIXED** — verified genuine |
| M1 | Dispatch `any()` short-circuit | **FIXED** — verified genuine |
| M2 | Silent reconstruction drops | **FIXED** — verified genuine |
| M3 | Missing nonce test | **DISMISSED** — coverage exists |
| M4 | Weak equivocation evidence | **OPEN** — non-blocking v1 tradeoff |
| N1 | Single-shred repair rate | **FIXED** — verified genuine |
| N2 | tx_count OOM vector | **FIXED** — verified genuine |
| N3 | Error variant discarded | **FIXED** — verified genuine |
| N4 | No serve-side feature gate | **FIXED** — verified genuine |
| N5 | O(n) nonce-less repair scan | **OPEN** — non-blocking performance concern |
| N6 | Dedup counter missing | **FIXED** — verified genuine |
| N7 | Duplicate retention constant | **FIXED** — verified genuine |

---

## 7. Integration Test — PASS

```
cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture
```

**Result: PASS** (59.91s, exit code 0). 5-node cluster with MCP activation.

---

## Current Verdict

- Prior fix regressions: **0**
- New high findings: **0**
- New medium findings: **3** (mcp_payload.rs bounds gap, McpReconstructionState dead code, canonical_filtered dead code)
- New low findings: **9** (dead code items, unreachable arm, test gaps, fallback fragility)
- Architectural gaps: **2** (snapshot catch-up, consensus-block recovery) — unchanged
- Non-blocking tracked items: **2** (M4 hash-only evidence, N5 O(n) scan) — unchanged
- All claimed fixes: **VERIFIED GENUINE**
- Plan conformance: **STRONG**
- Feature gate: **PASS**
- Integration test: **PASS**
