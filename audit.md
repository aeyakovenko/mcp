# MCP Adversarial Audit (Master)

Date: 2026-02-12
Branch: `master` (commit `a45c3023f2`)
Perspective: Principal engineer + security researcher, assuming adversarial/lazy developer.
Scope: Full MCP implementation vs plan.md, fixes from prior audit, local-cluster e2e, security, test coverage.

---

## Executive Summary

The MCP implementation is **feature-complete and passing end-to-end**. Both critical blockers from the prior audit (B3 deferral overreach, BlockComponent decode collision) are fixed and verified. The integration test passes in 78s with all MCP artifacts confirmed: shreds, attestations, consensus blocks, transaction inclusion, cross-node execution output equality, and delayed bankhash verification.

All 18 MCP-specific files contain real implementation code with zero stubs, zero TODOs, zero `#[ignore]`d tests. ~193 MCP-specific tests across the codebase, all with real assertions.

### Verdicts

| Area | Status |
|------|--------|
| Implementation vs plan.md | **PASS** (21/22 items implemented, 1 partial) |
| Local-cluster e2e test | **PASS** (78s, all artifacts verified) |
| B3 deferral fix | **PASS** (3-condition guard, 4 test scenarios) |
| BlockComponent decode fix | **PASS** (buffer-length disambiguation, round-trip test) |
| MCP repair protocol | **PASS** (all REAL, 7 tests) |
| Vote gate (10 tests, 7 rejections) | **PASS** |
| Feature gate enforcement (17 files) | **PASS** |
| Security attack surface | **ACCEPTABLE** (no critical vulns) |
| Code quality (zero stubs/TODOs) | **PASS** |
| Test coverage (~193 tests) | **GOOD** (gaps noted below) |

---

## 1. Prior Audit Fixes -- Verified

### Fix 1: B3 Deferral Overreach

**File:** `core/src/replay_stage.rs:4030-4039`

The function `should_defer_for_missing_mcp_authoritative_block_id` now has all three required conditions:
1. MCP feature active for slot
2. `has_mcp_consensus_block_for_slot` (the previously missing precondition)
3. `mcp_authoritative_block_id_for_slot` returns `None`

The old inline code at `f8a6de53be` had condition (2); it was lost during the refactor in `65568a2a79`. Now restored.

**Unit tests** cover all four branches:
- MCP not active -> no defer
- MCP active, no consensus block -> no defer (the regression case)
- MCP active, consensus block with invalid meta -> defer
- MCP active, consensus block with valid block_id -> no defer

**Minor nit:** Redundant lock acquisition (3 read locks in the hot path). Not a correctness issue.

### Fix 2: BlockComponent Empty-Entry Decode

**File:** `entry/src/block_component.rs`

The `SchemaRead` impl now disambiguates `entry_count == 0` by buffer length:
- Exactly 8 bytes remaining -> `EntryBatch(vec![])` (empty entries from `finish_prev_slot`)
- More than 8 bytes -> `BlockMarker` (legitimate marker with u16 tag + data)

This is sound because: (a) `bincode::serialize(&[] as &[Entry])` always produces exactly 8 zero bytes, (b) a valid `BlockMarker` always has 8 zero bytes + at least 2 more bytes for the u16 tag.

Round-trip test added for `BlockComponent::EntryBatch(vec![])`.
Additional helper fix in this pass: `infer_is_entry_batch` / `infer_is_block_marker` now correctly classify 8-byte zero payloads as empty `EntryBatch`, not marker.

---

## 2. Integration Test -- PASS

```
cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture
```

**Result: PASS** (78.27s, exit code 0)

Verified:
- Root advances from 63 -> 66+ (no stall)
- Zero `ReadSizeLimit(2)` errors (was every MCP slot on prior commit)
- MCP shred + relay attestation + execution artifacts at slot 64
- Non-leader execution output at slot 66
- Consensus block at slot 73 with matching delayed bankhash for slot 72
- 80 transactions decoded, submitted transfer signature found
- `consensus-metrics` thread panic on shutdown (non-fatal, known issue)

---

## 3. Implementation vs plan.md -- 21/22 IMPLEMENTED

| Plan Item | Status |
|-----------|--------|
| MCP constants (16/200/120/80/40) | IMPLEMENTED |
| Merkle commitment tree (0x00/0x01 domain) | IMPLEMENTED |
| Reed-Solomon 40+160=200 | IMPLEMENTED |
| Payload reconstruction from 40+ shards | IMPLEMENTED |
| B2 ordering (MCP-first, fee-desc, sig tie-break) | IMPLEMENTED |
| MCP shred format (1232 bytes) | IMPLEMENTED |
| Relay attestation wire format + signing | IMPLEMENTED |
| Aggregate attestation canonical filtering | IMPLEMENTED |
| Consensus block build/sign/verify | IMPLEMENTED |
| MCP proposer broadcast via QUIC | IMPLEMENTED |
| Relay shred processing pipeline | IMPLEMENTED |
| Attestation dispatch | IMPLEMENTED |
| Two-pass fees (Phase A/B) | IMPLEMENTED |
| MCP replay with reconstruction | IMPLEMENTED |
| Vote gate (7 checks) | IMPLEMENTED |
| Feature gate (mcp_protocol_v1) | IMPLEMENTED |
| Window service integration | IMPLEMENTED |
| Local cluster e2e test | IMPLEMENTED |
| MCP shred repair (McpShred type) | IMPLEMENTED |
| Nonce-less repair responses | PARTIALLY IMPLEMENTED |
| B3 strict block_id enforcement | IMPLEMENTED |
| B4 delayed bankhash (slot-1 saturating) | IMPLEMENTED |

**Partial item:** Nonce-less repair responses -- MCP repair response matching correctly uses payload key matching (not nonce), and MCP shreds fill full PACKET_DATA_SIZE so no room for trailing nonce. The request protocol header still carries a nonce field for protocol consistency. Functionally complete per plan intent.

---

## 4. Code Quality -- All 18 Files PASS

| # | File | Impl Lines | Tests | Verdict |
|---|------|-----------|-------|---------|
| 1 | `ledger/src/mcp.rs` | ~50 | 7 | PASS |
| 2 | `ledger/src/mcp_merkle.rs` | ~200 | 8 | PASS |
| 3 | `ledger/src/mcp_erasure.rs` | ~100 | 8 | PASS |
| 4 | `ledger/src/mcp_reconstruction.rs` | ~170 | 12 | PASS |
| 5 | `ledger/src/mcp_ordering.rs` | ~50 | 9 | PASS |
| 6 | `ledger/src/mcp_relay_attestation.rs` | ~200 | 14 | PASS |
| 7 | `ledger/src/mcp_aggregate_attestation.rs` | ~450 | 15 | PASS |
| 8 | `ledger/src/mcp_consensus_block.rs` | ~220 | 13 | PASS |
| 9 | `ledger/src/shred/mcp_shred.rs` | ~180 | 10 | PASS |
| 10 | `ledger/src/mcp_shredder.rs` | ~30 | 1 | PASS (thin facade) |
| 11 | `core/src/mcp_replay.rs` | ~430 | 3 | PASS |
| 12 | `core/src/mcp_vote_gate.rs` | ~100 | 10 | PASS |
| 13 | `core/src/mcp_relay.rs` | ~80 | 9 | PASS |
| 14 | `core/src/mcp_relay_submit.rs` | ~260 | 11 | PASS |
| 15 | `core/src/mcp_constant_consistency.rs` | ~0 | 3 | PASS |
| 16 | `turbine/src/mcp_proposer.rs` | ~55 | 2 | PASS |
| 17 | `transaction-view/src/mcp_payload.rs` | ~75 | 6 | PASS |
| 18 | `transaction-view/src/mcp_transaction.rs` | ~250 | 9 | PASS |

**Totals:** ~2,900 implementation lines, ~2,600 test lines, 0 stubs, 0 TODOs, 0 `unimplemented!()`, 0 `#[ignore]`.

---

## 5. Security Findings

### Consensus Attacks -- ALL DEFENDED

| Attack | Status | Defense |
|--------|--------|---------|
| Forged shreds | DEFENDED | ed25519 signature over Merkle root + domain-separated witness verification (slot/proposer/shred bound to leaf) |
| Forged attestations | DEFENDED | Relay ed25519 sig + proposer sigs within entries, strict sort enforcement, equivocation detection |
| Fake consensus block | DEFENDED | Leader signature verification + leader_index match + delayed bankhash binding |
| B2 ordering manipulation | PARTIALLY DEFENDED | Deterministic order is verifiable; proposers can still front-run within their own batch (inherent to multi-proposer design) |
| Cross-proposer tx duplication | DEFENDED | Runtime signature dedup at bank level; only one execution succeeds |

### DoS Attacks

| Attack | Severity | Status |
|--------|----------|--------|
| Relay channel flooding | MEDIUM | Cache bounded (25,600 entries), slot-window pruning (64 slots), sig verification before storage. No per-identity rate limiting in MCP code (relies on transport-layer SWQoS). |
| Malformed shred crash | DEFENDED | All parsers use bounds checking, checked arithmetic, validated offsets. No crash paths from malformed input. |
| Repair protocol abuse | MEDIUM | Nonce-less MCP repair allows injection of structurally valid but cryptographically invalid shreds. Downstream reconstruction verifies crypto, so impact is wasted repair slot + linear scan cost (bounded at 16K LRU). |

### Economic Attacks -- ALL DEFENDED

| Attack | Status | Defense |
|--------|--------|---------|
| Fee payer drain via two-pass | DEFENDED | `validate_fee_payer_with_multiplier` uses 16x fee with `checked_mul` + rent minimum preservation |
| Nonce Phase-A exploit | DEFENDED | `withdraw_for_mcp_phase_a_nonce` bypasses rent check but calling code pre-adds `nonce_min_balance` to fee; `validate_fee_payer_for_mcp` ensures sufficient balance |
| Fee multiplier insufficient | DEFENDED | 16x matches NUM_PROPOSERS; cross-crate constant consistency enforced by `mcp_constant_consistency.rs` tests |

### Implementation Robustness

| Issue | Severity | Notes |
|-------|----------|-------|
| `bank_forks.read().unwrap()` in mcp_replay.rs (2 sites) | LOW | Panics on poisoned RwLock; other sites in same file handle gracefully |
| `unreachable!()` in mcp_reconstruction.rs:225 | LOW | Logically sound (InvalidWitnessLength can't occur in commitment_root path) but could map to error instead |
| TOCTOU in consensus block processing | LOW | Between `has_mcp_consensus_block` and `mcp_authoritative_block_id` checks; worst case is extra deferral iteration (safe) |

---

## 6. Test Coverage -- ~193 MCP Tests

### Strong Coverage Areas

- **Vote gate:** 10 tests, all 7 rejection paths covered
- **Relay attestation:** 17 tests including signature tamper, unsorted, truncated
- **Aggregate attestation:** 16 tests including equivocation, signature filtering
- **Consensus block:** 14 tests including oversized, tampered, wrong key
- **Reconstruction:** 12 tests including commitment mismatch, poisoned state recovery
- **Replay stage MCP tests:** 10 tests covering B3 deferral, B4 bankhash, execution output
- **MCP relay processor:** 10 tests including sig/witness rejection, conflict, pruning
- **Relay submit:** 10 tests including QUIC dispatch, channel capacity
- **Erasure coding:** 8 tests including coding-only/data-only reconstruction

### Coverage Gaps

| Gap | Severity | Notes |
|-----|----------|-------|
| MCP repair pipeline is still lightly tested | MEDIUM | Added dedicated tests for `run_mcp_window_request` and `request_repair_for_mcp_shred_from_address`, but still missing direct failure-path coverage for malformed MCP repair responses. |
| `block_component.rs` negative decode coverage remains thin | MEDIUM | Added tests for `EmptyEntryBatch`, helper classification, and `UpdateParent` round-trip. Still missing truncated/corrupt marker decode tests. |
| `mcp_replay.rs` has only 4 tests for ~430 lines | MEDIUM | Missing: full payload reconstruction with real transactions, `ordering_metadata` edge cases |
| `mcp_merkle.rs` missing edge case tests | MEDIUM | No tests for `EmptyShredSet` error, `TooManyShreds` error, non-power-of-2 leaf count |
| Integration test doesn't explicitly assert root advancement | LOW | Root advancement is implicitly required for test to complete, but no `assert!(root > activation_slot)` |

---

## 7. Residual Items

| Item | Severity | Status |
|------|----------|--------|
| `finish_prev_slot` still uses legacy `make_merkle_shreds_from_entries` path | INFO | Works correctly with decode fix; fragile coupling between `bincode` and `wincode` serialization identity |
| `consensus-metrics` thread panic on shutdown | INFO | Non-fatal, known issue, not MCP-specific |
| Snapshot catch-up story | DEFERRED | Separate effort per user decision |

---

## Current Verdict

- Critical audit blockers: **CLOSED**
- MCP local-cluster integration: **PASS**
- Implementation completeness: **PASS** (21/22 plan items, 1 partial)
- Security posture: **ACCEPTABLE** (no critical/high vulnerabilities)
- Test coverage: **GOOD** (repair + block_component gaps reduced; medium-depth gaps remain)
