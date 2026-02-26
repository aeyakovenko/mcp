# MCP Implementation Adversarial Audit Report

**Date:** 2026-02-26
**Branch:** `master` (commit `cccd9c854`)
**Spec source:** `plan.md`
**Scope:** Full adversarial audit of MCP implementation against plan.md. Assumes developer is adversarial.

---

## Executive Summary

The MCP implementation is substantially complete and correctly implements the plan across all 7 passes. No consensus-safety-critical vulnerabilities were found. The audit identified **1 HIGH**, **8 MEDIUM**, and **9 LOW** severity issues. All plan acceptance invariants were verified. Feature gating is comprehensive (26 checks across 11 files). Critical shared-map lock handling is consistently explicit with no silent drops.

---

## Findings

### HIGH

#### H-001: Unchecked integer addition in relay attestation wire parser

**File:** `ledger/src/mcp_relay_attestation.rs:229,249`
**Plan ref:** Pass 1 wire types

The `read_u8` and `read_array<N>` helpers use unchecked addition for cursor arithmetic:
```rust
if *cursor + 1 > bytes.len() { ... }   // line 229
if *cursor + N > bytes.len() { ... }    // line 249
```

The addition `*cursor + N` can wrap around on `usize` overflow. If `cursor` reached a value near `usize::MAX`, the bounds check passes and the subsequent slice reads from an unintended position.

The sibling parsers in `mcp_aggregate_attestation.rs:513` and `mcp_consensus_block.rs:399` correctly use `cursor.checked_add(N)` with explicit error handling.

**Practical exploitability:** Very low -- cursor starts at 0 and increments by small amounts from a bounded buffer. But this is a defense-in-depth gap inconsistent with the safer pattern in sibling files.

**Recommendation:** Use `checked_add` consistently across all wire parsers.

---

### MEDIUM

#### M-001: Pre-activation MCP packets leak to Agave GPU sigverify path

**File:** `turbine/src/sigverify_shreds.rs:320-321`
**Plan ref:** Pass 3.3 sigverify partition

In `partition_mcp_packets`, when `is_mcp_shred_bytes(data)` returns true but `check_feature_activation` returns false (pre-activation slot), the function `continue`s without setting the packet as discarded. The MCP packet remains in the buffer and flows through to Agave dedup (wasting a bloom filter slot) and GPU sigverify (wasting GPU cycles before being rejected).

An adversary could flood pre-activation MCP packets to consume GPU sigverify capacity on the entire network before MCP activation.

**Recommendation:** Set `packet.meta_mut().set_discard(true)` on MCP-classified packets that fail the feature gate, rather than just `continue`ing.

#### M-002: `verify_signature()` is public without requiring `verify_witness()`

**File:** `ledger/src/shred/mcp_shred.rs:256-259`
**Plan ref:** Pass 1.4 shred wire format

`McpShred::verify_signature()` is `pub` and verifies ONLY the 32-byte commitment (Merkle root). It does NOT bind `slot`, `proposer_index`, or `shred_index` -- those are bound only through the Merkle witness verified by `verify_witness()`. An attacker can substitute wire header fields while keeping the same commitment+signature, producing a shred that appears validly signed but has wrong metadata.

The safe `verify()` method correctly calls both. **All current call sites (7 found) properly pair both checks.** But the public API is a footgun for future callers.

**Recommendation:** Make `verify_signature` private or `#[doc(hidden)]`, or rename to `verify_commitment_signature` with a doc comment warning.

#### M-003: `leader_index` not bounds-checked in AggregateAttestation/ConsensusBlock

**Files:** `ledger/src/mcp_aggregate_attestation.rs`, `ledger/src/mcp_consensus_block.rs`
**Plan ref:** Pass 6.1 validation rules

Both `new_canonical()` / `from_wire_bytes()` accept any `u32` for `leader_index`. A test explicitly verifies `u32::MAX` is accepted. With 16 proposers, an out-of-range `leader_index` in a consensus block could confuse downstream consumers that use it as an array index without bounds checking.

**Recommendation:** Reject `leader_index >= NUM_PROPOSERS` at parse time, or document that consumers must bounds-check.

#### M-004: Aggregate attestation wire parser accepts relay entries with 0 proposer entries

**File:** `ledger/src/mcp_aggregate_attestation.rs:191`
**Plan ref:** Pass 1.2 common parser invariants

The wire parser does not check for `entries_len == 0`. Relay entries with zero proposer entries are syntactically accepted. While `filtered_valid_entries()` filters these out downstream (line 274), the wire parser should reject them early to match the stricter relay attestation parser (`mcp_relay_attestation.rs:127-128`) which correctly rejects empty entries.

**Recommendation:** Add `if entries_len == 0 { return Err(...) }` after reading `entries_len`.

#### M-005: No feature gate on bank-less MCP cache lookup path

**File:** `ledger/src/leader_schedule_cache.rs:282-284`
**Plan ref:** Pass 2.3 cache feature gate

When `mcp_roles_at_slot` is called with `bank = None`, it reads from the cache without any feature gate check. The cache should only be populated after feature activation (gated in `compute_epoch_mcp_schedules`), but this is a defense-in-depth gap.

**Recommendation:** Add a feature-activated check on the bank-less path, or document the invariant.

#### M-006: Proposer dispatch uses UDP fallback for self-relay

**File:** `turbine/src/broadcast_stage/standard_broadcast_run.rs:981-991`
**Plan ref:** Pass 5.1 "dispatch to relay schedule via QUIC"

When the local node is both proposer and relay, dispatch prefers UDP over QUIC for self-delivery:
```rust
if relay_pubkey == identity {
    node.tvu(Protocol::UDP).map(McpRelayTarget::Udp)
        .or_else(|| node.tvu(Protocol::QUIC).map(McpRelayTarget::Quic))
}
```

The plan specifies "dispatch to relay schedule via QUIC." UDP delivery bypasses QUIC's sender authentication. While this appears to be an intentional optimization for loopback, it deviates from the stated plan.

**Recommendation:** Either use QUIC uniformly, or update plan.md to document this optimization.

#### M-007: Nonce-less MCP repair is a spoofing vector

**File:** `core/src/shred_fetch_stage.rs:413-426`
**Plan ref:** Pass 4.5 MCP repair

MCP repair responses omit trailing nonce bytes (by design, since MCP shreds fill the full PACKET_DATA_SIZE). The `register_response_without_nonce` method does a linear scan of outstanding requests. An attacker who knows which MCP shreds are being repaired can send unsolicited responses matching `(slot, proposer_index, shred_index)`.

**Mitigating factor:** MCP shreds still undergo full signature+witness verification downstream, so forged shreds are rejected. Risk is limited to resource amplification.

**Status:** Known design trade-off, documented in prior audit.

#### M-008: Phase A fee tracking in replay diverges from plan language

**File:** `runtime/src/bank.rs:3473-3537`
**Plan ref:** Pass 7.3 "Fee payer cumulative per-slot map in memory"

The plan specifies a "per-slot cumulative payer map in memory" for Phase A fee tracking. In replay, the bank's account store itself serves as the cumulative tracker (since `store_account` persists immediately in `collect_fees_only_for_transactions`). The explicit `McpFeePayerTracker` exists only in the banking stage admission path.

This is functionally correct (replay is single-threaded per slot), but the implementation strategy diverges from plan language.

**Recommendation:** Document that bank account store serves the cumulative tracking role for replay.

---

### LOW

#### L-001: `MCP_SHRED_OVERHEAD` not a named constant

**File:** `ledger/src/mcp.rs:17`
**Plan ref:** Pass 1.2

Plan specifies `MCP_SHRED_OVERHEAD = 370`. The code mentions this only in a comment, not as a testable constant. The invariant `SHRED_DATA_BYTES + MCP_SHRED_OVERHEAD == PACKET_DATA_SIZE` is implicitly held but not explicitly asserted.

#### L-002: `ceil_log2(0)` returns 0 instead of panicking

**File:** `ledger/src/mcp.rs:75-87`

`log2(0)` is mathematically undefined. The function silently returns 0. Not called with 0 in production (always `NUM_RELAYS=200`), but could mask bugs if future code calls it with 0.

#### L-003: MCP packets bypass sigverify dedup entirely

**File:** `turbine/src/sigverify_shreds.rs:285`
**Plan ref:** Pass 3.3

MCP packets extracted by `partition_mcp_packets` are not passed through the deduper. Duplicate MCP packets each get forwarded to window service. Blockstore `put_mcp_bytes_if_absent` rejects duplicates, but network and processing overhead of duplicates is not mitigated at the sigverify layer.

#### L-004: Silent domain truncation for oversized schedule domains

**File:** `ledger/src/leader_schedule.rs:94`
**Plan ref:** Pass 2.1

Domain length is capped at 24 bytes (`32 - 8`) via `.min()`. Current domains are 12 and 9 bytes (safe). A future domain > 24 bytes would be silently truncated without error.

#### L-005: Theoretical false positive in MCP shred classifier

**File:** `ledger/src/shred/mcp_shred.rs:92-122`
**Plan ref:** Pass 3.3

A crafted non-MCP packet that is exactly 1232 bytes, has byte 64 = 0x03, byte 975 = 0x08, and valid-range indices would pass `is_mcp_shred_bytes`. Such a packet cannot be a valid Agave shred (disjoint discriminator ranges) and would fail MCP signature verification downstream.

#### L-006: Sleep in retry loops on critical window service path

**File:** `core/src/window_service.rs:108-109`, `core/src/mcp_relay_submit.rs:334-335`
**Plan ref:** Pass 4.3

`try_send_mcp_control_frame` and `try_send_dispatch_frame_with_retry` use `std::thread::sleep` with microsecond backoff on full channels. While bounded (3 retries, 50-200us), this is on the latency-sensitive window service insert thread.

#### L-007: Whole ConsensusBlock (0x02) doesn't trigger finalization broadcast

**File:** `core/src/window_service.rs:1065`
**Plan ref:** Pass 6.1

The `MCP_CONTROL_MSG_CONSENSUS_BLOCK` handler returns `None` after storage, so it doesn't trigger `maybe_finalize_and_broadcast_mcp_consensus_block`. Only fragment reassembly (0x03) triggers it. Pending-slot retry logic compensates, but there's a latency gap for non-fragmented blocks.

#### L-008: Vote forwarding has no MCP awareness

**File:** `core/src/forwarding_stage.rs:191-195`
**Plan ref:** Pass 5.4

`get_vote_forwarding_addresses` always uses the traditional leader schedule, never MCP proposer schedule. Likely correct (votes go to consensus leader), but the plan's "MCP mode resolves proposer forward addresses" is ambiguous about vote traffic.

#### L-009: `McpReconstructionState` is `#[cfg(test)]` only

**File:** `ledger/src/mcp_reconstruction.rs:39-145`
**Plan ref:** Pass 7.2

The reconstruction state with poison/recovery semantics exists only in test code. Production uses a stateless `reconstruct_payload()` function that re-collects shards from blockstore each time. This is actually a cleaner design (immune to permanent poisoning by construction), but the test-only struct could diverge from production behavior.

---

## Verified Correct (Cross-Cutting)

### Feature Gating
- **26 feature gate checks** across 11 files verified
- All MCP computation paths trace to feature-gated entry points
- Wire format parsers are intentionally ungated (structural validation only, safe)
- No MCP state transition possible without `mcp_protocol_v1` active

### Lock Handling
- **20+ lock acquisitions** on critical MCP maps verified
- All use explicit `match Ok/Err` with `warn!()` logging on poison
- Zero use of `try_read()`/`try_write()` on critical maps
- Zero bare `unwrap()` on critical map locks in production code

### Acceptance Invariants (plan.md lines 881-894)
| Invariant | Status |
|---|---|
| No MCP packet parsed by Agave wire parsers | VERIFIED -- partition before `Shred::new_from_serialized_shred` |
| No MCP state transition without feature gate | VERIFIED -- 26 gate checks trace to all entry points |
| Threshold checks use ceil logic | VERIFIED -- `div_ceil()` at `mcp.rs:71` |
| Replay and vote gate use same filtering rules | VERIFIED -- both call `filtered_valid_entries` |
| Unknown versions/unsorted/duplicate entries rejected | VERIFIED -- strict sort + dedup checks in all parsers |
| Delayed-bankhash gating is strict | VERIFIED -- no finalization/vote without bankhash |
| Pending-slot retry is deterministic | VERIFIED -- both window_service and replay_stage |
| Lock failures never silent | VERIFIED -- explicit match/warn on all acquisitions |
| MCP control ingress bounded | VERIFIED -- 10,000 capacity, try_send with counters |
| McpExecutionOutput decode failures are hard errors | VERIFIED -- `InvalidMcpExecutionOutput` error |
| Cross-crate constants aligned | VERIFIED -- `mcp_constant_consistency.rs` tests |

### Wire Format Verification
| Check | Status |
|---|---|
| Discriminator 0x03 disjoint from ShredVariant (0x40-0xBF) | VERIFIED |
| Field offsets match layout (total 1232 bytes) | VERIFIED |
| Merkle domain separation: 0x00 leaf, 0x01 node | VERIFIED |
| Attestation signing domain: version\|\|slot\|\|relay_index\|\|entries_len\|\|entries | VERIFIED |
| Payload parser rejects trailing non-zero bytes | VERIFIED |
| Attestation entries sorted and deduplicated | VERIFIED |
| ConsensusMeta V1 = 41 bytes, rejects unknown version/truncated/trailing | VERIFIED |
| Reed-Solomon 40+160=200, recovery from any 40 | VERIFIED |
| Fragment overhead 45 bytes, MAX_FRAGMENT_DATA 1187 | VERIFIED |
| Fragment reassembly SHA-256 hash verified | VERIFIED |

### Vote Gate (7 checks)
| Check | Status |
|---|---|
| Leader signature + index | VERIFIED |
| Delayed bankhash availability + match | VERIFIED |
| Relay/proposer sig filtering (drop empty-after-filter) | VERIFIED |
| Global relay threshold >= 120 | VERIFIED |
| Proposer equivocation exclusion | VERIFIED |
| Local shred availability >= 40 per included proposer | VERIFIED |
| Non-consuming, idempotent lookups | VERIFIED |

### Two-Phase Fee Execution
| Check | Status |
|---|---|
| Gated on block_verification=true AND feature active | VERIFIED |
| Phase A: base_fee; nonce: base_fee + nonce_min_rent | VERIFIED |
| Phase B: skip_fee_collection=true, no re-deduction | VERIFIED |
| Lock-retry skip: only AccountInUse/AlreadyProcessed under MCP | VERIFIED |
| Non-lock errors remain slot-fatal | VERIFIED |
| McpExecutionOutput: no fallback to legacy entries | VERIFIED |

### B2 Ordering Policy
| Check | Status |
|---|---|
| MCP-format before legacy | VERIFIED |
| Within class: ordering_fee descending | VERIFIED |
| Ties: signature ascending | VERIFIED |
| Per-proposer dedup, then concat by proposer_index, then B2 | VERIFIED |

---

## Issue Summary

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 0 | -- |
| HIGH | 1 | H-001 |
| MEDIUM | 8 | M-001 through M-008 |
| LOW | 9 | L-001 through L-009 |

**Verdict:** No production MCP-v1 consensus-safety blockers found. H-001 and M-001 are the most actionable findings for immediate hardening. All other items are defense-in-depth improvements or plan documentation gaps.

## Update (2026-02-26): test_plan.md gap closure and execution status

### Implemented in this pass

- Added and passing:
  - `ledger/src/leader_schedule_utils.rs::test_mcp_schedule_vote_keyed_vs_identity_keyed`
  - `ledger/src/mcp_erasure.rs::test_decode_payload_rejects_oversized_payload_len`
  - `turbine/src/retransmit_stage.rs::test_get_mcp_slot_and_shred_id`
  - `turbine/src/broadcast_stage/standard_broadcast_run.rs::test_targeted_proposer_routing`
  - `core/src/block_creation_loop.rs::test_record_with_optional_bankless_rejects_without_working_bank`
  - `core/src/banking_stage/consumer.rs::test_should_use_bankless_recording_conditions`
  - `core/src/banking_stage/consumer.rs::test_record_transactions_bankless_produces_synthetic_commit`
  - `core/src/forwarding_stage.rs::test_vote_forwarding_uses_leader_schedule_not_proposer_schedule`
  - `core/src/window_service.rs::test_maybe_finalize_skips_non_leader_slot`
  - `core/src/window_service.rs::test_maybe_finalize_consensus_block_requires_block_id`
  - `ledger/src/blockstore_processor.rs::test_process_bank_0_mcp_active_seeds_empty_execution_output`

### Remaining blockers (local-cluster)

- `test_1_node_alpenglow` no longer fails startup after seeding slot-0 empty MCP execution output; however, in bounded runs it did not finish within 120s (timeout), so end-to-end completion is still unresolved.
- `test_local_cluster_mcp_produces_blockstore_artifacts` currently unstable in bounded runs:
  - repeated `BlockComponentProcessor(MissingBlockFooter)`
  - repeated slot-meta churn `consumed: 128 > meta.last_index + 1: Some(96)`
  - repeated turbine out-of-range index errors against `slot.last_index`

### Assessment

- The newly added unit-level coverage from `test_plan.md` is in place and passing.
- The remaining failures are end-to-end local-cluster/runtime integration blockers, not missing unit tests.
- These blockers should remain tracked as production blockers until the two local-cluster tests pass consistently.
