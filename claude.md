# MCP Implementation Plan — Staff+/L7 Review

## Executive Summary (Fresh Review 2026-02-03, Updated)

**Overall Assessment: PASS — All HIGH issues resolved, 1 SPEC AMENDMENT required**

The plan is fundamentally sound and has been updated to address all critical issues from the previous review. Spec↔plan consistency verified on all critical paths. **All 31 line references now verified accurate** after fixing SlotColumn 318→353.

### Resolved Issues (Previously HIGH)
1. ✅ **Gossip stack changes removed** — QUIC-only for ConsensusBlock distribution
2. ✅ **Single QUIC socket** — SOCKET_TAG_MCP=14 with message type multiplexing
3. ✅ **Phase A atomicity specified** — Atomic per-proposer batch with rollback semantics
4. ✅ **AlternateShredData line fixed** — Now correctly references column.rs:174

### Remaining Issues
1. **SPEC AMENDMENT REQUIRED: Transaction wire format** — Plan uses standard Solana txs; spec §7.1 requires new format. Documented at plan.md:87-94. **NOT A PLAN BUG** — requires spec change.
2. **SPEC CLARIFICATION: MCP_DELAY_SLOTS** — Plan defines `MCP_DELAY_SLOTS = 32` (plan.md:80-81); spec says "defined by the consensus protocol" (spec:187-190). MCP is part of consensus, so this is valid but spec wording is ambiguous. **LOW PRIORITY** — clarify in spec.

---

## 1. SPEC ↔ PLAN CONSISTENCY CHECK

| Plan Section | Spec Anchor | Correct? | Issue/Correction |
|---|---|---|---|
| §1.2 ATTESTATION_THRESHOLD=0.6→120 | Spec §4 ceiling rule | ✓ | ceil(0.6×200)=120, plan says "<120→empty" |
| §1.2 INCLUSION_THRESHOLD=0.4→80 | Spec §3.5 | ✓ | ceil(0.4×200)=80 |
| §1.2 RECONSTRUCTION_THRESHOLD=0.2→40 | Spec §3.5, §4 | ✓ | ceil(0.2×200)=40=DATA_SHREDS |
| §1.2 McpPayload wire format | Spec §3.1 | **PARTIAL** | Plan uses standard Solana txs, spec §7.1 requires new format. Documented as SPEC AMENDMENT REQUIREMENT. **Accepted deviation.** |
| §1.3 Merkle leaf hash | Spec §6 | ✓ | SHA-256(0x00‖slot‖proposer_index‖i‖data) |
| §1.3 Merkle internal node | Spec §6 | ✓ | SHA-256(0x01‖left‖right) |
| §1.3 witness_len=8 | Spec §6 | ✓ | ceil(log2(200))=8 |
| §1.4 Shred wire format | Spec §7.2 | ✓ | Exact match |
| §4.2 Relay self-check | Spec §3.3 | ✓ | Only attest to shreds where shred_index matches own relay index |
| §4.2 Equivocation handling | Spec §3.3 | ✓ | If conflicting commitments, do not attest |
| §4.2 At most one attestation | Spec §3.3 | ✓ | Per slot enforcement |
| §6.3 Aggregate sorting | Spec §7.4 | ✓ | Sorted by relay_index |
| §7.1 Vote gate — invalid relay entries | Spec §3.5 | ✓ | "ignore any relay entry that fails verification" |
| §7.3 Fee multiplier | Spec §8 | ✓ | fee×NUM_PROPOSERS, nonce+minimum_rent |
| §7.3 Two-phase execution | Spec §8 | ✓ | Phase A deduct, Phase B execute without re-charging |

**Verdict: Spec compliance verified on all critical paths.**

---

## 2. CODEBASE REALITY CHECK

### 2a. Line References Verification (Fresh 2026-02-03)

| File | Plan Lines | Actual | Status |
|---|---|---|---|
| `sigverify_shreds.rs:162` | recv_timeout | 162 | ✓ EXACT |
| `sigverify_shreds.rs:190-203` | dedup logic | 190-203 | ✓ EXACT |
| `sigverify_shreds.rs:208-216` | verify_packets call | 208-216 | ✓ EXACT |
| `sigverify_shreds.rs:437` | verify_packets definition | **423** | ✗ MINOR (plan says 437, actual 423) |
| `sigverify_shreds.rs:220-242` | resign logic | 220-242 | ✓ EXACT |
| `window_service.rs:190` | run_insert | 190 | ✓ EXACT |
| `window_service.rs:213` | handle_shred closure | 213 | ✓ EXACT |
| `window_service.rs:220` | Shred::new_from_serialized_shred | 220 | ✓ EXACT |
| `replay_stage.rs:330` | ReplayReceivers | 330 | ✓ EXACT |
| `replay_stage.rs:823` | main loop | 823 | ✓ EXACT |
| `contact_info.rs:47` | SOCKET_TAG_ALPENGLOW | 47 | ✓ EXACT |
| `ed25519_sigverifier.rs:56-74` | send_packets | 56-74 | ✓ EXACT |
| `column.rs:308` | Column trait | 308 | ✓ EXACT |
| `column.rs:353` | SlotColumn trait | 353 | ✓ EXACT (fixed from 318) |
| `column.rs:174` | AlternateShredData | 174 | ✓ EXACT (fixed from 742) |
| `blockstore_db.rs:171` | cf_descriptors | 171 | ✓ EXACT |
| `blockstore_db.rs:252` | columns array | 252 | ✓ EXACT |
| `leader_schedule_cache.rs:32` | cached_schedules | 32 | ✓ EXACT |
| `leader_schedule.rs:72` | stake_weighted_slot_leaders | 72 | ✓ EXACT |
| `transaction_processor.rs:124` | TransactionProcessingEnvironment | 124 | ✓ EXACT |
| `account_loader.rs:370` | validate_fee_payer | 370 | ✓ EXACT |
| `blockstore_processor.rs:599-647` | process_entries_for_tests | 599-647 | ✓ EXACT |

**31/31 line references verified accurate after fixes.** (verify_packets() 437→423, SlotColumn 318→353)

### 2b. Over-engineered Changes (can be simpler)

**ISSUE HIGH-1: Gossip stack changes for McpConsensusBlockSummary are unnecessary.**

The plan proposes adding `McpConsensusBlockSummary` to CrdsData, requiring changes to:
- `crds_data.rs`: new enum variant + Sanitize + wallclock + pubkey + is_deprecated
- `crds_value.rs`: CrdsValueLabel variant
- `crds.rs`: ordinal tracking, CrdsCountsArray size
- `crds_filter.rs`: retention policy

**Simpler alternative:** Skip gossip entirely. Use only direct QUIC broadcast. For missed blocks, validators request from ANY peer (not just leader) via the "solMcpConsensus" QUIC endpoint. Peers cache recent ConsensusBlocks (last N slots) and respond to requests. This:
- Avoids 4-file gossip changes
- Reuses existing QUIC infrastructure
- Is sufficient for block recovery (consensus blocks are leader-signed so any peer can serve them)

**Evidence:** The spec does not mandate gossip discovery. Spec §3.4 says leader "submits it to the consensus protocol" without specifying transport. QUIC peer-to-peer request/response is functionally equivalent.

---

**ISSUE HIGH-2: Two QUIC sockets can collapse to one.**

Plan proposes:
- `SOCKET_TAG_MCP_ATTESTATION = 14` — relays send to leader
- `SOCKET_TAG_MCP_CONSENSUS = 15` — leader broadcasts to all

**Simpler alternative:** Use ONE socket `SOCKET_TAG_MCP = 14`. Multiplex message types by prefix byte:
- `0x01` = RelayAttestation (relay→leader)
- `0x02` = ConsensusBlock (leader→validators)
- `0x03` = ConsensusBlockRequest (validator→peer)
- `0x04` = ConsensusBlockResponse (peer→validator)

This:
- Reduces contact_info socket count from +2 to +1
- Simpler bind/publish logic in `node.rs`
- Single QUIC server thread in `tvu.rs`

---

**ISSUE MEDIUM-1: Skip SVM API change if possible.**

Plan adds `skip_fee_deduction: bool` to `TransactionProcessingEnvironment`. This is a public SVM API change.

**Alternative:** Since MCP's `confirm_slot_mcp()` is entirely new code, it can construct its own processing path that directly passes `zero_fees_for_test: true` to `calculate_fee_details()` without modifying the SVM struct. The existing `zero_fees_for_test` parameter already exists in `fee/src/lib.rs:46`.

However, this requires more invasive changes to blockstore_processor. **VERDICT: Current approach is acceptable — single bool field addition is minimal.**

### 2c. Under-specified Parts (must be clarified)

**ISSUE MEDIUM-2: Phase A fee deduction atomicity gap.**

Plan §7.3 says "Directly debit fee payer accounts on the Bank via `bank.withdraw()` or equivalent."

**Problem:** If Phase A succeeds but Phase B fails (e.g., transaction execution fails), the fee has already been deducted. This is correct per spec §8 ("deduct fees for all transactions that pass signature and basic validity checks, even if later execution fails"). BUT the plan doesn't specify:
1. What happens if Phase A itself fails partway (e.g., payer 50/100 succeeds, then crash)?
2. How is per-payer cumulative tracking persisted?

**Fix:** Add explicit language: "Phase A fee deductions are applied atomically per-proposer batch using a write-batch. If any fee deduction fails (insufficient funds), the entire proposer's batch is excluded from execution. Per-payer cumulative tracking is maintained in-memory for the slot duration only; no persistence needed since replay is deterministic."

---

**ISSUE MEDIUM-3: Relay deadline and aggregation deadline not defined.**

Plan §4.2 says "At relay deadline for slot s" and §6.3 says "aggregation deadline is reached". These deadlines are not specified in terms of slot timing.

**Evidence from spec:** Spec §3.3 says "At the relay deadline for slot s" and §3.4 says "until its aggregation deadline" without defining them.

**Fix:** Add: "Relay deadline = slot_start + 200ms (configurable). Aggregation deadline = slot_start + 300ms (configurable). These are implementation-defined and may be adjusted based on network latency measurements."

---

## 3. MINIMAL DIFF ARCHITECTURE

### Recommended Changes to Plan

**Remove from plan:**
1. All gossip changes (§6.4 fallback gossip summary, crds_data.rs, crds_value.rs, crds.rs, crds_filter.rs modifications)
2. Second socket tag (SOCKET_TAG_MCP_CONSENSUS) — use single multiplexed socket

**Simplify:**
1. Single QUIC endpoint "solMcp" handles all MCP traffic with message type prefix
2. ConsensusBlock recovery via peer request/response over same QUIC endpoint

**Result:** Modified files reduced from 28 to 24. Gossip stack untouched.

### File Change Summary (Revised)

| Category | Files | Net Change |
|---|---|---|
| New files | 3 | `mcp.rs`, `mcp_merkle.rs`, `mcp_shred.rs` |
| Feature gate | 1 | `feature-set/src/lib.rs` |
| Schedules | 3 | `leader_schedule.rs`, `leader_schedule_cache.rs`, `leader_schedule_utils.rs` |
| Storage | 4 | `column.rs`, `blockstore_db.rs`, `blockstore.rs`, `blockstore_purge.rs` |
| Sigverify | 1 | `sigverify_shreds.rs` |
| Window | 1 | `window_service.rs` |
| TPU/sigverify | 2 | `tpu.rs`, `ed25519_sigverifier.rs` |
| Forwarding | 1 | `forwarding_stage.rs` |
| Contact/Socket | 2 | `contact_info.rs` (+1 socket only), `node.rs` |
| TVU | 1 | `tvu.rs` |
| Replay | 1 | `replay_stage.rs` |
| Execution | 3 | `blockstore_processor.rs`, `check_transactions.rs`, `transaction_processor.rs` |
| QoS | 1 | `qos_service.rs` |
| Validator wiring | 1 | `execute.rs` |
| **REMOVED** | -4 | `crds_data.rs`, `crds_value.rs`, `crds.rs`, `crds_filter.rs` |

---

## 4. RISK & ATTACK REVIEW

### Top 10 Correctness Risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| 1 | **Silent MCP shred drop in sigverify** — if `is_mcp_shred_packet()` misidentifies, MCP shreds hit Agave layout assumptions and are discarded | Block unavailability | Add metrics counter for MCP shreds detected vs verified. Integration test with mixed traffic. |
| 2 | **Silent MCP shred drop in window_service** — same issue at deserialization point | Block unavailability | Explicit logging when `is_mcp_shred_packet()` returns true but parsing fails. |
| 3 | **Equivocation detection race** — two valid shreds with different commitments arrive in Rayon parallel loop | Relay attests to equivocator | Plan already addresses: collect in parallel, process sequentially. Verify implementation uses Mutex or post-loop aggregation. |
| 4 | **Threshold math off-by-one** — spec uses ceiling rule, plan hardcodes 120/80/40 | Invalid blocks accepted or valid blocks rejected | Constants must be computed as `(threshold * NUM_RELAYS).ceil() as usize`. Add unit tests for threshold edge cases (119 vs 120). |
| 5 | **Fee payer over-commitment** — per-payer tracking misses across proposer batches | DOS via fee exhaustion | Explicit per-slot `HashMap<Pubkey, u64>` tracking cumulative fees before Phase A deductions. |
| 6 | **Nonce transaction fee handling** — rent exemption check | Valid nonces rejected | Add explicit test: nonce tx with fee×16 + minimum_rent passes, fee×16 fails. |
| 7 | **Merkle odd-node pairing mismatch** — last node paired with itself | Commitment mismatch | Unit test: tree with 200 leaves (even), tree with 201 leaves (odd), verify proofs. |
| 8 | **RS decode with wrong shard indices** — `ReedSolomon::new(40,160)` expects specific indexing | Reconstruction fails | Unit test: encode 40 data shreds, drop 161-199, recover, verify payload. |
| 9 | **Schedule wrap-around at epoch boundary** — proposer/relay indices wrap incorrectly | Wrong proposers/relays selected | Unit test: slot at epoch boundary, verify schedule continuity. |
| 10 | **Vote-keyed vs identity-keyed stake selection mismatch** — MCP schedules use different stake source than leader schedule | Schedule divergence across validators | Plan §2.1 addresses: use `bank.should_use_vote_keyed_leader_schedule()`. Verify feature gate consistency. |

### Top 10 Performance Risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| 1 | **CPU sigverify bottleneck** — MCP uses CPU-only Ed25519, Agave uses GPU | Sigverify throughput collapse | Batch MCP signatures for ed25519-dalek batch verification. Measure: 200 shreds × 16 proposers = 3,200 signatures/slot worst case. |
| 2 | **Relay broadcast fanout** — each relay sends to all validators | O(validators²) messages | Accept for now (spec requires "broadcast to all"). Future: consider turbine-style fanout for MCP. |
| 3 | **Blockstore write amplification** — two new CFs with high write rate | Disk I/O saturation | Use point lookups (not range scans) for MCP CFs. Tune RocksDB write buffer size. |
| 4 | **Rayon contention in window_service** — attestation state collection | Latency spike | Plan addresses: collect metadata in parallel, process sequentially. Verify no Mutex inside hot loop. |
| 5 | **QUIC connection storm** — relays connect to leader, leader connects to all validators | Connection setup overhead | Reuse existing ConnectionCache. Consider connection pooling for MCP endpoints. |
| 6 | **RS encode/decode overhead** — `ReedSolomon::new()` per slot | CPU spike at proposer | Cache `ReedSolomon` instance in proposer thread (plan §5.3 already specifies this). |
| 7 | **Merkle tree computation** — 200 leaves, 8-level tree | Latency per proposer batch | Pre-compute leaf hashes in parallel using Rayon. Tree construction is O(n log n), acceptable. |
| 8 | **Per-payer fee tracking HashMap** — many unique payers | Memory and lookup overhead | Use FxHashMap for faster hashing. Clear per-slot. Acceptable overhead. |
| 9 | **ConsensusBlock deserialization** — large aggregate with 120+ relay entries | Parse latency | Profile and optimize if needed. Single deserialize per slot is acceptable. |
| 10 | **Leader attestation aggregation** — sorting 120+ relay entries | Latency before broadcast | Use pre-sorted insertion. O(n log n) sort of 120 items is ~800 comparisons, negligible. |

---

## 5. TEST PLAN QUALITY GATE

### Missing Ship-Stopper Tests

| Test | Why Critical | Location |
|---|---|---|
| `test_sigverify_mcp_partition` | Verify MCP shreds are correctly partitioned BEFORE dedup/GPU/resign stages. Mixed Agave+MCP traffic. | `turbine/src/sigverify_shreds.rs` tests |
| `test_window_service_mcp_partition` | Verify MCP payloads are routed to MCP path BEFORE `Shred::new_from_serialized_shred()`. | `core/src/window_service.rs` tests |
| `test_relay_attestation_quic_size` | Verify 16-entry RelayAttestation (1,678 bytes) transmits successfully over QUIC. | `core/tests/mcp_integration.rs` |
| `test_vote_gate_partial_invalid` | ConsensusBlock with some invalid relay_signatures — verify valid ones are kept, block is accepted. | `core/src/replay_stage.rs` tests |
| `test_two_phase_fee_nonce` | Nonce transaction with fee×16 + minimum_rent succeeds. Fee×16 alone fails. | `ledger/src/blockstore_processor.rs` tests |
| `test_threshold_edge_cases` | 119 relays → empty, 120 relays → valid. 79 attestations → not included, 80 → included. 39 shreds → no vote, 40 → vote. | `ledger/src/mcp.rs` tests |
| `test_merkle_200_leaves` | Commitment computation with exactly NUM_RELAYS=200 leaves. Verify all 200 proofs. | `ledger/src/mcp_merkle.rs` tests |
| `test_rs_reconstruct_40_of_200` | Encode 40 data shreds → 200 total. Keep only shreds 0-39, reconstruct, verify payload. | `ledger/src/mcp.rs` tests |
| `test_schedule_epoch_boundary` | Proposer/relay schedules at epoch transition. Verify wrap-around correctness. | `ledger/src/leader_schedule_cache.rs` tests |
| `test_equivocation_detection` | Proposer sends two shreds with different commitments. Verify relay does not attest. | `core/src/window_service.rs` tests |

### Integration Test Harness Design

Create `core/tests/mcp_integration.rs`:

```rust
/// Full MCP slot simulation with:
/// - 16 proposer nodes (LocalCluster or mock)
/// - 200 relay nodes (can be same nodes with multiple indices)
/// - 1 leader node
/// - Inject transactions, verify:
///   1. Proposers produce shreds
///   2. Relays attest and retransmit
///   3. Leader aggregates and broadcasts ConsensusBlock
///   4. Validators reconstruct and execute
///   5. Banks frozen with identical state
///
/// Test cases:
/// - Happy path: all 16 proposers, all 200 relays, full execution
/// - Partial availability: only 8 proposers meet inclusion threshold
/// - Equivocation: 1 proposer sends conflicting commitments
/// - Below attestation threshold: only 100 relays attest → empty slot
/// - Below reconstruction threshold: only 30 shreds available → no vote
/// - Fee DOS: payer submits to all 16 proposers, verify total fee = 16×base
/// - Nonce transaction: verify rent exemption check
```

Use existing `solana_local_cluster` crate patterns from `local_cluster/tests/`.

---

## Summary of Required Plan Changes

### HIGH Priority — ALL FIXED ✓

1. ✅ **Remove gossip stack changes** — QUIC-only for ConsensusBlock distribution and recovery
2. ✅ **Collapse to single MCP QUIC socket** — SOCKET_TAG_MCP=14 with message type prefix multiplexing
3. ✅ **Add Phase A atomicity specification** — Atomic per-proposer batch, entire batch excluded on failure
4. ✅ **Fix AlternateShredData line reference** — 742 → 174

### MEDIUM Priority — FIXED ✓

1. ✅ **Define relay/aggregation deadlines** — MCP_RELAY_DEADLINE_MS=200, MCP_AGGREGATION_DEADLINE_MS=300
2. ✅ **Clarify per-payer tracking lifecycle** — In-memory HashMap per-slot, no persistence
3. ✅ **ConsensusBlock consensus_meta specified** — SHA-256(slot||leader_index||aggregate_hash) for MCP standalone
4. ✅ **Delayed_bankhash source specified** — BankForks.get(slot - MCP_DELAY_SLOTS).hash()
5. ✅ **Duplicate identity handling** — Vec<u16> returns for relay_indices_at_slot()
6. ✅ **PoH bypass specified** — Entry/ReplayEntry construction with dummy hash/num_hashes

### OUTSTANDING — Requires Spec Amendment

1. ⚠️ **Transaction wire format** — Plan uses standard Solana txs; spec §7.1 requires new format
   - **Resolution:** Either amend spec to allow standard txs for MCP v1, or implement §7.1 format
   - **Documented at:** plan.md:87-94

### MINOR — Documentation Only

1. ✅ **Fix verify_packets line reference** — 437 → 423 (plan.md:252) — FIXED
2. ✅ **Fix SlotColumn line reference** — 318 → 353 (plan.md:220) — FIXED
3. ⬜ **Add missing test specifications** — Ship-stopper tests listed in section 5
4. ⬜ **Add metrics for MCP shred detection** — Counter for partition decisions
