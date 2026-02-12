# MCP Adversarial Audit — Wiring, Parallel Systems, Semantic Bugs (Master)

Date: 2026-02-12
Branch: `master`
Perspective: Principal engineer + security researcher, assuming adversarial/lazy developer.
Scope: **Bad wiring, parallel-system anti-patterns, semantic bugs, dead code.** Builds on prior reachability audit.

---

## Executive Summary

All 5 prior addendum "wiring gaps" remain **REFUTED** (code is live). The **1 critical semantic bug** found in the prior round (relay attestation signature invalidation) is now **FIXED** with two new unit tests. The dispatch-abort bug is also **FIXED**. The remaining medium-severity semantics from the prior pass are now either **FIXED** (fee reservation parity, dispatch drop observability, replay TOCTOU) or **DISMISSED as non-reproducible** in production ingress (malformed `consensus_meta` deferral). This audit still tracks **1 parallel-system anti-pattern** worth evaluating (control messaging; sigverify GPU and legacy PoH dismissed as irrelevant post-Alpenglow) and a significantly **expanded dead-code inventory** (27+ dead public functions, 1 dead file).

### Verdicts

| Area | Status |
|------|--------|
| Local-cluster e2e test | **PASS** |
| Parallel-system anti-patterns | **1 FOUND** (control messaging); 2 dismissed (sigverify GPU deprecated, legacy PoH N/A post-Alpenglow) |
| Critical semantic bugs | **0** — relay attestation entry filtering bug **FIXED** (2 new unit tests) |
| Medium semantic bugs | **0 OPEN** — 4 prior items fixed, 1 prior item dismissed as non-repro on production ingress |
| Dead code | **EXPANDED** (27+ dead pub fns, 1 dead file: `mcp_shredder.rs`) |
| Feature gate coverage | **PASS** (all production paths gated; 3 low-severity defense-in-depth gaps) |

---

## 1. Parallel-System Anti-Pattern Audit

The user identified that MCP repair was originally built as a parallel admin-RPC-only system instead of being wired into the existing repair loop. This has been **fixed** (`identify_mcp_repairs` at `repair_service.rs:615` now called from the main loop at line 856). This audit searched for other instances of the same anti-pattern.

### Areas That EXTEND Existing Systems (Good)

| Area | How It Extends |
|------|----------------|
| Retransmit/turbine | MCP shreds flow through existing turbine fanout tree via `get_mcp_shred_id()` |
| Gossip/cluster info | No MCP-specific gossip; proposer/relay schedules derived from on-chain stake |
| Banking stage/scheduler | `McpFeePayerTracker` threaded through existing scheduler paths |
| Leader schedule | New `cached_mcp_proposer_schedules`/`cached_mcp_relay_schedules` in existing `LeaderScheduleCache` |
| Vote processing | `mcp_vote_gate` is an additional predicate in existing ReplayStage vote flow |
| Transaction forwarding | `ForwardAddressGetter` extended for MCP proposer fanout |
| Metrics | Standard `inc_new_counter_error!` and `datapoint_info!` macros throughout |
| Blockstore | New column families for genuinely new data types (MCP shreds, attestations, execution output) |
| Repair | **FIXED** — `identify_mcp_repairs` wired into main repair loop (200ms scan interval, 64-slot lookback) |
| Fee calculation | `apply_mcp_fee_component_values` adds MCP fees on top of existing `FeeDetails` |
| Block production | Bank initialized normally via `set_bank(tpu_bank)` at `block_creation_loop.rs:728`; scheduler ingests transactions normally |

### Dismissed: MCP Sigverify Bypass

**Files:** `turbine/src/sigverify_shreds.rs:182-327`

MCP shreds bypass GPU-batched sigverify and use CPU verification in window_service. **Dismissed** — the GPU sigverify path is being deprecated; CPUs are fast enough. MCP's CPU-based per-shred verification is the forward-looking approach.

### Dismissed: PoH `record_bankless` Path

**Files:** `poh/src/poh_recorder.rs:441-537`, `core/src/block_creation_loop.rs:443-465`

MCP introduces `record_bankless` as a fallback for records arriving after bank completion. **Dismissed** — MCP only activates after Alpenglow, so the legacy PoH path is not relevant. `record_bankless` is the Alpenglow-native recording path.

### Anti-Pattern: MCP Control-Message Channel

**Files:** `core/src/shred_fetch_stage.rs:448-489`, `core/src/window_service.rs:889-1060`, `core/src/mcp_relay_submit.rs:26-336`

MCP introduces a custom control-message framing protocol on the QUIC TVU endpoint. Incoming datagrams are inspected for MCP control-message type bytes (`0x01` relay attestation, `0x02` consensus block) and routed via a dedicated `mcp_control_message_sender` channel.

**Why it exists:** Relay attestations and consensus blocks are structurally incompatible with the shred pipeline — different sizes (consensus blocks can exceed `PACKET_DATA_SIZE`), different signature schemes, different storage.

**Risk:** Separate framing, dispatch, and retry logic (`try_send_mcp_control_frame`, `try_send_dispatch_frame_with_retry`). Three message delivery systems now coexist: gossip, turbine shreds, MCP control messages.

**Recommendation:** Acceptable given structural differences. Consider deduplicating the `MCP_CONTROL_MSG_CONSENSUS_BLOCK` constant (duplicated at `shred_fetch_stage.rs:47` and `window_service.rs:68`).

---

## 2. Critical Semantic Bug: Relay Attestation Signature Invalidation — FIXED

**Severity: CRITICAL → FIXED**
**Files:** `core/src/window_service.rs` (ingestion + consensus block building)

### The Bug (Prior State)

When a validator ingested a relay attestation, `valid_entries()` at line 946 filtered out entries where the proposer pubkey was unknown or the proposer signature didn't verify. The filtered entries **replaced** the original entries, but the attestation was stored with the **original** `relay_signature` (computed over unfiltered entries). Downstream `verify_relay_signature` would fail because signing bytes computed from filtered entries didn't match.

### The Fix (Current Working Tree)

**Ingestion path (line 942-948):** No longer calls `valid_entries()`. Stores the raw `payload` bytes directly via `blockstore.put_mcp_relay_attestation(slot, relay_index, payload)`. The relay signature was already verified against the relay's pubkey at line 938. Proposer-level validation is correctly deferred.

**Consensus block building (lines 248-267):** `valid_entries()` is now used ONLY as an `is_empty()` skip check. If at least one entry is valid, ALL `attestation.entries` are iterated into `AggregateRelayEntry` (not just the filtered ones). The original `relay_signature` is stored alongside the full entry list, preserving signature validity.

### Verification

Two new unit tests added:
- `test_ingest_mcp_relay_attestation_preserves_signed_entry_list` — verifies stored attestation has all entries and relay signature still verifies
- `test_maybe_finalize_consensus_block_keeps_original_relay_signed_entries` — verifies consensus block building preserves full entry list

---

## 3. Medium-Severity Semantic Issues

### 3a. Admission vs Execution Fee Formula Mismatch — FIXED

**Severity: MEDIUM → FIXED**
**Files:** `core/src/banking_stage/consumer.rs`, `runtime/src/bank/check_transactions.rs`

Admission now reserves and validates against `effective_fee = base_fee + inclusion_fee + ordering_fee` before multiplying by `NUM_PROPOSERS`. This matches execution-side fee composition.

### 3b. Silent Transaction Drops in Dispatch — FIXED

**Severity: MEDIUM → FIXED**
**File:** `turbine/src/broadcast_stage/standard_broadcast_run.rs`

Fee-related non-insert outcomes now emit explicit counters:
- `mcp-proposer-dispatch-fee-reservation-overflow`
- `mcp-proposer-dispatch-insufficient-funds`

### 3c. Dispatch Abort on `build_shred_messages` Error — FIXED

**Severity: MEDIUM → FIXED**
**File:** `turbine/src/broadcast_stage/standard_broadcast_run.rs:1052`

Changed `return` to `continue`. Error in one proposer's shred message build no longer aborts dispatch for remaining proposer indices.

### 3d. TOCTOU Race in Replay Per-Component Blockstore Query — FIXED

**Severity: MEDIUM → FIXED**
**File:** `ledger/src/blockstore_processor.rs`

`confirm_slot()` now snapshots `McpExecutionOutput` once per slot-replay invocation and passes the snapshot through all component confirms. Entry batches within the same slot no longer observe mixed transaction sources.

### 3e. Malformed `consensus_meta` Indefinite Deferral — DISMISSED (non-repro on ingress)

**Severity: MEDIUM → DISMISSED**
**Files:** `core/src/window_service.rs`, `core/src/replay_stage.rs`

Production ingress drops consensus blocks whose `consensus_meta.len() != 32` before cache insertion. Local finalization produces 32-byte sidecar bytes. The previously described malformed-sidecar deferral path is not reachable through normal ingest/finalize call paths.

---

## 4. Expanded Dead Code Inventory

### Dead File

| File | Status |
|------|--------|
| `ledger/src/mcp_shredder.rs` | **ALL functions dead.** Thin facade over `mcp_erasure` + `mcp_merkle`. Zero production callers. Production code imports `mcp_erasure` directly. Should be deleted. |

### Dead Public Functions (27+)

| Function | File | Notes |
|----------|------|-------|
| `order_batches_by_fee_desc` | `mcp_ordering.rs:23` | Test-only; production uses `order_batches_mcp_policy` |
| `McpRelayProcessor::stored_count` | `mcp_relay.rs:45` | Test-only |
| `calculate_fee_details_with_mcp` | `fee/src/lib.rs:71` | Dead convenience wrapper; production calls components separately |
| `apply_mcp_fee_components` | `fee/src/lib.rs:89` | Dead wrapper; divergent semantics from production path |
| `McpReconstructionState` (5 methods) | `mcp_reconstruction.rs:56-134` | Entire struct is test-only; production uses `reconstruct_payload` directly |
| `McpShred::verify` | `mcp_shred.rs:220` | Test-only; production calls `verify_signature` + `verify_witness` separately |
| `is_mcp_shred_packet` / `is_mcp_shred_packet_ref` | `mcp_shred.rs:96,100` | Zero non-test callers |
| `RelayAttestationV1::new_unsigned` | `mcp_relay_attestation.rs:54` | Test-only; production builds struct directly |
| `RelayAttestationV1::sign_relay` | `mcp_relay_attestation.rs:168` | Test-only; production signs via `signer.sign_message()` |
| `RelayAttestationV1::verify_proposer_signatures` | `mcp_relay_attestation.rs:182` | Test-only |
| `AggregateAttestation::filtered_valid_entries` | `mcp_aggregate_attestation.rs:248` | Internal only; called by `canonical_filtered` |
| `AggregateRelayEntry::sign` / `verify_relay_signature` | `mcp_aggregate_attestation.rs:345,356` | Test-only |
| `McpTransaction::from_bytes` | `mcp_transaction.rs:73` | Test-only; production uses `from_bytes_compat` |
| `witness_for_leaf` | `mcp_merkle.rs:73` | Test-only |
| `decode_payload` / `recover_data_shards` / `commitment_root` | `mcp_erasure.rs:113,57,130` | Only called from dead `mcp_shredder.rs` or tests |
| `concat_batches_by_proposer_index` | `mcp_ordering.rs:9` | Internal helper, no external callers |
| `encode_relay_attestation_frame` / `build_relay_attestation_dispatch` | `mcp_relay_submit.rs:224,256` | Internal only, no external callers |

### Dead Code Risk

`apply_mcp_fee_components` (fee/src/lib.rs:89) uses `ordering_fee().unwrap_or_default()` (defaults to 0) while the production path uses `ordering_fee_with_fallback()` (falls back to CU price). If anyone ever uses this dead function, fees will be silently different.

---

## 5. Feature Gate Coverage

All production MCP paths are properly gated on `mcp_protocol_v1`. Three low-severity defense-in-depth gaps:

| Location | Issue | Severity |
|----------|-------|----------|
| `shred_fetch_stage.rs:412` | MCP shred repair nonce bypass accepted without feature gate check | LOW |
| `shred_fetch_stage.rs:465-488` | MCP control messages forwarded without feature gate (downstream checks exist) | LOW |
| `retransmit_stage.rs:468` | MCP shred retransmit parsing without feature gate (upstream sigverify gates) | INFO |

---

## 6. Production Reachability — All Subsystems LIVE

Unchanged from prior audit. All major MCP production paths verified reachable:
- MCP shred ingestion → relay attestation → consensus block → vote gate → reconstruction → replay
- TPU admission → per-proposer dispatch → shredding → transmission
- Repair: serve side + automatic trigger in main repair loop

---

## 7. Integration Test — PASS

```
cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture
```

**Result: PASS** (59.82s, exit code 0). Verified in a 5-node cluster with equal stake: artifacts at slot 64, non-leader output at slot 67, consensus block at slot 76, decoded non-empty execution output (100 txs in this run), submitted signature found.

---

## 8. Prior Fixes — Still Intact

- B3 deferral 3-condition guard (replay_stage.rs:4030-4039): PASS
- BlockComponent decode disambiguation (block_component.rs:567-574): PASS
- `infer_is_entry_batch` fix (block_component.rs:509-512): PASS
- All 5 addendum claims: remain REFUTED

---

## 9. Applied Changes Audit

Key MCP hardening changes verified in this audit pass:

| File | Change | Verdict |
|------|--------|---------|
| `window_service.rs` | Attestation ingestion: store raw payload, no entry filtering | **CORRECT** — fixes critical bug |
| `window_service.rs` | Consensus block: `valid_entries()` as skip gate only, iterate all entries | **CORRECT** — preserves relay signature |
| `window_service.rs` | 2 new unit tests for attestation preservation | **CORRECT** — cover both paths |
| `consumer.rs` | MCP admission reservation uses effective fee (base + inclusion + ordering) | **CORRECT** — aligns admission with execution fee model |
| `standard_broadcast_run.rs` | Counters for reservation overflow / insufficient funds drops | **CORRECT** — removes silent fee-drop observability gap |
| `repair_service.rs` | `identify_mcp_repairs` wired into main loop at line 856 | **CORRECT** — automatic MCP repair |
| `standard_broadcast_run.rs` | `return` → `continue` on `build_shred_messages` error | **CORRECT** — fixes dispatch abort |
| `blockstore_processor.rs` | One-shot slot execution-output snapshot reused per component replay | **CORRECT** — removes replay TOCTOU source race |
| `replay_stage.rs` | Formatting changes only | **NO REGRESSION** |
| `block_component.rs` | Disambiguation hardening | **NO REGRESSION** |
| `blockstore.rs` | New `get_mcp_relay_attestations_for_slot`, `latest_mcp_relay_attestation_slots` | **CORRECT** — support repair scanning |
| `mcp_merkle.rs` | Domain-separation hardening | **NO REGRESSION** |
| `local_cluster.rs` | Expanded integration test assertions | **CORRECT** |

### Note on Repair Implementation

`identify_mcp_repairs` at line 689 uses `mcp::NUM_RELAYS` as the expected shred count per proposer per relay. This coupling is coincidentally correct today (each relay stores exactly `NUM_RELAYS` shreds) but is fragile — if the shred-per-relay count ever diverges from the relay count constant, repair will request wrong shred indices.

---

## Current Verdict

- Critical bugs: **0** (relay attestation signature invalidation **FIXED** + tested)
- Medium semantic issues: **0 OPEN** (fee mismatch, silent drops, TOCTOU fixed; malformed-sidecar deferral dismissed as non-repro on ingress)
- Parallel-system anti-patterns: **1** (control messaging); 2 dismissed (GPU deprecated, legacy PoH N/A)
- Dead code: **1 dead file** (`mcp_shredder.rs`), **27+ dead pub fns**
- Feature gate: **PASS** (3 low defense-in-depth gaps)
- Integration test: **PASS**
- Production reachability: **PASS**
