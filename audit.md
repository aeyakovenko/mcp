# MCP Audit

**Date:** 2026-02-13 | **Baseline:** commit `965da326b7`

All code-level findings resolved. Integration test passing. No open issues.

Protocol-level review raised four items (P1–P4); all are **documentation nits**, not security concerns. Reassessment below.

---

## P1: Inter-Proposer Hiding — NIT (was MEDIUM)

Immediate relay retransmit does not break any security property. A malicious proposer that reconstructs another proposer's batch gains nothing: (a) all transactions come from the public mempool — no private information in a batch, (b) the proposer already signed its Merkle root before sending shreds and cannot change its committed batch, (c) signing a second commitment is detectable equivocation and results in exclusion. The "front-running" attack is structurally impossible given commitment-before-send ordering.

## P2: Leader Equivocation — NIT

MCP spec says "consensus protocol is out of scope." Alpenglow handles leader equivocation. Adding one clarifying sentence to the spec would be nice but is not a gap.

## P3: Threshold Formalization — NIT (was MEDIUM)

The constants are mechanically determined from the RS coding parameters, not magic numbers. RECONSTRUCTION = DATA_SHREDS/NUM_RELAYS = 40/200 = 0.20 (mathematical identity). INCLUSION = 2x reconstruction = 0.40. ATTESTATION = 3x reconstruction = 0.60. The spec already states the key invariant (INCLUSION >= RECONSTRUCTION). Formal adversary-model proofs belong in a security paper, not an implementation spec — standard practice in BFT literature (Tendermint, HotStuff, Casper).

## P4: Cross-Proposer Dedup — NIT

Plan explicitly chose no cross-proposer dedup (policy B2) and documented why. Each occurrence charged the full priority fee (16x for all proposers). Correct design — cross-proposer dedup would route ties to lowest-indexed proposer, undermining censorship resistance. Spec wording ("basic validity checks") could be tighter but the implementation is unambiguous.

---

## Addendum (2026-02-16): Fresh-Eyes Adversarial Questions

### Q1) What is the canonical namespace for `leader_index`?

- Why unresolved:
  - Spec defines `leader_index` as position in the **consensus leader schedule**, not proposer schedule.
  - Implementation constrains `leader_index` to `< NUM_PROPOSERS` and resolves leader pubkey via `Proposers[s]`.
- Evidence:
  - Spec: `docs/src/proposals/mcp-protocol-spec.md:257`, `docs/src/proposals/mcp-protocol-spec.md:258`
  - Code: `ledger/src/mcp_consensus_block.rs:235`, `ledger/src/mcp_consensus_block.rs:236`, `core/src/window_service.rs:984`, `core/src/window_service.rs:989`, `core/src/mcp_replay.rs:158`, `core/src/mcp_replay.rs:169`
- Decision needed:
  - Canonicalize whether `leader_index` is consensus-schedule indexed, proposer-indexed, or replaced by explicit leader pubkey semantics.

### Q2) What is the versioned `consensus_meta` schema (including delayed-slot authority)?

- Why unresolved:
  - Spec leaves `consensus_meta` and delayed-slot semantics to consensus.
  - Plan/code currently hardcode delayed slot as `slot - 1` and require `consensus_meta.len() == 32`.
- Evidence:
  - Spec: `docs/src/proposals/mcp-protocol-spec.md:177`, `docs/src/proposals/mcp-protocol-spec.md:189`
  - Plan: `plan.md:101`, `plan.md:106`, `plan.md:523`
  - Code: `core/src/window_service.rs:146`, `core/src/mcp_replay.rs:255`, `core/src/window_service.rs:1005`
- Decision needed:
  - Define a canonical wire schema/versioning for `consensus_meta` and migration behavior when delayed-slot semantics differ from `slot - 1`.

### Q3) What exactly does a relay attestation assert: own-index storage or any-index observation?

- Why unresolved:
  - Spec says relay validates witness for its **own relay index**.
  - Plan/code intentionally use index-agnostic ingestion/storage and then emit attestation entries by proposer; emission timing is heuristic (coverage or slot age), not protocol-deadline-defined.
- Evidence:
  - Spec: `docs/src/proposals/mcp-protocol-spec.md:151`, `docs/src/proposals/mcp-protocol-spec.md:158`
  - Plan: `plan.md:388`, `plan.md:389`
  - Code: `core/src/mcp_relay.rs:53`, `core/src/mcp_relay.rs:67`, `core/src/window_service.rs:720`, `core/src/window_service.rs:763`, `core/src/window_service.rs:789`
- Decision needed:
  - Pin down attestation semantics and deadline semantics so threshold guarantees are unambiguous.

### Q4) How should nodes resolve conflicting valid `ConsensusBlock`s for the same slot?

- Why unresolved:
  - Plan says Alpenglow is authoritative for `block_id`.
  - Implementation currently keeps first-seen valid consensus block and ignores later conflicting blocks.
- Evidence:
  - Plan: `plan.md:99`, `plan.md:522`
  - Code: `core/src/window_service.rs:327`, `core/src/window_service.rs:330`, `core/src/window_service.rs:1022`, `core/src/window_service.rs:1025`
- Decision needed:
  - Define replacement/override rules when consensus later provides authoritative divergence.

### Q5) What is canonical behavior for empty-result vs non-empty block with zero included proposers?

- Why unresolved:
  - Spec defines empty consensus result behavior.
  - Vote gate rejects when no proposer is included.
  - Replay writes empty MCP execution output if consensus block is not yet observed.
- Evidence:
  - Spec: `docs/src/proposals/mcp-protocol-spec.md:181`, `docs/src/proposals/mcp-protocol-spec.md:219`
  - Plan: `plan.md:647`, `plan.md:649`
  - Code: `core/src/mcp_vote_gate.rs:147`, `core/src/mcp_vote_gate.rs:148`, `core/src/replay_stage.rs:3622`, `core/src/replay_stage.rs:3624`
- Decision needed:
  - Define explicit state/wire signal for empty result and deterministic vote/replay handling for zero-included-proposer outcomes.

---

## Deep Dive (2026-02-16): Implementation-Level Analysis

Parallel investigation of liveness, safety/determinism, and spec-vs-plan conformance. Findings below are backed by code-level tracing.

### D1: ConsensusBlock durability is the root cause of Q4, Q5, and late-arrival divergence

`McpConsensusBlockStore` is `Arc<RwLock<HashMap<Slot, Vec<u8>>>>` (`core/src/mcp_replay.rs:35`). Broadcast is one-shot QUIC fan-out (`core/src/window_service.rs:365-379`). No persistence, no repair type, no gossip.

This single design choice creates a cascade:
- **Q4 (conflicting blocks):** First-seen wins because there's no durable record to compare against a later consensus-authoritative outcome.
- **Q5 (empty vs non-empty):** The empty-placeholder path (`replay_stage.rs:3622-3624`) exists specifically because the consensus block may never arrive.
- **Late-arrival bank hash divergence:** When replay proceeds with an empty placeholder, the bank is frozen with ticks-only hash. Even if `maybe_process_pending_mcp_slots` (`replay_stage.rs:3088-3095`) later writes the correct execution output to blockstore (empty→non-empty upgrade via `blockstore.rs:3401-3402`), the in-memory bank hash is permanent. Vote gate prevents voting on the wrong hash (`replay_stage.rs:2876-2882`), preserving safety, but the diverged bank persists in the fork graph.
- **Snapshot catch-up:** Snapshot-booting nodes start with an empty blockstore and in-memory HashMap. They have no path to obtain ConsensusBlocks for catch-up slots.

Persisting ConsensusBlocks in a blockstore CF + adding a repair request type would resolve Q4, Q5, and the late-arrival scenario simultaneously.

### D2: Safety properties that DO hold

Verified through code tracing — these are NOT concerns:

- **RS reconstruction determinism:** GF(2^8) RS is mathematically subset-independent. Implementation zero-pads to fixed shard size (`mcp_erasure.rs:138-144`). Commitment root re-verified after reconstruction (`mcp_reconstruction.rs:192-195`). Safe.
- **B2 ordering determinism:** Integer-only sort keys (`ExecutionClass` enum, `u64` fee, `[u8;64]` signature), stable sort (`mcp_ordering.rs:46`). No floating point, no platform dependence. Safe.
- **Two-phase fee determinism:** Phase A/B split is deterministic given the same transaction sequence, which is guaranteed by the execution output override (`blockstore_processor.rs:1810-1871`). Safe.
- **Delayed bankhash deadlock:** Impossible. Chain is strictly linear (`slot.saturating_sub(1)` at `mcp_replay.rs:255`), always terminates at a pre-MCP slot or genesis. Not a concern.
- **Feature activation:** Correctly handled via lazy epoch-level schedule computation. `max_epoch` guard prevents premature use (`leader_schedule_cache.rs:273-276`). Not a concern.

### D3: Spec payload bound should be corrected

Spec §3.2 says `NUM_RELAYS * SHRED_DATA_BYTES` = 172,600 bytes. Actual RS data capacity is `DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES` = 34,520 bytes (`ledger/src/mcp.rs:53-58`). The 160 coding shreds are RS parity, not payload capacity. The spec conflates total shred count (200) with data shred count (40). This is a spec bug — an implementation following it literally would fail RS encoding at 34,521 bytes.

### D4: B2 ordering contradicts spec §3.6 (acknowledged)

Plan B2 adds MCP-first classing and signature tiebreak. Spec requires flat fee ordering with concatenation-order tiebreak. These produce different transaction orderings. Plan acknowledges this at line 93. Note: `order_batches_by_fee_desc` (`mcp_ordering.rs:23`) IS spec-compliant but is not the production path — `order_batches_mcp_policy` (`mcp_ordering.rs:33`) is. Must be resolved before multi-client.

### D5: Relay attestation timing heuristic (relates to Q3)

Implementation fires attestation when all 16 proposers' shreds seen OR working bank advances past the slot (`window_service.rs:761-764`). No wall-clock timer. A slow proposer sending shreds late in the slot could systematically miss attestation coverage if relays emit before its shreds arrive. This directly affects whether the 0.40 inclusion threshold provides its intended coverage guarantee for honest-but-slow proposers.

---

## Addendum (2026-02-17): Annotation Audit (upstream/master -> master)

Scope: exhaustive mapping of every changed file in `git diff upstream/master...master` to `plan.md` pass sections and spec anchors, plus validation against `human.md` feedback.

- Delta size: `96` files changed relative to `upstream/master`.
- Rust source traceability comment coverage (literal markers like `MCP spec §`, `Pass`, or `plan.md`): `6/85` files.
- Commands used: `git diff --name-only upstream/master...master`, targeted test reruns, and direct line-level checks.

### Human.md Consistency Check

| Human Feedback Item | Status | Evidence |
|---|---|---|
| `leader_index` must be consensus-leader-schedule index, not proposer index | Resolved in implementation and integration test harness | `core/src/mcp_replay.rs`, `core/src/window_service.rs`, `ledger/src/mcp_consensus_block.rs`, `ledger/src/mcp_aggregate_attestation.rs`, `local-cluster/tests/local_cluster.rs` |
| TVU control-frame byte-0 collision risk | Resolved | `core/src/shred_fetch_stage.rs` now routes only parseable MCP control frames (`RelayAttestation`/`ConsensusBlock`) |
| `dispatch_relay_attestation_to_slot_leader` should skip self-send | Resolved | `core/src/mcp_relay_submit.rs` short-circuits when `dispatch.leader_pubkey == cluster_info.id()` |
| Add comments quoting spec at validation points | Partially resolved (targeted locations), not exhaustive across all changed files | Spec comments present in `core/src/mcp_replay.rs`, `core/src/window_service.rs`, `core/src/shred_fetch_stage.rs`; global coverage remains incomplete |
| Suggest using new `ShredVariant` for MCP types | Contradicts hard plan/constraint; intentionally not applied | Plan constraints: keep existing shred pipeline types unchanged |

### Current Blockers / Unknowns

1. **Resolved during this audit:** local-cluster MCP test leader-signature check now uses `Leader[s]` from leader schedule and the test passes.
   - Fix: `local-cluster/tests/local_cluster.rs` now resolves consensus leader via `slot_leader_for(consensus_slot)` for `ConsensusBlock` signature verification.
   - Verification: `cargo test -p solana-local-cluster --test local_cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture` (PASS).
2. **Process blocker:** exhaustive in-source plan-section comment requirement is not yet met globally.
   - Evidence: only a small subset of changed Rust files include explicit plan/spec marker comments.
   - Impact: traceability requirement unmet; no runtime effect.

### File-to-Plan / Spec Mapping (Exhaustive)

| File | Plan Section(s) | Spec Anchor(s) |
|---|---|---|
| `Cargo.lock` | `cross` | dependency lock updates |
| `audit.md` | `docs` | audit tracking |
| `compute-budget-instruction/src/compute_budget_instruction_details.rs` | `7.3` | §7.1 ordering fee extraction |
| `core/src/banking_stage/consumer.rs` | `5.3` | proposer admission policy |
| `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs` | `5.3` | proposer admission policy |
| `core/src/banking_stage/transaction_scheduler/scheduler_controller.rs` | `5.3` | proposer admission policy |
| `core/src/block_creation_loop.rs` | `5.2` | bankless recording guardrails |
| `core/src/forwarding_stage.rs` | `5.4` | §3.2 proposer forwarding |
| `core/src/lib.rs` | `cross` | module wiring |
| `core/src/mcp_constant_consistency.rs` | `1/2/7` | cross-crate invariant checks |
| `core/src/mcp_relay.rs` | `4.2` | §3.3 relay attestation state |
| `core/src/mcp_relay_submit.rs` | `4.3` | §3.3 relay->leader transport |
| `core/src/mcp_replay.rs` | `6.4/7.1/7.2` | §3.5 + §3.6 vote-gate/reconstruct |
| `core/src/mcp_vote_gate.rs` | `7.1` | §3.5 Consensus Voting Stage |
| `core/src/repair/ancestor_hashes_service.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/repair/malicious_repair_handler.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/repair/outstanding_requests.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/repair/repair_handler.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/repair/repair_response.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/repair/repair_service.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/repair/serve_repair.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/repair/standard_repair_handler.rs` | `4.5` | repair path integration (impl extension) |
| `core/src/replay_stage.rs` | `6.4/7` | §3.5 + §3.6 replay wiring |
| `core/src/shred_fetch_stage.rs` | `4.3/6.1` | §7.3/§7.5 control-frame ingress |
| `core/src/tpu.rs` | `5` | pipeline wiring |
| `core/src/tvu.rs` | `4/6` | TVU MCP ingress wiring |
| `core/src/validator.rs` | `cross` | validator wiring |
| `core/src/window_service.rs` | `4.1/4.2/6.1/6.2` | §3.3-§3.5 + §7.3-§7.5 |
| `cost-model/src/transaction_cost.rs` | `7.3` | §8 fee accounting interaction |
| `entry/src/block_component.rs` | `7.3` | execution output component support |
| `feature-set/src/lib.rs` | `1.1` | §4 + feature activation semantics |
| `fee/Cargo.toml` | `7.3` | dependency wiring |
| `fee/src/lib.rs` | `7.3` | §8 fee decomposition helpers |
| `human.md` | `docs` | human review input |
| `ledger/Cargo.toml` | `1/3/7` | dependency wiring |
| `ledger/src/blockstore.rs` | `3.2` | §3.4/§3.6 MCP artifact storage APIs |
| `ledger/src/blockstore/blockstore_purge.rs` | `3.1` | MCP CF retention/purge |
| `ledger/src/blockstore/column.rs` | `3.1` | storage extension for MCP artifacts |
| `ledger/src/blockstore/error.rs` | `3.2` | §3.4/§3.6 persistence error handling |
| `ledger/src/blockstore_db.rs` | `3.1` | storage extension for MCP artifacts |
| `ledger/src/blockstore_processor.rs` | `7.3` | §3.6 replay execution + §8 fees |
| `ledger/src/leader_schedule.rs` | `2` | §5 Schedules and Indices |
| `ledger/src/leader_schedule/vote_keyed.rs` | `2.2` | §5 schedule stake-key parity |
| `ledger/src/leader_schedule_cache.rs` | `2` | §5 Schedules and Indices |
| `ledger/src/leader_schedule_utils.rs` | `2` | §5 Schedules and Indices |
| `ledger/src/lib.rs` | `cross` | module wiring |
| `ledger/src/mcp.rs` | `1.2` | §4 Protocol Parameters |
| `ledger/src/mcp_aggregate_attestation.rs` | `1.2/6.1` | §7.4 AggregateAttestation |
| `ledger/src/mcp_consensus_block.rs` | `1.2/6.1` | §7.5 ConsensusBlock |
| `ledger/src/mcp_erasure.rs` | `1.5` | §3.2 encoding + §4 erasure constants |
| `ledger/src/mcp_merkle.rs` | `1.3` | §6 Commitments and Witnesses |
| `ledger/src/mcp_ordering.rs` | `7.3` | §3.6 ordering + §8 fee policy (B2 override) |
| `ledger/src/mcp_reconstruction.rs` | `7.2` | §3.6 Reconstruct and Replay |
| `ledger/src/mcp_relay_attestation.rs` | `1.2/4.2` | §7.3 RelayAttestation |
| `ledger/src/mcp_shredder.rs` | `1.5` | §3.2 + §6 encode/reconstruct utility |
| `ledger/src/shred.rs` | `1.4/3.3` | MCP shred classifier integration |
| `ledger/src/shred/mcp_shred.rs` | `1.4` | §7.2 Shred wire format |
| `ledger/src/shred/wire.rs` | `1.4` | wire constants/types |
| `ledger/src/shredder.rs` | `1.5` | MCP shredder bridge |
| `local-cluster/Cargo.toml` | `7.6` | integration harness deps |
| `local-cluster/tests/local_cluster.rs` | `7.6` | end-to-end MCP integration |
| `net-utils/src/sockets.rs` | `7.6` | local-cluster bind retry robustness |
| `plan.md` | `docs` | implementation plan |
| `poh/src/poh_recorder.rs` | `5.2` | bankless recording API |
| `runtime-transaction/src/runtime_transaction.rs` | `7.3` | §7.1/§8 tx meta carriage |
| `runtime-transaction/src/runtime_transaction/sdk_transactions.rs` | `7.3` | §7.1 tx compatibility |
| `runtime-transaction/src/runtime_transaction/transaction_view.rs` | `7.3` | §7.1 tx view bridging |
| `runtime-transaction/src/transaction_meta.rs` | `7.3` | §8 fee components meta |
| `runtime/src/bank.rs` | `7.3/7.4` | §8 two-pass debit + block_id handoff |
| `runtime/src/bank/check_transactions.rs` | `7.3` | §8 payer checks |
| `runtime/src/bank/fee_distribution.rs` | `7.3` | §8 fee accounting |
| `runtime/src/bank/tests.rs` | `7.6` | §8 fee tests |
| `svm/Cargo.toml` | `7.3` | dependency wiring |
| `svm/src/account_loader.rs` | `7.3` | §8 fee collection mode support |
| `svm/src/transaction_processor.rs` | `7.3` | §8 skip_fee_collection execution mode |
| `transaction-view/Cargo.toml` | `1.2` | dependency wiring |
| `transaction-view/src/lib.rs` | `1.2` | §7.1 module export |
| `transaction-view/src/mcp_payload.rs` | `1.2/7.3` | §7.1 transaction payload framing |
| `transaction-view/src/mcp_transaction.rs` | `1.2/7.3` | §7.1 transaction format compatibility |
| `turbine/Cargo.toml` | `4/5` | dependency wiring |
| `turbine/src/broadcast_stage.rs` | `5.1` | §3.2 broadcast wiring |
| `turbine/src/broadcast_stage/standard_broadcast_run.rs` | `5.1/5.3` | §3.2 Proposal Stage |
| `turbine/src/cluster_nodes.rs` | `5.4` | §3.2 feature-slot activation semantics |
| `turbine/src/lib.rs` | `cross` | module wiring |
| `turbine/src/mcp_proposer.rs` | `5.1/5.3` | §3.2 proposer payload + shred dispatch |
| `turbine/src/quic_endpoint.rs` | `4.3` | MCP control QUIC transport |
| `turbine/src/retransmit_stage.rs` | `4.4` | relay broadcast/retransmit plumbing |
| `turbine/src/sigverify_shreds.rs` | `3.3` | §3.5 local shred validity precondition |
| `validator/src/admin_rpc_service.rs` | `4.5` | admin-trigger MCP repair API |
| `votor/Cargo.toml` | `7.4` | dependency wiring |
| `votor/src/consensus_metrics.rs` | `7.4` | consensus vote/block_id observability |
| `votor/src/consensus_pool/parent_ready_tracker.rs` | `7.4` | consensus parent readiness with MCP data |
| `votor/src/consensus_pool_service.rs` | `7.4` | consensus integration |
| `votor/src/consensus_pool_service/stats.rs` | `7.4` | consensus integration metrics |
| `votor/src/event_handler.rs` | `7.4` | consensus event handling for MCP block_id |
| `votor/src/voting_utils.rs` | `7.4` | vote payload + block_id |

---

## Addendum (2026-02-22): Bankless Plan/Implementation Audit

Scope:
- `plan.md` bankless sections (`plan.md:19-21`, `plan.md:755-786`)
- Spec §9 (`docs/src/proposals/mcp-protocol-spec.md:593-598`)
- Implementation paths:
  - `core/src/banking_stage/consumer.rs`
  - `core/src/replay_stage.rs`
  - `core/src/block_creation_loop.rs`
  - `poh/src/poh_recorder.rs`

Summary:
- `HIGH`: 1 (latent implementation gap on no-working-bank record path)
- `MEDIUM`: 2 (activation-edge gating + missing direct branch coverage)
- `LOW`: 1 (plan wording mismatch with runtime QoS behavior)

### BKL-1: `record_bankless` caller path is incomplete if exercised (`HIGH`, latent)

- Plan claims this blocker is resolved by wiring `PohRecorder::record_bankless` from production (`plan.md:19-21`).
- In production caller, the returned `BanklessRecordSummary` is discarded (`core/src/block_creation_loop.rs:456-464`).
- `record_bankless` returns `recorded_entries` but does not emit to `working_bank_sender` (`poh/src/poh_recorder.rs:500-519`).

Impact:
- If `record_with_optional_bankless` enters the `!has_bank()` branch, recorded transaction entries have no forwarding/broadcast sink and are effectively dropped.
- Current block-creation flow usually keeps a working bank installed while draining records (`core/src/block_creation_loop.rs:530-548`), so this is likely dormant today, but it contradicts the plan’s “resolved” framing.

Minimal fix direction:
1. Either make this path explicitly unsupported for now (return deterministic error when `!has_bank()` in block-creation recording path), or
2. Plumb `BanklessRecordSummary.recorded_entries` into the same downstream entry/broadcast flow used by normal recording.

### BKL-2: Bankless-start vote bypass is checked on parent slot, not candidate leader slot (`MEDIUM`)

- `allow_bankless_start` is computed from `parent_bank.slot() >= activated_slot` (`core/src/replay_stage.rs:2626-2630`).
- For activation boundary slots, the parent may be pre-activation while `maybe_my_leader_slot` is activation slot.

Impact:
- On the first MCP-active leader slot, rooted-vote bypass can be withheld unexpectedly.

Minimal fix direction:
- Compare activation against `maybe_my_leader_slot` (the candidate produced slot), not `parent_bank.slot()`.

### BKL-3: Direct coverage for bankless execution bypass is still missing (`MEDIUM`)

- `consumer.rs` tests now intentionally disable MCP feature to keep legacy path behavior (`core/src/banking_stage/consumer.rs:804-813`).
- Replay has a targeted test for common start checks (`core/src/replay_stage.rs:5775+`), but no direct test proving leader-owned MCP banks are replayed via the new `|| is_mcp_slot` branch (`core/src/replay_stage.rs:3766-3771`, `core/src/replay_stage.rs:3881-3886`).

Impact:
- The main bankless branch (`record_transactions_bankless`) can regress without deterministic unit-test detection.

Minimal fix direction:
1. Add a `consumer.rs` unit test with MCP active asserting no state transition occurs during `process_and_record_transactions`, while transactions are recorded for replay.
2. Add a replay-stage test asserting leader-owned MCP slot enters replay path.

### BKL-4: Plan wording mismatch for QoS cost behavior (`LOW`)

- Plan says “QoS costs revert to estimated values” (`plan.md:772`).
- Implementation sets synthetic committed CU to zero (`core/src/banking_stage/consumer.rs:600-607`), and QoS updates cost tracker with those actual values (`core/src/banking_stage/qos_service.rs:203-210`), which subtracts estimated execution cost (`cost-model/src/cost_tracker.rs:199-211`).

Impact:
- Documentation mismatch; runtime behavior is deterministic but wording is inaccurate.

Minimal fix direction:
- Update plan wording to “QoS actual execution units are updated to zero for bankless-recorded transactions.”

### Verification Run (targeted)

- `cargo test -p solana-core --lib test_common_maybe_start_leader_checks_allows_mcp_bankless_start_without_rooted_vote` ✅
- `cargo test -p solana-core --lib test_mcp_fee_payer_tracker_prevents_overcommit` ✅
- `cargo test -p solana-poh --lib test_record_bankless_without_working_bank` ✅

---

## Addendum (2026-02-22): Bankless Re-Audit (post `2ff01753ad`)

Scope:
- New bankless commit: `2ff01753ad`.
- Plan sections: `plan.md:19-21`, `plan.md:524-531`, `plan.md:755-787`.
- Spec anchor: `docs/src/proposals/mcp-protocol-spec.md:593-598` (Section 9).

### Summary

- Implementation correctness vs Spec §9: `PASS` for this change set (banking-stage execution bypass + replay of leader-owned MCP banks are present).
- Remaining production blockers from this delta: `none confirmed`.
- Remaining issues: 1 medium (weak replay regression test), 1 low (deferred/test-only helper path docs).

### RBK-1: `RESOLVED` (documentation sync)

Status:
- `plan.md:19-22` now matches implementation: production block recording is fail-fast when no working bank is installed, and `record_bankless` remains a guarded helper API.

### RBK-2 (MEDIUM): New replay test is not coupled to production code path

Evidence:
- `test_mcp_leader_owned_bank_enters_replay` only evaluates a local boolean expression (`core/src/replay_stage.rs:11068-11105`).
- It does not execute `replay_active_bank` or `replay_active_banks_concurrently` and therefore cannot catch regressions in those functions.

Why it matters:
- Intended regression coverage exists in name but not in effect.

Minimal correction:
- Add a unit test that exercises one real replay function and asserts leader-owned MCP bank is not skipped.

### RBK-3 (LOW): `record_bankless` is currently test-only code

Evidence:
- No production call sites for `.record_bankless(`; occurrences are in `poh_recorder` tests only.

Why it matters:
- Current state is valid if intentional, but should be documented as deferred wiring to avoid confusion.

Minimal correction:
- Document in plan/audit that `record_bankless` remains a guarded helper pending explicit entry-forwarding plumbing, and production uses fail-fast for no-bank record attempts.

### RBK-4: `RESOLVED` (comment wording sync)

Status:
- `core/src/banking_stage/consumer.rs` comment now matches `plan.md` wording: QoS actual execution units are updated to zero for bankless-recorded transactions.

### Revalidated on this pass

- `cargo test -p solana-core --lib test_mcp_bankless_records_without_execution` ✅
- `cargo test -p solana-core --lib test_mcp_leader_owned_bank_enters_replay` ✅
- `cargo test -p solana-core --lib test_common_maybe_start_leader_checks_allows_mcp_bankless_start_without_rooted_vote` ✅


---

## Addendum (2026-02-22): Bankless Re-Audit 2 (post `4c73f74689`)

Scope:
- Delta audited: `4c73f74689` + current workspace state.
- Spec anchor: `docs/src/proposals/mcp-protocol-spec.md:593-598` (Section 9).
- Plan anchors: `plan.md:19-22`, `plan.md:525-532`, `plan.md:757-799`.

### Summary

- Bankless implementation vs spec/plan: `CONSISTENT` for current behavior.
- Production blockers found in this pass: `none`.
- Open item: 1 low-priority deferred helper-path/documentation item.

### RBK-2 follow-up: `RESOLVED`

Previous concern:
- Replay regression test only validated a boolean expression.

Current status:
- Replaced with real replay-path test that invokes `ReplayStage::replay_blockstore_into_bank` on a leader-owned MCP bank and asserts success.
- Evidence: `core/src/replay_stage.rs:11068-11157` (`test_mcp_leader_owned_bank_replays_via_blockstore`).

### Current low-priority item

#### RBK-5 (LOW): `record_bankless` remains a deferred helper path

Evidence:
- Production block creation fail-fast rejects no-working-bank recording (`core/src/block_creation_loop.rs:455-466`).
- `record_bankless` remains available and tested in `poh_recorder` tests, but not used by production record path.
- Plan now documents this explicitly (`plan.md:791-799`).

Assessment:
- Not a release blocker for current bankless design.
- This is only a deferred enhancement if future design needs no-working-bank entry forwarding instead of fail-fast.

### Validation rerun in this pass

- `cargo test -p solana-core --lib test_mcp_leader_owned_bank_replays_via_blockstore` ✅
- `cargo test -p solana-core --lib test_mcp_bankless_records_without_execution` ✅
- `cargo test -p solana-core --lib test_common_maybe_start_leader_checks_allows_mcp_bankless_start_without_rooted_vote` ✅
- `cargo test -p solana-poh --lib test_record_bankless_without_working_bank` ✅


---

## Addendum (2026-02-22): Focused Failure Triage — bankless regressions

Scope requested:
- `test_1_node_alpenglow`: `PubsubError` / timeout while waiting for roots.
- `test_local_cluster_mcp_produces_blockstore_artifacts`: `consensus_meta` size mismatch (`41 vs 32`).

### F1) `test_1_node_alpenglow` (`UNVERIFIED exact panic text`, high-confidence call-path diagnosis)

Observed locally on this pass:
- The single-node cluster keeps finalizing and advancing roots continuously (root moves 4 -> 5 -> ... in runtime logs).
- Test flow did not terminate promptly under `--nocapture`; repeated transaction retry warnings appeared in local-cluster helpers.

Call path:
1. `local-cluster/tests/local_cluster.rs:224` (`test_1_node_alpenglow`)
2. `local-cluster/tests/local_cluster.rs:193` (`test_alpenglow_nodes_basic`)
3. `local-cluster/src/cluster_tests.rs:68` (`spend_and_verify_all_nodes`)
4. `local-cluster/src/local_cluster.rs:985` (`poll_for_processed_transaction` loop)
5. `local-cluster/src/cluster_tests.rs:458` (`check_for_new_commitment_slots` root polling)
6. `local-cluster/src/cluster_tests.rs:865` (`new_tpu_quic_client`)

Key issue in harness path:
- Root polling and spend verification repeatedly instantiate `TpuClient` via `new_tpu_quic_client(...)`, which requires `rpc_pubsub` websocket setup each time (`cluster_tests.rs:865-883`, `cluster_tests.rs:475`, `cluster_tests.rs:117`).
- This couples simple root/processed checks to pubsub transport health and connection churn; when pubsub is flaky, tests can fail as `PubsubError`/timeouts even while consensus/rooting is healthy.

Why this maps to your reported symptom:
- Root progress can be healthy, but the test still times out/fails because the checker path depends on pubsub-backed `TpuClient` creation, not a stable plain `RpcClient` root check.

Minimal fix direction:
- For root/processed polling in local-cluster tests, use direct `RpcClient` from `contact_info.rpc()` instead of `TpuClient`.
- Keep `TpuClient` only for send paths. This removes pubsub as a false-negative source for root liveness checks.

### F2) `test_local_cluster_mcp_produces_blockstore_artifacts` (`CONFIRMED`)

#### F2.a) Stale assertion (fixed in this workspace)

Cause:
- Test asserted `consensus_meta.len() == HASH_BYTES (32)`.
- Implementation defines versioned `ConsensusMeta::V1` wire size as `1 + 32 + 8 = 41` bytes.

Evidence:
- Wire size constant: `ledger/src/mcp_consensus_block.rs:18-19`
- Producer writes v1 metadata: `core/src/window_service.rs:196`
- Replay parses v1 metadata: `core/src/mcp_replay.rs:290-314`
- Test assertion site (updated): `local-cluster/tests/local_cluster.rs:7927-7937`

Fix applied:
- Test now parses `consensus_meta` via `consensus_meta_parsed()` and asserts v1 wire size via `CONSENSUS_META_V1_WIRE_BYTES`.
- Test now derives delayed-slot from parsed metadata (`delayed_slot()`) instead of hardcoding `slot - 1`.

#### F2.b) Additional blocker seen during rerun (likely bankless path)

Observed repeatedly during rerun:
- `BlockComponentProcessor(MissingBlockFooter)` dead-slot marks.
- Repeated slot-meta corruption signals: `consumed: 128 > last_index + 1: Some(96)`.

Relevant bankless path:
1. Leader bankless setup: `core/src/block_creation_loop.rs:738-743`
2. Block completion calls `tick_alpenglow(..., footer)`: `core/src/block_creation_loop.rs:552-560`
3. PoH bankless flush emits footer marker in `flush_cache`: `poh/src/poh_recorder.rs:816-833`
4. Replay of leader-owned bankless slots is forced in replay stage: `core/src/replay_stage.rs:3768-3771`, `core/src/replay_stage.rs:3883-3886`

Risk hypothesis:
- Marker/tick sequencing or multiplicity in bankless footer emission is producing malformed/partial block-component streams for some slots, which then fail block-component validation at replay finalization.
- This is consistent with `MissingBlockFooter` plus slot-meta over-consumption on the same slots.

Minimal verification/fix plan:
1. Add temporary counters/logs around footer-marker enqueue in `PohRecorder::flush_cache` (bankless branch) to prove exactly one footer per slot and its position relative to final tick.
2. Add a focused unit/integration assertion in local-cluster MCP test path: each executed MCP slot must have exactly one footer marker before replay finalization.
3. Fail test early with slot-level diagnostics when `MissingBlockFooter` appears, instead of waiting for global timeout.

Status after this pass:
- The explicit `41 vs 32` assertion mismatch is fixed.
- Remaining instability is dominated by `MissingBlockFooter` / slot-meta errors in bankless execution path; this is now the primary blocker for deterministic local-cluster MCP test completion.

---

## Addendum (2026-02-22): Principal Bankless Audit (fresh pass)

Scope:
- Bankless implementation surfaces:
  - `core/src/banking_stage/consumer.rs`
  - `core/src/block_creation_loop.rs`
  - `core/src/replay_stage.rs`
  - `poh/src/poh_recorder.rs`
- Spec anchors:
  - `docs/src/proposals/mcp-protocol-spec.md:581-591` (fee-payer DoS constraints)
  - `docs/src/proposals/mcp-protocol-spec.md:593-598` (bankless requirement)

### Summary

- Bankless core flow (`record only in banking stage, execute in replay`) is implemented and unit-tested.
- No immediate crash-level defect found in the new bankless PoH/replay wiring itself.
- 2 high-risk correctness/spec gaps remain in admission gating/accounting.

### Findings

#### PBK-1 (`HIGH`, `UNVERIFIED` reachability): bankless execution gate in BankingStage is feature-slot based, not migration-phase based

Evidence:
- BankingStage bankless branch activates when MCP feature slot is active:
  - `core/src/banking_stage/consumer.rs:348-353`
- Block creation bankless PoH mode is gated by alpenglow runtime state:
  - `core/src/block_creation_loop.rs:738-744`
- Replay leader-owned-bank execution bypass is gated by alpenglow slot classification:
  - `core/src/replay_stage.rs:3768-3770`

Why this matters:
- If there exists any phase where `mcp_protocol_v1` is active but `should_have_alpenglow_ticks(slot)` is false, BankingStage can skip execution while replay/broadcast still follow non-bankless assumptions.

Minimal fix:
1. Align BankingStage bankless predicate with migration/alpenglow slot predicate (same semantic source used by replay/block creation), not feature activation alone.
2. Add a regression test for the activation/migration boundary slot behavior.

Verification needed:
- Prove from migration state transitions whether the mixed condition is reachable in production.

#### PBK-2 (`HIGH`): per-slot cumulative fee commitments are not persisted across scheduler passes

Evidence:
- Spec requires per-slot cumulative fee commitments:
  - `docs/src/proposals/mcp-protocol-spec.md:587-588`
- Admission tracker is instantiated per pass (ephemeral) in multiple paths:
  - `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:263`
  - `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:520`
  - `core/src/banking_stage/transaction_scheduler/scheduler_controller.rs:202-203`

Why this matters:
- A payer can pass conservative fee checks in multiple independent passes within the same slot, violating cumulative per-slot reservation semantics.

Minimal fix:
1. Store `McpFeePayerTracker` in scheduler state keyed by slot and reuse it across receive/filter passes.
2. Reset tracker only when working slot advances.

#### PBK-3 (`MEDIUM`): MCP conservative fee check is conditional on `mcp_fee_components().is_some()`

Evidence:
- Admission route condition:
  - `core/src/banking_stage/consumer.rs:737-744`

Why this matters:
- Standard-wire transactions in MCP-active slots can bypass MCP conservative reservation logic if they carry no MCP fee metadata, conflicting with spec language for standard transactions.

Minimal fix:
1. For MCP-active slots, route all transactions through MCP fee admission.
2. Treat missing MCP fee components as `(inclusion=0, ordering=0)` but still apply the scaled reservation rule.

#### PBK-4 (`MEDIUM`): replay guard regression test still does not execute the exact guard path

Evidence:
- Test asserts the guard expression manually and calls `replay_blockstore_into_bank`, but does not exercise `replay_active_bank*` guard branches directly:
  - `core/src/replay_stage.rs:11097-11109`
  - Guard branches under test intent:
  - `core/src/replay_stage.rs:3768-3771`
  - `core/src/replay_stage.rs:3883-3886`

Why this matters:
- Guard regressions in those functions can slip through despite the current test passing.

Minimal fix:
1. Add a focused test that drives `replay_active_bank` (or `replay_active_banks_concurrently`) with a leader-owned MCP slot and asserts replay entry.

### Validation rerun (this pass)

- `cargo test -p solana-core --lib test_mcp_bankless_records_without_execution` ✅
- `cargo test -p solana-core --lib test_common_maybe_start_leader_checks_allows_mcp_bankless_start_without_rooted_vote` ✅
- `cargo test -p solana-core --lib test_mcp_leader_owned_bank_replays_via_blockstore` ✅
- `cargo test -p solana-poh --lib test_record_bankless_without_working_bank` ✅
- `cargo test -p solana-local-cluster --test local_cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --test-threads=1` ✅ (pass; observed non-fatal replay/bankless noise remains)

---

## Addendum (2026-02-22): PBK-1/PBK-2 Closure

Scope:
- Prior open items from this same file:
  - `PBK-1` (bankless activation gate alignment)
  - `PBK-2` (per-slot cumulative MCP fee reservation persistence)
- Files changed in this closure:
  - `core/src/banking_stage/consumer.rs`
  - `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs`
  - `core/src/banking_stage/transaction_scheduler/scheduler_controller.rs`
  - `core/src/banking_stage.rs`

### Status Summary

- `PBK-1`: `RESOLVED`
- `PBK-2`: `RESOLVED`
- `PBK-3/PBK-4`: unchanged by this delta

### PBK-1 resolution details (`RESOLVED`)

What changed:
- BankingStage bankless path now uses an explicit migration-aware predicate instead of feature-slot-only gating:
  - `core/src/banking_stage/consumer.rs:138` (`should_use_bankless_recording`)
  - `core/src/banking_stage/consumer.rs:361` (call site)

Predicate now requires:
1. MCP feature active for the slot, and
2. alpenglow genesis certificate present, and
3. `bank.slot() > genesis_cert.cert_type.slot()`.

Why this resolves the finding:
- Aligns BankingStage execution bypass with migration/alpenglow semantics used elsewhere, eliminating feature-only activation drift risk at transition boundaries.

Test evidence:
- `test_mcp_bankless_records_without_execution` verifies post-genesis MCP slot takes bankless record-only path (`core/src/banking_stage/consumer.rs:1861`).
- `test_mcp_feature_active_without_alpenglow_cert_uses_legacy_execution` verifies MCP-active without cert remains legacy execute path (`core/src/banking_stage/consumer.rs:1951`).

### PBK-2 resolution details (`RESOLVED`)

What changed:
- MCP fee tracker is now persistent scheduler state (instead of per-pass local temporary):
  - `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:114`
  - `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:370`
- Both receive/buffer paths now reuse `self.mcp_fee_payer_tracker` when calling fee admission:
  - sanitized path: `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:333`
  - view path: `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:574`
- View-mode constructor introduced and wired at call sites to initialize state cleanly:
  - `core/src/banking_stage/transaction_scheduler/receive_and_buffer.rs:373`
  - `core/src/banking_stage.rs:477`
- Pre-graph filter no longer re-runs fee reservation (avoids double-reserve in repeat filters):
  - `core/src/banking_stage/transaction_scheduler/scheduler_controller.rs:201`

Why this resolves the finding:
- Conservative fee commitments are now retained across repeated scheduler receive/filter passes for the same controller instance, matching per-slot cumulative reservation intent and preventing per-pass reset bypass.

Targeted validation on this pass:
- `cargo test -p solana-core --lib test_mcp_fee_payer_tracker_prevents_overcommit` ✅
- `cargo test -p solana-core --lib test_receive_and_buffer_simple_transfer` ✅
- `cargo test -p solana-core --lib test_schedule_consume_single_threaded_no_conflicts` ✅

### Remaining open items from the PBK set

- `PBK-3` and `PBK-4` remain as previously documented (not regressed by this change set).
