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
