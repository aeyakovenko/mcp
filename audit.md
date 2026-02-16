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
