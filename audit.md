# MCP Audit (Post 81bc269 Integration)

Date: 2026-02-11  
Branch: `issue-20-mcp-local-cluster-test`  
External input reviewed: `carllin/solana@81bc2690987f7424bc54a60c663e92db42abdd3d`

## Summary

- `plan.md` was updated with compatible improvements from the external commit.
- The plan remains aligned with your current policy decisions (`B1/B2/B3/B4`) and current Agave wiring.
- Core code still has several high/critical gaps versus plan requirements.

## External Commit Deltas Integrated Into Plan

1. Slot gate semantics are now explicitly documented, including the current implementation gap between cutover intent and ingress helper behavior.
- Evidence: `plan.md:128`

2. MCP shred wire-size derivation is now explicit (`overhead`, `data bytes`, `wire size`) with data-vs-coding index semantics.
- Evidence: `plan.md:176`

3. RS helper reuse now points to actual local modules (`mcp_erasure` + `turbine::mcp_proposer`) instead of generic placeholder wording.
- Evidence: `plan.md:192`

4. Pass-1 test matrix now includes wire invariants and RS recovery/mutation checks.
- Evidence: `plan.md:203`

5. Schedule derivation now states concrete seed construction and `repeat=1` MCP sampling semantics.
- Evidence: `plan.md:224`

6. Sigverify partition section now explicitly states feature-only gating (no proposer/relay-role filtering at ingress).
- Evidence: `plan.md:292`

7. Proposer dispatch section now names the concrete helper integration points used in code.
- Evidence: `plan.md:378`

8. Expected file list now includes `ledger/src/mcp_erasure.rs` and `turbine/src/mcp_proposer.rs`.
- Evidence: `plan.md:636`, `plan.md:655`

## External Commit Items Not Adopted (Intentional)

1. Dedicated TPU proposer worker/thread (`core/src/mcp_proposer.rs`, TPU thread spawn).
- Not adopted because current code uses broadcast-path dispatch and `turbine/src/mcp_proposer.rs` helpers, which is lower churn and matches existing architecture.
- Evidence: `turbine/src/broadcast_stage/standard_broadcast_run.rs:697`, `turbine/src/mcp_proposer.rs:30`.

2. Reverting to old ordering/fee policy.
- Not adopted because current plan intentionally uses MCP-first partition + signature tie-break + per-occurrence replay charging semantics.
- Evidence: `plan.md:80`, `plan.md:507`.

3. Re-defer `block_id` section.
- Not adopted because plan currently treats Alpenglow-authoritative `block_id` as active policy.
- Evidence: `plan.md:585`.

## Remaining Blocking Gaps (Plan vs Code)

1. `CRITICAL` MCP cutover execution-source enforcement missing.
- Code still validates MCP output then logs "execution override deferred".
- Evidence: `ledger/src/blockstore_processor.rs:1837`.

2. `CRITICAL` Replay phase-A still applies `* NUM_PROPOSERS` multiplier.
- Evidence: `runtime/src/bank.rs:3518`.

3. `HIGH` Fee component helper still scales MCP components.
- Evidence: `fee/src/lib.rs:109`.

4. `HIGH` Pending-slot replay still falls back to `heaviest_bank`.
- Evidence: `core/src/replay_stage.rs:3053`.

5. `HIGH` Ordering implementation still old (concat + fee-desc stable ties), not current plan policy.
- Evidence: `ledger/src/mcp_ordering.rs:17`, `core/src/mcp_replay.rs:495`.

6. `HIGH` `block_id` authority still not fully wired to plan-level behavior.
- `ConsensusBlock` still carries opaque `consensus_meta` and delayed bankhash only at this layer.
- Evidence: `ledger/src/mcp_consensus_block.rs:41`.

7. `MEDIUM` Activation semantics mismatch remains in code paths using epoch-effective checks.
- Evidence: `turbine/src/cluster_nodes.rs:713`, `core/src/shred_fetch_stage.rs:507`.

## Succinctness / Consistency Verdict

- Succinctness: `PASS` (incremental detail increase is targeted and localized to ambiguous sections).
- Internal consistency: `PASS` (no new internal contradictions introduced).
- Code consistency: `PARTIAL` (blockers above still unresolved).
