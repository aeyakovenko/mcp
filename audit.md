# MCP Audit (Current)

Date: 2026-02-11  
Branch: `issue-20-mcp-local-cluster-test`

## Summary

- `plan.md` policy is now mostly coherent and explicit.
- Core implementation still has blocking gaps against the current plan and cannot claim full MCP E2E correctness yet.

## Blocking Gaps (Plan vs Code)

1. `CRITICAL` MCP cutover execution source not enforced.
- Plan requires slots `>= mcp_cutover_slot` to execute from MCP canonical source only.
- Code still validates `McpExecutionOutput` but defers execution override.
- Evidence: `ledger/src/blockstore_processor.rs:1834`.

2. `CRITICAL` Replay fee semantics still overcharge.
- Plan says replay charges per occurrence, no replay-time `NUM_PROPOSERS` multiplier, and `ordering_fee` is not charged.
- Code multiplies replay charge by `MCP_NUM_PROPOSERS`.
- Evidence: `runtime/src/bank.rs:3518`.

3. `HIGH` MCP fee component scaling still inconsistent with replay policy.
- Fee helper scales inclusion/ordering components by `MCP_NUM_PROPOSERS`.
- This conflicts with current plan’s per-occurrence replay charging semantics.
- Evidence: `fee/src/lib.rs:109`, `fee/src/lib.rs:110`.

4. `HIGH` Pending-slot replay still uses `heaviest_bank` fallback.
- Plan says evaluate slot `X` using slot-`X` bank only; if missing, keep pending.
- Code falls back to `heaviest_bank`.
- Evidence: `core/src/replay_stage.rs:3053`.

5. `HIGH` Ordering implementation still old behavior.
- Plan requires MCP-first partition, signature tie-break, and proposer-local MCP dedup.
- Code still uses fee-desc over concatenated batches with stable positional tie behavior.
- Evidence: `ledger/src/mcp_ordering.rs:17`, `core/src/mcp_replay.rs:495`.

6. `HIGH` `block_id` authority still not fully integrated.
- Plan marks `block_id` path active under Alpenglow authority.
- Consensus block type still states local layer does not define block_id derivation and code path does not enforce full authoritative `block_id` verification from consensus metadata.
- Evidence: `ledger/src/mcp_consensus_block.rs:41`.

7. `MEDIUM` Activation semantics drift remains.
- Plan uses slot cutover semantics.
- Several feature checks still rely on epoch-effective activation behavior.
- Evidence: `turbine/src/cluster_nodes.rs:713`, `core/src/shred_fetch_stage.rs:507`.

## Non-Blocking but Should Fix

1. Parse-drop observability is weak.
- Individual parse failures are dropped but not strongly surfaced for operators.
- Evidence: `core/src/mcp_replay.rs:469`.

2. Critical lock paths still use `unwrap()` in MCP-sensitive flows.
- Not silent drop, but still crash-prone on poisoning.
- Evidence: `core/src/window_service.rs:149`, `core/src/mcp_replay.rs:240`.

## Required Next Code Changes (Minimal-Diff)

1. Implement MCP execution-source cutover in `blockstore_processor` for `slot >= mcp_cutover_slot`.
2. Remove replay-time `NUM_PROPOSERS` multiplier in `runtime/src/bank.rs` phase-A fee collection.
3. Align `fee/src/lib.rs` MCP component handling with final replay fee semantics.
4. Remove `heaviest_bank` fallback for pending-slot MCP replay evaluation.
5. Replace ordering helper/path with MCP-first partition + signature tie-break + proposer-local MCP dedup.
6. Complete authoritative `block_id` plumbing/verification semantics or downgrade plan text until implemented.
7. Reconcile slot-cutover plan text with actual activation checks (or implement slot-cutover checks).
