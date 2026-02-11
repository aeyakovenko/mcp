# MCP Audit (Authoritative-Constraint Recheck)

Date: 2026-02-11
Branch: `issue-20-mcp-local-cluster-test`
Authoritative constraint: `carllin/solana@81bc2690987f7424bc54a60c663e92db42abdd3d`

## Verdict

- `plan.md` consistency: `PASS` (with 2 explicit deferred external dependencies)
- code vs plan consistency: `PASS-PARTIAL` (core MCP path is aligned; deferred items remain)
- succinctness: `PASS` (contradictory/duplicate proposer sections removed)

## Resolved Findings

- `IC-1/IC-2/IC-3` resolved: removed contradictory TPU proposer worker design and retained single broadcast-path architecture.
  - Evidence: `plan.md:393`, `plan.md:410`, `plan.md:412`
- `IC-5/IC-6/IC-7` resolved: numbering gap removed, duplicate CU-budget section removed, process artifact text removed.
  - Evidence: `plan.md:410`, `plan.md:435`
- `IC-8` resolved: file list now includes wrapper/module names used in code (`mcp_shredder`, `mcp_ordering`, `turbine/mcp_proposer`).
  - Evidence: `plan.md:634`, `plan.md:645`, `plan.md:651`
- `PC-3` resolved: slot-effective feature checks now use `activated_slot` gate in critical helpers.
  - Evidence: `turbine/src/cluster_nodes.rs:713`, `core/src/shred_fetch_stage.rs:507`
- `PC-4` resolved: `mcp_shredder` wrapper module exists and reuses `mcp_erasure`/`mcp_merkle`.
  - Evidence: `ledger/src/mcp_shredder.rs:1`
- `PC-5` resolved: domain separation seed uses raw domain bytes after epoch bytes.
  - Evidence: `ledger/src/leader_schedule.rs:83`
- `BG-1` resolved: replay input override now uses `McpExecutionOutput` when present, not deferred logging.
  - Evidence: `ledger/src/blockstore_processor.rs:1781`, `ledger/src/blockstore_processor.rs:1834`
- `BG-2/BG-3` resolved: replay phase-A and fee-component helper charge per occurrence (no global `* NUM_PROPOSERS` multiplier).
  - Evidence: `runtime/src/bank.rs:3516`, `fee/src/lib.rs:104`
- `BG-4` resolved: pending-slot replay no longer falls back to `heaviest_bank`.
  - Evidence: `core/src/replay_stage.rs:3053`
- `BG-5` resolved: ordering now enforces MCP-first classing, fee-desc, signature tie-break; dedup is per proposer payload.
  - Evidence: `core/src/mcp_replay.rs:330`, `core/src/mcp_replay.rs:476`, `core/src/mcp_replay.rs:512`, `ledger/src/mcp_ordering.rs:33`
- `BG-7` resolved: MCP role lookup uses slot-effective activation slot check.
  - Evidence: `ledger/src/leader_schedule_cache.rs:264`

## Remaining Valid Blockers

1. `R1 CRITICAL` Alpenglow `block_id` authority is policy-complete but implementation-deferred.
- Reason: `block_id` derivation/setter/vote-path integration is still external to this branch.
- Evidence: `plan.md:586`, `plan.md:590`

2. `R2 HIGH` strict no-fallback replay mode for missing `McpExecutionOutput` remains deferred.
- Current behavior: malformed output is hard error, missing output still falls back in v1.
- Evidence: `plan.md:576`, `plan.md:582`

3. `R3 MEDIUM` full 5-node MCP local-cluster E2E was not rerun in this pass.
- Status: `UNVERIFIED` in this audit pass (targeted unit/integration tests passed; full cluster pass not re-executed here).

## Plan/Code Alignment Notes

- Policy `B2` is now explicit and matches implementation (MCP-first classing, fee-desc, signature tie-break, per-proposer dedup, cross-proposer per-occurrence charging).
  - Evidence: `plan.md:63`, `plan.md:535`, `core/src/mcp_replay.rs:476`
- Policy `B3` is now explicitly framed as target invariant with deferred implementation section to avoid contradiction.
  - Evidence: `plan.md:588`

## Tests Run In This Pass

- `cargo test -p solana-ledger mcp_ordering::tests -- --nocapture`
- `cargo test -p solana-runtime collect_fees_only_for -- --nocapture`
- `cargo test -p solana-fee apply_mcp_fee_component -- --nocapture`
- `cargo test -p solana-core maybe_persist_reconstructed_execution_output -- --nocapture`
- `cargo test -p solana-ledger test_maybe_override_replay_entries_with_mcp_execution_output_validates_and_overrides_replay_entries -- --nocapture`
- `cargo test -p solana-core test_is_active_mcp_shred_packet_obeys_feature_slot_gate -- --nocapture`
- `cargo test -p solana-turbine test_partition_mcp_packets_uses_layout_prefilter_and_feature_gate -- --nocapture`
- `cargo test -p solana-ledger test_domain_separated_schedule_seed -- --nocapture`
- `cargo test -p solana-ledger test_mcp_schedule_accessors_require_feature_activation -- --nocapture`
