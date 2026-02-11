# MCP Audit (Authoritative-Constraint Recheck)

Date: 2026-02-11
Branch: `issue-20-mcp-local-cluster-test`
Authoritative constraint: `carllin/solana@81bc2690987f7424bc54a60c663e92db42abdd3d`

## Verdict

- `plan.md` consistency: `PASS` (with 1 explicit pre-consensus compatibility fallback)
- code vs plan consistency: `PASS` (strict consensus-observed paths now match plan)
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

## Remaining Follow-Up

1. `F1 MEDIUM` pre-consensus replay-input compatibility fallback remains.
- Current behavior: once a consensus block is observed for a slot, replay has no fallback (vote-gate/output gating + defer behavior); before consensus observation, v1 may still execute legacy replay input.
- Evidence: `core/src/replay_stage.rs:3617`, `core/src/replay_stage.rs:3636`, `plan.md:35`

## Plan/Code Alignment Notes

- Policy `B2` is now explicit and matches implementation (MCP-first classing, fee-desc, signature tie-break, per-proposer dedup, cross-proposer per-occurrence charging).
  - Evidence: `plan.md:63`, `plan.md:535`, `core/src/mcp_replay.rs:476`
- Policy `B3` now matches code for consensus-observed slots: finalization retries until sidecar availability, ingestion rejects invalid sidecar sizes, and replay defers completion if a cached consensus block lacks authoritative `block_id`.
  - Evidence: `core/src/window_service.rs:189`, `core/src/window_service.rs:972`, `core/src/replay_stage.rs:4136`, `plan.md:26`

## Tests Run In This Pass

- `cargo check -p solana-core`
- `cargo test -p solana-core test_ingest_mcp_consensus_block_stores_valid_leader_frame -- --nocapture`
- `cargo test -p solana-core test_ingest_mcp_consensus_block_rejects_invalid_consensus_meta_length -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_from_relay_attestations -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_requires_delayed_bankhash -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_uses_blockstore_delayed_bankhash -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_broadcasts_quic_control_frame -- --nocapture`
- `cargo test -p solana-core test_mcp_authoritative_block_id_for_slot_reads_hash_sized_consensus_meta -- --nocapture`
- `cargo test -p solana-core test_mcp_authoritative_block_id_for_slot_rejects_non_hash_sized_consensus_meta -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`
