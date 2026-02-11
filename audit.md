# MCP Audit (Post-Fix Self Audit)

Date: 2026-02-11
Branch: `issue-20-mcp-local-cluster-test`
Authoritative constraint: `carllin/solana@81bc2690987f7424bc54a60c663e92db42abdd3d`
Scope: integration branch + consistency against `plan.md`

## Verdict

- `plan.md` consistency: `PASS`
- code vs `plan.md`: `PASS`
- PR-series consistency on integration branch: `PASS` (integration branch reconciles prior standalone PR deltas)
- succinctness: `PASS` (ordering policy centralized; file lists corrected)

## Self PR Audit

- Reviewed cumulative behavior from PR series (#24-#42, #44, #45) as integrated on this branch.
- No unresolved integration-branch regressions found against `plan.md`.
- Historical standalone-PR divergences are superseded by the integrated branch state validated in this audit.

## Systematic Fixes Applied

1. Slot-effective MCP feature gate consistency across entry points.
- Replaced `is_active()` checks with slot-effective `activated_slot()` checks where MCP logic is slot-dependent.
- Evidence:
  - `core/src/replay_stage.rs`
  - `ledger/src/blockstore_processor.rs`
  - `turbine/src/broadcast_stage/standard_broadcast_run.rs`
  - `core/src/forwarding_stage.rs`

2. Strict consensus-observed replay gating and authoritative `block_id` enforcement.
- Replay now defers execution/completion for consensus-observed slots until:
  - vote gate passes
  - `McpExecutionOutput` exists
  - authoritative `block_id` sidecar is usable
- Evidence:
  - `core/src/replay_stage.rs`
  - `core/src/window_service.rs`

3. ConsensusBlock sidecar validation tightened on ingest.
- Consensus blocks with non-32-byte `consensus_meta` are dropped.
- Added ingest test for invalid sidecar length.
- Evidence:
  - `core/src/window_service.rs`

4. Forwarding fanout behavior fixed for both forwarding clients in MCP mode.
- `ConnectionCacheClient` now fans out to all resolved proposer forwarding addresses.
- `TpuClientNext` fanout configuration now targets MCP proposer count.
- Evidence:
  - `core/src/forwarding_stage.rs`

5. MCP control-path backpressure tightened.
- Relay-attestation channel in TVU changed from unbounded to bounded.
- Evidence:
  - `core/src/tvu.rs`

6. MCP shred strict parser bounds added.
- `McpShred::from_bytes()` now rejects out-of-range proposer/shred indices.
- Added parser tests for both index bounds.
- Evidence:
  - `ledger/src/shred/mcp_shred.rs`

7. Phase-A zero-fee payer validation hardened.
- Removed zero-fee bypass so fee payer/account validation still runs through withdraw path.
- Evidence:
  - `runtime/src/bank.rs`

8. `plan.md` corrected for spec/policy clarity and implementation reality.
- Explicitly documents B2 as an intentional spec override and cross-proposer dedup as an Agave extension.
- Adds `McpExecutionOutput` CF to storage section.
- Adds v1 delayed-slot definition (`slot - 1`) and RS/invariant notes.
- Fixes file classification lists and reduces repeated ordering text.
- Evidence:
  - `plan.md`

## Remaining Issues

- None identified as blockers or correctness regressions in current integration branch scope.
- Intentional compatibility behavior retained and documented in `plan.md`:
  - pre-consensus replay compatibility fallback remains allowed in v1.

## Tests Run

- `cargo check -p solana-core -p solana-ledger -p solana-runtime -p solana-turbine`
- `cargo test -p solana-ledger test_mcp_shred_rejects_out_of_range_proposer_index_in_parser -- --nocapture`
- `cargo test -p solana-ledger test_mcp_shred_rejects_out_of_range_shred_index_in_parser -- --nocapture`
- `cargo test -p solana-core test_ingest_mcp_consensus_block_rejects_invalid_consensus_meta_length -- --nocapture`
- `cargo test -p solana-core test_mcp_authoritative_block_id_for_slot_reads_hash_sized_consensus_meta -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_from_relay_attestations -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_requires_delayed_bankhash -- --nocapture`
- `cargo test -p solana-core forwarding_stage::tests::test_forwarding -- --nocapture`
- `cargo test -p solana-runtime collect_fees_only_for -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`
