# MCP Audit (Post-Fix)

Date: 2026-02-11
Branch: `issue-20-mcp-local-cluster-test`
Scope: re-audit after closing the remaining MCP test coverage gaps and re-running targeted validation.

## Verdict

- `plan.md` vs implementation: `PASS`
- Remaining implementation correctness issues: `0`
- Remaining integration coverage blockers: `0`

## Fixes Applied In This Pass

1. `TESTGAP-1` closed: live `ConsensusBlock` content verification in 5-node local-cluster test.
- Added read-only consensus-block accessor path for tests:
  - `core/src/tvu.rs`: `Tvu::mcp_consensus_block_bytes`
  - `core/src/validator.rs`: `Validator::mcp_consensus_block_bytes`
- `local-cluster` now verifies observed consensus-block bytes by checking:
  - leader signature validity
  - `consensus_meta` length is exactly 32 bytes
  - delayed bankhash equals delayed-slot bankhash from blockstore
- Evidence: `local-cluster/tests/local_cluster.rs`

2. `TESTGAP-3` closed: explicit two-pass fee-per-occurrence assertion on block-verification path.
- Added deterministic unit test `test_execute_batch_mcp_two_pass_charges_fee_per_occurrence`.
- The test enables MCP feature, executes 1 tx and 2 tx cases on fresh banks, and asserts the 2-tx fee delta is exactly 2x the 1-tx delta.
- Evidence: `ledger/src/blockstore_processor.rs`

3. `TESTGAP-5` closed: direct forwarding fanout attribution assertion.
- Tightened dispatch test by forcing QUIC-only relay addressing for scheduled relay targets.
- Test now asserts exact dispatch fanout count equals proposer-index count times reachable relay-target count.
- Evidence: `turbine/src/broadcast_stage/standard_broadcast_run.rs`

## Tests Run

- `cargo test -p solana-turbine test_maybe_dispatch_mcp_shreds_removes_complete_slot_payload_state -- --nocapture`
- `cargo test -p solana-ledger mcp_two_pass -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_requires_delayed_bankhash -- --nocapture`
- `cargo test -p solana-ledger test_parser_and_classifier_accept_edge_slot_values -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`

All above passed in this pass.

## Plan Sync

- `plan.md` `A4` updated to `RESOLVED` with concrete evidence/test references.
- No additional architectural blockers found in this pass.
