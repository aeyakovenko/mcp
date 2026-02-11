# MCP Audit (Current)

Date: 2026-02-11
Branch: `issue-20-mcp-local-cluster-test`
Scope: current-state audit after revalidation and targeted fixes.

## Verdict

- `plan.md` vs implementation: `PASS` for implemented MCP behavior.
- Build status of relevant crates: `PASS`.
- Local-cluster MCP test (5-node): `PASS`.
- Remaining implementation correctness blockers: `0`.
- Remaining integration-test coverage gaps: `3` (non-blocking for compile/runtime correctness, listed below).

## Confirmed Fixes In This Pass

1. Relay out-of-range unit-test expectations fixed.
- `core/src/mcp_relay.rs` tests now match current decode behavior (`Dropped(DecodeError)` for invalid indices rejected at decode layer).
- Verified by:
  - `cargo test -p solana-core out_of_range_ -- --nocapture`

2. Local-cluster delayed-bankhash check stabilized.
- Consensus-block delayed-bankhash comparison now prefers the consensus-block observer validator’s blockstore hash for delayed slot, then falls back to any validator if needed.
- File: `local-cluster/tests/local_cluster.rs`

## Current Test Evidence

Passed in this audit pass:

- `cargo test -p solana-core out_of_range_ -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`

Previously passed and still consistent with current branch intent:

- `cargo test -p solana-ledger mcp_two_pass -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_requires_delayed_bankhash -- --nocapture`
- `cargo test -p solana-ledger test_parser_and_classifier_accept_edge_slot_values -- --nocapture`

## Remaining Gaps (Coverage, Not Core Correctness)

1. Transaction inclusion linkage is not asserted in local-cluster integration.
- The test submits transactions and verifies artifact production/decoding/crypto checks, but does not assert that any submitted signature appears in decoded execution output.
- File: `local-cluster/tests/local_cluster.rs`

2. Non-empty decoded execution output is not required.
- `decoded_tx_count` is observed/logged and can be zero while the test still passes.
- File: `local-cluster/tests/local_cluster.rs`

3. Vote-gate decision observability is indirect.
- Integration test infers progress via artifacts and replay behavior but does not directly assert vote-gate decision outputs.
- Files: `local-cluster/tests/local_cluster.rs`, `core/src/replay_stage.rs`

## Plan Sync Notes

- `plan.md` has release blockers marked resolved and `A4` marked `RESOLVED`.
- `A1`, `A2`, `A3`, `A5`, `A6` are still phrased as follow-ups (not explicitly tagged `RESOLVED`) even though the corresponding code paths are implemented.
- This is a documentation/status-tag sync item, not a runtime correctness blocker.
