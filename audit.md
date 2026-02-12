# MCP Audit (Master)

Date: 2026-02-12
Branch: `master`
Scope: confirm current audit concerns, land fixes on `master`, and re-validate with targeted tests.

## Verdict

- MCP implementation remains feature-complete vs `plan.md`.
- Confirmed audit gaps addressed in this pass: 4.
- Remaining open implementation concerns: 2 (unchanged, intentionally tracked).

## Confirmed Concerns and Status

1. Relay attestation proposer-entry signature validation in local-cluster integration test.
- Status: `RESOLVED`.
- Evidence: `local-cluster/tests/local_cluster.rs` now requires all attestation entries to pass `valid_entries(...)` against proposer schedule.

2. Vote-gate inclusion boundary coverage (`REQUIRED_INCLUSIONS` 79 vs 80).
- Status: `RESOLVED`.
- Evidence: new unit test in `core/src/mcp_vote_gate.rs` (`test_inclusion_threshold_boundary_requires_at_least_80_relays`).

3. Explicit Merkle domain-separation test coverage.
- Status: `RESOLVED`.
- Evidence: new unit test in `ledger/src/mcp_merkle.rs` (`test_domain_separation_formulas_for_leaf_and_internal_node_hashes`).

4. Data-shards-only erasure recovery coverage.
- Status: `RESOLVED`.
- Evidence: new unit test in `ledger/src/mcp_erasure.rs` (`test_reconstruction_from_data_shards_only`).

## Remaining Open Concerns

1. MCP shred repair protocol extension for `(slot, proposer_index, shred_index)` indexing.
- Status: `OPEN`.
- Notes: existing repair protocol remains slot+shred-index based.

2. B3 strictness deviation: block-id fallback path still exists for some missing-sidecar conditions.
- Status: `OPEN`.
- Notes: still treated as acknowledged v1 deviation.

## Validation Runs

Passed in this pass:

- `cargo test -p solana-core mcp_vote_gate -- --nocapture`
- `cargo test -p solana-ledger mcp_merkle -- --nocapture`
- `cargo test -p solana-ledger mcp_erasure -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`

## Files Updated This Pass

- `core/src/mcp_vote_gate.rs`
- `ledger/src/mcp_merkle.rs`
- `ledger/src/mcp_erasure.rs`
- `audit.md`
