# MCP Audit (Master)

Date: 2026-02-11
Branch: `master`
Scope: confirm current `audit.md` concerns against code, apply fixes on `master`, and re-validate.

## Summary

- MCP implementation status vs `plan.md`: `PASS` (feature-complete).
- Real audit concern fixed on `master`: relay attestation proposer-signature verification in local-cluster integration.
- Incorrect audit concern removed: "no mcp_vote_gate unit tests" (tests exist and pass).
- Remaining open concerns are implementation follow-ups, not regressions from this pass.

## Concerns Checked

### Confirmed + Fixed

1. Local-cluster test did not validate proposer signatures in relay attestation entries.
- Evidence before fix: `local-cluster/tests/local_cluster.rs` only checked `verify_relay_signature` and non-empty entries.
- Fix: test now validates all relay attestation entries via `valid_entries(...)` against proposer schedule for `observed_slot`, and requires full entry validity.
- File: `local-cluster/tests/local_cluster.rs`

### Invalid / Already Resolved

1. "No `mcp_vote_gate` unit tests exist".
- Reality: `core/src/mcp_vote_gate.rs` contains 9 tests covering all rejection branches and vote success path.
- Validation: `cargo test -p solana-core mcp_vote_gate -- --nocapture` passed (9/9).

## Remaining Open Concerns (Not fixed in this pass)

1. MCP repair protocol extension for `(slot, proposer_index, shred_index)` remains unimplemented.
- Existing repair types are slot+shred-index based (`ShredRepairType::{Shred, HighestShred, ...}`).
- Files: `core/src/repair/serve_repair.rs`, `core/src/repair/repair_service.rs`

2. B3 strictness deviation remains: replay can still derive/fallback block id when authoritative MCP sidecar is unavailable in some paths.
- File: `core/src/replay_stage.rs`

## Validation Run

Passed:

- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`
- `cargo test -p solana-core mcp_vote_gate -- --nocapture`

## Master Changes In This Pass

- `local-cluster/tests/local_cluster.rs`:
  - strengthened relay-attestation verification to require valid proposer signatures for all entries.
- `audit.md`:
  - replaced outdated concerns with confirmed-current audit status.
