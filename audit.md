# MCP Audit — Post-Fix Recheck (Master)

Date: 2026-02-12
Branch: `master`
Scope: Re-validated `audit.md` findings against code, implemented minimal-diff fixes, re-ran targeted and e2e tests.

## Executive Summary

- Prior critical/medium correctness findings in this audit are now closed in code.
- One previously listed medium concern (`nonce edge test coverage`) is not valid: coverage already exists in `runtime/src/bank/tests.rs`.
- One design tradeoff remains tracked (equivocation evidence stores conflict hashes, not full conflicting payload bodies).
- 5-node MCP local-cluster integration test still passes end to end.

## Concern Status

| ID | Concern | Status | Evidence |
|---|---|---|---|
| H1 | Vote-gate signature/equivocation checks effectively dead | FIXED | `core/src/mcp_replay.rs:181`, `core/src/mcp_replay.rs:189`, `core/src/mcp_replay.rs:200` now build `VoteGateInput` from raw aggregate entries with actual relay/proposer signature verification; vote-gate equivocation exclusion (`len() != 1`) is now exercised on real commitment sets. |
| H2 | Replay bridge parsed bincode before MCP, losing MCP fee components | FIXED | `ledger/src/blockstore_processor.rs:1778` now parses MCP first, then bincode fallback at `ledger/src/blockstore_processor.rs:1789`. Added regression test: `ledger/src/blockstore_processor.rs:5991`. |
| M1 | Proposer dispatch `any()` short-circuit skipped remaining proposer indices | FIXED | `turbine/src/broadcast_stage/standard_broadcast_run.rs:872` now iterates all owned proposer indices without early return; target proposer path also no longer aborts the batch at `turbine/src/broadcast_stage/standard_broadcast_run.rs:861`. |
| M2 | Silent drops during reconstruction ordering-metadata extraction | FIXED | Added explicit drop counter `mcp-reconstruction-transaction-metadata-drop` at `core/src/mcp_replay.rs:518`. Metadata parse now returns typed errors (`core/src/mcp_replay.rs:345`) instead of silent `None`. |
| M3 | Missing nonce edge coverage for two-phase fee path | DISMISSED (already covered) | Existing tests: `runtime/src/bank/tests.rs:1491` and `runtime/src/bank/tests.rs:1535`, covering fee+nonce-rent debit and exact-balance acceptance for `collect_fees_only_for_transactions` (`runtime/src/bank.rs:3473`, `runtime/src/bank.rs:3527`). |
| M4 | Conflict evidence only stores hashes, not full payloads | OPEN (non-blocking v1 tradeoff) | `ledger/src/blockstore.rs:233` (`McpConflictMarker`) intentionally stores deterministic hashes for conflict markers. Satisfies deterministic conflict signaling; full-body evidence persistence can be added later if external proof transport is required. |
| L2 | Lock poison panic in MCP replay path | FIXED | Replaced `unwrap()` with explicit poisoned-lock handling and warning at `core/src/mcp_replay.rs:442`. |
| L3 | Reconstruction constants not covered by consistency tests | FIXED | Added test `core/src/mcp_constant_consistency.rs:42`. |

## Additional Dispatch Observability

- Added payload-capacity counters in dispatch state:
  - `mcp-proposer-dispatch-payload-reservation-overflow`
  - `mcp-proposer-dispatch-payload-full`
- Evidence: `turbine/src/broadcast_stage/standard_broadcast_run.rs:175`, `turbine/src/broadcast_stage/standard_broadcast_run.rs:179`, `turbine/src/broadcast_stage/standard_broadcast_run.rs:183`.

## Validation Runs

All commands succeeded.

- `cargo test -p solana-core mcp_replay -- --nocapture`
- `cargo test -p solana-core mcp_vote_gate -- --nocapture`
- `cargo test -p solana-ledger test_versioned_transaction_from_mcp_wire_bytes_accepts_legacy_mcp_format -- --nocapture`
- `cargo test -p solana-ledger test_versioned_transaction_from_mcp_wire_bytes_accepts_bincode_versioned_transaction -- --nocapture`
- `cargo test -p solana-turbine test_maybe_dispatch_mcp_shreds_removes_complete_slot_payload_state -- --nocapture`
- `cargo test -p solana-core test_mcp_reconstruction_constants_match_ledger_protocol_constants -- --nocapture`
- `cargo check -p solana-core -p solana-ledger -p solana-turbine`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`
  - PASS, 5-node run, finished in 60.72s.

## Current Verdict

- Critical blockers from this audit: **0 open**.
- Medium blockers from this audit: **0 open** (1 dismissed with direct existing coverage evidence).
- Remaining tracked item: **1 non-blocking design tradeoff** (`McpConflictMarker` hash-only conflict evidence).
