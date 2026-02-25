# MCP Implementation Audit Report

**Date:** 2026-02-25  
**Branch:** `master`  
**Spec source:** `plan.md`  
**Scope:** Re-check of open issues from previous `audit.md`, then targeted fixes in code and tests.

## Executive Summary

The previously open **production-relevant** issues are now fixed in code:
- strict no-fallback replay for MCP-active slots
- consensus block acceptance from forwarded peers (signature-authenticated)
- proposer admission return-value correctness
- authoritative `block_id` conflict handling in release builds
- oldest-first retry of pending MCP slots

No unresolved high-severity blocker remains from the prior open-issues list.

## Issue Status

| ID | Prior finding | Status | Evidence |
|---|---|---|---|
| C-001 | Sigverify slot offset bug | **Already fixed before this pass** | `turbine/src/sigverify_shreds.rs:311`, `turbine/src/sigverify_shreds.rs:771` |
| H-001 | MCP replay silently falls back to legacy entries when execution output missing | **FIXED** | `ledger/src/blockstore_processor.rs:1866`, test `ledger/src/blockstore_processor.rs:6362` |
| M-001 | Consensus block rejected unless QUIC sender is slot leader | **FIXED** | `core/src/window_service.rs:941`, test `core/src/window_service.rs:1545` |
| M-002 | Missing nonce rent edge-case test | **Already fixed before this pass** | `runtime/src/bank/tests.rs:1535` |
| M-003 | Hardcoded fanout=16 wastes pre-MCP resources | **Reclassified (not a blocker)** | Pre-MCP path caps to legacy lookahead in `ForwardAddressGetter::get_non_vote_forwarding_addresses`; fanout does not force 16 active targets pre-MCP |
| M-006 | Admission returns `true` on rejection paths | **FIXED** | `turbine/src/broadcast_stage/standard_broadcast_run.rs:159`, test `turbine/src/broadcast_stage/standard_broadcast_run.rs:1347` |
| L-006 | `set_block_id` conflict ignored in release (`debug_assert_eq`) | **FIXED** | `runtime/src/bank.rs:5876`, test `runtime/src/bank/tests.rs:12658` |
| L-008 | Replay retries only newest pending MCP slots (starvation risk) | **FIXED** | `core/src/replay_stage.rs:3043` |

## Code Changes Applied

1. `ledger/src/blockstore_processor.rs`
- MCP-active replay now errors if `McpExecutionOutput` is missing.
- Added regression test to enforce no-fallback behavior.

2. `core/src/window_service.rs`
- Removed transport-peer identity gating for consensus blocks.
- Kept leader signature verification as the authentication rule.
- Updated test to validate forwarded sender acceptance.

3. `turbine/src/broadcast_stage/standard_broadcast_run.rs`
- Admission now returns `false` on insufficient funds / reservation overflow.
- Updated fee-reservation test accordingly.

4. `runtime/src/bank.rs`
- Replaced `debug_assert_eq!` with release-enforced `assert_eq!` for conflicting authoritative `block_id` assignment.

5. `runtime/src/bank/tests.rs`
- Added panic test to lock the conflict behavior.

6. `core/src/replay_stage.rs`
- Pending MCP slot retry is now oldest-first within the per-loop cap.

## Validation Run

Targeted tests run and passing:
- `cargo test -p solana-ledger test_maybe_override_replay_entries_with_mcp_execution_output_rejects_missing_output_when_active -- --nocapture`
- `cargo test -p solana-core test_ingest_mcp_consensus_block_accepts_forwarded_sender_with_valid_signature -- --nocapture`
- `cargo test -p solana-turbine test_slot_dispatch_state_requires_num_proposers_fee_reservation -- --nocapture`
- `cargo test -p solana-runtime test_set_block_id_rejects_conflicting_assignment -- --nocapture`

## Remaining Items (Non-blocking)

- Additional test-depth items from earlier audit drafts (e.g., certain wire-format negative cases) remain quality improvements, not production blockers for the fixed paths above.
