# MCP Test Plan Audit

Date: 2026-02-26
Branch: `master` (working tree dirty)
Scope: `test_plan.md` consistency vs implemented code/tests, plus call-path trace validation.

## Method

1. Parsed `test_plan.md` end-to-end.
2. Validated referenced files/functions in the pass matrix exist and are wired by callsites.
3. Validated referenced test symbols in `test_plan.md` against code (`fn test_*`).
4. Ran representative traced tests on current tree:
   - `cargo test -p solana-core test_maybe_finalize_consensus_block_requires_block_id -- --nocapture`
   - `cargo test -p solana-ledger test_mcp_schedule_accessors_require_feature_activation -- --nocapture`
5. Audited hard-spot "Required test" items for implemented vs open status.

## Executive Summary

- `test_plan.md` is now mostly aligned with current implementation and test names.
- Pass-matrix call paths are present and wired in code.
- Test-reference coverage is high: 94 explicit test names referenced; 93 exist; 1 is intentionally open.
- Plan exit criteria are **not fully met** due open hard-spot items and unstable local-cluster MCP status.

## Findings

### HIGH

1. Exit criteria not met (explicitly documented in plan)
- Evidence: `test_plan.md` now states `Current status (2026-02-26): NOT MET` and lists open items.
- Impact: cannot claim full test-plan completion / production-readiness gate closure.

2. Full local-cluster MCP status remains unstable
- Evidence: `test_plan.md` current run status still reports:
  - `test_1_node_alpenglow` timing out in bounded runs.
  - `test_local_cluster_mcp_produces_blockstore_artifacts` unstable (`MissingBlockFooter`, slot-meta churn symptoms).
- Impact: end-to-end confidence remains below production-readiness bar.

### MEDIUM

1. Missing explicit hard-spot test: empty relay entries in aggregate parser
- Evidence: `test_plan.md` references `test_from_wire_bytes_rejects_empty_relay_entries`; symbol does not exist.
- Code state: `ledger/src/mcp_aggregate_attestation.rs` parser still accepts `entries_len == 0` and relies on downstream filtering.
- Status: OPEN by plan annotation.

2. Missing dedicated 0x02 whole-consensus pending-finalization retry test
- Evidence: hard-spot HS-008 marked OPEN in `test_plan.md`.
- Code trace confirms pending retry mechanism exists, but no dedicated vector asserts this path specifically.

3. Missing defense-in-depth test for `proposers_at_slot(slot, None)` cache-empty behavior
- Evidence: HS-010 marked OPEN; no matching test symbol in `leader_schedule_cache` tests.

4. Missing static guard/lint for `verify_signature` usage without `verify_witness`
- Evidence: HS-001 marked OPEN.
- Current state: caller discipline is by convention + current callsites, not enforced guardrail.

5. Production-path reconstruction mismatch vector is partial
- Evidence: HS-009 marked PARTIAL in `test_plan.md`.
- Gap: explicit vector through `mcp_replay` production path is still pending.

### LOW

1. Some traced call-path references in `test_plan.md` include line numbers that will drift
- Not a correctness issue; function names/paths are currently valid.

## Call-Path Trace Verification

All pass-matrix primary call paths were validated as present and wired. Key evidence:

- Pass 3 (sigverify partition):
  - `run_shred_sigverify` -> `partition_mcp_packets`
  - `turbine/src/sigverify_shreds.rs:182`, `turbine/src/sigverify_shreds.rs:291`

- Pass 4 (window service ingest/finalize):
  - `run_insert` calls `ingest_mcp_control_message`; retry loop calls `maybe_finalize_and_broadcast_mcp_consensus_block`
  - `core/src/window_service.rs:581`, `core/src/window_service.rs:980`, `core/src/window_service.rs:1333`, `core/src/window_service.rs:1376`

- Pass 5 (proposer + forwarding):
  - `maybe_record_mcp_payload_batch` and `maybe_dispatch_mcp_shreds`
  - `turbine/src/broadcast_stage/standard_broadcast_run.rs:819`, `turbine/src/broadcast_stage/standard_broadcast_run.rs:881`
  - `ForwardAddressGetter::get_non_vote_forwarding_addresses` wired to `LeaderUpdater::next_leaders`
  - `core/src/forwarding_stage.rs:119`, `core/src/forwarding_stage.rs:635-637`

- Pass 7 (replay + batch execution):
  - replay uses `maybe_process_pending_mcp_slots` + `should_vote_mcp_slot`
  - `core/src/replay_stage.rs:2994`, `core/src/replay_stage.rs:3100`
  - blockstore processor calls `maybe_override_replay_entries_with_mcp_execution_output`, then `queue_batches_with_lock_retry`, then `execute_batch`
  - `ledger/src/blockstore_processor.rs:2142`, `ledger/src/blockstore_processor.rs:794`, `ledger/src/blockstore_processor.rs:168`

## Test Reference Audit (from `test_plan.md`)

- Total backtick `test_*` tokens: 101
- Explicit test names (non-wildcard): 94
- Missing explicit test symbols: 1
  - `test_from_wire_bytes_rejects_empty_relay_entries`

Interpretation:
- The single missing explicit test is consistent with an OPEN hard-spot item and is now annotated as such in `test_plan.md`.

## Representative Test Runs (this audit)

- PASS: `test_maybe_finalize_consensus_block_requires_block_id`
- PASS: `test_mcp_schedule_accessors_require_feature_activation`

## Conclusion

`test_plan.md` is materially up to date and correctly annotated about what is implemented vs open. The main remaining issues are known, explicit, and concentrated in five hard-spot gaps plus unresolved local-cluster instability. No new hidden matrix wiring breaks were found in this audit.
