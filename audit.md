# MCP Audit (Master)

Date: 2026-02-12
Branch: `master`
Commit: `65568a2a79` (plus local uncommitted fixes in this pass)
Scope: re-check `audit.md` concerns, confirm in code, land fixes, and re-validate local-cluster MCP integration.

## Executive Summary

All previously reported critical blockers in `audit.md` are now fixed on `master`:

1. B3 deferral no longer over-defers pre-consensus MCP slots.
2. `BlockComponent` empty-entry decode no longer collides with `BlockMarker` decode.

The MCP local-cluster integration test now passes end-to-end.

## Concern Revalidation

### 1) B3 deferral overreach

- Prior concern: MCP-active slots were deferred even when no consensus block existed yet.
- Confirmed on code before fix at `core/src/replay_stage.rs`.
- Fix: `should_defer_for_missing_mcp_authoritative_block_id` now requires:
  - MCP feature active for slot
  - **and** `has_mcp_consensus_block_for_slot(slot, store)`
  - **and** missing/invalid authoritative sidecar block-id
- File: `core/src/replay_stage.rs`

### 2) Empty `EntryBatch` decode collision

- Prior concern: serialized `EntryBatch(vec![])` (`8` zero bytes) was interpreted as `BlockMarker` and failed with `ReadSizeLimit(2)`.
- Confirmed on code before fix at `entry/src/block_component.rs`.
- Fix: decode path disambiguates `entry_count == 0` by buffer length:
  - exactly `ENTRY_COUNT_SIZE` bytes => `EntryBatch(vec![])`
  - otherwise => `BlockMarker(...)`
- Added round-trip assertion for `BlockComponent::EntryBatch(vec![])`.
- File: `entry/src/block_component.rs`

## Validation Runs (Post-fix)

Passed:

- `cargo test -p solana-core test_should_defer_for_missing_mcp_authoritative_block_id_for_active_mcp_slot -- --nocapture`
- `cargo test -p solana-core test_should_not_defer_for_missing_mcp_authoritative_block_id_before_feature_activation -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`
  - Result: `ok` (1 passed)
  - Regression symptoms from prior audit (stuck root at 63, repeated `ReadSizeLimit(2)` dead-slot loop) are no longer present.

Also passed:

- `cargo check -p solana-core -p solana-entry`

## Residual Notes

- `cargo test -p solana-entry round_trips -- --nocapture` currently fails due pre-existing test-only API drift in reward-certificate helpers (`new_for_tests` not found); unrelated to MCP fixes.
- `cargo check -p solana-local-cluster` currently fails on an unrelated `QuicServerParams::default_for_tests` symbol mismatch in `local-cluster/src/cluster_tests.rs`; MCP integration test itself passes.

## Current Verdict

- Critical audit blockers: `CLOSED`
- MCP local-cluster integration (issue-20 target): `PASS`
- Additional branch propagation is required only if issue branches are behind this master commit.
