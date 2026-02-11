# MCP Audit (Post-Remediation)

Date: 2026-02-11
Branch: `issue-20-mcp-local-cluster-test`
Scope: re-audit after systematic fixes against current `plan.md` and implementation

## Verdict

- `plan.md` consistency with code: `PASS`
- previously open high-priority implementation gaps: `FIXED`
- end-to-end 5-node local-cluster MCP test: `PASS`
- remaining blockers to full strict MCP semantics: `0`

## Fixes Applied In This Pass

1. Proposer admission policy (§5.3) implemented.
- Added payer reservation enforcement (`NUM_PROPOSERS * base_fee`) at payload admission.
- Added signature dedup at proposer payload build path.
- Added proposer-side B2 ordering before MCP payload encoding.
- Evidence:
  - `turbine/src/broadcast_stage/standard_broadcast_run.rs`
  - `turbine/Cargo.toml`

2. Vote-gate relay counting semantics aligned with plan (§6.1/§7.1).
- Relays with no valid proposer entries are excluded from global relay threshold counting.
- Evidence:
  - `core/src/mcp_vote_gate.rs`

3. Relay attestation dispatch reliability tightened.
- Added bounded retry behavior and explicit drop counters for full/closed send channel cases.
- Evidence:
  - `core/src/mcp_relay_submit.rs`

4. Window-service equivocation suppression tightened.
- Conflicting MCP shred observations now suppress attestation tracking for that `(slot, proposer_index)` and remove pending entry.
- Evidence:
  - `core/src/window_service.rs`

5. Plan status synchronized.
- Release-blocker status updated to mark proposer admission/payload policy wiring as resolved.
- Evidence:
  - `plan.md`

6. Retransmit MCP addressing revalidated.
- MCP slot/shred-id derivation fallback already exists for retransmit addressing.
- Evidence:
  - `turbine/src/retransmit_stage.rs`

7. Pre-consensus strict no-fallback replay resolved (`B-1`).
- Replay now writes an empty `McpExecutionOutput` placeholder for MCP-active non-leader slots with no cached consensus block, so replay does not execute legacy entry transactions.
- Pending-slot reconstruction and reconstruction persistence treat empty output as upgradable placeholder and can overwrite it once vote-gate + reconstruction succeed.
- Evidence:
  - `core/src/replay_stage.rs`
  - `core/src/mcp_replay.rs`
  - `plan.md`

## Non-Blocking Coverage Gaps

- Integration coverage can still be expanded for:
  - forwarding fanout assertions
  - explicit two-pass fee behavior assertions in local cluster
  - delayed-bankhash gating at integration level (currently unit-tested)

## Tests Run

- `cargo check -p solana-turbine -p solana-core`
- `cargo test -p solana-turbine test_slot_dispatch_state_enforces_payload_bound_with_framing_overhead -- --nocapture`
- `cargo test -p solana-turbine test_slot_dispatch_state_dedups_by_signature -- --nocapture`
- `cargo test -p solana-turbine test_slot_dispatch_state_requires_num_proposers_fee_reservation -- --nocapture`
- `cargo test -p solana-turbine test_order_mcp_payload_transactions_uses_b2_policy -- --nocapture`
- `cargo test -p solana-turbine test_maybe_dispatch_mcp_shreds_removes_complete_slot_payload_state -- --nocapture`
- `cargo test -p solana-core test_ingest_mcp_consensus_block_rejects_invalid_consensus_meta_length -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_from_relay_attestations -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_requires_delayed_bankhash -- --nocapture`
- `cargo test -p solana-core test_maybe_prepare_mcp_execution_output_for_replay_slot_writes_empty_placeholder_without_consensus -- --nocapture`
- `cargo test -p solana-core test_maybe_persist_reconstructed_execution_output_marks_empty_output -- --nocapture`
- `cargo test -p solana-core forwarding_stage::tests::test_forwarding -- --nocapture`
- `cargo test -p solana-core test_relays_without_any_valid_proposer_entries_do_not_count -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`
