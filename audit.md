# MCP Audit (Post-Remediation)

Date: 2026-02-11
Branch: `issue-20-mcp-local-cluster-test`
Authoritative constraint: `carllin/solana@81bc2690987f7424bc54a60c663e92db42abdd3d`
Scope: implementation + `plan.md` consistency after systematic remediation

## Verdict

- `plan.md` internal consistency: `PASS`
- implementation vs `plan.md`: `PASS`
- prior open findings: `PASS` (all resolved or clarified as intentional policy)
- MCP local-cluster integration strictness (issue-20): `PASS` (5-node, strict timeout failure)

## Fixes Applied

1. MCP schedule sampling now matches plan/spec intent (`slots_in_epoch * count` sampling, per-slot disjoint windows).
- Evidence:
  - `ledger/src/leader_schedule_utils.rs`
  - `ledger/src/leader_schedule_cache.rs`

2. Invalid MCP shreds no longer fall through to legacy path for MCP-active slots.
- Evidence:
  - `core/src/window_service.rs`

3. Pre-activation forwarding fanout is capped to standard lookahead; MCP fanout preserved post-activation.
- Evidence:
  - `core/src/forwarding_stage.rs`

4. Vote-gate relay threshold excludes relays whose proposer entries are all invalid after signature filtering.
- Evidence:
  - `core/src/mcp_vote_gate.rs`

5. Relay-attestation dispatch retry behavior now matches naming and requirements.
- Added bounded retries and explicit drop counters (`full`/`closed`).
- Evidence:
  - `core/src/mcp_relay_submit.rs`

6. Reconstruction failures for vote-gate-included proposers now log at warning level.
- Evidence:
  - `core/src/mcp_replay.rs`

7. Constant-invariant coverage tightened.
- Added explicit test for `REQUIRED_RECONSTRUCTION == DATA_SHREDS_PER_FEC_BLOCK`.
- Evidence:
  - `ledger/src/mcp.rs`

8. `plan.md` tightened and synchronized with implementation.
- Clarified framing widths, slot-gate wording, schedule window mapping, dedup ordering sequence, nonce rent term, empty-result fork mismatch behavior, dependency order, file lists, and MCP-active-slot parser invariant.
- Evidence:
  - `plan.md`

## Clarified Policy (Intentional, Not a Blocker)

- Nonce Phase-A charging intentionally debits `base_fee + nonce_min_rent` exactly once and may reduce nonce fee payer to zero in Phase A; this matches current tests and plan wording.

## Tests Run

- `cargo check -p solana-core -p solana-ledger -p solana-runtime -p solana-turbine -p agave-transaction-view`
- `cargo test -p solana-ledger test_mcp_schedule_is_deterministic -- --nocapture`
- `cargo test -p solana-ledger test_mcp_schedule_length_scales_with_role_count -- --nocapture`
- `cargo test -p solana-ledger test_mcp_schedule_accessors_are_cached_and_sized -- --nocapture`
- `cargo test -p solana-ledger test_mcp_relay_schedule_handles_short_epoch_schedules -- --nocapture`
- `cargo test -p solana-ledger test_threshold_counts -- --nocapture`
- `cargo test -p solana-core test_relays_without_any_valid_proposer_entries_do_not_count -- --nocapture`
- `cargo test -p solana-core test_ingest_mcp_consensus_block_rejects_invalid_consensus_meta_length -- --nocapture`
- `cargo test -p solana-core test_maybe_finalize_consensus_block_from_relay_attestations -- --nocapture`
- `cargo test -p solana-core forwarding_stage::tests::test_forwarding -- --nocapture`
- `cargo test -p solana-core mcp_relay_submit::tests::test_attestation_roundtrip_and_signature_checks -- --nocapture`
- `cargo test -p solana-runtime collect_fees_only_for -- --nocapture`
- `cargo test -p solana-local-cluster test_local_cluster_mcp_produces_blockstore_artifacts -- --nocapture`

## Remaining Blockers

- `B-1` Strict no-fallback MCP replay is not fully enforced for pre-consensus-observation slots.
  - Current behavior: when MCP is active but no `ConsensusBlock` has been observed yet for a slot, replay may still use legacy entry-derived input as compatibility fallback.
  - This is the only remaining blocker to claim fully strict end-to-end MCP replay semantics for all MCP-active slots.
  - Evidence:
    - `plan.md` release blocker `Reconstruction-to-execution bridge reader: PARTIAL`
    - `plan.md` notes at `Reconstruction-to-execution bridge` (`v1 compatibility fallback`)
