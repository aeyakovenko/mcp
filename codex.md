# MCP Audit Snapshot (spec vs code)
- Repo: /home/anatoly/mcp
- Audit time: 2026-01-23T05:05:10Z
- Sources: `mcp_spec.md`, local code, GitHub issues (20 open items, includes PR #21)
- Trust level: assume lazy implementation; comments are not authoritative

## Verdict
- MCP is not implemented to spec and not fully wired into Agave.
- Only partial MCP shred handling runs (size-based detection and signature checks); consensus, replay, and voting remain unused.
- Multiple MCP wire formats exist in code and disagree with each other and the spec.

## Spec vs Implementation Gaps (hard mismatches)
- MCP shred format: spec requires fixed 1225-byte `McpShredV1` with `witness_len=8`; broadcast still sends legacy `Shred` bytes and MCP detection is length-based only.
  - Evidence: `turbine/src/broadcast_stage/standard_broadcast_run.rs`, `turbine/src/sigverify_shreds.rs`, `ledger/src/shred/mcp_shred.rs`.
- Merkle proof verification: spec requires witness verification before acceptance; sigverify has TODO, and `mcp_merkle` compares only truncated root bytes (not full root).
  - Evidence: `turbine/src/sigverify_shreds.rs`, `ledger/src/mcp_merkle.rs`.
- Relay attestation format: spec requires proposer signature per entry; `ledger/src/mcp_attestation.rs` omits it while `ledger/src/shred/mcp_shred.rs` defines a different attestation format.
  - Evidence: `ledger/src/mcp_attestation.rs`, `ledger/src/shred/mcp_shred.rs`, `core/src/mcp_consensus_block.rs`.
- Transaction format: spec defines `transaction_config_mask` in the transaction header and `target_proposer` as `u32`; code uses a separate config blob with `Pubkey` and does not wire parsing into SDK/runtime or fee calculation.
  - Evidence: `mcp_spec.md` §7, `ledger/src/mcp.rs`.
- Consensus payload/voting: spec defines `McpBlockV1`/`McpVoteV1` and implied block computation with signature checks; `core/src/mcp_consensus_block.rs` is unused and does not verify proposer signatures in `compute_implied_blocks`.
  - Evidence: `core/src/mcp_consensus_block.rs`, no call sites in `core/src/consensus.rs` or `core/src/replay_stage.rs`.
- Replay reconstruction: spec requires RS decode and commitment re-check; no replay pipeline uses MCP shreds or RS decoding.
  - Evidence: no references in `core/src/replay_stage.rs`.
- Storage schema: spec requires MCP block/attestation/reconstructed payload/execution output CFs; only MCP data/code shreds are stored and nothing writes consensus payload or execution output.
  - Evidence: `ledger/src/blockstore.rs`, `ledger/src/mcp_storage.rs`, `core/src/window_service.rs`.
- Committee selection: spec mandates per-slot rotation with sampling a new validator; code uses fixed pool rotation without per-slot new sampling.
  - Evidence: `ledger/src/leader_schedule.rs`, `mcp_spec.md` §3.3.
- Fee enforcement: spec requires MCP fee handling; `transaction_processor` only logs MCP fee insufficiency and proceeds.
  - Evidence: `svm/src/transaction_processor.rs`.

## Wiring Gaps (code exists but not connected)
- MCP shreds are stored by size in `window_service` but never used to reconstruct payloads or validate availability.
- MCP consensus block/vote types exist (`core/src/mcp_consensus_block.rs`) but are not invoked by consensus/voting/replay stages.
- MCP attestation formats exist but no relay sends attestations and no leader aggregates them.
- MCP fee-only replay path and fee breakdown types exist but are not part of replay execution.

## Issue-by-Issue Status (what is still missing)
- #21 PR Spec: spec file added, but code does not implement the wire formats or pipeline behavior described.
- #19 MCP-04 Transaction format: no SDK/runtime parsing or fee integration; `target_proposer` type mismatch.
- #18 MCP-16 Replay reconstruct: no RS decoding, no reconstruction pipeline.
- #17 MCP-15 Empty slots: no replay handling or execution output persistence.
- #16 MCP-14 Voting: MCP block validation/voting not wired; implied block validation lacks signature checks.
- #15 MCP-13 Consensus leader broadcast: no MCP block broadcast path in turbine.
- #14 MCP-12 Aggregate attestations: no relay attestation aggregation or threshold checks.
- #13 MCP-11 Relay submit attestations: no relay attestation send path; conflicting formats.
- #12 MCP-09 Relay verify shreds: Merkle proof verification missing; relay tracking structures unused.
- #11 MCP-07 Proposer distribute shreds: broadcast uses legacy shreds; no `McpShredV1` construction.
- #10 MCP-19 Bankless proposer/leader: no bankless integration in banking or replay.
- #9 MCP-10 Record attestation: MCP attestation CFs defined but not used.
- #8 MCP-17 Fee-only replay: fee phase types exist but not invoked in replay.
- #7 MCP-05 Proposer ID in shreds: legacy shred header changes exist, but MCP shreds are separate and never generated.
- #6 MCP-08 Fee payer check: validation only logs warning; per-slot commitment tracker unused.
- #5 MCP-02 Schedules: algorithm does not match spec sampling rule; only partially used for IDs.
- #4 MCP-01 Constants: duplicated across crates, not derived from genesis/config.
- #3 MCP-06 Encode/commit: RS encoding and Merkle commitment generation missing.
- #2 MCP-03 Blockstore: MCP CFs partially defined; no consensus/execution payload storage or alternate block versions.
- #1 MCP-18 Ordered output: no deterministic ordering logic wired into replay.

## Immediate High-Risk Bugs
- Invalid MCP shreds can pass signature checks without Merkle validation and still be stored.
- Multiple, incompatible attestation formats can lead to silent drift between components.
- Transaction format mismatches will break clients that implement the spec.

## Commands Run
- `curl -sL "https://api.github.com/repos/anza-xyz/mcp/issues?state=open&per_page=100"`
- `python3 - <<'PY' ... PY` (issue list)
- `date -u +"%Y-%m-%dT%H:%M:%SZ"`
