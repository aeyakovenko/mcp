# Codex Audit: anza-xyz/mcp implementation worktree
- Local repo root: /home/anatoly/mcp
- Current branch: master
- Upstream: https://github.com/anza-xyz/mcp
- Upstream default branch: master (via `git remote show upstream`)
- Audit mode: assume adversarial/lazy author
<!-- CODEX_LAST_AUDITED: 939aeba6dedf1bf7427647b2e4bc83a17ffe9cfd -->
- Last updated: 2026-01-22T13:52:31Z

## Latest Summary (most recent iteration)
- New commits audited this iteration: 0
- Highest risk finding: treating `mcp_spec.md` as source of truth exposes multiple code deviations (schedule selection, block_id derivation, tx ordering, shred header offsets), all of which are consensus-critical.
- Test status: `cargo fmt --check` failed due to nightly-only rustfmt options and formatting diffs; clippy/test not run.
- Issue coverage snapshot: 19 open issues fetched (unauthenticated GitHub API, first page only; no pagination). No new commits.

## Issue Map (Open upstream issues)
- #19: MCP-04 Transaction: update transaction format [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:39Z
  - Evidence of work in this repo: e08adc174b
  - Notes: Adds config struct only; no integration with transaction/message parsing or fee calculation.
- #18: MCP-16 Replay: reconstruct messages from shreds [Replay] — status: OPEN — last updated: 2026-01-21T15:46:33Z
  - Evidence of work in this repo: a9f217887f
  - Notes: Reconstruction is a skeleton; no erasure coding or commitment verification implemented.
- #17: MCP-15 Replay: handle empty slots [Replay] — status: OPEN — last updated: 2026-01-21T15:46:32Z
  - Evidence of work in this repo: a9f217887f
  - Notes: Defines types/serialization only; no replay-stage integration.
- #16: MCP-14 Voting: validate and vote on blocks [-] — status: OPEN — last updated: 2026-01-21T15:46:30Z
  - Evidence of work in this repo: 19c13464f1
  - Notes: Uses local constants and placeholder block_id computation; not integrated with real payload.
- #15: MCP-13 Consensus Leader: broadcast block via turbine [Consensus] — status: OPEN — last updated: 2026-01-21T15:46:28Z
  - Evidence of work in this repo: 19c13464f1
  - Notes: Broadcast format defined but not wired into turbine.
- #14: MCP-12 Consensus Leader: aggregate relay attestations [Consensus] — status: OPEN — last updated: 2026-01-21T15:46:27Z
  - Evidence of work in this repo: a7414945f4
  - Notes: Aggregator does not verify signatures; assumes caller does.
- #13: MCP-11 Relay: submit attestations to leader [Relay] — status: OPEN — last updated: 2026-01-21T15:46:26Z
  - Evidence of work in this repo: a7414945f4
  - Notes: Wire format duplicates ledger module, risk of drift.
- #12: MCP-09 Relay: process and verify shreds [Relay] — status: OPEN — last updated: 2026-01-21T15:45:44Z
  - Evidence of work in this repo: 49f680818b
  - Notes: Merkle proof verification uses shred index, not relay index; relay assignment checks are absent.
- #11: MCP-07 Proposer: distribute shreds to relays [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:42Z
  - Evidence of work in this repo: ac77f71f73
  - Notes: Signing only commitment/slot/proposer; no binding to shred index or relay.
- #10: MCP-19 Proposer: Bankless Leader/proposer [Proposer] — status: OPEN — last updated: 2026-01-21T15:46:36Z
  - Evidence of work in this repo: 19c13464f1
  - Notes: No signature verification or bounds checks in bankless recording.
- #9: MCP-10 Relay: record attestation [Relay] — status: OPEN — last updated: 2026-01-21T15:46:14Z
  - Evidence of work in this repo: 5c682d6104
  - Notes: Storage format exists but not wired to blockstore columns.
- #8: MCP-17 Replay: do an initial pass to deduct fees before applying state transitions [Replay] — status: OPEN — last updated: 2026-01-21T15:46:34Z
  - Evidence of work in this repo: 7b74e1891d
  - Notes: Fee phase implemented in isolation; not integrated with execution pipeline.
- #7: MCP-05 Proposer: add proposerID to the shred format [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:40Z
  - Evidence of work in this repo: 3b37551c44
  - Notes: Critical offset mismatches in parsing; legacy shreds likely broken.
- #6: MCP-08 Proposer: update fee payer check to Address/test DA fee payer attacks [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:43Z
  - Evidence of work in this repo: c081d11574
  - Notes: Over-commit check ignores NUM_PROPOSERS requirement; not integrated.
- #5: MCP-02 Setup: Proposer, Relay and Leader schedule [Setup] — status: OPEN — last updated: 2026-01-21T15:45:36Z
  - Evidence of work in this repo: bdcf8c135d
  - Notes: Sampling with replacement allows duplicate validators per slot.
- #4: MCP-01 Setup: protocol constants [Setup] — status: OPEN — last updated: 2026-01-21T15:45:35Z
  - Evidence of work in this repo: 938bdaa693
  - Notes: Constants not wired into other modules; many duplicates in other crates.
- #3: MCP-06 Proposer: encode and commit [Proposer] — status: OPEN — last updated: 2026-01-21T15:45:41Z
  - Evidence of work in this repo: af5949c9e4
  - Notes: Constants only; shredder/merkle logic not updated to use MCP FEC.
- #2: MCP-03 Setup: Adjust blockstore to handle multiple proposers and execution consensus seperation. [Setup,Replay] — status: OPEN — last updated: 2026-01-21T15:45:38Z
  - Evidence of work in this repo: 39005c6fe5
  - Notes: CFs added but blockstore read/write paths not updated.
- #1: MCP-18 Replay: output ordered transactions [Replay] — status: OPEN — last updated: 2026-01-21T15:46:35Z
  - Evidence of work in this repo: a9f217887f
  - Notes: Ordering logic exists but not wired into replay stage.

## Commit-by-commit audit (chronological)
### 938bdaa693 — MCP-01: Add McpConfig with protocol constants
- Claimed intent: Centralize MCP protocol constants and config.
- Suspected upstream issue(s): #4
- Files changed: `ledger/src/mcp.rs`
- What actually changed (brief, concrete): New constants + `McpConfig` container; no usage elsewhere.
- Red flags / potential defects:
  - Constants duplicated later in other crates (core/turbine/svm) instead of using `McpConfig`, causing drift risk.
- Security considerations: None directly; misconfiguration risk if constants diverge.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Thread `McpConfig` through consensus/relay/replay paths and remove duplicate constants.

### bdcf8c135d — MCP-02: Implement proposer and relay schedules
- Claimed intent: Stake-weighted schedule with rotation for proposers/relays.
- Suspected upstream issue(s): #5
- Files changed: `ledger/src/mcp_schedule.rs`, `ledger/src/mcp_schedule_cache.rs`
- What actually changed: Adds schedule generation and caching using `WeightedIndex` sampling.
- Red flags / potential defects:
  - Sampling with replacement allows duplicate validators within a slot (`ledger/src/mcp_schedule.rs:322`), violating “unique proposer_id” assumptions and returning arbitrary first match (`ledger/src/mcp_schedule.rs:89`).
  - Test `test_proposer_relay_schedules_differ` is a no-op (compares lengths 16 vs 200) (`ledger/src/mcp_schedule.rs:392`).
- Security considerations: Duplicate scheduling could be abused to concentrate proposer slots.
- Test impact: Weak/ineffective tests; does not validate uniqueness.
- Verdict (Risk/Confidence/Status): HIGH / MED / Incorrect
- Recommended follow-ups: Use sampling without replacement and add explicit uniqueness tests for each slot.

### 39005c6fe5 — MCP-03: Add blockstore columns for multiple proposers
- Claimed intent: New CFs to support multi-proposer shreds and consensus/execution separation.
- Suspected upstream issue(s): #2
- Files changed: `ledger/src/blockstore/column.rs`, `ledger/src/blockstore_db.rs`, `ledger/src/lib.rs`
- What actually changed: Adds column families and key serialization only.
- Red flags / potential defects:
  - No read/write integration in blockstore paths; schema is unused and acceptance criteria are unmet.
- Security considerations: New CFs can bloat DB without serving functionality.
- Test impact: None.
- Verdict (Risk/Confidence/Status): MED / HIGH / Incomplete
- Recommended follow-ups: Wire new CFs into `blockstore.rs` and window service; add migration/compat notes.

### 3b37551c44 — MCP-05: Add proposer_id to shred common header
- Claimed intent: Add proposer_id to shred header and update offsets.
- Suspected upstream issue(s): #7
- Files changed: `ledger/src/shred.rs`, `ledger/src/shred/merkle.rs`, `ledger/src/shred/wire.rs`
- What actually changed: Header size increased by 1, new proposer_id field; some offsets updated.
- Red flags / potential defects:
  - Offsets still use legacy positions in merkle root calculations (`ledger/src/shred/merkle.rs:200`, `ledger/src/shred/merkle.rs:256`), breaking merkle verification/erasure indexing.
  - `get_reference_tick` reads byte 85 (legacy) while `get_flags` moved to 86 (`ledger/src/shred/wire.rs:203`).
  - `get_proposer_id` returns byte 79 for legacy shreds; that byte belongs to `fec_set_index`, not proposer_id (`ledger/src/shred/wire.rs:109`).
  - `get_common_header_bytes` always slices 84 bytes; legacy shreds used by dedup (`turbine/src/retransmit_stage.rs:212`) will be mis-keyed.
- Security considerations: Consensus-critical parsing inconsistencies can cause signature/merkle verification bypass or false failures.
- Test impact: No tests cover legacy/MCP compatibility or merkle offsets.
- Verdict (Risk/Confidence/Status): CRITICAL / HIGH / Incorrect
- Recommended follow-ups: Update all offsets consistently; add explicit legacy/MCP regression tests; ensure dedup uses correct header length.

### af5949c9e4 — MCP-06: Add MCP FEC rate constants (40 data + 160 coding)
- Claimed intent: Introduce MCP FEC constants and merkle proof size.
- Suspected upstream issue(s): #3
- Files changed: `ledger/src/shred.rs`, `ledger/src/shred/merkle_tree.rs`
- What actually changed: Adds constants only.
- Red flags / potential defects:
  - No integration with shredder/merkle encoding paths; constants are unused.
- Security considerations: None directly; but gives false sense of MCP FEC support.
- Test impact: None.
- Verdict (Risk/Confidence/Status): MED / HIGH / Incomplete
- Recommended follow-ups: Wire constants into shred creation/verification and update proof sizing logic.

### e08adc174b — MCP-04: Add MCP transaction config format with inclusion_fee and ordering_fee
- Claimed intent: Add transaction config and fee helpers.
- Suspected upstream issue(s): #19
- Files changed: `ledger/src/mcp.rs`
- What actually changed: Adds a `transaction` module with config mask serialization and fee helpers.
- Red flags / potential defects:
  - Not integrated into actual transaction/message parsing or `solana_fee::calculate_fee_details` as required by issue acceptance.
  - `target_proposer` is a `Pubkey` rather than a proposer ID (issue text suggests proposer targeting by ID).
- Security considerations: None, but parsing inconsistencies likely if clients implement differently.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / HIGH / Incomplete
- Recommended follow-ups: Implement wire integration in message/transaction crates and clarify `target_proposer` type.

### 5c682d6104 — MCP-10: Add relay attestation wire format and storage
- Claimed intent: Deterministic attestation wire format.
- Suspected upstream issue(s): #9
- Files changed: `ledger/src/lib.rs`, `ledger/src/mcp_attestation.rs`
- What actually changed: New attestation struct + serialization helpers.
- Red flags / potential defects:
  - Core uses a different attestation message format (`core/src/mcp_attestation_service.rs`), risking diverging encodings.
- Security considerations: Format drift can cause signature failures or acceptance mismatches across components.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Consolidate attestation format and reuse this module across core/turbine.

### c081d11574 — MCP-08: Add MCP fee payer validation to prevent DA attacks
- Claimed intent: Prevent fee payer overcommit in multi-proposer scenario.
- Suspected upstream issue(s): #6
- Files changed: `svm/src/mcp_fee_payer.rs`, `svm/src/lib.rs`
- What actually changed: Validator/tracker types, balance checks.
- Red flags / potential defects:
  - `SlotFeePayerTracker::can_commit` caps by spendable balance, not by `NUM_PROPOSERS * fee`, undermining the stated protection model.
  - Not integrated into transaction processing path.
- Security considerations: Under-enforcement enables DA griefing; over-enforcement can reject valid txs.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Align commitment logic with protocol requirement and wire into fee payer validation path.

### 49f680818b — MCP-09: Add relay shred processing and verification
- Claimed intent: Verify proposer shreds and track for attestation.
- Suspected upstream issue(s): #12
- Files changed: `turbine/src/mcp_relay.rs`, `turbine/src/lib.rs`
- What actually changed: New relay processing/verification structs.
- Red flags / potential defects:
  - Merkle proof verification uses `shred_index`, not relay index, while comments imply relay index verification (`turbine/src/mcp_relay.rs:263`). This fails to enforce relay assignment and enables arbitrary relays to claim any shred.
  - No constraints on witness size; could be used for memory/CPU DoS.
- Security considerations: Weak relay assignment checks enable spam and equivocation ambiguity.
- Test impact: Unit tests do not cover merkle proof correctness.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Define proof format explicitly, include relay index in validation, and bound witness size.

### ac77f71f73 — MCP-07: Add proposer shred distribution to relays
- Claimed intent: Proposers distribute shreds with commitments.
- Suspected upstream issue(s): #11
- Files changed: `turbine/src/mcp_proposer.rs`, `turbine/src/lib.rs`
- What actually changed: New distribution structs and serialization.
- Red flags / potential defects:
  - Signature covers only (slot, proposer_id, commitment); no binding to shred index or witness, enabling replay of stale commitments across shreds.
  - Relay selection is `idx % NUM_RELAYS`, with no scheduling tie-in.
- Security considerations: Ambiguous binding between shred and signature; potential replay/mix-up.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Include shred index in signed data and integrate with relay schedule.

### a7414945f4 — MCP-11/MCP-12: relay attestation submission and aggregation
- Claimed intent: Relay attestation submission and leader aggregation with equivocation detection.
- Suspected upstream issue(s): #13, #14
- Files changed: `core/src/mcp_attestation_service.rs`, `core/src/lib.rs`
- What actually changed: New wire format and aggregation logic.
- Red flags / potential defects:
  - `AttestationAggregator::add_attestation` does not verify relay signatures or relay_id validity; assumes caller did (`core/src/mcp_attestation_service.rs:170`).
  - Duplicate wire formats vs `ledger/src/mcp_attestation.rs`.
  - Attestation threshold uses stake of relays that submitted anything, not proposer-specific stake thresholds.
- Security considerations: Aggregator can be fed forged attestations if verification is skipped.
- Test impact: Unit tests only; no negative tests for signature failures.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Enforce signature verification inside aggregator and unify attestation format.

### 7b74e1891d — MCP-17: fee-only replay pass before state transitions
- Claimed intent: Two-phase fee charging with unconditional inclusion fees.
- Suspected upstream issue(s): #8
- Files changed: `svm/src/mcp_fee_replay.rs`, `svm/src/lib.rs`
- What actually changed: Fee phase structs; `execute_fee_phase` deducts all fees.
- Red flags / potential defects:
  - `conditional_fees` vs `unconditional_fees` is defined but unused; fee phase charges all fees regardless, which may contradict intended policy.
  - No integration into replay/execution pipeline.
- Security considerations: Charging policy ambiguity can cause consensus divergence.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Clarify fee policy and integrate with actual transaction processing.

### a9f217887f — MCP-15/16/18: replay components for empty slots, reconstruction, ordering
- Claimed intent: Replay stage structures for empty slots, reconstruction, ordering.
- Suspected upstream issue(s): #17, #18, #1
- Files changed: `core/src/mcp_replay.rs`, `core/src/lib.rs`
- What actually changed: Type definitions and local algorithms; no integration.
- Red flags / potential defects:
  - Reconstruction uses `total_shreds * 20%` without validating erasure coding or commitments.
  - Ordering assumes proposer IDs 0..15 and ignores proposer schedule or target proposer constraints.
- Security considerations: Placeholder logic can lead to mismatched ordering rules across nodes.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): MED / MED / Suspicious
- Recommended follow-ups: Implement real reconstruction and integrate with replay stage pipeline.

### 19c13464f1 — MCP-13/14/19: consensus broadcast, voting, bankless proposer
- Claimed intent: Consensus payload broadcast, block validation/voting, bankless leader.
- Suspected upstream issue(s): #15, #16, #10
- Files changed: `core/src/mcp_bankless.rs`, `core/src/mcp_consensus_broadcast.rs`, `core/src/mcp_voting.rs`, `core/src/lib.rs`
- What actually changed: New wire formats and validation structs.
- Red flags / potential defects:
  - `BlockValidator::compute_block_id` hashes slot + proposer roots, but `ConsensusPayload::block_id` hashes payload data; mismatch can cause vote disagreement (`core/src/mcp_voting.rs:236`).
  - `BanklessBatch::deserialize` trusts `tx_len` and allocates without bounds; potential memory DoS for malformed input (`core/src/mcp_bankless.rs:86`).
  - Signature verification is not enforced in `BanklessRecorder`; `RecordingStatus::InvalidSignature` is never reachable.
  - Constants duplicated (NUM_PROPOSERS/RELAYS and CONSENSUS_PAYLOAD_PROPOSER_ID) across core/ledger, no shared source.
- Security considerations: Divergent block_id computation and unbounded allocations can cause consensus or DoS issues.
- Test impact: Unit tests only.
- Verdict (Risk/Confidence/Status): HIGH / MED / Suspicious
- Recommended follow-ups: Unify block_id derivation, add size limits for deserialization, and wire signature checks.

### 2952d2ec84 — Add comprehensive MCP protocol specification
- Claimed intent: Consolidate all MCP issues into a single, unambiguous specification and declare implementation complete.
- Suspected upstream issue(s): References all MCP-01..MCP-19 items implicitly.
- Files changed: `mcp_spec.md`
- What actually changed (brief, concrete): Adds a 624-line specification document describing constants, wire formats, schedules, and role flows.
- Red flags / potential defects:
  - The spec asserts “Implementation Complete” while multiple subsystems are placeholders or unintegrated (see earlier commit audits); this is misleading and risks being used as authoritative guidance (`mcp_spec.md:4`).
  - Schedule generation described as a deterministic stake-weighted shuffle without replacement, but implementation uses `WeightedIndex` sampling with replacement in `ledger/src/mcp_schedule.rs:322`, enabling duplicate validators per slot (`mcp_spec.md:105`).
  - Transaction config layout is shown with fixed offsets (1-8, 9-16, 17-48), but the actual serialization is mask-ordered and variable-length in `ledger/src/mcp.rs`, so offsets depend on which bits are set; spec is ambiguous and incorrect (`mcp_spec.md:247`).
  - Proposer ordering rule uses “arrival time” as a tie-breaker, which is non-deterministic across validators and conflicts with the determinism requirement in Appendix B (`mcp_spec.md:283`, `mcp_spec.md:616`).
  - Block ID derivation references “canonical_aggregate_bytes” but never defines the canonical serialization of `SlotAggregate` or `ConsensusMeta`; the spec is incomplete and not executable (`mcp_spec.md:361`, `mcp_spec.md:514`).
  - Shred distribution to relays is underspecified (no mapping from shred index to relay_id, no rule for which relay receives which shred), making protocol behavior ambiguous (`mcp_spec.md:298`).
  - Fee payer requirements state `NUM_PROPOSERS * total_fee` for all account types but current code does not enforce this; the spec overstates implemented security guarantees (`mcp_spec.md:456`).
- Security considerations: A misleading spec can normalize unsafe or divergent behavior, making consensus bugs harder to detect during review and testing.
- Test impact: Documentation-only change; no tests updated.
- Verdict (Risk/Confidence/Status): MED / HIGH / Suspicious
- Recommended follow-ups: Mark the spec as draft or explicitly align it with current code; reconcile differences (schedules, fee rules, transaction config layout, block_id derivation) and link to tracking issues.

### 939aeba6de — Fix MCP specification accuracy and clarity
- Claimed intent: Correct MCP specification inaccuracies and clarify deterministic rules.
- Suspected upstream issue(s): References all MCP-01..MCP-19 items implicitly.
- Files changed: `mcp_spec.md`
- What actually changed (brief, concrete): Marks spec as draft, clarifies variable-length transaction config, defines canonical block_id serialization, adds relay assignment rule, replaces arrival-time tie-breaker with tx hash, adds unique selection note for schedules.
- Red flags / potential defects:
  - Schedule section now mandates “without replacement” selection and `role_magic` in the seed, but implementation uses `WeightedIndex` sampling with replacement and no role-specific seed (`ledger/src/mcp_schedule.rs:322`), so spec still conflicts with code.
  - Block_id derivation now matches consensus payload serialization, but `core/src/mcp_voting.rs` still computes block_id from a different input; spec/code divergence remains.
  - Relay assignment rule (`shred_index % NUM_RELAYS`) matches current proposer helper, but the spec still omits how this maps to the stake-weighted relay schedule (the rule ignores schedule ordering).
  - “Order by transaction hash” is a new deterministic rule but no code enforces ordering in bankless batch assembly; spec risks becoming aspirational rather than authoritative.
  - “Witness max 8 entries” is stated in the message format, but no limit is enforced in relay parsing, so the spec is not backed by code.
- Security considerations: Spec/code mismatches can lead to inconsistent third-party implementations and hidden consensus failures.
- Test impact: Documentation-only change; no tests updated.
- Verdict (Risk/Confidence/Status): MED / HIGH / Suspicious
- Recommended follow-ups: Align schedule selection and block_id computation across code and spec; document or remove relay assignment if not enforced by schedule; add explicit serialization limits for witnesses or remove the constraint.

## Cross-cutting concerns (delta vs upstream)
- Behavioral changes that span commits:
  - Widespread constant duplication (NUM_PROPOSERS/RELAYS, CONSENSUS_PAYLOAD_PROPOSER_ID) across crates; risks drift and inconsistent behavior.
  - Many commits define types/serialization without integrating into actual pipeline (blockstore, turbine, replay, fee processing).
  - `mcp_spec.md` is now labeled draft but still contains rules that conflict with code (schedules, voting block_id), so external implementations remain at risk.
- Spec-as-source-of-truth deviations (code is buggy where it diverges):
  - Schedule selection without replacement and role-specific seed are required, but code uses `WeightedIndex` sampling with replacement and no `role_magic` (`mcp_spec.md:100`, `ledger/src/mcp_schedule.rs:322`).
  - Shred common header offsets require `fec_set_index` at bytes 80-83, but `ledger/src/shred/merkle.rs` still reads 79-83, so MCP header parsing is inconsistent with spec (`mcp_spec.md:219`, `ledger/src/shred/merkle.rs:200`).
  - Block ID must be derived from canonical consensus payload bytes, but `core/src/mcp_voting.rs` derives it from proposer roots instead of payload serialization (`mcp_spec.md:374`, `core/src/mcp_voting.rs:249`).
  - Proposer ordering must sort by ordering_fee then tx hash; bankless recorder preserves input order only (`mcp_spec.md:289`, `core/src/mcp_bankless.rs:96`).
  - Witness length must be capped at 8 entries (200 shreds), but relay parsing accepts unbounded witness sizes (`mcp_spec.md:324`, `turbine/src/mcp_relay.rs:268`).
  - Fee payer balance must cover `NUM_PROPOSERS * total_fee`, but `svm/src/mcp_fee_payer.rs` only checks spendable balance and is not integrated into execution, violating spec (`mcp_spec.md:482`, `svm/src/mcp_fee_payer.rs:94`).
  - Replay reconstruction must use Reed-Solomon and verify commitments; `core/src/mcp_replay.rs` uses threshold logic without erasure recovery or merkle verification (`mcp_spec.md:437`, `core/src/mcp_replay.rs:88`).
  - Relay attestation aggregation must verify relay signatures; `core/src/mcp_attestation_service.rs` assumes verification elsewhere (`mcp_spec.md:365`, `core/src/mcp_attestation_service.rs:170`).
- API compatibility concerns:
  - Shred header size change not consistently handled; legacy shreds and merkle offsets are inconsistent.
- Dependency changes:
  - No new dependencies; new modules use existing crates.
- Performance/regression risks:
  - Unbounded allocation in deserializers (bankless batches, relay messages) and large witness vectors without limits.
  - Schedule generation may produce duplicate proposers/relays per slot.

## Commands run + results (this iteration)
- `git rev-parse --show-toplevel`
  - Result: /home/anatoly/mcp
- `git status --porcelain=v1`
  - Result: `?? codex.md`
- `git branch --show-current`
  - Result: master
- `git remote -v`
  - Result: origin set; upstream added
- `git fetch upstream --prune`
  - Result: success
- `curl -sL "https://api.github.com/repos/anza-xyz/mcp/issues?state=open&per_page=100"`
  - Result: fetched 19 open issues (unauthenticated)
- `git rev-list --reverse 19c13464f132644cea6ce91043b69d589cf7e7f2..HEAD`
  - Result: 1 new commit (2952d2ec84)
- `git show --name-status --stat 2952d2ec84d311cff8f997c5116183fd261f7c18`
  - Result: adds `mcp_spec.md` (624 lines)
- `git show 2952d2ec84d311cff8f997c5116183fd261f7c18`
  - Result: documentation-only spec; no code changes
- `git diff --stat upstream/master..HEAD`
  - Result: 24 files changed, 6586 insertions, 11 deletions
- `git diff upstream/master..HEAD | rg -n "TODO|FIXME|HACK|unwrap\(|expect\(|panic!|unsafe|allow\(|deny\(|skip|ignored|only\s+in\s+test|password|token|secret"`
  - Result: no high-risk patterns beyond test unwraps and column key parsing
- `cargo fmt --check`
  - Result: failed; nightly rustfmt options unsupported and formatting diffs reported
- `git fetch --all --prune`
  - Result: success
- `rg -o --no-line-number "<!-- CODEX_LAST_AUDITED: ([0-9a-f]+) -->" -r '$1' codex.md | tail -n 1`
  - Result: 939aeba6dedf1bf7427647b2e4bc83a17ffe9cfd
- `git rev-list --reverse 939aeba6dedf1bf7427647b2e4bc83a17ffe9cfd..HEAD`
  - Result: no new commits
- `rg -n "" mcp_spec.md`
  - Result: re-scanned spec for correctness/completeness
- `rg -n "" mcp_spec.md`
  - Result: re-scanned spec for correctness/completeness
- `git fetch --all --prune`
  - Result: success
- `curl -sL "https://api.github.com/repos/anza-xyz/mcp/issues?state=open&per_page=100"`
  - Result: refreshed open issues (unauthenticated)
- `git rev-list --reverse 2952d2ec84d311cff8f997c5116183fd261f7c18..HEAD`
  - Result: 1 new commit (939aeba6de)
- `git show --name-status --stat 939aeba6dedf1bf7427647b2e4bc83a17ffe9cfd`
  - Result: `mcp_spec.md` updated
- `git show 939aeba6dedf1bf7427647b2e4bc83a17ffe9cfd`
  - Result: documentation-only update; no code changes
- `git diff --stat upstream/master..HEAD`
  - Result: 24 files changed, 6625 insertions, 11 deletions
- `git diff upstream/master..HEAD | rg -n "TODO|FIXME|HACK|unwrap\(|expect\(|panic!|unsafe|allow\(|deny\(|skip|ignored|only\s+in\s+test|password|token|secret"`
  - Result: no high-risk patterns beyond test unwraps and column key parsing
- `cargo fmt --check`
  - Result: failed; nightly rustfmt options unsupported and formatting diffs reported
