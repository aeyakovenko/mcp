MCP plan review — spec+code reality check and minimized plan v2 (2026-02-03)

A) Executive summary of high/critical issues (with evidence)

Critical
1) Transaction wire format mismatch (spec §3.1/§7.1 vs plan uses Solana txs)
- Evidence: spec requires Transaction message as in §7.1 (custom layout) — docs/src/proposals/mcp-protocol-spec.md:126-127, 280-318.
- Plan explicitly uses standard Solana wire format — plan.md:87-105 ("PENDING SPEC AMENDMENT"), plan.md:93-95.
- Impact: Any strict spec implementation will reject MCP payloads; client/tooling changes required. Must either amend spec or implement §7.1 format.

2) Block_id derivation violates spec requirement
- Evidence: spec says block_id is the underlying ledger commitment carried in consensus_meta (not hash of aggregate) — docs/src/proposals/mcp-protocol-spec.md:189-198, 383-395.
- Plan sets consensus_meta=SHA256(slot||leader_index||aggregate_hash) — plan.md:346-354.
- Impact: Votes will not match ledger rules; may cause consensus divergence. Must align with ledger commitment semantics or explicitly mark as temporary fork-only placeholder (UNVERIFIED).

High
3) Ordering_fee source mismatch
- Evidence: spec defines ordering_fee as explicit TransactionConfigMask bit (config value) — docs/src/proposals/mcp-protocol-spec.md:286-303, 340-347, 208-219.
- Plan derives ordering_fee from compute_unit_price (Solana compute budget) — plan.md:108-109, 634-637, 740-742.
- Impact: Ordering may be non-compliant even if tx format is amended; must implement spec field or amend spec.

4) Delayed bankhash warmup behavior not defined in spec
- Evidence: spec requires delayed_bankhash verified against delayed slot defined by consensus protocol — docs/src/proposals/mcp-protocol-spec.md:189-193, 202-206.
- Plan allows Hash::default() when delayed slot not frozen — plan.md:356-362, 402-406.
- Impact: Safety assumption; needs explicit spec/consensus rule or validator must refuse to vote if delayed hash unavailable.

---

1) SPEC ↔ PLAN CONSISTENCY CHECK (table)

| Plan section | Spec anchor | Correct? | Exact correction if not | Reason |
|---|---|---|---|---|
| Pass 1.2 Transaction payload (standard Solana txs) | §3.1, §7.1 | NO | Either implement §7.1 Transaction format or amend spec to permit legacy Solana txs for MCP v1 | Spec mandates §7.1 layout for each tx bytes value; plan uses legacy format |
| Pass 1.2 ordering_fee derived from compute_unit_price | §3.6, §7.1 | NO | Parse ordering_fee from TransactionConfigMask bit1 value (or amend spec to map compute_unit_price→ordering_fee) | ordering_fee is a distinct field in spec |
| Pass 1.2 MAX_PROPOSER_PAYLOAD=40*863 | §3.2, §4 | PARTIAL | Keep k*SHRED_DATA_BYTES bound but note spec’s bound is looser; ensure encoder enforces k=DATA_SHREDS_PER_FEC_BLOCK | Spec says batch MUST NOT exceed NUM_RELAYS*SHRED_DATA_BYTES; k=40 implies tighter bound |
| Pass 1.3 Merkle tree | §6 | YES | — | Correct prefixes, SHA-256, 32-byte witness entries |
| Pass 1.4 MCP shred wire format | §7.2 | YES (with missing check) | Enforce witness_len == ceil(log2(NUM_RELAYS)) at parse time | Spec requires witness_len match implied Merkle proof length |
| Pass 2 schedule generation | §5 | YES | — | Domain separation + same stake set + wraparound windows |
| Pass 3 sigverify partition | §3.3, §7.2 | YES | — | Must reject invalid signature/witness before storage |
| Pass 4 relay attestation | §3.3, §7.3 | PARTIAL | Enforce entries sorted by proposer_index and no duplicates; reject invalid ordering/dupes on parse | Spec mandates sorted unique entries |
| Pass 6 leader aggregation | §3.4, §7.4 | PARTIAL | Enforce relay_entries sorted by relay_index; enforce per-relay entries sorted by proposer_index; drop invalid entries | Spec mandates ordering; plan doesn’t specify validation |
| Pass 6 threshold handling | §3.4 | YES | — | Leader SHOULD submit empty if < threshold; validators MUST treat below threshold invalid |
| Pass 7 vote gate equivocation | §3.5 | YES | — | Exclude proposer with multiple commitments |
| Pass 7 vote gate invalid relay entries | §3.5 | YES | — | Ignore invalid entries, keep valid |
| Pass 7 reconstruct/execute | §3.6, §8 | PARTIAL | Explicitly ensure per-payer cumulative fee tracking is per-slot and deterministic across forks | Spec requires two-pass fee handling and cumulative per payer |
| Pass 7 consensus_meta/block_id | §3.4, §7.5 | NO | Provide consensus_meta consistent with ledger rules (bank hash/ledger commitment), not aggregate hash | Spec forbids aggregate-hash-derived block_id |
| Pass 7 delayed_bankhash | §3.5 | NO (assumption) | Either define consensus rule for unavailable delayed slot or reject vote | Spec does not allow Hash::default() exception |

---

2) CODEBASE REALITY CHECK (Agave)

2a) Line references that don’t match current code (corrected)
- plan.md (NOT reusable table) cites `ledger/src/merkle_tree.rs:37/100/108` and `MERKLE_HASH_PREFIX_*` at `merkle_tree.rs:17-18` — file does not exist. Correct file is `ledger/src/shred/merkle_tree.rs` (prefixes at `ledger/src/shred/merkle_tree.rs:17-18`, join_nodes at `ledger/src/shred/merkle_tree.rs:100`, get_merkle_root at `ledger/src/shred/merkle_tree.rs:108`).
- plan.md references `runtime/src/bank/account_loader.rs:370` for `validate_fee_payer()` — correct file is `svm/src/account_loader.rs:370`.

2b) Over-engineered changes (can be simpler / lower diff)
1) New MCP socket tag + new QUIC server thread
- Existing QUIC server `solQuicAlpglw` already bound via `TvuSockets.alpenglow_quic` — core/src/tvu.rs:258-273.
- Minimal-diff option: multiplex MCP messages on the existing alpenglow QUIC socket and dispatch by 1-byte type prefix, avoiding new ContactInfo socket tag and node/socket plumbing. This is consistent with “single multiplexed socket” goal; change is isolated to server dispatch and handler routing.

2) ConsensusBlock recovery protocol (request/response)
- Adds new message types and caching logic. If acceptable, recovery can reuse existing repair/cluster slot info by broadcasting multiple times at deadline + N retries (same QUIC broadcast) and rely on gossip for peer discovery. That removes request/response complexity. If reliability required, keep but ensure caching interface is tiny.

2c) Under-specified parts (must clarify to avoid ambiguity)
- Deadline computation: define clock source and slot start (e.g., PoH tick height to wallclock mapping or bank slot timing). Otherwise relays/leaders will diverge on when to send attestations.
- Relay index ownership with duplicates: explicitly handle multiple indices per relay identity when validating “relay’s own index” rule; must accept shreds for all owned indices.
- Parsing rules: reject RelayAttestation/AggregateAttestation with unsorted or duplicate indices (spec required). Define whether leader/validator drops entire message or just invalid entries.
- Consensus block_id semantics: must be tied to actual ledger commitment. If Alpenglow defines block_id, specify the exact bytes in consensus_meta and how validators verify it.
- MCP shred detection: `is_mcp_shred_packet()` must be unambiguous and constant-time-ish. Specify exact header/length checks to avoid false positives on Agave shreds or other packet types.
- Witness length: enforce `witness_len == ceil(log2(NUM_RELAYS))` (8) at parse time to avoid ambiguity and inconsistent verification.

---

3) MINIMAL DIFF ARCHITECTURE REWRITE — Plan v2 (shorter, same pass structure)

Pass 1 — Feature gate + types + MCP Merkle + MCP shred (NO behavior change)
- Gate all MCP paths by `feature_set::mcp_protocol_v1::id()` at the listed locations.
- Add `ledger/src/mcp.rs` constants + wire types + helper functions:
  - Constants: NUM_PROPOSERS=16, NUM_RELAYS=200, DATA_SHREDS=40, CODING_SHREDS=160, SHRED_DATA_BYTES=863, thresholds (ceil to 120/80/40).
  - `McpPayload` = u32 count + (u32 len + tx bytes)... ; ignore trailing zero padding (§3.1).
  - `RelayAttestation`, `AggregateAttestation`, `ConsensusBlock` serialize exactly per §7.3–§7.5 and reject unknown version.
  - **Spec deviation (UNVERIFIED)**: If using legacy Solana txs, explicitly document amendment required; otherwise implement §7.1 Transaction format and use ordering_fee from TransactionConfigMask bit1.
- Add `ledger/src/mcp_merkle.rs` implementing §6 (0x00/0x01 prefixes, 32-byte witness entries, odd node duplication).
- Add `ledger/src/shred/mcp_shred.rs` implementing §7.2 and validation rules:
  - Enforce `proposer_index < NUM_PROPOSERS`, `shred_index < NUM_RELAYS`, `witness_len == ceil(log2(NUM_RELAYS))`.
  - `verify_signature` over commitment and `verify_witness` via MCP Merkle proof.
  - `is_mcp_shred_packet()` MUST be length==PACKET_DATA_SIZE and fail `shred::wire::get_shred()` signature/variant layout checks (UNVERIFIED: finalize exact predicate).

Pass 2 — Schedules (reuse leader schedule algorithm)
- Add `stake_weighted_slot_schedule()` with domain-separated seed (SHA-256(domain||epoch)) and same WeightedIndex/ChaChaRng algorithm as leader schedule.
- Implement `mcp_proposer_schedule()` / `mcp_relay_schedule()` in `leader_schedule_utils.rs` using vote-keyed vs identity-keyed stake selection identical to leader schedule.
- Extend `LeaderScheduleCache` with proposer/relay caches + accessors:
  - `proposers_at_slot()`, `relays_at_slot()` return windows of 16/200 with wrap.
  - `*_indices_at_slot()` returns all indices (supports duplicates).

Pass 3 — Storage + sigverify partition
- Add MCP CFs: `McpShredData(slot,u8,u32)` and `McpRelayAttestation(slot,u16)`; register in `blockstore_db.rs` and purge logic.
- Add `Blockstore` helpers: put/get MCP shreds/attestations.
- In `turbine/src/sigverify_shreds.rs`, partition MCP packets immediately after `recv_timeout()` and BEFORE dedup/GPU/resign.
  - MCP path: parse + proposer signature verify + witness verify + proposer_index lookup via `LeaderScheduleCache`.
  - Agave path unchanged.
  - Verified MCP packets sent to existing `verified_sender`.

Pass 4 — Window service + relay attestations + relay retransmit
- In `window_service.run_insert()`, detect MCP packets on raw payload (before `Shred::new_from_serialized_shred`).
- MCP handler:
  - Parse/validate MCP shred; store in MCP CF; record per-slot proposer commitment; track equivocation.
  - If node is relay (has relay indices): accept only shreds where `shred_index` matches one of its indices (spec §3.3).
- Relay attestation deadline handling (define clock source):
  - Build `RelayAttestation` with entries sorted by proposer_index and NO duplicates; sign; send to leader over QUIC.
  - Enforce “at most one attestation per slot”.
- Retransmit: relay broadcasts verified MCP shreds to all validators via TVU fetch UDP sockets (spec §3.3). No changes to turbine retransmit (Agave shred layout incompatible).

Pass 5 — Proposer pipeline + forwarding
- Forwarding: when MCP active, resolve proposer TPU-forward addresses (via `LeaderScheduleCache`) instead of leader; forward to 16 proposers.
- Sigverify split: add optional `mcp_proposer_sender` in `TransactionSigVerifier` and clone packets to proposer thread when this node is a proposer for the slot.
- Proposer thread:
  - Deserialize txs, extract ordering_fee (spec §7.1) OR map from compute_unit_price if spec amendment is accepted.
  - Sort by ordering_fee desc, tie by concatenation order (by proposer_index).
  - Serialize `McpPayload` (must fit DATA_SHREDS*SHRED_DATA_BYTES); encode RS(40,160).
  - Compute MCP Merkle root; build 200 MCP shreds with witness + proposer signature; send one shred to each relay (relay_index = shred_index).
- QoS: divide block-level compute and loaded-accounts-data limits by NUM_PROPOSERS (§3.2).

Pass 6 — Leader aggregation + ConsensusBlock
- ReplayStage receives RelayAttestations via QUIC handler.
- Leader aggregation:
  - Drop relay message if relay_signature invalid.
  - Drop invalid proposer entries; keep remaining entries.
  - Build AggregateAttestation sorted by relay_index; per-relay entries sorted by proposer_index.
- ConsensusBlock creation:
  - If relay entries < ceil(ATTESTATION_THRESHOLD*NUM_RELAYS): submit empty.
  - consensus_meta MUST carry ledger block_id (UNVERIFIED until Alpenglow integration defines exact bytes).
  - delayed_bankhash MUST match consensus-defined delayed slot; if unavailable, validator must refuse to vote (unless consensus protocol explicitly allows a default).
- Broadcast ConsensusBlock via QUIC to all validators; optional peer request/response if needed (keep minimal).

Pass 7 — Vote gate + reconstruct + replay
- On ConsensusBlock receipt:
  - Verify leader_signature + leader_index + delayed_bankhash (no default unless consensus allows).
  - Verify relay + proposer signatures; drop invalid entries only.
  - Compute implied proposers: exclude equivocations; include commitment if >= ceil(INCLUSION_THRESHOLD*NUM_RELAYS) distinct relay indices.
  - Check local availability: for each included proposer, need >= ceil(RECONSTRUCTION_THRESHOLD*NUM_RELAYS) valid shreds for commitment; otherwise do not vote.
- Reconstruction:
  - RS decode ≥40 shreds; re-encode and verify commitment.
  - Parse `McpPayload` txs.
- Execution:
  - Two-phase fees per §8: Phase A pre-deduct fees with per-payer cumulative tracking (slot-scoped). Phase B executes with fee-deduction disabled (`zero_fees_for_test` path).
  - No PoH verification; use `entry::verify_transactions()` then `process_entries()`.

UNVERIFIED (explicit)
- Block_id encoding in consensus_meta (requires Alpenglow/ledger commitment definition).
- Delayed slot source and policy if delayed bank not frozen.
- Exact MCP shred packet detection predicate.

---

4) RISK & ATTACK REVIEW (pragmatic)

Correctness risks (top 10) + minimal mitigation
1) Tx wire format mismatch → reject on other nodes
- Mitigation: implement §7.1 or finalize spec amendment; add compatibility flag with explicit version.
2) Block_id mismatch to ledger rules → consensus divergence
- Mitigation: define consensus_meta encoding (bank hash or ledger commitment) and enforce verification.
3) Delayed bankhash unavailable → inconsistent voting
- Mitigation: define consensus rule: no vote until delayed slot frozen; instrument metric + backoff.
4) Invalid relay entries poisoning aggregate → incorrect inclusion
- Mitigation: strict parsing (sorted/no duplicates), drop invalid entries only.
5) Equivocation handling on relay/validator differs → inconsistent inclusion
- Mitigation: same rule everywhere: if >1 commitment for proposer, exclude completely.
6) Duplicate relay indices with same identity → incorrect counts
- Mitigation: counts based on relay_index, not pubkey; schedule cache returns all indices.
7) Witness_len not enforced → acceptance of malformed proofs
- Mitigation: enforce exact length at parse time (8 for NUM_RELAYS=200).
8) MCP shreds dropped by Agave sigverify/window_service path
- Mitigation: partition BEFORE dedup/deserialize; add tests that ensure MCP shreds survive.
9) Fee double-charging or missed charging across phases
- Mitigation: unit-test two-phase path; ensure Phase B uses zero fees; track per-payer cumulative fees.
10) Nonce fee rule mismatch (fee*NUM_PROPOSERS + min rent)
- Mitigation: explicit check during Phase A; test with nonce accounts.

Performance risks (top 10) + minimal mitigation
1) CPU-only MCP signature + witness verification overhead
- Mitigation: batch verify proposer sigs by grouping per proposer; cache proposer pubkey per slot.
2) Relay broadcast fanout O(N^2) (relays→all validators)
- Mitigation: use UDP batch send + rate-limit; consider reuse of existing cluster send helpers.
3) Blockstore IO pressure from 200 shreds/proposer
- Mitigation: write-batch inserts; small in-memory dedup before write.
4) ReplayStage aggregation memory growth
- Mitigation: keep per-slot caps; evict after deadlines.
5) Rayon contention in window_service
- Mitigation: collect MCP metadata in thread-local vector, aggregate sequentially.
6) QUIC contention (single MCP socket)
- Mitigation: reuse existing QUIC server thread; limit max in-flight streams.
7) RS decode hotspots in reconstruction
- Mitigation: cache ReedSolomon instance per thread; only decode once per proposer.
8) Ordering sort cost for large payload
- Mitigation: partial sort or bucket by fee if needed; keep stable tie-breaker.
9) Schedule cache churn for proposer/relay lists
- Mitigation: reuse LeaderScheduleCache LRU pattern; limit epochs stored.
10) Sigverify path backpressure (verified_sender)
- Mitigation: instrument queue size; drop MCP shreds only after metrics indicate saturation.

---

5) TEST PLAN QUALITY GATE

Missing ship-stopper tests
- Tx format compliance: §7.1 serialization/deserialization and ordering_fee extraction.
- Vote gate with partial invalid relay entries: ensure invalid entries dropped, not whole block.
- Block_id/consensus_meta verification end-to-end with stubbed ledger commitment.
- Delayed_bankhash unavailability: validator must refuse vote unless consensus rule allows.
- Duplicate relay indices for same identity: counts by index not pubkey.
- Witness_len enforcement (reject non-8 len proofs).

Minimal integration harness design (fits Agave test style)
- New `core/tests/mcp_integration.rs` using existing local cluster test utilities.
- Use a deterministic `LeaderScheduleCache` seeded by a fixed epoch and static stakes.
- Stub QUIC handler with in-process channels to avoid network flakiness; feed MCP messages directly into ReplayStage receivers.
- Use a tiny Blockstore temp dir and inject MCP shreds + attestations to simulate relay/leader behavior.

Coverage requirements mapping
- Partition-before-Agave-layout assumptions: tests ensuring MCP shreds are not dropped in `sigverify_shreds` and `window_service`.
- QUIC payload sizing: assert RelayAttestation/ConsensusBlock sizes exceed PACKET_DATA_SIZE; ensure QUIC path used.
- Vote gate + partial invalid relay entries: confirm invalid entries dropped, inclusion threshold computed correctly.
- Two-phase fee correctness: includes nonce edge (fee*NUM_PROPOSERS + min rent), cumulative per payer, and Phase B zero-fee path.


---

Addendum — Review of “McpProposerContext” light-bank proposal (2026-02-04)

Decision: PARTIAL ACCEPT with corrections. Good direction for minimal-diff, but current suggestion conflicts with spec and Agave reality in two places and needs tighter scoping to avoid re-implementing Bank logic.

High issues
1) Fee validation at proposer is NOT required by spec; must not be treated as authoritative
- Spec: proposer stage only requires batch size bound and per-proposer resource split; fee payer DOS handling is a replay-time validator rule (§3.2, §8). Proposers can include invalid/insufficient-fee txs; validators will filter/charge in Phase A. Early filtering is allowed as local policy but must not change consensus outcomes.
- Correction: if implemented, this must be “best-effort local admission” only, and MUST NOT affect inclusion guarantees or be assumed by validators.

2) Using AccountsDb load_with_fixed_root risks inconsistency with replay eligibility
- Proposer may read balances from a parent bank snapshot that diverges from validators’ replay-time view (forks, root changes). This can cause proposer to drop txs that would be valid on the eventual fork, reducing liveness.
- Correction: treat fee validation as optional admission control with metrics; do not enforce hard rejection at proposer unless explicitly required by network policy. Alternatively, avoid balance checks entirely and only enforce size/QoS.

Codebase reality checks (Agave)
- “consumer.rs:460-493” reference is likely stale; current fee payer validation path is in `svm/src/account_loader.rs:370` and transaction fee computation in `runtime/src/bank/check_transactions.rs:100-126` (see earlier). If mirroring logic, use these real locations; otherwise mark as UNVERIFIED.
- `CostTracker` and `CostModel` are in the runtime/banking pipeline; they assume a Bank-scoped config (block cost limits, loaded accounts data size). You can construct a local `CostTracker` with explicit limits, but ensure you import from the same module as `QosService` to avoid duplication.

Minimal-diff recommendation
- Keep proposer thread bankless; add a tiny “admission control” helper that reuses existing cost model and compute budget parsing but does NOT read accounts or compute fees unless absolutely necessary.
- If fee checks are desired, do them as soft filters (metrics + optional drop) and guard with `mcp_protocol_v1` feature gate to keep behavior contained.

Concrete corrections to the proposed design
1) McpProposerContext should be explicit about non-authoritative admission:
- Add: `mode: AdmissionMode { SizeOnly, SizePlusQoS, SizePlusQoSPlusFeeSoft }`.
- Default to SizePlusQoS; use fee checks only if product requires it.

2) Fee validation path must be aligned with spec tx format decision
- If MCP uses §7.1 Transaction format, ordering_fee and fee computation should use that config values. If MCP uses legacy Solana txs, compute_budget_instructions are fine, but this is spec-deviant and must be flagged (see Critical issue #1 above).

3) Use cost_tracker limits derived from per-proposer share
- Limits must be 1/NUM_PROPOSERS of the same block-level limits used by QoS for Agave banking. Ensure loaded_accounts_data_size limits are also scaled (spec §3.2 requires both CU and loaded accounts data size).

4) Avoid direct AccountsDb load unless policy requires
- If kept: use a consistent snapshot (rooted bank or fixed root) and do not treat failure as consensus-critical. Record in metrics to assess false negatives.

Updated Plan v2 patch (delta only)
- Pass 5 proposer loop: add optional “Admission control” subsection
  - Use compute budget parsing + local CostTracker to enforce per-proposer CU + loaded-accounts-data limits.
  - Fee payer balance check is OPTIONAL/soft; must not affect consensus correctness.
  - If implemented, document that validation is advisory only and may drop txs that would be valid on final fork (liveness trade-off).

UNVERIFIED items to explicitly mark in plan
- Exact source of block-level loaded-accounts-data size limits to divide by NUM_PROPOSERS.
- Correct module paths for cost model and cost tracker in Agave at time of implementation.

