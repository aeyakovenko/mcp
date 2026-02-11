# MCP Implementation Plan (Agave, Minimal-Diff v2)

Spec: `docs/src/proposals/mcp-protocol-spec.md`

## Constraints (must hold)

- Reuse existing TPU/TVU pipelines, sigverify, `window_service`, blockstore, replay stage, and execution paths.
- No new stage types. Only add small targeted modules where no equivalent exists.
- All MCP behavior is gated by `feature_set::mcp_protocol_v1::id()`.
- Activation semantics: define `mcp_cutover_slot` as the first slot whose bank has `mcp_protocol_v1` active.
- Slots `< mcp_cutover_slot` are legacy-executed.
- Slots `>= mcp_cutover_slot` are MCP-executed from canonical MCP-ordered source (no legacy execution-source fallback).
- Do **not** modify `ShredVariant`, `ShredCommonHeader`, or existing Agave shred pipeline types.
- MCP shreds use a separate wire format and dedicated column families.
- Invalid MCP messages are dropped and MUST NOT advance protocol state.

## Release Blockers (status)

- Vote-gate input producer wiring: `RESOLVED`
  - Per-slot `VoteGateInput` is populated from ingested `ConsensusBlock` state and refreshed in replay before MCP vote-gate evaluation.
  - Wiring points: `core/src/window_service.rs`, `core/src/mcp_replay.rs`, `core/src/replay_stage.rs`.
- Bankless recording caller wiring: `RESOLVED`
  - `PohRecorder::record_bankless` is called from production block recording when no working bank is installed.
  - Wiring point: `core/src/block_creation_loop.rs`.
- Deterministic pending-slot retry + delayed bankhash sourcing: `RESOLVED`
  - Leader finalization keeps retrying pending slots when prerequisites are temporarily unavailable (especially delayed bankhash).
  - Replay keeps retrying pending consensus slots independently of fork-choice one-shot behavior.
  - Delayed-slot bankhash source order is: `BankForks` delayed slot, then blockstore frozen bank hash.
- Reconstruction-to-execution bridge reader: `PARTIAL`
  - `blockstore_processor` now has a production reader for `McpExecutionOutput` and strict decode/verification of framed transaction bytes.
  - Reader accepts both bincode `VersionedTransaction` bytes and MCP latest/legacy wire bytes (converted to `VersionedTransaction`) before bank verification.
  - Required invariant (not fully implemented yet): once `slot >= mcp_cutover_slot`, replay must not execute from legacy entry-derived source for that slot.
  - Remaining blocker: `McpExecutionOutput` production currently happens post-execution in replay, so pre-execution availability for `slot >= mcp_cutover_slot` is not yet guaranteed.

## Audit Follow-Ups (from `audit.md`)

- `A1` No silent lock-drop on critical MCP maps (`ConsensusBlock` cache, vote-gate input, included proposers):
  - Required behavior: no `try_write`/silent `if let Ok(..)` on critical path; use explicit `match` and warn on poisoned locks.
- `A2` Reconstruction-state poison semantics:
  - Commitment mismatch must not permanently brick a slot/proposer reconstruction state; next shard insert must reset state.
- `A3` Local-cluster MCP integration strictness:
  - Issue-20 test must fail on timeout by default (no env-gated soft pass).
  - Must read from live validator blockstore handles during runtime.
- `A4` Coverage gap to close before final sign-off:
  - Add multi-node MCP integration coverage for forwarding + two-pass replay-fee path (`block_verification=true` path).
  - Issue-20 test must run with a real 5-node cluster and enforce non-leader execution-output observation.
  - Startup failure to allocate required validator ports is a hard failure after bounded retries (no soft skip).
- `A5` Rollout invariant:
  - MCP CF additions require coordinated node upgrade before feature activation.
- `A6` MCP control-message backpressure:
  - TVU MCP control channel must be bounded and ingress must be non-blocking with explicit drop counters.

## Resolved Policy Decisions

- `B1` Transaction payload compatibility:
  - MCP payload decoder accepts both:
    - latest MCP §7.1 transaction format
    - legacy Solana wire-format transaction bytes
  - Producer behavior:
    - produce latest §7.1 format whenever the transaction representation supports it
    - otherwise pass through legacy bytes
  - Fee/ordering extraction:
    - latest format:
      - `inclusion_fee`: read §7.1 config field when present, else default `0`
      - `ordering_fee`: read §7.1 config field when present, else derive from `compute_unit_price` (default `0` if absent)
    - legacy format: derive ordering key from `compute_unit_price` (default `0` if absent)
  - Conservative proposer admission fee check:
    - an MCP proposer only admits a transaction if the fee payer can cover conservative slot-level exposure:
      - legacy standard tx: `NUM_PROPOSERS * base_fee`
      - MCP standard tx: `NUM_PROPOSERS * (base_fee + inclusion_fee)`
      - legacy nonce tx: `NUM_PROPOSERS * base_fee + nonce_min_rent`
      - MCP nonce tx: `NUM_PROPOSERS * (base_fee + inclusion_fee) + nonce_min_rent`
    - this is an admission precheck, not a replay-time charge multiplier
  - Note: this dual-format behavior requires explicit spec compatibility text.
- `B2` `ordering_fee` direction:
  - Execute highest-paying transactions first.
  - Partition ordering:
    - first: MCP-format transactions
    - second: legacy/standard-Solana transactions
  - MCP partition ordering:
    - primary key: MCP `ordering_fee` descending
    - tie-break: first signature bytes lexicographic ascending
    - within each proposer batch, keep at most one transaction per signature in execution output
  - Legacy partition ordering:
    - primary key: legacy priority (`compute_unit_price`) descending
    - tie-break: first signature bytes lexicographic ascending
  - no signature dedup across proposers or across partitions
  - fee charging remains per occurrence (pre-dedup), even when proposer-local duplicate signatures collapse to one executed transaction
- `B3` `block_id` authority:
  - `block_id` is defined by Alpenglow consensus.
  - MCP MUST treat the Alpenglow-provided `block_id` as authoritative and MUST NOT derive a local substitute hash.
  - `consensus_meta` carries the consensus-defined data needed to recover/verify that `block_id`.
  - MCP integration state is `ACTIVE` (not deferred): leader construction, validator verification, and vote submission paths must use the authoritative `block_id`.
- `B4` delayed bankhash availability:
  - There must always be a delayed-slot bankhash before MCP progression.
  - v1 delayed slot is `slot.saturating_sub(1)`.
  - Nodes MUST NOT proceed (leader finalization or validator voting) until delayed bankhash is locally available for the consensus-defined delayed slot.
  - No fallback hash value is permitted.

---

## Reuse Map (Agave)

| MCP area | Reuse target | Integration point |
|---|---|---|
| Schedules | Existing leader-schedule algorithm and cache pattern | `ledger/src/leader_schedule.rs`, `ledger/src/leader_schedule_cache.rs`, `ledger/src/leader_schedule_utils.rs` |
| Shred ingestion | Existing sigverify + window_service flow | `turbine/src/sigverify_shreds.rs`, `core/src/window_service.rs` |
| Storage | Existing blockstore column registration + purge plumbing | `ledger/src/blockstore/column.rs`, `ledger/src/blockstore_db.rs`, `ledger/src/blockstore.rs`, `ledger/src/blockstore/blockstore_purge.rs` |
| Replay integration | Existing replay main loop and receivers | `core/src/replay_stage.rs` |
| Transaction forwarding | Existing forwarding stage and clients | `core/src/forwarding_stage.rs`, `core/src/next_leader.rs` |
| QUIC patterns | Existing `quinn` endpoint patterns (not streamer packet path) | `turbine/src/quic_endpoint.rs`, `core/src/repair/quic_endpoint.rs` |
| Fee deduction primitives | Existing fee-payer and withdrawal behavior | `svm/src/account_loader.rs`, `runtime/src/bank.rs` |

Non-reusable for MCP wire correctness:
- Agave shred Merkle implementation uses different domain separation and proof entry width than MCP (`ledger/src/shred/merkle_tree.rs`).

---

## Pass 1 — Feature Gate + Constants + Wire Types

**Goal:** MCP types compile, serialize, and validate strictly. No behavior changes.

### 1.1 Feature gate

- `feature-set/src/lib.rs`:
  - Add `pub mod mcp_protocol_v1 { declare_id!("..."); }`.
  - Register in `FEATURE_NAMES`.

### 1.2 MCP constants and wire types

- Add `ledger/src/mcp.rs`:
  - Constants:
    - `NUM_PROPOSERS = 16`
    - `NUM_RELAYS = 200`
    - `DATA_SHREDS_PER_FEC_BLOCK = 40`
    - `CODING_SHREDS_PER_FEC_BLOCK = 160`
    - `SHRED_DATA_BYTES = 863`
    - `ATTESTATION_THRESHOLD = 0.60` (`ceil -> 120`)
    - `INCLUSION_THRESHOLD = 0.40` (`ceil -> 80`)
    - `RECONSTRUCTION_THRESHOLD = 0.20` (`ceil -> 40`)
    - `REQUIRED_ATTESTATIONS = ceil(ATTESTATION_THRESHOLD * NUM_RELAYS) = 120`
    - `REQUIRED_INCLUSIONS = ceil(INCLUSION_THRESHOLD * NUM_RELAYS) = 80`
    - `REQUIRED_RECONSTRUCTION = ceil(RECONSTRUCTION_THRESHOLD * NUM_RELAYS) = 40`
    - `MAX_PROPOSER_PAYLOAD = DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES = 34_520` (tight bound equals RS data capacity; always `<= NUM_RELAYS * SHRED_DATA_BYTES`)
  - Types:
    - `RelayAttestation`
    - `AggregateAttestation`
    - `ConsensusBlock`
- Add `transaction-view/src/mcp_payload.rs`:
  - `McpPayload` parser behavior:
    - decode `tx_count + [tx_len, tx_bytes]` framing
    - for each `tx_bytes`, accept latest MCP §7.1 tx or legacy layout without version prefix
    - carry per-tx format tag for later ordering-key extraction and possible re-encoding
    - after decoding `tx_count` entries, ignore trailing zero bytes and reject trailing non-zero bytes
  - Common parser invariants:
    - reject unknown version
    - reject out-of-range indices
    - enforce sortedness/uniqueness per spec for attestation entries

### 1.3 MCP Merkle

- Add `ledger/src/mcp_merkle.rs`:
  - leaf hash: `SHA-256(0x00 || slot || proposer_index || shred_index || shred_data)`
  - node hash: `SHA-256(0x01 || left || right)`
  - witness entries are 32 bytes
  - odd-node rule pairs with self
  - shared by `mcp_shred`, `mcp_erasure`, and `mcp_reconstruction` (no duplicated Merkle implementations)

### 1.4 MCP shred wire format

- Add `ledger/src/shred/mcp_shred.rs`:
  - Format: `slot:u64 + proposer_index:u32 + shred_index:u32 + commitment:[u8;32] + shred_data + witness_len:u8 + witness + proposer_sig:[u8;64]`
  - `is_mcp_shred_packet(packet)` classifier
  - strict parse + verify helpers
  - enforce `witness_len == ceil(log2(NUM_RELAYS))`

### 1.5 Reed-Solomon helper visibility

- Keep RS internals in `ledger` crate.
- Add ledger-level MCP helpers for encode/decode/reconstruct so `core` code does not call `pub(crate)` RS APIs directly.

### 1.6 Tests

- Round-trip serde for all MCP wire types.
- Merkle construction/proof vectors.
- Unknown version rejection.
- Attestation sorting/duplicate rejection.
- `witness_len` enforcement.
- MCP shred packet size and classifier tests.

---

## Pass 2 — Schedules

**Goal:** deterministic `Proposers[s]` and `Relays[s]`, including duplicate identities.

### 2.1 Domain-separated schedules

- `ledger/src/leader_schedule.rs`:
  - Add helper that reuses stake-weighted leader sampling with domain-separated seed.
  - `NUM_PROPOSERS`/`NUM_RELAYS` must be imported from `ledger::mcp` (single source of truth), not duplicated locally.
  - Domains:
    - proposer: `b"mcp:proposer"`
    - relay: `b"mcp:relay"`

### 2.2 Stake source parity with leader schedule

- `ledger/src/leader_schedule_utils.rs`:
  - Add `mcp_proposer_schedule(epoch, bank)`.
  - Add `mcp_relay_schedule(epoch, bank)`.
  - Mirror existing vote-keyed vs identity-keyed leader-schedule feature behavior.

### 2.3 Cache and lookup APIs

- `ledger/src/leader_schedule_cache.rs`:
  - Add proposer/relay schedule caches.
  - Add:
    - `proposers_at_slot(slot, bank) -> Option<Vec<Pubkey>>` (len=16)
    - `relays_at_slot(slot, bank) -> Option<Vec<Pubkey>>` (len=200)
    - `proposer_indices_at_slot(slot, pubkey, bank) -> Vec<u32>`
    - `relay_indices_at_slot(slot, pubkey, bank) -> Vec<u32>`
  - Duplicate identities return all indices (spec §5).

### 2.4 Tests

- Deterministic derivation for same epoch/stake set.
- Domain separation vs leader schedule.
- Window wrap-around across epoch boundary.
- Duplicate-identity index lookup returns all indices.

---

## Pass 3 — Storage + Sigverify Partition

**Goal:** MCP shreds are preserved through sigverify and stored in MCP CFs.

### 3.1 MCP column families

- `ledger/src/blockstore/column.rs`:
  - Add `McpShredData` with index `(Slot, u32 proposer_index, u32 shred_index)`.
  - Add `McpRelayAttestation` with index `(Slot, u32 relay_index)`.
- `ledger/src/blockstore_db.rs`:
  - Register CF descriptors.
  - Add names to `columns()` list.
- `ledger/src/blockstore/blockstore_purge.rs`:
  - Add both MCP CFs to `purge_range()` and `purge_files_in_range()`.

### 3.2 Blockstore APIs

- `ledger/src/blockstore.rs`:
  - Add CF handles to `Blockstore`.
  - Add MCP put/get APIs.
  - Use a dedicated MCP write lock for MCP CF read-modify-write paths (do not serialize on `insert_shreds_lock`).
  - Conflict rule for same key with different bytes:
    - do not silently overwrite
    - surface deterministic conflict marker (equivocation evidence) for replay logic

### 3.3 Sigverify integration (critical partition)

- `turbine/src/sigverify_shreds.rs`:
  - Partition MCP packets before Agave dedup/GPU/resign code paths.
  - MCP partition classifier MUST be strict (`McpShred` wire-size/layout + witness-length/path checks), not a loose size-only check.
  - Agave packets: unchanged existing path.
  - MCP packets:
    - apply slot feature gate
    - bypass Agave shred-id/leader-sigverify assumptions
    - forward through existing `verified_sender` channel for MCP-specific verification in `window_service`

### 3.4 Tests

- MCP shreds survive partition and are not dropped by Agave layout assumptions.
- classifier rejects valid Agave Merkle shreds.
- Valid MCP shred passes, bad signature/proof fails.
- MCP CF put/get + purge behavior.

---

## Pass 4 — Window Service + Relay Attestations + MCP Transport

**Goal:** MCP shreds flow through `window_service`, relay attestations are emitted correctly, and MCP control messages are transported reliably.

### 4.1 Window-service MCP partition

- `core/src/window_service.rs` (`run_insert`):
  - Partition on raw payload bytes before `Shred::new_from_serialized_shred`.
  - MCP payload path:
    - parse + validate MCP shred
    - verify proposer signature + witness against slot schedule
    - store via MCP blockstore APIs
    - feed relay-attestation tracker
    - accept/store valid relay-broadcast MCP shreds on all validators (no local relay-index storage filter)
  - Non-MCP path remains unchanged.

### 4.2 Relay attestation semantics

- Track attestation state by `(slot, relay_index, proposer_index)`.
- Relay self-check:
  - relay-index ownership (`relay_indices_at_slot`) applies only to relay-attestation emission.
  - MCP shred storage/retransmit ingestion remains index-agnostic for validator reconstruction.
- Equivocation:
  - conflicting commitments for same `(slot, relay_index, proposer_index)` => no attestation entry for that tuple.
- Cardinality:
  - at most one `RelayAttestation` per `(slot, relay_index)`.
  - if a validator owns multiple relay indices, it may emit multiple attestations (one per index).
- Attestation encoding:
  - `RelayAttestation.entries` MUST be sorted by `proposer_index` and deduplicated.
  - Empty `RelayAttestation.entries` is invalid and MUST be rejected.
  - relay-signing domain is `version || slot || relay_index || entries_len || entries` and intentionally excludes `leader_index` (leader-agnostic within slot).
- Relay attestation emission trigger:
  - emit once per `(slot, relay_index)` when either proposer coverage is complete (`NUM_PROPOSERS`) or the slot is at least one working-bank slot old.
  - this defines the relay deadline in implementation terms and avoids unbounded waiting.

### 4.3 MCP QUIC transport

- Reuse existing QUIC endpoint patterns (no new gossip socket enums unless proven necessary).
- MCP control messages use `1-byte type + payload` framing:
  - `0x01` RelayAttestation
  - `0x02` ConsensusBlock
- Leader resolution reuses existing leader-schedule lookup and TVU QUIC contact info.
- Dispatch retries are bounded and instrumented; dropped sends must increment explicit counters.
- TVU MCP control ingress channel is bounded; fetch-stage enqueue is non-blocking with explicit full/disconnected drop counters.
- Reject unknown type and oversize frame.

### 4.4 Relay shred broadcast

- Relay retransmits verified MCP shreds to validators over existing TVU fetch UDP sockets.
- Extend retransmit addressing to derive slot/shred-id from MCP wire format when Agave shred-id parsing fails.

### 4.5 Tests

- Window-service partition before Agave shred deserialize.
- Duplicate relay-index behavior (one attestation per relay index).
- Equivocation suppression.
- QUIC payload >1232B accepted by MCP transport path.

---

## Pass 5 — Proposer Pipeline + Forwarding

**Goal:** proposer nodes build MCP shred sets from produced entry batches using existing broadcast flow; non-proposers forward txs to proposers.

### 5.1 Proposer dispatch in broadcast run

- `turbine/src/broadcast_stage/standard_broadcast_run.rs`:
  - use existing broadcast entry-batch flow (no new TPU stage/worker).
  - collect per-slot transaction wire bytes and enforce `MAX_PROPOSER_PAYLOAD` with framing overhead.
  - on slot completion, encode MCP shreds and dispatch to relay schedule over existing QUIC endpoint sender.
  - proposer activation: local pubkey must appear in `proposer_indices_at_slot`.
  - duplicate proposer indices are valid and dispatch once per owned index.

### 5.2 Bankless recording guardrails

- Bankless recording guardrails:
  - record path is explicit opt-in from replay-stage call sites
  - reject if a working bank is installed
  - reject slot-mismatch vs PoH recorder start slot
  - reject malformed inputs (`mixins.len() != transaction_batches.len()` or any empty transaction batch)

### 5.3 Forwarding stage changes

- `core/src/forwarding_stage.rs` + `core/src/next_leader.rs`:
  - MCP mode resolves proposer forward addresses using schedule cache and same lookahead slot-offset policy used today.
  - implement fanout behavior for both forwarding clients:
    - `ConnectionCacheClient`: `ForwardAddressGetter::get_non_vote_forwarding_addresses` resolves proposer addresses via `mcp_leader_schedule_cache`
    - `TpuClientNext`: `get_forward_addresses_from_tpu_info` must also resolve MCP proposer addresses when `mcp_protocol_v1` is active, using the same schedule cache lookup
  - preserve non-MCP behavior unchanged.

### 5.4 Explicit non-change

- Do not globally divide BankingStage QoS limits in `core/src/banking_stage/qos_service.rs` in v1.
- Per-proposer limits are handled by proposer admission and replay validation paths.

### 5.5 Tests

- MCP dispatch removes completed slot state and emits one shred per relay index per owned proposer index.
- Payload bound enforcement.
- Forwarding routes to proposer addresses in MCP mode for both forwarding clients.

---

## Pass 6 — Leader Aggregation + ConsensusBlock

**Goal:** aggregate relay attestations and distribute leader-signed `ConsensusBlock`.

### 6.1 Control-path ingestion in window service

- `core/src/shred_fetch_stage.rs`:
  - classify MCP control frames (`0x01` relay attestation, `0x02` consensus block) and forward to TVU control channel.
- `core/src/window_service.rs`:
  - ingest and validate control frames with slot-effective feature gating.
  - store validated relay attestations in MCP CF.
  - store validated consensus blocks in shared in-memory slot map for replay consumption.

Validation rules:
- invalid relay signature => drop relay message
- invalid proposer signature inside relay entry => drop that entry, keep other valid entries
- canonical aggregate ordering by `relay_index`
- enforce aggregate and consensus wire-size upper bounds before decode (including QUIC control payload cap)
- threshold counting rule => count distinct `relay_index` entries that pass relay-signature/index validation and retain at least one valid proposer entry after proposer filtering
- relay entries that become empty after proposer-signature filtering are dropped and MUST NOT count toward attestation thresholds

### 6.2 Leader finalization

When this node is leader for slot `s` and attestation quorum is present:
1. filter invalid entries as above
2. if valid relay entries < `REQUIRED_ATTESTATIONS` -> do not finalize/broadcast a consensus block
3. build `AggregateAttestation`
4. construct/sign `ConsensusBlock` with:
   - `consensus_meta` and authoritative `block_id` from Alpenglow consensus (`B3`)
   - `delayed_bankhash` for the consensus-defined delayed slot
   - delayed-bankhash lookup order: delayed-slot `BankForks` entry, then blockstore frozen bank hash
   - if delayed-bankhash is unavailable, keep slot in a pending-finalization set and retry each insert loop until available or rooted-out

Implementation point:
- `core/src/window_service.rs::maybe_finalize_and_broadcast_mcp_consensus_block`

### 6.3 Distribution

- Leader broadcasts `ConsensusBlock` (`0x02` control frame) to TVU QUIC peers using existing turbine QUIC endpoint sender.

### 6.4 Replay consumption

- `core/src/replay_stage.rs` + `core/src/mcp_replay.rs`:
  - refresh per-slot `VoteGateInput` from validated consensus-block bytes before MCP vote-gate evaluation.
  - retain and retry pending MCP consensus slots in replay loop so evaluation does not depend on one-shot heaviest-fork selection timing.
  - evaluate slot `X` only against slot-`X` bank context (parent of `X` must already be replayed/frozen before `X` is replayed).
  - if slot-`X` bank is unavailable, keep slot pending and retry later; never substitute `heaviest_bank` as a fallback evaluation context.

### 6.6 Fork semantics

- ConsensusBlock cache is keyed by `slot`; first valid block for a slot wins in-memory for that process lifetime.
- Conflicting later consensus blocks for the same slot are ignored and logged as conflicts.
- Replay evaluates pending MCP slots only within `[root, heaviest]`; rooted-out slots are pruned.
- `heaviest_bank` remains the parent selection source for creating new leader work, not a fallback bank for evaluating already-existing pending MCP slots.
- On restart, in-memory MCP maps are rebuilt from incoming control traffic and blockstore artifacts; no snapshot persistence of in-memory MCP maps is assumed in v1.

### 6.5 Tests

- threshold behavior (`< REQUIRED_ATTESTATIONS` => empty)
- relay/proposer filtering semantics
- canonical aggregate ordering
- direct QUIC block distribution + frame typing

---

## Pass 7 — Vote Gate + Reconstruct + Replay + Fees

**Goal:** deterministic vote gate, reconstruction, and two-phase fee-safe execution.

### 7.1 Vote gate on `ConsensusBlock`

- `core/src/mcp_replay.rs` (called from replay loop):
  1. verify leader signature and leader index for slot
  2. verify delayed bankhash by consensus-defined delayed slot
     - if consensus block for slot is missing, keep slot pending and retry
     - if local delayed bankhash is unavailable, keep slot pending and retry
  3. verify relay/proposer signatures and ignore invalid entries
     - drop relay entries that become empty after proposer-signature filtering
  4. enforce global relay threshold using the same relay-count rule from Pass 6 (`>= REQUIRED_ATTESTATIONS`)
  5. implied proposer rules:
     - multiple commitments => exclude
     - one commitment with `>= REQUIRED_INCLUSIONS` relay attestations => include
  6. local availability check:
     - count only locally stored shreds whose witness validates against included commitment
     - require `>= REQUIRED_RECONSTRUCTION` per included proposer
     - strict gate behavior: if any included proposer is below threshold, do not vote the slot yet and retry on later passes; do not locally drop/exclude that proposer for voting

Staged rollout guard:
- replay-stage vote-gate lookups must be non-consuming; repeated evaluations for the same slot must see identical gate input.
- critical-path map updates must never silently fail on lock contention/poisoning; all failures are explicit and logged.

### 7.2 Reconstruction

- For each included proposer:
  - load shreds from MCP CF
  - decode + re-encode + recompute commitment via ledger helper
  - discard proposer batch on commitment mismatch
  - commitment mismatch may poison current attempt, but next shard insert must reset state (no permanent poison for slot/proposer)
  - decode payload tx list with dual-format `B1` parser (latest + legacy)
  - if an individual transaction cannot be parsed for ordering-key extraction, drop only that transaction and continue with the remaining transactions in the same proposer batch

### 7.3 Ordering and execution

- Deterministic order:
  - build two partitions:
    - MCP-format transactions (latest/legacy MCP wire format)
    - legacy/standard-Solana transactions
  - MCP partition:
    - for each proposer batch, dedup by signature (retain first occurrence)
    - merge proposer batches by proposer index
    - sort by MCP `ordering_fee` descending
    - tie-break by first signature bytes lexicographic ascending
  - legacy partition:
    - no MCP proposer-batch dedup semantics
    - sort by `compute_unit_price` descending
    - tie-break by first signature bytes lexicographic ascending
  - final order is MCP partition first, then legacy partition.
  - no signature dedup across proposers or across partitions.

- Replay execution wiring:
  - `ledger/src/blockstore_processor.rs::execute_batch` uses MCP two-pass path only when both are true:
    - block-verification execution path
    - `mcp_protocol_v1` is slot-effective active
  - Phase A calls `Bank::collect_fees_only_for_transactions`.
  - Phase B calls `Bank::load_execute_and_commit_transactions_skip_fee_collection_with_pre_commit_callback`.

Two-phase fee handling (spec §8):
- Phase A (fee commitment):
  - per-transaction checks for signature/basic validity
  - fee charging is evaluated on pre-dedup occurrences
  - per-slot cumulative payer map in memory
  - required debit:
    - legacy standard tx: `base_fee` per occurrence
    - MCP standard tx: `base_fee + inclusion_fee` per occurrence
    - legacy nonce tx: `base_fee + nonce_min_rent` per occurrence
    - MCP nonce tx: `base_fee + inclusion_fee + nonce_min_rent` per occurrence
    - `ordering_fee` is not charged in replay
    - no replay-time `NUM_PROPOSERS` multiplier
  - debit implementation:
    - standard tx: `Bank::withdraw()`
    - nonce tx: dedicated MCP nonce helper to debit the precomputed amount exactly once
  - drop only failing transaction; continue others
- Phase B (execution):
  - execute filtered tx list with fee deduction disabled
  - no second fee charge

Implementation wiring:
- keep default non-MCP execution path unchanged
- use explicit fee-mode control already plumbed through SVM (`skip_fee_collection`)
- apply phase-A fee failures as execution filters for phase B
- add explicit multi-node integration coverage for this path (single-node leader-only tests do not exercise `block_verification=true`)

Reconstruction-to-execution bridge:
- `McpExecutionOutput` stored via `put_mcp_execution_output()` MUST have a production reader
- cutover rule:
  - for slots `< mcp_cutover_slot`, execution source is legacy entry-derived
  - for slots `>= mcp_cutover_slot`, execution source is MCP canonical ordered transactions only
- during block-verification replay (`block_verification=true`) for `slot >= mcp_cutover_slot`:
  - read `McpExecutionOutput` for the slot from blockstore
  - deserialize the MCP-ordered transaction list
  - validate against bank transaction verification rules
  - malformed `McpExecutionOutput` is a hard replay error for the slot
  - missing `McpExecutionOutput` is a retry/pending condition; no fallback to legacy source for that slot
- during leader execution (`block_verification=false`):
  - legacy banking-stage path continues unchanged; MCP reconstruction does not apply to the leader's own execution
  - the leader's MCP execution output is still persisted for verification by other nodes
- implementation requirement: move `McpExecutionOutput` production to a pre-execution point (or equivalent deterministic MCP pre-exec construction) so first-run and restart share the same source for slots `>= mcp_cutover_slot`

### 7.4 Bank/block ID and vote

- `block_id` handling is active in MCP flow.
- Leader finalization:
  - construct `ConsensusBlock` so authoritative `block_id` is recoverable/verifiable from consensus-defined fields.
  - sign and broadcast only after delayed-bankhash and threshold checks pass.
- Validator replay/vote path:
  - verify `block_id` semantics from `ConsensusBlock` using Alpenglow-defined rules.
  - vote submission uses authoritative `block_id` (not legacy fallback hash for MCP-effective slots).
- underlying vote wire format remains unchanged unless Alpenglow requires an explicit new field.

### 7.5 Empty result

- if consensus outputs empty result for slot, record empty MCP execution output for the slot.
- if a local slot bank exists with a different `block_id`, treat it as fork mismatch and do not record empty output for that slot.

### 7.6 Tests

- vote-gate rejections: bad leader sig/index, bad delayed bankhash, equivocation, insufficient local valid shreds, global threshold failure
- delayed bankhash availability gate: leader does not finalize and validator does not vote until delayed-slot bankhash is available locally
- reconstruction mismatch rejection
- deterministic ordering behavior
- partition ordering behavior: MCP-first then legacy
- signature tie-break behavior for both partitions
- MCP proposer-local signature dedup behavior (retain first per proposer)
- pre-dedup fee charging behavior (duplicates still charged per occurrence)
- transaction-level parse-failure handling: unparsable transactions are dropped individually (batch continues)
- execution-output reader behavior: strict decode for malformed payloads; MCP-wire (latest/legacy) and standard-wire transactions decode into replay input
- dual-format payload acceptance: mixed latest + legacy tx bytes decode correctly
- producer serialization preference: latest format emitted when available, legacy retained otherwise
- two-phase fees:
  - per-transaction granularity
  - cross-proposer cumulative payer accounting
  - MCP `inclusion_fee` charged once per pre-dedup occurrence
  - MCP `ordering_fee` not charged in replay
  - nonce minimum-rent edge case
  - phase-B no re-deduction
- issue-20 integration:
  - strict timeout failure by default (no soft-pass env toggle)
  - strict 5-node startup with equal stake (20% each) and no soft skip on port failures
  - use live validator blockstore handles during runtime
  - assert all three artifacts are observed: relay attestation, MCP shreds, MCP execution output
  - assert non-leader MCP execution output is observed for at least one slot where leader differs
  - emit periodic diagnostics for gossip-visible nodes, vote accounts, and per-validator slot progress
- additional multi-node integration:
  - verify proposer forwarding fanout and non-leader replay path for MCP two-pass fees when 2+ validators are live

---

## Modified Files (expected)

New files:
- `ledger/src/mcp.rs`
- `ledger/src/mcp_merkle.rs`
- `transaction-view/src/mcp_payload.rs`
- `ledger/src/shred/mcp_shred.rs`
- `core/src/mcp_replay.rs`

Modified files:
- `feature-set/src/lib.rs`
- `ledger/src/leader_schedule.rs`
- `ledger/src/leader_schedule_cache.rs`
- `ledger/src/leader_schedule_utils.rs`
- `ledger/src/blockstore/column.rs`
- `ledger/src/blockstore_db.rs`
- `ledger/src/blockstore.rs`
- `ledger/src/blockstore/blockstore_purge.rs`
- `turbine/src/sigverify_shreds.rs`
- `turbine/src/retransmit_stage.rs`
- `turbine/src/quic_endpoint.rs`
- `turbine/src/broadcast_stage/standard_broadcast_run.rs`
- `core/src/shred_fetch_stage.rs`
- `core/src/window_service.rs`
- `core/src/forwarding_stage.rs`
- `core/src/next_leader.rs`
- `core/src/tvu.rs`
- `core/src/replay_stage.rs`
- `core/src/block_creation_loop.rs`
- `core/src/mcp_vote_gate.rs`
- `core/src/mcp_relay.rs`
- `core/src/mcp_relay_submit.rs`
- `ledger/src/blockstore_processor.rs`
- `runtime/src/bank.rs` (MCP-specific execution entrypoint plumbing)
- `transaction-view/src/lib.rs`
- `transaction-view/src/mcp_transaction.rs`
- `svm/src/transaction_processor.rs` (fee-mode plumbing)
- `local-cluster/tests/local_cluster.rs`

---

## Dependency Order

- Passes 1, 2, and 3.1/3.2 can proceed in parallel.
- Pass 3.3 depends on 1 + 2.
- Pass 4 depends on 1 + 2 + 3.
- Pass 5 depends on 1 + 2 + 4.
- Pass 6 depends on 1 + 2 + 4.
- Pass 7 depends on 1 + 2 + 3 + 6.

## Acceptance Invariants

- No MCP packet is parsed by Agave shred wire parsers.
- No MCP state transition occurs without feature gate active.
- All threshold checks use ceil-threshold logic with `NUM_RELAYS=200`.
- Replay and vote gate use the same attestation filtering rules.
- Unknown versions, unsorted entries, duplicate entries, invalid signatures/proofs are rejected deterministically.
- Delayed-bankhash gating is strict: no leader finalization or validator vote progression without local delayed-slot bankhash availability.
- Pending-slot retry paths are deterministic in both window-service finalization and replay vote-gate evaluation.
- Critical MCP shared-map lock failures are never silently ignored; failures are explicit and logged.
- MCP control ingress is bounded; enqueue drops are explicit and counted.
- `McpExecutionOutput` decode failures are explicit replay errors (never silently ignored).
- Cross-crate MCP constants remain aligned via dedicated consistency tests.
