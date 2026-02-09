# MCP Implementation Plan (Agave, Minimal-Diff v2)

Spec: `docs/src/proposals/mcp-protocol-spec.md`

## Constraints (must hold)

- Reuse existing TPU/TVU pipelines, sigverify, `window_service`, blockstore, replay stage, and execution paths.
- No new stage types. Only add small targeted modules where no equivalent exists.
- All MCP behavior is gated by `feature_set::mcp_protocol_v1::id()`.
- Do **not** modify `ShredVariant`, `ShredCommonHeader`, or existing Agave shred pipeline types.
- MCP shreds use a separate wire format and dedicated column families.
- Invalid MCP messages are dropped and MUST NOT advance protocol state.

## Release Blockers (`UNVERIFIED` until resolved)

- none currently

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
  - Note: this dual-format behavior requires explicit spec compatibility text.
- `B2` `ordering_fee` direction:
  - Execute highest-paying transactions first.
  - Ordering rule is `ordering_fee` descending.
  - Stable tie-break remains concatenated position (after proposer-index concatenation).
- `B3` `block_id` authority:
  - `block_id` is defined by Alpenglow consensus.
  - MCP MUST treat the Alpenglow-provided `block_id` as authoritative and MUST NOT derive a local substitute hash.
  - `consensus_meta` carries the consensus-defined data needed to recover/verify that `block_id`.
- `B4` delayed bankhash availability:
  - There must always be a delayed-slot bankhash before MCP progression.
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
    - `MAX_PROPOSER_PAYLOAD = DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES = 34_520` (this is always `<= NUM_RELAYS * SHRED_DATA_BYTES` because `DATA_SHREDS_PER_FEC_BLOCK <= NUM_RELAYS`)
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

### 4.3 MCP QUIC transport

- Reuse existing QUIC endpoint patterns (no new gossip socket enums unless proven necessary).
- MCP control messages use `1-byte type + payload` framing:
  - `0x01` RelayAttestation
  - `0x02` ConsensusBlock
- Leader resolution reuses existing leader-schedule lookup and TVU QUIC contact info.
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

**Goal:** proposer nodes build MCP shred sets from verified transactions; non-proposers forward txs to proposers.

### 5.1 Sigverify clone path and Vortexor parity

- `core/src/ed25519_sigverifier.rs`:
  - add optional MCP proposer sender clone.
- `core/src/vortexor_receiver_adapter.rs`:
  - add same clone behavior, or hard-disable MCP when Vortexor is enabled.

### 5.2 TPU proposer worker

- `core/src/tpu.rs`:
  - create MCP proposer receiver and worker when feature active.
  - derive current slot from `tick_height()/ticks_per_slot()` (no `PohRecorder::slot()`).
  - proposer activation: node is proposer for current slot if own pubkey appears in proposer indices.
- Worker steps:
  1. drain verified tx packets from MCP channel.
  2. parse ordering key using dual-format rules from resolved `B1` and descending-fee policy from `B2`.
  3. enforce per-proposer admission control with `CostModel` + local `CostTracker` budgets for CU and loaded account data (spec §3.2 resource partitioning).
  4. order transactions deterministically.
  5. serialize payload and enforce `MAX_PROPOSER_PAYLOAD`; emit latest §7.1 format where available, otherwise legacy bytes.
  6. call ledger MCP encode helper -> 200 shreds + witnesses.
  7. send shred `i` to relay index `i` address.
- Bankless recording guardrails:
  - record path is explicit opt-in from replay-stage call sites
  - reject if a working bank is installed
  - reject slot-mismatch vs PoH recorder start slot
  - reject malformed inputs (`mixins.len() != transaction_batches.len()` or any empty transaction batch)

### 5.3 Forwarding stage changes

- `core/src/forwarding_stage.rs` + `core/src/next_leader.rs`:
  - MCP mode resolves proposer forward addresses using schedule cache and same lookahead slot-offset policy used today.
  - implement fanout behavior for both forwarding clients:
    - `ConnectionCacheClient`
    - `TpuClientNext`
  - preserve non-MCP behavior unchanged.

### 5.4 Explicit non-change

- Do not globally divide BankingStage QoS limits in `core/src/banking_stage/qos_service.rs` in v1.
- Per-proposer limits are handled by proposer admission and replay validation paths.

### 5.5 Tests

- MCP clone path in normal sigverify and Vortexor modes.
- Proposer worker emits exactly one shred per relay index.
- Payload bound enforcement.
- Forwarding routes to proposer addresses in MCP mode for both forwarding clients.

---

## Pass 6 — Leader Aggregation + ConsensusBlock

**Goal:** aggregate relay attestations and distribute leader-signed `ConsensusBlock`.

### 6.1 Replay receivers

- `core/src/replay_stage.rs`:
  - extend `ReplayReceivers` with MCP attestation and consensus-block channels.
  - keep replay-loop diff minimal by delegating MCP logic to helper module.

### 6.2 MCP replay helper

- Add `core/src/mcp_replay.rs`:
  - drain and validate relay attestations.
  - maintain per-slot aggregate state.
  - expose entrypoints called by replay loop.

Validation rules:
- invalid relay signature => drop relay message
- invalid proposer signature inside relay entry => drop that entry, keep other valid entries
- canonical aggregate ordering by `relay_index`
- enforce aggregate and consensus wire-size upper bounds before decode (including QUIC control payload cap)
- threshold counting rule => count distinct `relay_index` entries that pass relay-signature/index validation and retain at least one valid proposer entry after proposer filtering
- relay entries that become empty after proposer-signature filtering are dropped and MUST NOT count toward attestation thresholds

### 6.3 Leader finalization

When this node is leader for slot `s` at aggregation deadline:
1. filter invalid entries as above
2. if valid relay entries < `REQUIRED_ATTESTATIONS` -> submit empty result
3. build `AggregateAttestation`
4. construct/sign `ConsensusBlock` with:
   - `consensus_meta` and authoritative `block_id` from Alpenglow consensus (`B3`)
   - `delayed_bankhash` for the consensus-defined delayed slot; if unavailable locally, defer finalization and do not submit yet

### 6.4 Distribution

- Leader broadcasts `ConsensusBlock` directly to validators over MCP QUIC.
- Optional pull-recovery protocol is deferred unless required by loss testing.

### 6.5 Tests

- threshold behavior (`< REQUIRED_ATTESTATIONS` => empty)
- relay/proposer filtering semantics
- canonical aggregate ordering
- direct QUIC block distribution

---

## Pass 7 — Vote Gate + Reconstruct + Replay + Fees

**Goal:** deterministic vote gate, reconstruction, and two-phase fee-safe execution.

### 7.1 Vote gate on `ConsensusBlock`

- `core/src/mcp_replay.rs` (called from replay loop):
  1. verify leader signature and leader index for slot
  2. verify delayed bankhash by consensus-defined delayed slot; if local delayed bankhash is unavailable, do not vote and keep block pending
  3. verify relay/proposer signatures and ignore invalid entries
     - drop relay entries that become empty after proposer-signature filtering
  4. enforce global relay threshold using the same relay-count rule from Pass 6 (`>= REQUIRED_ATTESTATIONS`)
  5. implied proposer rules:
     - multiple commitments => exclude
     - one commitment with `>= REQUIRED_INCLUSIONS` relay attestations => include
  6. local availability check:
     - count only locally stored shreds whose witness validates against included commitment
     - require `>= REQUIRED_RECONSTRUCTION` per included proposer

Staged rollout guard:
- replay-stage vote-gate lookups must be non-consuming; repeated evaluations for the same slot must see identical gate input.

### 7.2 Reconstruction

- For each included proposer:
  - load shreds from MCP CF
  - decode + re-encode + recompute commitment via ledger helper
  - discard proposer batch on commitment mismatch
  - decode payload tx list with dual-format `B1` parser (latest + legacy)

### 7.3 Ordering and execution

- Deterministic order:
  - concat by proposer index
  - apply `ordering_fee` descending (highest fee first)
  - stable tie-break by concatenated position

- Replay execution wiring:
  - `ledger/src/blockstore_processor.rs::execute_batch` uses MCP two-pass path when feature active.
  - Phase A calls `Bank::collect_fees_only_for_transactions`.
  - Phase B calls `Bank::load_execute_and_commit_transactions_skip_fee_collection_with_pre_commit_callback`.

Two-phase fee handling (spec §8):
- Phase A (fee commitment):
  - per-transaction checks for signature/basic validity
  - per-slot cumulative payer map in memory
  - required debit:
    - standard tx: `base_fee * NUM_PROPOSERS`
    - nonce tx: `base_fee * NUM_PROPOSERS + nonce_min_rent`
  - use `Bank::withdraw()` for debit
  - drop only failing transaction; continue others
- Phase B (execution):
  - execute filtered tx list with fee deduction disabled
  - no second fee charge

Implementation wiring:
- keep default non-MCP execution path unchanged
- use explicit fee-mode control already plumbed through SVM (`skip_fee_collection`)
- apply phase-A fee failures as execution filters for phase B

### 7.4 Bank/block ID and vote

- set `bank.block_id()` directly from the Alpenglow-consensus `block_id` carried in `ConsensusBlock` (`B3`).
- underlying vote wire format remains unchanged.

### 7.5 Empty result

- if consensus outputs empty result for slot, record empty MCP execution output for the slot.
- if a local slot bank exists with a different `block_id`, treat it as fork mismatch and do not record empty output for that slot.

### 7.6 Tests

- vote-gate rejections: bad leader sig/index, bad delayed bankhash, equivocation, insufficient local valid shreds, global threshold failure
- delayed bankhash availability gate: leader does not finalize and validator does not vote until delayed-slot bankhash is available locally
- reconstruction mismatch rejection
- deterministic ordering behavior
- dual-format payload acceptance: mixed latest + legacy tx bytes decode correctly
- producer serialization preference: latest format emitted when available, legacy retained otherwise
- two-phase fees:
  - per-transaction granularity
  - cross-proposer cumulative payer accounting
  - nonce minimum-rent edge case
  - phase-B no re-deduction
- end-to-end integration: small deterministic MCP slot flow

---

## Modified Files (expected)

New files:
- `ledger/src/mcp.rs`
- `ledger/src/mcp_merkle.rs`
- `transaction-view/src/mcp_payload.rs`
- `ledger/src/shred/mcp_shred.rs`
- `core/src/mcp_replay.rs`
- `core/src/mcp_quic.rs` (or equivalent small helper)

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
- `core/src/window_service.rs`
- `core/src/ed25519_sigverifier.rs`
- `core/src/vortexor_receiver_adapter.rs`
- `core/src/forwarding_stage.rs`
- `core/src/next_leader.rs`
- `gossip/src/contact_info.rs`
- `gossip/src/node.rs`
- `gossip/src/cluster_info.rs`
- `core/src/tvu.rs`
- `core/src/tpu.rs`
- `core/src/replay_stage.rs`
- `ledger/src/blockstore_processor.rs`
- `runtime/src/bank.rs` (MCP-specific execution entrypoint plumbing)
- `transaction-view/src/lib.rs`
- `transaction-view/src/mcp_transaction.rs`
- `svm/src/transaction_processor.rs` (fee-mode plumbing)
- `core/src/validator.rs` (socket wiring)

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
