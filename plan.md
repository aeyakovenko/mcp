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

- `B1` Transaction payload format:
  - Spec §3.1/§7.1 requires MCP payload tx bytes to use the §7.1 Transaction format.
  - If Agave keeps legacy Solana tx bytes, this is spec-non-compliant and must be explicitly amended.
- `B2` `ordering_fee` direction:
  - Spec §3.6 says “order by ordering_fee” but does not define ascending/descending.
- `B3` `block_id` encoding in `consensus_meta`:
  - Spec §3.4/§7.5 defers to underlying consensus/ledger rules.
  - No local placeholder hash is allowed in production.
- `B4` `delayed_bankhash` delayed-slot rule:
  - Spec §3.5 says delayed slot is defined by consensus protocol.
  - No implicit fallback (for example `Hash::default()`) unless consensus defines it.

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
    - `MAX_PROPOSER_PAYLOAD = DATA_SHREDS_PER_FEC_BLOCK * SHRED_DATA_BYTES = 34_520`
  - Types:
    - `McpPayload`
    - `RelayAttestation`
    - `AggregateAttestation`
    - `ConsensusBlock`
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
    - `proposer_indices_at_slot(slot, pubkey, bank) -> Vec<u8>`
    - `relay_indices_at_slot(slot, pubkey, bank) -> Vec<u16>`
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
  - Add `McpShredData` with index `(Slot, u8 proposer_index, u32 shred_index)`.
  - Add `McpRelayAttestation` with index `(Slot, u16 relay_index)`.
- `ledger/src/blockstore_db.rs`:
  - Register CF descriptors.
  - Add names to `columns()` list.
- `ledger/src/blockstore/blockstore_purge.rs`:
  - Add both MCP CFs to `purge_range()` and `purge_files_in_range()`.

### 3.2 Blockstore APIs

- `ledger/src/blockstore.rs`:
  - Add CF handles to `Blockstore`.
  - Add MCP put/get APIs.
  - Conflict rule for same key with different bytes:
    - do not silently overwrite
    - surface deterministic conflict marker (equivocation evidence) for replay logic

### 3.3 Sigverify integration (critical partition)

- `turbine/src/sigverify_shreds.rs`:
  - Partition MCP packets before Agave dedup/GPU/resign code paths.
  - Agave packets: unchanged existing path.
  - MCP packets: CPU verification path only:
    - parse MCP shred
    - lookup proposer pubkey from MCP schedule for slot
    - verify proposer signature
    - verify Merkle witness
  - Forward verified MCP packets through existing `verified_sender` channel.

### 3.4 Tests

- MCP shreds survive partition and are not dropped by Agave layout assumptions.
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
    - store via MCP blockstore APIs
    - feed relay-attestation tracker
  - Non-MCP path remains unchanged.

### 4.2 Relay attestation semantics

- Track attestation state by `(slot, relay_index, proposer_index)`.
- Relay self-check:
  - if node owns relay indices `R = relay_indices_at_slot(...)`, accept only shreds with `shred_index in R` for relay-attest path.
- Equivocation:
  - conflicting commitments for same `(slot, relay_index, proposer_index)` => no attestation entry for that tuple.
- Cardinality:
  - at most one `RelayAttestation` per `(slot, relay_index)`.
  - if a validator owns multiple relay indices, it may emit multiple attestations (one per index).

### 4.3 MCP QUIC transport

- Need dedicated MCP QUIC stream server (standard streamer path enforces 1232-byte packet limit).
- Add one socket tag in contact info for MCP endpoint:
  - `gossip/src/contact_info.rs`
  - `gossip/src/node.rs`
  - `gossip/src/cluster_info.rs`
  - `core/src/validator.rs` wiring
- `core/src/tvu.rs`:
  - spawn MCP QUIC service (small helper module, for example `core/src/mcp_quic.rs`).
  - stream framing: 1-byte message type prefix + payload.
  - message types:
    - `0x01` RelayAttestation
    - `0x02` ConsensusBlock
  - reject unknown type and oversize frame.

### 4.4 Relay shred broadcast

- Relay retransmits verified MCP shreds to validators over existing TVU fetch UDP sockets.
- Do not use existing retransmit-stage shred-id logic for MCP bytes.

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
  2. parse ordering key according to resolved `B1/B2` rules.
  3. optional local admission control with `CostModel` + local `CostTracker` budgeted per proposer.
  4. order transactions deterministically.
  5. serialize payload and enforce max payload bound.
  6. call ledger MCP encode helper -> 200 shreds + witnesses.
  7. send shred `i` to relay index `i` address.

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

### 6.3 Leader finalization

When this node is leader for slot `s` at aggregation deadline:
1. filter invalid entries as above
2. if valid relay entries < 120 -> submit empty result
3. build `AggregateAttestation`
4. construct/sign `ConsensusBlock` with:
   - `consensus_meta` and `block_id` from consensus adapter (`B3`)
   - `delayed_bankhash` per consensus delayed-slot rule (`B4`)

### 6.4 Distribution

- Leader broadcasts `ConsensusBlock` directly to validators over MCP QUIC.
- Optional pull-recovery protocol is deferred unless required by loss testing.

### 6.5 Tests

- threshold behavior (`<120` => empty)
- relay/proposer filtering semantics
- canonical aggregate ordering
- direct QUIC block distribution

---

## Pass 7 — Vote Gate + Reconstruct + Replay + Fees

**Goal:** deterministic vote gate, reconstruction, and two-phase fee-safe execution.

### 7.1 Vote gate on `ConsensusBlock`

- `core/src/mcp_replay.rs` (called from replay loop):
  1. verify leader signature and leader index for slot
  2. verify delayed bankhash by consensus-defined delayed slot (`B4`)
  3. verify relay/proposer signatures and ignore invalid entries
  4. enforce global relay threshold after filtering (`>=120`)
  5. implied proposer rules:
     - multiple commitments => exclude
     - one commitment with `>=80` relay attestations => include
  6. local availability check:
     - count only locally stored shreds whose witness validates against included commitment
     - require `>=40` per included proposer

### 7.2 Reconstruction

- For each included proposer:
  - load shreds from MCP CF
  - decode + re-encode + recompute commitment via ledger helper
  - discard proposer batch on commitment mismatch
  - decode payload tx list

### 7.3 Ordering and execution

- Deterministic order:
  - concat by proposer index
  - apply `ordering_fee` ordering per resolved `B2` rule
  - stable tie-break by concatenated position

- `ledger/src/blockstore_processor.rs`:
  - add `confirm_slot_mcp()` that bypasses PoH checks and reuses transaction verification + execution pipeline.

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
- add explicit fee-mode control in SVM validation path (for example `skip_fee_deduction` in processing environment)
- plumb through bank execution API via MCP-specific execution entrypoint; default path unchanged

### 7.4 Bank/block ID and vote

- set `bank.block_id()` from consensus-meta-derived `block_id` (`B3`).
- underlying vote wire format remains unchanged.

### 7.5 Empty result

- if consensus outputs empty result for slot, freeze bank with no transactions.

### 7.6 Tests

- vote-gate rejections: bad leader sig/index, bad delayed bankhash, equivocation, insufficient local valid shreds, global threshold failure
- reconstruction mismatch rejection
- deterministic ordering behavior
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
