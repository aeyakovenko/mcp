MCP plan.md review (Source‑of‑Truth)

Scope
- Re‑reviewed /home/anatoly/mcp/plan.md against the current tree.
- Current repo has **no MCP source files**. This review defines the correct, minimal, in‑place MCP implementation plan.

Top‑level verdict
- plan.md is **not** a correct source of truth for this repo state. It assumes MCP files and infrastructure that do not exist and omits the required minimal, in‑place integration path.
- The corrected plan below is the authoritative, unambiguous implementation path for ICs.

Corrected MCP implementation plan (minimal change, in‑place)

0) Non‑negotiable constraints
- Reuse existing TPU/TVU pipelines, sigverify, window_service, blockstore, replay_stage, and execution paths.
- No new stages; only add small, targeted modules where no equivalent exists.
- All MCP paths must be gated by `feature_set::mcp_protocol_v1::id()`.

1) Feature gate (single source)
- `feature-set/src/lib.rs`:
  - Add `pub mod mcp_protocol_v1 { declare_id!("..."); }`.
  - Add to `FEATURE_NAMES` map.

2) MCP constants + wire types (new, minimal)
- Add `ledger/src/mcp.rs` containing:
  - Constants: NUM_PROPOSERS, NUM_RELAYS, thresholds, SHRED_DATA_BYTES.
  - `McpPayload` serialization (§3.1).
  - `RelayAttestation`, `AggregateAttestation`, `ConsensusBlock` wire types (§7.3–§7.5).
  - Reconstruction helper (RS decode + commitment verify) (§3.6).

3) MCP shred wire format (new, minimal)
- Add `ledger/src/shred/mcp_shred.rs`:
  - Implements MCP shred bytes as per §7.2.
  - Parse/serialize, verify signature and Merkle witness.
- Do **not** modify existing `ShredVariant` or `ShredCommonHeader`.

4) Sigverify integration (in‑place)
- Extend `turbine/src/sigverify_shreds.rs` to detect MCP shreds by size/header:
  - If MCP shred: verify proposer signature and Merkle witness; discard on failure.
  - Keep existing shred pipeline intact.

5) Storage (in‑place, MCP CFs)
- `ledger/src/blockstore/column.rs`:
  - Add MCP column families:
    - MCP shreds keyed by (slot, proposer_index, shred_index).
    - Relay attestations keyed by (slot, relay_index).
    - Consensus payload keyed by (slot, block_hash).
    - Execution output keyed by (slot, block_hash).
- `ledger/src/blockstore.rs`:
  - Add put/get APIs for MCP columns.

6) Window service (in‑place)
- `core/src/window_service.rs::run_insert()`:
  - Parse MCP shreds.
  - Store them in MCP CFs.
  - Track per‑slot/proposer availability.
  - Record for relay attestation when valid.

7) Schedules (in‑place)
- `ledger/src/leader_schedule.rs`:
  - Add domain‑separated schedule generation for proposers and relays.
- `ledger/src/leader_schedule_cache.rs` + `ledger/src/leader_schedule_utils.rs`:
  - Add proposer/relay schedule getters and index lookup.

8) Proposer pipeline (TPU‑side, bankless)
- `core/src/ed25519_sigverifier.rs`:
  - Add optional MCP clone sender from sig‑verified packets if node is proposer for slot.
- `core/src/tpu.rs`:
  - Consume MCP packets, sort by ordering_fee, build `McpPayload`, RS encode, compute Merkle commitment.
  - Unicast one shred per relay via existing TVU sockets.

9) Relay attestations + leader aggregation (replay_stage)
- Add a small relay attestation helper (new module or inline in window_service) to:
  - Track proposer commitments per slot.
  - Enforce equivocation rule (if conflicting commitments, do not attest).
  - Produce exactly one RelayAttestation per slot.
- `core/src/replay_stage.rs`:
  - Collect relay attestations, validate signatures, aggregate into AggregateAttestation.
  - Enforce relay threshold (ATTESTATION_THRESHOLD * NUM_RELAYS).
  - Build ConsensusBlock and broadcast through existing paths.

10) Voting gate + reconstruction + execution (in‑place)
- `core/src/replay_stage.rs`:
  - Gate votes on: leader signature, delayed_bankhash, relay/proposer sigs, inclusion thresholds, and local reconstruction availability.
- `ledger/src/blockstore_processor.rs`:
  - Add an MCP execution path before `confirm_slot_entries()` that accepts ordered txs from MCP reconstruction.
  - Ensure deterministic ordering: proposer_index order, then ordering_fee desc, tie by position.
- Two‑phase fees:
  - Phase A: deduct fees for all valid txs (even if execution fails).
  - Phase B: execute without re‑charging fees.
  - Implement as a flag in existing execution path, not a new pipeline.

11) Tests (minimum necessary)
- MCP shred parsing/verification unit tests.
- MCP RS reconstruction correctness test.
- End‑to‑end: proposer→relay→leader→vote gating on a small local cluster.

Why plan.md is not correct
- It assumes MCP files/infrastructure exist when they do not.
- It proposes reuse of base shred CFs, which is incorrect because MCP shreds must be keyed by proposer.
- It routes proposer logic via block creation (banked path) rather than TPU (bankless requirement).

Final note
- If you want plan.md to be the authoritative source, it must be rewritten to match this corrected plan verbatim.
