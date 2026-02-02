MCP plan.md review (Pass 3, Principal Engineer)

Correction to prior reviews
- The user clarified: **there should be no MCP source files yet**. Any references to existing MCP modules (e.g., `core/src/mcp_*.rs`, `ledger/src/mcp_*.rs`, `ledger/src/shred/mcp_shred.rs`, MCP column families, MCP sockets) are invalid for this repo state and must be removed from the plan.

Required plan.md reset (ground truth for ICs)
- Treat MCP as **not implemented**. The plan must describe **new in‑place changes** to existing Agave pipelines with **minimal new code**, and it must be consistent with the constraint “no MCP source files yet.”
- The plan must not reference or depend on MCP modules or MCP column families that don’t exist.

Minimum‑change, in‑place implementation plan (no existing MCP code assumed)

A) Feature gate + constants (smallest new surface)
- Add MCP feature gate in `feature-set/src/lib.rs`.
- Introduce a single new file `ledger/src/mcp.rs` to hold:
  - constants (NUM_PROPOSERS, NUM_RELAYS, thresholds, SHRED_DATA_BYTES)
  - MCP wire types (RelayAttestation, AggregateAttestation, ConsensusBlock)
  - MCP payload serialization helpers
  - MCP reconstruction helpers (RS decode + commitment verify)

B) MCP shred wire format (new file, not ShredVariant)
- Add `ledger/src/shred/mcp_shred.rs` implementing MCP shred wire format per spec §7.2.
- Do **not** modify existing `ShredVariant` or repurpose `ShredCommonHeader` fields.
- Keep MCP shreds as a parallel wire format to avoid breaking existing shred logic.

C) Sigverify integration (in‑place)
- Extend `turbine/src/sigverify_shreds.rs` to:
  - detect MCP shreds by size or header
  - validate proposer signature and Merkle witness
  - discard invalid MCP shreds using the existing packet pipeline

D) Window service + storage (in‑place)
- Add MCP handling to `core/src/window_service.rs::run_insert()`:
  - parse MCP shreds
  - store MCP shreds in MCP‑specific column families
  - track per‑slot/proposer availability
  - trigger relay attestations at relay deadline
- Add MCP column families in `ledger/src/blockstore/column.rs` and `ledger/src/blockstore.rs`:
  - MCP shreds keyed by (slot, proposer_index, shred_index)
  - Relay attestations keyed by (slot, relay_index)
  - Consensus payload keyed by (slot, block_hash)
  - Execution output keyed by (slot, block_hash)

E) Schedules (in‑place)
- Extend leader schedule generation for domain‑separated proposer/relay schedules in `ledger/src/leader_schedule.rs`.
- Add proposer/relay schedule getters in `ledger/src/leader_schedule_cache.rs` and `ledger/src/leader_schedule_utils.rs`.

F) Proposer pipeline (TPU‑side, bankless)
- Tap sig‑verified packets in `core/src/ed25519_sigverifier.rs`.
- In `core/src/tpu.rs`, for proposer slots:
  - order txs by ordering_fee
  - build MCP payload
  - RS encode + merkle commit
  - unicast one shred per relay to existing TVU sockets

G) Relay attestations + leader aggregation (replay stage)
- Add relay attestation builder (new small module or inline in window_service).
- Add attestation aggregation + ConsensusBlock building in `core/src/replay_stage.rs`.
- Reuse existing TVU sockets; add MCP attestation socket only if absolutely required.

H) Vote gate + reconstruction + execution
- In `core/src/replay_stage.rs`, gate votes on MCP availability and thresholds.
- Add MCP reconstruction → ordered tx list in `ledger/src/blockstore_processor.rs` before `confirm_slot_entries()`.
- Implement two‑phase fee processing in existing execution path (Phase A fees, Phase B execute without re‑charging).

Unambiguous missing work (IC checklist)
- Add MCP wire type file(s): `ledger/src/mcp.rs` and `ledger/src/shred/mcp_shred.rs`.
- Extend sigverify, window_service, blockstore, leader schedule cache, replay stage, and execution path with MCP logic as described.
- Keep changes in‑place and minimal; avoid new stages and new protocols.

Net assessment
- plan.md must be rewritten to remove references to non‑existent MCP source files and reflect the minimal in‑place integration described above.
