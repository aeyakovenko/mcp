# MCP Audit Snapshot (spec vs code)
- Repo: /home/anatoly/mcp
- Audit time: 2026-01-24T00:36:08Z
- Spec reviewed: `docs/src/proposals/mcp-protocol-spec.md` (latest in repo)
- GitHub issues: unavailable from this environment (GitHub API returned empty)
- Assumption: lazy implementation; comments are not trusted

## Verdict
- MCP is still not spec-compliant and is not fully wired into Agave.
- Some spec-shaped types exist (ConsensusBlock/AggregateAttestation, variable-length shreds), but the live pipeline still uses deprecated formats and unverified paths.

## Spec Compliance Gaps (with evidence)
- **Merkle commitment hashing does not match spec**: spec hashes `slot || proposer_index || shred_index || shred_data` with prefixes (`docs/src/proposals/mcp-protocol-spec.md:265`), but implementation hashes only the payload with domain strings and omits slot/proposer/index entirely (`ledger/src/mcp_merkle.rs:124`, `ledger/src/mcp_merkle.rs:169`). Tree construction uses 256 padded leaves rather than the spec’s NUM_RELAYS with odd-node self-pairing.
- **Proposer signature message mismatch**: spec signs only the 32-byte commitment (`docs/src/proposals/mcp-protocol-spec.md:329`), while code signs `"mcp:commitment:v1" || commitment` (`ledger/src/shred/mcp_shred.rs:286`, `core/src/mcp_consensus_block.rs:355`).
- **Transaction wire format not implemented**: spec introduces `TransactionConfigMask` and config fields in the serialized transaction (`docs/src/proposals/mcp-protocol-spec.md:282`), but runtime/SDK parsing is untouched and MCP config stays unused (`ledger/src/mcp.rs:206`). Proposer payloads still serialize transactions with `bincode` from executed entries (`turbine/src/broadcast_stage/standard_broadcast_run.rs:670`).
- **Ordering by `ordering_fee` missing**: spec requires ordering by `ordering_fee` and tie-breaking by proposer order (`docs/src/proposals/mcp-protocol-spec.md:215`), but reconstruction concatenates proposers and de-dupes without fee ordering (`core/src/mcp_replay_reconstruction.rs:351`).
- **Relay attestation criteria deviate from spec**: relays require `MIN_SHREDS_FOR_ATTESTATION=40` before attesting (`core/src/mcp_relay_attestation.rs:38`), but spec says relays attest to any valid shred set and avoid equivocations (`docs/src/proposals/mcp-protocol-spec.md:155`).
- **Equivocation handling missing in relay aggregation**: spec mandates excluding proposers with multiple commitments (`docs/src/proposals/mcp-protocol-spec.md:195`), but `get_included_proposers` counts entries without per-commitment equivocation checks (`core/src/mcp_relay_attestation.rs:357`).
- **Leader validation of relay/proposer signatures missing**: aggregator accepts attestations without verifying relay/proposer signatures (`core/src/mcp_relay_attestation.rs:420`); replay-stage storage does not validate relay signatures before use (`core/src/replay_stage.rs:944`).
- **Consensus block framing implemented but unused**: `ConsensusBlock` and `AggregateAttestation` exist (`core/src/mcp_consensus_block.rs:236`), yet the live pipeline still builds/consumes deprecated `McpBlockV1` (`core/src/replay_stage.rs:23`, `core/src/replay_stage.rs:2954`).
- **Block_id semantics still wrong in storage/voting**: pipeline keys consensus payloads by `McpBlockV1::compute_block_hash()` instead of spec-defined `block_id` from `consensus_meta` (`core/src/replay_stage.rs:2964`, `core/src/mcp_consensus_block.rs:472`).
- **Vote format not wired to consensus**: spec requires votes over `block_id` (`docs/src/proposals/mcp-protocol-spec.md:452`), but MCP vote type is custom and not integrated with consensus vote flow (`core/src/mcp_consensus_block.rs:457`).
- **Reconstruction uses wrong shred indices in replay**: replay-stage uses enumeration index rather than the shred’s index when building `ShredData`, breaking RS reconstruction (`core/src/replay_stage.rs:2789`).
- **Bankless leader requirement not met**: spec requires shreds be produced without executing a bank (`docs/src/proposals/mcp-protocol-spec.md:485`), but proposer payloads are derived from executed entries in broadcast (`turbine/src/broadcast_stage/standard_broadcast_run.rs:664`).
- **Relay attestation signature framing conflicts**: `ledger/src/mcp_attestation.rs` signs raw bytes per spec, while `ledger/src/shred/mcp_shred.rs` uses a domain-prefixed signature (`ledger/src/shred/mcp_shred.rs:517`), leaving two incompatible formats in-tree.

## Wiring / Integration Gaps (Agave)
- **Relay index wiring is hardcoded**: window service uses `RelayAttestationConfig::default()` and a TODO for actual relay ID (`core/src/window_service.rs:709`).
- **Relay attestations never sent to leader**: attestation creation stops at TODO for UDP submit (`core/src/window_service.rs:367`).
- **Attestation receiving socket not wired**: TVU config sets `mcp_attestation_receiver: None` (`core/src/tvu.rs:433`).
- **MCP blocks not broadcast**: retransmit stage has a TODO and does not transmit MCP blocks to validators (`turbine/src/retransmit_stage.rs:693`).
- **MCP shreds are not retransmitted**: window service partitions MCP shreds and never forwards them through Turbine (`core/src/window_service.rs:282`).
- **Consensus leader index not set**: MCP block creation uses `leader_index = 0` placeholder (`core/src/replay_stage.rs:2951`).
- **Two-pass fee processing is not integrated**: two-phase fee code exists but replay explicitly TODOs integration (`core/src/replay_stage.rs:2828`).
- **Per-slot fee commitments are not tracked**: `SlotFeePayerTracker` exists but is unused in transaction processing (`svm/src/account_loader.rs:96`).
- **Duplicate/unused MCP stacks**: `core/src/mcp_proposer.rs`, `core/src/mcp_relay_ops.rs`, and `ledger/src/mcp_storage.rs` are not wired into the active broadcast or replay pipelines (`core/src/lib.rs:32`, `ledger/src/lib.rs:32`).

## Spec Under-Defined / Ambiguous Areas
- **Consensus meta + block_id definition**: spec says `block_id` is defined by “underlying ledger rules” and carried in `consensus_meta`, but does not define the format or the ledger commitment to use (`docs/src/proposals/mcp-protocol-spec.md:426`).
- **Leader/relay deadlines**: spec references aggregation deadlines but does not define derivation; current code uses ad-hoc timeouts (`core/src/mcp_relay_attestation.rs:41`).
- **Bankhash delay**: spec says delayed bankhash is defined by consensus protocol without specifying parameters; code hardcodes `BANKHASH_DELAY_SLOTS=4` (`core/src/mcp_consensus_block.rs:45`).
- **Payload size bound vs FEC params**: spec requires payload <= `NUM_RELAYS * SHRED_DATA_BYTES` (`docs/src/proposals/mcp-protocol-spec.md:136`), but FEC uses `DATA_SHREDS_PER_FEC_BLOCK` without a spec-defined reconciliation.

## GitHub Issue Mapping (blocked)
- GitHub issues could not be fetched from this environment (API returned empty). Provide an issue list or enable network access to map the gaps above to specific issues.
