# MCP Audit Snapshot (spec vs code)
- Repo: /home/anatoly/mcp
- Audit time: 2026-01-24T03:22:50Z
- Spec reviewed: `docs/src/proposals/mcp-protocol-spec.md` (source of truth)
- GitHub issues: unavailable from this environment (GitHub API returned empty)
- Assumption: lazy implementation; comments are not trusted

## Verdict
- MCP is still not spec-compliant and not fully wired into Agave.
- Some spec-shaped types exist (ConsensusBlock/AggregateAttestation), but the end-to-end pipeline (attestations → aggregate → consensus → replay) is incomplete or non-compliant.

## Spec Compliance Gaps (with evidence)
- **Merkle commitments and witnesses do not bind slot/proposer/shred_index**: spec leaf hash must include `slot || proposer_index || shred_index` (`docs/src/proposals/mcp-protocol-spec.md:265-272`), but the active path uses legacy helpers that pass zero context. `McpMerkleTree::from_payloads` calls `from_payloads_with_context(0, 0, ...)` (`ledger/src/mcp_merkle.rs:273-277`), and `McpShredV1::verify_merkle_witness` calls `MerkleProof::verify` (legacy, zero context) (`ledger/src/shred/mcp_shred.rs:330-349`, `ledger/src/mcp_merkle.rs:131-135`). Broadcast builds commitments using `from_payloads` (legacy) (`turbine/src/broadcast_stage/standard_broadcast_run.rs:747-749`).
- **Transaction wire format not used for payloads**: spec requires `TransactionConfigMask` and config values in the serialized transaction (`docs/src/proposals/mcp-protocol-spec.md:282-297`), but broadcast serializes `Transaction` with `bincode` (legacy layout) (`turbine/src/broadcast_stage/standard_broadcast_run.rs:664-672`). Replay tries to parse `ordering_fee` from spec offsets, which will not match bincode bytes (`core/src/mcp_replay_reconstruction.rs:318-365`).
- **Consensus block_id semantics are not implemented**: spec requires leader to compute `block_id` via ledger rules and include it in `consensus_meta` (`docs/src/proposals/mcp-protocol-spec.md:174-178`, `docs/src/proposals/mcp-protocol-spec.md:420-430`), but `consensus_meta` is left empty and block_id is a hash of serialized block bytes (`core/src/replay_stage.rs:2959-2979`).
- **Relay/proposer signature verification is skipped in aggregation**: spec mandates verification of relay and proposer signatures before aggregating (`docs/src/proposals/mcp-protocol-spec.md:168-172`, `docs/src/proposals/mcp-protocol-spec.md:191-193`), but replay uses `add_attestation` (no verification) (`core/src/replay_stage.rs:944-960`, `core/src/mcp_relay_attestation.rs:446-448`). `ConsensusBlock::compute_implied_blocks_with_verification` validates proposer signatures only, not relay signatures (`core/src/mcp_consensus_block.rs:381-425`).
- **Equivocation handling is incomplete in aggregation**: spec excludes proposers with multiple commitments (`docs/src/proposals/mcp-protocol-spec.md:195-197`), but `SlotAttestations::get_included_proposers` counts attestations per proposer without checking conflicting commitments (`core/src/mcp_relay_attestation.rs:382-399`, `core/src/mcp_relay_attestation.rs:402-409`).
- **Bankless leader requirement not met**: spec requires shreds to be produced without executing a bank (`docs/src/proposals/mcp-protocol-spec.md:485-489`), but proposer payloads are gathered from executed entries (`turbine/src/broadcast_stage/standard_broadcast_run.rs:664-672`).
- **Fee-payer DOS protections are incomplete**: spec requires per-slot cumulative fee commitments and two-pass replay (`docs/src/proposals/mcp-protocol-spec.md:473-483`), but `SlotFeePayerTracker` is unused (`svm/src/account_loader.rs:94-157`) and replay still has a TODO to integrate two-phase processing (`core/src/replay_stage.rs:2832-2835`).

## Wiring / Integration Gaps (Agave)
- ~~**Attestation receiving not wired**~~: **FIXED** - MCP attestation socket is now bound and wired through TVU to ReplayStage (`gossip/src/contact_info.rs`, `gossip/src/node.rs`, `core/src/tvu.rs`, `core/src/validator.rs`).
- ~~**ConsensusBlock broadcast is not implemented**~~: **FIXED** - Gossip-based distribution via McpConsensusBlockSummary (`gossip/src/crds_data.rs`, `gossip/src/cluster_info.rs`, `core/src/replay_stage.rs`). Turbine retransmit is supplementary.
- **Relay index wiring is hardcoded**: window service initializes relay attestation with default relay_index (0), not the scheduled relay index (`core/src/window_service.rs:735-738`).
- **Consensus block storage key does not align with consensus**: replay stores MCP consensus payloads under a locally hashed block_id placeholder, not the consensus block_id (`core/src/replay_stage.rs:2975-2980`).

## Duplicate / Drift-Prone Implementations
- **Relay attestation formats are duplicated**: there are parallel implementations in `ledger/src/shred/mcp_shred.rs` and `ledger/src/mcp_attestation.rs`, increasing the risk of divergence (`ledger/src/shred/mcp_shred.rs:511-585`, `ledger/src/mcp_attestation.rs:122-219`).
- **Merkle helpers include both compliant and legacy APIs**: code exposes `from_payloads_with_context` and `from_payloads` (legacy), but the live path still uses the legacy variant (`ledger/src/mcp_merkle.rs:204-277`, `turbine/src/broadcast_stage/standard_broadcast_run.rs:747-749`).

## Spec Under-Defined / Ambiguous Areas
- **Consensus meta + block_id definition**: spec says `block_id` comes from underlying ledger rules and is carried in `consensus_meta`, but the format is not defined (`docs/src/proposals/mcp-protocol-spec.md:426-430`).
- **Leader/relay deadlines**: spec references deadlines but does not define derivation; code uses local timeouts (`core/src/mcp_relay_attestation.rs:170-185`).
- **Bankhash delay**: spec says delayed bankhash is defined by consensus protocol without a parameter; code hardcodes `BANKHASH_DELAY_SLOTS` (`core/src/mcp_consensus_block.rs:45`).

## GitHub Issue Mapping (blocked)
- GitHub issues could not be fetched from this environment (API returned empty). Provide an issue list or enable network access to map the gaps above to specific issues.
