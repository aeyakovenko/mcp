# MCP Audit (Master)

Date: 2026-02-12
Branch: `master`
Scope: close remaining audit blockers and re-validate implementation deltas against `plan.md`.

## Verdict

- Previously open blockers are now implemented on `master`.
- `B3` strictness and MCP repair indexing are both closed in code.
- Remaining risk is integration breadth, not known correctness bugs in these two areas.

## Closed Blockers

1. MCP shred repair extension for `(slot, proposer_index, shred_index)`.
- Status: `RESOLVED`.
- Evidence:
  - request/response protocol and mapping: `core/src/repair/serve_repair.rs`
    - `ShredRepairType::McpShred`
    - `RepairProtocol::McpWindowIndex`
    - request mapping, verification, stats paths
  - handler support: `core/src/repair/repair_handler.rs`, `core/src/repair/standard_repair_handler.rs`, `core/src/repair/malicious_repair_handler.rs`
  - request API + admin RPC: `core/src/repair/repair_service.rs`, `validator/src/admin_rpc_service.rs`
  - response framing fix for max-size MCP shred payload:
    - MCP responses omit nonce when payload is full-size (`PACKET_DATA_SIZE`)
    - implemented in `core/src/repair/repair_response.rs`
  - nonce verification path updated:
    - legacy repair responses still require nonce
    - nonce-less repair acceptance is MCP-only and matched via outstanding MCP request payload
    - `core/src/shred_fetch_stage.rs`, `core/src/repair/outstanding_requests.rs`
  - wire extraction supports MCP repair payloads: `ledger/src/shred/wire.rs`

2. B3 strictness deviation (fallback block-id path for MCP-active replay slots).
- Status: `RESOLVED`.
- Evidence:
  - replay now defers completion for any MCP-active slot missing authoritative sidecar hash:
    - `core/src/replay_stage.rs` (`should_defer_for_missing_mcp_authoritative_block_id`)
  - completion path no longer relies on local fallback for MCP-active slots.

## Validation Runs (This Pass)

- `cargo check -p solana-core -p solana-ledger -p agave-validator`
- `cargo test -p solana-core repair::serve_repair::tests -- --nocapture`
- `cargo test -p solana-core repair::outstanding_requests::tests -- --nocapture`
- `cargo test -p solana-core shred_fetch_stage::tests -- --nocapture`
- `cargo test -p solana-core test_should_defer_for_missing_mcp_authoritative_block_id_for_active_mcp_slot -- --nocapture`
- `cargo test -p solana-core test_should_not_defer_for_missing_mcp_authoritative_block_id_before_feature_activation -- --nocapture`
- `cargo test -p solana-core test_sigverify_shred_cpu_repair -- --nocapture`
- `cargo test -p solana-core test_repair_response_packet_from_bytes_without_nonce_allows_full_payload -- --nocapture`
- `cargo test -p solana-ledger test_get_shred_and_repair_nonce_for_mcp_shred_payload_without_nonce -- --nocapture`

## Residual Risk / UNVERIFIED

- `UNVERIFIED`: full multi-node local-cluster e2e coverage specifically exercising MCP repair request/response under network fault conditions in this pass.
  - Follow-up validation target: run issue-20 local-cluster flow with induced MCP shred loss and explicit `repairMcpShredFromPeer` triggers.
