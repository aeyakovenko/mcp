MCP plan review — all issues found (2026-02-07)

A) Executive summary of high/critical issues (with evidence)

Critical
1) Transaction wire format mismatch (spec §3.1/§7.1 vs plan uses legacy Solana txs).
Evidence: spec requires each tx bytes value be a Transaction message per §7.1 — `docs/src/proposals/mcp-protocol-spec.md:123-128`, `docs/src/proposals/mcp-protocol-spec.md:280-296`. Plan explicitly uses standard Solana wire-format transactions — `plan.md:96`, `plan.md:405`.
Required change: implement §7.1 format or amend spec and gate by version.

2) Consensus block_id derivation violates spec.
Evidence: spec requires block_id to be the underlying ledger commitment carried in consensus_meta and NOT derived from aggregate hash — `docs/src/proposals/mcp-protocol-spec.md:175-183`, `docs/src/proposals/mcp-protocol-spec.md:426-431`. Plan derives consensus_meta as SHA256(slot||leader_index||aggregate_hash) — `plan.md:475`.
Required change: define consensus_meta encoding that matches ledger commitment rules (UNVERIFIED until Alpenglow specifies exact bytes).

3) QUIC transport size limit breaks MCP messages.
Evidence: existing QUIC streamer rejects any stream where accumulated size exceeds PACKET_DATA_SIZE — `streamer/src/nonblocking/quic.rs:1294-1300`. RelayAttestation and ConsensusBlock exceed 1232 bytes — `plan.md:320`.
Required change: add MCP fragmentation framing or a dedicated QUIC handler with larger max size.

4) Delayed bankhash fallback not allowed by spec.
Evidence: spec requires delayed_bankhash verification against consensus-defined delayed slot — `docs/src/proposals/mcp-protocol-spec.md:187-190`. Plan allows Hash::default() “warmup” acceptance — `plan.md:476`, `plan.md:514`.
Required change: no vote unless delayed bankhash is verifiable, unless consensus protocol explicitly defines a fallback.

5) Validator missing global relay-count threshold check.
Evidence: spec says validators MUST treat any block below ATTESTATION_THRESHOLD*NUM_RELAYS as invalid — `docs/src/proposals/mcp-protocol-spec.md:181-183`. Plan vote gate omits the global <120 relay-entries invalidation — `plan.md:511-520`.
Required change: add explicit global relay-count threshold check after filtering invalid entries.

High
6) ordering_fee semantics mismatch.
Evidence: spec defines ordering_fee as TransactionConfigMask bit1 config value — `docs/src/proposals/mcp-protocol-spec.md:292-296`. Plan derives ordering_fee from compute_unit_price — `plan.md:96`, `plan.md:405`, `plan.md:532`.
Required change: parse ordering_fee from §7.1 config field or amend spec to map compute_unit_price→ordering_fee.

7) ordering_fee sort direction is unspecified in spec; plan assumes descending.
Evidence: spec says “order them by ordering_fee” without direction — `docs/src/proposals/mcp-protocol-spec.md:216-219`. Plan uses descending — `plan.md:532`, `plan.md:426`.
Required change: spec amendment or explicit rule gating.

8) Relay/Aggregate ordering and duplicate rules are not enforced in plan.
Evidence: spec requires entries sorted and no duplicates — `docs/src/proposals/mcp-protocol-spec.md:158-161`, `docs/src/proposals/mcp-protocol-spec.md:356-365`. Plan does not specify validation/enforcement.
Required change: enforce sorted unique entries at parse/verify; define drop rules for invalid ordering.

9) witness_len enforcement missing.
Evidence: spec mandates witness_len == ceil(log2(NUM_RELAYS)) — `docs/src/proposals/mcp-protocol-spec.md:270-273`, `docs/src/proposals/mcp-protocol-spec.md:336-343`. Plan does not enforce.
Required change: enforce witness_len at deserialization time.

10) dedup stage reasoning is incorrect; MCP shreds are discarded pre-partition.
Evidence: dedup filter in sigverify marks packets discard when `get_shred()` returns None — `turbine/src/sigverify_shreds.rs:190-203`. Plan claims MCP shreds survive dedup — `plan.md:232-236`.
Required change: keep partition-before-dedup (correct), but update reasoning to reflect discard behavior.

11) MCP path incompatible with Vortexor remote sigverify.
Evidence: MCP proposer clone is added in `TransactionSigVerifier::send_packets()` — `core/src/ed25519_sigverifier.rs:56-74`. When Vortexor is enabled, `TransactionSigVerifier` is bypassed — `core/src/tpu.rs:270-294`.
Required change: extend Vortexor adapter or disable MCP when Vortexor is enabled.

12) Two-phase fee path uses wrong API assumption.
Evidence: plan states “bank.withdraw() does not exist” — `plan.md:567-571`, but `Bank::withdraw()` exists — `runtime/src/bank.rs:6076`.
Required change: use `Bank::withdraw()` for Phase A fee debit (handles nonce minimum balance).

13) `entry::verify_transactions()` signature mismatch in plan.
Evidence: plan calls a skip_verification parameter — `plan.md:553-561`. Actual function signature is `entry::verify_transactions(entries, &thread_pool, verify_transaction)` — `ledger/src/blockstore_processor.rs:615-619`.
Required change: update plan to match actual API.

14) QosService change is leader-side only; plan claims replay-side QoS enforcement.
Evidence: QosService is used in banking-stage leader path — `core/src/banking_stage/qos_service.rs:1-120`. Replay uses `process_entries()` with Bank cost tracker — `ledger/src/blockstore_processor.rs:649-658`.
Required change: clarify that 1/NUM_PROPOSERS enforcement in replay must happen via Bank cost tracker or separate logic, not QosService.

15) Test plan includes gossip propagation for missed blocks but design avoids gossip.
Evidence: plan test says “Gossip summary propagates for missed blocks” — `plan.md:501`, while design says no gossip changes in Pass 6.4.
Required change: remove/replace test or add gossip path (not recommended for minimal diff).

16) MCP QUIC socket tag addition is not minimal diff.
Evidence: plan adds new `SOCKET_TAG_MCP` and contact info plumbing — `plan.md:329-339`. Existing `TvuSockets.alpenglow_quic` already provides QUIC server — `core/src/tvu.rs:258-273`.
Required change: reuse alpenglow QUIC socket and multiplex by message type to avoid gossip/socket churn (minimal diff).

17) ReedSolomonCache is reusable within ledger crate; plan says not reusable.
Evidence: `ReedSolomonCache::get()` is `pub(crate)` and available in `ledger` — `ledger/src/shredder.rs:276`. MCP modules live in `ledger` and can use it.
Required change: reuse cache to reduce CPU churn and diff.

18) ForwardingStage proposer routing needs explicit slot offset and time source.
Evidence: existing `next_leaders()` uses `FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET` and PoH recorder — `core/src/next_leader.rs:27-55`.
Required change: define MCP-specific offset rule and source of slot timing; otherwise different nodes forward to different proposers.

19) Relay deadline and aggregation deadline use wallclock in plan but spec is silent.
Evidence: plan defines `MCP_RELAY_DEADLINE_MS` and `MCP_AGGREGATION_DEADLINE_MS` — `plan.md:286-292`, but no clock source defined.
Required change: define slot start time source (PoH ticks or bank slot timing) to avoid divergence.

20) Relay index ownership with duplicates needs explicit handling.
Evidence: spec allows duplicate identities in Relays[s] — `docs/src/proposals/mcp-protocol-spec.md:254-257`. Plan’s relay self-check uses a single index description; duplicates must be treated as distinct indices.
Required change: explicitly accept all indices returned by `relay_indices_at_slot()` and count by relay_index, not pubkey.

21) Consensus_meta/block_id verification is UNVERIFIED until Alpenglow defines bytes.
Evidence: spec defers to consensus protocol — `docs/src/proposals/mcp-protocol-spec.md:175-178`, `docs/src/proposals/mcp-protocol-spec.md:426-431`. Plan invents SHA256 placeholder.
Required change: mark as UNVERIFIED and do not ship without consensus definition.

22) MCP shred detection predicate is unspecified and must avoid false positives.
Evidence: plan says detect via size/header pattern but does not fix predicate — `plan.md:142-145`.
Required change: define exact predicate and add tests vs Agave shred layout.

23) Replay availability check must verify witness for the included commitment.
Evidence: spec requires counting shreds that pass witness verification for that commitment — `docs/src/proposals/mcp-protocol-spec.md:200-203`. Plan says “count locally stored shreds with valid witness” but does not require commitment match at count time.
Required change: ensure witness verification uses the included commitment and shred_index.

24) ConsensusBlock request/response is extra complexity not required by spec.
Evidence: spec does not mandate recovery protocol; plan adds request/response and caching — `plan.md:490-507`.
Required change: optional; remove for minimal diff or keep tiny if needed.

25) Line reference mismatches and ambiguous files in plan.
Evidence and corrections:
- `merkle_tree.rs:*` must be `ledger/src/shred/merkle_tree.rs` (not `ledger/src/merkle_tree.rs`).
- `account_loader.rs:370` is `svm/src/account_loader.rs:370`.
- `blockstore.rs` and `blockstore_processor.rs` references should point to `ledger/src/blockstore.rs` and `ledger/src/blockstore_processor.rs` (avoid benches/tests).
- `consensus.rs:717` is `core/src/consensus.rs:717` and is dev-only (`cfg(feature = "dev-context-only-utils")`).

B) Spec ↔ Plan consistency table (mismatches only)

| Plan section | Spec anchor | Correct? | Exact correction if not | Reason |
|---|---|---|---|---|
| Pass 1.2 tx wire format | §3.1, §7.1 | NO | Implement §7.1 or amend spec | Spec mandates §7.1 format |
| Pass 1.2 ordering_fee source | §3.6, §7.1 | NO | Parse config field or amend spec mapping | ordering_fee is distinct field |
| Pass 1.2 ordering_fee direction | §3.6 | NO (spec ambiguous) | Specify direction via amendment | Spec says “order by” only |
| Pass 1.4 witness_len enforcement | §6, §7.2 | NO | Enforce witness_len == ceil(log2(NUM_RELAYS)) | Required by spec |
| Pass 4.2 RelayAttestation entry ordering | §7.3 | NO | Enforce sorted unique proposer_index | Spec requires ordering |
| Pass 6.2 AggregateAttestation ordering | §7.4 | NO | Enforce relay_index order and per-relay proposer_index order | Spec requires canonical bytes |
| Pass 6.3 block_id in consensus_meta | §3.4, §7.5 | NO | Encode ledger commitment in consensus_meta | Spec forbids aggregate-hash block_id |
| Pass 7.1 delayed_bankhash fallback | §3.5 | NO | No fallback unless consensus defines | Spec mandates verification |
| Pass 7.1 global relay threshold | §3.4 | NO | Reject if relay entries < ceil(ATTESTATION_THRESHOLD*NUM_RELAYS) | Validators must treat block invalid |

C) Codebase reality check — additional mismatches and assumptions

Over‑engineered changes (can be simpler / lower diff)
- New MCP socket tag and ContactInfo plumbing. Reuse existing `alpenglow_quic` socket and multiplex MCP messages by type.
- ConsensusBlock request/response and caching are optional; can drop for minimal diff.
- ReedSolomonCache is usable within `ledger` crate; no need for direct `ReedSolomon::new()` everywhere.

Under‑specified or incorrect assumptions
- QUIC message size: existing streamer enforces PACKET_DATA_SIZE, so MCP messages must be fragmented or handled by a dedicated server.
- Vortexor path: MCP proposer clone is bypassed; MCP must be disabled or Vortexor extended.
- Deadline timing: clock source and slot start must be defined; wallclock constants alone are insufficient.
- MCP shred detection predicate is not fully specified; needs an exact rule and tests.
- Proposer routing in ForwardingStage needs explicit slot offset semantics to match existing `next_leaders()` behavior.
- Replay availability check must verify witness for the included commitment, not just any valid shred.
- QosService change affects leader path only; replay enforcement must be defined separately.
- Two‑phase fee implementation should use `Bank::withdraw()` instead of manual account store.
- `entry::verify_transactions()` signature mismatch in plan needs correction.
