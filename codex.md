MCP plan.md review (Principal Engineer) — Pass 7

All previous Critical and High issues have been resolved.

Remaining issues (Medium/Low only):

Medium
- ordering_fee sort direction: spec section 3.6 says "order by ordering_fee" without specifying ascending or descending. Plan assumes descending (higher fees first). Implementations must agree on direction or validators diverge on execution order. Recommend spec clarification.
- Deadlines not defined: plan references "relay deadline" and "aggregation deadline" but never specifies how they are computed, what clock they use, or what triggers them. Spec also leaves this unspecified.
- DELAY_SLOTS parameter: plan references Alpenglow's DELAY_SLOTS for delayed_bankhash but does not specify its value or where it comes from. Must be defined by Alpenglow integration.

Low
- Per-slot state initialization is scattered across passes rather than a single unified setup step (organizational, not correctness).

Previously resolved issues (for reference):
- Critical: sigverify dedup/GPU/resign all assume Agave layout → fixed: partition at line 162 before all 3 stages
- Critical: window service discards MCP shreds → fixed: partition at raw Payload bytes before deserialization
- Critical: retransmit assumes Solana shred IDs → fixed: relay broadcasts directly to all validators
- Critical: no proposer intake channel → fixed: third sender in TransactionSigVerifier.send_packets()
- Critical: PoH/Entry integration missing → fixed: confirm_slot_mcp() bypasses PoH via process_entries_for_tests pattern
- Critical: consensus_meta/delayed_bankhash undefined → fixed: explicitly documented as opaque Alpenglow payloads with verification path
- Critical: Transaction wire format mismatch → fixed: explicit spec deviation note documenting MCP v1 uses standard Solana txs, v2 will implement spec 7.1
- Critical: Duplicate identities not handled → fixed: schedule APIs return Vec of all indices per identity
- Critical: ConsensusBlock recovery path not implementable → fixed: McpConsensusBlockRequest message type + QUIC handler
- High: ConsensusBlock reception path unspecified → fixed: "solMcpConsensus" QUIC receiver + mcp_consensus_block_receiver channel in ReplayReceivers
- High: proposer_index u8 storage vs u32 wire → fixed: explicit range validation (< NUM_PROPOSERS) in McpShred::from_bytes() before u8 cast
- High: MAX_PROPOSER_PAYLOAD spec discrepancy → fixed: documented that spec bound (172,600) is loose; RS(40,160) capacity is 34,520; spec clarification noted
- High: forwarding stage uses PohRecorder → fixed: direct LeaderScheduleCache access for proposers_at_slot()
- High: CrdsData needs full enum plumbing → fixed: crds_data + crds_value + crds + crds_filter listed
- High: socket tag needs full plumbing → fixed: contact_info + node + cluster_info listed
- High: CFs need cleanup/purge paths → fixed: blockstore_db + blockstore_purge listed
- High: vote-keyed vs identity-keyed stake selection → fixed: MCP schedules use same feature-gated selection as leader schedules
- High: feature gate call sites undefined → fixed: explicit list of 7 gate locations in Constraints section
- High: ReplayEntry construction without PoH → fixed: confirm_slot_mcp() uses entry::verify_transactions() directly
- Medium: Rayon parallelism conflict → fixed: collect metadata lock-free, process sequentially after loop
- Medium: fee bypass mechanism → fixed: skip_fee_deduction in TransactionProcessingEnvironment + zero_fees_for_test
- Medium: relay shred_index self-check → fixed: relay verifies shred_index matches own relay index
- Medium: vote-side per-entry failure handling → fixed: explicit ignore-invalid-keep-valid in section 7.1
- Medium: nonce tx fee + minimum rent → fixed: explicit in section 7.3 Phase A
- Medium: validator.rs TvuSockets wiring → fixed: added to Modified Files
- Medium: relay_index u16 vs u32 wire → fixed: explicit range validation (< NUM_RELAYS) in storage
