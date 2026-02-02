MCP plan.md review (Principal Engineer) — Pass 6

All previous Critical and High issues have been resolved.

Remaining issues (Medium/Low only):

Medium
- ordering_fee sort direction: spec section 3.6 says "order by ordering_fee" without specifying ascending or descending. Plan assumes descending (higher fees first). Implementations must agree on direction or validators diverge on execution order. Recommend spec clarification.
- Transaction wire format deferred: plan explicitly defers spec section 7.1 (TransactionConfigMask, explicit ordering_fee/inclusion_fee/target_proposer fields), using standard Solana tx format instead. Justified for initial implementation (ordering_fee derived from compute_unit_price, protocol is safe without new tx format). Must be revisited for full spec compliance.
- Deadlines not defined: plan references "relay deadline" and "aggregation deadline" but never specifies how they are computed, what clock they use, or what triggers them. Spec also leaves this unspecified.

Low
- Per-slot state initialization is scattered across passes rather than a single unified setup step (organizational, not correctness).
- block_id computation by leader deferred to consensus_meta (spec section 3.4); the underlying Alpenglow consensus handles this.

Previously resolved issues (for reference):
- Critical: sigverify dedup/GPU/resign all assume Agave layout → fixed: partition at line 162 before all 3 stages
- Critical: window service discards MCP shreds → fixed: partition at raw Payload bytes before deserialization
- Critical: retransmit assumes Solana shred IDs → fixed: relay broadcasts directly to all validators
- Critical: no proposer intake channel → fixed: third sender in TransactionSigVerifier.send_packets()
- High: ConsensusBlock reception path unspecified → fixed: "solMcpConsensus" QUIC receiver + mcp_consensus_block_receiver channel in ReplayReceivers
- High: proposer_index u8 storage vs u32 wire → fixed: explicit range validation (< NUM_PROPOSERS) in McpShred::from_bytes() before u8 cast
- High: MAX_PROPOSER_PAYLOAD spec discrepancy → fixed: documented that spec bound (172,600) is loose; RS(40,160) capacity is 34,520; spec clarification noted
- High: forwarding stage uses PohRecorder → fixed: direct LeaderScheduleCache access for proposers_at_slot()
- High: CrdsData needs full enum plumbing → fixed: crds_data + crds_value + crds + crds_filter listed
- High: socket tag needs full plumbing → fixed: contact_info + node + cluster_info listed
- High: CFs need cleanup/purge paths → fixed: blockstore_db + blockstore_purge listed
- Medium: Rayon parallelism conflict → fixed: collect metadata lock-free, process sequentially after loop
- Medium: fee bypass mechanism → fixed: skip_fee_deduction in TransactionProcessingEnvironment + zero_fees_for_test
- Medium: relay shred_index self-check → fixed: relay verifies shred_index matches own relay index
- Medium: vote-side per-entry failure handling → fixed: explicit ignore-invalid-keep-valid in section 7.1
- Medium: nonce tx fee + minimum rent → fixed: explicit in section 7.3 Phase A
- Medium: validator.rs TvuSockets wiring → fixed: added to Modified Files
- Medium: relay_index u16 vs u32 wire → fixed: explicit range validation (< NUM_RELAYS) in storage
