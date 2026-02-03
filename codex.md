MCP plan review — executive summary with evidence (fresh read 2026-02-03)

## Status: All Critical/High issues RESOLVED except 1 SPEC AMENDMENT required

### Issue 1: Transaction wire format mismatch — SPEC AMENDMENT REQUIRED
- **Status:** DOCUMENTED, requires spec amendment (NOT a plan bug)
- Plan explicitly uses standard Solana transactions inside McpPayload and documents this at `plan.md:87-94`.
- Spec requires McpPayload to carry the MCP Transaction message defined in 7.1 (`docs/src/proposals/mcp-protocol-spec.md:280-303`).
- **Resolution:** Plan correctly documents this as "SPEC AMENDMENT REQUIREMENT" with options: (a) spec allows standard txs for v1, (b) implement 7.1 format, (c) version negotiation.

### Issue 2: Delayed bankhash parameterization — RESOLVED ✓
- **Status:** FIXED in plan.md:80 and plan.md:460
- Plan now defines `MCP_DELAY_SLOTS: u64 = 32` with rationale (matches typical optimistic confirmation latency ~12.8 seconds)
- Plan specifies delayed_bankhash source: `BankForks.get(slot - MCP_DELAY_SLOTS).map(|b| b.hash())`
- Warmup handling specified: use Hash::default() during first MCP_DELAY_SLOTS slots

### Issue 3: Line references — RESOLVED ✓
- **Status:** ALL FIXED (31/31 references verified accurate)
- AlternateShredData is correctly at `column.rs:174` (was never at 742)
- SlotColumn fixed from 318 → 353 (plan.md:220)
- verify_packets fixed from 437 → 423 (plan.md:252)

### Issue 4: ConsensusBlock contents — RESOLVED ✓
- **Status:** FIXED in plan.md:458-461
- consensus_meta: SHA-256(slot || leader_index || aggregate_hash) for MCP standalone
- delayed_bankhash: BankForks.get(slot - MCP_DELAY_SLOTS).hash()

### Issue 5: Duplicate identity handling — RESOLVED ✓
- **Status:** FIXED in plan.md:189-193 and 300-301
- relay_indices_at_slot() returns Vec<u16> for ALL indices
- Relay self-check handles multiple indices per identity

### Issue 6: PoH bypass — RESOLVED ✓
- **Status:** FIXED in plan.md:519-545
- Entry construction with dummy hash/num_hashes
- entry::verify_transactions() for signature verification
- PoH verification skipped by not calling start_verify()/verify_ticks()

## Line Reference Verification (2026-02-03)

All 31 critical line references verified against current Agave codebase:
- sigverify_shreds.rs: 162, 190-203, 208-216, 220-242, 423 ✓
- window_service.rs: 190, 213, 220 ✓
- replay_stage.rs: 330, 823 ✓
- contact_info.rs: 47 ✓
- column.rs: 174, 308, 353 ✓
- blockstore_db.rs: 171, 252 ✓
- blockstore_processor.rs: 599-647, 1485 ✓
- transaction_processor.rs: 124 ✓
- account_loader.rs: 370 ✓
- check_transactions.rs: 106 ✓
