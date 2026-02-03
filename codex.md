MCP plan review — executive summary with evidence (fresh read 2026-02-03)

## Status: 3/4 Critical Issues RESOLVED

### Issue 1: Transaction wire format mismatch — SPEC AMENDMENT REQUIRED
- **Status:** DOCUMENTED, requires spec amendment (NOT a plan bug)
- Plan explicitly uses standard Solana transactions inside McpPayload and documents this at `plan.md:87-94`.
- Spec requires McpPayload to carry the MCP Transaction message defined in 7.1 (`docs/src/proposals/mcp-protocol-spec.md:280-303`).
- **Resolution:** Plan correctly documents this as "SPEC AMENDMENT REQUIREMENT" with three options: (a) spec allows standard txs for v1, (b) implement 7.1 format, (c) version negotiation.

### Issue 2: ConsensusBlock contents not implementable — RESOLVED ✓
- **Status:** FIXED in plan.md:458-461
- Plan now defines:
  - `consensus_meta`: "contains a single 32-byte block_id computed as SHA-256(slot || leader_index || aggregate_hash)"
  - `delayed_bankhash`: "MCP_DELAY_SLOTS: u64 = 32... leader fetches frozen bank hash for slot - MCP_DELAY_SLOTS via BankForks.get(slot - MCP_DELAY_SLOTS).map(|b| b.hash())"
  - Warmup handling: "If the delayed slot is not yet frozen, use Hash::default() and validators accept it during warmup period"

### Issue 3: Duplicate identity handling incomplete — RESOLVED ✓
- **Status:** FIXED in plan.md:189-193 and 300-301
- Plan now explicitly handles:
  - `relay_indices_at_slot()` returns `Vec<u16>` for ALL indices where pubkey appears
  - "A validator appearing N times in Relays[s] acts as N separate relays, each with its own index"
  - Relay self-check: "For each relay index I own, only accept shreds with shred_index == I"

### Issue 4: Replay/PoH integration underspecified — RESOLVED ✓
- **Status:** FIXED in plan.md:519-545
- Plan now specifies exact call path:
  - Entry construction: `Entry { num_hashes: 0, hash: Hash::default(), transactions: txs }`
  - ReplayEntry construction: `entry::verify_transactions(&entries, skip_verification=false, ...)`
  - PoH bypass: "PoH verification is skipped by NOT calling entries.start_verify() or verify_ticks()"
  - Signature verification preserved via `skip_verification=false`

## Line Reference Verification (2026-02-03)

All critical line references verified against current Agave codebase:
- 29/30 exact matches
- 1 minor offset: `verify_packets()` at line 423, not 437 (plan.md:252)
