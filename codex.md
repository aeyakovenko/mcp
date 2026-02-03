MCP plan review — Pass 10 (after Staff+/L7 review fixes)

## All HIGH/CRITICAL Issues: ADDRESSED

### From claude.md:

**H1: Gossip stack changes over-engineered** — FIXED
- Removed McpConsensusBlockSummary from CrdsData (4 gossip files no longer modified)
- Using QUIC peer-to-peer request/response for missed block recovery
- Modified Files section updated to remove crds_data.rs, crds_value.rs, crds.rs, crds_filter.rs

**H2: Two QUIC sockets collapsed to one** — FIXED
- Changed from SOCKET_TAG_MCP_ATTESTATION + SOCKET_TAG_MCP_CONSENSUS to single SOCKET_TAG_MCP = 14
- Added message type multiplexing with 1-byte prefix (0x01-0x04)
- SOCKET_CACHE_SIZE bump from 14 to 15 (not 16)

**H3: Phase A fee atomicity gap** — FIXED
- Added explicit atomicity specification: "atomically per-proposer batch using write-batch"
- Added failure handling: "entire proposer's batch is excluded" on any fee deduction failure
- Added per-payer tracking lifecycle: "in-memory HashMap<Pubkey, u64> for slot duration only"

**H4: AlternateShredData line reference** — FIXED
- Changed column.rs:742 to column.rs:174 (two locations)

### From codex.md (prior Critical issues):

**1. Transaction wire format** — Already addressed with SPEC AMENDMENT REQUIREMENT

**2. ConsensusBlock fields** — Already addressed with MCP_DELAY_SLOTS=32 and concrete consensus_meta definition

**3. Duplicate identity handling** — Already addressed (relay_indices_at_slot returns Vec<u16>, downstream code handles multiple indices)

**4. Replay/PoH integration under-specified** — FIXED
- Added explicit Entry construction code snippet
- Added ReplayEntry construction explanation
- Added execution path code snippet
- Clarified that entry::verify_transactions() does signature verification independent of PoH

### MEDIUM issues also fixed:

**Relay/aggregation deadlines** — FIXED
- Added MCP_RELAY_DEADLINE_MS = 200
- Added MCP_AGGREGATION_DEADLINE_MS = 300
- Referenced in both §4.2 and §6.3

---

## Summary

Modified files reduced from 28 to 24 (gossip stack untouched).
All HIGH/CRITICAL issues from both review documents addressed.
Plan ready for implementation pending spec amendment for transaction wire format.
