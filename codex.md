MCP plan.md review (Principal Engineer)

Scope
- Reviewed /home/anatoly/mcp/plan.md against clean Agave source (commit 1e6b8bf78a, no MCP code).
- Goal: least code, maximum reuse, in-place integration, unambiguous for ICs.

Line Number Accuracy
- 18 of 21 line references verified correct.
- 3 minor off-by-one: LeaderScheduleCache struct is line 30 (not 29); data_shred_cf/code_shred_cf are reversed (260/261); ShredCommonHeader is line 251 (not 250). Non-material.

High-Severity Correctness Issues

1) Merkle tree is NOT reusable (plan Reuse Map rows 2-4 and §1.3)
- Plan says: "Use MERKLE_HASH_PREFIX_NODE from merkle_tree.rs:18 for internal nodes."
- Reality: Agave uses `MERKLE_HASH_PREFIX_LEAF = b"\x00SOLANA_MERKLE_SHREDS_LEAF"` (26 bytes) and `MERKLE_HASH_PREFIX_NODE = b"\x01SOLANA_MERKLE_SHREDS_NODE"` (26 bytes). MCP spec §6 defines leaf hash as `SHA-256(0x00 || slot || proposer_index || shred_index || shred_data)` and internal nodes as `SHA-256(0x01 || left || right)`. These are incompatible hash constructions.
- Additionally, Agave's `MerkleProofEntry` is 20 bytes (merkle_tree.rs:9,20) while MCP spec §6 uses 32-byte witness entries. The `join_nodes()` function at merkle_tree.rs:100 truncates to 20 bytes before hashing.
- Finally, `MerkleTree`, `try_new()`, `make_merkle_proof()` are all `pub(crate)` — not accessible outside the shred module.
- Fix: MCP must implement its own Merkle tree with spec-compliant hash construction and 32-byte proof entries. Remove `MerkleTree`, `get_merkle_root()`, and `MERKLE_HASH_PREFIX_*` from the Agave Reuse Map. Add a Merkle implementation to `ledger/src/mcp.rs` or a dedicated `ledger/src/mcp_merkle.rs`.

2) Sigverify GPU batching incompatibility (plan §3.3)
- Plan says: "In the verification loop, before existing Agave shred verification: detect MCP shreds."
- Reality: `spawn_shred_sigverify()` uses GPU batch signature verification (`verify_shreds_gpu` in `ledger/src/sigverify_shreds.rs:269`). All packets in a batch are sent to GPU together. Packets must conform to Agave shred structure (signature at bytes 0-63, variant at byte 64). MCP shreds with different wire format (slot at bytes 0-7, proposer_index at 8-11) cannot be in the same GPU batch.
- Fix: MCP shreds must be separated from Agave shreds BEFORE GPU batching. At packet receipt (around line 162 in `run_shred_sigverify`), partition packets using `is_mcp_shred_packet()`. Run MCP through a CPU-only verification path (Ed25519 sig + witness). Send both verified streams into the same `verified_sender` channel.

3) Window service deserialization silently discards MCP shreds (plan §4.1)
- Plan says: "Partition into MCP and Agave shreds using is_mcp_shred_packet()."
- Reality: `run_insert()` at window_service.rs:220 calls `Shred::new_from_serialized_shred(shred)` which requires a valid `ShredVariant` at byte 64. MCP shreds fail this check and are discarded by `.ok()?`.
- The partition MUST happen BEFORE deserialization (before line 220), not after. The plan says "After receiving verified shreds from verified_receiver" but at that point the current code attempts Agave deserialization on ALL payloads.
- Fix: Detect MCP by examining raw Payload bytes before calling `Shred::new_from_serialized_shred()`. Route MCP payloads to a separate path using `McpShred::from_bytes()`.

4) TransactionConfigMask does not exist in standard Solana txs (plan §5.2)
- Plan says: "Parse TransactionConfigMask per tx. Sort by ordering_fee descending."
- Reality: At TPU SigVerify, packets contain standard Solana wire-format transactions. Standard Solana transactions do NOT have TransactionConfigMask or ordering_fee fields. These only exist in the MCP Transaction format (spec §7.1).
- The plan assumes MCP-formatted transactions arrive at TPU. They don't.
- Fix: Either (a) define MCP as requiring a new client-facing transaction format (breaking change, requires SDK updates), or (b) derive ordering_fee from existing priority fee fields (compute_unit_price), or (c) use ordering_fee=0 for standard transactions. The plan must specify which.

5) ReedSolomonCache::get() is pub(crate) (plan §5.2 and Reuse Map)
- Plan says: "RS encode via ReedSolomonCache.get(40, 160) (same cache at shredder.rs:276)."
- Reality: `ReedSolomonCache::get()` is `pub(crate)`. Code in `core/src/tpu.rs` cannot call it across crate boundaries.
- Fix: Either make it `pub`, add a pub wrapper, or use `reed_solomon_erasure::ReedSolomon::new(40, 160)` directly in MCP code. Option (c) is simplest.

6) Two-phase fee execution not cleanly separable (plan §7.3)
- Plan says: "Phase B: execute via process_entries() with a flag to skip fee re-charging."
- Reality: Fee deduction happens 8-10 layers deep: `process_entries()` → `process_batches()` → `execute_batches()` → `execute_batches_internal()` → `execute_batch()` → `bank.load_execute_and_commit_transactions()` → `TransactionBatchProcessor::load_and_execute_sanitized_transactions()` → `validate_fee_payer()`. Threading a flag through all layers is extremely invasive.
- Fix: Use a Bank-level context flag (`bank.set_mcp_fee_mode(true)`) that `validate_fee_payer()` checks at account_loader.rs:370. This requires 2-3 changes instead of 8+. Alternatively, implement Phase A as a pre-processing step that directly debits fee payer accounts on the Bank BEFORE calling the standard `process_entries()` pipeline.

7) SHRED_DATA_BYTES not specified (plan §1.2)
- Constants section lists NUM_PROPOSERS, NUM_RELAYS, thresholds, DATA_SHREDS, CODING_SHREDS — but omits SHRED_DATA_BYTES.
- Spec §4 says this is required. It determines max payload per proposer (NUM_RELAYS * SHRED_DATA_BYTES) and shred wire format size.
- Fix: Add SHRED_DATA_BYTES to constants.

Medium-Severity Issues

8) Plan dependency graph is wrong — sigverify depends on schedules
- Plan says: "Pass 1, 2, 3 can parallelize."
- Reality: Sigverify (Pass 3.3) calls `proposers_at_slot()` which requires schedule cache from Pass 2. Storage (Pass 3.1-3.2) can parallelize with Pass 1/2, but sigverify cannot.
- Fix: Split Pass 3 into storage (parallelizable) and sigverify (depends on Pass 2).

9) No retransmit path for MCP shreds
- Spec §3.3: "relay MUST broadcast the same Shred message to all validators."
- Plan describes relay attestation but not how relays retransmit MCP shreds to all validators. Existing retransmit_stage handles Agave shreds. MCP shreds are a different format.
- Fix: Specify retransmit mechanism: direct broadcast via TVU sockets, or adapt turbine tree for MCP.

10) ConsensusBlock distribution underspecified (plan §6.3-6.4)
- Plan lists two mechanisms (direct broadcast and gossip CrdsData variant) but does not specify which is primary, how full blocks are distributed (gossip has size limits), or how late validators request missed blocks.
- Fix: Specify primary distribution (direct broadcast to TVU addresses) with gossip summary as fallback. Define request/response for missed blocks.

11) MCP attestation may exceed UDP MTU (plan §4.3)
- A RelayAttestation with 16 proposer entries is: 1+8+4+1+16*(4+32+64)+64 = 1678 bytes. Exceeds 1280-byte UDP MTU.
- Fix: Use QUIC (reuse existing `alpenglow_quic` socket) or specify fragmentation. Plan should define transport.

Corrected Agave Reuse Map

| MCP concept | Agave component | Reusable? | Notes |
|---|---|---|---|
| ReedSolomonCache | shredder.rs:276 | NO | pub(crate); use reed_solomon_erasure directly |
| MerkleTree | merkle_tree.rs:37 | NO | Different hash prefixes, 20-byte vs 32-byte entries, pub(crate) |
| get_merkle_root() | merkle_tree.rs:108 | NO | Uses incompatible MerkleProofEntry (20 bytes) |
| MERKLE_HASH_PREFIX_* | merkle_tree.rs:17-18 | NO | Agave: domain-separated; MCP spec: simple 0x00/0x01 |
| Schedule generation algo | leader_schedule.rs:72 | YES | Same ChaChaRng/WeightedIndex pattern, different seed |
| LeaderScheduleCache pattern | leader_schedule_cache.rs:30 | YES | Add parallel caches for proposer/relay |
| Column trait | column.rs:308 | YES | 3-tuple index supported (AlternateShredData at column.rs:742) |
| Blockstore struct pattern | blockstore.rs:252 | YES | Add LedgerColumn fields; register in cf_descriptors() at blockstore_db.rs:176 |
| Window service run_insert() | window_service.rs:190 | YES | Partition MCP before Agave deserialization at line 220 |
| Replay main loop | replay_stage.rs:823 | YES | Add mcp_attestation_receiver to ReplayReceivers at line 330 |
| confirm_slot pipeline | blockstore_processor.rs:1485 | PARTIAL | Reuse process_entries() for Phase B with Bank-level fee flag |
| validate_fee_payer | account_loader.rs:370 | PARTIAL | Needs MCP multiplier check, not a rewrite |
| Voting path | consensus.rs:717 | YES | Unchanged |

Net Assessment
- Plan structure (7 passes, new files vs modified, feature gating) is sound.
- Column family design (3-tuple index) has precedent (AlternateShredData at column.rs:742) and is correct.
- Schedule cache design mirrors existing LeaderScheduleCache correctly.
- 7 high-severity issues must be fixed before plan is implementable: Merkle tree incompatibility, GPU sigverify batching, window service deserialization, transaction format mismatch, RS cache visibility, two-phase fee invasiveness, and missing SHRED_DATA_BYTES.
- 4 medium-severity issues should be addressed: dependency graph, retransmit path, ConsensusBlock distribution, and attestation transport.
