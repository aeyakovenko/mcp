# MCP (Multiple Concurrent Proposers) Protocol Specification (No Encryption)

**Spec ID:** MCP-001  
**Version:** 1.0.0-draft2 (No-Encryption)  
**Date:** 2026-01-22  
**Status:** Draft (implementable, wire formats stable)  

This document defines the **source-of-truth** protocol behavior and wire formats for the **Solana-Alpenglow MCP** fork **without transaction encryption** (no hiding / threshold encryption in this version). It is intended to match the *current* MCP “Part 1” public spec structure while resolving underspecification and internal inconsistencies, and while remaining implementable in a Solana-style pipeline.

> Future versions may add threshold encryption and “hiding”; those are explicitly out of scope here.

---

## Table of Contents

1. [Overview](#1-overview)  
2. [Protocol Constants](#2-protocol-constants)  
3. [Roles, Committees, and Scheduling](#3-roles-committees-and-scheduling)  
4. [Cryptographic and Coding Primitives](#4-cryptographic-and-coding-primitives)  
5. [Canonical Data Structures](#5-canonical-data-structures)  
6. [Wire Formats](#6-wire-formats)  
7. [Transaction Format](#7-transaction-format)  
8. [Proposer Operations](#8-proposer-operations)  
9. [Relay Operations](#9-relay-operations)  
10. [Consensus Leader Operations](#10-consensus-leader-operations)  
11. [Validator Operations](#11-validator-operations)  
12. [Replay Operations](#12-replay-operations)  
13. [Fee Mechanics](#13-fee-mechanics)  
14. [Storage Schema](#14-storage-schema)  
15. [Security Considerations](#15-security-considerations)  
16. [Determinism Requirements](#16-determinism-requirements)  
17. [Forward-Compatible Extensions](#17-forward-compatible-extensions)  
18. [References](#18-references)  

---

## 1. Overview

MCP (Multiple Concurrent Proposers) allows **multiple proposers** to submit transaction payloads for the **same slot** in parallel. A **relay committee** acts as a data-availability and fanout layer. The **slot leader** aggregates relay attestations into a consensus block. Execution occurs later during deterministic replay.

### 1.1 Goals

* **Parallel submission:** multiple proposers per slot.
* **Data availability signaling:** relays attest to receiving a proposer’s payload in time.
* **Deterministic replay:** all validators reconstruct identical proposer payloads and execute transactions in a deterministic order.
* **Consensus safety preserved:** MCP is a gadget over the underlying consensus (Alpenglow); it does not change the fork-choice or voting rules except by adding new block validity checks.

### 1.2 Non-goals (this version)

* **No encryption / hiding.** Transactions are plaintext.
* **No MEV protection.** MCP only defines ordering and availability.
* **No multi-FEC streaming batches.** Each proposer contributes **at most one erasure-coded payload per slot** (see §17 for streaming).

### 1.3 Slot Phases (logical)

For slot `s`:

1. **Proposal phase:** each proposer constructs a payload `M_s,q`, erasure-encodes it into `NUM_RELAYS` shreds, commits to the shred vector, and sends **one shred** to each relay.
2. **Relay phase:** each relay verifies its received shreds and broadcasts verified shreds to validators; relays send attestations to the leader.
3. **Consensus phase (leader):** leader aggregates relay attestations and proposes a block to Alpenglow.
4. **Consensus voting:** validators verify the block and verify they can reconstruct enough shreds for each included proposer; then vote.
5. **Replay:** validators reconstruct proposer payloads from shreds, parse transactions, order deterministically, execute, and produce the slot output.

---

## 2. Protocol Constants

All constants are derived from genesis configuration / feature activation and MUST be identical across all nodes that have MCP enabled.

### 2.1 Core constants

| Constant | Value | Meaning |
|---|---:|---|
| `NUM_PROPOSERS` | 16 | Number of proposers per slot |
| `NUM_RELAYS` | 200 | Number of relays per slot |
| `ATTESTATION_THRESHOLD` | 0.60 | **Block-level** minimum fraction of relays whose attestations must be included for the block to be valid |
| `INCLUSION_THRESHOLD` | 0.40 | **Per-proposer** minimum fraction of relays that must attest to a proposer commitment for that proposer to be included |
| `RECONSTRUCTION_THRESHOLD` | 0.20 | Minimum fraction of distinct relay shreds required to reconstruct a proposer payload |
| `BANKHASH_DELAY_SLOTS` | 4 | Bank hash delay used by “bankless leader” validation (§11.2) |

**Derived integer thresholds (ceil):**

```
MIN_RELAYS_IN_BLOCK = ceil(ATTESTATION_THRESHOLD * NUM_RELAYS) = ceil(0.60 * 200) = 120
MIN_RELAYS_PER_PROPOSER = ceil(INCLUSION_THRESHOLD * NUM_RELAYS) = ceil(0.40 * 200) = 80
K_DATA_SHREDS = ceil(RECONSTRUCTION_THRESHOLD * NUM_RELAYS) = ceil(0.20 * 200) = 40
```

### 2.2 Packet sizing constants

MCP shreds are sized to fit within Solana’s UDP packet budget.

| Constant | Value |
|---|---:|
| `MCP_SHRED_TOTAL_BYTES` | 1225 |
| `MCP_SHRED_PAYLOAD_BYTES` | 952 |
| `MERKLE_ROOT_BYTES` | 32 |
| `MERKLE_PROOF_ENTRY_BYTES` | 20 |
| `MERKLE_PROOF_ENTRIES` | 8 |
| `MERKLE_PROOF_BYTES` | 160 |
| `SIGNATURE_BYTES` | 64 |

These satisfy:

```
1225 = 8(slot) + 4(proposer_index) + 4(shred_index) + 32(commitment)
     + 952(shred_data) + 1(witness_len) + 160(witness) + 64(signature)
```

### 2.3 Payload size limits

Each proposer payload is encoded into `NUM_RELAYS` shreds of `MCP_SHRED_PAYLOAD_BYTES`, with `K_DATA_SHREDS` data capacity.

| Limit | Value |
|---|---:|
| `MAX_PROPOSER_PAYLOAD_BYTES` | `K_DATA_SHREDS * MCP_SHRED_PAYLOAD_BYTES` = `40 * 952` = **38,080 bytes** |

A proposer MUST NOT produce a payload exceeding this limit for a given slot. Oversized payloads are invalid and MUST be rejected by relays.

---

## 3. Roles, Committees, and Scheduling

### 3.1 Roles

**Proposer (q):** A validator selected into the proposer committee for slot `s`, indexed by `proposer_index ∈ [0, NUM_PROPOSERS-1]`. Produces one MCP payload for slot `s`.

**Relay (r):** A validator selected into the relay committee for slot `s`, indexed by `relay_index ∈ [0, NUM_RELAYS-1]`. Receives one shred from each proposer and attests to commitments it verified.

**Consensus Leader (L):** The underlying Alpenglow slot leader for slot `s` (leader schedule unchanged by MCP).

**Validator:** Any validator participating in consensus and replay.

### 3.2 Canonical validator registry

At epoch `E`, define `ValidatorRegistry_E` as the list of active validator vote pubkeys in **ascending lexicographic order of pubkey bytes**. All indices used by MCP reference this registry deterministically.

* `validator_index` in votes refers to an index into `ValidatorRegistry_E`.
* Committee selection outputs ordered lists of `validator_index` values, which map to pubkeys.

### 3.3 Committee selection (stake-weighted rotation)

This spec adopts a *deterministic stake-weighted rotation* per slot, consistent with the public MCP overview:

* Each role maintains an ordered committee for slot `s`.
* The committee for slot `s+1` is derived by **rotating** the committee for slot `s` by 1 position and **sampling 1 new validator** by stake weight to fill the vacated position.

#### 3.3.1 Inputs

For epoch `E`:

* `stakes[i]` for each `validator_index i` in `ValidatorRegistry_E`.
* Total stake `W = sum_i stakes[i]`.

#### 3.3.2 RNG

For role `role ∈ {proposer, relay}`, define:

```
seed_role = SHA256("mcp:committee:" || role || LE64(E))
rng = ChaCha20Rng(seed_role)
```

For each slot `s` in epoch, define `slot_index = s - epoch_start_slot(E)`.

To sample the one new member for slot `s`, derive a per-slot RNG:

```
seed_slot = SHA256(seed_role || LE64(slot_index))
rng_slot = ChaCha20Rng(seed_slot)
```

#### 3.3.3 Weighted sample (deterministic)

Given a candidate set `C` (a list of validator indices in registry order), sample `x` by stake weight:

1. Let `W_C = sum_{i ∈ C} stakes[i]`.
2. Draw `r` uniformly from `[0, W_C-1]` using `rng_slot.next_u64() mod W_C`.
3. Return the smallest index `i ∈ C` such that `sum_{j ∈ C, j <= i} stakes[j] > r`.

#### 3.3.4 Rotation update rule

Let `Committee_role[s]` be an **ordered list** of length `ROLE_COUNT` (16 for proposers, 200 for relays).

For the first slot of the epoch, initialize `Committee_role[s0]` by sampling **without replacement** until the committee is full:

```
C = all validators in registry order
for k in 0..ROLE_COUNT-1:
  pick = weighted_sample(C)
  committee[k] = pick
  remove pick from C
```

For each subsequent slot `s+1`:

1. Rotate left by 1:
   ```
   committee' = committee[1..] || [committee[0]]
   ```
2. Replace the last element with a new sample:
   * Candidate set `C` is all validators excluding the current `committee'` elements (to avoid duplicates within the committee).
   * If `|C| == 0`, allow duplicates by setting `C = all validators`.
   * Sample `pick = weighted_sample(C)` and set `committee'[-1] = pick`.

The resulting `committee'` is `Committee_role[s+1]`.

#### 3.3.5 Index mapping

For slot `s`:

* `Proposers[s][proposer_index]` yields a `validator_index` and then a pubkey.
* `Relays[s][relay_index]` yields a `validator_index` and then a pubkey.

---

## 4. Cryptographic and Coding Primitives

### 4.1 Hash

`Hash(x)` is SHA-256, returning 32 bytes, and used as Solana `Hash`.

### 4.2 Signatures

All signatures are Ed25519 over the exact byte strings defined below.

### 4.3 Vector commitment: fixed-depth Merkle with 20-byte proof entries

This section defines a Merkle commitment scheme that yields:

* Commitment/root: 32 bytes.
* Proof entries: 20 bytes each.
* Proof length: 8 entries (for 256-leaf padded tree).

This choice is **intentional** to keep UDP packet sizes fixed at 1225 bytes; see §15.4 for security notes.

#### 4.3.1 Domain separation

All hashes use domain separation:

* `LEAF_PREFIX = 0x00`
* `NODE_PREFIX = 0x01`
* `LEAF_DOMAIN = ASCII("SOLANA_MCP_MERKLE_LEAF_V1")`
* `NODE_DOMAIN = ASCII("SOLANA_MCP_MERKLE_NODE_V1")`

#### 4.3.2 Leaf hash

Given a leaf payload `leaf_bytes` (exactly `MCP_SHRED_PAYLOAD_BYTES = 952` bytes):

```
leaf_hash = SHA256(LEAF_PREFIX || LEAF_DOMAIN || leaf_bytes)   // 32 bytes
leaf_trunc = leaf_hash[0..20]                                 // 20 bytes
```

#### 4.3.3 Node hash

Given two children hashes as **20-byte truncations**:

```
node_hash = SHA256(NODE_PREFIX || NODE_DOMAIN || left20 || right20)  // 32 bytes
node_trunc = node_hash[0..20]                                        // 20 bytes
```

#### 4.3.4 Tree shape, padding, and commitment

For each proposer payload in slot `s` and proposer `q`, define:

* Leaves `L[i]` for `i = 0..255` (256 leaves).
* For `i < NUM_RELAYS (200)`, `L[i]` is the leaf hash of the shred payload bytes at `shred_index=i`.
* For `i ≥ 200`, `leaf_bytes` is **all zeros** (952 zero bytes).

The Merkle tree is built bottom-up as a complete binary tree over 256 leaves, using `leaf_trunc` and `node_trunc` as the values carried upward. The **commitment** is the full 32-byte `node_hash` at the root (not truncated).

#### 4.3.5 Proof / witness

A witness for `shred_index i` is the concatenation of the **8 sibling truncations** (20 bytes each) along the path from leaf `i` to the root:

```
witness = sibling0_20 || sibling1_20 || ... || sibling7_20     // 160 bytes
witness_len = 8                                               // u8
```

Verification recomputes upward hashes exactly as in §4.3.3 and checks that the resulting root equals the commitment.

### 4.4 Erasure coding (Reed–Solomon)

MCP uses a systematic Reed–Solomon erasure code with parameters:

* `N = NUM_RELAYS = 200` total shreds
* `K = K_DATA_SHREDS = 40` data shreds
* `N-K = 160` coding shreds

#### 4.4.1 Encoding interface

Given a payload byte string `M` of length `|M| ≤ MAX_PROPOSER_PAYLOAD_BYTES`:

1. Pad `M` with trailing zero bytes to length exactly `K * MCP_SHRED_PAYLOAD_BYTES`.
2. Split into `K` equal-size chunks of length `MCP_SHRED_PAYLOAD_BYTES`.
3. Apply systematic RS encoding across chunk positions to produce `N` chunks (each 952 bytes).

Output is `shreds[0..N-1]`, each `shreds[i]` exactly 952 bytes.

#### 4.4.2 Decoding interface

Given any set of `K` distinct shard indices and shard bytes `{(i, shreds[i])}`, decode deterministically to recover the original `K` data shards and thus the padded message `M_padded`. The original message length is recovered from the payload header (§5.1).

**Determinism requirement:** all implementations MUST produce identical output bytes given the same input shards. Nodes MUST reject shards with invalid Merkle proofs before attempting decoding.

---

## 5. Canonical Data Structures

All integers are little-endian unless stated otherwise.

### 5.1 Proposer payload format: `McpPayloadV1`

This is the byte string `M` that proposers encode with RS (§4.4).

```
struct McpPayloadV1 {
  u8   payload_version;        // = 1
  u64  slot;                   // slot number
  u32  proposer_index;         // [0..NUM_PROPOSERS-1]
  u32  payload_len;            // number of bytes following this field (payload body length)
  u16  tx_count;               // number of transactions
  TxEntry txs[tx_count];       // concatenated
  // payload body may include reserved bytes; tx parsing uses tx_count+tx_len
}

struct TxEntry {
  u16  tx_len;                 // length in bytes of serialized transaction
  u8   tx_bytes[tx_len];
}
```

**Constraints:**

* `payload_len` MUST equal the number of bytes from `tx_count` to the end of the payload.
* Each `tx_len` MUST be `> 0` and MUST be ≤ 4096.
* Total serialized payload length MUST be ≤ `MAX_PROPOSER_PAYLOAD_BYTES` (38,080).

### 5.2 Proposer commitment signature

The proposer signs the commitment with slot binding:

```
proposer_sig_msg = ASCII("mcp:commitment:v1") || LE64(slot) || LE32(proposer_index) || commitment32
proposer_signature = Ed25519Sign(SK_proposer, proposer_sig_msg)
```

This signature is carried inside shreds and attestations.

---

## 6. Wire Formats

This section defines the on-wire messages. Implementations MAY transport these over UDP/Turbine/gossip, but the **byte formats and signature messages are normative**.

### 6.1 Shred message: `McpShredV1` (1225 bytes)

| Offset | Field | Type | Bytes |
|---:|---|---|---:|
| 0 | slot | u64 | 8 |
| 8 | proposer_index | u32 | 4 |
| 12 | shred_index | u32 | 4 |
| 16 | commitment | [u8; 32] | 32 |
| 48 | shred_data | [u8; 952] | 952 |
| 1000 | witness_len | u8 | 1 |
| 1001 | witness | [u8; 160] | 160 |
| 1161 | proposer_signature | [u8; 64] | 64 |

**Semantics:**

* `shred_index` MUST equal the receiver relay’s `relay_index` for that slot.
* `witness_len` MUST equal `MERKLE_PROOF_ENTRIES = 8`. Any other value is invalid.

### 6.2 Relay attestation: `RelayAttestationV1` (variable)

| Field | Type |
|---|---|
| slot | u64 |
| relay_index | u32 |
| num_attestations | u8 |
| entries | `num_attestations` × `AttestationEntryV1` |
| relay_signature | [u8; 64] |

```
struct AttestationEntryV1 {
  u32 proposer_index;
  [u8;32] commitment;
  [u8;64] proposer_signature;
}
```

**Relay signature message:**

```
relay_sig_msg = ASCII("mcp:relay-attestation:v1") || serialize_without_relay_signature(attestation)
relay_signature = Ed25519Sign(SK_relay, relay_sig_msg)
```

**Constraints:**

* `num_attestations` MUST be ≤ `NUM_PROPOSERS` (16).
* Entries MUST be sorted by ascending `proposer_index`.
* At most one entry per proposer_index.

### 6.3 Consensus block payload: `McpBlockV1` (variable)

This is the MCP payload inside an Alpenglow block for slot `s`.

| Field | Type |
|---|---|
| slot | u64 |
| leader_index | u32 |
| delayed_bankhash | [u8; 32] |
| num_relays | u16 |
| relay_entries | `num_relays` × `RelayEntryV1` |
| leader_signature | [u8; 64] |

```
struct RelayEntryV1 {
  u32 relay_index;
  u8  num_attestations;
  AttestationEntryV1 entries[num_attestations];
  [u8;64] relay_signature;
}
```

**Leader signature and block hash:**

Define:

```
block_body = serialize_without_leader_signature(McpBlockV1)
block_hash = SHA256(ASCII("mcp:block-hash:v1") || block_body)
leader_signature = Ed25519Sign(SK_leader, ASCII("mcp:block-sig:v1") || block_hash)
```

Validators vote on `block_hash` (carried in vote messages).

**Constraints:**

* `num_relays` MUST be ≥ `MIN_RELAYS_IN_BLOCK` (= 120) for the block to be valid.
* `relay_entries` MUST be sorted by ascending `relay_index`.
* `relay_index` values MUST be distinct.

### 6.4 Vote message: `McpVoteV1` (117 bytes)

This is the compact vote format used by MCP-aware consensus voting.

| Offset | Field | Type | Bytes |
|---:|---|---|---:|
| 0 | slot | u64 | 8 |
| 8 | validator_index | u32 | 4 |
| 12 | block_hash | [u8; 32] | 32 |
| 44 | vote_type | u8 | 1 |
| 45 | timestamp | i64 | 8 |
| 53 | signature | [u8; 64] | 64 |

`signature = Ed25519Sign(SK_validator, ASCII("mcp:vote:v1") || serialize_without_signature(vote))`.

---

## 7. Transaction Format

MCP uses a transaction format that matches Solana transaction semantics with an additional `transaction_config_mask` and optional config values.

This section is normative for MCP-specific fields; all other transaction semantics follow the Solana runtime.

### 7.1 Transaction V1 layout (summary)

```
offset  size  field
0       1     version_byte
1       3     legacy_header (3x u8)
4       4     transaction_config_mask (u32)
8       32    lifetime_specifier ([u8;32])   // recent blockhash or durable nonce hash
40      1     num_instructions (u8)
41      1     num_addresses (u8)
42      var   addresses ([u8;32] * num_addresses)
...     var   config values in bit order
...     var   instruction headers
...     var   instruction payloads
...     var   signatures
```

### 7.2 Config mask bits (u32)

| Bit index | Name | Type | Meaning |
|---:|---|---|---|
| 0 | `inclusion_fee` | u32 | Lamports paid to proposer for including this tx |
| 1 | `ordering_fee` | u32 | Lamports paid to proposer for higher intra-proposer ordering |
| 2 | `compute_unit_limit` | u32 | Requested CU limit |
| 3 | `accounts_data_size_limit` | u32 | Requested accounts data size |
| 4 | `heap_size` | u32 | Requested heap size |
| 5 | `target_proposer` | u32 | If present, only proposer with this proposer_index may include |

Fields are serialized in ascending bit index order, omitting fields whose bits are not set.

### 7.3 Limits

* Max serialized tx size: **4096 bytes**.
* Max signature count (MCP format max): **42**.
* Max accounts: **96**.
* Max instructions: **255**.

---

## 8. Proposer Operations

### 8.1 Transaction intake and filtering

For slot `s`, proposer `q`:

1. Collect pending transactions from the network/mempool.
2. Perform **stateless validation**:
   * Transaction parses correctly.
   * Signatures verify.
   * Serialized size ≤ 4096 bytes.
3. Apply target filtering:
   * If tx has `target_proposer` and it is not equal to `q`, discard the tx.

### 8.2 Ordering and packing

Proposer ordering is deterministic:

1. Define `ordering_fee(tx)` = tx.config.ordering_fee if present else 0.
2. Define `tx_hash = SHA256(serialized_tx_bytes)`.
3. Sort transactions by:
   1. `ordering_fee` descending
   2. `tx_hash` ascending

Pack transactions in that order into `McpPayloadV1` until adding the next tx would exceed `MAX_PROPOSER_PAYLOAD_BYTES`.

### 8.3 Encoding and commitment

1. Serialize `McpPayloadV1` to bytes `M`.
2. Erasure-encode `M` into `NUM_RELAYS` shreds of 952 bytes (§4.4).
3. Compute Merkle commitment root over the shred vector (§4.3).
4. Compute `proposer_signature` over `(slot, proposer_index, commitment)` (§5.2).
5. For each relay_index `r`:
   * Compute Merkle witness for leaf `r`.
   * Construct `McpShredV1` with `shred_index = r` and send to relay `r` (unicast).

---

## 9. Relay Operations

### 9.1 Shred verification (per received `McpShredV1`)

Relay `r` for slot `s`:

1. Verify `slot == s` and `shred_index == relay_index(r)`.
2. Verify `proposer_index ∈ [0, NUM_PROPOSERS-1]`.
3. Verify `witness_len == 8`.
4. Verify `proposer_signature` against the expected proposer pubkey:
   * `PK_q = Proposers[s][proposer_index]`
   * Verify `Ed25519Verify(PK_q, proposer_sig_msg, proposer_signature)`
5. Verify Merkle witness for `shred_data` at index `shred_index` yields `commitment`.

If any check fails, the shred is dropped.

### 9.2 Storage and retransmission

For each verified shred, relay stores it under key `(slot, proposer_index, shred_index)` and **broadcasts** the verified shred to the validator network (gossip / turbine), so validators can count and reconstruct shreds before voting.

Relays MUST NOT retransmit invalid shreds.

### 9.3 Relay attestation construction

At the attestation deadline for slot `s`:

1. For each proposer `q`, if the relay has a verified shred for `q`, include an `AttestationEntryV1`:
   * `(proposer_index=q, commitment, proposer_signature)`
2. Sort entries by ascending proposer_index.
3. Sign as in §6.2 and send `RelayAttestationV1` to the slot leader.

---

## 10. Consensus Leader Operations

For slot `s`, leader `L`:

1. Collect `RelayAttestationV1` messages until the leader proposal deadline.
2. For each received relay attestation:
   * Verify the relay is a member of `Relays[s]` at the claimed `relay_index`.
   * Verify the relay signature.
   * Verify each `AttestationEntryV1`:
     * proposer_index is in range
     * proposer is in `Proposers[s]`
     * proposer signature is valid for `(s, proposer_index, commitment)`
3. Build `McpBlockV1`:
   * Include at least `MIN_RELAYS_IN_BLOCK` distinct relay entries (120).
   * Set `delayed_bankhash = BankHash(s - BANKHASH_DELAY_SLOTS)` from the leader’s local finalized fork view.
4. Compute `block_hash` and `leader_signature` (§6.3).
5. Broadcast `(McpBlockV1, block_hash)` to all validators as the MCP payload of the Alpenglow block for slot `s`.

---

## 11. Validator Operations

### 11.1 Block validation (before voting)

Upon receiving an Alpenglow block for slot `s` containing `McpBlockV1`:

1. Verify `leader_index` matches the expected Alpenglow leader for slot `s`.
2. Verify `leader_signature` against `block_hash` (§6.3).
3. Verify `delayed_bankhash` equals the validator’s local `BankHash(s - BANKHASH_DELAY_SLOTS)` on its finalized fork.
4. Verify `num_relays ≥ MIN_RELAYS_IN_BLOCK` and relay entries are sorted and unique.
5. Verify each relay entry:
   * Relay is scheduled for slot `s` at `relay_index`.
   * Relay signature is valid.
   * Entries are sorted and unique per proposer_index.
   * Each proposer_signature is valid.

If any verification fails, the validator MUST treat the block as invalid and MUST NOT vote for it.

### 11.2 Compute implied proposer commitments (`computeImpliedBlocks`)

Given a valid `McpBlockV1`, validators compute which proposer commitments are “implied” by the relay attestations.

For each proposer_index `q`:

1. Gather all `(commitment, proposer_signature)` pairs for proposer `q` appearing in any relay entry.
2. **Proposer equivocation rule:**  
   If there exist **two different commitments** `C1 != C2` for proposer `q` such that both have valid proposer signatures for slot `s`, then proposer `q` is **equivocating** and MUST be excluded (no commitment for `q` is implied).
3. Otherwise, count relay support:
   * Let `count(C)` be the number of distinct relays in the block that attest to commitment `C` for proposer `q`.
4. Choose `C*` as the commitment with maximum `count(C)`. Break ties by choosing the lexicographically smallest commitment bytes.
5. If `count(C*) ≥ MIN_RELAYS_PER_PROPOSER` (= 80), then `(q, C*)` is included in `ImpliedBlocks`. Otherwise proposer `q` is excluded.

`ImpliedBlocks` is the set of included proposer commitments.

### 11.3 Availability check before voting

For each `(q, commitment)` in `ImpliedBlocks`:

1. Count the number of **distinct shred_index** values for which the validator has a shred that:
   * matches `(slot s, proposer_index q, commitment)`, and
   * has a valid Merkle proof
2. If this count is `< K_DATA_SHREDS` (= 40), the validator MUST NOT vote yet.

If all implied proposer commitments meet this local availability threshold, the validator MAY vote (subject to underlying Alpenglow rules).

---

## 12. Replay Operations

Replay begins once the block is finalized in the underlying consensus.

### 12.1 Deterministic reconstruction: `DeterministicECCDecode`

For each `(q, commitment)` in `ImpliedBlocks`:

1. Collect all locally stored shreds `(i, shred_data[i])` for this `(slot, proposer_index=q, commitment)` that pass Merkle verification.
2. If fewer than `K_DATA_SHREDS` distinct indices exist, output `⊥` for this proposer.
3. Let `I` be the sorted list of available indices; take the first `K_DATA_SHREDS` indices `I0`.
4. Decode RS using shards at indices `I0` to recover `M_padded`.
5. Re-encode `M_padded` and re-compute Merkle commitment root:
   * If it does not equal `commitment`, output `⊥` for this proposer.
6. Otherwise, parse `M_padded` as `McpPayloadV1`:
   * Use `payload_len`, `tx_count`, and `tx_len` to recover the exact payload bytes and transactions.
   * Reject malformed payloads (length mismatches, invalid tx lengths) by outputting `⊥`.

### 12.2 Global ordering

Let `TxList[q]` be the list of parsed transactions for proposer `q`, in the order encoded by the proposer (already deterministically sorted in §8.2).

The global ordered transaction stream is:

1. Iterate proposers by increasing proposer_index:
   ```
   Ordered = concat(TxList[0], TxList[1], ..., TxList[NUM_PROPOSERS-1])
   ```
2. Transactions from excluded or failed proposers (`⊥`) contribute nothing.

### 12.3 De-duplication

To prevent multiple charging/execution of identical transactions, validators MUST deterministically de-duplicate:

* Define `txid = SHA256(serialized_tx_bytes)`.
* When scanning `Ordered`, keep the **first** occurrence of each `txid` and drop subsequent duplicates.

The first occurrence determines which proposer receives MCP fees (§13.2).

### 12.4 Two-phase processing

Replay is executed in two phases to separate fee collection from state transition outcomes.

**Phase A — Fee deduction (pre-execution):**

For each tx in de-duplicated order:

1. Perform Solana’s standard prechecks (signature, lifetime_specifier, etc.).
2. Compute standard fees (signature fee, prioritization fee) per runtime rules.
3. Compute MCP fees:
   * inclusion_fee (u32 lamports, default 0)
   * ordering_fee (u32 lamports, default 0)
4. Attempt to deduct all fees from the fee payer.
   * If fee payer cannot cover total fees, mark tx failed and do not execute.
5. Distribute MCP fees to the **including proposer** (the proposer_index whose list contributed the first occurrence).

**Phase B — Execution (state transitions):**

Execute only transactions that passed Phase A fee deduction.

* No additional fee charging is performed.
* Record success/failure outcomes per standard Solana semantics.

### 12.5 Empty / skipped slots

If the underlying consensus output for slot `s` is `⊥`, MCP replay output is the empty list `∅`.

---

## 13. Fee Mechanics

### 13.1 Fee types

| Fee | Source | Recipient | Charged when |
|---|---|---|---|
| signature fee | runtime | validator rewards | Phase A |
| prioritization fee | runtime | validator rewards | Phase A |
| inclusion_fee | tx config | including proposer | Phase A |
| ordering_fee | tx config | including proposer | Phase A |

### 13.2 Including proposer

The including proposer for a transaction is the proposer_index that contributed the tx’s **first occurrence** in the global ordered list (after ordering but before de-dup).

### 13.3 Execution failure

Fees charged in Phase A are **not refunded** if Phase B execution fails.

---

## 14. Storage Schema

Suggested Blockstore column families (names are informative; exact implementation may vary):

| Column Family | Key | Value |
|---|---|---|
| `McpShred` | `(slot, proposer_index, shred_index)` | full `McpShredV1` bytes |
| `McpRelayAttestation` | `(slot, relay_index)` | `RelayAttestationV1` bytes |
| `McpBlock` | `(slot, block_hash)` | `McpBlockV1` bytes |
| `McpReconstructedPayload` | `(slot, block_hash, proposer_index)` | `McpPayloadV1` bytes or `⊥` |
| `McpExecutionOutput` | `(slot, block_hash)` | execution result |

Key encoding for on-disk ordering should use big-endian for `slot` if lexicographic ordering is desired; on-wire encoding is little-endian.

---

## 15. Security Considerations

### 15.1 Proposer equivocation

A proposer that signs two different commitments for the same `(slot, proposer_index)` is excluded entirely (§11.2).

### 15.2 Relay equivocation

If a relay sends conflicting relay attestations for the same slot (different signed bodies), leaders and validators SHOULD ignore that relay’s entries. Implementations SHOULD log and penalize via gossip slashing policy if available.

### 15.3 Data availability

Requiring both:

* `MIN_RELAYS_IN_BLOCK` relay attestations in the block (≥120), and
* per-proposer inclusion threshold (≥80 relays)

combined with validator local availability checks (≥40 shreds) prevents leaders from including proposer commitments that the network cannot reconstruct.

### 15.4 Truncated Merkle proofs

This spec uses 20-byte truncated proof entries and feeds only 20-byte truncations into parent hashing (§4.3). This is a tradeoff to keep fixed UDP packet sizes; it reduces Merkle collision resistance vs full 32-byte paths.

Future versions may switch to full 32-byte entries (at the cost of reduced shred payload bytes) or to alternative vector commitments.

### 15.5 DoS considerations

Relays and validators MUST enforce:

* maximum tx size and counts,
* maximum proposer payload bytes,
* maximum witness_len,
* strict parsing and bounds checks.

---

## 16. Determinism Requirements

All nodes MUST agree on:

1. `ValidatorRegistry_E` ordering.
2. Committee selection for proposers/relays for every slot.
3. RS encoding/decoding output bytes.
4. Merkle commitment and witness verification.
5. `computeImpliedBlocks` tie-break rules.
6. Deterministic reconstruction index selection (lowest K indices).
7. Transaction ordering, de-duplication, fee charging, and execution outputs.

---

## 17. Forward-Compatible Extensions

The following are explicitly deferred to future versions:

* Threshold encryption / hiding.
* Multi-FEC / streaming proposer payloads (multiple commitments per proposer per slot).
* Relay replay watermark / lag-based replay budget control.

---

## 18. References

* Solana MCP Specification (interactive “Part 1”): https://mcpspec.vercel.app/  
* “Supernova: Fast Multiple Concurrent Proposers via Threshold Encryption”, Nov 23 2025 (used for committee/threshold intuition and deterministic reconstruction pattern; encryption sections ignored in this version).

