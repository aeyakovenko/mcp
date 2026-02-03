MCP plan review — fresh scan executive summary with evidence (2026-02-03)

## Status: PASS — 1 SPEC AMENDMENT required, all line references verified

---

## Critical Issues

**NONE** — All critical issues resolved or properly documented.

---

## High Issues

### 1) Transaction wire format requires spec amendment (ACKNOWLEDGED DEVIATION)

- **Plan:** Uses standard Solana wire-format transactions (`plan.md:87-94`).
- **Spec:** Section 7.1 requires new MCP Transaction format with VersionByte, TransactionConfigMask, ordering_fee, inclusion_fee fields (`docs/src/proposals/mcp-protocol-spec.md:280-303`).
- **Status:** Plan explicitly documents this as `SPEC AMENDMENT REQUIREMENT` at `plan.md:87-94`. This is not a bug — it's a known deviation pending formal spec change.
- **Resolution:** Either amend spec to allow standard Solana txs for MCP v1, or implement spec §7.1 format.

---

## Medium Issues

### 2) MCP_DELAY_SLOTS definition location (spec clarification needed)

- **Plan:** Introduces `MCP_DELAY_SLOTS = 32` as an MCP constant (`plan.md:80-81`).
- **Spec:** Says delayed slot is "defined by the consensus protocol" (`docs/src/proposals/mcp-protocol-spec.md:187-190`).
- **Analysis:** The spec phrase "defined by the consensus protocol" is ambiguous. MCP is part of the consensus protocol, so defining this constant in MCP is valid. The plan provides rationale: "matches typical optimistic confirmation latency (~12.8 seconds)".
- **Resolution:** Spec clarification recommended to explicitly state where this constant is defined (MCP spec vs Alpenglow spec vs genesis).

### 3) Column pattern references could cite both locations (documentation improvement)

- **Plan:** References `AlternateShredData` at `column.rs:174` as the 3-tuple pattern (`plan.md:26`, `plan.md:220`).
- **Code reality:**
  - Line 174: `pub struct AlternateShredData;` — struct definition with doc comment showing index type `(slot: u64, shred_index: u64, block_id: Hash)`
  - Line 742: `impl Column for columns::AlternateShredData` — trait impl showing `key()`, `index()`, `slot()`, `as_index()` methods
- **Analysis:** Plan correctly cites the struct definition (174) which includes the index type. However, implementers would benefit from seeing both locations.
- **Status:** NOT A BUG — plan reference is accurate. Could be improved by citing both lines.
- **Resolution:** Consider updating plan line 220 to: "follow the `AlternateShredData` pattern (struct at `column.rs:174`, Column impl at `column.rs:742`)"

---

## Line Reference Verification (All 31 verified accurate)

| Reference | Plan Location | Actual Code | Status |
|-----------|---------------|-------------|--------|
| `column.rs:174` | AlternateShredData struct | `pub struct AlternateShredData;` | ✓ EXACT |
| `column.rs:353` | SlotColumn trait | `pub trait SlotColumn<Index = Slot> {}` | ✓ EXACT |
| `column.rs:308` | Column trait | Verified | ✓ EXACT |
| `sigverify_shreds.rs:162` | recv_timeout | `recv_timeout(RECV_TIMEOUT)?` | ✓ EXACT |
| `sigverify_shreds.rs:190-203` | dedup logic | Verified | ✓ EXACT |
| `sigverify_shreds.rs:423` | verify_packets | `fn verify_packets(...)` | ✓ EXACT |
| `window_service.rs:190` | run_insert | Verified | ✓ EXACT |
| `window_service.rs:213` | handle_shred closure | Verified | ✓ EXACT |
| `replay_stage.rs:330` | ReplayReceivers | Verified | ✓ EXACT |
| `replay_stage.rs:823` | main loop | Verified | ✓ EXACT |

All remaining 21 references verified in claude.md section 2a.

---

## Summary

The MCP implementation plan is sound. The only outstanding issue requiring action is the transaction wire format spec amendment, which is already documented in the plan as a known deviation.
