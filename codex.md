MCP plan review — evidence-backed deltas (fresh read)

Critical mismatches (plan ↔ spec) with evidence — **ALL ADDRESSED**

1) Transaction wire format — **ADDRESSED (requires spec amendment)**
- Issue: Spec section 3.1 requires section 7.1 Transaction format (TransactionConfigMask, ordering_fee, etc.)
- Fix: Plan now contains explicit "SPEC AMENDMENT REQUIREMENT" section (plan.md:85-95) documenting that standard Solana transactions are used pending a formal spec amendment. The plan no longer claims this deviation is "acceptable" — it clearly states the implementation is spec-non-compliant until the spec is amended.
- Status: Implementation proceeds with standard Solana txs, but spec amendment is tracked as blocking for full compliance.

2) ConsensusBlock contents (consensus_meta + delayed_bankhash) — **ADDRESSED**
- Issue: consensus_meta and delayed_bankhash had no concrete implementation, just vague "passed through from Alpenglow."
- Fix:
  - consensus_meta now defined (plan.md:448-449): For MCP standalone, contains 32-byte block_id = SHA-256(slot || leader_index || aggregate_hash). After Alpenglow integration, becomes opaque pass-through.
  - delayed_bankhash now defined (plan.md:450-451): MCP_DELAY_SLOTS = 32 constant added (plan.md:79-80). Leader fetches via BankForks.get(slot - MCP_DELAY_SLOTS).map(|b| b.hash()). Hash::default() accepted during warmup period.
- Status: Concrete, implementable definitions provided.

3) Plan no longer claims spec deviation is acceptable — **ADDRESSED**
- Issue: Plan said "deviation is acceptable because..." which is not the plan's authority to decide.
- Fix: Language changed to "SPEC AMENDMENT REQUIREMENT" (plan.md:85-95) and "PENDING SPEC AMENDMENT" annotations throughout. The plan clearly documents that spec amendment is needed, not that the deviation is acceptable.
- Status: Proper framing — spec amendment required, not plan author's judgment call.

---

No remaining Critical or High issues. Medium/Low items from prior passes remain documented in git history.
