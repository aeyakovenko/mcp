# MCP Audit

**Date:** 2026-02-13 | **Baseline:** commit `965da326b7`

All code-level findings resolved. Integration test passing. No open issues.

Protocol-level review raised four items (P1–P4); all are **documentation nits**, not security concerns. Reassessment below.

---

## P1: Inter-Proposer Hiding — NIT (was MEDIUM)

Immediate relay retransmit does not break any security property. A malicious proposer that reconstructs another proposer's batch gains nothing: (a) all transactions come from the public mempool — no private information in a batch, (b) the proposer already signed its Merkle root before sending shreds and cannot change its committed batch, (c) signing a second commitment is detectable equivocation and results in exclusion. The "front-running" attack is structurally impossible given commitment-before-send ordering.

## P2: Leader Equivocation — NIT

MCP spec says "consensus protocol is out of scope." Alpenglow handles leader equivocation. Adding one clarifying sentence to the spec would be nice but is not a gap.

## P3: Threshold Formalization — NIT (was MEDIUM)

The constants are mechanically determined from the RS coding parameters, not magic numbers. RECONSTRUCTION = DATA_SHREDS/NUM_RELAYS = 40/200 = 0.20 (mathematical identity). INCLUSION = 2x reconstruction = 0.40. ATTESTATION = 3x reconstruction = 0.60. The spec already states the key invariant (INCLUSION >= RECONSTRUCTION). Formal adversary-model proofs belong in a security paper, not an implementation spec — standard practice in BFT literature (Tendermint, HotStuff, Casper).

## P4: Cross-Proposer Dedup — NIT

Plan explicitly chose no cross-proposer dedup (policy B2) and documented why. Each occurrence charged the full priority fee (16x for all proposers). Correct design — cross-proposer dedup would route ties to lowest-indexed proposer, undermining censorship resistance. Spec wording ("basic validity checks") could be tighter but the implementation is unambiguous.
