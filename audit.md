# MCP Audit — Open Protocol Issues

**Date:** 2026-02-13 | **Baseline:** commit `965da326b7`

All prior code-level findings (H1, H2, M1, M2, V1, NEW-1, NEW-2) are resolved.
No open code bugs. Integration test passing.

---

## P1: Inter-Proposer Hiding — MEDIUM

Spec §3.3 requires relays to retransmit shreds immediately on receipt. Any validator (including a co-proposer) can reconstruct a batch from 40 shreds before the relay deadline. No commit-reveal phase exists. Hiding relies on temporal discipline (honest proposers send before receiving), not cryptographic guarantee.

**Risk:** Malicious proposer delays own shreds, reconstructs honest proposer's batch, front-runs.

**Recommendation:** Document that inter-proposer hiding is a timing assumption. If it becomes a hard requirement, the spec needs a commit-reveal phase.

## P2: Leader Equivocation — LOW

MCP spec is silent on leader equivocation (two ConsensusBlocks for same slot). Correctly deferred to Alpenglow BFT, but the trust boundary should be stated explicitly in the spec.

## P3: Threshold Formalization — MEDIUM

Constants (0.60/0.40/0.20) lack formal adversary-model justification. They are consistent with both 20/20 (20% malicious + 20% delinquent) and Alpenglow 1/3 adversarial models, but this derivation is unstated.

| Scenario | Adversary | Delinquent | Honest | Attestation (>=120) | Inclusion attack (<80) |
|---|---|---|---|---|---|
| 20/20 | 40 | 40 | 120 | Exactly met | 40 < 80: safe |
| Alpenglow 1/3 | 67 | 0 | 133 | Met | 67 < 80: safe |

**Recommendation:** Add adversary-model justification to spec so constants aren't magic numbers.

## P4: Cross-Proposer Dedup / Fee Incentive — LOW

Spec §8 says "basic validity checks" but doesn't define whether cross-proposer dedup is included. Plan chose no cross-proposer dedup (policy B2). Each occurrence is charged the **full transaction fee including priority/ordering fee** — a tx with ordering fee X sent to all 16 proposers pays 16X total, with 15X pure fee burn.

This is the correct design: cross-proposer dedup would route all ties to the lowest-indexed proposer, undermining censorship resistance. The 16x-full-fee cost is a strong self-penalizing disincentive that scales with transaction value.

**Recommendation:** Spec should clarify that "basic validity checks" excludes cross-proposer dedup and document the fee-burn incentive as intentional.
