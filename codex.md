MCP plan review — executive summary with evidence (fresh read)

Critical issues that must change (with evidence)

1) Transaction wire format mismatch (spec non‑compliance)
- Plan acknowledges it uses standard Solana txs and requires a spec amendment for MCP v1 (`plan.md:85-99`).
- Spec mandates that McpPayload carries the MCP Transaction message defined in 7.1 (`docs/src/proposals/mcp-protocol-spec.md:123-128`, `docs/src/proposals/mcp-protocol-spec.md:280-303`).
- Correction: either implement spec 7.1 now or update the spec to allow standard Solana txs for MCP v1 (and gate consensus acceptance accordingly).

2) Delayed bankhash parameterization conflicts with spec
- Plan introduces `MCP_DELAY_SLOTS = 32` as an MCP constant (`plan.md:67-83`).
- Spec says the delayed slot is defined by the consensus protocol, not by MCP parameters (`docs/src/proposals/mcp-protocol-spec.md:187-190`).
- Code reality: there is no `DELAY_SLOTS` constant in the repo (`rg "DELAY_SLOTS" -S .` only hits `plan.md`).
- Correction: derive delayed slot via existing consensus config (or define a consensus‑layer constant), do not introduce a new MCP parameter without spec change.

High issues that must change (with evidence)

3) Line references are incorrect in plan (causes mis-implementation)
- Plan cites `AlternateShredData` at `column.rs:174` (`plan.md:33`).
- Actual location is around `ledger/src/blockstore/column.rs:742` (`ledger/src/blockstore/column.rs:742-772`).
- Correction: update plan line references to current code locations to avoid mis-wiring.
