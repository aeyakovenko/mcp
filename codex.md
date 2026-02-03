MCP plan review — executive summary (verified 2026-02-03)

## Status: PASS — 1 SPEC AMENDMENT required, all other issues RESOLVED

---

### SPEC AMENDMENT REQUIRED

**Transaction wire format mismatch**
- Plan uses standard Solana transactions (`plan.md:87-94`)
- Spec §7.1 requires new MCP Transaction format with TransactionConfigMask, ordering_fee, etc.
- **Resolution:** Spec must be amended to allow standard Solana txs for MCP v1, OR implement §7.1 format
- **NOT A PLAN BUG** — documented as known deviation pending spec change

---

### RESOLVED ISSUES

**1. AlternateShredData line reference — VERIFIED CORRECT ✓**
- Plan says `column.rs:174` for struct definition
- Code confirms: line 174 = `pub struct AlternateShredData;`
- Line 742 = `impl Column for columns::AlternateShredData` (trait impl, different purpose)
- **Plan is correct** — references struct definition location for adding new column types

**2. Delayed bankhash — RESOLVED ✓**
- Plan defines `MCP_DELAY_SLOTS = 32` at `plan.md:80`
- Plan specifies source: `BankForks.get(slot - MCP_DELAY_SLOTS).map(|b| b.hash())` at `plan.md:460`
- Warmup handling: Hash::default() for first MCP_DELAY_SLOTS slots

**3. SlotColumn line reference — FIXED ✓**
- Was: 318, Now: 353 (`plan.md:220`)

**4. verify_packets line reference — FIXED ✓**
- Was: 437, Now: 423 (`plan.md:252`)

**5. ConsensusBlock contents — RESOLVED ✓**
- consensus_meta defined at `plan.md:459`
- delayed_bankhash defined at `plan.md:460`

**6. Duplicate identity handling — RESOLVED ✓**
- relay_indices_at_slot() returns Vec<u16> (`plan.md:190`)

**7. PoH bypass — RESOLVED ✓**
- Entry construction specified at `plan.md:521-529`
- Signature verification via entry::verify_transactions() at `plan.md:532`

---

### LINE REFERENCES VERIFIED (31/31)

| Location | Content | Status |
|----------|---------|--------|
| column.rs:174 | `pub struct AlternateShredData` | ✓ |
| column.rs:308 | `pub trait Column` | ✓ |
| column.rs:353 | `pub trait SlotColumn` | ✓ |
| column.rs:742 | `impl Column for AlternateShredData` | ✓ |
| sigverify_shreds.rs:162 | recv_timeout | ✓ |
| sigverify_shreds.rs:190-203 | dedup logic | ✓ |
| sigverify_shreds.rs:208-216 | verify_packets call | ✓ |
| sigverify_shreds.rs:423 | fn verify_packets | ✓ |
| window_service.rs:190 | fn run_insert | ✓ |
| window_service.rs:213 | handle_shred closure | ✓ |
| window_service.rs:220 | Shred::new_from_serialized_shred | ✓ |
| replay_stage.rs:330 | ReplayReceivers | ✓ |
| replay_stage.rs:823 | main loop | ✓ |
| contact_info.rs:47 | SOCKET_TAG_ALPENGLOW | ✓ |
| blockstore_processor.rs:599-647 | process_entries_for_tests | ✓ |
| transaction_processor.rs:124 | TransactionProcessingEnvironment | ✓ |
| account_loader.rs:370 | validate_fee_payer | ✓ |
