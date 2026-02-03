MCP plan review — Pass 9 (final verification)

## Critical/High Issues: NONE REMAINING

All issues from prior passes have been addressed:

### Pass 8 fixes (commit e0ae74e91b):
1. Transaction wire format: Added explicit "SPEC AMENDMENT REQUIREMENT" section
2. ConsensusBlock contents: Defined MCP_DELAY_SLOTS=32, concrete consensus_meta and delayed_bankhash implementations
3. Removed "spec deviation acceptable" language

### Pass 9 fixes (commit fd7f8b8400):
1. Fixed relay_indices_at_slot naming inconsistency (singular vs plural)
2. Clarified column family patterns for McpShredData (3-tuple) vs McpRelayAttestation (2-tuple)

## Verified Non-Issues (raised in Pass 9 but determined to be false positives):

- **Relay/Proposer index storage types**: Plan correctly documents validation before narrowing cast (u32->u16, u32->u8). These ranges fit (NUM_RELAYS=200, NUM_PROPOSERS=16).
- **Merkle tree odd-level handling**: Already documented at line 110.
- **Merkle truncation**: Already documented that Agave truncates to 20 bytes, MCP uses 32-byte entries.
- **skip_fee_deduction field**: Plan explicitly documents adding this to TransactionProcessingEnvironment; that's the intended modification.
- **Leader index verification**: Already documented at line 490 ("Verify leader_signature, leader_index matches Leader[s]").

## Outstanding Spec Amendment Requirement:

The plan uses standard Solana wire-format transactions instead of spec section 7.1 format. This is documented as "SPEC AMENDMENT REQUIREMENT" and is pending formal spec amendment approval. Until amended, the implementation is spec-non-compliant on transaction format only.

## Conclusion:

No remaining Critical or High issues. Plan is ready for implementation pending spec amendment for transaction wire format.
