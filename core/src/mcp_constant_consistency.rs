#[test]
fn test_mcp_num_proposers_constant_matches_ledger() {
    assert_eq!(
        solana_fee::MCP_NUM_PROPOSERS as usize,
        solana_ledger::mcp::NUM_PROPOSERS
    );
}
