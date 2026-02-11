use std::cmp::Reverse;

pub fn concat_batches_by_proposer_index<T>(
    proposer_batches: impl IntoIterator<Item = (u32, Vec<T>)>,
) -> Vec<T> {
    let mut batches: Vec<(u32, Vec<T>)> = proposer_batches.into_iter().collect();
    // Canonical proposer order for deterministic replay.
    batches.sort_by_key(|(proposer_index, _)| *proposer_index);

    let mut out = Vec::with_capacity(batches.iter().map(|(_, batch)| batch.len()).sum());
    for (_, batch) in batches {
        out.extend(batch);
    }
    out
}

pub fn order_batches_by_fee_desc<T>(
    proposer_batches: impl IntoIterator<Item = (u32, Vec<T>)>,
    mut ordering_fee_of: impl FnMut(&T) -> u64,
) -> Vec<T> {
    let mut concatenated = concat_batches_by_proposer_index(proposer_batches);
    // Stable sort keeps concatenation order for equal fees.
    concatenated.sort_by_cached_key(|tx| Reverse(ordering_fee_of(tx)));
    concatenated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Tx {
        id: &'static str,
        fee: u64,
    }

    #[test]
    fn test_concat_batches_by_proposer_index_is_deterministic() {
        let batches = vec![
            (
                5,
                vec![Tx { id: "p5-0", fee: 5 }, Tx { id: "p5-1", fee: 1 }],
            ),
            (
                2,
                vec![Tx { id: "p2-0", fee: 9 }, Tx { id: "p2-1", fee: 8 }],
            ),
            (3, vec![Tx { id: "p3-0", fee: 7 }]),
        ];

        let ordered = concat_batches_by_proposer_index(batches);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["p2-0", "p2-1", "p3-0", "p5-0", "p5-1"]);
    }

    #[test]
    fn test_order_batches_by_fee_desc_highest_first() {
        let batches = vec![
            (1, vec![Tx { id: "a", fee: 10 }, Tx { id: "b", fee: 4 }]),
            (0, vec![Tx { id: "c", fee: 12 }, Tx { id: "d", fee: 7 }]),
            (2, vec![Tx { id: "e", fee: 11 }]),
        ];

        let ordered = order_batches_by_fee_desc(batches, |tx| tx.fee);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["c", "e", "a", "d", "b"]);
    }

    #[test]
    fn test_fee_ties_keep_concatenated_position_order() {
        let batches = vec![
            (
                1,
                vec![Tx { id: "p1-0", fee: 5 }, Tx { id: "p1-1", fee: 5 }],
            ),
            (
                0,
                vec![Tx { id: "p0-0", fee: 5 }, Tx { id: "p0-1", fee: 5 }],
            ),
        ];

        // Concatenated order is p0 then p1; ties should preserve this order.
        let ordered = order_batches_by_fee_desc(batches, |tx| tx.fee);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["p0-0", "p0-1", "p1-0", "p1-1"]);
    }

    #[test]
    fn test_duplicate_proposer_indices_preserve_input_batch_order() {
        let batches = vec![
            (3, vec![Tx { id: "first", fee: 1 }]),
            (3, vec![Tx { id: "second", fee: 1 }]),
            (2, vec![Tx { id: "p2", fee: 1 }]),
        ];

        let ordered = concat_batches_by_proposer_index(batches);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["p2", "first", "second"]);
    }

    #[test]
    fn test_concat_handles_empty_and_single_batches() {
        let ordered_empty: Vec<Tx> = concat_batches_by_proposer_index(Vec::new());
        assert!(ordered_empty.is_empty());

        let ordered_single =
            concat_batches_by_proposer_index(vec![(9, vec![Tx { id: "only", fee: 42 }])]);
        let ids: Vec<_> = ordered_single.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["only"]);
    }

    #[test]
    fn test_order_handles_empty_and_single_batches() {
        let empty_batches: Vec<(u32, Vec<Tx>)> = Vec::new();
        let ordered_empty: Vec<Tx> = order_batches_by_fee_desc(empty_batches, |tx| tx.fee);
        assert!(ordered_empty.is_empty());

        let ordered_single =
            order_batches_by_fee_desc(vec![(9, vec![Tx { id: "only", fee: 42 }])], |tx| tx.fee);
        let ids: Vec<_> = ordered_single.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["only"]);
    }

    #[test]
    fn test_duplicate_transactions_are_not_deduplicated() {
        let batches = vec![
            (
                0,
                vec![Tx {
                    id: "dup",
                    fee: 10,
                }],
            ),
            (
                1,
                vec![Tx {
                    id: "dup",
                    fee: 10,
                }],
            ),
        ];

        let ordered = order_batches_by_fee_desc(batches, |tx| tx.fee);
        let ids: Vec<_> = ordered.into_iter().map(|tx| tx.id).collect();
        assert_eq!(ids, vec!["dup", "dup"]);
    }
}
