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
}
