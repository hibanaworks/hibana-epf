extern crate std;

use super::*;
use crate::Protocol;
use hibana::{g, runtime::program::project, runtime::tap};
use std::{vec, vec::Vec};

fn pairwise_conflict(source: &Unfolded, actors: &[usize]) -> Option<(usize, usize)> {
    for first in 0..actors.len() {
        if actors[first] == usize::MAX {
            continue;
        }
        for second in first + 1..actors.len() {
            if actors[second] == usize::MAX {
                continue;
            }
            let sides = |packed: usize| [packed >> 8, packed & 255];
            if sides(actors[first])
                .iter()
                .any(|actor| sides(actors[second]).contains(actor))
                && source.independent_between(first, second)
            {
                return Some((first, second));
            }
        }
    }
    None
}

// Exhaustive predicate equivalence belongs to native tests. Miri separately
// checks the reordered insertion and highest actor-tag storage below.
#[cfg(not(miri))]
fn compare_actor_subsets(snapshot: &[tap::TapEvent], steps: &[Unfold]) {
    let mut protocol_storage = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(steps)];
    let source = protocol.unfolding(steps, &mut proof).unwrap();
    let count = source.event_count();
    assert!((2..=8).contains(&count));
    let mut positions = Vec::new();
    for event in 0..count {
        source.contexts(event, |proof, base, local| {
            if matches!(source.step(proof), Unfold::Source) {
                positions.push(base + local);
                false
            } else {
                true
            }
        });
    }
    positions.sort_unstable();
    assert_eq!(positions, (0..count).collect::<Vec<_>>());
    let mut actors = vec![0; count];
    let mut index = vec![0; Layout::path_index_words(count).unwrap()];
    let mut stack = vec![0; 2 * count];
    source
        .index_source(&mut index, &mut actors, &mut stack)
        .unwrap();
    let (origins, order) = index[Layout::binary_words(count).unwrap()..].split_at(count);
    for (event, &origin) in origins.iter().enumerate() {
        assert_eq!(origin, usize::from(source.origin(event).unwrap()));
    }
    let mut last = vec![0; 256];
    for common in [0, 128, 255] {
        for side in 0..3 {
            for mut rank in 0..3usize.pow(count as u32) {
                for (event, packed) in actors.iter_mut().enumerate() {
                    let a = 1 + 2 * event;
                    let b = a + 1;
                    *packed = match rank % 3 {
                        0 => usize::MAX,
                        1 => match side {
                            0 => common << 8 | b,
                            1 => a << 8 | common,
                            _ => common << 8 | common,
                        },
                        _ => a << 8 | b,
                    };
                    rank /= 3;
                }
                let expected = pairwise_conflict(&source, &actors);
                let observed = source.independent_conflict(&actors, order, &mut last);
                assert_eq!(observed.is_some(), expected.is_some(), "{actors:?}");
                if let Some((first, second)) = observed {
                    assert!(source.independent_between(first, second));
                    let a = [actors[first] >> 8, actors[first] & 255];
                    let b = [actors[second] >> 8, actors[second] & 255];
                    assert!(a.iter().any(|actor| b.contains(actor)));
                }
            }
        }
    }
}

#[cfg(not(miri))]
#[test]
fn nested_insertions_preserve_the_independent_subtrees_proof_order() {
    let global = g::seq(
        g::send::<0, 255, g::Msg<1, ()>>().roll(),
        g::seq(
            g::send::<0, 128, g::Msg<2, ()>>().roll(),
            g::par(
                g::send::<0, 254, g::Msg<3, ()>>(),
                g::send::<0, 127, g::Msg<4, ()>>(),
            )
            .roll(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let retained = |start, end| {
        snapshot
            .iter()
            .find(|row| {
                row.id() == tap::PROJECTED_SCOPE
                    && row.causal_key() >> 13 == 1
                    && protocol
                        .scope(row.causal_key())
                        .is_some_and(|scope| scope.start == start && scope.end == end)
            })
            .unwrap()
            .causal_key()
    };
    for before in [false, true] {
        let inner = if before {
            Unfold::Before {
                retained: retained(1, 2),
                earlier: 1,
                next: 1,
                tail: 6,
                focus: [1, 2],
            }
        } else {
            Unfold::Alongside {
                retained: retained(1, 2),
                earlier: 1,
                next: 1,
                tail: 6,
                focus: [1, 2],
            }
        };
        let outer = if before {
            Unfold::Before {
                retained: retained(0, 1),
                earlier: 9,
                next: 9,
                tail: 7,
                focus: [1, 2],
            }
        } else {
            Unfold::Alongside {
                retained: retained(0, 1),
                earlier: 9,
                next: 9,
                tail: 7,
                focus: [1, 2],
            }
        };
        let steps = [
            Unfold::Source,
            Unfold::Once(0),
            Unfold::Source,
            Unfold::Once(2),
            Unfold::Source,
            Unfold::Once(4),
            Unfold::Independent([3, 5]),
            inner,
            Unfold::Source,
            Unfold::Once(8),
            outer,
        ];
        compare_actor_subsets(&snapshot, &steps);
    }
}

#[cfg(not(miri))]
#[test]
fn adjacent_actor_checks_match_every_pair_for_nested_and_reused_visits() {
    let global = g::par(
        g::par(
            g::send::<0, 255, g::Msg<1, ()>>(),
            g::send::<0, 128, g::Msg<2, ()>>(),
        ),
        g::par(
            g::send::<0, 254, g::Msg<3, ()>>(),
            g::send::<0, 127, g::Msg<4, ()>>(),
        ),
    )
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    compare_actor_subsets(
        &snapshot,
        &[
            Unfold::Source,
            Unfold::Once(0),
            Unfold::Source,
            Unfold::Once(2),
            Unfold::Independent([1, 3]),
            Unfold::Source,
            Unfold::Once(5),
            Unfold::Source,
            Unfold::Once(7),
            Unfold::Independent([6, 8]),
            Unfold::Independent([4, 9]),
        ],
    );
    // The compact ordinary parallel child is not itself an independent visit;
    // only the outer split is guarded. Reuse its DAG in consecutive visits.
    compare_actor_subsets(
        &snapshot,
        &[
            Unfold::Source,
            Unfold::Once(0),
            Unfold::Source,
            Unfold::Once(2),
            Unfold::More([3, 2]),
            Unfold::Independent([1, 4]),
        ],
    );
}

#[test]
fn an_inserted_occurrence_cannot_hide_a_conflict_between_tail_visits() {
    let global = g::seq(
        g::send::<0, 255, g::Msg<1, ()>>().roll(),
        g::par(
            g::send::<0, 128, g::Msg<2, ()>>(),
            g::send::<0, 254, g::Msg<3, ()>>(),
        )
        .roll(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let retained = snapshot
        .iter()
        .find(|r| r.id() == tap::PROJECTED_SCOPE && r.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    for before in [false, true] {
        for focus in [[0, 1], [1, 2], [0, 2]] {
            let steps = [
                Unfold::Source,
                Unfold::Once(0),
                Unfold::Source,
                Unfold::Once(2),
                Unfold::Source,
                Unfold::Once(4),
                Unfold::Independent([3, 5]),
                if before {
                    Unfold::Before {
                        retained,
                        earlier: 1,
                        next: 1,
                        tail: 6,
                        focus,
                    }
                } else {
                    Unfold::Alongside {
                        retained,
                        earlier: 1,
                        next: 1,
                        tail: 6,
                        focus,
                    }
                },
            ];
            #[cfg(not(miri))]
            compare_actor_subsets(&snapshot, &steps);
            let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
            let source = protocol.unfolding(&steps, &mut proof).unwrap();
            let inserted = 1 + focus[0];
            let left = if inserted <= 1 { 2 } else { 1 };
            let right = 3;
            let mut actors = vec![1 << 8 | 2; 4];
            for event in [inserted, left, right] {
                actors[event] = 255 << 8 | 255;
            }
            let mut index = vec![0; Layout::path_index_words(4).unwrap()];
            source
                .index_source(&mut index, &mut [0; 4], &mut [0; 8])
                .unwrap();
            let order = &index[Layout::binary_words(4).unwrap() + 4..];
            let mut last = vec![0; usize::from(Layout::checked(protocol).max_role) + 1];
            assert!(pairwise_conflict(&source, &actors).is_some());
            assert!(
                source
                    .independent_conflict(&actors, order, &mut last)
                    .is_some()
            );
            if focus == [1, 2] {
                assert!(!source.independent_between(left, inserted));
                assert!(!source.independent_between(inserted, right));
                assert!(source.independent_between(left, right));
                assert_eq!(order, [0, 2, 1, 3]);
            }
        }
    }
}
