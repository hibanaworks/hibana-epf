extern crate std;

use super::*;
use crate::Protocol;
use hibana::{g, runtime::program::project, runtime::tap};
use std::{vec, vec::Vec};

#[test]
#[cfg(not(miri))]
fn predecessor_sweep_matches_recursive_order_for_every_six_leaf_binary_tree() {
    use std::boxed::Box;
    #[derive(Clone)]
    enum Tree {
        Leaf,
        Branch(usize, Box<Tree>, Box<Tree>),
    }
    impl Tree {
        fn leaves(&self) -> usize {
            match self {
                Self::Leaf => 1,
                Self::Branch(_, left, right) => left.leaves() + right.leaves(),
            }
        }
        fn index(&self, start: usize, parent: usize, rows: &mut [usize]) {
            if let Self::Branch(kind, left, right) = self {
                let node = start + left.leaves() - 1;
                rows[3 * node..3 * node + 3].copy_from_slice(&[
                    parent,
                    start + self.leaves(),
                    *kind,
                ]);
                left.index(start, node, rows);
                right.index(node + 1, node, rows);
            }
        }
        fn before(&self, first: usize, second: usize) -> bool {
            match self {
                Self::Leaf => false,
                Self::Branch(kind, left, right) => {
                    let split = left.leaves();
                    if second < split {
                        left.before(first, second)
                    } else if first >= split {
                        right.before(first - split, second - split)
                    } else {
                        first < second && *kind == 0
                    }
                }
            }
        }
    }
    fn trees(leaves: usize) -> Vec<Tree> {
        if leaves == 1 {
            return vec![Tree::Leaf];
        }
        let mut result = Vec::new();
        for split in 1..leaves {
            for left in trees(split) {
                for right in trees(leaves - split) {
                    for kind in 0..3 {
                        result.push(Tree::Branch(
                            kind,
                            Box::new(left.clone()),
                            Box::new(right.clone()),
                        ));
                    }
                }
            }
        }
        result
    }
    // Borrow a real selected six-event path. Each synthetic immutable index
    // enumerates one whole binary interval tree, including inactive routes;
    // structural order does not depend on the selected actors or route arms.
    let global = g::seq(
        g::seq(
            g::send::<0, 0, g::Msg<1, ()>>(),
            g::send::<0, 0, g::Msg<2, ()>>(),
        ),
        g::seq(
            g::seq(
                g::send::<0, 0, g::Msg<3, ()>>(),
                g::send::<0, 0, g::Msg<4, ()>>(),
            ),
            g::seq(
                g::send::<0, 0, g::Msg<5, ()>>(),
                g::send::<0, 0, g::Msg<6, ()>>(),
            ),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
    let steps = [Unfold::Source];
    let mut expansion = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let source = protocol.unfolding(&steps, &mut expansion).unwrap();
    let mut selection = vec![0; source.path_workspace_len().unwrap()];
    let path = source.select(&[], &mut selection).unwrap();
    let mut checked = 0;
    for leaves in 1..=6 {
        for tree in trees(leaves) {
            let mut index = vec![usize::MAX; 3 * (leaves - 1)];
            tree.index(0, usize::MAX, &mut index);
            let path = SourcePath {
                index: &index,
                ..path
            };
            let mut rows = vec![usize::MAX; leaves];
            for second in (0..leaves).chain((0..leaves).rev()) {
                path.mark_source_before(second, &mut rows);
                for (first, row) in rows.iter().enumerate() {
                    let expected = first < second && tree.before(first, second);
                    assert_eq!(path.source_before(first, second), expected);
                    assert_eq!(row & super::super::word::SOURCE_ORDER != 0, expected);
                    assert_eq!(row | super::super::word::SOURCE_ORDER, usize::MAX);
                }
                path.mark_source_after(second, &mut rows);
                for (other, row) in rows.iter().enumerate() {
                    let expected = second < other && tree.before(second, other);
                    assert_eq!(path.source_before(second, other), expected);
                    assert_eq!(row & super::super::word::SOURCE_ORDER != 0, expected);
                    assert_eq!(row | super::super::word::SOURCE_ORDER, usize::MAX);
                }
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 11497);
}

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
    let locators = &index[Layout::binary_words(count).unwrap()..][..2 * count];
    let (origins, order) = locators.split_at(count);
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
                earlier: 7,
                next: 1,
                focus: [2, 3],
            }
        } else {
            Unfold::Alongside {
                retained: retained(1, 2),
                earlier: 7,
                next: 1,
                focus: [2, 3],
            }
        };
        let outer = if before {
            Unfold::Before {
                retained: retained(0, 1),
                earlier: 11,
                next: 10,
                focus: [2, 3],
            }
        } else {
            Unfold::Alongside {
                retained: retained(0, 1),
                earlier: 11,
                next: 10,
                focus: [2, 3],
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
            Unfold::Sequence([1, 6]),
            inner,
            Unfold::Source,
            Unfold::Once(9),
            Unfold::Sequence([10, 8]),
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
                Unfold::Sequence([1, 6]),
                if before {
                    Unfold::Before {
                        retained,
                        earlier: 7,
                        next: 1,
                        focus: [focus[0] + 1, focus[1] + 1],
                    }
                } else {
                    Unfold::Alongside {
                        retained,
                        earlier: 7,
                        next: 1,
                        focus: [focus[0] + 1, focus[1] + 1],
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
            let start = Layout::binary_words(4).unwrap() + 4;
            let order = &index[start..start + 4];
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
                // The complete earlier proof stays contiguous around its
                // independent tail; the resumed proof is a separate block.
                assert_eq!(order, [2, 0, 1, 3]);
            }
        }
    }
}
