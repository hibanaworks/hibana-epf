extern crate std;

use super::*;
use hibana::{
    g,
    runtime::{
        program::project,
        tap::{self, TapEvent},
    },
};
use std::{vec, vec::Vec};

#[test]
fn observed_seed_gives_nested_rolls_their_own_visit_counts() {
    let global = g::seq(
        g::seq(
            g::send::<0, 0, g::Msg<1, ()>>().roll(),
            g::send::<0, 0, g::Msg<2, ()>>(),
        )
        .roll(),
        g::send::<0, 0, g::Msg<3, ()>>(),
    );
    let snapshot = tap::projected(&project::<0>(&global)).collect::<Vec<_>>();
    let rolls = snapshot
        .iter()
        .filter(|row| {
            row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1 && row.arg1() & 3 == 0
        })
        .map(|row| row.causal_key())
        .collect::<Vec<_>>();
    let &[outer, inner] = rolls.as_slice() else {
        panic!("expected the outer and nested rolls");
    };
    let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
    for (resets, expected) in [
        ([inner, outer], [0, 0, 1, 0, 1, 2]),
        ([outer, inner], [0, 1, 0, 0, 1, 2]),
    ] {
        let observations = core::array::from_fn::<_, 2, _>(|i| {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&(i as u32).to_be_bytes());
            bytes[4..6].copy_from_slice(&tap::SCOPE_REENTRY.to_be_bytes());
            bytes[8..12].copy_from_slice(&17u32.to_be_bytes());
            bytes[12..14].copy_from_slice(&resets[i].to_be_bytes());
            TapEvent::from(bytes)
        });
        let captures = [crate::Capture::new(&observations, Some(2)).unwrap()];
        let mut steps = [Unfold::Source; 32];
        let mut workspace = [0; 8 * 32];
        let size = generate::observed_seed(protocol, &captures, 17, &mut steps, &mut workspace)
            .expect("observed resets suggest a source unfolding");
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps[..size])];
        let unfolded = protocol.unfolding(&steps[..size], &mut proof).unwrap();
        let origins = (0..unfolded.event_count())
            .map(|event| unfolded.origin(event).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(origins, expected);
    }
}

fn compare(snapshot: &[TapEvent], steps: &[Unfold]) {
    let mut source_storage = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut source_storage).unwrap();
    let mut scratch = std::vec![0; Protocol::unfolding_workspace_len(steps)];
    let source = protocol.unfolding(steps, &mut scratch).unwrap();
    // A checked More's earlier child unfolds a roll. A nonempty child must
    // contain a first copy, independently of whether a caller enumerates it.
    for step in steps {
        if let Unfold::More([earlier, _]) = *step {
            assert!(matches!(
                source.step(earlier),
                Unfold::Source | Unfold::Once(_) | Unfold::More(_) | Unfold::Independent(_)
            ));
            if source.count(earlier) != 0 {
                let span = source.copy_range(earlier, 0).unwrap();
                assert_eq!(span[0], 0);
                assert!(0 < span[1] && span[1] <= source.count(earlier));
            }
        }
    }
    for first in 0..=source.event_count() {
        let mut left = Vec::new();
        source.contexts(first, |proof, base, _| {
            left.push((proof, base));
            true
        });
        for second in 0..=source.event_count() {
            let mut right = Vec::new();
            source.contexts(second, |proof, base, _| {
                right.push((proof, base));
                true
            });
            let expected = left.iter().copied().rfind(|at| right.contains(at));
            assert_eq!(
                source.common_context(first, second),
                expected,
                "common context for {first}/{second}, steps {steps:?}"
            );
            let mut shared = expected.is_some();
            for at in &left {
                assert_eq!(
                    shared,
                    right.contains(at),
                    "shared invocations form one prefix"
                );
                if Some(*at) == expected {
                    shared = false;
                }
            }
        }
    }
    for target in 0..=source.event_count() {
        let mut witnessed = false;
        for prior in 0..source.event_count() {
            for entered in 0..source.event_count() {
                let related = source.same_resumption(prior, target, entered);
                assert!(!related || source.resumption_target(target));
                witnessed |= related;
            }
        }
        assert_eq!(source.resumption_target(target), witnessed);
    }
    let mut parts = vec![usize::MAX; Layout::path_index_words(source.event_count()).unwrap()];
    let mut parents = vec![0; source.event_count()];
    let mut stack = vec![0; 2 * source.event_count()];
    source
        .index_source(&mut parts, &mut parents, &mut stack)
        .unwrap();
    let mut actors = vec![0; source.event_count()];
    let mut selection = vec![0; source.path_workspace_len().unwrap()];
    let path = source
        .select_by(
            |_, _, _| Ok(false),
            |_, _| true,
            &mut actors,
            &parts,
            &mut selection,
        )
        .unwrap();
    for origin in 0..=Layout::checked(protocol).sources.len() {
        let expected: Vec<_> = (0..source.event_count())
            .filter(|&event| source.origin(event) == Some(origin as u16))
            .collect();
        assert_eq!(path.origin_events(origin as u16), expected);
        for first in 0..=source.event_count() {
            assert_eq!(
                path.next_origin_event(origin as u16, first),
                expected.iter().copied().find(|&event| event >= first)
            );
        }
    }
    for prior in 0..=source.event_count() {
        let mut left = Vec::new();
        source.contexts(prior, |proof, base, local| {
            left.push((proof, base, local));
            true
        });
        for target in 0..=source.event_count() {
            let mut right = Vec::new();
            source.contexts(target, |proof, base, _| {
                right.push((proof, base));
                true
            });
            let shared = left
                .iter()
                .rfind(|&&(proof, base, _)| right.contains(&(proof, base)));
            let mut expected = Vec::new();
            if let Some(&(common, _, _)) = shared
                && matches!(source.step(common), Unfold::Sequence(_))
            {
                let region = get(source.rows, common);
                let target_origin = usize::from(source.origin(target).unwrap());
                for &(proof, base, local) in &left {
                    let Unfold::More([earlier, _]) = source.step(proof) else {
                        continue;
                    };
                    let body = get(source.rows, proof);
                    if !right.contains(&(proof, base))
                        && source.count(earlier) != 0
                        && local >= source.count(earlier)
                        && region.start <= body.start
                        && body.end <= region.end
                        && body.end <= target_origin
                        && target_origin < region.end
                        && Layout::checked(protocol).source_before(
                            protocol,
                            region,
                            body.end - 1 - region.start,
                            target_origin - region.start,
                        )
                    {
                        expected.push((proof, base, earlier));
                    }
                }
            }
            let mut indexed = Vec::new();
            assert!(!path.earlier_rolls(prior, target, |proof, base, earlier| {
                indexed.push((proof, base, earlier));
                false
            }));
            expected.sort_unstable();
            indexed.sort_unstable();
            assert_eq!(
                indexed, expected,
                "prior rolls for {prior}/{target}, steps {steps:?}"
            );
            assert_eq!(
                path.earlier_rolls(prior, target, |_, _, _| true),
                !expected.is_empty()
            );
        }
    }
    for first in 0..=source.event_count() {
        for last in 0..=source.event_count() + 1 {
            let span = [first, last];
            let reference = source.kind(span).and_then(|kind| {
                if kind == NodeKind::Message {
                    return Some((kind, last));
                }
                (first + 1..last)
                    .find(|&split| {
                        source.kind([first, split]).is_some()
                            && source.kind([split, last]).is_some()
                    })
                    .map(|split| (kind, split))
            });
            assert_eq!(
                source.parts(span),
                reference,
                "span {span:?}, steps {steps:?}"
            );
            if reference.is_some() {
                assert_eq!(
                    source.indexed_parts(span, &parts),
                    reference,
                    "indexed span {span:?}, steps {steps:?}"
                );
            }
        }
    }
}

#[test]
fn structural_splits_match_full_cut_enumeration_across_all_unfolding_constructors() {
    let global = g::seq(
        g::par(
            g::send::<0, 0, g::Msg<1, ()>>(),
            g::send::<0, 0, g::Msg<2, ()>>(),
        ),
        g::route(
            g::send::<0, 0, g::Msg<3, ()>>(),
            g::send::<0, 0, g::Msg<4, ()>>(),
        ),
    )
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    compare(&snapshot, &[Unfold::Source]);
    compare(
        &snapshot,
        &[
            Unfold::Source,
            Unfold::Source,
            Unfold::Parallel([0, 1]),
            Unfold::Source,
            Unfold::Source,
            Unfold::Choice([3, 4]),
            Unfold::Sequence([2, 5]),
            Unfold::Once(6),
            Unfold::More([7, 6]),
        ],
    );
    let global = g::par(
        g::send::<0, 1, g::Msg<1, ()>>(),
        g::send::<2, 3, g::Msg<2, ()>>(),
    )
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    compare(
        &snapshot,
        &[
            Unfold::Source,
            Unfold::Once(0),
            Unfold::More([1, 0]),
            Unfold::Source,
            Unfold::Once(3),
            Unfold::Independent([2, 4]),
        ],
    );
    let global = g::seq(
        g::send::<0, 0, g::Msg<1, ()>>().roll(),
        g::seq(
            g::send::<0, 0, g::Msg<2, ()>>().roll(),
            g::send::<0, 0, g::Msg<3, ()>>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let rolls: Vec<_> = snapshot
        .iter()
        .filter(|row| {
            row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1 && row.arg1() == 0
        })
        .map(|row| row.causal_key())
        .collect();
    compare(
        &snapshot,
        &[
            Unfold::Source,
            Unfold::Once(0),
            Unfold::More([1, 0]),
            Unfold::Source,
            Unfold::Once(3),
            Unfold::More([4, 3]),
            Unfold::Source,
            Unfold::Sequence([5, 6]),
            Unfold::Sequence([2, 7]),
        ],
    );
    for inner_before in [false, true] {
        for outer_before in [false, true] {
            let inner = if inner_before {
                Unfold::Before {
                    retained: rolls[1],
                    earlier: 5,
                    next: 3,
                    focus: [1, 2],
                }
            } else {
                Unfold::Alongside {
                    retained: rolls[1],
                    earlier: 5,
                    next: 3,
                    focus: [1, 2],
                }
            };
            let outer = if outer_before {
                Unfold::Before {
                    retained: rolls[0],
                    earlier: 7,
                    next: 1,
                    focus: [2, 4],
                }
            } else {
                Unfold::Alongside {
                    retained: rolls[0],
                    earlier: 7,
                    next: 1,
                    focus: [2, 4],
                }
            };
            compare(
                &snapshot,
                &[
                    Unfold::Source,
                    Unfold::Once(0),
                    Unfold::Source,
                    Unfold::Once(2),
                    Unfold::Source,
                    Unfold::Sequence([3, 4]),
                    inner,
                    Unfold::Sequence([1, 6]),
                    outer,
                ],
            );
        }
    }
    compare(
        &snapshot,
        &[
            Unfold::Source,
            Unfold::Once(0),
            Unfold::Source,
            Unfold::Sequence([1, 2]),
            Unfold::After {
                retained: rolls[0],
                earlier: 3,
                next: 0,
            },
        ],
    );
    let nested = g::seq(
        g::seq(
            g::send::<0, 0, g::Msg<1, ()>>().roll(),
            g::send::<0, 0, g::Msg<2, ()>>(),
        )
        .roll(),
        g::send::<0, 0, g::Msg<3, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&nested)).collect();
    compare(
        &snapshot,
        &[
            Unfold::Source,
            Unfold::Once(0),
            Unfold::More([1, 0]),
            Unfold::Source,
            Unfold::Sequence([2, 3]),
            Unfold::Once(4),
            Unfold::More([5, 4]),
            Unfold::Source,
            Unfold::Sequence([6, 7]),
        ],
    );
}
