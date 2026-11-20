extern crate std;

use super::*;
use crate::protocol::{Protocol, RouteChoice, Unfold};
use core::cell::Cell;
#[cfg(not(miri))]
use hibana::Endpoint;
use hibana::{
    g,
    runtime::{program::project, tap},
};
use std::{vec, vec::Vec};

impl SourcePath<'_, '_, '_> {
    // Tests construct words directly. Production callers supply the index
    // they already maintain when appending or restoring that same word.
    pub(in crate::protocol) fn query_from_word(
        &self,
        history: impl Clone + Iterator<Item = SourcePoint>,
        (point, actor): (SourcePoint, u8),
        workspace: &mut [usize],
    ) -> bool {
        let mut prefix = vec![0; self.unfolding().event_count()];
        for prior in history.clone() {
            if let Some(row) = prefix.get_mut(prior.event()) {
                *row |= prior.bit();
            }
        }
        self.query_ready((history, &prefix), (point, actor), workspace)
    }
}

#[test]
fn an_unfinished_fixed_actor_in_a_mixed_parallel_prefix_blocks_the_whole_suffix() {
    let global = g::seq(
        g::par(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<2, 3, g::Msg<2, ()>>(),
        ),
        g::send::<0, 1, g::Msg<3, ()>>(),
    )
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let steps = [Unfold::Source, Unfold::Once(0), Unfold::More([1, 0])];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let source = protocol.unfolding(&steps, &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    let path = source.select(&[], &mut storage).unwrap();
    let mut prefix = vec![0; source.event_count()];

    // The unrelated actor may already have completed. Its presence or
    // completion cannot hide actor 0's mandatory unfinished send.
    let history = [SourcePoint::Accepted(1), SourcePoint::Sent(1)];
    path.check_word(&history).unwrap();
    for prior in history {
        prefix[prior.event()] |= prior.bit();
    }
    for event in [2, 3, 5] {
        assert_eq!(
            path.fixed_prefix_blocked_until(SourcePoint::Accepted(event), 0, &prefix),
            Some(source.event_count())
        );
    }
    let mut scratch = vec![usize::MAX; path.query_workspace_len().unwrap()];
    assert!(!path.query_from_word(
        history.into_iter(),
        (SourcePoint::Accepted(2), 0),
        &mut scratch
    ));
    assert!(
        scratch[source.event_count()..]
            .iter()
            .all(|word| *word == usize::MAX),
        "the missing fixed predecessor excludes the suffix before selection search"
    );
    #[cfg(not(miri))]
    compare(&snapshot, &[Unfold::Source]);
}

#[test]
fn a_mixed_parallel_prefix_does_not_require_the_other_actors_completion() {
    let global = g::seq(
        g::par(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<2, 3, g::Msg<2, ()>>(),
        ),
        g::send::<0, 1, g::Msg<3, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    let path = source.select(&[], &mut storage).unwrap();
    let history = [SourcePoint::Accepted(0), SourcePoint::Sent(0)];
    path.check_word(&history).unwrap();
    let mut prefix = vec![0; source.event_count()];
    for prior in history {
        prefix[prior.event()] |= prior.bit();
    }
    assert_eq!(
        path.fixed_prefix_blocked_until(SourcePoint::Accepted(2), 0, &prefix),
        None
    );
    let mut scratch = vec![0; path.query_workspace_len().unwrap()];
    assert!(path.query_from_word(
        history.into_iter(),
        (SourcePoint::Accepted(2), 0),
        &mut scratch
    ));
}

#[test]
fn a_committed_route_arm_keeps_its_missing_receive_mandatory() {
    let global = g::seq(
        g::route(
            g::send::<1, 0, g::Msg<1, ()>>(),
            g::send::<1, 0, g::Msg<2, ()>>(),
        )
        .resolve::<77>(),
        g::send::<0, 1, g::Msg<3, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    let path = source
        .select(
            &[RouteChoice {
                span: [0, 2],
                right: false,
            }],
            &mut storage,
        )
        .unwrap();
    let point = SourcePoint::Accepted(2);
    let mut scratch = vec![0; path.query_workspace_len().unwrap()];

    // Acceptance alone does not force this particular earlier receive:
    // another selection can still omit it, although this protocol requires
    // a receive on the other arm too before the outgoing continuation.
    let mut prefix = [SourcePoint::Accepted(0).bit(), 0, 0];
    assert!(!path.unavoidable_before(0, 2, |span| {
        prefix[span[0]..span[1]]
            .iter()
            .any(|points| points & 56 != 0)
    }));
    prefix[0] |= SourcePoint::Sent(0).bit();
    assert!(path.unavoidable_before(0, 2, |span| {
        prefix[span[0]..span[1]]
            .iter()
            .any(|points| points & 56 != 0)
    }));
    let history = [SourcePoint::Accepted(0), SourcePoint::Sent(0)];
    path.check_word(&history).unwrap();
    scratch.fill(usize::MAX);
    assert!(!path.query_from_word(history.into_iter(), (point, 0), &mut scratch));
    assert!(
        scratch[source.event_count()..]
            .iter()
            .all(|&word| word == usize::MAX),
        "a committed sender forces the earlier receive without choice search"
    );

    // Receiver commit alone also forces the arm; the delayed sender's local
    // publication must not prevent its peer's legitimate continuation.
    let history = [SourcePoint::Accepted(0), SourcePoint::Received(0)];
    path.check_word(&history).unwrap();
    assert!(path.query_from_word(history.into_iter(), (point, 0), &mut scratch));
    #[cfg(not(miri))]
    compare(&snapshot, &[Unfold::Source]);
}

#[test]
fn an_inactive_reply_cannot_skip_its_mandatory_request() {
    let global = g::route(
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<1, 0, g::Msg<2, ()>>(),
        ),
        g::seq(
            g::send::<0, 1, g::Msg<3, ()>>(),
            g::send::<1, 0, g::Msg<4, ()>>(),
        ),
    )
    .resolve::<77>();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    for right in [false, true] {
        let path = source
            .select(
                &[RouteChoice {
                    span: [0, 4],
                    right,
                }],
                &mut storage,
            )
            .unwrap();
        let mut scratch = vec![usize::MAX; path.query_workspace_len().unwrap()];
        let reply = if right { 1 } else { 3 };
        assert!(path.actors(reply).is_none());
        assert!(!path.query_from_word(
            [].into_iter(),
            (SourcePoint::Accepted(reply), 1),
            &mut scratch
        ));
        assert!(
            scratch.iter().all(|word| *word == usize::MAX),
            "an inactive reply must reject before building query workspace"
        );
    }
    #[cfg(not(miri))]
    compare(&snapshot, &[Unfold::Source]);
}

#[test]
fn a_missing_prefix_receive_skips_every_unrelated_suffix_choice() {
    let global = g::seq(
        g::send::<0, 1, g::Msg<1, ()>>(),
        g::seq(
            g::route(
                g::send::<1, 0, g::Msg<2, ()>>(),
                g::send::<1, 0, g::Msg<3, ()>>(),
            )
            .resolve::<77>(),
            g::route(
                g::send::<0, 1, g::Msg<4, ()>>(),
                g::send::<0, 1, g::Msg<5, ()>>(),
            )
            .resolve::<78>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    let path = source
        .select(
            &[
                RouteChoice {
                    span: [1, 3],
                    right: false,
                },
                RouteChoice {
                    span: [3, 5],
                    right: false,
                },
            ],
            &mut storage,
        )
        .unwrap();
    let mut scratch = vec![0; path.query_workspace_len().unwrap()];
    let reads = Cell::new(0);
    let history = core::iter::from_fn(|| {
        reads.set(reads.get() + 1);
        None::<SourcePoint>
    });
    assert!(!path.query_from_word(history, (SourcePoint::Accepted(2), 1), &mut scratch));
    // Index the empty prefix once. Its missing fixed predecessor rejects
    // before alternative-choice propagation needs another history walk.
    assert_eq!(reads.get(), 1);
    scratch.fill(usize::MAX);
    assert!(!path.query_from_word([].into_iter(), (SourcePoint::Accepted(1), 1), &mut scratch));
    assert!(
        scratch[source.event_count()..]
            .iter()
            .all(|word| *word == usize::MAX),
        "a missing mandatory predecessor must reject before choice propagation"
    );
    assert!(path.query_from_word(
        [SourcePoint::Accepted(0), SourcePoint::Received(0)].into_iter(),
        (SourcePoint::Accepted(2), 1),
        &mut scratch
    ));
    assert!(!path.query_from_word(
        [SourcePoint::Accepted(0), SourcePoint::Sent(0)].into_iter(),
        (SourcePoint::Accepted(2), 1),
        &mut scratch
    ));
}

#[cfg(not(miri))]
#[test]
fn query_history_bounds_include_the_highest_physical_actor() {
    let global = g::seq(
        g::send::<0, 255, g::Msg<1, ()>>(),
        g::route(
            g::send::<255, 0, g::Msg<2, ()>>(),
            g::send::<255, 0, g::Msg<3, ()>>(),
        )
        .resolve::<77>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut left_storage = vec![0; source.path_workspace_len().unwrap()];
    let mut right_storage = vec![0; source.path_workspace_len().unwrap()];
    let left = source
        .select(
            &[RouteChoice {
                span: [1, 3],
                right: false,
            }],
            &mut left_storage,
        )
        .unwrap();
    let right = source
        .select(
            &[RouteChoice {
                span: [1, 3],
                right: true,
            }],
            &mut right_storage,
        )
        .unwrap();
    let paths = [left, right];
    let history = [
        SourcePoint::Accepted(0),
        SourcePoint::Sent(0),
        SourcePoint::Received(0),
    ];
    let mut scratch = vec![0; paths[0].query_workspace_len().unwrap()];
    for path in &paths {
        for prefix in 0..=history.len() {
            let word = &history[..prefix];
            path.check_word(word).unwrap();
            for event in 0..=source.event_count() {
                for point in [
                    SourcePoint::Local(event),
                    SourcePoint::Accepted(event),
                    SourcePoint::Sent(event),
                    SourcePoint::Received(event),
                ] {
                    for actor in [0, 1, 255] {
                        assert_eq!(
                            path.query_from_word(
                                word.iter().copied(),
                                (point, actor),
                                &mut scratch
                            ),
                            reference(path, &paths, word, point, actor),
                            "point={point:?} actor={actor} history={word:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn opposite_committed_arms_reject_before_searching_unrelated_choices() {
    let global = g::seq(
        g::route(
            g::send::<2, 3, g::Msg<1, ()>>(),
            g::send::<2, 3, g::Msg<2, ()>>(),
        )
        .resolve::<77>(),
        g::route(
            g::send::<0, 1, g::Msg<3, ()>>(),
            g::send::<0, 1, g::Msg<4, ()>>(),
        )
        .resolve::<78>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    let path = source
        .select(
            &[
                RouteChoice {
                    span: [0, 2],
                    right: false,
                },
                RouteChoice {
                    span: [2, 4],
                    right: false,
                },
            ],
            &mut storage,
        )
        .unwrap();
    let history = [SourcePoint::Accepted(2), SourcePoint::Sent(2)];
    path.check_word(&history).unwrap();
    let mut scratch = vec![0; path.query_workspace_len().unwrap()];
    assert!(!path.query_from_word(
        history.into_iter(),
        (SourcePoint::Accepted(3), 0),
        &mut scratch
    ));
}

#[test]
fn a_past_inactive_arm_cannot_add_a_predecessor_to_a_committed_receive() {
    let global = g::seq(
        g::route(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<0, 1, g::Msg<2, ()>>(),
        )
        .resolve::<77>(),
        g::seq(
            g::send::<4, 0, g::Msg<3, ()>>(),
            g::route(
                g::send::<5, 6, g::Msg<4, ()>>(),
                g::send::<5, 6, g::Msg<5, ()>>(),
            )
            .resolve::<78>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    let path = source
        .select(
            &[
                RouteChoice {
                    span: [0, 2],
                    right: false,
                },
                RouteChoice {
                    span: [3, 5],
                    right: false,
                },
            ],
            &mut storage,
        )
        .unwrap();
    let history = [
        SourcePoint::Accepted(0),
        SourcePoint::Sent(0),
        SourcePoint::Accepted(2),
        SourcePoint::Sent(2),
        SourcePoint::Received(2),
    ];
    path.check_word(&history).unwrap();
    let mut scratch = vec![usize::MAX; path.query_workspace_len().unwrap()];
    assert!(!path.query_from_word(
        history.into_iter(),
        (SourcePoint::Accepted(1), 0),
        &mut scratch
    ));
    assert!(
        scratch[source.event_count()..]
            .iter()
            .all(|word| *word == usize::MAX),
        "the committed receive already excludes this missing earlier send"
    );
}

#[test]
fn an_uncommitted_fixed_actor_visit_blocks_later_visits_before_choice_search() {
    let global = g::route(
        g::send::<0, 1, g::Msg<1, ()>>(),
        g::send::<0, 1, g::Msg<2, ()>>(),
    )
    .resolve::<77>()
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let steps = [Unfold::Source, Unfold::Once(0), Unfold::More([1, 0])];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let source = protocol.unfolding(&steps, &mut proof).unwrap();
    for first_right in [false, true] {
        for second_right in [false, true] {
            let mut storage = vec![0; source.path_workspace_len().unwrap()];
            let path = source
                .select(
                    &[
                        RouteChoice {
                            span: [0, 2],
                            right: first_right,
                        },
                        RouteChoice {
                            span: [2, 4],
                            right: second_right,
                        },
                    ],
                    &mut storage,
                )
                .unwrap();
            let first = usize::from(first_right);
            let point = SourcePoint::Accepted(2 + usize::from(second_right));
            let mut prefix = vec![0; source.event_count()];
            assert_eq!(
                path.fixed_prefix_blocked_until(point, 0, &prefix),
                Some(source.event_count())
            );
            let mut scratch = vec![usize::MAX; path.query_workspace_len().unwrap()];
            assert!(!path.query_from_word([].into_iter(), (point, 0), &mut scratch));
            assert!(
                scratch[source.event_count()..]
                    .iter()
                    .all(|word| *word == usize::MAX)
            );

            prefix[first] = SourcePoint::Accepted(first).bit();
            assert_eq!(
                path.fixed_prefix_blocked_until(point, 0, &prefix),
                Some(source.event_count())
            );
            let history = [SourcePoint::Accepted(first), SourcePoint::Sent(first)];
            path.check_word(&history).unwrap();
            prefix[first] |= SourcePoint::Sent(first).bit();
            assert_eq!(path.fixed_prefix_blocked_until(point, 0, &prefix), None);
            assert!(path.query_from_word(history.into_iter(), (point, 0), &mut scratch));
        }
    }
    #[cfg(not(miri))]
    compare(&snapshot, &steps);
}

#[test]
fn an_earlier_commit_does_not_hide_a_later_mandatory_child() {
    let first = || {
        g::route(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<0, 1, g::Msg<2, ()>>(),
        )
        .resolve::<77>()
    };
    let second = || {
        g::route(
            g::send::<0, 1, g::Msg<3, ()>>(),
            g::send::<0, 1, g::Msg<4, ()>>(),
        )
        .resolve::<78>()
    };
    let sequential = g::seq(g::seq(first(), second()), g::send::<0, 1, g::Msg<5, ()>>());
    let right_parallel = g::seq(
        g::seq(first(), g::par(g::send::<2, 3, g::Msg<6, ()>>(), second())),
        g::send::<0, 1, g::Msg<5, ()>>(),
    );
    let left_parallel = g::seq(
        g::seq(first(), g::par(second(), g::send::<2, 3, g::Msg<6, ()>>())),
        g::send::<0, 1, g::Msg<5, ()>>(),
    );
    for (snapshot, second_start, pruned) in [
        (
            tap::projected(&project::<0>(&sequential)).collect::<Vec<_>>(),
            2,
            true,
        ),
        (
            tap::projected(&project::<0>(&right_parallel)).collect(),
            3,
            true,
        ),
        (
            tap::projected(&project::<0>(&left_parallel)).collect(),
            2,
            false,
        ),
    ] {
        let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
        let steps = [Unfold::Source];
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let source = protocol.unfolding(&steps, &mut proof).unwrap();
        let point = SourcePoint::Accepted(source.event_count() - 1);
        for first_right in [false, true] {
            for second_right in [false, true] {
                let mut storage = vec![0; source.path_workspace_len().unwrap()];
                let path = source
                    .select(
                        &[
                            RouteChoice {
                                span: [0, 2],
                                right: first_right,
                            },
                            RouteChoice {
                                span: [second_start, second_start + 2],
                                right: second_right,
                            },
                        ],
                        &mut storage,
                    )
                    .unwrap();
                let first = usize::from(first_right);
                let second = second_start + usize::from(second_right);
                let mut history = vec![
                    SourcePoint::Accepted(first),
                    SourcePoint::Received(first),
                    SourcePoint::Sent(first),
                ];
                for accepted_second in [false, true] {
                    if accepted_second {
                        history.push(SourcePoint::Accepted(second));
                    }
                    path.check_word(&history).unwrap();
                    let mut prefix = vec![0; source.event_count()];
                    for &prior in &history {
                        prefix[prior.event()] |= prior.bit();
                    }
                    assert_eq!(
                        path.fixed_prefix_blocked_until(point, 0, &prefix),
                        pruned.then_some(source.event_count()),
                    );
                    let mut scratch = vec![usize::MAX; path.query_workspace_len().unwrap()];
                    assert!(!path.query_from_word(
                        history.iter().copied(),
                        (point, 0),
                        &mut scratch
                    ));
                    if pruned {
                        assert!(
                            scratch[source.event_count()..]
                                .iter()
                                .all(|&word| word == usize::MAX)
                        );
                    }
                }
                // Receipt can precede sender publication. It does not permit
                // the sender's next operation until that publication exists.
                history.push(SourcePoint::Received(second));
                path.check_word(&history).unwrap();
                let mut scratch = vec![0; path.query_workspace_len().unwrap()];
                assert!(!path.query_from_word(history.iter().copied(), (point, 0), &mut scratch));
                history.push(SourcePoint::Sent(second));
                path.check_word(&history).unwrap();
                assert!(path.query_from_word(history.iter().copied(), (point, 0), &mut scratch));
            }
        }
        #[cfg(not(miri))]
        compare(&snapshot, &steps);
    }
}

#[test]
fn blocked_candidate_spans_stop_before_an_independent_parallel_sibling() {
    let global = g::par(
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::route(
                g::send::<0, 1, g::Msg<2, ()>>(),
                g::send::<0, 1, g::Msg<3, ()>>(),
            )
            .resolve::<77>(),
        ),
        g::send::<0, 2, g::Msg<4, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let steps = [Unfold::Source];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let source = protocol.unfolding(&steps, &mut proof).unwrap();
    for right in [false, true] {
        let mut storage = vec![0; source.path_workspace_len().unwrap()];
        let path = source
            .select(
                &[RouteChoice {
                    span: [1, 3],
                    right,
                }],
                &mut storage,
            )
            .unwrap();
        let prefix = vec![0; source.event_count()];
        for event in 1..3 {
            assert_eq!(
                path.fixed_prefix_blocked_until(SourcePoint::Accepted(event), 0, &prefix),
                Some(3),
            );
        }
        assert_eq!(
            path.fixed_prefix_blocked_until(SourcePoint::Accepted(3), 0, &prefix),
            None,
        );
        let mut scratch = vec![0; path.query_workspace_len().unwrap()];
        assert!(path.query_from_word([].into_iter(), (SourcePoint::Accepted(3), 0), &mut scratch));
    }
    #[cfg(not(miri))]
    compare(&snapshot, &steps);
}

#[test]
fn a_missing_visit_excludes_the_remaining_sequence_of_visits() {
    let global = g::route(
        g::send::<0, 1, g::Msg<1, ()>>(),
        g::send::<0, 1, g::Msg<2, ()>>(),
    )
    .resolve::<77>()
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    for visits in [4, 72] {
        let mut steps = vec![Unfold::Source, Unfold::Once(0)];
        steps.extend((1..visits).map(|earlier| Unfold::More([earlier, 0])));
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let source = protocol.unfolding(&steps, &mut proof).unwrap();
        let choices: Vec<_> = (0..visits)
            .map(|visit| RouteChoice {
                span: [2 * visit, 2 * visit + 2],
                right: false,
            })
            .collect();
        let mut storage = vec![0; source.path_workspace_len().unwrap()];
        let path = source.select(&choices, &mut storage).unwrap();
        let history = [SourcePoint::Accepted(0), SourcePoint::Sent(0)];
        path.check_word(&history).unwrap();
        let mut prefix = vec![0; source.event_count()];
        for prior in history {
            prefix[prior.event()] |= prior.bit();
        }
        assert_eq!(
            path.fixed_prefix_blocked_until(SourcePoint::Accepted(2), 0, &prefix),
            None
        );
        assert_eq!(
            path.fixed_prefix_blocked_until(SourcePoint::Accepted(4), 0, &prefix),
            Some(source.event_count()),
        );
        let mut scratch = vec![0; path.query_workspace_len().unwrap()];
        assert!(path.query_from_word(
            history.into_iter(),
            (SourcePoint::Accepted(2), 0),
            &mut scratch
        ));
        #[cfg(not(miri))]
        if visits == 4 {
            compare(&snapshot, &steps);
        }
    }
}

#[test]
fn blocked_candidate_spans_do_not_cross_a_choice_into_a_legal_continuation() {
    let blocked = || {
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<0, 1, g::Msg<2, ()>>(),
        )
    };
    let left = g::seq(
        g::route(blocked(), g::send::<0, 1, g::Msg<3, ()>>()).resolve::<77>(),
        g::send::<0, 1, g::Msg<4, ()>>(),
    );
    let right = g::seq(
        g::route(g::send::<0, 1, g::Msg<3, ()>>(), blocked()).resolve::<77>(),
        g::send::<0, 1, g::Msg<4, ()>>(),
    );
    for (snapshot, other_right, attempted, completed, end) in [
        (
            tap::projected(&project::<0>(&left)).collect::<Vec<_>>(),
            true,
            1,
            2,
            2,
        ),
        (
            tap::projected(&project::<0>(&right)).collect(),
            false,
            2,
            0,
            3,
        ),
    ] {
        let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
        let steps = [Unfold::Source];
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let source = protocol.unfolding(&steps, &mut proof).unwrap();
        let mut storage = vec![0; source.path_workspace_len().unwrap()];
        let path = source
            .select(
                &[RouteChoice {
                    span: [0, 3],
                    right: other_right,
                }],
                &mut storage,
            )
            .unwrap();
        let history = [
            SourcePoint::Accepted(completed),
            SourcePoint::Sent(completed),
        ];
        path.check_word(&history).unwrap();
        let mut prefix = vec![0; source.event_count()];
        for prior in history {
            prefix[prior.event()] |= prior.bit();
        }
        assert_eq!(
            path.fixed_prefix_blocked_until(SourcePoint::Accepted(attempted), 0, &prefix),
            Some(end),
        );
        let mut scratch = vec![0; path.query_workspace_len().unwrap()];
        assert!(path.query_from_word(
            history.into_iter(),
            (SourcePoint::Accepted(3), 0),
            &mut scratch
        ));
        #[cfg(not(miri))]
        compare(&snapshot, &steps);
    }
}

#[cfg(not(miri))]
#[test]
fn conditional_queries_require_the_actual_loan_before_unrelated_suffix_choices() {
    type Loan = g::Msg<7, Endpoint<'static, 3>>;
    type Skip = g::Msg<8, ()>;
    let choice = || {
        g::route(
            g::send::<5, 6, g::Msg<10, ()>>(),
            g::send::<5, 6, g::Msg<11, ()>>(),
        )
        .resolve::<78>()
    };
    let global = g::seq(
        g::route(
            g::seq(g::send::<0, 1, Loan>(), g::send::<0, 4, Skip>()),
            g::seq(g::send::<0, 1, Skip>(), g::send::<0, 4, Loan>()),
        )
        .resolve::<77>(),
        g::seq(
            g::send::<3, 2, g::Msg<9, ()>>(),
            g::seq(choice(), g::seq(choice(), choice())),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    for right in [false, true] {
        let mut storage = vec![0; source.path_workspace_len().unwrap()];
        let path = source
            .select(
                &[
                    RouteChoice {
                        span: [0, 4],
                        right,
                    },
                    RouteChoice {
                        span: [5, 7],
                        right: false,
                    },
                    RouteChoice {
                        span: [7, 9],
                        right: false,
                    },
                    RouteChoice {
                        span: [9, 11],
                        right: false,
                    },
                ],
                &mut storage,
            )
            .unwrap();
        let mut scratch = vec![0; path.query_workspace_len().unwrap()];
        for actor in [1, 4] {
            assert!(!path.query_from_word(
                core::iter::empty(),
                (SourcePoint::Accepted(4), actor),
                &mut scratch
            ));
        }
        let first = if right { 2 } else { 0 };
        let history = [
            SourcePoint::Accepted(first),
            SourcePoint::Sent(first),
            SourcePoint::Received(first),
            SourcePoint::Accepted(first + 1),
            SourcePoint::Sent(first + 1),
            SourcePoint::Received(first + 1),
        ];
        path.check_word(&history).unwrap();
        for actor in [1, 4] {
            assert_eq!(
                path.query_from_word(
                    history.into_iter(),
                    (SourcePoint::Accepted(4), actor),
                    &mut scratch
                ),
                actor == if right { 4 } else { 1 }
            );
        }
    }
}

#[test]
fn a_fixed_missing_receive_rejects_without_searching_prior_unrelated_choices() {
    let global = g::seq(
        g::send::<1, 0, g::Msg<1, ()>>(),
        g::seq(
            g::route(
                g::send::<2, 3, g::Msg<2, ()>>(),
                g::send::<2, 3, g::Msg<3, ()>>(),
            )
            .resolve::<77>(),
            g::send::<0, 1, g::Msg<4, ()>>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut protocol_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&[Unfold::Source])];
    let source = protocol.unfolding(&[Unfold::Source], &mut proof).unwrap();
    let mut storage = vec![0; source.path_workspace_len().unwrap()];
    let path = source
        .select(
            &[RouteChoice {
                span: [1, 3],
                right: false,
            }],
            &mut storage,
        )
        .unwrap();
    let mut scratch = vec![0; path.query_workspace_len().unwrap()];
    assert!(!path.query_from_word(
        core::iter::empty(),
        (SourcePoint::Accepted(3), 0),
        &mut scratch
    ));
    // Receipt suffices; delayed sender publication is still allowed.
    let history = [SourcePoint::Accepted(0), SourcePoint::Received(0)];
    path.check_word(&history).unwrap();
    assert!(path.query_from_word(
        history.into_iter(),
        (SourcePoint::Accepted(3), 0),
        &mut scratch
    ));
}

// Enumerate full selections independently of the pruned query search. The
// source is the same checked unfolding; this introduces no second grammar.
#[cfg(not(miri))]
fn selections(source: &super::super::Unfolded, span: [usize; 2]) -> Vec<Vec<RouteChoice>> {
    use super::super::unfolding::NodeKind;
    let (kind, split) = source.parts(span).unwrap();
    if kind == NodeKind::Message {
        return vec![vec![]];
    }
    let left = selections(source, [span[0], split]);
    let right = selections(source, [split, span[1]]);
    if matches!(kind, NodeKind::Choice(_)) {
        [(false, left), (true, right)]
            .into_iter()
            .flat_map(|(right, children)| {
                children.into_iter().map(move |mut choices| {
                    choices.insert(0, RouteChoice { span, right });
                    choices
                })
            })
            .collect()
    } else {
        left.iter()
            .flat_map(|a| {
                right
                    .iter()
                    .map(move |b| a.iter().chain(b).copied().collect())
            })
            .collect()
    }
}

#[cfg(not(miri))]
fn ready_from_source(path: &SourcePath, history: &[SourcePoint], point: SourcePoint) -> bool {
    if matches!(point, SourcePoint::Sent(event) | SourcePoint::Received(event)
        if !history.contains(&SourcePoint::Accepted(event)))
    {
        return false;
    }
    let source = path.unfolding();
    // Deliberately visit the full expansion and use the unbounded source
    // relations. This oracle does not share the production prefix limit or
    // its publication/resumption shortcuts.
    (0..source.event_count()).all(|event| {
        [
            SourcePoint::Local(event),
            SourcePoint::Sent(event),
            SourcePoint::Received(event),
        ]
        .into_iter()
        .all(|prior| {
            let Some(actor) = path.point_actor(prior) else {
                return true;
            };
            if path.point_actor(point) != Some(actor) || history.contains(&prior) {
                return true;
            }
            let ordered = match point {
                SourcePoint::Sent(_) => false,
                _ if prior.event() == point.event() => matches!(
                    (prior, point),
                    (SourcePoint::Sent(_), SourcePoint::Received(_))
                ),
                _ => source.before(prior.event(), point.event()),
            };
            let resumed = matches!(point, SourcePoint::Accepted(_))
                && history.iter().copied().any(|entry| {
                    !matches!(entry, SourcePoint::Accepted(_))
                        && path.point_actor(entry) == Some(actor)
                        && source.same_resumption(prior.event(), point.event(), entry.event())
                });
            // Enumerate choices and prerequisites independently of query
            // pruning. The actor-local completion component is shared with
            // the word specification and has literal positive/negative tests.
            let credited = matches!(point, SourcePoint::Received(_))
                && event != point.event()
                && path.completed_incoming_visit(event, point.event(), actor, |point| {
                    history.contains(&point)
                });
            (!ordered || credited) && !resumed
        })
    })
}

#[cfg(not(miri))]
fn reference(
    original: &SourcePath,
    candidates: &[SourcePath],
    history: &[SourcePoint],
    point: SourcePoint,
    actor: u8,
) -> bool {
    let Some((_, binding)) = original.point_binding(point) else {
        return false;
    };
    if binding < 256 && binding != u32::from(actor) {
        return false;
    }
    let finish = match point {
        SourcePoint::Accepted(e) => SourcePoint::Sent(e),
        other => other,
    };
    if history.contains(&finish) {
        return false;
    }
    candidates.iter().any(|path| {
        path.point_actor(point) == Some(actor)
            && ready_from_source(path, history, point)
            && history.iter().enumerate().all(|(index, &prior)| {
                matches!(prior, SourcePoint::Accepted(_))
                    || path.point_actor(prior) == original.point_actor(prior)
                        && ready_from_source(path, &history[..index], prior)
            })
    })
}

#[cfg(not(miri))]
fn compare(snapshot: &[tap::TapEvent], steps: &[Unfold]) {
    let mut protocol_storage = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut protocol_storage).unwrap();
    let mut proof = vec![0; Protocol::unfolding_workspace_len(steps)];
    let source = protocol.unfolding(steps, &mut proof).unwrap();
    let choices = selections(&source, [0, source.event_count()]);
    let mut stores: Vec<_> = choices
        .iter()
        .map(|_| vec![0; source.path_workspace_len().unwrap()])
        .collect();
    let paths: Vec<_> = choices
        .iter()
        .zip(&mut stores)
        .map(|(choices, storage)| source.select(choices, storage).unwrap())
        .collect();
    for path in &paths {
        // Compare every prefix-preserved leaf subset against independent
        // complete selections. This also exercises nested choices, both
        // children, parallel ancestors and retained roll unfoldings without
        // assuming that the subset is a causally reachable execution prefix.
        for retained in 0..1usize << source.event_count() {
            if (0..source.event_count())
                .any(|event| retained & (1 << event) != 0 && path.actors(event).is_none())
            {
                continue;
            }
            for first in 0..=source.event_count() {
                for second in 0..=source.event_count() {
                    // Incompatible target/prefix combinations have no path
                    // at all, rather than a mandatory predecessor. They are
                    // rejected separately by the full query constraints.
                    if !paths.iter().any(|selected| {
                        selected.actors(second).is_some()
                            && (0..source.event_count()).all(|event| {
                                retained & (1 << event) == 0 || selected.actors(event).is_some()
                            })
                    }) {
                        continue;
                    }
                    let unavoidable = source.before(first, second)
                        && paths.iter().all(|selected| {
                            selected.actors(second).is_none()
                                || (0..source.event_count()).any(|event| {
                                    retained & (1 << event) != 0 && selected.actors(event).is_none()
                                })
                                || selected.actors(first).is_some()
                        });
                    assert_eq!(
                        path.unavoidable_before(first, second, |span| {
                            (span[0]..span[1]).any(|event| retained & (1 << event) != 0)
                        }),
                        unavoidable,
                        "prefix-forced source order first={first} second={second} retained={retained}",
                    );
                }
            }
        }
        for origin in (0..Layout::checked(protocol).sources.len() as u16).chain([u16::MAX]) {
            for first in 0..=source.event_count() {
                assert_eq!(
                    path.next_origin_event(origin, first),
                    (first..source.event_count())
                        .find(|&event| source.origin(event) == Some(origin)),
                    "source identity index origin={origin} first={first}"
                );
            }
        }
        for first in 0..=source.event_count() {
            for second in 0..=source.event_count() {
                assert_eq!(
                    path.source_before(first, second),
                    source.before(first, second),
                    "indexed source order first={first} second={second}"
                );
                assert_eq!(
                    path.unavoidable_before(first, second, |_| false),
                    source.before(first, second)
                        && paths.iter().all(|selected| {
                            selected.actors(second).is_none() || selected.actors(first).is_some()
                        }),
                    "mandatory source order first={first} second={second}"
                );
            }
        }
        let reads = Cell::new(0);
        let history = core::iter::from_fn(|| {
            reads.set(reads.get() + 1);
            None::<SourcePoint>
        });
        for event in 1..source.event_count() {
            for prior in [
                SourcePoint::Local(event),
                SourcePoint::Sent(event),
                SourcePoint::Received(event),
            ] {
                if let Some(actor) = path.point_actor(prior) {
                    assert!(!path.prerequisite(
                        history.clone(),
                        SourcePoint::Accepted(0),
                        |_| false
                    )(prior, actor));
                }
            }
        }
        assert_eq!(
            reads.get(),
            0,
            "future events must not search resumption history"
        );
        for event in 0..source.event_count() {
            if path.point_actor(SourcePoint::Sent(event)).is_some() {
                let history = [SourcePoint::Accepted(event)];
                let reads = Cell::new(0);
                assert!(
                    path.missing(history.into_iter(), SourcePoint::Sent(event), |prior| {
                        reads.set(reads.get() + 1);
                        history.contains(&prior)
                    })
                    .is_none()
                );
                assert_eq!(reads.get(), 1, "publication must only read its acceptance");
            }
        }
    }
    let mut scopes: Vec<_> = choices
        .iter()
        .flatten()
        .map(|choice| match source.parts(choice.span).unwrap().0 {
            super::super::unfolding::NodeKind::Choice(scope) => scope,
            _ => unreachable!("choice enumeration contains only choices"),
        })
        .chain([u16::MAX])
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    for path in &paths {
        for event in 0..=source.event_count() {
            for &scope in &scopes {
                assert_eq!(
                    path.route_at(event, scope),
                    root_route(&source, event, scope),
                    "event={event} scope={scope}"
                );
            }
        }
    }
    for (path, choices) in paths.iter().zip(&choices) {
        for choice in choices {
            let (super::super::unfolding::NodeKind::Choice(scope), _) =
                source.parts(choice.span).unwrap()
            else {
                unreachable!("selection enumeration contains only choices");
            };
            for event in choice.span[0]..choice.span[1] {
                assert_eq!(
                    path.choice_at(event, scope),
                    path.selection(choice.span),
                    "event={event} scope={scope} span={:?}",
                    choice.span
                );
            }
        }
    }
    let mut scratch = vec![0; paths[0].query_workspace_len().unwrap()];
    let mut word = Vec::new();
    let mut checked = 0;
    let mut histories = 0;
    for path in &paths {
        for (reverse_events, reverse_halves) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let points: Vec<_> = (0..source.event_count())
                .map(|event| {
                    if reverse_events {
                        source.event_count() - 1 - event
                    } else {
                        event
                    }
                })
                .flat_map(|event| {
                    if reverse_halves {
                        [
                            SourcePoint::Accepted(event),
                            SourcePoint::Received(event),
                            SourcePoint::Sent(event),
                            SourcePoint::Local(event),
                        ]
                    } else {
                        [
                            SourcePoint::Accepted(event),
                            SourcePoint::Sent(event),
                            SourcePoint::Received(event),
                            SourcePoint::Local(event),
                        ]
                    }
                })
                .filter(|&point| path.point_actor(point).is_some())
                .collect();
            assert!(points.len() < usize::BITS as usize);
            for mask in 0..1usize << points.len() {
                word.clear();
                word.extend(
                    points
                        .iter()
                        .enumerate()
                        .filter_map(|(i, &point)| (mask & (1 << i) != 0).then_some(point)),
                );
                if path.check_word(&word).is_err() {
                    continue;
                }
                histories += 1;
                let mut prefix = vec![0; source.event_count()];
                for &prior in &word {
                    prefix[prior.event()] |= prior.bit();
                }
                for event in 0..=source.event_count() {
                    for point in [
                        SourcePoint::Local(event),
                        SourcePoint::Accepted(event),
                        SourcePoint::Sent(event),
                        SourcePoint::Received(event),
                    ] {
                        for actor in
                            (0..=super::super::Layout::checked(protocol).max_role).chain([255])
                        {
                            if let Some(end) =
                                path.fixed_prefix_blocked_until(point, actor, &prefix)
                            {
                                assert!(event < end && end <= source.event_count());
                                for later in event..end {
                                    // A certificate belongs to this point
                                    // kind. A blocked outgoing operation need
                                    // not block a credited incoming receipt.
                                    // The outer loop checks every kind itself.
                                    let excluded = match point {
                                        SourcePoint::Local(_) => SourcePoint::Local(later),
                                        SourcePoint::Accepted(_) => SourcePoint::Accepted(later),
                                        SourcePoint::Sent(_) => SourcePoint::Sent(later),
                                        SourcePoint::Received(_) => SourcePoint::Received(later),
                                    };
                                    assert!(
                                        !reference(path, &paths, &word, excluded, actor),
                                        "blocked span event={event} end={end} actor={actor} query={excluded:?} history={word:?}"
                                    );
                                }
                            }
                            assert_eq!(
                                path.query_from_word(
                                    word.iter().copied(),
                                    (point, actor),
                                    &mut scratch
                                ),
                                reference(path, &paths, &word, point, actor),
                                "point={point:?} actor={actor} history={word:?}"
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(histories > 0 && checked > 0);
    std::eprintln!(
        "prefix-query equivalence: events={} selections={} histories={histories} queries={checked}",
        source.event_count(),
        paths.len()
    );
}

// Independent root descent using the uncached structural split oracle.
#[cfg(not(miri))]
fn root_route(
    source: &super::super::Unfolded,
    event: usize,
    scope: u16,
) -> Option<([usize; 2], bool)> {
    use super::super::unfolding::NodeKind;
    if event >= source.event_count() {
        return None;
    }
    let mut span = [0, source.event_count()];
    loop {
        let (kind, split) = source.parts(span)?;
        if kind == NodeKind::Choice(scope) {
            return Some((span, event >= split));
        }
        if kind == NodeKind::Message {
            return None;
        }
        span = if event < split {
            [span[0], split]
        } else {
            [split, span[1]]
        };
    }
}

#[cfg(not(miri))]
#[test]
fn prefix_queries_match_complete_search_on_both_skewed_sequence_shapes() {
    let first = || g::send::<1, 0, g::Msg<1, ()>>();
    let second = || g::send::<1, 0, g::Msg<2, ()>>();
    let third = || g::send::<1, 0, g::Msg<3, ()>>();
    let choice = || {
        g::route(
            g::send::<0, 1, g::Msg<4, ()>>(),
            g::send::<0, 1, g::Msg<5, ()>>(),
        )
        .resolve::<77>()
    };
    let left = g::seq(g::seq(g::seq(first(), second()), third()), choice());
    let right = g::seq(first(), g::seq(second(), g::seq(third(), choice())));
    for snapshot in [
        tap::projected(&project::<0>(&left)).collect::<Vec<_>>(),
        tap::projected(&project::<0>(&right)).collect::<Vec<_>>(),
    ] {
        compare(&snapshot, &[Unfold::Source]);
    }
}

#[cfg(not(miri))]
#[test]
fn prefix_pruning_matches_complete_choice_search_for_both_parallel_subtrees() {
    let global = g::par(
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::route(
                g::send::<1, 0, g::Msg<2, ()>>(),
                g::send::<1, 0, g::Msg<3, ()>>(),
            )
            .resolve::<77>(),
        ),
        g::seq(
            g::send::<2, 3, g::Msg<4, ()>>(),
            g::route(
                g::send::<3, 2, g::Msg<5, ()>>(),
                g::send::<3, 2, g::Msg<6, ()>>(),
            )
            .resolve::<78>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    compare(&snapshot, &[Unfold::Source]);
}

#[cfg(not(miri))]
#[test]
fn prefix_pruning_matches_complete_search_after_retained_body_reentry() {
    let global = g::seq(
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<1, 0, g::Msg<2, ()>>(),
        )
        .roll(),
        g::route(
            g::send::<0, 1, g::Msg<3, ()>>(),
            g::send::<0, 1, g::Msg<4, ()>>(),
        )
        .resolve::<77>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let retained = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    for before in [false, true] {
        let step = if before {
            Unfold::Before {
                retained,
                earlier: 7,
                next: 3,
                focus: [2, 4],
            }
        } else {
            Unfold::Alongside {
                retained,
                earlier: 7,
                next: 3,
                focus: [2, 4],
            }
        };
        compare(
            &snapshot,
            &[
                Unfold::Source,
                Unfold::Source,
                Unfold::Sequence([0, 1]),
                Unfold::Once(2),
                Unfold::Source,
                Unfold::Source,
                Unfold::Choice([4, 5]),
                Unfold::Sequence([3, 6]),
                step,
            ],
        );
    }
}

#[cfg(not(miri))]
#[test]
fn prefix_pruning_matches_complete_search_with_conditional_endpoint_holders() {
    type Loan = g::Msg<7, Endpoint<'static, 3>>;
    type Skip = g::Msg<8, ()>;
    let global = g::seq(
        g::route(
            g::seq(g::send::<0, 1, Loan>(), g::send::<0, 4, Skip>()),
            g::seq(g::send::<0, 1, Skip>(), g::send::<0, 4, Loan>()),
        )
        .resolve::<17>(),
        g::seq(
            g::send::<3, 2, g::Msg<9, ()>>(),
            g::route(
                g::send::<2, 3, g::Msg<10, ()>>(),
                g::send::<2, 3, g::Msg<11, ()>>(),
            )
            .resolve::<18>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    compare(&snapshot, &[Unfold::Source]);
}

#[cfg(not(miri))]
#[test]
fn conditional_local_and_colocated_wire_queries_match_complete_search() {
    type Loan = g::Msg<7, Endpoint<'static, 3>>;
    type Skip = g::Msg<8, ()>;
    let choice = || {
        g::route(
            g::seq(g::send::<0, 1, Loan>(), g::send::<0, 4, Skip>()),
            g::seq(g::send::<0, 1, Skip>(), g::send::<0, 4, Loan>()),
        )
        .resolve::<17>()
    };
    let wire = g::seq(choice(), g::send::<3, 1, g::Msg<9, ()>>());
    let local = g::seq(choice(), g::send::<3, 3, g::Msg<9, ()>>());
    for snapshot in [
        tap::projected(&project::<0>(&wire)).collect::<Vec<_>>(),
        tap::projected(&project::<0>(&local)).collect::<Vec<_>>(),
    ] {
        compare(&snapshot, &[Unfold::Source]);
    }
}
