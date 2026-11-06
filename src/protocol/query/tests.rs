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
    assert!(!path.query_ready(history, SourcePoint::Accepted(2), 1, &mut scratch));
    // Source conditions are propagated once. Unrelated choices must not
    // multiply reads of the supplied history.
    assert_eq!(reads.get(), 2);
    assert!(path.query_ready(
        [SourcePoint::Accepted(0), SourcePoint::Received(0)].into_iter(),
        SourcePoint::Accepted(2),
        1,
        &mut scratch
    ));
    assert!(!path.query_ready(
        [SourcePoint::Accepted(0), SourcePoint::Sent(0)].into_iter(),
        SourcePoint::Accepted(2),
        1,
        &mut scratch
    ));
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
    assert!(!path.query_ready(
        history.into_iter(),
        SourcePoint::Accepted(3),
        0,
        &mut scratch
    ));
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
    assert!(!path.query_ready(
        core::iter::empty(),
        SourcePoint::Accepted(3),
        0,
        &mut scratch
    ));
    // Receipt suffices; delayed sender publication is still allowed.
    let history = [SourcePoint::Accepted(0), SourcePoint::Received(0)];
    path.check_word(&history).unwrap();
    assert!(path.query_ready(
        history.into_iter(),
        SourcePoint::Accepted(3),
        0,
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
            && path
                .missing(history.iter().copied(), point, |prior| {
                    history.contains(&prior)
                })
                .is_none()
            && history.iter().enumerate().all(|(index, &prior)| {
                matches!(prior, SourcePoint::Accepted(_))
                    || path.point_actor(prior) == original.point_actor(prior)
                        && path
                            .check_next(history[..index].iter().copied(), prior, index)
                            .is_ok()
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
        for reverse_halves in [false, true] {
            let points: Vec<_> = (0..source.event_count())
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
                            assert_eq!(
                                path.query_ready(word.iter().copied(), point, actor, &mut scratch),
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
                earlier: 3,
                next: 3,
                tail: 6,
                focus: [0, 2],
            }
        } else {
            Unfold::Alongside {
                retained,
                earlier: 3,
                next: 3,
                tail: 6,
                focus: [0, 2],
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
