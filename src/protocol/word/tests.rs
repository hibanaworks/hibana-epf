extern crate std;
use super::*;
use crate::protocol::{Protocol, Unfold};
use hibana::{
    g,
    runtime::{program::project, tap},
};
use std::{vec, vec::Vec};

// The unfactored prerequisite rule, kept only as a comparison for the optimized
// check. It deliberately evaluates resumption even for already present points.
fn reference(
    path: SourcePath<'_, '_, '_>,
    history: &[SourcePoint],
    point: SourcePoint,
) -> Option<SourcePoint> {
    if let SourcePoint::Sent(e) | SourcePoint::Received(e) = point
        && !history.contains(&SourcePoint::Accepted(e))
    {
        return Some(SourcePoint::Accepted(e));
    }
    let source = path.unfolding();
    for event in 0..source.event_count() {
        for prior in [
            SourcePoint::Local(event),
            SourcePoint::Sent(event),
            SourcePoint::Received(event),
        ] {
            let Some(actor) = path.point_actor(prior) else {
                continue;
            };
            if Some(actor) != path.point_actor(point) {
                continue;
            }
            let ordered = match point {
                SourcePoint::Sent(_) => false,
                _ if event == point.event() => matches!(
                    (prior, point),
                    (SourcePoint::Sent(_), SourcePoint::Received(_))
                ),
                _ => source.before(event, point.event()),
            };
            let resumed = matches!(point, SourcePoint::Accepted(_))
                && history.iter().any(|entry| {
                    !matches!(entry, SourcePoint::Accepted(_))
                        && path.point_actor(*entry) == Some(actor)
                        && source.same_resumption(event, point.event(), entry.event())
                });
            if (ordered || resumed) && !history.contains(&prior) {
                return Some(prior);
            }
        }
    }
    None
}

#[cfg(not(miri))]
#[test]
fn prerequisite_factoring_matches_the_unfactored_rule_for_every_point_subset() {
    let global = g::seq(
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<1, 0, g::Msg<2, ()>>(),
        )
        .roll(),
        g::send::<0, 1, g::Msg<3, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let retained = snapshot
        .iter()
        .find(|r| r.id() == tap::PROJECTED_SCOPE && r.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
    for insertion in [None, Some(false), Some(true)] {
        let mut steps = vec![Unfold::Source];
        if let Some(before) = insertion {
            steps = vec![
                Unfold::Source,
                Unfold::Once(0),
                Unfold::Source,
                if before {
                    Unfold::Before {
                        retained,
                        earlier: 1,
                        next: 1,
                        tail: 2,
                        focus: [0, 1],
                    }
                } else {
                    Unfold::Alongside {
                        retained,
                        earlier: 1,
                        next: 1,
                        tail: 2,
                        focus: [0, 1],
                    }
                },
            ];
        }
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let source = protocol.unfolding(&steps, &mut proof).unwrap();
        let mut actors = vec![0; source.path_workspace_len().unwrap()];
        let path = source.select(&[], &mut actors).unwrap();
        let points: Vec<_> = (0..source.event_count())
            .flat_map(|e| {
                [
                    SourcePoint::Accepted(e),
                    SourcePoint::Sent(e),
                    SourcePoint::Received(e),
                ]
            })
            .collect();
        // Either no initial visit or its complete request/reply. Enumerate
        // every subset of the remaining acceptance/publication/receipt points,
        // including an entered resumed sender with its return still missing.
        for initial in [false, true] {
            for bits in 0..1usize << (points.len() - 6) {
                let mut history = if initial {
                    points[..6].to_vec()
                } else {
                    Vec::new()
                };
                history.extend(
                    points[6..]
                        .iter()
                        .enumerate()
                        .filter_map(|(i, &p)| (bits & (1 << i) != 0).then_some(p)),
                );
                for &point in &points {
                    assert_eq!(
                        path.missing(history.iter().copied(), point),
                        reference(path, &history, point),
                        "{insertion:?} {initial} {bits} {point:?}"
                    );
                }
            }
        }
    }
}
