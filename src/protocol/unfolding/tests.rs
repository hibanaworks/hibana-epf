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

fn compare(snapshot: &[TapEvent], steps: &[Unfold]) {
    let mut scratch = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut scratch).unwrap();
    scratch.resize(Protocol::unfolding_workspace_len(steps), 0);
    let source = protocol.unfolding(steps, &mut scratch).unwrap();
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
    for inner_before in [false, true] {
        for outer_before in [false, true] {
            let inner = if inner_before {
                Unfold::Before {
                    retained: rolls[1],
                    earlier: 3,
                    next: 3,
                    tail: 4,
                    focus: [0, 1],
                }
            } else {
                Unfold::Alongside {
                    retained: rolls[1],
                    earlier: 3,
                    next: 3,
                    tail: 4,
                    focus: [0, 1],
                }
            };
            let outer = if outer_before {
                Unfold::Before {
                    retained: rolls[0],
                    earlier: 1,
                    next: 1,
                    tail: 5,
                    focus: [1, 3],
                }
            } else {
                Unfold::Alongside {
                    retained: rolls[0],
                    earlier: 1,
                    next: 1,
                    tail: 5,
                    focus: [1, 3],
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
                    inner,
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
}
