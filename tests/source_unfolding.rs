use hibana::{
    Endpoint, g,
    runtime::{
        program::project,
        tap::{self, TapEvent},
    },
};
use hibana_epf::{Protocol, Unfold, UnfoldingError};

fn check(snapshot: &[TapEvent], steps: &[Unfold], expected: (&[u16], &[(usize, usize)])) {
    let mut scratch = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut scratch).unwrap();
    let words = Protocol::unfolding_workspace_len(steps);
    scratch.resize(words, 0);
    assert!(
        matches!(protocol.unfolding(steps, &mut scratch[..words - 1]),
        Err(UnfoldingError::Workspace { required, .. }) if required == words)
    );
    let unfolded = protocol.unfolding(steps, &mut scratch).unwrap();
    assert_eq!(unfolded.event_count(), expected.0.len());
    assert_eq!(unfolded.protocol().records().as_ptr(), snapshot.as_ptr());
    for (event, &origin) in expected.0.iter().enumerate() {
        assert_eq!(unfolded.origin(event), Some(origin));
        for after in 0..expected.0.len() {
            assert_eq!(
                unfolded.before(event, after),
                expected.1.contains(&(event, after)),
                "{event} before {after}"
            );
        }
    }
    assert_eq!(unfolded.origin(expected.0.len()), None);
    assert!(!unfolded.before(usize::MAX, 0));
    assert!(!unfolded.before(0, usize::MAX));
}

#[test]
fn compiled_scope_nesting_preserves_sequence_parallel_and_choice() {
    type M = g::Msg<7, ()>;
    let global = g::seq(
        g::send::<0, 1, M>(),
        g::par(
            g::send::<0, 2, g::Msg<8, ()>>(),
            g::route(
                g::send::<0, 3, g::Msg<9, ()>>(),
                g::send::<0, 3, g::Msg<10, ()>>(),
            ),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Message,
            Unfold::Message,
            Unfold::Message,
            Unfold::Choice([2, 3]),
            Unfold::Parallel([1, 4]),
            Unfold::Sequence([0, 5]),
        ],
        (&[0, 1, 2, 3], &[(0, 1), (0, 2), (0, 3)]),
    );
}

#[test]
fn original_scope_identity_distinguishes_nested_rolls_with_equal_event_bounds() {
    type M = g::Msg<7, ()>;
    let global = g::send::<0, 0, M>()
        .roll()
        .roll()
        .roll()
        .roll()
        .roll()
        .roll()
        .roll()
        .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut steps = vec![Unfold::Message];
    let mut body = 0;
    for _ in 0..8 {
        let once = steps.len();
        steps.push(Unfold::Once(body));
        let twice = steps.len();
        steps.push(Unfold::More([once, body]));
        body = twice;
    }
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    assert_eq!(unfolded.event_count(), 256);
    for event in 0..256 {
        assert_eq!(unfolded.origin(event), Some(0));
        for after in 0..256 {
            assert_eq!(unfolded.before(event, after), event < after);
        }
    }
}

#[test]
fn nested_visits_can_have_different_lengths_without_a_catalogue_horizon() {
    type Tick = g::Msg<7, ()>;
    type Tail = g::Msg<8, ()>;
    let global = g::seq(g::send::<0, 0, Tick>().roll(), g::send::<0, 0, Tail>()).roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Once(0),
            Unfold::More([1, 0]),
            Unfold::Message,
            Unfold::Sequence([2, 3]),
            Unfold::Sequence([1, 3]),
            Unfold::Once(4),
            Unfold::More([6, 5]),
        ],
        (
            &[0, 0, 1, 0, 1],
            &[
                (0, 1),
                (0, 2),
                (0, 3),
                (0, 4),
                (1, 2),
                (1, 3),
                (1, 4),
                (2, 3),
                (2, 4),
                (3, 4),
            ],
        ),
    );
}

#[test]
fn independent_parallel_visits_keep_both_branches_unordered() {
    type M = g::Msg<7, ()>;
    let global = g::par(g::send::<0, 1, M>(), g::send::<2, 3, M>()).roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Once(0),
            Unfold::More([1, 0]),
            Unfold::Message,
            Unfold::Once(3),
            Unfold::Independent([2, 4]),
        ],
        (&[0, 0, 1], &[(0, 1)]),
    );
}

#[test]
fn retained_visits_can_follow_precede_or_overlap_the_continuation() {
    type M = g::Msg<7, ()>;
    let global = g::seq(
        g::send::<0, 0, M>().roll(),
        g::send::<0, 0, g::Msg<8, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let retained = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE)
        .unwrap()
        .causal_key();
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Once(0),
            Unfold::Message,
            Unfold::Sequence([1, 2]),
            Unfold::After {
                retained,
                earlier: 3,
                next: 0,
            },
        ],
        (&[0, 1, 0], &[(0, 1), (0, 2), (1, 2)]),
    );
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Once(0),
            Unfold::Message,
            Unfold::Alongside {
                retained,
                earlier: 1,
                next: 1,
                tail: 2,
                focus: [0, 1],
            },
        ],
        (&[0, 0, 1], &[(0, 1), (0, 2)]),
    );
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Once(0),
            Unfold::Message,
            Unfold::Before {
                retained,
                earlier: 1,
                next: 1,
                tail: 2,
                focus: [0, 1],
            },
        ],
        (&[0, 0, 1], &[(0, 1), (0, 2), (1, 2)]),
    );
}

#[test]
fn an_inserted_subtree_remains_an_insertion_point_for_another_retained_roll() {
    type M = g::Msg<7, ()>;
    let global = g::seq(
        g::send::<0, 0, M>().roll(),
        g::seq(
            g::send::<0, 0, g::Msg<8, ()>>().roll(),
            g::send::<0, 0, g::Msg<9, ()>>(),
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
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Once(0),
            Unfold::Message,
            Unfold::Once(2),
            Unfold::Message,
            Unfold::Alongside {
                retained: rolls[1],
                earlier: 3,
                next: 3,
                tail: 4,
                focus: [0, 1],
            },
            Unfold::Alongside {
                retained: rolls[0],
                earlier: 1,
                next: 1,
                tail: 5,
                focus: [1, 3],
            },
        ],
        (
            &[0, 1, 0, 1, 2],
            &[(0, 1), (0, 2), (0, 3), (0, 4), (1, 2), (1, 3), (1, 4)],
        ),
    );
}

#[test]
fn a_range_that_crosses_subtrees_cannot_remove_source_dependencies() {
    type M = g::Msg<7, ()>;
    let global = g::seq(
        g::send::<0, 0, M>().roll(),
        g::seq(
            g::send::<0, 0, g::Msg<8, ()>>(),
            g::par(
                g::send::<0, 0, g::Msg<9, ()>>(),
                g::send::<0, 0, g::Msg<10, ()>>(),
            ),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let retained = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let steps = [
        Unfold::Message,
        Unfold::Once(0),
        Unfold::Message,
        Unfold::Message,
        Unfold::Message,
        Unfold::Parallel([3, 4]),
        Unfold::Sequence([2, 5]),
        Unfold::Alongside {
            retained,
            earlier: 1,
            next: 1,
            tail: 6,
            focus: [0, 2],
        },
    ];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    assert!(matches!(
        protocol.unfolding(&steps, &mut scratch),
        Err(UnfoldingError::Step { index: 7 })
    ));
}

#[test]
fn the_legal_four_inner_visit_resource_return_has_a_checked_source_witness() {
    type Loan = g::Msg<0, Endpoint<'static, 3>>;
    type Return = g::Msg<3, Endpoint<'static, 3>>;
    let global = g::seq(
        g::send::<0, 1, Loan>(),
        g::seq(
            g::par(
                g::send::<3, 2, g::Msg<1, ()>>(),
                g::send::<1, 0, g::Msg<2, ()>>().roll(),
            )
            .roll(),
            g::send::<1, 0, Return>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let edges: Vec<_> = (0..7)
        .flat_map(|first| {
            (first + 1..7).filter_map(move |after| {
                (first == 0 || after == 6 || (first >= 2 && after < 6)).then_some((first, after))
            })
        })
        .collect();
    check(
        &snapshot,
        &[
            Unfold::Message,
            Unfold::Message,
            Unfold::Message,
            Unfold::Once(2),
            Unfold::More([3, 2]),
            Unfold::More([4, 2]),
            Unfold::More([5, 2]),
            Unfold::Parallel([1, 6]),
            Unfold::Once(7),
            Unfold::Message,
            Unfold::Sequence([8, 9]),
            Unfold::Sequence([0, 10]),
        ],
        (&[0, 1, 2, 2, 2, 2, 3], &edges),
    );
}

#[test]
fn malformed_or_unreachable_proof_steps_never_publish_a_checked_unfolding() {
    let global = g::seq(
        g::send::<0, 0, g::Msg<1, ()>>(),
        g::send::<0, 0, g::Msg<2, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let cases: &[&[Unfold]] = &[
        &[],
        &[Unfold::Message],
        &[Unfold::Message, Unfold::Message, Unfold::Parallel([0, 1])],
        &[Unfold::Message, Unfold::Message, Unfold::Sequence([0, 0])],
        &[Unfold::Message, Unfold::Message, Unfold::Sequence([0, 2])],
        &[
            Unfold::Message,
            Unfold::Message,
            Unfold::Sequence([0, usize::MAX]),
        ],
        &[
            Unfold::Message,
            Unfold::Message,
            Unfold::Message,
            Unfold::Sequence([0, 1]),
        ],
        &[Unfold::Once(0), Unfold::Message, Unfold::Sequence([0, 1])],
        &[
            Unfold::Message,
            Unfold::Message,
            Unfold::Sequence([0, 1]),
            Unfold::After {
                retained: u16::MAX,
                earlier: 2,
                next: 0,
            },
        ],
    ];
    for steps in cases {
        scratch.resize(Protocol::unfolding_workspace_len(steps), 0);
        assert!(matches!(
            protocol.unfolding(steps, &mut scratch),
            Err(UnfoldingError::Step { .. })
        ));
    }
}
