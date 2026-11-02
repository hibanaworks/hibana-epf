use hibana::{
    Endpoint, g,
    runtime::{program::project, tap},
};
use hibana_epf::{PathError, Protocol, RouteChoice, Unfold};

#[test]
fn separate_visits_can_select_different_holders_without_sharing_a_choice() {
    type Loan = g::Msg<7, Endpoint<'static, 3>>;
    type Return = g::Msg<10, Endpoint<'static, 3>>;
    type Skip = g::Msg<8, ()>;
    type Use = g::Msg<9, ()>;
    let global = g::route(
        g::seq(
            g::send::<0, 1, Loan>(),
            g::seq(
                g::send::<0, 4, Skip>(),
                g::seq(g::send::<3, 2, Use>(), g::send::<1, 0, Return>()),
            ),
        ),
        g::seq(
            g::send::<0, 1, Skip>(),
            g::seq(
                g::send::<0, 4, Loan>(),
                g::seq(g::send::<3, 2, Use>(), g::send::<4, 0, Return>()),
            ),
        ),
    )
    .resolve::<17>()
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let steps = [
        Unfold::Source,
        Unfold::Source,
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([2, 3]),
        Unfold::Sequence([1, 4]),
        Unfold::Sequence([0, 5]),
        Unfold::Source,
        Unfold::Source,
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([9, 10]),
        Unfold::Sequence([8, 11]),
        Unfold::Sequence([7, 12]),
        Unfold::Choice([6, 13]),
        Unfold::Once(14),
        Unfold::More([15, 14]),
    ];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    let choices = [
        RouteChoice {
            span: [0, 8],
            right: false,
        },
        RouteChoice {
            span: [8, 16],
            right: true,
        },
    ];
    let path = unfolded.select(&choices, &mut rows).unwrap();
    assert_eq!(path.actors(2), Some([1, 2]));
    assert_eq!(path.actors(3), Some([1, 0]));
    assert_eq!(path.actors(6), None);
    assert_eq!(path.actors(10), None);
    assert_eq!(path.actors(14), Some([4, 2]));
    assert_eq!(path.actors(15), Some([4, 0]));
}

#[test]
fn a_conditional_holder_is_resolved_from_the_same_selected_source_choice() {
    type Loan = g::Msg<7, Endpoint<'static, 3>>;
    type Skip = g::Msg<8, ()>;
    let global = g::seq(
        g::route(
            g::seq(g::send::<0, 1, Loan>(), g::send::<0, 4, Skip>()),
            g::seq(g::send::<0, 1, Skip>(), g::send::<0, 4, Loan>()),
        )
        .resolve::<17>(),
        g::send::<3, 2, g::Msg<9, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let steps = [
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([0, 1]),
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([3, 4]),
        Unfold::Choice([2, 5]),
        Unfold::Source,
        Unfold::Sequence([6, 7]),
    ];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    for right in [false, true] {
        let choices = [RouteChoice {
            span: [0, 4],
            right,
        }];
        let path = unfolded.select(&choices, &mut rows).unwrap();
        let expected = if right {
            [None, None, Some([0, 1]), Some([0, 4]), Some([4, 2])]
        } else {
            [Some([0, 1]), Some([0, 4]), None, None, Some([1, 2])]
        };
        for (event, actors) in expected.iter().enumerate() {
            assert_eq!(path.actors(event), *actors);
        }
        assert_eq!(path.actors(5), None);
        assert_eq!(path.unfolding().event_count(), 5);
    }
    assert!(matches!(
        unfolded.select(&[], &mut rows),
        Err(PathError::Choice { .. })
    ));
    assert!(matches!(
        unfolded.select(
            &[RouteChoice {
                span: [0, 4],
                right: false
            }; 2],
            &mut rows
        ),
        Err(PathError::Choice { .. })
    ));
    let words = rows.len();
    assert!(matches!(
        unfolded.select(&[], &mut rows[..words - 1]),
        Err(PathError::Workspace { .. })
    ));
}

#[test]
fn independent_visits_need_physical_separation_in_addition_to_the_source_proof() {
    let global = g::par(
        g::send::<0, 1, g::Msg<7, ()>>(),
        g::send::<0, 2, g::Msg<8, ()>>(),
    )
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let steps = [
        Unfold::Source,
        Unfold::Once(0),
        Unfold::More([1, 0]),
        Unfold::Source,
        Unfold::Once(3),
        Unfold::Independent([2, 4]),
    ];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    assert!(matches!(
        unfolded.select(&[], &mut rows),
        Err(PathError::ParallelActor { .. })
    ));

    let global = g::par(
        g::send::<0, 1, g::Msg<7, ()>>(),
        g::send::<2, 3, g::Msg<8, ()>>(),
    )
    .roll();
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    rows.resize(unfolded.path_workspace_len().unwrap(), 0);
    let path = unfolded.select(&[], &mut rows).unwrap();
    assert_eq!(path.actors(0), Some([0, 1]));
    assert_eq!(path.actors(1), Some([0, 1]));
    assert_eq!(path.actors(2), Some([2, 3]));
}

#[test]
fn a_retained_visit_cannot_transfer_the_same_resource_as_its_parallel_continuation() {
    type Loan = g::Msg<7, Endpoint<'static, 3>>;
    type Return = g::Msg<10, Endpoint<'static, 3>>;
    type Tail = g::Msg<11, Endpoint<'static, 3>>;
    let global = g::seq(
        g::seq(
            g::send::<0, 1, Loan>(),
            g::seq(g::send::<3, 2, g::Msg<9, ()>>(), g::send::<1, 0, Return>()),
        )
        .roll(),
        g::send::<0, 4, Tail>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let retained = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let steps = [
        Unfold::Source,
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([1, 2]),
        Unfold::Sequence([0, 3]),
        Unfold::Once(4),
        Unfold::Source,
        Unfold::Alongside {
            retained,
            earlier: 5,
            next: 5,
            tail: 6,
            focus: [0, 1],
        },
    ];
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    assert!(matches!(
        unfolded.select(&[], &mut rows),
        Err(PathError::ParallelResource { role: 3, .. })
    ));
}

#[test]
fn an_unselected_old_arm_cannot_anchor_a_resumed_body() {
    let global = g::seq(
        g::route(
            g::send::<0, 0, g::Msg<1, ()>>().roll(),
            g::send::<0, 0, g::Msg<2, ()>>(),
        ),
        g::send::<0, 0, g::Msg<3, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let retained = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let steps = [
        Unfold::Source,
        Unfold::Once(0),
        Unfold::Source,
        Unfold::Choice([1, 2]),
        Unfold::Source,
        Unfold::Sequence([3, 4]),
        Unfold::After {
            retained,
            earlier: 5,
            next: 0,
        },
    ];
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    unfolded
        .select(
            &[RouteChoice {
                span: [0, 2],
                right: false,
            }],
            &mut rows,
        )
        .unwrap();
    assert!(matches!(
        unfolded.select(
            &[RouteChoice {
                span: [0, 2],
                right: true
            }],
            &mut rows
        ),
        Err(PathError::Anchor { event: 3 })
    ));
}
