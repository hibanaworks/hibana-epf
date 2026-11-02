use hibana::{
    g,
    runtime::{program::project, tap},
};
use hibana_epf::{
    Protocol,
    SourcePoint::{self, Accepted as A, Local as L, Received as R, Sent as S},
    Unfold, WordError,
};

#[test]
fn later_publication_cannot_hide_an_acceptance_before_its_source_predecessor() {
    let global = g::seq(
        g::send::<0, 0, g::Msg<6, ()>>(),
        g::send::<0, 1, g::Msg<7, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let steps = [Unfold::Source, Unfold::Source, Unfold::Sequence([0, 1])];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut rows).unwrap();
    let correct = [L(0), A(1), R(1), S(1)];
    let early = [A(1), L(0), R(1), S(1)];
    let commits = |word: &[SourcePoint]| {
        word.iter()
            .copied()
            .filter(|point| !matches!(point, A(_)))
            .collect::<Vec<_>>()
    };
    assert_eq!(commits(&correct), commits(&early));
    path.check_word(&correct).unwrap();
    assert_eq!(
        path.check_word(&early),
        Err(WordError::Predecessor {
            index: 0,
            prior: L(0)
        })
    );
    assert_eq!(
        path.check_word(&[L(0), R(1), S(1)]),
        Err(WordError::Predecessor {
            index: 1,
            prior: A(1)
        })
    );
    assert_eq!(
        path.check_word(&[L(0), L(0)]),
        Err(WordError::Duplicate {
            index: 1,
            earlier: 0
        })
    );
    assert_eq!(path.check_word(&[R(0)]), Err(WordError::Point { index: 0 }));
    assert_eq!(path.check_word(&[L(1)]), Err(WordError::Point { index: 0 }));
}

#[test]
fn a_parallel_join_requires_both_sides_without_ordering_the_siblings() {
    let global = g::seq(
        g::par(
            g::send::<0, 0, g::Msg<1, ()>>(),
            g::send::<0, 0, g::Msg<2, ()>>(),
        ),
        g::send::<0, 0, g::Msg<3, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let steps = [
        Unfold::Source,
        Unfold::Source,
        Unfold::Parallel([0, 1]),
        Unfold::Source,
        Unfold::Sequence([2, 3]),
    ];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut rows).unwrap();
    path.check_word(&[L(0), L(1), L(2)]).unwrap();
    path.check_word(&[L(1), L(0), L(2)]).unwrap();
    assert_eq!(
        path.check_word(&[L(0), L(2)]),
        Err(WordError::Predecessor {
            index: 1,
            prior: L(1)
        })
    );
}

#[test]
fn only_a_committed_resumed_body_delays_the_outgoing_continuation() {
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
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    let steps = [
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([0, 1]),
        Unfold::Once(2),
        Unfold::Source,
        Unfold::Alongside {
            retained,
            earlier: 3,
            next: 3,
            tail: 4,
            focus: [0, 1],
        },
    ];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut rows).unwrap();
    let first = [A(0), S(0), R(0), A(1), S(1), R(1)];
    let mut word = first.to_vec();
    word.extend([A(2), A(4)]);
    path.check_word(&word).unwrap();
    let mut word = first.to_vec();
    word.extend([A(2), S(2), A(4)]);
    assert_eq!(
        path.check_word(&word),
        Err(WordError::Predecessor {
            index: 8,
            prior: R(3)
        })
    );
    let mut word = first.to_vec();
    word.extend([A(2), S(2), R(2), A(3), S(3), R(3), A(4)]);
    path.check_word(&word).unwrap();
}

#[test]
fn an_old_incoming_continuation_can_arrive_after_the_other_view_resumes() {
    let global = g::seq(
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<1, 0, g::Msg<2, ()>>(),
        )
        .roll(),
        g::send::<1, 0, g::Msg<3, ()>>(),
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
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([0, 1]),
        Unfold::Once(2),
        Unfold::Source,
        Unfold::Alongside {
            retained,
            earlier: 3,
            next: 3,
            tail: 4,
            focus: [0, 1],
        },
    ];
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut rows).unwrap();
    path.check_word(&[A(0), S(0), R(0), A(1), S(1), R(1), A(4), A(2), S(2), R(4)])
        .unwrap();
}

#[test]
fn reusing_a_proof_dag_does_not_share_a_resumption_entry_across_invocations() {
    let global = g::seq(
        g::seq(
            g::seq(
                g::send::<0, 1, g::Msg<1, ()>>(),
                g::send::<1, 0, g::Msg<2, ()>>(),
            )
            .roll(),
            g::send::<0, 1, g::Msg<3, ()>>(),
        )
        .roll(),
        g::send::<0, 1, g::Msg<4, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
    let roll = |end| {
        snapshot
            .iter()
            .find(|row| {
                row.id() == tap::PROJECTED_SCOPE
                    && row.causal_key() >> 13 == 1
                    && row.arg1() == 2
                    && row.arg0() == end
            })
            .unwrap()
            .causal_key()
    };
    let inner = roll(2);
    let outer = roll(3);
    let steps = [
        Unfold::Source,
        Unfold::Source,
        Unfold::Sequence([0, 1]),
        Unfold::Once(2),
        Unfold::Source,
        Unfold::Alongside {
            retained: inner,
            earlier: 3,
            next: 3,
            tail: 4,
            focus: [0, 1],
        },
        Unfold::Once(5),
        Unfold::Source,
        Unfold::Alongside {
            retained: outer,
            earlier: 6,
            next: 6,
            tail: 7,
            focus: [0, 1],
        },
    ];
    let mut scratch = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut scratch).unwrap();
    scratch.resize(Protocol::unfolding_workspace_len(&steps), 0);
    let unfolded = protocol.unfolding(&steps, &mut scratch).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut rows).unwrap();
    path.check_word(&[
        A(0),
        S(0),
        R(0),
        A(1),
        S(1),
        R(1),
        A(2),
        S(2),
        R(2),
        A(3),
        S(3),
        R(3),
        A(4),
        S(4),
        R(4),
        A(5),
        S(5),
        R(5),
        A(6),
        S(6),
        R(6),
        A(7),
        A(9),
    ])
    .unwrap();
}
