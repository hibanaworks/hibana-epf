use hibana::{
    g,
    runtime::{
        program::project,
        tap::{self, TapEvent},
    },
};
use hibana_epf::{
    Acceptance, Capture, ExecutionStorage, ExecutionWitness, Protocol, RecordId, Unfold,
};

fn record(ordinal: usize, id: u16, view: u8, detail: u32) -> TapEvent {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6] = 7;
    bytes[7] = view;
    bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
    bytes[12..].copy_from_slice(&detail.to_be_bytes());
    bytes.into()
}

#[test]
fn a_committed_route_selection_cannot_name_an_unselected_query_occurrence() {
    use hibana_epf::RouteChoice;
    let global = g::route(
        g::send::<7, 8, g::Msg<1, ()>>(),
        g::send::<7, 8, g::Msg<2, ()>>(),
    )
    .resolve::<77>();
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    let scope = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 0)
        .unwrap()
        .causal_key();
    let mut source_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut source_storage).unwrap();
    let steps = [Unfold::Source, Unfold::Source, Unfold::Choice([0, 1])];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let source = protocol.unfolding(&steps, &mut proof).unwrap();
    let mut actors = vec![0; source.path_workspace_len().unwrap()];
    let path = source
        .select(
            &[RouteChoice {
                span: [0, 2],
                right: false,
            }],
            &mut actors,
        )
        .unwrap();
    // Synthetic complete controls: an uncommitted resolver query followed by
    // the committed Left selection. Only the query may use another path.
    let records = [
        record(0, tap::RESOLVER_AUDIT, 0, u32::from(scope) << 16 | 77),
        record(1, tap::ROUTE_ARM_SELECTION, 2, u32::from(scope) << 16),
    ];
    let captures = [Capture::new(&records, Some(2)).unwrap()];
    let order = [
        RecordId {
            producer: 0,
            ordinal: 0,
        },
        RecordId {
            producer: 0,
            ordinal: 1,
        },
    ];
    for (selection, accepted) in [(0, true), (1, false)] {
        let occurrences = [Some(0), Some(selection)];
        let witness = ExecutionWitness {
            session: 1,
            order: &order,
            occurrences: &occurrences,
            acceptances: &[],
        };
        let mut workspace = vec![0; path.execution_workspace_len(&captures, &witness).unwrap()];
        assert_eq!(
            path.check_execution(&captures, &witness, &mut workspace)
                .is_ok(),
            accepted
        );
    }
    let records = [
        records[0],
        records[1],
        record(2, tap::RESOLVER_AUDIT, 1, u32::from(scope) << 16 | 77),
    ];
    let captures = [Capture::new(&records, Some(3)).unwrap()];
    let order = [
        order[0],
        order[1],
        RecordId {
            producer: 0,
            ordinal: 2,
        },
    ];
    let occurrences = [Some(0), Some(0), Some(1)];
    let witness = ExecutionWitness {
        session: 1,
        order: &order,
        occurrences: &occurrences,
        acceptances: &[],
    };
    let mut workspace = vec![0; path.execution_workspace_len(&captures, &witness).unwrap()];
    assert!(
        path.check_execution(&captures, &witness, &mut workspace)
            .is_err()
    );
}

#[cfg(not(miri))]
#[test]
fn finite_attribution_search_matches_enumeration_of_every_small_assignment() {
    let sequential = g::seq(
        g::send::<7, 7, g::Msg<1, ()>>(),
        g::send::<7, 7, g::Msg<2, ()>>(),
    )
    .roll();
    let parallel = g::par(
        g::send::<7, 7, g::Msg<1, ()>>(),
        g::send::<7, 7, g::Msg<2, ()>>(),
    )
    .roll();
    for (is_parallel, snapshot) in [
        (
            false,
            tap::projected(&project::<7>(&sequential)).collect::<Vec<_>>(),
        ),
        (
            true,
            tap::projected(&project::<7>(&parallel)).collect::<Vec<_>>(),
        ),
    ] {
        let scope = snapshot
            .iter()
            .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
            .unwrap()
            .causal_key();
        let mut source_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut source_storage).unwrap();
        let mut workspace = std::vec::Vec::<usize>::new();
        let steps = [
            Unfold::Source,
            Unfold::Source,
            if is_parallel {
                Unfold::Parallel([0, 1])
            } else {
                Unfold::Sequence([0, 1])
            },
            Unfold::Once(2),
            Unfold::More([3, 2]),
        ];
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let source = protocol.unfolding(&steps, &mut proof).unwrap();
        let mut rows = vec![0; source.path_workspace_len().unwrap()];
        let path = source.select(&[], &mut rows).unwrap();
        let mut successful = 0;
        for length in 0..=4 {
            for sequence in 0..1usize << length {
                let mut records = Vec::new();
                let mut seen = [false; 2];
                for position in 0..length {
                    let original = sequence >> position & 1;
                    if seen[original] {
                        records.push(record(
                            records.len(),
                            tap::SCOPE_REENTRY,
                            7,
                            u32::from(scope) << 16 | original as u32,
                        ));
                        seen.fill(false);
                    }
                    seen[original] = true;
                    let lane = (snapshot[2 + original].arg0() >> 8) as u8;
                    records.push(record(
                        records.len(),
                        tap::ENDPOINT_SEND,
                        1,
                        7 << 24 | u32::from(lane) << 16 | original as u32,
                    ));
                }
                // These are synthetic record fixtures with a declared full
                // checkpoint, not reports of actual Endpoint executions.
                let capture = Capture::new(&records, Some(records.len() as u32)).unwrap();
                let order: Vec<_> = (0..records.len())
                    .map(|ordinal| RecordId {
                        producer: 0,
                        ordinal,
                    })
                    .collect();
                workspace.resize(path.interpretation_workspace_len(&[capture]).unwrap(), 0);
                let mut expected = false;
                let mut assignments = vec![None; records.len()];
                for mut assignment in 0..4usize.pow(length as u32) {
                    let choices: Vec<_> = (0..length)
                        .map(|_| {
                            let event = assignment % 4;
                            assignment /= 4;
                            event
                        })
                        .collect();
                    let mut at = 0;
                    for (position, record) in records.iter().enumerate() {
                        assignments[position] = Some(choices[at]);
                        if record.id() == tap::ENDPOINT_SEND {
                            at += 1;
                        }
                    }
                    let witness = ExecutionWitness {
                        session: 1,
                        order: &order,
                        occurrences: &assignments,
                        acceptances: &[],
                    };
                    expected |= path
                        .check_execution(&[capture], &witness, &mut workspace)
                        .is_ok();
                }
                let mut occurrences = vec![None; records.len()];
                let mut acceptances: [Acceptance; 0] = [];
                let mut inferred_order = vec![
                    RecordId {
                        producer: usize::MAX,
                        ordinal: usize::MAX,
                    };
                    order.len()
                ];
                let actual = path.interpret(
                    &[capture],
                    ExecutionStorage {
                        session: 1,
                        order: &mut inferred_order,
                        occurrences: &mut occurrences,
                        acceptances: &mut acceptances,
                    },
                    &mut workspace,
                );
                assert_eq!(
                    actual.is_ok(),
                    expected,
                    "par={is_parallel}, length={length}, sequence={sequence}"
                );
                if let Ok(witness) = actual {
                    assert_eq!(witness.order, order);
                    path.check_execution(&[capture], &witness, &mut workspace)
                        .unwrap();
                    successful += 1;
                }
            }
        }
        assert_eq!(successful, if is_parallel { 13 } else { 5 });
    }
}

#[test]
fn causal_order_search_matches_every_interleaving_and_rejects_an_early_reply() {
    let global = g::seq(
        g::send::<7, 8, g::Msg<1, ()>>(),
        g::send::<8, 7, g::Msg<2, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    let mut source_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut source_storage).unwrap();
    let mut workspace = std::vec::Vec::<usize>::new();
    let steps = [Unfold::Source, Unfold::Source, Unfold::Sequence([0, 1])];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
    let mut rows = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut rows).unwrap();
    let observed = |ordinal, actor: u8, id, source: u16| {
        let lane = (snapshot[2 + usize::from(source)].arg0() >> 8) as u8;
        let (direction, detail) = if id == tap::SEND_POLL {
            (actor, 0xffff_0000 | u32::from(source))
        } else {
            (
                if id == tap::ENDPOINT_SEND { 1 } else { 2 },
                u32::from(actor) << 24 | u32::from(lane) << 16 | u32::from(source),
            )
        };
        let mut bytes: [u8; 16] = record(ordinal, id, direction, detail).into();
        bytes[6] = actor;
        TapEvent::from(bytes)
    };
    // Synthetic complete captures. The early reply is impossible in every
    // interleaving because its producer has not yet committed the request.
    for early in [false, true] {
        let first = [
            observed(0, 7, tap::SEND_POLL, 0),
            observed(1, 7, tap::ENDPOINT_SEND, 0),
            observed(2, 7, tap::ENDPOINT_RECV, 1),
        ];
        let second = if early {
            [
                observed(0, 8, tap::SEND_POLL, 1),
                observed(1, 8, tap::ENDPOINT_SEND, 1),
                observed(2, 8, tap::ENDPOINT_RECV, 0),
            ]
        } else {
            [
                observed(0, 8, tap::ENDPOINT_RECV, 0),
                observed(1, 8, tap::SEND_POLL, 1),
                observed(2, 8, tap::ENDPOINT_SEND, 1),
            ]
        };
        let captures = [
            Capture::new(&first, Some(3)).unwrap(),
            Capture::new(&second, Some(3)).unwrap(),
        ];
        for captures in [captures, [captures[1], captures[0]]] {
            workspace.resize(path.interpretation_workspace_len(&captures).unwrap(), 0);
            let mut valid_orders = Vec::new();
            let mut checked = 0;
            for mask in (0u32..64).filter(|word| word.count_ones() == 3) {
                let mut ordinals = [0; 2];
                let order: Vec<_> = (0..6)
                    .map(|position| {
                        let producer = (mask >> position & 1) as usize;
                        let ordinal = ordinals[producer];
                        ordinals[producer] += 1;
                        RecordId { producer, ordinal }
                    })
                    .collect();
                let occurrences: Vec<_> = order
                    .iter()
                    .map(|id| {
                        Some(captures[id.producer].records()[id.ordinal].arg1() as u16 as usize)
                    })
                    .collect();
                let acceptances: Vec<_> = order
                    .iter()
                    .enumerate()
                    .filter(|(_, id)| {
                        captures[id.producer].records()[id.ordinal].id() == tap::SEND_POLL
                    })
                    .map(|(position, &first_poll)| Acceptance {
                        first_poll,
                        before: position + 1,
                    })
                    .collect();
                let witness = ExecutionWitness {
                    session: 1,
                    order: &order,
                    occurrences: &occurrences,
                    acceptances: &acceptances,
                };
                if path
                    .check_execution(&captures, &witness, &mut workspace)
                    .is_ok()
                {
                    valid_orders.push(order);
                }
                checked += 1;
            }
            assert_eq!(checked, 20);
            assert_eq!(valid_orders.is_empty(), early);
            let mut order = [RecordId {
                producer: usize::MAX,
                ordinal: usize::MAX,
            }; 6];
            let mut occurrences = [None; 6];
            let mut acceptances = [Acceptance {
                first_poll: RecordId {
                    producer: 0,
                    ordinal: 0,
                },
                before: 0,
            }; 2];
            let result = path.interpret(
                &captures,
                ExecutionStorage {
                    session: 1,
                    order: &mut order,
                    occurrences: &mut occurrences,
                    acceptances: &mut acceptances,
                },
                &mut workspace,
            );
            if early {
                assert!(matches!(
                    result,
                    Err(hibana_epf::InterpretationError::NoInterpretation)
                ));
            } else {
                let witness = result.unwrap();
                assert!(valid_orders.iter().any(|order| order == witness.order));
                path.check_execution(&captures, &witness, &mut workspace)
                    .unwrap();
            }
            let mut short = [RecordId {
                producer: usize::MAX,
                ordinal: usize::MAX,
            }; 5];
            assert!(matches!(
                path.interpret(
                    &captures,
                    ExecutionStorage {
                        session: 1,
                        order: &mut short,
                        occurrences: &mut occurrences,
                        acceptances: &mut acceptances,
                    },
                    &mut workspace,
                ),
                Err(hibana_epf::InterpretationError::Order {
                    required: 6,
                    actual: 5
                })
            ));
        }
    }
}
