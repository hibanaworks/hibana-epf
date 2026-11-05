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
    // Prefix readiness alone cannot reject a later contradictory resolver
    // decision: the final checker must retain the earlier committed choice.
    workspace.resize(path.interpretation_workspace_len(&captures).unwrap(), 0);
    let mut inferred = order;
    let mut occurrences = [None; 3];
    assert!(matches!(
        path.interpret(
            &captures,
            ExecutionStorage {
                session: 1,
                order: &mut inferred,
                occurrences: &mut occurrences,
                acceptances: &mut [],
            },
            &mut workspace,
        ),
        Err(hibana_epf::InterpretationError::NoInterpretation)
    ));
}

#[test]
fn interleaved_captures_resolve_open_call_completion_without_a_static_fifo_order() {
    let global = g::send::<7, 8, g::Msg<1, ()>>().roll();
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    let mut source_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut source_storage).unwrap();
    let steps = [Unfold::Source, Unfold::Once(0), Unfold::More([1, 0])];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let source = protocol.unfolding(&steps, &mut proof).unwrap();
    let mut bindings = vec![0; source.path_workspace_len().unwrap()];
    let path = source.select(&[], &mut bindings).unwrap();
    let lane = (snapshot[2].arg0() >> 8) as u8;
    let scope = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let observed = |ordinal, id, actor: u8| {
        let (direction, detail) = if id == tap::SEND_POLL {
            (actor, 0xffff_0000)
        } else {
            (
                if id == tap::ENDPOINT_SEND { 1 } else { 2 },
                u32::from(actor) << 24 | u32::from(lane) << 16,
            )
        };
        let mut bytes: [u8; 16] = record(ordinal, id, direction, detail).into();
        bytes[6] = actor;
        TapEvent::from(bytes)
    };
    // Complete synthetic prefixes. One publication is observed, whereas the
    // other call is supported only by a receipt in a different producer.
    let first = [
        observed(0, tap::SEND_POLL, 7),
        observed(1, tap::ENDPOINT_SEND, 7),
    ];
    let mut prepared: [u8; 16] = observed(0, tap::SEND_POLL, 7).into();
    prepared[12..].copy_from_slice(&(u32::from(scope) << 16).to_be_bytes());
    let second = [TapEvent::from(prepared)];
    let mut reset: [u8; 16] = record(1, tap::SCOPE_REENTRY, 8, u32::from(scope) << 16).into();
    reset[6] = 8;
    let received = [
        observed(0, tap::ENDPOINT_RECV, 8),
        TapEvent::from(reset),
        observed(2, tap::ENDPOINT_RECV, 8),
    ];
    let captures = [
        Capture::new(&first, Some(2)).unwrap(),
        Capture::new(&second, Some(1)).unwrap(),
        Capture::new(&received, Some(3)).unwrap(),
    ];
    let reference_order = [
        RecordId {
            producer: 0,
            ordinal: 0,
        },
        RecordId {
            producer: 0,
            ordinal: 1,
        },
        RecordId {
            producer: 2,
            ordinal: 0,
        },
        RecordId {
            producer: 1,
            ordinal: 0,
        },
        RecordId {
            producer: 2,
            ordinal: 1,
        },
        RecordId {
            producer: 2,
            ordinal: 2,
        },
    ];
    let reference = ExecutionWitness {
        session: 1,
        order: &reference_order,
        occurrences: &[Some(0), Some(0), Some(0), Some(1), Some(1), Some(1)],
        acceptances: &[
            Acceptance {
                first_poll: reference_order[0],
                before: 1,
            },
            Acceptance {
                first_poll: reference_order[3],
                before: 4,
            },
        ],
    };
    let mut reference_workspace =
        vec![0; path.execution_workspace_len(&captures, &reference).unwrap()];
    path.check_execution(&captures, &reference, &mut reference_workspace)
        .unwrap();
    for captures in [captures, [captures[2], captures[1], captures[0]]] {
        let mut workspace = vec![0; path.interpretation_workspace_len(&captures).unwrap()];
        assert!(matches!(
            protocol.deliveries(&captures, &mut workspace),
            Err(hibana_epf::DeliveryError::Ambiguous { .. })
        ));
        let mut order = [RecordId {
            producer: 0,
            ordinal: 0,
        }; 6];
        let mut occurrences = [None; 6];
        let mut acceptances = [Acceptance {
            first_poll: order[0],
            before: 0,
        }; 2];
        let witness = path
            .interpret(
                &captures,
                ExecutionStorage {
                    session: 1,
                    order: &mut order,
                    occurrences: &mut occurrences,
                    acceptances: &mut acceptances,
                },
                &mut workspace,
            )
            .unwrap();
        assert_eq!(witness.acceptances.len(), 2);
        assert_eq!(witness.order.len(), 6);
        path.check_execution(&captures, &witness, &mut workspace)
            .unwrap();
    }
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
            // Opaque diagnostics must remain in the returned order. Another
            // session's complete send is checked by custody, but must neither
            // acquire a source occurrence nor consume this session's slots.
            let mut padded = captures.map(|capture| capture.records().to_vec());
            padded[0].insert(0, record(0, tap::LANE_ACQUIRE, 7, 0));
            padded[1].push(record(0, tap::LANE_RELEASE, 7, 0));
            for producer in &mut padded {
                for (ordinal, event) in producer.iter_mut().enumerate() {
                    let mut bytes: [u8; 16] = (*event).into();
                    bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
                    *event = bytes.into();
                }
            }
            let unrelated = [first[0], first[1]].map(|event| {
                let mut bytes: [u8; 16] = event.into();
                bytes[8..12].copy_from_slice(&2u32.to_be_bytes());
                TapEvent::from(bytes)
            });
            let padded = [
                Capture::new(&padded[0], Some(4)).unwrap(),
                Capture::new(&padded[1], Some(4)).unwrap(),
                Capture::new(&unrelated, Some(2)).unwrap(),
            ];
            workspace.resize(path.interpretation_workspace_len(&padded).unwrap(), 0);
            let mut order = [order[0]; 10];
            let mut occurrences = [None; 10];
            let result = path.interpret(
                &padded,
                ExecutionStorage {
                    session: 1,
                    order: &mut order,
                    occurrences: &mut occurrences,
                    acceptances: &mut acceptances,
                },
                &mut workspace,
            );
            assert_eq!(result.is_ok(), !early);
            if let Ok(witness) = result {
                assert_eq!(witness.order.len(), 10);
                assert_eq!(
                    witness
                        .occurrences
                        .iter()
                        .filter(|event| event.is_none())
                        .count(),
                    4
                );
                path.check_execution(&padded, &witness, &mut workspace)
                    .unwrap();
            }
        }
    }
}
