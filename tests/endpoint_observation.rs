use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use hibana::{
    g::{self, Msg},
    runtime::transport::{Outgoing, PortOpen, ReceivedFrame, Transport, TransportError},
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::project,
        resolver::{DecisionArm, ResolverError, ResolverRef},
        tap::{self, TapEvent},
    },
};
use hibana_epf::{Epf, EpfStorage, ImageSpec};

struct LocalOnly;

#[test]
fn automatic_audit_uses_a_complete_burst_capture_instead_of_the_diagnostic_window() {
    use hibana_epf::Capture;
    let rows = Cell::new(Vec::new());
    let recorder = |event| {
        let mut captured = rows.take();
        captured.push(event);
        rows.set(captured);
    };
    let global = g::send::<7, 7, Msg<1, ()>>().roll();
    let program = project::<7>(&global);
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let rv = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    rv.observe(&recorder);
    let mut endpoint = rv.enter(SessionId::new(1), &program).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let operation = core::pin::pin!(async {
        for _ in 0..32 {
            endpoint.send::<Msg<1, ()>>(&()).await?;
        }
        Ok::<_, hibana::EndpointError>(())
    });
    assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
    let checkpoint = rv.tap().checkpoint();
    let captured = rows.take();
    let window: Vec<_> = rv.tap().collect();
    assert!(Capture::new(&window, checkpoint).is_err());
    let snapshot: Vec<_> = tap::projected(&program).collect();
    assert_eq!(audit_capture(&snapshot, &captured, checkpoint).unwrap(), 32);
}

fn audit_capture(
    snapshot: &[TapEvent],
    captured: &[TapEvent],
    checkpoint: Option<u32>,
) -> Result<usize, hibana_epf::AuditError> {
    use hibana_epf::{
        Acceptance, AuditStorage, Capture, ExecutionStorage, Protocol, RecordId, RouteChoice,
        Unfold,
    };
    let captures = [Capture::new(captured, checkpoint).unwrap()];
    let mut source_storage = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut source_storage).unwrap();
    let capacity = 2 * captured.len() + 1;
    let mut unfolding = vec![Unfold::Source; capacity];
    let mut choices = vec![
        RouteChoice {
            span: [0, 0],
            right: false
        };
        protocol.audit_choice_capacity(capacity).unwrap()
    ];
    let mut order = vec![
        RecordId {
            producer: 0,
            ordinal: 0
        };
        captured.len()
    ];
    let mut occurrences = vec![None; captured.len()];
    let mut acceptances = vec![
        Acceptance {
            first_poll: RecordId {
                producer: 0,
                ordinal: 0
            },
            before: 0
        };
        captured.len()
    ];
    let mut workspace = std::vec![0; protocol.audit_workspace_len(&captures, capacity).unwrap()];
    let audit = protocol.audit(
        &captures,
        AuditStorage {
            unfolding: &mut unfolding,
            choices: &mut choices,
            execution: ExecutionStorage {
                session: 1,
                order: &mut order,
                occurrences: &mut occurrences,
                acceptances: &mut acceptances,
            },
        },
        &mut workspace,
    )?;
    Ok(audit.path().unfolding().event_count())
}

#[test]
fn automatic_audit_checks_resolver_calls_from_outgoing_offers_in_each_visit() {
    let rows = Cell::new(Vec::new());
    let recorder = |event| {
        let mut captured = rows.take();
        captured.push(event);
        rows.set(captured);
    };
    let right = Cell::new(false);
    let global = g::route(
        g::seq(g::send::<7, 7, Msg<1, ()>>(), g::send::<7, 7, Msg<3, ()>>()),
        g::seq(g::send::<7, 7, Msg<2, ()>>(), g::send::<7, 7, Msg<3, ()>>()),
    )
    .resolve::<77>()
    .roll();
    let program = project::<7>(&global);
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let rv = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    rv.observe(&recorder);
    rv.set_resolver(
        &program,
        ResolverRef::<77>::decision_state(&right, |right| {
            Ok(if right.get() {
                DecisionArm::Right
            } else {
                DecisionArm::Left
            })
        }),
    )
    .unwrap();
    let mut endpoint = rv.enter(SessionId::new(1), &program).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let operation = core::pin::pin!(async {
        endpoint.offer().await?.send::<Msg<1, ()>>(&()).await?;
        endpoint.send::<Msg<3, ()>>(&()).await?;
        right.set(true);
        endpoint.offer().await?.send::<Msg<2, ()>>(&()).await?;
        endpoint.send::<Msg<3, ()>>(&()).await?;
        Ok::<_, hibana::EndpointError>(())
    });
    assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
    let captured = rows.take();
    let snapshot: Vec<_> = tap::projected(&program).collect();
    assert_eq!(
        captured
            .iter()
            .filter(|row| row.id() == tap::RESOLVER_AUDIT)
            .count(),
        2
    );
    assert_eq!(
        audit_capture(&snapshot, &captured, rv.tap().checkpoint()).unwrap(),
        8
    );
    // Keep a complete, correctly numbered prefix while deleting only the
    // resolver evidence. Agreement between later commits cannot replace it.
    let missing: Vec<TapEvent> = captured
        .iter()
        .filter(|row| row.id() != tap::RESOLVER_AUDIT)
        .enumerate()
        .map(|(ordinal, row)| {
            let mut bytes: [u8; 16] = (*row).into();
            bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
            bytes.into()
        })
        .collect();
    let captures = [hibana_epf::Capture::new(&missing, Some(missing.len() as u32)).unwrap()];
    let mut source_storage = vec![0; hibana_epf::Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = hibana_epf::Protocol::new(&snapshot, &mut source_storage).unwrap();
    let order: Vec<_> = (0..missing.len())
        .map(|ordinal| hibana_epf::RecordId {
            producer: 0,
            ordinal,
        })
        .collect();
    let mut workspace = std::vec![0; protocol.custody_workspace_len(&captures)];
    assert!(matches!(
        protocol.check_routes(&captures, &order, &mut workspace),
        Err(hibana_epf::RouteHistoryError::Record { .. })
    ));
}

#[test]
fn automatic_audit_infers_typed_branch_visits_without_resolver_or_offer_records() {
    let rows = Cell::new(Vec::new());
    let recorder = |event| {
        let mut captured = rows.take();
        captured.push(event);
        rows.set(captured);
    };
    let global = g::route(
        g::seq(g::send::<7, 7, Msg<1, ()>>(), g::send::<7, 7, Msg<2, ()>>()),
        g::seq(g::send::<7, 7, Msg<3, ()>>(), g::send::<7, 7, Msg<4, ()>>()),
    )
    .roll();
    let program = project::<7>(&global);
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let rv = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    rv.observe(&recorder);
    let mut endpoint = rv.enter(SessionId::new(1), &program).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let operation = core::pin::pin!(async {
        endpoint.send::<Msg<3, ()>>(&()).await?;
        endpoint.send::<Msg<4, ()>>(&()).await?;
        endpoint.send::<Msg<1, ()>>(&()).await?;
        endpoint.send::<Msg<2, ()>>(&()).await?;
        Ok::<_, hibana::EndpointError>(())
    });
    assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
    let captured = rows.take();
    assert!(
        !captured
            .iter()
            .any(|r| matches!(r.id(), tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION))
    );
    let snapshot: Vec<_> = tap::projected(&program).collect();
    assert_eq!(
        audit_capture(&snapshot, &captured, rv.tap().checkpoint()).unwrap(),
        8
    );
}

#[test]
fn nested_route_visits_can_change_arms_without_reusing_the_previous_choice() {
    type Left = Msg<7, ()>;
    type Right = Msg<8, ()>;
    type Tail = Msg<9, ()>;
    let global = g::seq(
        g::route(g::send::<7, 7, Left>(), g::send::<7, 7, Right>())
            .resolve::<17>()
            .roll(),
        g::send::<7, 7, Tail>(),
    )
    .roll();
    let program = project::<7>(&global);
    let selected = Cell::new(DecisionArm::Left);
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    kit.set_resolver(
        &program,
        ResolverRef::<17>::decision_state(&selected, |choice| Ok(choice.get())),
    )
    .unwrap();
    let mut endpoint = kit.enter(SessionId::new(137), &program).unwrap();
    let mut records = kit.tap();
    let mut captured: Vec<_> = records.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    {
        let operation = core::pin::pin!(async {
            endpoint.send::<Left>(&()).await?;
            captured.extend(records.by_ref());
            endpoint.send::<Left>(&()).await?;
            captured.extend(records.by_ref());
            selected.set(DecisionArm::Right);
            endpoint.send::<Right>(&()).await?;
            captured.extend(records.by_ref());
            endpoint.send::<Tail>(&()).await?;
            captured.extend(records.by_ref());
            selected.set(DecisionArm::Left);
            endpoint.send::<Left>(&()).await?;
            captured.extend(records.by_ref());
            endpoint.send::<Tail>(&()).await?;
            captured.extend(records.by_ref());
            Ok::<_, hibana::EndpointError>(())
        });
        assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
    }
    let snapshot: Vec<_> = tap::projected(&program).collect();
    let mut source_storage = vec![0; hibana_epf::Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = hibana_epf::Protocol::new(&snapshot, &mut source_storage).unwrap();
    let capture = hibana_epf::Capture::new(&captured, records.checkpoint()).unwrap();
    let order: Vec<_> = (0..captured.len())
        .map(|ordinal| hibana_epf::RecordId {
            producer: 0,
            ordinal,
        })
        .collect();
    let mut workspace = std::vec![0; protocol.custody_workspace_len(&[capture])];
    protocol
        .check_routes(&[capture], &order, &mut workspace)
        .unwrap();
    let steps = [
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Choice([0, 1]),
        hibana_epf::Unfold::Once(2),
        hibana_epf::Unfold::More([3, 2]),
        hibana_epf::Unfold::More([4, 2]),
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Sequence([5, 6]),
        hibana_epf::Unfold::Once(7),
        hibana_epf::Unfold::Sequence([3, 6]),
        hibana_epf::Unfold::More([8, 9]),
    ];
    let mut proof = vec![0; hibana_epf::Protocol::unfolding_workspace_len(&steps)];
    let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
    let choices = [
        hibana_epf::RouteChoice {
            span: [0, 2],
            right: false,
        },
        hibana_epf::RouteChoice {
            span: [2, 4],
            right: false,
        },
        hibana_epf::RouteChoice {
            span: [4, 6],
            right: true,
        },
        hibana_epf::RouteChoice {
            span: [7, 9],
            right: false,
        },
    ];
    let mut actors = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&choices, &mut actors).unwrap();
    let executed = [0, 2, 5, 6, 7, 9];
    let mut completed = 0;
    let occurrences: Vec<_> = captured
        .iter()
        .map(|record| {
            if matches!(
                record.id(),
                tap::SCOPE_REENTRY | tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION
            ) {
                Some(executed[completed])
            } else if record.id() == tap::ENDPOINT_SEND {
                let event = executed[completed];
                completed += 1;
                Some(event)
            } else {
                None
            }
        })
        .collect();
    let witness = hibana_epf::ExecutionWitness {
        session: 137,
        order: &order,
        occurrences: &occurrences,
        acceptances: &[],
    };
    workspace.resize(
        path.execution_workspace_len(&[capture], &witness).unwrap(),
        0,
    );
    path.check_execution(&[capture], &witness, &mut workspace)
        .unwrap();
    let mut inferred = vec![None; order.len()];
    let mut inferred_acceptances = [];
    let mut inferred_order = order.clone();
    workspace.resize(path.interpretation_workspace_len(&[capture]).unwrap(), 0);
    let automatic = path
        .interpret(
            &[capture],
            hibana_epf::ExecutionStorage {
                session: 137,
                order: &mut inferred_order,
                occurrences: &mut inferred,
                acceptances: &mut inferred_acceptances,
            },
            &mut workspace,
        )
        .unwrap();
    for (position, record) in captured.iter().enumerate() {
        if record.id() == tap::ENDPOINT_SEND {
            assert_eq!(automatic.occurrences[position], occurrences[position]);
        }
    }
    assert!(automatic.acceptances.is_empty());
    path.check_execution(&[capture], &automatic, &mut workspace)
        .unwrap();
    // Keep the complete ordinal sequence while replacing the reset that makes
    // the first change of arm legal with an irrelevant observation.
    let right = captured
        .iter()
        .position(|record| record.id() == tap::ENDPOINT_SEND && record.arg1() as u16 == 1)
        .unwrap();
    let reset = captured[..right]
        .iter()
        .rposition(|record| record.id() == tap::SCOPE_REENTRY)
        .unwrap();
    let mut missing_reset = captured.clone();
    let mut bytes: [u8; 16] = missing_reset[reset].into();
    bytes[4..6].copy_from_slice(&0u16.to_be_bytes());
    missing_reset[reset] = bytes.into();
    let invalid = hibana_epf::Capture::new(&missing_reset, records.checkpoint()).unwrap();
    assert!(
        protocol
            .check_routes(&[invalid], &order, &mut workspace)
            .is_err()
    );
}

#[test]
fn a_static_local_row_cannot_be_replayed_without_a_new_visit() {
    type Tick = Msg<7, ()>;
    let global = g::send::<7, 7, Tick>();
    let program = project::<7>(&global);
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    let mut endpoint = kit.enter(SessionId::new(138), &program).unwrap();
    let mut records = kit.tap();
    let mut captured: Vec<_> = records.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        core::pin::pin!(endpoint.send::<Tick>(&())).poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    captured.extend(records.by_ref());
    let snapshot: Vec<_> = tap::projected(&program).collect();
    let mut source_storage = vec![0; hibana_epf::Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = hibana_epf::Protocol::new(&snapshot, &mut source_storage).unwrap();
    let mut replayed = captured.clone();
    let mut bytes: [u8; 16] = (*captured
        .iter()
        .find(|record| record.id() == tap::ENDPOINT_SEND)
        .unwrap())
    .into();
    bytes[..4].copy_from_slice(&(replayed.len() as u32).to_be_bytes());
    replayed.push(bytes.into());
    let invalid = hibana_epf::Capture::new(&replayed, Some(replayed.len() as u32)).unwrap();
    let order: Vec<_> = (0..replayed.len())
        .map(|ordinal| hibana_epf::RecordId {
            producer: 0,
            ordinal,
        })
        .collect();
    let mut workspace = std::vec![0; protocol.custody_workspace_len(&[invalid])];
    // Membership and ownership alone both accept this duplicate static row.
    protocol
        .check_custody(&[invalid], &order, &mut workspace)
        .unwrap();
    assert!(matches!(
        protocol.check_routes(&[invalid], &order, &mut workspace),
        Err(hibana_epf::RouteHistoryError::Duplicate { .. })
    ));
}

#[test]
fn live_reentry_records_retain_the_exact_scope_through_epf_observation() {
    type Tick = Msg<7, ()>;
    type Tail = Msg<8, ()>;
    let global = g::seq(g::send::<7, 7, Tick>().roll(), g::send::<7, 7, Tail>()).roll();
    let program = project::<7>(&global);
    let snapshot: Vec<_> = tap::projected(&program).collect();
    let outer = snapshot
        .iter()
        .find(|row| {
            row.id() == tap::PROJECTED_SCOPE
                && row.causal_key() >> 13 == 1
                && row.arg0() == 2
                && row.arg1() & 3 == 2
        })
        .unwrap()
        .causal_key();
    let mut source_storage = vec![0; hibana_epf::Protocol::workspace_len(&snapshot).unwrap()];
    let _protocol = hibana_epf::Protocol::new(&snapshot, &mut source_storage).unwrap();
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    let mut endpoint = kit.enter(SessionId::new(96), &program).unwrap();
    let mut records = kit.tap();
    let mut captured: Vec<_> = records.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    {
        let operation = core::pin::pin!(async {
            endpoint.send::<Tick>(&()).await?;
            captured.extend(records.by_ref());
            endpoint.send::<Tick>(&()).await?;
            captured.extend(records.by_ref());
            endpoint.send::<Tail>(&()).await?;
            captured.extend(records.by_ref());
            endpoint.send::<Tick>(&()).await?;
            captured.extend(records.by_ref());
            endpoint.send::<Tail>(&()).await?;
            captured.extend(records.by_ref());
            Ok::<_, hibana::EndpointError>(())
        });
        assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
    }
    assert!(
        captured
            .windows(2)
            .all(|pair| pair[0].ts() + 1 == pair[1].ts())
    );
    let checkpoint = records.checkpoint();
    let capture = hibana_epf::Capture::new(&captured, checkpoint).unwrap();
    assert_eq!(capture.records().len(), captured.len());
    assert!(matches!(
        hibana_epf::Capture::new(&captured[..captured.len() - 1], checkpoint),
        Err(hibana_epf::CaptureError::Length { .. }),
    ));
    let mut epf_storage = EpfStorage::<0, 64>::new();
    let epf = Epf::new(&mut epf_storage);
    let resets: Vec<_> = captured
        .iter()
        .filter(|record| record.id() == tap::SCOPE_REENTRY)
        .collect();
    assert_eq!(resets.len(), 2);
    assert_ne!(resets[0].arg1(), resets[1].arg1());
    assert_eq!(resets[1].arg1(), u32::from(outer) << 16);
    for record in &resets {
        let decoded = TapEvent::from(<[u8; 16]>::from(**record));
        let observed = epf.run(decoded);
        assert_eq!(observed.kind(), u32::from(tap::SCOPE_REENTRY));
        assert_eq!(observed.arg0(), 96);
        assert_eq!(observed.arg1(), record.arg1());
        assert_eq!(observed.arg2(), (7 << 8) | 7);
        assert_eq!(decoded.ts(), record.ts());
    }
    let mut image = [0; 64];
    let len = ImageSpec::ObserveMatch {
        input: 1,
        value: u32::from(outer) << 16,
        kind: u32::from(tap::SCOPE_REENTRY),
        reason: 0,
    }
    .write(&mut image)
    .unwrap();
    epf.load(&image[..len]).unwrap();
    for record in captured {
        let observed = epf.run(record);
        assert_eq!(observed.emitted(), record.arg1() == u32::from(outer) << 16,);
    }
}

#[test]
fn a_live_capture_accounts_for_overwrite_and_continuously_drained_records() {
    type Tick = Msg<7, ()>;
    let global = g::send::<7, 7, Tick>().roll();
    let program = project::<7>(&global);
    for drain in [false, true] {
        let mut slab = [0; 8192];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
        let mut endpoint = kit.enter(SessionId::new(97), &program).unwrap();
        let mut records = kit.tap();
        let mut captured = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        {
            let operation = core::pin::pin!(async {
                for _ in 0..129 {
                    endpoint.send::<Tick>(&()).await?;
                    if drain {
                        captured.extend(records.by_ref());
                    }
                }
                Ok::<_, hibana::EndpointError>(())
            });
            assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        captured.extend(records.by_ref());
        let checked = hibana_epf::Capture::new(&captured, records.checkpoint());
        if drain {
            let checked = checked.unwrap();
            assert!(checked.records().len() > 255);
        } else {
            assert!(captured[0].ts() > 0);
            assert!(matches!(
                checked,
                Err(hibana_epf::CaptureError::Length { .. })
            ));
        }
    }
}

impl Transport for LocalOnly {
    type Tx<'a> = ();
    type Rx<'a> = ();

    fn open(&self, _: PortOpen) -> ((), ()) {
        ((), ())
    }

    fn poll_send(
        &self,
        _: &mut (),
        _: Outgoing<'_>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        panic!("a local unit operation must not send a transport frame")
    }

    fn cancel_send(&self, _: &mut ()) {
        panic!("no transport send was started")
    }

    fn poll_recv<'a>(
        &'a self,
        _: &'a mut (),
        _: &mut Context<'_>,
    ) -> Poll<Result<ReceivedFrame<'a>, TransportError>> {
        panic!("a local unit operation must not receive a transport frame")
    }

    fn requeue(&self, _: &mut ()) -> Result<(), TransportError> {
        panic!("no transport frame was received")
    }
}

#[test]
fn loaded_epf_policies_control_live_endpoint_choices_across_roll_visits() {
    type Left = Msg<7, ()>;
    type Right = Msg<8, ()>;
    let global = g::route(g::send::<0, 0, Left>(), g::send::<0, 0, Right>())
        .resolve::<{ u16::MAX }>()
        .roll();
    let program = project::<0>(&global);
    let mut epf_storage = EpfStorage::<1, 64>::new();
    let epf = Epf::new(&mut epf_storage);
    let resolver = epf
        .resolver::<{ u16::MAX }>(ResolverRef::decision_state(&(), |_| {
            panic!("an active policy must supply the decision")
        }))
        .unwrap();
    let mut slab = [0; 8192];
    let mut kit_storage = SessionKitStorage::uninit();
    let kit = kit_storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    kit.set_resolver(&program, resolver).unwrap();
    let mut endpoint = kit.enter(SessionId::new(45), &program).unwrap();
    let mut events = kit.tap();
    let mut cx = Context::from_waker(Waker::noop());
    while events.next().is_some() {}

    for arm in [0, 1, 0] {
        let mut image = [0; 64];
        let len = ImageSpec::PolicyChoose {
            policy_id: u16::MAX,
            arm,
        }
        .write(&mut image)
        .unwrap();
        epf.load(&image[..len]).unwrap();
        {
            let mut operation = core::pin::pin!(async {
                let branch = endpoint.offer().await.unwrap();
                assert_eq!(branch.label(), if arm == 0 { 7 } else { 8 });
                match branch.label() {
                    7 => branch.recv::<Left>().await.unwrap(),
                    8 => branch.recv::<Right>().await.unwrap(),
                    label => panic!("unexpected branch {label}"),
                };
            });
            assert!(matches!(operation.as_mut().poll(&mut cx), Poll::Ready(())));
        }
        let batch: Vec<_> = events.by_ref().collect();
        assert_eq!(
            batch
                .iter()
                .filter(|e| e.id() == tap::ENDPOINT_RECV)
                .count(),
            1
        );
        assert!(
            batch.iter().any(|event| {
                event.id() == tap::RESOLVER_AUDIT && event.causal_key() as u8 == arm
            })
        );
        for event in batch {
            let observed = epf.run(event);
            assert!(observed.emitted());
            assert_eq!(observed.arg0(), event.arg0());
            assert_eq!(observed.arg1(), event.arg1());
        }
    }
}

#[test]
fn observed_endpoint_input_can_choose_or_reject_the_next_registered_route() {
    type Prefix = Msg<6, ()>;
    type Left = Msg<7, ()>;
    type Right = Msg<8, ()>;
    let global = g::seq(
        g::send::<0, 0, Prefix>(),
        g::route(g::send::<0, 0, Left>(), g::send::<0, 0, Right>()).resolve::<17>(),
    );
    let program = project::<0>(&global);

    for matches_input in [true, false] {
        let mut epf_storage = EpfStorage::<1, 64>::new();
        let epf = Epf::new(&mut epf_storage);
        let resolver = epf
            .resolver::<17>(ResolverRef::decision_state(&(), |_| {
                panic!("a nonmatching active policy must reject")
            }))
            .unwrap();
        let mut slab = [0; 8192];
        let mut kit_storage = SessionKitStorage::uninit();
        let kit = kit_storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
        kit.set_resolver(&program, resolver).unwrap();
        let mut endpoint = kit.enter(SessionId::new(46), &program).unwrap();
        let mut events = kit.tap();
        let mut cx = Context::from_waker(Waker::noop());
        {
            let prefix = core::pin::pin!(endpoint.send::<Prefix>(&()));
            assert!(matches!(prefix.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        let committed = events
            .by_ref()
            .find(|event| event.id() == tap::ENDPOINT_SEND)
            .expect("the prefix must commit before the resolver runs");
        assert_eq!(committed.arg0(), 46);
        epf.run(committed);
        while events.next().is_some() {}
        let mut image = [0; 64];
        let len = ImageSpec::PolicyChooseOnInput {
            policy_id: 17,
            input: 0,
            value: if matches_input { 46 } else { 47 },
            arm: 1,
        }
        .write(&mut image)
        .unwrap();
        epf.load(&image[..len]).unwrap();

        {
            let mut operation = core::pin::pin!(async {
                match endpoint.offer().await {
                    Ok(branch) => {
                        assert!(matches_input);
                        assert_eq!(branch.label(), 8);
                        branch.recv::<Right>().await.unwrap();
                    }
                    Err(_) => assert!(!matches_input),
                }
            });
            assert!(matches!(operation.as_mut().poll(&mut cx), Poll::Ready(())));
        }
        let batch: Vec<_> = events.by_ref().collect();
        assert!(batch.iter().any(|event| {
            event.id() == tap::RESOLVER_AUDIT
                && event.causal_key() as u8 == if matches_input { 1 } else { 0xff }
        }));
        assert_eq!(
            batch
                .iter()
                .filter(|e| e.id() == tap::ENDPOINT_RECV)
                .count(),
            usize::from(matches_input)
        );
    }
}

#[test]
fn flat_projected_rows_cannot_distinguish_a_finite_step_from_a_roll() {
    type Step = Msg<19, ()>;
    let finite = g::send::<0, 0, Step>();
    let repeated = g::send::<0, 0, Step>().roll();
    let finite = project::<0>(&finite);
    let repeated = project::<0>(&repeated);
    let finite_snapshot: Vec<_> = tap::projected(&finite).collect();
    let repeated_snapshot: Vec<_> = tap::projected(&repeated).collect();
    assert!(finite_snapshot != repeated_snapshot);
    let finite_rows: Vec<[u8; 16]> = finite_snapshot
        .into_iter()
        .filter(|row| row.id() == tap::PROJECTED_LOCAL)
        .map(Into::into)
        .collect();
    let repeated_rows: Vec<[u8; 16]> = repeated_snapshot
        .into_iter()
        .filter(|row| row.id() == tap::PROJECTED_LOCAL)
        .map(Into::into)
        .collect();
    assert_eq!(finite_rows, repeated_rows);

    let mut permitted = [false; 2];
    for (index, program) in [&finite, &repeated].into_iter().enumerate() {
        let mut slab = [0; 8192];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
        let mut endpoint = kit.enter(SessionId::new(43), program).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        {
            let first = core::pin::pin!(endpoint.send::<Step>(&()));
            assert!(matches!(first.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        let second = core::pin::pin!(endpoint.send::<Step>(&()));
        let second = second.poll(&mut cx);
        assert!(second.is_ready(), "the second call must not wait");
        permitted[index] = matches!(second, Poll::Ready(Ok(())));
    }
    assert_eq!(permitted, [false, true]);
}

#[test]
fn flat_projected_rows_cannot_distinguish_sequence_from_choice() {
    type First = Msg<20, ()>;
    type Second = Msg<21, ()>;
    let sequential = g::seq(g::send::<0, 0, First>(), g::send::<0, 0, Second>());
    let alternative = g::route(g::send::<0, 0, First>(), g::send::<0, 0, Second>());
    let sequential = project::<0>(&sequential);
    let alternative = project::<0>(&alternative);
    let sequential_snapshot: Vec<_> = tap::projected(&sequential).collect();
    let alternative_snapshot: Vec<_> = tap::projected(&alternative).collect();
    assert!(sequential_snapshot != alternative_snapshot);
    let sequential_rows: Vec<[u8; 16]> = sequential_snapshot
        .into_iter()
        .filter(|row| row.id() == tap::PROJECTED_LOCAL)
        .map(Into::into)
        .collect();
    let alternative_rows: Vec<[u8; 16]> = alternative_snapshot
        .into_iter()
        .filter(|row| row.id() == tap::PROJECTED_LOCAL)
        .map(Into::into)
        .collect();
    assert_eq!(sequential_rows, alternative_rows);

    let mut permitted = [false; 2];
    for (index, program) in [&sequential, &alternative].into_iter().enumerate() {
        let mut slab = [0; 8192];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
        let mut endpoint = kit.enter(SessionId::new(44), program).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        {
            let first = core::pin::pin!(endpoint.send::<First>(&()));
            assert!(matches!(first.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        let second = core::pin::pin!(endpoint.send::<Second>(&()));
        let second = second.poll(&mut cx);
        assert!(second.is_ready(), "the second call must not wait");
        permitted[index] = matches!(second, Poll::Ready(Ok(())));
    }
    assert_eq!(permitted, [true, false]);
}

#[test]
fn compiled_snapshot_carries_nested_control_and_conditional_delegation_data() {
    type Loan = Msg<1, hibana::Endpoint<'static, 9>>;
    let global = g::seq(
        g::send::<0, 1, Loan>(),
        g::seq(
            g::route(g::send::<1, 2, Msg<4, ()>>(), g::send::<1, 2, Loan>()).resolve::<17>(),
            g::par(
                g::send::<9, 3, Msg<2, ()>>().roll(),
                g::send::<0, 4, Msg<3, ()>>(),
            ),
        ),
    );
    let program = project::<0>(&global);
    let compiled = tap::projected(&program);
    let snapshot: Vec<_> = compiled.clone().collect();
    assert_eq!(compiled.len(), snapshot.len());
    let header = snapshot[0];
    assert_eq!(header.id(), tap::PROJECTED_PROGRAM);
    assert_eq!(header.ts(), 1 | 1 << 16);
    assert_eq!(header.arg0(), 5 << 16 | 9);
    assert_eq!(header.arg1(), 1 << 16 | 1);
    let role = snapshot[1];
    assert_eq!(role.id(), tap::PROJECTED_ROLE);
    assert_eq!(role.arg0(), 1);
    assert_eq!(role.arg1(), 9);
    assert_eq!(
        snapshot.len(),
        2 + 5 + 9 + 1 + 5 + 1 + 1 + role.ts() as usize
    );
    let source: Vec<_> = snapshot
        .iter()
        .filter(|row| row.id() == tap::PROJECTED_SOURCE)
        .collect();
    assert_eq!(source.len(), 5);
    assert_eq!(source[0].causal_key() >> 8, 1);
    assert_eq!(source[0].arg1(), 9);
    assert_eq!(source[3].arg0() >> 16, 9 << 8 | 3);
    let markers: Vec<_> = snapshot
        .iter()
        .filter(|row| row.id() == tap::PROJECTED_SCOPE)
        .collect();
    assert_eq!(markers.len(), 9);
    for kind in 0..3 {
        assert!(markers.iter().any(|row| row.causal_key() >> 13 == kind));
    }
    let choice = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_CHOICE)
        .unwrap();
    assert_eq!((choice.arg0(), choice.arg1()), (1, 18));
    let bindings: Vec<_> = snapshot
        .iter()
        .filter(|row| row.id() == tap::PROJECTED_BINDING)
        .collect();
    assert_eq!(bindings.len(), 5);
    assert_eq!((bindings[3].arg0(), bindings[3].arg1()), (256, 3));
    let decision = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_ACTOR_DECISION)
        .unwrap();
    assert_eq!(decision.ts(), 256);
    assert_eq!(choice.causal_key(), decision.causal_key());
    assert_eq!((decision.arg0(), decision.arg1()), (1, 2));
    let initial = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_INITIAL_ACTOR)
        .unwrap();
    assert_eq!((initial.arg0(), initial.arg1()), (9, 0));
    for (index, row) in snapshot.into_iter().enumerate() {
        assert!(compiled.clone().nth(index).unwrap() == row);
        let encoded: [u8; 16] = row.into();
        assert!(TapEvent::from(encoded) == row);
    }
}

#[test]
fn live_endpoint_choices_and_roll_commits_reach_epf_without_losing_observation_fields() {
    type Left = Msg<7, ()>;
    type Right = Msg<8, ()>;
    let global = g::route(g::send::<7, 7, Left>(), g::send::<7, 7, Right>())
        .resolve::<17>()
        .roll();
    let program = project::<7>(&global);
    let choice = Cell::new(DecisionArm::Left);
    let mut slab = [0; 8192];
    let mut kit_storage = SessionKitStorage::uninit();
    let kit = kit_storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
    kit.set_resolver(
        &program,
        ResolverRef::<17>::decision_state(&choice, |choice| Ok::<_, ResolverError>(choice.get())),
    )
    .unwrap();
    let mut endpoint = kit.enter(SessionId::new(42), &program).unwrap();
    let mut events = kit.tap();
    let mut storage = EpfStorage::<0, 64>::new();
    let epf = Epf::new(&mut storage);
    let mut observed = Vec::new();
    let mut cx = Context::from_waker(Waker::noop());
    while events.next().is_some() {}

    for arm in [DecisionArm::Left, DecisionArm::Right, DecisionArm::Left] {
        choice.set(arm);
        {
            let mut operation = core::pin::pin!(async {
                let branch = endpoint.offer().await.unwrap();
                match branch.label() {
                    7 => branch.recv::<Left>().await.unwrap(),
                    8 => branch.recv::<Right>().await.unwrap(),
                    label => panic!("unexpected branch {label}"),
                };
            });
            assert!(operation.as_mut().poll(&mut cx).is_ready());
        }
        let batch: Vec<_> = events.by_ref().collect();
        assert!(batch.iter().any(|event| event.id() == tap::ENDPOINT_RECV));
        assert!(batch.iter().any(|event| {
            event.id() == tap::RESOLVER_AUDIT
                && event.causal_key() as u8
                    == match arm {
                        DecisionArm::Left => 0,
                        DecisionArm::Right => 1,
                    }
        }));
        for event in batch {
            if matches!(event.id(), tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION) {
                assert_eq!(event.causal_key() >> 8, 7);
            }
            let record: [u8; 16] = event.into();
            let decoded = TapEvent::from(record);
            let out = epf.run(decoded);
            assert!(out.emitted());
            assert_eq!(out.kind(), event.evidence().kind() as u32);
            assert_eq!(out.reason(), event.evidence().reason() as u32);
            assert_eq!(out.arg0(), event.arg0());
            assert_eq!(out.arg1(), event.arg1());
            assert_eq!(out.arg2(), event.evidence().input()[3]);
            assert_eq!(decoded.ts(), event.ts());
            observed.push(event);
        }
    }
    assert_eq!(
        observed
            .iter()
            .filter(|e| e.id() == tap::ENDPOINT_RECV)
            .count(),
        3
    );
    assert_eq!(
        observed
            .iter()
            .filter(|e| e.id() == tap::RESOLVER_AUDIT)
            .count(),
        3
    );
    assert!(
        observed
            .windows(2)
            .all(|pair| pair[0].ts() + 1 == pair[1].ts())
    );
}

struct PendingAudit<'a> {
    cancelled: &'a Cell<usize>,
}

impl Transport for PendingAudit<'_> {
    type Tx<'a>
        = ()
    where
        Self: 'a;
    type Rx<'a>
        = ()
    where
        Self: 'a;

    fn open(&self, _: PortOpen) -> ((), ()) {
        ((), ())
    }

    fn poll_send(
        &self,
        _: &mut (),
        _: Outgoing<'_>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        Poll::Pending
    }

    fn cancel_send(&self, _: &mut ()) {
        self.cancelled.set(self.cancelled.get() + 1);
    }

    fn poll_recv<'a>(
        &'a self,
        _: &'a mut (),
        _: &mut Context<'_>,
    ) -> Poll<Result<ReceivedFrame<'a>, TransportError>> {
        Poll::Pending
    }

    fn requeue(&self, _: &mut ()) -> Result<(), TransportError> {
        panic!("this transport has received no frame")
    }
}

#[test]
fn cancelled_resolved_send_keeps_its_decision_without_claiming_a_commit() {
    for right in [false, true] {
        let rows = Cell::new(Vec::new());
        let recorder = |event| {
            let mut captured = rows.take();
            captured.push(event);
            rows.set(captured);
        };
        let cancelled = Cell::new(0);
        let global =
            g::route(g::send::<7, 8, Msg<1, ()>>(), g::send::<7, 8, Msg<2, ()>>()).resolve::<77>();
        let program = project::<7>(&global);
        let mut slab = [0; 16384];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(
                &mut slab,
                PendingAudit {
                    cancelled: &cancelled,
                },
            )
            .unwrap();
        kit.observe(&recorder);
        kit.set_resolver(
            &program,
            ResolverRef::<77>::decision_state(&right, |right| {
                Ok(if *right {
                    DecisionArm::Right
                } else {
                    DecisionArm::Left
                })
            }),
        )
        .unwrap();
        let mut endpoint = kit.enter(SessionId::new(1), &program).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut sending = core::pin::pin!(async {
                if right {
                    endpoint.send::<Msg<2, ()>>(&()).await
                } else {
                    endpoint.send::<Msg<1, ()>>(&()).await
                }
            });
            assert!(matches!(sending.as_mut().poll(&mut cx), Poll::Pending));
        }
        assert_eq!(cancelled.get(), 1);
        let captured = rows.take();
        let checkpoint = kit.tap().checkpoint();
        assert_eq!(
            captured
                .iter()
                .filter(|row| row.id() == tap::RESOLVER_AUDIT)
                .count(),
            1
        );
        assert_eq!(
            captured
                .iter()
                .filter(|row| row.id() == tap::SEND_POLL)
                .count(),
            1
        );
        assert!(!captured.iter().any(|row| matches!(
            row.id(),
            tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ROUTE_ARM_SELECTION | tap::SCOPE_REENTRY
        )));
        let snapshot: Vec<_> = tap::projected(&program).collect();
        let checked = audit_capture(&snapshot, &captured, checkpoint);
        assert!(checked.is_ok(), "right={right}: {checked:?}; {captured:?}");
        let mut invalid = captured.clone();
        let decision = invalid
            .iter_mut()
            .find(|row| row.id() == tap::RESOLVER_AUDIT)
            .unwrap();
        let mut bytes: [u8; 16] = (*decision).into();
        bytes[7] ^= 1;
        *decision = bytes.into();
        let checked = audit_capture(&snapshot, &invalid, checkpoint);
        assert!(checked.is_err(), "right={right}: {checked:?}; {invalid:?}");
    }
}

#[test]
fn cancelled_offer_records_a_decision_without_consuming_the_source_operation() {
    for right in [false, true] {
        let rows = Cell::new(Vec::new());
        let recorder = |event| {
            let mut captured = rows.take();
            captured.push(event);
            rows.set(captured);
        };
        let global =
            g::route(g::send::<7, 7, Msg<1, ()>>(), g::send::<7, 7, Msg<2, ()>>()).resolve::<77>();
        let program = project::<7>(&global);
        let mut slab = [0; 16384];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init().rendezvous(&mut slab, LocalOnly).unwrap();
        kit.observe(&recorder);
        kit.set_resolver(
            &program,
            ResolverRef::<77>::decision_state(&right, |right| {
                Ok(if *right {
                    DecisionArm::Right
                } else {
                    DecisionArm::Left
                })
            }),
        )
        .unwrap();
        let mut endpoint = kit.enter(SessionId::new(1), &program).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut offering = core::pin::pin!(endpoint.offer());
            let Poll::Ready(Ok(branch)) = offering.as_mut().poll(&mut cx) else {
                panic!("the local preview is ready");
            };
            assert_eq!(branch.label(), if right { 2 } else { 1 });
            drop(branch);
        }
        let captured = rows.take();
        assert_eq!(
            captured
                .iter()
                .filter(|row| row.id() == tap::RESOLVER_AUDIT)
                .count(),
            1
        );
        assert!(!captured.iter().any(|row| matches!(
            row.id(),
            tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ROUTE_ARM_SELECTION | tap::SCOPE_REENTRY
        )));
        let snapshot: Vec<_> = tap::projected(&program).collect();
        let checked = audit_capture(&snapshot, &captured, kit.tap().checkpoint());
        assert!(checked.is_ok(), "right={right}: {checked:?}; {captured:?}");
        let operation = core::pin::pin!(async {
            if right {
                endpoint.send::<Msg<2, ()>>(&()).await
            } else {
                endpoint.send::<Msg<1, ()>>(&()).await
            }
        });
        assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
        let mut completed = captured.clone();
        completed.extend(rows.take());
        assert!(audit_capture(&snapshot, &completed, kit.tap().checkpoint()).is_ok());
        // Replaying an old callback after the finite operation completed is
        // not a fresh readiness query. There is no enclosing roll here.
        let audit = captured
            .iter()
            .find(|row| row.id() == tap::RESOLVER_AUDIT)
            .unwrap();
        let mut bytes: [u8; 16] = (*audit).into();
        bytes[..4].copy_from_slice(&(completed.len() as u32).to_be_bytes());
        completed.push(bytes.into());
        assert!(audit_capture(&snapshot, &completed, Some(completed.len() as u32)).is_err());
    }
}

#[test]
fn cancelled_resolved_send_can_retry_the_other_arm_before_any_commit() {
    for first_right in [false, true] {
        let rows = Cell::new(Vec::new());
        let recorder = |event| {
            let mut captured = rows.take();
            captured.push(event);
            rows.set(captured);
        };
        let right = Cell::new(first_right);
        let cancelled = Cell::new(0);
        let global =
            g::route(g::send::<7, 8, Msg<1, ()>>(), g::send::<7, 8, Msg<2, ()>>()).resolve::<77>();
        let program = project::<7>(&global);
        let mut slab = [0; 16384];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(
                &mut slab,
                PendingAudit {
                    cancelled: &cancelled,
                },
            )
            .unwrap();
        kit.observe(&recorder);
        kit.set_resolver(
            &program,
            ResolverRef::<77>::decision_state(&right, |right| {
                Ok(if right.get() {
                    DecisionArm::Right
                } else {
                    DecisionArm::Left
                })
            }),
        )
        .unwrap();
        let mut endpoint = kit.enter(SessionId::new(1), &program).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        for arm in [first_right, !first_right] {
            right.set(arm);
            let mut sending = core::pin::pin!(async {
                if arm {
                    endpoint.send::<Msg<2, ()>>(&()).await
                } else {
                    endpoint.send::<Msg<1, ()>>(&()).await
                }
            });
            let result = sending.as_mut().poll(&mut cx);
            assert!(
                matches!(result, Poll::Pending),
                "first_right={first_right} arm={arm}: {result:?}"
            );
        }
        assert_eq!(cancelled.get(), 2);
        let captured = rows.take();
        let decisions: Vec<_> = captured
            .iter()
            .filter(|row| row.id() == tap::RESOLVER_AUDIT)
            .map(|row| row.causal_key() as u8)
            .collect();
        assert_eq!(decisions, [u8::from(first_right), u8::from(!first_right)]);
        assert_eq!(
            captured
                .iter()
                .filter(|row| row.id() == tap::SEND_POLL)
                .count(),
            2
        );
        assert!(!captured.iter().any(|row| matches!(
            row.id(),
            tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ROUTE_ARM_SELECTION | tap::SCOPE_REENTRY
        )));
        let snapshot: Vec<_> = tap::projected(&program).collect();
        let checked = audit_capture(&snapshot, &captured, kit.tap().checkpoint());
        assert!(
            checked.is_ok(),
            "first_right={first_right}: {checked:?}; {captured:?}"
        );
        // Changing either real callback result must not be repaired by choosing
        // another path for the corresponding, already observed poll.
        for decision in [0, 1] {
            let mut invalid = captured.clone();
            let audit = invalid
                .iter_mut()
                .filter(|row| row.id() == tap::RESOLVER_AUDIT)
                .nth(decision)
                .unwrap();
            let mut bytes: [u8; 16] = (*audit).into();
            bytes[7] ^= 1;
            *audit = bytes.into();
            assert!(audit_capture(&snapshot, &invalid, kit.tap().checkpoint()).is_err());
        }
        // A synthetic mutation commits the first attempt before the opposite
        // query. That prefix fixes the branch; it is not another cancelled run.
        let first_poll = captured
            .iter()
            .find(|row| row.id() == tap::SEND_POLL)
            .unwrap();
        let mut bytes: [u8; 16] = (*first_poll).into();
        bytes[4..6].copy_from_slice(&tap::ENDPOINT_SEND.to_be_bytes());
        bytes[7] = 1;
        bytes[12..].copy_from_slice(&(7 << 24 | u32::from(first_right)).to_be_bytes());
        let mut committed = captured.clone();
        let after_poll = committed
            .iter()
            .position(|row| row.id() == tap::SEND_POLL)
            .unwrap()
            + 1;
        committed.insert(after_poll, bytes.into());
        for (ordinal, record) in committed.iter_mut().enumerate() {
            let mut bytes: [u8; 16] = (*record).into();
            bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
            *record = bytes.into();
        }
        assert!(audit_capture(&snapshot, &committed, Some(committed.len() as u32)).is_err());
        // Even without the opposite poll, the completed prefix precludes a
        // resolver invocation attributed to the other, unselected arm.
        committed.pop();
        assert!(audit_capture(&snapshot, &committed, Some(committed.len() as u32)).is_err());
    }
}
