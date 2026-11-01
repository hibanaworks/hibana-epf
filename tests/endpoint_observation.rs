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
    let global = g::route(g::send::<0, 0, Left>(), g::send::<0, 0, Right>())
        .resolve::<17>()
        .roll();
    let program = project::<0>(&global);
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
