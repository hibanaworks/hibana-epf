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
use hibana_epf::{Epf, EpfStorage};

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
    let mut storage = EpfStorage::<0, 64, 0, 8>::new();
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
