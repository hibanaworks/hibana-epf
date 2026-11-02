use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use hibana::{
    Endpoint,
    g::{self, Msg},
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::project,
        resolver::{DecisionArm, ResolverRef},
        tap::{self, TapEvent},
        transport::{
            EndpointBinding, FrameHeader, Outgoing, PortOpen, ReceivedFrame, Transport,
            TransportError,
        },
        wire::Payload,
    },
};
use hibana_epf::{
    Capture, CustodyError, DeliveryError, Epf, EpfStorage, HistoryError, Protocol, RecordId,
};

#[derive(Clone, Copy)]
struct Frame {
    header: FrameHeader,
    bytes: [u8; 3], // unit payload or the three-byte owned Endpoint envelope
    len: u8,
}

// A single physical frame inbox. Normally a send exposes its frame on the
// first poll and reports acceptance on the next. A backpressured receiver's
// frame is exposed only by the second poll. No payload pointer survives a poll.
struct DelayedPublication {
    inbox: Cell<Result<Option<Frame>, TransportError>>,
    reader: Cell<Option<Waker>>,
    resource: Option<EndpointBinding>,
    backpressured_receiver: Option<u8>,
}

impl Transport for DelayedPublication {
    type Tx<'a> = (PortOpen, Option<FrameHeader>);
    type Rx<'a> = (PortOpen, Option<Frame>);

    fn initial_endpoint_binding(&self, _: SessionId, role: u8) -> Option<&EndpointBinding> {
        if role == 3 {
            self.resource.as_ref()
        } else {
            None
        }
    }

    fn open(&self, port: PortOpen) -> (Self::Tx<'_>, Self::Rx<'_>) {
        ((port, None), (port, None))
    }

    fn poll_send(
        &self,
        tx: &mut Self::Tx<'_>,
        outgoing: Outgoing<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        assert_eq!(outgoing.lane(), tx.0.lane());
        let session = tx.0.session_id().raw().to_be_bytes();
        let label = outgoing.frame_label().raw().to_be_bytes();
        let header = FrameHeader::from_bytes([
            session[0],
            session[1],
            session[2],
            session[3],
            tx.0.lane(),
            tx.0.local_role(),
            outgoing.target_role(),
            label[0],
            label[1],
        ]);
        let backpressured = self.backpressured_receiver == Some(outgoing.target_role());
        if let Some(accepted) = tx.1.take() {
            assert_eq!(accepted, header);
            if !backpressured {
                return Poll::Ready(Ok(()));
            }
        } else if backpressured {
            tx.1 = Some(header);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match self.inbox.get() {
            Ok(None) => {
                let bytes = outgoing.payload().as_bytes();
                let mut copied = [0; 3];
                copied[..bytes.len()].copy_from_slice(bytes);
                self.inbox.set(Ok(Some(Frame {
                    header,
                    bytes: copied,
                    len: bytes.len() as u8,
                })));
                if let Some(reader) = self.reader.take() {
                    reader.wake();
                }
                if backpressured {
                    Poll::Ready(Ok(()))
                } else {
                    tx.1 = Some(header);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Ok(Some(_)) => Poll::Ready(Err(TransportError::Capacity)),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn cancel_send(&self, tx: &mut Self::Tx<'_>) {
        if tx.1.take().is_some() {
            // A possibly delivered frame cannot be reused after cancellation.
            self.inbox.set(Err(TransportError::Offline));
            if let Some(reader) = self.reader.take() {
                reader.wake();
            }
        }
    }

    fn poll_recv<'a>(
        &'a self,
        rx: &'a mut Self::Rx<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReceivedFrame<'a>, TransportError>> {
        match self.inbox.get() {
            Ok(Some(frame)) => {
                assert_eq!(frame.header.bytes()[6], rx.0.local_role());
                self.inbox.set(Ok(None));
                rx.1 = Some(frame);
                let frame = rx.1.as_ref().unwrap();
                Poll::Ready(Ok(ReceivedFrame::framed(
                    frame.header,
                    Payload::new(&frame.bytes[..usize::from(frame.len)]),
                )))
            }
            Ok(None) => {
                self.reader.set(Some(cx.waker().clone()));
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn requeue(&self, rx: &mut Self::Rx<'_>) -> Result<(), TransportError> {
        let frame = rx.1.take().expect("requeue requires a received frame");
        match self.inbox.get() {
            Ok(None) => {
                self.inbox.set(Ok(Some(frame)));
                if let Some(reader) = self.reader.take() {
                    reader.wake();
                }
                Ok(())
            }
            Ok(Some(_)) => Err(TransportError::Capacity),
            Err(error) => Err(error),
        }
    }
}

// These handles reach one physical test inbox and the same sole binding.
// Each runtime still owns its own ports, progress, tap ring and checkpoint.
impl Transport for &DelayedPublication {
    type Tx<'a>
        = <DelayedPublication as Transport>::Tx<'a>
    where
        Self: 'a;
    type Rx<'a>
        = <DelayedPublication as Transport>::Rx<'a>
    where
        Self: 'a;

    fn initial_endpoint_binding(&self, sid: SessionId, role: u8) -> Option<&EndpointBinding> {
        (**self).initial_endpoint_binding(sid, role)
    }

    fn open(&self, port: PortOpen) -> (Self::Tx<'_>, Self::Rx<'_>) {
        (**self).open(port)
    }

    fn poll_send(
        &self,
        tx: &mut (PortOpen, Option<FrameHeader>),
        outgoing: Outgoing<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        (**self).poll_send(tx, outgoing, cx)
    }

    fn cancel_send(&self, tx: &mut (PortOpen, Option<FrameHeader>)) {
        (**self).cancel_send(tx);
    }

    fn poll_recv<'a>(
        &'a self,
        rx: &'a mut (PortOpen, Option<Frame>),
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReceivedFrame<'a>, TransportError>> {
        (**self).poll_recv(rx, cx)
    }

    fn requeue(&self, rx: &mut (PortOpen, Option<Frame>)) -> Result<(), TransportError> {
        (**self).requeue(rx)
    }
}

#[test]
fn separate_producer_captures_match_real_loans_and_rolled_receipts_before_publication() {
    type Loan = Msg<7, Endpoint<'static, 3>>;
    type Use = Msg<8, ()>;
    let global = g::seq(
        g::send::<0, 1, Loan>(),
        g::seq(g::send::<3, 2, Use>().roll(), g::send::<1, 0, Loan>()),
    );
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    let p2 = project::<2>(&global);
    let p3 = project::<3>(&global);
    let transport = DelayedPublication {
        inbox: Cell::new(Ok(None)),
        reader: Cell::new(None),
        // SAFETY: all three runtimes reach this sole fresh physical resource.
        resource: Some(unsafe { EndpointBinding::new() }),
        backpressured_receiver: None,
    };
    let mut slabs = [[0; 32768]; 3];
    let [slab0, slab1, slab2] = &mut slabs;
    let mut storage0 = SessionKitStorage::uninit();
    let mut storage1 = SessionKitStorage::uninit();
    let mut storage2 = SessionKitStorage::uninit();
    let kit0 = storage0.init().rendezvous(slab0, &transport).unwrap();
    let kit1 = storage1.init().rendezvous(slab1, &transport).unwrap();
    let kit2 = storage2.init().rendezvous(slab2, &transport).unwrap();
    let sid = SessionId::new(110);
    let mut owner = kit0.enter(sid, &p0).unwrap();
    let resource = kit0.enter(sid, &p3).unwrap();
    let mut worker = kit1.enter(sid, &p1).unwrap();
    let mut service = kit2.enter(sid, &p2).unwrap();
    let mut tap0 = kit0.tap();
    let mut tap1 = kit1.tap();
    let mut tap2 = kit2.tap();
    let mut order = Vec::new();
    let mut records0: Vec<_> = tap0
        .by_ref()
        .inspect(|record| {
            order.push(RecordId {
                producer: 0,
                ordinal: record.ts() as usize,
            })
        })
        .collect();
    let mut records1: Vec<_> = tap1
        .by_ref()
        .inspect(|record| {
            order.push(RecordId {
                producer: 1,
                ordinal: record.ts() as usize,
            })
        })
        .collect();
    let mut records2: Vec<_> = tap2
        .by_ref()
        .inspect(|record| {
            order.push(RecordId {
                producer: 2,
                ordinal: record.ts() as usize,
            })
        })
        .collect();
    let mut cx = Context::from_waker(Waker::noop());
    let resource = {
        let mut lending = core::pin::pin!(owner.send::<Loan>(resource));
        assert!(lending.as_mut().poll(&mut cx).is_pending());
        let receiving = core::pin::pin!(worker.recv::<Loan>());
        let Poll::Ready(Ok(mut resource)) = receiving.poll(&mut cx) else {
            panic!("the separate runtime must receive the actual resource")
        };
        records0.extend(tap0.by_ref().inspect(|record| {
            order.push(RecordId {
                producer: 0,
                ordinal: record.ts() as usize,
            })
        }));
        records1.extend(tap1.by_ref().inspect(|record| {
            order.push(RecordId {
                producer: 1,
                ordinal: record.ts() as usize,
            })
        }));
        for _ in 0..2 {
            let mut sending = core::pin::pin!(resource.send::<Use>(&()));
            assert!(sending.as_mut().poll(&mut cx).is_pending());
            let receiving = core::pin::pin!(service.recv::<Use>());
            assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
            records1.extend(tap1.by_ref().inspect(|record| {
                order.push(RecordId {
                    producer: 1,
                    ordinal: record.ts() as usize,
                })
            }));
            records2.extend(tap2.by_ref().inspect(|record| {
                order.push(RecordId {
                    producer: 2,
                    ordinal: record.ts() as usize,
                })
            }));
            // The loan's publication is still absent on its other producer.
            assert!(!records0.iter().any(
                |record| record.id() == tap::ENDPOINT_SESSION && record.causal_key() as u8 == 1
            ));
            assert!(matches!(
                sending.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
            records1.extend(tap1.by_ref().inspect(|record| {
                order.push(RecordId {
                    producer: 1,
                    ordinal: record.ts() as usize,
                })
            }));
        }
        assert!(matches!(
            lending.as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        records0.extend(tap0.by_ref().inspect(|record| {
            order.push(RecordId {
                producer: 0,
                ordinal: record.ts() as usize,
            })
        }));
        resource
    };
    {
        let mut returning = core::pin::pin!(worker.send::<Loan>(resource));
        assert!(returning.as_mut().poll(&mut cx).is_pending());
        records1.extend(tap1.by_ref().inspect(|record| {
            order.push(RecordId {
                producer: 1,
                ordinal: record.ts() as usize,
            })
        }));
        let receiving = core::pin::pin!(owner.recv::<Loan>());
        let Poll::Ready(Ok(resource)) = receiving.poll(&mut cx) else {
            panic!("the original runtime must receive the returned continuation")
        };
        records0.extend(tap0.by_ref().inspect(|record| {
            order.push(RecordId {
                producer: 0,
                ordinal: record.ts() as usize,
            })
        }));
        assert!(matches!(
            returning.as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        drop(resource);
    }
    records0.extend(tap0.by_ref().inspect(|record| {
        order.push(RecordId {
            producer: 0,
            ordinal: record.ts() as usize,
        })
    }));
    records1.extend(tap1.by_ref().inspect(|record| {
        order.push(RecordId {
            producer: 1,
            ordinal: record.ts() as usize,
        })
    }));
    records2.extend(tap2.by_ref().inspect(|record| {
        order.push(RecordId {
            producer: 2,
            ordinal: record.ts() as usize,
        })
    }));
    let originals = [records0.clone(), records1.clone(), records2.clone()];
    let captures = [
        Capture::new(&records0, tap0.checkpoint()).unwrap(),
        Capture::new(&records1, tap1.checkpoint()).unwrap(),
        Capture::new(&records2, tap2.checkpoint()).unwrap(),
    ];
    let snapshot: Vec<_> = tap::projected(&p0).collect();
    let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
    let steps = [
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Once(1),
        hibana_epf::Unfold::More([2, 1]),
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Sequence([3, 4]),
        hibana_epf::Unfold::Sequence([0, 5]),
    ];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
    let mut actors = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut actors).unwrap();
    for permutation in [[0, 1, 2], [2, 0, 1], [1, 2, 0]] {
        let inputs = permutation.map(|index| captures[index]);
        let witnessed: Vec<_> = order
            .iter()
            .map(|id| RecordId {
                producer: permutation
                    .iter()
                    .position(|&original| original == id.producer)
                    .unwrap(),
                ordinal: id.ordinal,
            })
            .collect();
        workspace.resize(protocol.custody_workspace_len(&inputs), usize::MAX);
        protocol
            .check_custody(&inputs, &witnessed, &mut workspace)
            .unwrap();
        protocol
            .check_routes(&inputs, &witnessed, &mut workspace)
            .unwrap();
        workspace.resize(protocol.delivery_workspace_len(&inputs), usize::MAX);

        let deliveries: Vec<_> = protocol
            .deliveries(&inputs, &mut workspace)
            .unwrap()
            .collect();
        assert_eq!(deliveries.len(), 4);
        let mut sends = 0;
        let mut receipts = 0;
        let occurrences: Vec<_> = witnessed
            .iter()
            .map(|id| {
                let record = inputs[id.producer].records()[id.ordinal];
                if record.id() == tap::SCOPE_REENTRY {
                    return Some(2);
                }
                if !matches!(
                    record.id(),
                    tap::SEND_POLL
                        | tap::ENDPOINT_SEND
                        | tap::ENDPOINT_RECV
                        | tap::ENDPOINT_SESSION
                ) {
                    return None;
                }
                match record.arg1() as u16 {
                    0 => Some(0),
                    2 => Some(3),
                    1 if record.id() == tap::ENDPOINT_RECV => {
                        receipts += 1;
                        Some(receipts)
                    }
                    1 => {
                        let event = 1 + sends;
                        if record.id() == tap::ENDPOINT_SEND {
                            sends += 1;
                        }
                        Some(event)
                    }
                    _ => unreachable!(),
                }
            })
            .collect();
        let mut acceptances: Vec<_> = deliveries
            .iter()
            .map(|delivery| {
                let before = witnessed
                    .iter()
                    .position(|&id| id == delivery.first_poll)
                    .unwrap()
                    + 1;
                hibana_epf::Acceptance {
                    first_poll: delivery.first_poll,
                    before,
                }
            })
            .collect();
        acceptances.sort_by_key(|acceptance| acceptance.before);
        let witness = hibana_epf::ExecutionWitness {
            session: 110,
            order: &witnessed,
            occurrences: &occurrences,
            acceptances: &acceptances,
        };
        workspace.resize(path.execution_workspace_len(&inputs, &witness).unwrap(), 0);
        path.check_execution(&inputs, &witness, &mut workspace)
            .unwrap();
        let mut inferred = vec![None; witnessed.len()];
        let mut inferred_acceptances = vec![
            hibana_epf::Acceptance {
                first_poll: RecordId {
                    producer: 0,
                    ordinal: 0
                },
                before: 0,
            };
            witnessed.len()
        ];
        workspace.resize(path.interpretation_workspace_len(&inputs).unwrap(), 0);
        let mut inferred_order = vec![
            RecordId {
                producer: usize::MAX,
                ordinal: usize::MAX,
            };
            witnessed.len()
        ];
        let automatic = path
            .interpret(
                &inputs,
                hibana_epf::ExecutionStorage {
                    session: 110,
                    order: &mut inferred_order,
                    occurrences: &mut inferred,
                    acceptances: &mut inferred_acceptances,
                },
                &mut workspace,
            )
            .unwrap();
        for (position, id) in automatic.order.iter().enumerate() {
            let expected = witnessed
                .iter()
                .position(|candidate| candidate == id)
                .unwrap();
            assert_eq!(automatic.occurrences[position], occurrences[expected]);
        }
        assert_eq!(automatic.acceptances.len(), 4);
        path.check_execution(&inputs, &automatic, &mut workspace)
            .unwrap();
        // Exercise the public constructor from only the immutable compiled
        // snapshot and the three actual runtime capture prefixes. Neither the
        // hand-written unfolding above nor its record order is supplied.
        let mut generated = [hibana_epf::Unfold::Source; 7];
        let mut selected = vec![
            hibana_epf::RouteChoice {
                span: [0, 0],
                right: false
            };
            protocol.audit_choice_capacity(generated.len()).unwrap()
        ];
        workspace.resize(
            protocol
                .audit_workspace_len(&inputs, generated.len())
                .unwrap(),
            0,
        );
        let audit = protocol
            .audit(
                &inputs,
                hibana_epf::AuditStorage {
                    unfolding: &mut generated,
                    choices: &mut selected,
                    execution: hibana_epf::ExecutionStorage {
                        session: 110,
                        order: &mut inferred_order,
                        occurrences: &mut inferred,
                        acceptances: &mut inferred_acceptances,
                    },
                },
                &mut workspace,
            )
            .unwrap();
        assert_eq!(audit.execution().acceptances.len(), 4);
        for (position, id) in audit.execution().order.iter().enumerate() {
            let expected = witnessed
                .iter()
                .position(|candidate| candidate == id)
                .unwrap();
            assert_eq!(
                audit.execution().occurrences[position],
                occurrences[expected]
            );
        }
        let aliased: Vec<_> = occurrences
            .iter()
            .map(|event| if *event == Some(2) { Some(1) } else { *event })
            .collect();
        let alias_witness = hibana_epf::ExecutionWitness {
            occurrences: &aliased,
            ..witness
        };
        assert!(
            path.check_execution(&inputs, &alias_witness, &mut workspace)
                .is_err()
        );
        for delivery in deliveries {
            let sending =
                inputs[delivery.first_poll.producer].records()[delivery.first_poll.ordinal];
            let received = inputs[delivery.receive.producer].records()[delivery.receive.ordinal];
            assert_eq!(sending.id(), tap::SEND_POLL);
            assert_eq!(sending.arg1() as u16, received.arg1() as u16);
            assert_ne!(delivery.first_poll.producer, delivery.receive.producer);
            let event = sending.arg1() as u16;
            let expected = if event == 0 {
                (0, 1)
            } else if event == 1 {
                (1, 2)
            } else {
                (1, 0)
            };
            assert_eq!(
                (
                    permutation[delivery.first_poll.producer],
                    permutation[delivery.receive.producer]
                ),
                expected
            );
        }
    }
    assert_eq!(
        originals,
        [records0.clone(), records1.clone(), records2.clone()]
    );
    let inputs = [captures[2]];
    workspace.resize(protocol.delivery_workspace_len(&inputs), 0);
    assert!(matches!(
        protocol.deliveries(&inputs, &mut workspace),
        Err(DeliveryError::Unmatched { .. })
    ));
}

#[test]
fn a_real_receive_can_commit_before_sender_publication_is_observed() {
    type Message = Msg<7, ()>;
    let global = g::send::<0, 1, Message>();
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage
        .init()
        .rendezvous(
            &mut slab,
            DelayedPublication {
                inbox: Cell::new(Ok(None)),
                reader: Cell::new(None),
                backpressured_receiver: None,
                resource: None,
            },
        )
        .unwrap();
    let mut sender = kit.enter(SessionId::new(93), &p0).unwrap();
    let mut receiver = kit.enter(SessionId::new(93), &p1).unwrap();
    let mut records = kit.tap();
    let mut captured: Vec<TapEvent> = records.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    let mut sending = core::pin::pin!(sender.send::<Message>(&()));
    assert!(sending.as_mut().poll(&mut cx).is_pending());
    captured.extend(records.by_ref());
    let first_poll = *captured
        .iter()
        .find(|record| record.id() == tap::SEND_POLL)
        .expect("a checked send is observed before exposing its frame");
    assert_eq!(first_poll.causal_key(), 0); // actor 0, logical view 0
    assert_eq!(first_poll.arg0(), 93);
    assert_eq!(first_poll.arg1(), 0xffff_0000); // no reset, source event 0
    assert_eq!(
        first_poll.evidence().input(),
        [93, 0xffff_0000, first_poll.ts(), 0]
    );
    assert!(
        !captured
            .iter()
            .any(|record| record.id() == tap::ENDPOINT_SEND)
    );
    {
        let receiving = core::pin::pin!(receiver.recv::<Message>());
        assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
    }
    captured.extend(records.by_ref());
    let receipt = captured
        .iter()
        .position(|record| record.id() == tap::ENDPOINT_RECV)
        .unwrap();
    assert!(
        !captured
            .iter()
            .any(|record| record.id() == tap::ENDPOINT_SEND)
    );
    assert!(matches!(
        sending.as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    captured.extend(records.by_ref());
    let publication = captured
        .iter()
        .position(|record| record.id() == tap::ENDPOINT_SEND)
        .unwrap();
    assert!(receipt < publication);
    let polls: Vec<_> = captured
        .iter()
        .filter(|record| record.id() == tap::SEND_POLL)
        .collect();
    assert_eq!(polls.len(), 2);
    assert!(first_poll.ts() < captured[receipt].ts());
    assert!(captured[receipt].ts() < polls[1].ts());
    assert!(polls[1].ts() < captured[publication].ts());
    assert_eq!(polls[0].arg1(), polls[1].arg1());
    let received = captured[receipt];
    let sent = captured[publication];
    let source = tap::projected(&p0)
        .find(|record| record.id() == tap::PROJECTED_SOURCE)
        .unwrap();
    assert_eq!(source.ts(), 0);
    assert_eq!(source.arg0() >> 16, 1); // logical 0 -> 1
    assert_eq!(source.arg0() as u8, 7);
    assert_eq!(source.causal_key(), 0); // ordinary user wire message
    assert_eq!(source.arg1(), 0); // canonical unit schema
    assert_eq!(received.arg0(), sent.arg0());
    for (record, actor, view, direction) in [(sent, 0, 0, 1), (received, 1, 1, 2)] {
        assert_eq!(record.causal_key() >> 8, actor);
        assert_eq!(record.causal_key() as u8, direction);
        assert_eq!(record.arg1() >> 24, view);
        assert_eq!(record.arg1() & 0xffff, source.ts());
    }
    let mut epf_storage = EpfStorage::<0, 128>::new();
    let epf = Epf::new(&mut epf_storage);
    for record in &captured {
        let decoded = TapEvent::from(<[u8; 16]>::from(*record));
        let out = epf.run(decoded);
        assert!(out.emitted());
        assert_eq!(out.arg0(), record.arg0());
        assert_eq!(out.arg1(), record.arg1());
        assert_eq!(decoded.ts(), record.ts());
    }
    let mut image = [0; 128];
    let len = hibana_epf::ImageSpec::ObserveMatch {
        input: 1,
        value: 0xffff_0000,
        kind: u32::from(tap::SEND_POLL),
        reason: 0,
    }
    .write(&mut image)
    .unwrap();
    epf.load(&image[..len]).unwrap();
    for record in &captured {
        let out = epf.run(*record);
        assert_eq!(out.emitted(), record.id() == tap::SEND_POLL);
        if out.emitted() {
            assert_eq!(out.arg0(), 93);
            assert_eq!(out.arg1(), 0xffff_0000);
            assert_eq!(out.arg2(), 0); // actor 0, logical view 0
        }
    }
    hibana_epf::Capture::new(&captured, records.checkpoint()).unwrap();
    let snapshot: Vec<_> = tap::projected(&p0).collect();
    let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
    let capture = Capture::new(&captured, records.checkpoint()).unwrap();
    workspace.resize(protocol.send_call_workspace_len(capture), 0);
    let calls: Vec<_> = protocol
        .send_calls(capture, &mut workspace)
        .unwrap()
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].first_poll(), first_poll);
    assert_eq!(calls[0].polls().count(), 2);
    assert_eq!(calls[0].publication(), Some(sent));
    assert!(
        captured
            .windows(2)
            .all(|records| records[0].ts() + 1 == records[1].ts())
    );
}

#[test]
fn source_order_is_checked_before_a_pending_transport_send_can_expose_its_frame() {
    type Gate = Msg<6, ()>;
    type Message = Msg<7, ()>;
    let global = g::seq(g::send::<0, 0, Gate>(), g::send::<0, 1, Message>());
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    for early in [true, false] {
        let mut slab = [0; 8192];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(
                &mut slab,
                DelayedPublication {
                    inbox: Cell::new(Ok(None)),
                    reader: Cell::new(None),
                    backpressured_receiver: None,
                    resource: None,
                },
            )
            .unwrap();
        let mut sender = kit.enter(SessionId::new(98), &p0).unwrap();
        let mut receiver = kit.enter(SessionId::new(98), &p1).unwrap();
        let mut records = kit.tap();
        let mut captured: Vec<_> = records.by_ref().collect();
        let mut cx = Context::from_waker(Waker::noop());
        if early {
            let operation = core::pin::pin!(sender.send::<Message>(&()));
            let Poll::Ready(Err(error)) = operation.poll(&mut cx) else {
                panic!("an early send must fail before transport admission")
            };
            assert!(format!("{error:?}").contains("OutOfOrder"));
            let operation = core::pin::pin!(receiver.recv::<Message>());
            assert!(!matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
            captured.extend(records.by_ref());
            assert!(!captured.iter().any(|record| matches!(
                record.id(),
                tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::TRANSPORT_FRAME | tap::SEND_POLL
            )));
        } else {
            {
                let operation = core::pin::pin!(sender.send::<Gate>(&()));
                assert!(matches!(operation.poll(&mut cx), Poll::Ready(Ok(()))));
            }
            let mut sending = core::pin::pin!(sender.send::<Message>(&()));
            assert!(sending.as_mut().poll(&mut cx).is_pending());
            captured.extend(records.by_ref());
            let gate = captured
                .iter()
                .find(|record| record.id() == tap::ENDPOINT_SEND)
                .unwrap();
            let poll = captured
                .iter()
                .find(|record| record.id() == tap::SEND_POLL)
                .unwrap();
            assert!(gate.ts() < poll.ts());
            assert_eq!(gate.arg1() & 0xffff, 0);
            assert_eq!(poll.arg1(), 0xffff_0001);
            assert!(!captured.iter().any(|record| {
                record.id() == tap::ENDPOINT_SEND && record.arg1() & 0xffff == 1
            }));
            {
                let receiving = core::pin::pin!(receiver.recv::<Message>());
                assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
            }
            assert!(matches!(
                sending.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
            captured.extend(records.by_ref());
            let commits: Vec<_> = captured
                .iter()
                .filter(|record| matches!(record.id(), tap::ENDPOINT_SEND | tap::ENDPOINT_RECV))
                .map(|record| (record.arg1() & 0xffff, record.causal_key() as u8))
                .collect();
            assert_eq!(commits, [(0, 1), (1, 2), (1, 1)]);
        }
        hibana_epf::Capture::new(&captured, records.checkpoint()).unwrap();
        let snapshot: Vec<_> = tap::projected(&p0).collect();
        let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
        let capture = Capture::new(&captured, records.checkpoint()).unwrap();
        workspace.resize(protocol.send_call_workspace_len(capture), 0);
        let calls: Vec<_> = protocol
            .send_calls(capture, &mut workspace)
            .unwrap()
            .collect();
        assert_eq!(calls.len(), usize::from(!early));
        if !early {
            assert_eq!(calls[0].polls().count(), 2);
            assert!(calls[0].publication().is_some());
            let first_poll = calls[0].first_poll().ts() as usize;
            drop(calls);
            let steps = [
                hibana_epf::Unfold::Source,
                hibana_epf::Unfold::Source,
                hibana_epf::Unfold::Sequence([0, 1]),
            ];
            let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
            let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
            let mut actors = vec![0; unfolded.path_workspace_len().unwrap()];
            let path = unfolded.select(&[], &mut actors).unwrap();
            let order: Vec<_> = (0..captured.len())
                .map(|ordinal| RecordId {
                    producer: 0,
                    ordinal,
                })
                .collect();
            let occurrences: Vec<_> = captured
                .iter()
                .map(|record| {
                    matches!(
                        record.id(),
                        tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV
                    )
                    .then_some(usize::from(record.arg1() as u16))
                })
                .collect();
            let acceptances = [hibana_epf::Acceptance {
                first_poll: order[first_poll],
                before: first_poll + 1,
            }];
            let witness = hibana_epf::ExecutionWitness {
                session: 98,
                order: &order,
                occurrences: &occurrences,
                acceptances: &acceptances,
            };
            workspace.resize(
                path.execution_workspace_len(&[capture], &witness).unwrap(),
                0,
            );
            path.check_execution(&[capture], &witness, &mut workspace)
                .unwrap();
            let mut inferred = vec![None; order.len()];
            let mut inferred_acceptances = vec![
                hibana_epf::Acceptance {
                    first_poll: RecordId {
                        producer: 0,
                        ordinal: 0
                    },
                    before: 0,
                };
                order.len()
            ];
            workspace.resize(path.interpretation_workspace_len(&[capture]).unwrap(), 0);
            let mut inferred_order = order.clone();
            let automatic = path
                .interpret(
                    &[capture],
                    hibana_epf::ExecutionStorage {
                        session: 98,
                        order: &mut inferred_order,
                        occurrences: &mut inferred,
                        acceptances: &mut inferred_acceptances,
                    },
                    &mut workspace,
                )
                .unwrap();
            assert_eq!(automatic.occurrences, occurrences);
            assert!(matches!(
                path.interpret(
                    &[capture],
                    hibana_epf::ExecutionStorage {
                        session: 98,
                        order: &mut inferred_order,
                        occurrences: &mut inferred,
                        acceptances: &mut inferred_acceptances,
                    },
                    &mut []
                ),
                Err(hibana_epf::InterpretationError::Workspace { .. })
            ));
            assert!(matches!(
                path.interpret(
                    &[capture],
                    hibana_epf::ExecutionStorage {
                        session: 98,
                        order: &mut inferred_order,
                        occurrences: &mut inferred[..order.len() - 1],
                        acceptances: &mut inferred_acceptances,
                    },
                    &mut workspace
                ),
                Err(hibana_epf::InterpretationError::Occurrences { .. })
            ));
            assert!(matches!(
                path.interpret(
                    &[capture],
                    hibana_epf::ExecutionStorage {
                        session: 98,
                        order: &mut inferred_order,
                        occurrences: &mut inferred,
                        acceptances: &mut [],
                    },
                    &mut workspace
                ),
                Err(hibana_epf::InterpretationError::Acceptances { required: 1, .. })
            ));
            assert!(matches!(
                path.check_execution(&[capture], &witness, &mut workspace[..1]),
                Err(hibana_epf::ExecutionError::Workspace { .. })
            ));
            let short = hibana_epf::ExecutionWitness {
                occurrences: &occurrences[..occurrences.len() - 1],
                ..witness
            };
            assert!(matches!(
                path.check_execution(&[capture], &short, &mut workspace),
                Err(hibana_epf::ExecutionError::Length { .. })
            ));
            for acceptance in [
                hibana_epf::Acceptance {
                    first_poll: order[first_poll],
                    before: first_poll,
                },
                hibana_epf::Acceptance {
                    first_poll: RecordId {
                        producer: usize::MAX,
                        ordinal: 0,
                    },
                    before: first_poll + 1,
                },
            ] {
                let bad = [acceptance];
                let invalid = hibana_epf::ExecutionWitness {
                    acceptances: &bad,
                    ..witness
                };
                assert!(matches!(
                    path.check_execution(&[capture], &invalid, &mut workspace),
                    Err(hibana_epf::ExecutionError::Acceptance { index: 0 })
                ));
            }
            let absent = hibana_epf::ExecutionWitness {
                acceptances: &[],
                ..witness
            };
            assert!(matches!(
                path.check_execution(&[capture], &absent, &mut workspace),
                Err(hibana_epf::ExecutionError::Source {
                    error: hibana_epf::WordError::Predecessor {
                        prior: hibana_epf::SourcePoint::Accepted(1),
                        ..
                    },
                    ..
                })
            ));

            // Preserve every successful Endpoint operation, but move only the
            // first transport poll before its local source predecessor.
            let gate = captured
                .iter()
                .position(|record| record.id() == tap::ENDPOINT_SEND && record.arg1() as u16 == 0)
                .unwrap();
            let mut changed = captured.clone();
            let poll = changed.remove(first_poll);
            changed.insert(gate, poll);
            for (ordinal, record) in changed.iter_mut().enumerate() {
                let mut bytes: [u8; 16] = (*record).into();
                bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
                *record = bytes.into();
            }
            let invalid = Capture::new(&changed, records.checkpoint()).unwrap();
            protocol
                .check_routes(&[invalid], &order, &mut workspace)
                .unwrap();
            let changed_occurrences: Vec<_> = changed
                .iter()
                .map(|record| {
                    matches!(
                        record.id(),
                        tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV
                    )
                    .then_some(usize::from(record.arg1() as u16))
                })
                .collect();
            // Even proposing acceptance after Gate cannot conceal an early
            // admission. SEND_POLL is checked separately without committing it.
            let accepted_later = [hibana_epf::Acceptance {
                first_poll: order[gate],
                before: gate + 2,
            }];
            let invalid_witness = hibana_epf::ExecutionWitness {
                session: 98,
                order: &order,
                occurrences: &changed_occurrences,
                acceptances: &accepted_later,
            };
            assert_eq!(
                path.check_execution(&[invalid], &invalid_witness, &mut workspace),
                Err(hibana_epf::ExecutionError::Admission {
                    record: order[gate],
                    prior: hibana_epf::SourcePoint::Local(0),
                })
            );
            assert!(matches!(
                path.interpret(
                    &[invalid],
                    hibana_epf::ExecutionStorage {
                        session: 98,
                        order: &mut inferred_order,
                        occurrences: &mut inferred,
                        acceptances: &mut inferred_acceptances,
                    },
                    &mut workspace
                ),
                Err(hibana_epf::InterpretationError::NoInterpretation)
            ));
        }
    }
}

#[test]
fn repeated_source_events_have_distinct_calls_and_reject_broken_correspondence() {
    type Message = Msg<7, ()>;
    let global = g::send::<0, 1, Message>().roll();
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    let mut slab = [0; 8192];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage
        .init()
        .rendezvous(
            &mut slab,
            DelayedPublication {
                inbox: Cell::new(Ok(None)),
                reader: Cell::new(None),
                backpressured_receiver: None,
                resource: None,
            },
        )
        .unwrap();
    let mut sender = kit.enter(SessionId::new(100), &p0).unwrap();
    let mut receiver = kit.enter(SessionId::new(100), &p1).unwrap();
    let mut records = kit.tap();
    let mut captured: Vec<_> = records.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..2 {
        let mut sending = core::pin::pin!(sender.send::<Message>(&()));
        assert!(sending.as_mut().poll(&mut cx).is_pending());
        captured.extend(records.by_ref());
        {
            let receiving = core::pin::pin!(receiver.recv::<Message>());
            assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        captured.extend(records.by_ref());
        assert!(matches!(
            sending.as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        captured.extend(records.by_ref());
    }
    let checkpoint = records.checkpoint();
    let snapshot: Vec<_> = tap::projected(&p0).collect();
    let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
    let capture = Capture::new(&captured, checkpoint).unwrap();
    let required = protocol.send_call_workspace_len(capture);
    assert!(matches!(
        protocol.send_calls(capture, &mut []),
        Err(HistoryError::Workspace { required: size, actual: 0 }) if size == required
    ));
    workspace.resize(required, 0);
    let calls: Vec<_> = protocol
        .send_calls(capture, &mut workspace)
        .unwrap()
        .collect();
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .all(|call| call.first_poll().arg1() as u16 == 0)
    );
    assert!(calls.iter().all(|call| call.polls().count() == 2));
    assert!(calls.iter().all(|call| call.publication().is_some()));
    assert!(calls[0].publication().unwrap().ts() < calls[1].first_poll().ts());
    let reset = (calls[1].first_poll().arg1() >> 16) as u16;
    assert_ne!(reset, u16::MAX);
    let first_poll = calls[0].first_poll().ts() as usize;
    let second_poll = calls[0].polls().nth(1).unwrap().ts() as usize;
    let publication = calls[0].publication().unwrap().ts() as usize;
    drop(calls);
    for mutation in 0..9 {
        let mut changed = captured.clone();
        for (index, record) in changed.iter_mut().enumerate() {
            let mut bytes = <[u8; 16]>::from(*record);
            match mutation {
                0 if record.id() == tap::SEND_POLL => {
                    bytes[4..6].copy_from_slice(&tap::LANE_ACQUIRE.to_be_bytes());
                }
                1 if index == second_poll => {
                    bytes[4..6].copy_from_slice(&tap::ENDPOINT_SEND.to_be_bytes());
                    bytes[7] = 1;
                    bytes[12..16].copy_from_slice(&0u32.to_be_bytes());
                }
                2 if index == publication => bytes[13] ^= 1, // wrong lane
                3 if index == first_poll => bytes[7] = 1,    // wrong logical view
                4 if matches!(record.id(), tap::SEND_POLL | tap::ENDPOINT_SEND) => bytes[6] = 2,
                5 if index == first_poll => bytes[14..16].copy_from_slice(&u16::MAX.to_be_bytes()),
                6 if index == first_poll => bytes[12..14].copy_from_slice(&0u16.to_be_bytes()),
                7 if index == second_poll => bytes[12..14].copy_from_slice(&reset.to_be_bytes()),
                8 if index == publication => {
                    bytes[4..6].copy_from_slice(&tap::ENDPOINT_SESSION.to_be_bytes());
                }
                _ => {}
            }
            *record = TapEvent::from(bytes);
        }
        let capture = Capture::new(&changed, checkpoint).unwrap();
        assert!(
            matches!(
                protocol.send_calls(capture, &mut workspace),
                Err(HistoryError::Record { .. })
            ),
            "mutation {mutation}"
        );
    }
}

#[test]
fn parallel_calls_keep_their_own_polls_when_publications_finish_in_reverse() {
    type First = Msg<10, ()>;
    type Second = Msg<11, ()>;
    let global = g::par(g::send::<0, 1, First>(), g::send::<0, 2, Second>());
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    let p2 = project::<2>(&global);
    let mut slab = [0; 16384];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage
        .init()
        .rendezvous(
            &mut slab,
            DelayedPublication {
                inbox: Cell::new(Ok(None)),
                reader: Cell::new(None),
                backpressured_receiver: None,
                resource: None,
            },
        )
        .unwrap();
    let sid = SessionId::new(102);
    let mut owner = kit.enter(sid, &p0).unwrap();
    let mut left = kit.enter(sid, &p1).unwrap();
    let mut right = kit.enter(sid, &p2).unwrap();
    let mut records = kit.tap();
    let mut captured: Vec<_> = records.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    {
        let [mut first, mut second] = owner.par().unwrap();
        let mut first = core::pin::pin!(first.send::<First>(&()));
        assert!(first.as_mut().poll(&mut cx).is_pending());
        {
            let receiving = core::pin::pin!(left.recv::<First>());
            assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        captured.extend(records.by_ref());
        let mut second = core::pin::pin!(second.send::<Second>(&()));
        assert!(second.as_mut().poll(&mut cx).is_pending());
        {
            let receiving = core::pin::pin!(right.recv::<Second>());
            assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        assert!(matches!(second.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        captured.extend(records.by_ref());
        assert!(matches!(first.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        captured.extend(records.by_ref());
    }
    let snapshot: Vec<_> = tap::projected(&p0).collect();
    let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
    let capture = Capture::new(&captured, records.checkpoint()).unwrap();
    workspace.resize(protocol.send_call_workspace_len(capture), 0);
    let calls: Vec<_> = protocol
        .send_calls(capture, &mut workspace)
        .unwrap()
        .collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].first_poll().arg1() as u16, 0);
    assert_eq!(calls[1].first_poll().arg1() as u16, 1);
    assert!(calls[0].first_poll().ts() < calls[1].first_poll().ts());
    assert!(calls[1].publication().unwrap().ts() < calls[0].publication().unwrap().ts());
    for (source, call) in calls.iter().enumerate() {
        let polls: Vec<_> = call.polls().collect();
        assert_eq!(polls.len(), 2);
        assert!(
            polls
                .iter()
                .all(|poll| usize::from(poll.arg1() as u16) == source)
        );
        assert!(polls[0].ts() < polls[1].ts());
        assert!(polls[1].ts() < call.publication().unwrap().ts());
    }
}

#[test]
fn a_pending_continuation_can_publish_after_the_other_view_reenters_its_roll() {
    type Tick = Msg<12, ()>;
    type Tail = Msg<13, ()>;
    type Loan = Msg<14, Endpoint<'static, 3>>;
    let global = g::seq(
        g::send::<3, 4, Tick>().roll(),
        g::seq(g::send::<0, 2, Tail>(), g::send::<0, 1, Loan>()),
    );
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    let p2 = project::<2>(&global);
    let p3 = project::<3>(&global);
    let p4 = project::<4>(&global);
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage
        .init()
        .rendezvous(
            &mut slab,
            DelayedPublication {
                inbox: Cell::new(Ok(None)),
                reader: Cell::new(None),
                // SAFETY: this fresh fixture is the only physical resource.
                resource: Some(unsafe { EndpointBinding::new() }),
                backpressured_receiver: Some(2),
            },
        )
        .unwrap();
    let sid = SessionId::new(103);
    let mut owner = kit.enter(sid, &p0).unwrap();
    let mut worker = kit.enter(sid, &p1).unwrap();
    let mut other = kit.enter(sid, &p2).unwrap();
    let mut resource = kit.enter(sid, &p3).unwrap();
    let mut service = kit.enter(sid, &p4).unwrap();
    let mut records = kit.tap();
    let mut captured: Vec<_> = records.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut sending = core::pin::pin!(resource.send::<Tick>(&()));
        assert!(sending.as_mut().poll(&mut cx).is_pending());
        {
            let receiving = core::pin::pin!(service.recv::<Tick>());
            assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        assert!(matches!(
            sending.as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }
    captured.extend(records.by_ref());
    {
        // Tail has passed source admission, but its first transport poll
        // exposes no frame. A separate logical view starts the next Tick.
        let mut tail = core::pin::pin!(owner.send::<Tail>(&()));
        assert!(tail.as_mut().poll(&mut cx).is_pending());
        captured.extend(records.by_ref());
        let mut tick = core::pin::pin!(resource.send::<Tick>(&()));
        let started = tick.as_mut().poll(&mut cx);
        captured.extend(records.by_ref());
        assert!(started.is_pending(), "Tick reentry: {started:?}");
        {
            let receiving = core::pin::pin!(service.recv::<Tick>());
            let received = receiving.poll(&mut cx);
            captured.extend(records.by_ref());
            assert!(
                matches!(received, Poll::Ready(Ok(()))),
                "Tick receipt: {received:?}"
            );
        }
        let finished = tail.as_mut().poll(&mut cx);
        captured.extend(records.by_ref());
        assert!(
            matches!(finished, Poll::Ready(Ok(()))),
            "Tail publication: {finished:?}"
        );
        {
            let receiving = core::pin::pin!(other.recv::<Tail>());
            assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        assert!(matches!(tick.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    }
    captured.extend(records.by_ref());
    let publications: Vec<_> = captured
        .iter()
        .filter(|record| matches!(record.id(), tap::ENDPOINT_SEND | tap::ENDPOINT_RECV))
        .map(|record| (record.arg1() as u16, record.causal_key() as u8))
        .collect();
    assert_eq!(
        publications,
        [(0, 2), (0, 1), (0, 2), (1, 1), (1, 2), (0, 1)]
    );
    let snapshot: Vec<_> = tap::projected(&p0).collect();
    let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
    let capture = Capture::new(&captured, records.checkpoint()).unwrap();
    workspace.resize(protocol.send_call_workspace_len(capture), 0);
    let calls: Vec<_> = protocol
        .send_calls(capture, &mut workspace)
        .unwrap()
        .collect();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].first_poll().causal_key(), 3); // actor 0, view 3
    assert_eq!(calls[1].first_poll().arg1() as u16, 1); // Tail
    assert_eq!(calls[2].first_poll().arg1() as u16, 0); // second Tick
    assert!(calls[1].first_poll().ts() < calls[2].first_poll().ts());
    assert!(calls[1].publication().unwrap().ts() < calls[2].publication().unwrap().ts());
    assert!(calls.iter().all(|call| call.polls().count() == 2));
    drop(calls);
    // The same resource still has a usable continuation and is moved once.
    let order: Vec<_> = (0..captured.len())
        .map(|ordinal| RecordId {
            producer: 0,
            ordinal,
        })
        .collect();
    workspace.resize(protocol.custody_workspace_len(&[capture]), 0);
    protocol
        .check_routes(&[capture], &order, &mut workspace)
        .unwrap();
    let retained = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let steps = [
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Once(0),
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Sequence([2, 3]),
        hibana_epf::Unfold::Alongside {
            retained,
            earlier: 1,
            next: 1,
            tail: 4,
            focus: [0, 1],
        },
    ];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
    let mut actors = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut actors).unwrap();
    let mut sent = 0;
    let mut received = 0;
    let occurrences: Vec<_> = captured
        .iter()
        .map(|record| {
            if record.id() == tap::SCOPE_REENTRY {
                return Some(1);
            }
            if !matches!(
                record.id(),
                tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV
            ) {
                return None;
            }
            if record.arg1() as u16 == 1 {
                return Some(2);
            }
            if record.id() == tap::ENDPOINT_RECV {
                let event = received;
                received += 1;
                Some(event)
            } else {
                let event = sent;
                if record.id() == tap::ENDPOINT_SEND {
                    sent += 1;
                }
                Some(event)
            }
        })
        .collect();
    let mut acceptances: Vec<_> = captured
        .iter()
        .enumerate()
        .filter_map(|(position, record)| {
            let event = occurrences[position]?;
            if record.id() != tap::SEND_POLL
                || captured[..position].iter().enumerate().any(|(at, prior)| {
                    prior.id() == tap::SEND_POLL && occurrences[at] == Some(event)
                })
            {
                return None;
            }
            let before = captured
                .iter()
                .enumerate()
                .position(|(at, record)| {
                    matches!(record.id(), tap::ENDPOINT_SEND | tap::ENDPOINT_RECV)
                        && occurrences[at] == Some(event)
                })
                .unwrap();
            Some(hibana_epf::Acceptance {
                first_poll: order[position],
                before,
            })
        })
        .collect();
    acceptances.sort_by_key(|acceptance| acceptance.before);
    let witness = hibana_epf::ExecutionWitness {
        session: 103,
        order: &order,
        occurrences: &occurrences,
        acceptances: &acceptances,
    };
    workspace.resize(
        path.execution_workspace_len(&[capture], &witness).unwrap(),
        0,
    );
    path.check_execution(&[capture], &witness, &mut workspace)
        .unwrap();
    let mut lending = core::pin::pin!(owner.send::<Loan>(resource));
    assert!(lending.as_mut().poll(&mut cx).is_pending());
    let receiving = core::pin::pin!(worker.recv::<Loan>());
    let Poll::Ready(Ok(borrowed)) = receiving.poll(&mut cx) else {
        panic!("the resource continuation must remain transferable")
    };
    assert!(matches!(
        lending.as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    drop(borrowed);
}

#[test]
fn an_old_send_keeps_one_call_while_another_view_finishes_reentry() {
    type Tick = Msg<12, ()>;
    type Pong = Msg<15, ()>;
    type Tail = Msg<13, ()>;
    type Loan = Msg<14, Endpoint<'static, 3>>;
    let global = g::seq(
        g::seq(g::send::<3, 4, Tick>(), g::send::<4, 3, Pong>()).roll(),
        g::seq(g::send::<0, 2, Tail>(), g::send::<0, 1, Loan>()),
    );
    let p0 = project::<0>(&global);
    let p2 = project::<2>(&global);
    let p3 = project::<3>(&global);
    let p4 = project::<4>(&global);
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage
        .init()
        .rendezvous(
            &mut slab,
            DelayedPublication {
                inbox: Cell::new(Ok(None)),
                reader: Cell::new(None),
                resource: Some(unsafe { EndpointBinding::new() }),
                backpressured_receiver: None,
            },
        )
        .unwrap();
    let sid = SessionId::new(140);
    let mut owner = kit.enter(sid, &p0).unwrap();
    let mut other = kit.enter(sid, &p2).unwrap();
    let mut resource = kit.enter(sid, &p3).unwrap();
    let mut service = kit.enter(sid, &p4).unwrap();
    let mut tap = kit.tap();
    let mut captured: Vec<_> = tap.by_ref().collect();
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut tick = core::pin::pin!(resource.send::<Tick>(&()));
        assert!(tick.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(
            core::pin::pin!(service.recv::<Tick>()).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(tick.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    }
    {
        let mut pong = core::pin::pin!(service.send::<Pong>(&()));
        assert!(pong.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(
            core::pin::pin!(resource.recv::<Pong>()).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(pong.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    }
    captured.extend(tap.by_ref());
    {
        let mut tail = core::pin::pin!(owner.send::<Tail>(&()));
        assert!(tail.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(
            core::pin::pin!(other.recv::<Tail>()).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        captured.extend(tap.by_ref());
        {
            let mut tick = core::pin::pin!(resource.send::<Tick>(&()));
            assert!(tick.as_mut().poll(&mut cx).is_pending());
            assert!(matches!(
                core::pin::pin!(service.recv::<Tick>()).poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(matches!(tick.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
        }
        captured.extend(tap.by_ref());
        let before_retry = captured.len();
        let published = tail.as_mut().poll(&mut cx);
        captured.extend(tap.by_ref());
        match published {
            Poll::Ready(Ok(())) => (),
            Poll::Pending => {
                // Pending does not claim another transport admission. The
                // current kernel can wait for this actor's other view first.
                assert!(
                    !captured[before_retry..]
                        .iter()
                        .any(|record| record.id() == tap::SEND_POLL)
                );
                let mut pong = core::pin::pin!(service.send::<Pong>(&()));
                assert!(pong.as_mut().poll(&mut cx).is_pending());
                assert!(matches!(
                    core::pin::pin!(resource.recv::<Pong>()).poll(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert!(matches!(pong.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
                captured.extend(tap.by_ref());
                assert!(matches!(tail.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
                captured.extend(tap.by_ref());
            }
            Poll::Ready(Err(error)) => panic!("an old send must remain usable: {error:?}"),
        }
    }
    let snapshot: Vec<_> = tap::projected(&p0).collect();
    let retained = snapshot
        .iter()
        .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
        .unwrap()
        .causal_key();
    let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
    let steps = [
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Sequence([0, 1]),
        hibana_epf::Unfold::Once(2),
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Source,
        hibana_epf::Unfold::Sequence([4, 5]),
        hibana_epf::Unfold::Alongside {
            retained,
            earlier: 3,
            next: 3,
            tail: 6,
            focus: [0, 1],
        },
    ];
    let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
    let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
    let mut actors = vec![0; unfolded.path_workspace_len().unwrap()];
    let path = unfolded.select(&[], &mut actors).unwrap();
    let order: Vec<_> = (0..captured.len())
        .map(|ordinal| RecordId {
            producer: 0,
            ordinal,
        })
        .collect();
    let mut sends = [0; 2];
    let mut receives = [0; 2];
    let occurrences: Vec<_> = captured
        .iter()
        .map(|record| {
            let original = usize::from(record.arg1() as u16);
            if record.id() == tap::SCOPE_REENTRY {
                return Some(2 + original);
            }
            if !matches!(
                record.id(),
                tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV
            ) {
                return None;
            }
            if original == 2 {
                return Some(4);
            }
            if record.id() == tap::ENDPOINT_RECV {
                let event = 2 * receives[original] + original;
                receives[original] += 1;
                Some(event)
            } else {
                let event = 2 * sends[original] + original;
                if record.id() == tap::ENDPOINT_SEND {
                    sends[original] += 1;
                }
                Some(event)
            }
        })
        .collect();
    let acceptances: Vec<_> = captured
        .iter()
        .enumerate()
        .filter_map(|(position, record)| {
            let event = occurrences[position]?;
            if record.id() != tap::SEND_POLL
                || captured[..position].iter().enumerate().any(|(at, prior)| {
                    prior.id() == tap::SEND_POLL && occurrences[at] == Some(event)
                })
            {
                return None;
            }
            Some(hibana_epf::Acceptance {
                first_poll: order[position],
                before: position + 1,
            })
        })
        .collect();
    let capture = Capture::new(&captured, tap.checkpoint()).unwrap();
    let witness = hibana_epf::ExecutionWitness {
        session: 140,
        order: &order,
        occurrences: &occurrences,
        acceptances: &acceptances,
    };
    workspace.resize(
        path.execution_workspace_len(&[capture], &witness).unwrap(),
        0,
    );
    path.check_execution(&[capture], &witness, &mut workspace)
        .unwrap();
}

#[test]
fn pending_siblings_can_share_the_reset_published_by_the_first_completed_send() {
    type Tick = Msg<12, ()>;
    type Tail = Msg<13, ()>;
    type Loan = Msg<14, Endpoint<'static, 3>>;
    let global = g::seq(
        g::par(g::send::<3, 4, Tick>(), g::send::<0, 2, Tail>()).roll(),
        g::send::<0, 1, Loan>(),
    );
    let p0 = project::<0>(&global);
    let p2 = project::<2>(&global);
    let p3 = project::<3>(&global);
    let p4 = project::<4>(&global);
    for reverse in [false, true] {
        let mut slab = [0; 32768];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(
                &mut slab,
                DelayedPublication {
                    inbox: Cell::new(Ok(None)),
                    reader: Cell::new(None),
                    // SAFETY: every port reaches this one fresh physical resource.
                    // SAFETY: all ports in this fixture reach one fresh resource.
                    resource: Some(unsafe { EndpointBinding::new() }),
                    backpressured_receiver: None,
                },
            )
            .unwrap();
        let sid = SessionId::new(104);
        let mut owner = kit.enter(sid, &p0).unwrap();
        let mut other = kit.enter(sid, &p2).unwrap();
        let mut resource = kit.enter(sid, &p3).unwrap();
        let mut service = kit.enter(sid, &p4).unwrap();
        let mut records = kit.tap();
        let mut captured: Vec<_> = records.by_ref().collect();
        let mut cx = Context::from_waker(Waker::noop());
        for visit in 0..2 {
            let mut tick = core::pin::pin!(resource.send::<Tick>(&()));
            assert!(tick.as_mut().poll(&mut cx).is_pending());
            {
                let receiving = core::pin::pin!(service.recv::<Tick>());
                assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
            }
            captured.extend(records.by_ref());
            if visit == 0 {
                assert!(matches!(tick.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
            }
            {
                let mut tail = core::pin::pin!(owner.send::<Tail>(&()));
                assert!(tail.as_mut().poll(&mut cx).is_pending());
                {
                    let receiving = core::pin::pin!(other.recv::<Tail>());
                    assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
                }
                if visit != 0 && reverse {
                    assert!(matches!(tick.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
                }
                assert!(matches!(tail.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
            }
            if visit != 0 && !reverse {
                assert!(matches!(tick.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
            }
            captured.extend(records.by_ref());
        }
        let snapshot: Vec<_> = tap::projected(&p0).collect();
        let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
        let capture = Capture::new(&captured, records.checkpoint()).unwrap();
        workspace.resize(protocol.send_call_workspace_len(capture), 0);
        let calls: Vec<_> = protocol
            .send_calls(capture, &mut workspace)
            .unwrap()
            .collect();
        assert_eq!(calls.len(), 4);
        assert!(calls.iter().all(|call| call.polls().count() == 2));
        assert!(calls.iter().all(|call| call.publication().is_some()));
        let waiting = &calls[if reverse { 3 } else { 2 }];
        let polls: Vec<_> = waiting.polls().collect();
        assert_ne!(polls[0].arg1() >> 16, u32::from(u16::MAX));
        assert_eq!(polls[1].arg1() >> 16, u32::from(u16::MAX));
        let reset = captured
            .iter()
            .position(|record| {
                record.id() == tap::SCOPE_REENTRY
                    && record.causal_key() >> 8 == 0
                    && polls[0].ts() < record.ts()
                    && record.ts() < polls[1].ts()
            })
            .unwrap();
        let first_polls: Vec<_> = calls
            .iter()
            .map(|call| call.first_poll().ts() as usize)
            .collect();
        drop(calls);
        let order: Vec<_> = (0..captured.len())
            .map(|ordinal| RecordId {
                producer: 0,
                ordinal,
            })
            .collect();
        workspace.resize(protocol.custody_workspace_len(&[capture]), 0);
        protocol
            .check_routes(&[capture], &order, &mut workspace)
            .unwrap();
        let steps = [
            hibana_epf::Unfold::Source,
            hibana_epf::Unfold::Source,
            hibana_epf::Unfold::Parallel([0, 1]),
            hibana_epf::Unfold::Once(2),
            hibana_epf::Unfold::More([3, 2]),
            hibana_epf::Unfold::Source,
            hibana_epf::Unfold::Sequence([4, 5]),
        ];
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
        let mut actors = vec![0; unfolded.path_workspace_len().unwrap()];
        let path = unfolded.select(&[], &mut actors).unwrap();
        let mut sends = [0; 2];
        let mut receives = [0; 2];
        let occurrences: Vec<_> = captured
            .iter()
            .map(|record| {
                let original = usize::from(record.arg1() as u16);
                if record.id() == tap::SCOPE_REENTRY {
                    return Some(2 + original);
                }
                if !matches!(
                    record.id(),
                    tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV
                ) {
                    return None;
                }
                if record.id() == tap::ENDPOINT_RECV {
                    let event = 2 * receives[original] + original;
                    receives[original] += 1;
                    Some(event)
                } else {
                    let event = 2 * sends[original] + original;
                    if record.id() == tap::ENDPOINT_SEND {
                        sends[original] += 1;
                    }
                    Some(event)
                }
            })
            .collect();
        let acceptances: Vec<_> = first_polls
            .iter()
            .map(|&ordinal| hibana_epf::Acceptance {
                first_poll: order[ordinal],
                before: ordinal + 1,
            })
            .collect();
        let witness = hibana_epf::ExecutionWitness {
            session: 104,
            order: &order,
            occurrences: &occurrences,
            acceptances: &acceptances,
        };
        workspace.resize(
            path.execution_workspace_len(&[capture], &witness).unwrap(),
            0,
        );
        path.check_execution(&[capture], &witness, &mut workspace)
            .unwrap();
        for mutation in 0..5 {
            let mut changed = captured.clone();
            let mut bytes = <[u8; 16]>::from(changed[reset]);
            match mutation {
                0 => bytes[4..6].copy_from_slice(&tap::LANE_ACQUIRE.to_be_bytes()),
                1 => bytes[8..12].copy_from_slice(&105u32.to_be_bytes()),
                2 => bytes[6] = 7,
                3 => bytes[7] = 4,
                4 => bytes[14..16].copy_from_slice(&u16::MAX.to_be_bytes()),
                _ => unreachable!(),
            }
            changed[reset] = TapEvent::from(bytes);
            let capture = Capture::new(&changed, records.checkpoint()).unwrap();
            assert!(
                matches!(
                    protocol.send_calls(capture, &mut workspace),
                    Err(HistoryError::Record { .. })
                ),
                "reverse={reverse}, mutation={mutation}"
            );
        }
    }
}

#[test]
fn conditional_resource_holders_keep_their_own_call_before_loan_publication() {
    type Loan = Msg<7, Endpoint<'static, 3>>;
    type Skip = Msg<8, ()>;
    type Use = Msg<9, ()>;
    let global = g::seq(
        g::route(
            g::seq(g::send::<0, 1, Loan>(), g::send::<0, 4, Skip>()),
            g::seq(g::send::<0, 1, Skip>(), g::send::<0, 4, Loan>()),
        )
        .resolve::<17>(),
        g::send::<3, 2, Use>(),
    );
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    let p2 = project::<2>(&global);
    let p3 = project::<3>(&global);
    let p4 = project::<4>(&global);
    for selected in [DecisionArm::Left, DecisionArm::Right] {
        let mut slab = [0; 32768];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(
                &mut slab,
                DelayedPublication {
                    inbox: Cell::new(Ok(None)),
                    reader: Cell::new(None),
                    backpressured_receiver: None,
                    // SAFETY: all ports reach this one fresh physical fixture.
                    resource: Some(unsafe { EndpointBinding::new() }),
                },
            )
            .unwrap();
        kit.set_resolver(
            &p0,
            ResolverRef::<17>::decision_state(&selected, |selected| Ok(*selected)),
        )
        .unwrap();
        let sid = SessionId::new(101);
        let mut owner = kit.enter(sid, &p0).unwrap();
        let mut first = kit.enter(sid, &p1).unwrap();
        let mut service = kit.enter(sid, &p2).unwrap();
        let resource = kit.enter(sid, &p3).unwrap();
        let mut other = kit.enter(sid, &p4).unwrap();
        let mut records = kit.tap();
        let mut captured: Vec<_> = records.by_ref().collect();
        let mut cx = Context::from_waker(Waker::noop());
        // The right arm first informs role 1, then lends to role 4.
        if selected == DecisionArm::Right {
            let mut sending = core::pin::pin!(owner.send::<Skip>(&()));
            assert!(sending.as_mut().poll(&mut cx).is_pending());
            {
                let receiving = core::pin::pin!(first.recv::<Skip>());
                assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
            }
            assert!(matches!(
                sending.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
            captured.extend(records.by_ref());
        }
        {
            let mut lending = core::pin::pin!(owner.send::<Loan>(resource));
            assert!(lending.as_mut().poll(&mut cx).is_pending());
            let mut resource = if selected == DecisionArm::Left {
                let receiving = core::pin::pin!(first.recv::<Loan>());
                let Poll::Ready(Ok(resource)) = receiving.poll(&mut cx) else {
                    panic!("role 1 must receive its resource")
                };
                resource
            } else {
                let receiving = core::pin::pin!(other.recv::<Loan>());
                let Poll::Ready(Ok(resource)) = receiving.poll(&mut cx) else {
                    panic!("role 4 must receive its resource")
                };
                resource
            };
            captured.extend(records.by_ref());
            {
                let mut sending = core::pin::pin!(resource.send::<Use>(&()));
                assert!(sending.as_mut().poll(&mut cx).is_pending());
                {
                    let receiving = core::pin::pin!(service.recv::<Use>());
                    assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
                }
                assert!(matches!(
                    sending.as_mut().poll(&mut cx),
                    Poll::Ready(Ok(()))
                ));
            }
            captured.extend(records.by_ref());
            let snapshot: Vec<_> = tap::projected(&p0).collect();
            assert!(
                snapshot
                    .iter()
                    .any(|row| row.id() == tap::PROJECTED_ACTOR_DECISION)
            );
            let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
            let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
            let capture = Capture::new(&captured, records.checkpoint()).unwrap();
            workspace.resize(protocol.send_call_workspace_len(capture), 0);
            let calls: Vec<_> = protocol
                .send_calls(capture, &mut workspace)
                .unwrap()
                .collect();
            let loan = calls
                .iter()
                .find(|call| call.first_poll().causal_key() == 0 && call.publication().is_none())
                .unwrap();
            assert_eq!(loan.polls().count(), 1);
            let used = calls
                .iter()
                .find(|call| call.first_poll().causal_key() as u8 == 3)
                .unwrap();
            assert_eq!(
                used.first_poll().causal_key() >> 8,
                if selected == DecisionArm::Left { 1 } else { 4 }
            );
            assert_eq!(used.first_poll().arg1() as u16, 4);
            assert_eq!(used.polls().count(), 2);
            assert!(used.publication().is_some());
            drop(calls);
            assert!(matches!(
                lending.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
            captured.extend(records.by_ref());
        }
        if selected == DecisionArm::Left {
            let mut sending = core::pin::pin!(owner.send::<Skip>(&()));
            assert!(sending.as_mut().poll(&mut cx).is_pending());
            {
                let receiving = core::pin::pin!(other.recv::<Skip>());
                assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
            }
            assert!(matches!(
                sending.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
            captured.extend(records.by_ref());
        }
        let snapshot: Vec<_> = tap::projected(&p0).collect();
        let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
        let capture = Capture::new(&captured, records.checkpoint()).unwrap();
        workspace.resize(protocol.send_call_workspace_len(capture), 0);
        let calls: Vec<_> = protocol
            .send_calls(capture, &mut workspace)
            .unwrap()
            .collect();
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|call| call.polls().count() == 2));
        assert!(calls.iter().all(|call| call.publication().is_some()));
        drop(calls);
        let order: Vec<_> = (0..captured.len())
            .map(|ordinal| RecordId {
                producer: 0,
                ordinal,
            })
            .collect();
        let required = protocol.custody_workspace_len(&[capture]);
        workspace.resize(required, usize::MAX);
        protocol
            .check_custody(&[capture], &order, &mut workspace)
            .unwrap();
        protocol
            .check_routes(&[capture], &order, &mut workspace)
            .unwrap();
        assert!(matches!(
            protocol.check_custody(&[capture], &order, &mut workspace[..required - 1]),
            Err(CustodyError::Workspace { .. })
        ));
        assert!(matches!(
            protocol.check_custody(&[capture], &order[..order.len() - 1], &mut workspace),
            Err(CustodyError::Order { .. })
        ));
        let mut repeated = order.clone();
        repeated[1] = repeated[0];
        assert!(matches!(
            protocol.check_custody(&[capture], &repeated, &mut workspace),
            Err(CustodyError::Order { .. })
        ));

        // Both holders belong to the compiled actor candidate set. Changing
        // all observations of Use preserves static membership and call links,
        // but contradicts the transfer actually received in this execution.
        let mut wrong_holder = captured.clone();
        for record in &mut wrong_holder {
            if record.arg1() as u16 == 4
                && (record.id() == tap::SEND_POLL
                    || (record.id() == tap::ENDPOINT_SEND && record.causal_key() as u8 == 1))
            {
                let mut bytes: [u8; 16] = (*record).into();
                bytes[6] = if selected == DecisionArm::Left { 4 } else { 1 };
                *record = bytes.into();
            }
        }
        let invalid = Capture::new(&wrong_holder, records.checkpoint()).unwrap();
        protocol
            .send_calls(invalid, &mut workspace)
            .unwrap()
            .for_each(drop);
        assert!(matches!(
            protocol.check_custody(&[invalid], &order, &mut workspace),
            Err(CustodyError::Owner { role: 3, .. })
        ));
    }
}

#[test]
fn an_observed_send_poll_can_end_in_a_transport_error_without_a_commit() {
    type Message = Msg<7, ()>;
    let global = g::send::<0, 1, Message>();
    let program = project::<0>(&global);
    for error in [
        TransportError::Offline,
        TransportError::Deadline,
        TransportError::Capacity,
        TransportError::Failed,
    ] {
        let mut slab = [0; 8192];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(
                &mut slab,
                DelayedPublication {
                    inbox: Cell::new(Err(error)),
                    reader: Cell::new(None),
                    backpressured_receiver: None,
                    resource: None,
                },
            )
            .unwrap();
        let mut sender = kit.enter(SessionId::new(99), &program).unwrap();
        let mut records = kit.tap();
        let mut captured: Vec<_> = records.by_ref().collect();
        let mut cx = Context::from_waker(Waker::noop());
        let operation = core::pin::pin!(sender.send::<Message>(&()));
        assert!(matches!(operation.poll(&mut cx), Poll::Ready(Err(_))));
        captured.extend(records.by_ref());
        let polls: Vec<_> = captured
            .iter()
            .filter(|record| record.id() == tap::SEND_POLL)
            .collect();
        assert_eq!(polls.len(), 1, "{error:?}");
        assert_eq!(polls[0].causal_key(), 0);
        assert_eq!(polls[0].arg0(), 99);
        assert_eq!(polls[0].arg1(), 0xffff_0000);
        assert!(!captured.iter().any(|record| matches!(
            record.id(),
            tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::TRANSPORT_FRAME | tap::SCOPE_REENTRY
        )));
        hibana_epf::Capture::new(&captured, records.checkpoint()).unwrap();
        let snapshot: Vec<_> = tap::projected(&program).collect();
        let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
        let capture = Capture::new(&captured, records.checkpoint()).unwrap();
        workspace.resize(protocol.send_call_workspace_len(capture), 0);
        let calls: Vec<_> = protocol
            .send_calls(capture, &mut workspace)
            .unwrap()
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].polls().count(), 1);
        assert_eq!(calls[0].publication(), None);
        drop(calls);
        let steps = [hibana_epf::Unfold::Source];
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let unfolded = protocol.unfolding(&steps, &mut proof).unwrap();
        let mut actors = vec![0; unfolded.path_workspace_len().unwrap()];
        let path = unfolded.select(&[], &mut actors).unwrap();
        let order: Vec<_> = (0..captured.len())
            .map(|ordinal| RecordId {
                producer: 0,
                ordinal,
            })
            .collect();
        let occurrences: Vec<_> = captured
            .iter()
            .map(|record| (record.id() == tap::SEND_POLL).then_some(0))
            .collect();
        let witness = hibana_epf::ExecutionWitness {
            session: 99,
            order: &order,
            occurrences: &occurrences,
            acceptances: &[],
        };
        workspace.resize(
            path.execution_workspace_len(&[capture], &witness).unwrap() + 2,
            0,
        );
        path.check_execution(&[capture], &witness, &mut workspace)
            .unwrap();
        let fabricated = [hibana_epf::Acceptance {
            first_poll: order[polls[0].ts() as usize],
            before: order.len(),
        }];
        let invalid = hibana_epf::ExecutionWitness {
            acceptances: &fabricated,
            ..witness
        };
        assert_eq!(
            path.check_execution(&[capture], &invalid, &mut workspace),
            Err(hibana_epf::ExecutionError::Acceptance { index: 0 })
        );
    }
}

#[test]
fn learning_a_resolved_choice_is_distinct_from_invoking_its_resolver() {
    type Left = Msg<7, ()>;
    type Right = Msg<8, ()>;
    let global = g::route(g::send::<0, 1, Left>(), g::send::<0, 1, Right>()).resolve::<17>();
    let p0 = project::<0>(&global);
    let p1 = project::<1>(&global);
    for selected in [DecisionArm::Left, DecisionArm::Right] {
        let mut slab = [0; 8192];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(
                &mut slab,
                DelayedPublication {
                    inbox: Cell::new(Ok(None)),
                    reader: Cell::new(None),
                    backpressured_receiver: None,
                    resource: None,
                },
            )
            .unwrap();
        kit.set_resolver(
            &p0,
            ResolverRef::<17>::decision_state(&selected, |selected| Ok(*selected)),
        )
        .unwrap();
        let mut sender = kit.enter(SessionId::new(94), &p0).unwrap();
        let mut receiver = kit.enter(SessionId::new(94), &p1).unwrap();
        let mut records = kit.tap();
        let mut captured: Vec<_> = records.by_ref().collect();
        let mut cx = Context::from_waker(Waker::noop());
        let mut sending = core::pin::pin!(async {
            match selected {
                DecisionArm::Left => sender.send::<Left>(&()).await,
                DecisionArm::Right => sender.send::<Right>(&()).await,
            }
        });
        assert!(sending.as_mut().poll(&mut cx).is_pending());
        captured.extend(records.by_ref());
        let attempt = captured
            .iter()
            .find(|record| record.id() == tap::SEND_POLL)
            .unwrap();
        assert_eq!(attempt.causal_key(), 0);
        assert_eq!(attempt.arg0(), 94);
        assert_eq!(
            attempt.arg1() & 0xffff,
            u32::from(selected == DecisionArm::Right)
        );
        {
            let receiving = core::pin::pin!(async {
                let branch = receiver.offer().await?;
                match branch.label() {
                    7 => {
                        branch.recv::<Left>().await?;
                    }
                    8 => {
                        branch.recv::<Right>().await?;
                    }
                    label => panic!("unexpected branch {label}"),
                }
                Ok::<_, hibana::EndpointError>(())
            });
            assert!(matches!(receiving.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        captured.extend(records.by_ref());
        assert!(
            !captured
                .iter()
                .any(|record| record.id() == tap::ENDPOINT_SEND)
        );
        assert!(matches!(
            sending.as_mut().poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        captured.extend(records.by_ref());
        let decisions: Vec<_> = captured
            .iter()
            .filter(|record| record.id() == tap::RESOLVER_AUDIT)
            .collect();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].causal_key() >> 8, 0);
        let learned = captured
            .iter()
            .find(|record| record.id() == tap::ROUTE_ARM_SELECTION && record.causal_key() >> 8 == 1)
            .unwrap();
        assert!(matches!(learned.causal_key() as u8, 1 | 3));
        let site = learned.arg1() >> 16;
        let compiled = tap::projected(&p1)
            .find(|row| row.id() == tap::PROJECTED_CHOICE && u32::from(row.causal_key()) == site)
            .unwrap();
        assert_eq!(
            compiled.arg0(),
            0,
            "learning does not change the logical controller"
        );
        assert_eq!(
            learned.arg1() & 0xffff,
            u32::from(selected == DecisionArm::Right)
        );
        let snapshot: Vec<_> = tap::projected(&p0).collect();
        let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
        let capture = Capture::new(&captured, records.checkpoint()).unwrap();
        workspace.resize(protocol.send_call_workspace_len(capture), 0);
        let calls: Vec<_> = protocol
            .send_calls(capture, &mut workspace)
            .unwrap()
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].first_poll().arg1() as u16,
            u16::from(selected == DecisionArm::Right)
        );
        assert!(calls[0].publication().is_some());
        drop(calls);
        let order: Vec<_> = (0..captured.len())
            .map(|ordinal| RecordId {
                producer: 0,
                ordinal,
            })
            .collect();
        workspace.resize(protocol.custody_workspace_len(&[capture]), 0);
        protocol
            .check_routes(&[capture], &order, &mut workspace)
            .unwrap();
        for mutation in 0..4 {
            let mut invalid = captured.clone();
            let record = invalid
                .iter_mut()
                .find(|record| match mutation {
                    0 => record.id() == tap::ROUTE_ARM_SELECTION && record.causal_key() >> 8 == 1,
                    _ => record.id() == tap::RESOLVER_AUDIT,
                })
                .unwrap();
            let mut bytes: [u8; 16] = (*record).into();
            match mutation {
                0 => bytes[15] ^= 1,
                1 => bytes[7] ^= 1,
                2 => bytes[15] ^= 1,
                _ => bytes[6] = 1,
            }
            *record = bytes.into();
            let invalid = Capture::new(&invalid, records.checkpoint()).unwrap();
            assert!(
                protocol
                    .check_routes(&[invalid], &order, &mut workspace)
                    .is_err(),
                "mutation {mutation}"
            );
        }
    }
}
