use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use hibana::{
    g::{self, Msg},
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::project,
        resolver::{DecisionArm, ResolverRef},
        tap::{self, TapEvent},
        transport::{FrameHeader, Outgoing, PortOpen, ReceivedFrame, Transport, TransportError},
        wire::Payload,
    },
};
use hibana_epf::{Epf, EpfStorage};

// A single physical unit-frame inbox. A send makes its frame available on
// the first poll and reports acceptance on the next. Only copied frame
// headers survive a poll; no outgoing payload pointer is retained.
struct DelayedPublication {
    inbox: Cell<Result<Option<FrameHeader>, TransportError>>,
    reader: Cell<Option<Waker>>,
}

impl Transport for DelayedPublication {
    type Tx<'a> = (PortOpen, Option<FrameHeader>);
    type Rx<'a> = (PortOpen, Option<FrameHeader>);

    fn open(&self, port: PortOpen) -> (Self::Tx<'_>, Self::Rx<'_>) {
        ((port, None), (port, None))
    }

    fn poll_send(
        &self,
        tx: &mut Self::Tx<'_>,
        outgoing: Outgoing<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        assert!(outgoing.payload().as_bytes().is_empty());
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
        if let Some(accepted) = tx.1.take() {
            assert_eq!(accepted, header);
            return Poll::Ready(Ok(()));
        }
        match self.inbox.get() {
            Ok(None) => {
                self.inbox.set(Ok(Some(header)));
                tx.1 = Some(header);
                if let Some(reader) = self.reader.take() {
                    reader.wake();
                }
                cx.waker().wake_by_ref();
                Poll::Pending
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
            Ok(Some(header)) => {
                assert_eq!(header.bytes()[6], rx.0.local_role());
                self.inbox.set(Ok(None));
                rx.1 = Some(header);
                Poll::Ready(Ok(ReceivedFrame::framed(header, Payload::new(&[]))))
            }
            Ok(None) => {
                self.reader.set(Some(cx.waker().clone()));
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn requeue(&self, rx: &mut Self::Rx<'_>) -> Result<(), TransportError> {
        let header = rx.1.take().expect("requeue requires a received frame");
        match self.inbox.get() {
            Ok(None) => {
                self.inbox.set(Ok(Some(header)));
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
    let received = captured[receipt];
    let sent = captured[publication];
    assert_eq!(received.arg0(), sent.arg0());
    assert_eq!(received.arg1() & 0xffff, sent.arg1() & 0xffff);
    let mut epf_storage = EpfStorage::<0, 0>::new();
    let epf = Epf::new(&mut epf_storage);
    for record in &captured {
        let decoded = TapEvent::from(<[u8; 16]>::from(*record));
        let out = epf.run(decoded);
        assert!(out.emitted());
        assert_eq!(out.arg0(), record.arg0());
        assert_eq!(out.arg1(), record.arg1());
        assert_eq!(decoded.ts(), record.ts());
    }
    assert!(
        captured
            .windows(2)
            .all(|records| records[0].ts() + 1 == records[1].ts())
    );
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
    }
}
