//! Retrospective correspondence across complete producer captures.
use super::{HistoryError, Layout, Protocol};
use crate::Capture;
use hibana::runtime::tap::{self, TapEvent};

/// An observation in the supplied array of producer captures.
///
/// Ordinals order records within one producer only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordId {
    /// Index of the capture in the supplied producer array.
    pub producer: usize,
    /// Position in that capture, equal to the checked tap ordinal.
    pub ordinal: usize,
}

/// One successful receive and the first checked poll of its send call.
///
/// Physical acceptance occurred after a poll and before this receive. Its
/// exact position, source eligibility and the received payload are not proved
/// by this correspondence. Publication may follow the receive or be absent
/// from the captured prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// First checked transport poll of this send call.
    pub first_poll: RecordId,
    /// Successfully committed receive for this call.
    pub receive: RecordId,
}

/// Producer histories cannot establish an unambiguous causal correspondence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryError {
    /// One producer failed the source-membership or send-call checks.
    History {
        producer: usize,
        error: HistoryError,
    },
    /// Required words in the caller-owned workspace.
    Workspace { required: usize, actual: usize },
    /// More than one producer supplies this source's sends or receives.
    /// Their order needs further evidence, such as the resource handoff history.
    Ambiguous { session: u32, source: u16 },
    /// A receive has no corresponding observed send call.
    Unmatched { receive: RecordId },
    /// Producer order and the proposed delivery edges form a causal cycle.
    Cycle,
}

impl Protocol<'_> {
    /// Temporary words for `deliveries`, derived from capture and source sizes.
    pub fn delivery_workspace_len(&self, captures: &[Capture<'_>]) -> usize {
        4 * captures
            .iter()
            .map(|capture| capture.records().len())
            .sum::<usize>()
            + captures.len()
            + 1
            + captures
                .iter()
                .map(|&capture| self.send_call_workspace_len(capture))
                .max()
                .unwrap_or(0)
    }

    /// Match receives to send calls without inventing a distributed clock.
    ///
    /// First checks every producer with `send_calls`. Within each session and
    /// source event, FIFO delivery pairs sends and receives in producer order.
    /// The transport's affine FIFO contract is a premise. If either side spans
    /// several producers, this method reports ambiguity instead of guessing an
    /// order from their unrelated ordinals. It then checks that producer order
    /// and first-poll-before-receive edges admit one common causal ordering.
    ///
    /// Every receive is matched once and no call supplies two receives. A
    /// staged frame is not a receive; open or failed sends need not have one.
    /// These checks concern a complete captured prefix, not session completion,
    /// authenticity, chosen ownership or route/roll eligibility. In particular,
    /// a first poll is not a physical-acceptance observation.
    ///
    /// Storage is temporary caller-owned audit space. The returned links are
    /// ordered by their send's producer and ordinal, without modifying captures.
    pub fn deliveries<'w>(
        &self,
        captures: &[Capture<'_>],
        workspace: &'w mut [usize],
    ) -> Result<impl Iterator<Item = Delivery> + 'w, DeliveryError> {
        let required = self.delivery_workspace_len(captures);
        if workspace.len() < required {
            return Err(DeliveryError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let count = captures.iter().map(|capture| capture.records().len()).sum();
        let (order, rest) = workspace[..required].split_at_mut(count);
        let (links, rest) = rest.split_at_mut(count);
        let (queue, rest) = rest.split_at_mut(count);
        let (ranks, rest) = rest.split_at_mut(count);
        let (offsets, scratch) = rest.split_at_mut(captures.len() + 1);
        offsets[0] = 0;
        links.fill(0);
        let layout = Layout::checked(*self);
        let mut tokens = 0;
        for (producer, &capture) in captures.iter().enumerate() {
            let base = offsets[producer];
            offsets[producer + 1] = base + capture.records().len();
            let calls = self
                .send_calls(capture, scratch)
                .map_err(|error| DeliveryError::History { producer, error })?;
            for call in calls {
                order[tokens] = base + call.first_poll().ts() as usize;
                tokens += 1;
            }
            for record in capture.records() {
                if is_receive(*record) {
                    let source =
                        self.records[layout.sources.start + usize::from(record.arg1() as u16)];
                    if source.arg0() >> 24 != (source.arg0() >> 16) & 255 {
                        order[tokens] = base + record.ts() as usize;
                        tokens += 1;
                    }
                }
            }
        }
        let record_at = |index| {
            let id = locate(offsets, index);
            captures[id.producer].records()[id.ordinal]
        };
        let tokens = &mut order[..tokens];
        tokens.sort_unstable_by_key(|&index| {
            let record = record_at(index);
            (stream(record), is_receive(record), index)
        });
        let mut start = 0;
        while start < tokens.len() {
            let identity = stream(record_at(tokens[start]));
            let end = start
                + tokens[start..].partition_point(|&index| stream(record_at(index)) == identity);
            let group = &tokens[start..end];
            let split = group.partition_point(|&index| !is_receive(record_at(index)));
            let (sends, receives) = group.split_at(split);
            for side in [sends, receives] {
                if let Some(&first) = side.first() {
                    let producer = locate(offsets, first).producer;
                    if side
                        .iter()
                        .any(|&index| locate(offsets, index).producer != producer)
                    {
                        return Err(DeliveryError::Ambiguous {
                            session: identity.0,
                            source: identity.1,
                        });
                    }
                }
            }
            if let Some(&extra) = receives.get(sends.len()) {
                return Err(DeliveryError::Unmatched {
                    receive: locate(offsets, extra),
                });
            }
            for (&send, &receive) in sends.iter().zip(receives) {
                links[send] = receive + 1;
            }
            start = end;
        }
        causal_order(offsets, links, queue, ranks)?;
        // Check the constructed order by its defining inequalities, rather
        // than trusting the queue's degree accounting or its traversal order.
        check_causal_order(offsets, links, queue, ranks)?;
        let links: &'w [usize] = links;
        let offsets: &'w [usize] = offsets;
        Ok(links
            .iter()
            .enumerate()
            .filter_map(move |(index, &receive)| {
                receive.checked_sub(1).map(|receive| Delivery {
                    first_poll: locate(offsets, index),
                    receive: locate(offsets, receive),
                })
            }))
    }
}

fn stream(record: TapEvent) -> (u32, u16) {
    (record.arg0(), record.arg1() as u16)
}

fn is_receive(record: TapEvent) -> bool {
    matches!(record.id(), tap::ENDPOINT_RECV | tap::ENDPOINT_SESSION)
        && record.causal_key() as u8 == 2
}

fn locate(offsets: &[usize], index: usize) -> RecordId {
    let producer = offsets.partition_point(|&offset| offset <= index) - 1;
    RecordId {
        producer,
        ordinal: index - offsets[producer],
    }
}

fn causal_order(
    offsets: &[usize],
    links: &[usize],
    queue: &mut [usize],
    remaining: &mut [usize],
) -> Result<(), DeliveryError> {
    remaining.fill(1);
    for interval in offsets.windows(2) {
        if interval[0] < interval[1] {
            remaining[interval[0]] = 0;
        }
    }
    for &receive in links {
        if let Some(receive) = receive.checked_sub(1) {
            remaining[receive] += 1;
        }
    }
    let mut end = 0;
    for (index, &degree) in remaining.iter().enumerate() {
        if degree == 0 {
            queue[end] = index;
            end += 1;
        }
    }
    let mut at = 0;
    while at < end {
        let index = queue[at];
        at += 1;
        let producer = locate(offsets, index).producer;
        let next = (index + 1 < offsets[producer + 1]).then_some(index + 1);
        for after in [next, links[index].checked_sub(1)].into_iter().flatten() {
            remaining[after] -= 1;
            if remaining[after] == 0 {
                queue[end] = after;
                end += 1;
            }
        }
    }
    if end != links.len() {
        return Err(DeliveryError::Cycle);
    }
    Ok(())
}

fn check_causal_order(
    offsets: &[usize],
    links: &[usize],
    order: &[usize],
    ranks: &mut [usize],
) -> Result<(), DeliveryError> {
    ranks.fill(usize::MAX);
    for (rank, &index) in order.iter().enumerate() {
        let Some(slot) = ranks.get_mut(index) else {
            return Err(DeliveryError::Cycle);
        };
        if *slot != usize::MAX {
            return Err(DeliveryError::Cycle);
        }
        *slot = rank;
    }
    if ranks.contains(&usize::MAX) {
        return Err(DeliveryError::Cycle);
    }
    for interval in offsets.windows(2) {
        if ranks[interval[0]..interval[1]]
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(DeliveryError::Cycle);
        }
    }
    for (send, &receive) in links.iter().enumerate() {
        if let Some(receive) = receive.checked_sub(1)
            && ranks.get(receive).is_none_or(|&rank| ranks[send] >= rank)
        {
            return Err(DeliveryError::Cycle);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use hibana::{g, runtime::program::project};
    use std::{vec, vec::Vec};

    fn operation(snapshot: &[TapEvent], event: u16, id: u16) -> TapEvent {
        let source = snapshot[2 + usize::from(event)];
        let from = (source.arg0() >> 24) as u8;
        let to = (source.arg0() >> 16) as u8;
        let lane = (source.arg0() >> 8) as u8;
        let receiving = id == tap::ENDPOINT_RECV;
        let view = if receiving { to } else { from };
        let direction = if receiving { 2 } else { 1 };
        let poll = id == tap::SEND_POLL;
        let detail = if poll {
            0xffff_0000 | u32::from(event)
        } else {
            (u32::from(view) << 24) | (u32::from(lane) << 16) | u32::from(event)
        };
        let mut bytes = [0; 16];
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[6] = view;
        bytes[7] = if poll { view } else { direction };
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..].copy_from_slice(&detail.to_be_bytes());
        bytes.into()
    }

    fn ordinals(records: &mut [TapEvent]) {
        for (index, record) in records.iter_mut().enumerate() {
            let mut bytes: [u8; 16] = (*record).into();
            bytes[..4].copy_from_slice(&(index as u32).to_be_bytes());
            *record = bytes.into();
        }
    }

    #[test]
    fn repeated_fifo_occurrences_have_distinct_receipts_without_a_shared_clock() {
        let global = g::send::<0, 1, g::Msg<7, ()>>().roll();
        let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
        let mut source_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut source_storage).unwrap();
        let poll = operation(&snapshot, 0, tap::SEND_POLL);
        let publication = operation(&snapshot, 0, tap::ENDPOINT_SEND);
        let receive = operation(&snapshot, 0, tap::ENDPOINT_RECV);
        let mut sends = vec![TapEvent::from([0; 16]); 16];
        sends.extend([poll, publication, poll, publication]);
        let mut receipts = [receive, receive];
        ordinals(&mut sends);
        ordinals(&mut receipts);
        let captures = [
            Capture::new(&sends, Some(20)).unwrap(),
            Capture::new(&receipts, Some(2)).unwrap(),
        ];
        let required = protocol.delivery_workspace_len(&captures);
        let mut workspace = std::vec![usize::MAX; required];
        assert!(
            matches!(protocol.deliveries(&captures, &mut workspace[..required - 1]),
            Err(DeliveryError::Workspace { required: size, .. }) if size == required)
        );
        let actual: Vec<_> = protocol
            .deliveries(&captures, &mut workspace)
            .unwrap()
            .collect();
        assert_eq!(
            actual,
            [
                Delivery {
                    first_poll: RecordId {
                        producer: 0,
                        ordinal: 16
                    },
                    receive: RecordId {
                        producer: 1,
                        ordinal: 0
                    }
                },
                Delivery {
                    first_poll: RecordId {
                        producer: 0,
                        ordinal: 18
                    },
                    receive: RecordId {
                        producer: 1,
                        ordinal: 1
                    }
                },
            ]
        );
        assert!(
            actual
                .iter()
                .all(|link| link.first_poll.ordinal > link.receive.ordinal)
        );
        // A complete capture prefix can contain unreceived or unpublished calls.
        let open = [Capture::new(&sends[..17], Some(17)).unwrap()];
        workspace.resize(protocol.delivery_workspace_len(&open), 0);
        assert_eq!(
            protocol.deliveries(&open, &mut workspace).unwrap().count(),
            0
        );
        workspace.resize(protocol.delivery_workspace_len(&[]), usize::MAX);
        assert_eq!(protocol.deliveries(&[], &mut workspace).unwrap().count(), 0);
    }

    #[test]
    fn missing_reused_or_unordered_producer_evidence_cannot_supply_a_receive() {
        let global = g::send::<0, 1, g::Msg<7, ()>>().roll();
        let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
        let mut source_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut source_storage).unwrap();
        let mut workspace = std::vec::Vec::<usize>::new();
        let mut sends = [
            operation(&snapshot, 0, tap::SEND_POLL),
            operation(&snapshot, 0, tap::ENDPOINT_SEND),
        ];
        let mut receipts = [operation(&snapshot, 0, tap::ENDPOINT_RECV); 2];
        ordinals(&mut sends);
        ordinals(&mut receipts);
        let sending = Capture::new(&sends, Some(2)).unwrap();
        let receiving = Capture::new(&receipts, Some(2)).unwrap();
        let one_receive = Capture::new(&receipts[..1], Some(1)).unwrap();
        for inputs in [&[receiving][..], &[sending, receiving]] {
            workspace.resize(protocol.delivery_workspace_len(inputs), 0);
            assert!(matches!(
                protocol.deliveries(inputs, &mut workspace),
                Err(DeliveryError::Unmatched { .. })
            ));
        }
        for inputs in [
            &[sending, sending, one_receive][..],
            &[sending, one_receive, one_receive],
        ] {
            workspace.resize(protocol.delivery_workspace_len(inputs), 0);
            assert!(matches!(
                protocol.deliveries(inputs, &mut workspace),
                Err(DeliveryError::Ambiguous {
                    session: 1,
                    source: 0
                })
            ));
        }
        let publication_only = Capture::new(&sends[1..], Some(1));
        assert!(
            publication_only.is_err(),
            "capture ordinals are checked independently"
        );
        let mut missing_poll = [sends[1]];
        ordinals(&mut missing_poll);
        let inputs = [Capture::new(&missing_poll, Some(1)).unwrap(), one_receive];
        workspace.resize(protocol.delivery_workspace_len(&inputs), 0);
        assert!(matches!(
            protocol.deliveries(&inputs, &mut workspace),
            Err(DeliveryError::History { producer: 0, .. })
        ));
    }

    #[test]
    fn individually_matching_frames_can_still_form_a_cross_producer_causal_cycle() {
        let global = g::par(
            g::send::<0, 1, g::Msg<7, ()>>(),
            g::send::<1, 0, g::Msg<8, ()>>(),
        );
        let snapshot: Vec<_> = tap::projected(&project::<0>(&global)).collect();
        let mut source_storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut source_storage).unwrap();
        let mut first = [
            operation(&snapshot, 1, tap::ENDPOINT_RECV),
            operation(&snapshot, 0, tap::SEND_POLL),
            operation(&snapshot, 0, tap::ENDPOINT_SEND),
        ];
        let mut second = [
            operation(&snapshot, 0, tap::ENDPOINT_RECV),
            operation(&snapshot, 1, tap::SEND_POLL),
            operation(&snapshot, 1, tap::ENDPOINT_SEND),
        ];
        ordinals(&mut first);
        ordinals(&mut second);
        let inputs = [
            Capture::new(&first, Some(3)).unwrap(),
            Capture::new(&second, Some(3)).unwrap(),
        ];
        let mut workspace = std::vec![0; protocol.delivery_workspace_len(&inputs)];
        assert!(matches!(
            protocol.deliveries(&inputs, &mut workspace),
            Err(DeliveryError::Cycle)
        ));
        // Move both receives after their own poll. Both sender publications
        // can still follow the remote receives; no total clock is imposed.
        first.swap(0, 1);
        second.swap(0, 1);
        ordinals(&mut first);
        ordinals(&mut second);
        let inputs = [
            Capture::new(&first, Some(3)).unwrap(),
            Capture::new(&second, Some(3)).unwrap(),
        ];
        assert_eq!(
            protocol
                .deliveries(&inputs, &mut workspace)
                .unwrap()
                .count(),
            2
        );
    }

    #[test]
    fn the_order_certificate_must_preserve_both_producer_and_delivery_edges() {
        let offsets = [0, 2, 4];
        let links = [0, 3, 0, 0]; // sender ordinal 1 precedes receiver ordinal 0
        let mut ranks = [usize::MAX; 4];
        check_causal_order(&offsets, &links, &[0, 1, 2, 3], &mut ranks).unwrap();
        // Both are permutations; one reverses a producer edge, the other a
        // delivery edge. A permutation check alone would accept both.
        for order in [[1, 0, 2, 3], [0, 2, 1, 3], [0, 1, 2, 4], [0, 1, 2, 2]] {
            assert_eq!(
                check_causal_order(&offsets, &links, &order, &mut ranks),
                Err(DeliveryError::Cycle)
            );
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn causal_sort_matches_independent_reachability_for_all_small_graphs() {
        for count in 0usize..=4 {
            let partitions = if count == 0 { 1 } else { 1 << (count - 1) };
            for cuts in 0..partitions {
                let mut offsets = vec![0, 0]; // include empty producer captures
                for boundary in 1..count {
                    if cuts & (1 << (boundary - 1)) != 0 {
                        offsets.push(boundary);
                    }
                }
                offsets.extend([count, count]);
                for mut encoding in 0..(count + 1).pow(count as u32) {
                    let mut links = vec![0; count];
                    for link in &mut links {
                        *link = encoding % (count + 1);
                        encoding /= count + 1;
                    }
                    let mut reachable = vec![vec![false; count]; count];
                    for interval in offsets.windows(2) {
                        for (before, after) in
                            (interval[0]..interval[1]).zip(interval[0] + 1..interval[1])
                        {
                            reachable[before][after] = true;
                        }
                    }
                    for (before, &after) in links.iter().enumerate() {
                        if after != 0 {
                            reachable[before][after - 1] = true;
                        }
                    }
                    for via in 0..count {
                        let via_row = reachable[via].clone();
                        for before in &mut reachable {
                            let enters = before[via];
                            for (after, found) in before.iter_mut().enumerate() {
                                *found |= enters && via_row[after];
                            }
                        }
                    }
                    let acyclic = (0..count).all(|index| !reachable[index][index]);
                    let mut order = vec![usize::MAX; count];
                    let mut ranks = vec![usize::MAX; count];
                    assert_eq!(
                        causal_order(&offsets, &links, &mut order, &mut ranks).is_ok(),
                        acyclic
                    );
                    if acyclic {
                        check_causal_order(&offsets, &links, &order, &mut ranks).unwrap();
                        if count >= 2 {
                            order[1] = order[0];
                            assert_eq!(
                                check_causal_order(&offsets, &links, &order, &mut ranks),
                                Err(DeliveryError::Cycle)
                            );
                        }
                    }
                }
            }
        }
    }
}
