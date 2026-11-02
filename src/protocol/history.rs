//! Link already observed transport polls and publications. Source eligibility
//! and cross-producer delivery require further checks on this correspondence.
use super::{Layout, Protocol, contains_actor};
use crate::Capture;
use hibana::runtime::tap::{self, TapEvent};

/// A malformed operation record, inconsistent send boundary or insufficient
/// caller-owned space for retrospective correspondence checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryError {
    /// This observation disagrees with the compiled source or its earlier polls.
    Record { index: usize },
    /// Words needed for record links, scope sorting and actor-reference membership.
    Workspace { required: usize, actual: usize },
}

/// The checked polls of one send and its publication, when present.
///
/// The records remain borrowed from a complete capture. An unfinished or failed
/// send has no publication. Neither a poll nor this correspondence establishes
/// physical acceptance, source eligibility, receipt or session completion.
#[derive(Clone, Copy, Debug)]
pub struct SendCall<'a> {
    records: &'a [TapEvent],
    next: &'a [usize],
    publication: Option<&'a TapEvent>,
}

impl<'a> SendCall<'a> {
    /// The first observed poll of this operation.
    pub fn first_poll(&self) -> TapEvent {
        self.records[0]
    }

    /// All its polls, preserving their producer's original ordinals.
    pub fn polls(&self) -> impl Iterator<Item = TapEvent> + 'a {
        let records = self.records;
        let next = self.next;
        let mut at = Some(0);
        core::iter::from_fn(move || {
            let index = at?;
            at = next[index].checked_sub(1);
            Some(records[index])
        })
    }

    /// Sender publication, which can follow a receiver's commit.
    pub fn publication(&self) -> Option<TapEvent> {
        self.publication.copied()
    }
}

impl Protocol<'_> {
    /// Workspace words for `send_calls`: four per capture record, two per
    /// source event, one per scope marker and one bit per actor decision.
    pub fn send_call_workspace_len(&self, capture: Capture<'_>) -> usize {
        let layout = Layout::checked(*self);
        4 * capture.records().len()
            + 2 * layout.sources.len()
            + layout.scopes.len()
            + layout.actor_words()
    }

    /// Recover this producer's send boundaries in first-poll order.
    ///
    /// All Endpoint records are checked against the supplied compiled source:
    /// source identity, direction, logical view, lane and possible actor. A
    /// prepared reset must name an enclosing compiled roll. A changed preparation
    /// needs an intervening observed roll reset covering that event, on the same
    /// actor and run. The preparation is rechecked on each poll; it is not a call
    /// identity or a visit number. A transport publication needs
    /// earlier polls and consumes them once. Local unit actions create no call.
    ///
    /// The capture may include several runs of the same compiled protocol. Its
    /// association to the executable must come from the saved build evidence.
    /// Actor candidates are static possibilities; chosen ownership, route/roll
    /// eligibility and delivery across producers are not checked here. Safe
    /// Endpoint borrowing prevents two unpublished calls with the same actor,
    /// run, logical view and source event from overlapping.
    ///
    /// This checks the entire input before yielding any calls. Storage is
    /// derived from record and decision counts; no allocator is used. Building
    /// links takes O((N + M) log(N + M) + N log(E + 1) + A D), for N capture
    /// records, E source events, M scope markers, A observed actors and D decisions.
    /// The returned iterator borrows the link storage. Reset records are checked
    /// for static membership; their dynamic eligibility still requires replay.
    pub fn send_calls<'a: 'w, 'w>(
        &self,
        capture: Capture<'a>,
        workspace: &'w mut [usize],
    ) -> Result<impl Iterator<Item = SendCall<'w>> + 'w, HistoryError> {
        let required = self.send_call_workspace_len(capture);
        if workspace.len() < required {
            return Err(HistoryError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let records = capture.records();
        let count = records.len();
        let layout = Layout::checked(*self);
        let (next, rest) = workspace[..required].split_at_mut(count);
        let (ends, rest) = rest.split_at_mut(count);
        let (order, rest) = rest.split_at_mut(count);
        let (resets, rest) = rest.split_at_mut(count);
        let (cover, rest) = rest.split_at_mut(2 * layout.sources.len());
        let (rolls, actors) = rest.split_at_mut(layout.scopes.len());
        let mut markers = 0;
        for index in layout.scopes.clone() {
            if self.records[index].causal_key() >> 13 == 1 {
                rolls[markers] = index;
                markers += 1;
            }
        }
        let rolls = &mut rolls[..markers];
        rolls.sort_unstable_by_key(|&index| (self.records[index].causal_key(), index));
        next.fill(0);
        ends.fill(0);
        let mut operations = 0;
        for (index, record) in records.iter().enumerate() {
            if is_operation(*record) {
                order[operations] = index;
                operations += 1;
            }
        }
        let sorted = &mut order[..operations];
        sorted.sort_unstable_by_key(|&index| (key(records[index]), index));
        let mut actor = None;
        let mut group = None;
        let mut active: Option<usize> = None;
        let mut last_poll: Option<usize> = None;
        for &index in sorted.iter() {
            let record = records[index];
            let identity = key(record);
            if actor != Some(identity.0) {
                layout.select_actor(self.records, identity.0, actors);
                actor = Some(identity.0);
            }
            if group != Some(identity) {
                group = Some(identity);
                active = None;
                last_poll = None;
            }
            let local = layout.check_observed_operation(self.records, record, actors)?;
            if local {
                continue;
            }
            if record.id() == tap::SEND_POLL {
                let reset = (record.arg1() >> 16) as u16;
                if reset != u16::MAX {
                    let at =
                        rolls.partition_point(|&index| self.records[index].causal_key() < reset);
                    let interval = rolls.get(at..at + 2);
                    if !matches!(interval, Some([start, end])
                        if self.records[*start].causal_key() == reset
                            && self.records[*end].causal_key() == reset
                            && self.records[*start].arg0() <= u32::from(identity.3)
                            && u32::from(identity.3) < self.records[*end].arg0())
                    {
                        return Err(HistoryError::Record { index });
                    }
                }
                let start = match active {
                    Some(start) => start,
                    None => {
                        active = Some(index);
                        // Capture ordinals cannot reach usize::MAX. Reserve it
                        // for an observed call with no publication in the prefix.
                        ends[index] = usize::MAX;
                        index
                    }
                };
                if let Some(previous) = last_poll {
                    next[previous] = index - start + 1;
                }
                last_poll = Some(index);
            } else if record.causal_key() as u8 == 1 {
                let Some(start) = active.take() else {
                    return Err(HistoryError::Record { index });
                };
                ends[start] = index + 1;
                last_poll = None;
            }
        }
        self.check_call_links(capture, (next, ends), order)?;
        // Index only observed resets. A range update records the latest reset
        // covering each source event; it grants no Endpoint permission.
        cover.fill(0);
        let mut indexed = 0;
        for (index, record) in records.iter().enumerate() {
            if record.id() == tap::SEND_POLL
                || (record.id() == tap::SCOPE_REENTRY && record.arg1() >> 29 == 1)
            {
                order[indexed] = index;
                indexed += 1;
            }
        }
        let sorted = &mut order[..indexed];
        sorted.sort_unstable_by_key(|&index| {
            let record = records[index];
            (record.causal_key() >> 8, record.arg0(), index)
        });
        actor = None;
        for &index in sorted.iter() {
            let record = records[index];
            if record.id() == tap::SEND_POLL {
                resets[index] = last_reset(cover, records, index);
            } else {
                let current_actor = (record.causal_key() >> 8) as u8;
                if actor != Some(current_actor) {
                    layout.select_actor(self.records, current_actor, actors);
                    actor = Some(current_actor);
                }
                let reset = (record.arg1() >> 16) as u16;
                let at = rolls.partition_point(|&index| self.records[index].causal_key() < reset);
                let Some([start, end]) = rolls.get(at..at + 2) else {
                    return Err(HistoryError::Record { index });
                };
                let start = self.records[*start];
                let end = self.records[*end];
                let event = usize::from(record.arg1() as u16);
                if start.causal_key() != reset
                    || end.causal_key() != reset
                    || event < start.arg0() as usize
                    || event >= end.arg0() as usize
                    || !layout.reset_actor_matches(self.records, record, actors)
                {
                    return Err(HistoryError::Record { index });
                }
                mark_reset(cover, start.arg0() as usize..end.arg0() as usize, index + 1);
            }
        }
        for (start, &end) in ends.iter().enumerate() {
            if end == 0 {
                continue;
            }
            let mut before = start;
            while let Some(after) = next[before].checked_sub(1) {
                let after = start + after;
                if records[before].arg1() != records[after].arg1() && resets[after] <= before + 1 {
                    return Err(HistoryError::Record { index: after });
                }
                before = after;
            }
        }
        let next: &'w [usize] = next;
        let ends: &'w [usize] = ends;
        Ok(records
            .iter()
            .enumerate()
            .filter_map(move |(index, record)| {
                if record.id() != tap::SEND_POLL || ends[index] == 0 {
                    return None;
                }
                let (end, publication) = match ends[index] {
                    usize::MAX => (count, None),
                    end => (end - 1, Some(&records[end - 1])),
                };
                Some(SendCall {
                    records: &records[index..end],
                    next: &next[index..end],
                    publication,
                })
            }))
    }

    // Check the produced links directly. This does not repeat the grouping
    // algorithm: chains must move forward, cover every poll exactly once, use
    // each publication once, and have disjoint intervals for each call key.
    fn check_call_links(
        &self,
        capture: Capture<'_>,
        (next, ends): (&[usize], &[usize]),
        workspace: &mut [usize],
    ) -> Result<(), HistoryError> {
        let records = capture.records();
        let count = records.len();
        if next.len() != count || ends.len() != count || workspace.len() < count {
            return Err(HistoryError::Record { index: count });
        }
        let seen = &mut workspace[..count.div_ceil(usize::BITS as usize)];
        seen.fill(0);
        for (start, &end) in ends.iter().enumerate() {
            if end == 0 {
                continue;
            }
            let limit = if end == usize::MAX { count } else { end - 1 };
            let first = records[start];
            if first.id() != tap::SEND_POLL || limit <= start || limit > count {
                return Err(HistoryError::Record { index: start });
            }
            let mut at = 0;
            loop {
                if at >= limit - start {
                    return Err(HistoryError::Record { index: start });
                }
                let index = start + at;
                let poll = records[index];
                if poll.id() != tap::SEND_POLL
                    || poll.causal_key() != first.causal_key()
                    || poll.arg0() != first.arg0()
                    || poll.arg1() as u16 != first.arg1() as u16
                    || !mark_once(seen, index)
                {
                    return Err(HistoryError::Record { index });
                }
                let Some(after) = next[index].checked_sub(1) else {
                    break;
                };
                if after <= at {
                    return Err(HistoryError::Record { index });
                }
                at = after;
            }
            if end != usize::MAX {
                let Some(publication) = records.get(limit) else {
                    return Err(HistoryError::Record { index: start });
                };
                if !matches!(publication.id(), tap::ENDPOINT_SEND | tap::ENDPOINT_SESSION)
                    || publication.causal_key() as u8 != 1
                    || publication.causal_key() >> 8 != first.causal_key() >> 8
                    || publication.arg0() != first.arg0()
                    || publication.arg1() >> 24 != u32::from(first.causal_key() as u8)
                    || publication.arg1() as u16 != first.arg1() as u16
                    || !mark_once(seen, limit)
                {
                    return Err(HistoryError::Record { index: limit });
                }
            }
        }
        let layout = Layout::checked(*self);
        for (index, record) in records.iter().enumerate() {
            let publication = matches!(record.id(), tap::ENDPOINT_SEND | tap::ENDPOINT_SESSION)
                && record.causal_key() as u8 == 1;
            let wire_publication = if publication {
                let source_index = layout.sources.start + usize::from(record.arg1() as u16);
                if source_index >= layout.sources.end {
                    return Err(HistoryError::Record { index });
                }
                let source = self.records[source_index];
                source.arg0() >> 24 != ((source.arg0() >> 16) & 255)
            } else {
                false
            };
            let required = record.id() == tap::SEND_POLL || wire_publication;
            let present =
                seen[index / usize::BITS as usize] & (1 << (index % usize::BITS as usize)) != 0;
            if required != present {
                return Err(HistoryError::Record { index });
            }
        }
        let mut roots = 0;
        for (index, &end) in ends.iter().enumerate() {
            if end != 0 {
                workspace[roots] = index;
                roots += 1;
            }
        }
        let roots = &mut workspace[..roots];
        roots.sort_unstable_by_key(|&index| (key(records[index]), index));
        for pair in roots.windows(2) {
            let [before, after] = [pair[0], pair[1]];
            if key(records[before]) == key(records[after]) && ends[before] > after {
                return Err(HistoryError::Record { index: after });
            }
        }
        Ok(())
    }
}

fn mark_once(seen: &mut [usize], index: usize) -> bool {
    let word = &mut seen[index / usize::BITS as usize];
    let bit = 1 << (index % usize::BITS as usize);
    if *word & bit != 0 {
        return false;
    }
    *word |= bit;
    true
}

fn mark_reset(cover: &mut [usize], range: core::ops::Range<usize>, record: usize) {
    let events = cover.len() / 2;
    let (mut left, mut right) = (range.start + events, range.end + events);
    while left < right {
        if left % 2 != 0 {
            cover[left] = record;
            left += 1;
        }
        if right % 2 != 0 {
            right -= 1;
            cover[right] = record;
        }
        left /= 2;
        right /= 2;
    }
}

fn last_reset(cover: &[usize], records: &[TapEvent], index: usize) -> usize {
    let query = records[index];
    let mut at = cover.len() / 2 + usize::from(query.arg1() as u16);
    let mut found = 0;
    while at != 0 {
        if let Some(reset) = cover[at].checked_sub(1) {
            let candidate = records[reset];
            // Earlier actor/run groups may retain nodes. Their observations
            // never justify a change in this group's prepared send.
            if candidate.causal_key() >> 8 == query.causal_key() >> 8
                && candidate.arg0() == query.arg0()
            {
                found = found.max(reset + 1);
            }
        }
        at /= 2;
    }
    found
}

fn is_operation(record: TapEvent) -> bool {
    matches!(
        record.id(),
        tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ENDPOINT_SESSION
    )
}

fn key(record: TapEvent) -> (u8, u32, u8, u16) {
    let view = if record.id() == tap::SEND_POLL {
        record.causal_key() as u8
    } else {
        (record.arg1() >> 24) as u8
    };
    (
        (record.causal_key() >> 8) as u8,
        record.arg0(),
        view,
        record.arg1() as u16,
    )
}

impl Layout {
    fn reset_actor_matches(
        &self,
        snapshot: &[TapEvent],
        reset: TapEvent,
        candidates: &[usize],
    ) -> bool {
        let event = usize::from(reset.arg1() as u16);
        let source = snapshot[self.sources.start + event];
        let view = reset.causal_key() as u8;
        let from = (source.arg0() >> 24) as u8;
        let to = (source.arg0() >> 16) as u8;
        let reference = if self.bindings.is_empty() {
            u32::from(view)
        } else {
            let binding = snapshot[self.bindings.start + event];
            if view == from {
                binding.arg0()
            } else {
                binding.arg1()
            }
        };
        (view == from || view == to)
            && contains_actor(reference, reset.causal_key() >> 8, candidates)
    }

    fn checked(protocol: Protocol<'_>) -> Self {
        match Self::read(protocol.records) {
            Ok(layout) => layout,
            Err(_) => unreachable!("Protocol retains checked immutable headers"),
        }
    }

    fn select_actor(&self, records: &[TapEvent], actor: u8, candidates: &mut [usize]) {
        candidates.fill(0);
        for (index, decision) in records[self.decisions.clone()].iter().enumerate() {
            if contains_actor(decision.arg0(), u16::from(actor), candidates)
                || contains_actor(decision.arg1(), u16::from(actor), candidates)
            {
                candidates[index / usize::BITS as usize] |= 1 << (index % usize::BITS as usize);
            }
        }
    }

    fn check_observed_operation(
        &self,
        snapshot: &[TapEvent],
        record: TapEvent,
        candidates: &[usize],
    ) -> Result<bool, HistoryError> {
        let index = record.ts() as usize;
        let (actor, _, view, event) = key(record);
        let source_index = self.sources.start + usize::from(event);
        if source_index >= self.sources.end {
            return Err(HistoryError::Record { index });
        }
        let source = snapshot[source_index];
        let from = (source.arg0() >> 24) as u8;
        let to = (source.arg0() >> 16) as u8;
        let poll = record.id() == tap::SEND_POLL;
        let direction = if poll { 1 } else { record.causal_key() as u8 };
        let sender = direction == 1;
        let reference = if self.bindings.is_empty() {
            u32::from(if sender { from } else { to })
        } else {
            let binding = snapshot[self.bindings.start + usize::from(event)];
            if sender {
                binding.arg0()
            } else {
                binding.arg1()
            }
        };
        let origin = source.causal_key() as u8;
        let origin_matches = match record.id() {
            tap::SEND_POLL => true,
            tap::ENDPOINT_SEND => sender && origin == 0,
            tap::ENDPOINT_RECV => !sender && origin == 0,
            tap::ENDPOINT_SESSION => origin == 1,
            _ => false,
        };
        let local = from == to;
        if !matches!(direction, 1 | 2)
            || !origin_matches
            || view != if sender { from } else { to }
            || !contains_actor(reference, u16::from(actor), candidates)
            || (local && (source.causal_key() >> 8 != 0 || source.arg1() != 0 || poll))
            || (!poll && (record.arg1() >> 16) as u8 != (source.arg0() >> 8) as u8)
        {
            return Err(HistoryError::Record { index });
        }
        Ok(local)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use hibana::{g, runtime::program::project};
    use std::{vec, vec::Vec};

    // Synthetic table checks supplement the actual Endpoint integration tests.
    // No transport acceptance or successful source execution is inferred here.
    fn records(points: &[(u16, u32)]) -> Vec<TapEvent> {
        points
            .iter()
            .enumerate()
            .map(|(index, &(id, detail))| {
                let mut bytes = [0; 16];
                bytes[..4].copy_from_slice(&(index as u32).to_be_bytes());
                bytes[4..6].copy_from_slice(&id.to_be_bytes());
                bytes[7] = u8::from(id == tap::ENDPOINT_SEND);
                bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
                bytes[12..16].copy_from_slice(&detail.to_be_bytes());
                TapEvent::from(bytes)
            })
            .collect()
    }

    #[test]
    fn link_checker_rejects_lost_polls_cycles_and_reused_publications() {
        type Message = g::Msg<7, ()>;
        let global = g::send::<0, 1, Message>().roll();
        let program = project::<0>(&global);
        let snapshot: Vec<_> = tap::projected(&program).collect();
        let mut work = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut work).unwrap();
        let records = records(&[
            (tap::SEND_POLL, 0xffff_0000),
            (tap::SEND_POLL, 0xffff_0000),
            (tap::ENDPOINT_SEND, 0),
            (tap::SEND_POLL, 0x2000_0000),
            (tap::SEND_POLL, 0x2000_0000),
            (tap::ENDPOINT_SEND, 0),
        ]);
        let capture = Capture::new(&records, Some(6)).unwrap();
        work.resize(records.len(), 0);
        protocol
            .check_call_links(
                capture,
                (&[2, 0, 0, 2, 0, 0], &[3, 0, 0, 6, 0, 0]),
                &mut work,
            )
            .unwrap();
        for mutation in 0..7 {
            let mut next = [2, 0, 0, 2, 0, 0];
            let mut ends = [3, 0, 0, 6, 0, 0];
            match mutation {
                0 => next[0] = 1,
                1 => next[0] = usize::MAX,
                2 => next[0] = 0,
                3 => ends[0] = 0,
                4 => ends[0] = 6,
                5 => ends[2] = 3,
                6 => next[0] = 3,
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    protocol.check_call_links(capture, (&next, &ends), &mut work),
                    Err(HistoryError::Record { .. })
                ),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn link_checker_rejects_overlapping_calls_with_complete_unique_coverage() {
        type Message = g::Msg<7, ()>;
        let global = g::send::<0, 1, Message>().roll();
        let program = project::<0>(&global);
        let snapshot: Vec<_> = tap::projected(&program).collect();
        let mut work = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut work).unwrap();
        let records = records(&[
            (tap::SEND_POLL, 0xffff_0000),
            (tap::SEND_POLL, 0xffff_0000),
            (tap::ENDPOINT_SEND, 0),
            (tap::ENDPOINT_SEND, 0),
        ]);
        let capture = Capture::new(&records, Some(4)).unwrap();
        work.resize(records.len(), 0);
        assert!(matches!(
            protocol.check_call_links(capture, (&[0; 4], &[3, 4, 0, 0]), &mut work),
            Err(HistoryError::Record { index: 1 })
        ));
    }

    #[test]
    fn reset_range_index_matches_linear_updates_across_producer_groups() {
        // Synthetic intervals exercise the index itself. Actual compiled scope
        // and Endpoint records are checked by the integration tests.
        for events in 1..=7 {
            let mut records = Vec::new();
            for (actor, sid) in [(1u8, 2u32), (1, 1), (0, 2), (0, 1)] {
                for start in 0..events {
                    for end in start + 1..=events {
                        for (id, detail) in core::iter::once((
                            tap::SCOPE_REENTRY,
                            ((start as u32) << 16) | end as u32,
                        ))
                        .chain((0..events).map(|event| (tap::SEND_POLL, event as u32)))
                        {
                            let mut bytes = [0; 16];
                            bytes[..4].copy_from_slice(&(records.len() as u32).to_be_bytes());
                            bytes[4..6].copy_from_slice(&id.to_be_bytes());
                            bytes[6] = actor;
                            bytes[8..12].copy_from_slice(&sid.to_be_bytes());
                            bytes[12..16].copy_from_slice(&detail.to_be_bytes());
                            records.push(TapEvent::from(bytes));
                        }
                    }
                }
            }
            let mut sorted: Vec<_> = (0..records.len()).collect();
            sorted.sort_unstable_by_key(|&index| {
                let record = records[index];
                (record.causal_key() >> 8, record.arg0(), index)
            });
            let mut cover = vec![0; 2 * events];
            let mut expected = vec![0; events];
            let mut group = None;
            for index in sorted {
                let record = records[index];
                let current = (record.causal_key() >> 8, record.arg0());
                if group != Some(current) {
                    expected.fill(0);
                    group = Some(current);
                }
                if record.id() == tap::SCOPE_REENTRY {
                    let start = (record.arg1() >> 16) as usize;
                    let end = usize::from(record.arg1() as u16);
                    mark_reset(&mut cover, start..end, index + 1);
                    expected[start..end].fill(index + 1);
                } else {
                    assert_eq!(
                        last_reset(&cover, &records, index),
                        expected[record.arg1() as usize]
                    );
                }
            }
        }
    }
}
