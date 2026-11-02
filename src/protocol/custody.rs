//! Replay Endpoint transfers in a witnessed causal order of complete captures.
use super::{HistoryError, Layout, Protocol, RecordId};
use crate::Capture;
use hibana::runtime::tap::{self, TapEvent};

/// Captured operations do not preserve the delegated role's exclusive custody
/// in the supplied ordering, or the ordering is not a complete causal witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyError {
    /// One capture failed the checked source-membership and send-call rules.
    History {
        producer: usize,
        error: HistoryError,
    },
    /// Temporary words needed for replay.
    Workspace { required: usize, actual: usize },
    /// The ordering omits, repeats or reverses a producer's observation.
    Order { position: usize },
    /// A successful wire receive has no earlier unused send call.
    Unmatched { receive: RecordId },
    /// This actor used or transferred a role it did not hold at this boundary.
    Owner { record: RecordId, role: u8 },
    /// Resolver evidence names no compiled choice authority.
    Resolver { record: RecordId },
}

impl Protocol<'_> {
    /// Words needed to check custody. Space depends on the actual capture sizes,
    /// compiled initial bindings and existing send-call checker's requirements.
    pub fn custody_workspace_len(&self, captures: &[Capture<'_>]) -> usize {
        let records: usize = captures.iter().map(|capture| capture.records().len()).sum();
        4 * records
            + captures.len()
            + 1
            + Layout::checked(*self).initial.len()
            + captures
                .iter()
                .map(|&capture| self.send_call_workspace_len(capture))
                .max()
                .unwrap_or(0)
    }

    /// Replay delegated-role custody in one proposed ordering of observations.
    ///
    /// `order` must contain every capture record exactly once and preserve each
    /// producer's ordinal order. It is a witness, not a distributed clock. The
    /// affine FIFO transport contract pairs each receive with the earliest
    /// unmatched send of that source occurrence in this ordering. Repeated polls
    /// belong to the same checked call and do not create another transfer.
    ///
    /// The first poll of a transfer takes its resource out of the sender's
    /// custody. Only the corresponding committed receive grants it to the
    /// recipient; sender publication can happen later. Every observed operation
    /// and reentry through a delegated view needs that view's current holder.
    /// An unfinished transfer stays unavailable. No Endpoint is issued, restored
    /// or authorized by this retrospective checker.
    ///
    /// Success establishes custody in this witnessed order. Route choice and
    /// source-order/roll eligibility require the source-execution check as well;
    /// this method alone does not establish full dynamic protocol conformance.
    pub fn check_custody(
        &self,
        captures: &[Capture<'_>],
        order: &[RecordId],
        workspace: &mut [usize],
    ) -> Result<(), CustodyError> {
        let required = self.custody_workspace_len(captures);
        if workspace.len() < required {
            return Err(CustodyError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let count: usize = captures.iter().map(|capture| capture.records().len()).sum();
        if order.len() != count {
            return Err(CustodyError::Order {
                position: order.len().min(count),
            });
        }
        let layout = Layout::checked(*self);
        let (ranks, rest) = workspace[..required].split_at_mut(count);
        let (roots, rest) = rest.split_at_mut(count);
        let (links, rest) = rest.split_at_mut(count);
        let (sessions, rest) = rest.split_at_mut(count);
        let (offsets, rest) = rest.split_at_mut(captures.len() + 1);
        let (holders, scratch) = rest.split_at_mut(layout.initial.len());
        offsets[0] = 0;
        roots.fill(0);
        links.fill(0);
        ranks.fill(usize::MAX);
        for (producer, &capture) in captures.iter().enumerate() {
            let base = offsets[producer];
            offsets[producer + 1] = base + capture.records().len();
            for call in self
                .send_calls(capture, scratch)
                .map_err(|error| CustodyError::History { producer, error })?
            {
                let root = base + call.first_poll().ts() as usize;
                for poll in call.polls() {
                    roots[base + poll.ts() as usize] = root + 1;
                }
                if let Some(publication) = call.publication() {
                    roots[base + publication.ts() as usize] = root + 1;
                }
            }
        }
        let index_of = |id: RecordId| {
            let capture = captures.get(id.producer)?;
            (id.ordinal < capture.records().len()).then(|| offsets[id.producer] + id.ordinal)
        };
        for (position, &id) in order.iter().enumerate() {
            let Some(index) = index_of(id) else {
                return Err(CustodyError::Order { position });
            };
            if ranks[index] != usize::MAX || (id.ordinal != 0 && ranks[index - 1] >= position) {
                return Err(CustodyError::Order { position });
            }
            ranks[index] = position;
        }
        let record_at = |id: RecordId| captures[id.producer].records()[id.ordinal];
        // Match in the witnessed order. No producer's unrelated ordinal is
        // compared with another producer's ordinal to infer delivery order.
        let mut session_count = 0;
        for (position, &id) in order.iter().enumerate() {
            let record = record_at(id);
            if !operation(record)
                && !matches!(record.id(), tap::SCOPE_REENTRY | tap::RESOLVER_AUDIT)
            {
                continue;
            }
            sessions[session_count] = record.arg0() as usize;
            session_count += 1;
            if !receive(record) {
                continue;
            }
            let source = self.records[layout.sources.start + usize::from(record.arg1() as u16)];
            if source.arg0() >> 24 == (source.arg0() >> 16) & 255 {
                continue;
            }
            let sender = order[..position].iter().copied().find(|&candidate| {
                let index = index_of(candidate).unwrap();
                let poll = record_at(candidate);
                poll.id() == tap::SEND_POLL
                    && roots[index] == index + 1
                    && links[index] == 0
                    && poll.arg0() == record.arg0()
                    && poll.arg1() as u16 == record.arg1() as u16
            });
            let Some(sender) = sender else {
                return Err(CustodyError::Unmatched { receive: id });
            };
            let first = index_of(sender).unwrap();
            let received = index_of(id).unwrap();
            roots[received] = first + 1;
            links[first] = received + 1;
        }
        let sessions = &mut sessions[..session_count];
        sessions.sort_unstable();
        let mut previous = None;
        for &session in sessions.iter() {
            if previous == Some(session) {
                continue;
            }
            previous = Some(session);
            for (held, initial) in holders
                .iter_mut()
                .zip(&self.records[layout.initial.clone()])
            {
                *held = initial.arg1() as usize;
            }
            for &id in order {
                let record = record_at(id);
                if record.arg0() as usize != session
                    || (!operation(record)
                        && !matches!(record.id(), tap::SCOPE_REENTRY | tap::RESOLVER_AUDIT))
                {
                    continue;
                }
                let index = index_of(id).unwrap();
                let actor = (record.causal_key() >> 8) as usize;
                let view = if record.id() == tap::RESOLVER_AUDIT {
                    let choice = self.records[layout.choices.clone()]
                        .iter()
                        .find(|choice| u32::from(choice.causal_key()) == record.arg1() >> 16)
                        .ok_or(CustodyError::Resolver { record: id })?;
                    choice.arg0() as u8
                } else if matches!(record.id(), tap::SEND_POLL | tap::SCOPE_REENTRY) {
                    record.causal_key() as u8
                } else {
                    (record.arg1() >> 24) as u8
                };
                if let Some(resource) = self.records[layout.initial.clone()]
                    .iter()
                    .position(|initial| initial.arg0() == u32::from(view))
                    && holders[resource] != actor
                {
                    return Err(CustodyError::Owner {
                        record: id,
                        role: view,
                    });
                }
                if record.id() == tap::RESOLVER_AUDIT
                    && !self.records[layout.initial.clone()]
                        .iter()
                        .any(|initial| initial.arg0() == u32::from(view))
                    && actor != usize::from(view)
                {
                    return Err(CustodyError::Owner {
                        record: id,
                        role: view,
                    });
                }
                if !operation(record) {
                    continue;
                }
                let source = self.records[layout.sources.start + usize::from(record.arg1() as u16)];
                if source.causal_key() >> 8 == 0 {
                    continue;
                }
                let role = source.arg1() as u8;
                let resource = self.records[layout.initial.clone()]
                    .iter()
                    .position(|initial| initial.arg0() == u32::from(role))
                    .expect("checked snapshot has an initial binding for every transferred role");
                if record.id() == tap::SEND_POLL && roots[index] == index + 1 {
                    if holders[resource] != actor {
                        return Err(CustodyError::Owner { record: id, role });
                    }
                    // Actors occupy 0..256. Larger values name the concrete
                    // checked send call whose receive may next acquire this role.
                    holders[resource] = 256 + index;
                } else if receive(record) {
                    let first = roots[index] - 1;
                    if holders[resource] != 256 + first {
                        return Err(CustodyError::Owner { record: id, role });
                    }
                    holders[resource] = actor;
                }
            }
        }
        Ok(())
    }
}

fn operation(record: TapEvent) -> bool {
    matches!(
        record.id(),
        tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ENDPOINT_SESSION
    )
}

fn receive(record: TapEvent) -> bool {
    matches!(record.id(), tap::ENDPOINT_RECV | tap::ENDPOINT_SESSION)
        && record.causal_key() as u8 == 2
}
