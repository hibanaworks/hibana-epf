//! Connect complete runtime captures to one checked finite source execution.
use super::{Layout, RecordId, RouteHistoryError, SourcePath, SourcePoint, WordError};
use crate::Capture;
use hibana::runtime::tap::{self, TapEvent};

/// A proposed acceptance boundary supported by a checked publication or receipt.
///
/// This is an execution witness, not an observed timestamp. A transport poll
/// alone cannot support it. The call must have a successful publication or a
/// FIFO-matched receipt somewhere in the complete supplied capture prefixes.
#[derive(Clone, Copy, Debug)]
pub struct Acceptance {
    /// The first poll of this checked send call, not a later retry.
    pub first_poll: RecordId,
    /// Boundary before this position in `ExecutionWitness::order`.
    pub before: usize,
}

/// Retrospective correspondence for one session in complete producer captures.
///
/// The source unfolding and selections come from the receiving `SourcePath`.
/// These inputs grant no application authority and never drive an Endpoint.
pub struct ExecutionWitness<'a> {
    /// One session run; other runs require their own source witness.
    pub session: u32,
    /// Every capture record once, preserving producer ordinals and deliveries.
    pub order: &'a [RecordId],
    /// Expanded source event for each ordered operation or control record of
    /// this session. Other observations, including other sessions, use None.
    pub occurrences: &'a [Option<usize>],
    /// Acceptance boundaries in nondecreasing `before` order.
    pub acceptances: &'a [Acceptance],
}

/// Captures cannot be interpreted as the proposed selected source execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    /// Capture correspondence, custody or observed route agreement failed.
    History(RouteHistoryError),
    /// One occurrence entry is required per record in the complete order.
    Length { expected: usize, actual: usize },
    /// Caller-owned evidence and source-word storage is too short.
    Workspace { required: usize, actual: usize },
    /// Required storage cannot be represented on this target.
    Overflow,
    /// A record has no matching selected source occurrence or reuses another
    /// call's occurrence. `position` indexes the witness order.
    Record { position: usize },
    /// A proposed acceptance lacks its call, completion or valid boundary.
    Acceptance { index: usize },
    /// The reconstructed source word violates an execution prerequisite.
    Source { record: RecordId, error: WordError },
    /// A poll or control observation preceded a necessary source operation.
    Admission {
        record: RecordId,
        prior: SourcePoint,
    },
}

impl SourcePath<'_, '_, '_> {
    /// Temporary words for the actual captures and proposed acceptance points.
    pub fn execution_workspace_len(
        &self,
        captures: &[Capture<'_>],
        witness: &ExecutionWitness<'_>,
    ) -> Result<usize, ExecutionError> {
        let source = self.unfolding();
        let protocol = source.protocol();
        let custody = protocol
            .custody_words(captures)
            .ok_or(ExecutionError::Overflow)?;
        let points = witness
            .order
            .len()
            .checked_add(witness.acceptances.len())
            .and_then(|n| n.checked_mul(2))
            .ok_or(ExecutionError::Overflow)?;
        custody.checked_add(points).ok_or(ExecutionError::Overflow)
    }

    /// Check the named session's operation history against this source path.
    ///
    /// Reuses checked call and FIFO links, exact source/actor assignments and
    /// route evidence. Every poll is an admission query at its own boundary;
    /// it does not append acceptance or advance the reconstructed source word.
    /// Completed wire halves require one supported acceptance after a poll and
    /// no later than either completion. Open calls remain admission queries.
    ///
    /// Success establishes a source interpretation compatible with the proposed
    /// order and acceptance intervals under the transport contract. It does not
    /// authenticate records, recover a distributed clock, prove a session has
    /// ended, or validate application effects. Other sessions in the same
    /// complete captures need separate source witnesses.
    pub fn check_execution(
        &self,
        captures: &[Capture<'_>],
        witness: &ExecutionWitness<'_>,
        workspace: &mut [usize],
    ) -> Result<(), ExecutionError> {
        let required = self.execution_workspace_len(captures, witness)?;
        if workspace.len() < required {
            return Err(ExecutionError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let order = witness.order;
        if witness.occurrences.len() != order.len() {
            return Err(ExecutionError::Length {
                expected: order.len(),
                actual: witness.occurrences.len(),
            });
        }
        let source = self.unfolding();
        let protocol = source.protocol();
        let custody_words = protocol.custody_workspace_len(captures);
        let (scratch, word) = workspace[..required].split_at_mut(custody_words);
        let links = protocol
            .checked_custody(captures, order, scratch)
            .map_err(|error| ExecutionError::History(RouteHistoryError::Custody(error)))?;
        protocol
            .check_route_records(captures, order)
            .map_err(ExecutionError::History)?;
        let observed = |id: RecordId| captures[id.producer].records()[id.ordinal];
        let layout = Layout::checked(protocol);
        let in_session = |record: TapEvent| relevant(record) && record.arg0() == witness.session;
        for (position, &id) in order.iter().enumerate() {
            let record = observed(id);
            let event = witness.occurrences[position];
            if !in_session(record) {
                if event.is_some() {
                    return Err(ExecutionError::Record { position });
                }
                continue;
            }
            let Some(event) = event.filter(|&event| self.actors(event).is_some()) else {
                return Err(ExecutionError::Record { position });
            };
            let origin = source.origin(event).unwrap();
            let row = protocol.records[layout.sources.start + usize::from(origin)];
            let actor = (record.causal_key() >> 8) as u8;
            let point = operation_point(row, record, event);
            if operation(record) {
                if origin != record.arg1() as u16
                    || point.is_none_or(|point| self.point_actor(point) != Some(actor))
                {
                    return Err(ExecutionError::Record { position });
                }
                if let Some(first) = links.root_rank(id) {
                    if witness.occurrences[first] != Some(event) {
                        return Err(ExecutionError::Record { position });
                    }
                    if first == position
                        && order[..position].iter().enumerate().any(|(at, &prior)| {
                            let prior_record = observed(prior);
                            prior_record.id() == tap::SEND_POLL
                                && prior_record.arg0() == witness.session
                                && links.root_rank(prior) == Some(at)
                                && witness.occurrences[at] == Some(event)
                        })
                    {
                        return Err(ExecutionError::Record { position });
                    }
                }
            } else {
                let scope = (record.arg1() >> 16) as u16;
                if record.id() == tap::SCOPE_REENTRY && scope >> 13 == 1 {
                    let next = order[position + 1..].iter().enumerate().find(|(_, next)| {
                        let next = observed(**next);
                        committed(next)
                            && next.arg0() == witness.session
                            && next.causal_key() >> 8 == record.causal_key() >> 8
                            && (next.arg1() >> 24) as u8 == record.causal_key() as u8
                    });
                    if !source.reentered(event, scope)
                        || origin != record.arg1() as u16
                        || next.is_none_or(|(at, _)| {
                            witness.occurrences[position + 1 + at] != Some(event)
                        })
                    {
                        return Err(ExecutionError::Record { position });
                    }
                } else {
                    let Some(right) = self.choice_at(event, scope) else {
                        return Err(ExecutionError::Record { position });
                    };
                    let arm = if record.id() == tap::RESOLVER_AUDIT {
                        u16::from(record.causal_key() as u8)
                    } else {
                        record.arg1() as u16
                    };
                    if (arm != 255 || record.id() != tap::RESOLVER_AUDIT) && arm != u16::from(right)
                    {
                        return Err(ExecutionError::Record { position });
                    }
                    if record.id() == tap::SCOPE_REENTRY && !source.reentered(event, scope) {
                        return Err(ExecutionError::Record { position });
                    }
                }
            }
        }
        for (index, acceptance) in witness.acceptances.iter().enumerate() {
            let invalid = || ExecutionError::Acceptance { index };
            let Some(first) = order.iter().position(|&id| id == acceptance.first_poll) else {
                return Err(invalid());
            };
            let poll = observed(acceptance.first_poll);
            if poll.id() != tap::SEND_POLL
                || poll.arg0() != witness.session
                || links.root_rank(acceptance.first_poll) != Some(first)
                || first >= acceptance.before
                || acceptance.before > order.len()
                || witness.acceptances[..index]
                    .iter()
                    .any(|prior| prior.first_poll == acceptance.first_poll)
                || index != 0 && witness.acceptances[index - 1].before > acceptance.before
            {
                return Err(invalid());
            }
            let mut completed = false;
            for (position, &id) in order.iter().enumerate() {
                if links.root(id) == links.root(acceptance.first_poll) && committed(observed(id)) {
                    if position < acceptance.before {
                        return Err(invalid());
                    }
                    completed = true;
                }
            }
            if !completed {
                return Err(invalid());
            }
        }
        let mut used = 0;
        let mut accepted = 0;
        for position in 0..=order.len() {
            while let Some(acceptance) = witness.acceptances.get(accepted)
                && acceptance.before == position
            {
                let at = links.rank(acceptance.first_poll);
                let event = witness.occurrences[at].unwrap();
                let point = SourcePoint::Accepted(event);
                self.check_next(points(&word[..used]), point, used / 2)
                    .map_err(|error| ExecutionError::Source {
                        record: acceptance.first_poll,
                        error,
                    })?;
                put(&mut word[used..used + 2], point);
                used += 2;
                accepted += 1;
            }
            let Some(&id) = order.get(position) else {
                break;
            };
            let record = observed(id);
            if !in_session(record) {
                continue;
            }
            let event = witness.occurrences[position].unwrap();
            let row =
                protocol.records[layout.sources.start + usize::from(source.origin(event).unwrap())];
            if let Some(point) = operation_point(row, record, event) {
                if record.id() == tap::SEND_POLL {
                    if let Some(prior) = self.missing(points(&word[..used]), point) {
                        return Err(ExecutionError::Admission { record: id, prior });
                    }
                } else {
                    self.check_next(points(&word[..used]), point, used / 2)
                        .map_err(|error| ExecutionError::Source { record: id, error })?;
                    put(&mut word[used..used + 2], point);
                    used += 2;
                }
            } else if matches!(record.id(), tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION) {
                let actor = (record.causal_key() >> 8) as u8;
                let candidate = [
                    SourcePoint::Local(event),
                    SourcePoint::Accepted(event),
                    SourcePoint::Received(event),
                ]
                .into_iter()
                .find(|&point| self.point_actor(point) == Some(actor))
                .ok_or(ExecutionError::Record { position })?;
                if let Some(prior) = self.missing(points(&word[..used]), candidate) {
                    return Err(ExecutionError::Admission { record: id, prior });
                }
            }
        }
        Ok(())
    }
}

pub(super) fn relevant(record: TapEvent) -> bool {
    operation(record)
        || matches!(
            record.id(),
            tap::SCOPE_REENTRY | tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION
        )
}

pub(super) fn operation(record: TapEvent) -> bool {
    record.id() == tap::SEND_POLL || committed(record)
}

pub(super) fn committed(record: TapEvent) -> bool {
    matches!(
        record.id(),
        tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ENDPOINT_SESSION
    )
}

pub(super) fn operation_point(
    row: TapEvent,
    observed: TapEvent,
    event: usize,
) -> Option<SourcePoint> {
    if !operation(observed) {
        return None;
    }
    if row.arg0() >> 24 == (row.arg0() >> 16) & 255 {
        return Some(SourcePoint::Local(event));
    }
    Some(if observed.id() == tap::SEND_POLL {
        SourcePoint::Accepted(event)
    } else if observed.causal_key() as u8 == 1 {
        SourcePoint::Sent(event)
    } else {
        SourcePoint::Received(event)
    })
}

fn points(words: &[usize]) -> impl Clone + Iterator<Item = SourcePoint> + '_ {
    words.as_chunks::<2>().0.iter().map(|row| match row[0] {
        0 => SourcePoint::Accepted(row[1]),
        1 => SourcePoint::Sent(row[1]),
        2 => SourcePoint::Received(row[1]),
        3 => SourcePoint::Local(row[1]),
        _ => unreachable!("only checked source points are stored"),
    })
}

fn put(words: &mut [usize], point: SourcePoint) {
    words[0] = match point {
        SourcePoint::Accepted(_) => 0,
        SourcePoint::Sent(_) => 1,
        SourcePoint::Received(_) => 2,
        SourcePoint::Local(_) => 3,
    };
    words[1] = point.event();
}
