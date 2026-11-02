//! Construct and independently check a finite capture interpretation.
use super::{
    Acceptance, ExecutionError, ExecutionWitness, Layout, RecordId, RouteHistoryError, SourcePath,
    SourcePoint, execution,
};
use crate::Capture;
use hibana::runtime::tap::{self, TapEvent};

/// Caller-owned evidence outputs for one run in complete producer captures.
/// These arrays never hold application progress or permissions.
pub struct ExecutionStorage<'a> {
    /// Session whose source interpretation is being constructed.
    pub session: u32,
    /// One output slot per captured record. Initial contents are ignored.
    pub order: &'a mut [RecordId],
    /// One writable occurrence entry per ordered record.
    pub occurrences: &'a mut [Option<usize>],
    /// One output slot per completed wire call, at most the record count.
    pub acceptances: &'a mut [Acceptance],
}

/// No checked interpretation was constructed for this selected finite path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterpretationError {
    /// Invalid causal evidence or a failure independent of attribution.
    Evidence(ExecutionError),
    /// One ordering slot is required per captured record.
    Order { required: usize, actual: usize },
    /// One occurrence slot is required per ordered record.
    Occurrences { required: usize, actual: usize },
    /// Too few slots for the completed wire calls.
    Acceptances { required: usize, actual: usize },
    /// Too little temporary search/checking storage.
    Workspace { required: usize, actual: usize },
    /// Required storage is not representable on this target.
    Overflow,
    /// No producer-preserving order and attribution in this path passes checking.
    /// This neither rejects the global nor excludes another unfolding.
    NoInterpretation,
}

impl SourcePath<'_, '_, '_> {
    /// Eight words per captured record, one per producer, plus custody space.
    /// There is no fixed source-depth, visit-count or search-step capacity.
    pub fn interpretation_workspace_len(
        &self,
        captures: &[Capture<'_>],
    ) -> Result<usize, InterpretationError> {
        let source = self.unfolding();
        let records = captures
            .iter()
            .try_fold(0usize, |count, capture| {
                count.checked_add(capture.records().len())
            })
            .ok_or(InterpretationError::Overflow)?;
        source
            .protocol()
            .custody_words(captures)
            .and_then(|n| {
                records
                    .checked_mul(8)?
                    .checked_add(captures.len())?
                    .checked_add(n)
            })
            .ok_or(InterpretationError::Overflow)
    }

    /// Construct a checked interpretation of this particular finite source path.
    ///
    /// Searches producer-order-preserving record interleavings and the expanded
    /// occurrence domain. Custody-invalid prefixes are discarded by the same
    /// custody walk used to check a complete order. A completed call's acceptance
    /// is proposed after its first poll;
    /// every poll's source admission is still checked separately. Acceptance
    /// alone advances no actor or resumed body. This supplies an interval
    /// witness rather than claiming a recovered physical acceptance time.
    ///
    /// Every finished candidate passes through `check_execution`. No Endpoint
    /// authority is created. Worst-case search is exponential; storage and
    /// search depth derive from the actual observations, without a catalogue
    /// horizon. This does not construct the unfolding or choose its branches.
    pub fn interpret<'a>(
        &self,
        captures: &[Capture<'_>],
        storage: ExecutionStorage<'a>,
        workspace: &mut [usize],
    ) -> Result<ExecutionWitness<'a>, InterpretationError> {
        let required = self.interpretation_workspace_len(captures)?;
        if workspace.len() < required {
            return Err(InterpretationError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let ExecutionStorage {
            session,
            order,
            occurrences,
            acceptances,
        } = storage;
        let count: usize = captures.iter().map(|capture| capture.records().len()).sum();
        if order.len() != count {
            return Err(InterpretationError::Order {
                required: count,
                actual: order.len(),
            });
        }
        if occurrences.len() != order.len() {
            return Err(InterpretationError::Occurrences {
                required: order.len(),
                actual: occurrences.len(),
            });
        }
        let source = self.unfolding();
        let protocol = source.protocol();
        let (next, rest) = workspace[..required].split_at_mut(count);
        let (used, scratch) = rest.split_at_mut(captures.len());
        // Validate every producer before searching. A malformed capture cannot
        // be hidden by choosing a different interleaving or an empty prefix.
        protocol
            .custody_prefix(captures, &[], scratch)
            .map_err(|error| {
                InterpretationError::Evidence(ExecutionError::History(RouteHistoryError::Custody(
                    error,
                )))
            })?;
        next.fill(0);
        used.fill(0);
        let mut depth = 0;
        loop {
            if depth == count {
                match self.interpret_order(
                    captures,
                    ExecutionStorage {
                        session,
                        order: &mut *order,
                        occurrences: &mut *occurrences,
                        acceptances: &mut *acceptances,
                    },
                    scratch,
                ) {
                    Ok(accepted) => {
                        return Ok(ExecutionWitness {
                            session,
                            order,
                            occurrences,
                            acceptances: &acceptances[..accepted],
                        });
                    }
                    Err(
                        InterpretationError::NoInterpretation
                        | InterpretationError::Evidence(
                            ExecutionError::History(_) | ExecutionError::Acceptance { .. },
                        ),
                    ) => {}
                    Err(error) => return Err(error),
                }
            } else {
                let candidate = (next[depth]..captures.len())
                    .find(|&producer| used[producer] < captures[producer].records().len());
                if let Some(producer) = candidate {
                    next[depth] = producer + 1;
                    order[depth] = RecordId {
                        producer,
                        ordinal: used[producer],
                    };
                    used[producer] += 1;
                    match protocol.custody_prefix(captures, &order[..depth + 1], scratch) {
                        Ok(_) => {
                            depth += 1;
                            if depth != count {
                                next[depth] = 0;
                            }
                        }
                        Err(
                            super::CustodyError::Unmatched { .. }
                            | super::CustodyError::Owner { .. },
                        ) => {
                            used[producer] -= 1;
                        }
                        Err(error) => {
                            return Err(InterpretationError::Evidence(ExecutionError::History(
                                RouteHistoryError::Custody(error),
                            )));
                        }
                    }
                    continue;
                }
            }
            if depth == 0 {
                return Err(InterpretationError::NoInterpretation);
            }
            depth -= 1;
            used[order[depth].producer] -= 1;
        }
    }

    fn interpret_order(
        &self,
        captures: &[Capture<'_>],
        storage: ExecutionStorage<'_>,
        workspace: &mut [usize],
    ) -> Result<usize, InterpretationError> {
        let ExecutionStorage {
            session,
            order,
            occurrences,
            acceptances,
        } = storage;
        let source = self.unfolding();
        let protocol = source.protocol();
        let count: usize = captures.iter().map(|capture| capture.records().len()).sum();
        let (classes, rest) = workspace.split_at_mut(count);
        let (variables, rest) = rest.split_at_mut(count);
        let (next, scratch) = rest.split_at_mut(count);
        let links = protocol
            .checked_custody(captures, order, scratch)
            .map_err(|error| {
                InterpretationError::Evidence(ExecutionError::History(RouteHistoryError::Custody(
                    error,
                )))
            })?;
        protocol
            .check_route_records(captures, order)
            .map_err(|error| InterpretationError::Evidence(ExecutionError::History(error)))?;
        let observed = |id: RecordId| captures[id.producer].records()[id.ordinal];
        let relevant = |record: TapEvent| execution::relevant(record) && record.arg0() == session;
        classes.fill(usize::MAX);
        occurrences.fill(None);
        next.fill(0);
        for (position, &id) in order.iter().enumerate() {
            let record = observed(id);
            if !relevant(record) {
                continue;
            }
            classes[position] = if execution::operation(record) {
                links.root_rank(id).unwrap_or(position)
            } else {
                position
            };
        }
        for (position, &id) in order.iter().enumerate() {
            let record = observed(id);
            if !relevant(record) || record.id() != tap::SCOPE_REENTRY || record.arg1() >> 29 != 1 {
                continue;
            }
            let after = order[position + 1..]
                .iter()
                .position(|&id| {
                    let candidate = observed(id);
                    execution::committed(candidate)
                        && candidate.arg0() == session
                        && candidate.causal_key() >> 8 == record.causal_key() >> 8
                        && (candidate.arg1() >> 24) as u8 == record.causal_key() as u8
                })
                .ok_or(InterpretationError::NoInterpretation)?;
            classes[position] = classes[position + 1 + after];
        }
        let needed = order
            .iter()
            .enumerate()
            .filter(|(position, id)| {
                let record = observed(**id);
                relevant(record)
                    && record.id() == tap::SEND_POLL
                    && classes[*position] == *position
                    && order.iter().any(|&other| {
                        links.root(other) == links.root(**id)
                            && execution::committed(observed(other))
                    })
            })
            .count();
        if acceptances.len() < needed {
            return Err(InterpretationError::Acceptances {
                required: needed,
                actual: acceptances.len(),
            });
        }
        let mut accepted = 0;
        let mut used = 0;
        for (position, &id) in order.iter().enumerate() {
            if classes[position] != position {
                continue;
            }
            variables[used] = position;
            used += 1;
            if observed(id).id() == tap::SEND_POLL
                && order.iter().any(|&other| {
                    links.root(other) == links.root(id) && execution::committed(observed(other))
                })
            {
                acceptances[accepted] = Acceptance {
                    first_poll: id,
                    before: position + 1,
                };
                accepted += 1;
            }
        }
        let acceptances = &acceptances[..accepted];
        let variables = &variables[..used];
        let layout = Layout::checked(protocol);
        let mut depth = 0;
        loop {
            if depth != variables.len() {
                let variable = variables[depth];
                let candidate = (next[depth]..source.event_count()).find(|&event| {
                    let Some(origin) = source.origin(event) else {
                        return false;
                    };
                    let row = protocol.records[layout.sources.start + usize::from(origin)];
                    if self.actors(event).is_none() {
                        return false;
                    }
                    if execution::operation(observed(order[variable]))
                        && variables[..depth].iter().any(|&prior| {
                            execution::operation(observed(order[prior]))
                                && occurrences[prior] == Some(event)
                        })
                    {
                        return false;
                    }
                    order.iter().enumerate().all(|(position, &id)| {
                        if classes[position] != variable {
                            return true;
                        }
                        let record = observed(id);
                        let actor = (record.causal_key() >> 8) as u8;
                        if execution::operation(record) {
                            return origin == record.arg1() as u16
                                && execution::operation_point(row, record, event)
                                    .is_some_and(|point| self.point_actor(point) == Some(actor));
                        }
                        let key = (record.arg1() >> 16) as u16;
                        if record.id() == tap::SCOPE_REENTRY && key >> 13 == 1 {
                            return origin == record.arg1() as u16 && source.reentered(event, key);
                        }
                        let arm = if record.id() == tap::RESOLVER_AUDIT {
                            u16::from(record.causal_key() as u8)
                        } else {
                            record.arg1() as u16
                        };
                        self.choice_at(event, key).is_some_and(|right| {
                            (arm == u16::from(right)
                                || record.id() == tap::RESOLVER_AUDIT && arm == 255)
                                && (record.id() != tap::SCOPE_REENTRY
                                    || source.reentered(event, key))
                                && [
                                    SourcePoint::Local(event),
                                    SourcePoint::Accepted(event),
                                    SourcePoint::Received(event),
                                ]
                                .into_iter()
                                .any(|point| self.point_actor(point) == Some(actor))
                        })
                    })
                });
                if let Some(event) = candidate {
                    next[depth] = event + 1;
                    occurrences[variable] = Some(event);
                    depth += 1;
                    if depth != variables.len() {
                        next[depth] = 0;
                    }
                    continue;
                }
                next[depth] = 0;
                occurrences[variable] = None;
                if depth == 0 {
                    return Err(InterpretationError::NoInterpretation);
                }
                depth -= 1;
                continue;
            }
            for position in 0..order.len() {
                if classes[position] != usize::MAX {
                    occurrences[position] = occurrences[classes[position]];
                }
            }
            let trial = ExecutionWitness {
                session,
                order,
                occurrences,
                acceptances,
            };
            match self.check_execution(captures, &trial, scratch) {
                Ok(()) => break,
                Err(
                    ExecutionError::Record { .. }
                    | ExecutionError::Source { .. }
                    | ExecutionError::Admission { .. },
                ) => {
                    if variables.is_empty() {
                        return Err(InterpretationError::NoInterpretation);
                    }
                    depth -= 1;
                }
                Err(error) => return Err(InterpretationError::Evidence(error)),
            }
        }
        Ok(accepted)
    }
}
