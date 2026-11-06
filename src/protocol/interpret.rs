//! Construct and independently check a finite capture interpretation.
use super::{
    Acceptance, CustodyError, DeliveryError, ExecutionError, ExecutionWitness, Layout, RecordId,
    RouteHistoryError, SourcePath, SourcePoint, execution,
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
    /// Eight words per captured record, one per producer, custody space and
    /// readiness-query selection space derived from this source unfolding.
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
                    .and_then(|n| n.checked_add(self.query_workspace_len()?))
            })
            .ok_or(InterpretationError::Overflow)
    }

    /// Construct a checked interpretation of this particular finite source path.
    ///
    /// Searches producer-order-preserving record interleavings and the expanded
    /// occurrence domain together, checking custody and source readiness before
    /// extending each prefix. A completed call's acceptance is proposed after its first poll;
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
        let (next_producer, rest) = workspace[..required].split_at_mut(count);
        let (next_event, rest) = rest.split_at_mut(count);
        let (completion, rest) = rest.split_at_mut(count);
        let (taken, tail) = rest.split_at_mut(captures.len());
        self.prepare_completions(captures, completion, tail)?;
        self.prepare_custody(captures, tail)?;
        let mut flat = 0;
        let mut needed = 0;
        for capture in captures {
            for record in capture.records() {
                needed += usize::from(completion[flat] == 1 && record.arg0() == session);
                flat += 1;
            }
        }
        if acceptances.len() < needed {
            return Err(InterpretationError::Acceptances {
                required: needed,
                actual: acceptances.len(),
            });
        }
        next_producer.fill(0);
        next_event.fill(0);
        taken.fill(0);
        occurrences.fill(None);
        let layout = Layout::checked(protocol);
        let observed = |id: RecordId| captures[id.producer].records()[id.ordinal];
        let mut depth = 0;
        let mut word_len = 0;
        let mut accepted = 0;
        let alternatives = source
            .event_count()
            .checked_mul(2)
            .ok_or(InterpretationError::Overflow)?;
        'search: loop {
            if depth == count {
                let trial = ExecutionWitness {
                    session,
                    order,
                    occurrences,
                    acceptances: &acceptances[..accepted],
                };
                match self.check_execution(captures, &trial, tail) {
                    Ok(()) => {
                        return Ok(ExecutionWitness {
                            session,
                            order,
                            occurrences,
                            acceptances: &acceptances[..accepted],
                        });
                    }
                    Err(ExecutionError::Workspace { required, actual }) => {
                        return Err(InterpretationError::Workspace { required, actual });
                    }
                    Err(ExecutionError::Overflow) => return Err(InterpretationError::Overflow),
                    Err(_) => {
                        // The independent final check uses this same temporary
                        // region. Restore the selected prefix, not a second
                        // interpreter or a fresh Cartesian attribution search.
                        self.restore_prefix(captures, &trial, tail)?;
                    }
                }
            } else {
                let (word_cuts, rest) = tail.split_at_mut(count);
                let (acceptance_cuts, rest) = rest.split_at_mut(count);
                let (word, scratch) = rest.split_at_mut(2 * count);
                let (custody, query) =
                    scratch.split_at_mut(protocol.custody_workspace_len(captures));
                word_cuts[depth] = word_len;
                acceptance_cuts[depth] = accepted;
                // Opaque diagnostics neither advance source nor change custody.
                // Keep them all, but do not permute their equivalent placements.
                let diagnostic = (0..captures.len()).find(|&producer| {
                    captures[producer]
                        .records()
                        .get(taken[producer])
                        .is_some_and(|&record| !execution::relevant(record))
                });
                while next_producer[depth] < captures.len() {
                    let producer = next_producer[depth];
                    if taken[producer] == captures[producer].records().len()
                        || diagnostic.is_some_and(|eager| producer != eager)
                    {
                        next_producer[depth] += 1;
                        next_event[depth] = 0;
                        continue;
                    }
                    let id = RecordId {
                        producer,
                        ordinal: taken[producer],
                    };
                    order[depth] = id;
                    taken[producer] += 1;
                    let links =
                        match protocol.prepared_custody_prefix(captures, &order[..=depth], custody)
                        {
                            Ok(links) => links,
                            Err(CustodyError::Unmatched { .. } | CustodyError::Owner { .. }) => {
                                taken[producer] -= 1;
                                next_producer[depth] += 1;
                                next_event[depth] = 0;
                                continue;
                            }
                            Err(error) => {
                                return Err(InterpretationError::Evidence(
                                    ExecutionError::History(RouteHistoryError::Custody(error)),
                                ));
                            }
                        };
                    let record = observed(id);
                    let relevant = execution::relevant(record) && record.arg0() == session;
                    let root = links.root_rank(id);
                    let first_poll =
                        relevant && record.id() == tap::SEND_POLL && root == Some(depth);
                    let evidence = completion[links.index(id)];
                    let alternatives = if relevant { alternatives } else { 1 };
                    while next_event[depth] < alternatives {
                        let candidate = next_event[depth];
                        next_event[depth] += 1;
                        let event = candidate / 2;
                        let accepts = candidate % 2 != 0;
                        if accepts && !first_poll
                            || first_poll
                                && match evidence {
                                    0 => accepts,
                                    1 => !accepts,
                                    2 => false,
                                    _ => {
                                        unreachable!("completion evidence is checked before search")
                                    }
                                }
                        {
                            continue;
                        }
                        if relevant {
                            if !self.matches_record(record, event) {
                                continue;
                            }
                            if execution::operation(record) {
                                if let Some(first) = root.filter(|&first| first < depth) {
                                    if occurrences[first] != Some(event) {
                                        continue;
                                    }
                                } else if order[..depth].iter().enumerate().any(|(at, &prior)| {
                                    execution::operation(observed(prior))
                                        && observed(prior).arg0() == session
                                        && occurrences[at] == Some(event)
                                }) {
                                    continue;
                                }
                            }
                            if execution::committed(record) {
                                // A roll reset names the next commit by this
                                // actor/view. Resolve that forward obligation
                                // here, before exploring any later records.
                                let mut resets_match = true;
                                for (at, &prior) in order[..depth].iter().enumerate().rev() {
                                    let prior = observed(prior);
                                    if prior.arg0() != session
                                        || prior.causal_key() >> 8 != record.causal_key() >> 8
                                    {
                                        continue;
                                    }
                                    if execution::committed(prior)
                                        && prior.arg1() >> 24 == record.arg1() >> 24
                                    {
                                        break;
                                    }
                                    if prior.id() == tap::SCOPE_REENTRY
                                        && prior.arg1() >> 29 == 1
                                        && prior.causal_key() as u8 == (record.arg1() >> 24) as u8
                                        && occurrences[at] != Some(event)
                                    {
                                        resets_match = false;
                                        break;
                                    }
                                }
                                if !resets_match {
                                    continue;
                                }
                            }
                            let origin = self.origin(event).unwrap();
                            let row = protocol.records[layout.sources.start + usize::from(origin)];
                            if let Some(point) = execution::operation_point(row, record, event) {
                                if record.id() == tap::SEND_POLL {
                                    if !self.query_ready(
                                        execution::points(&word[..word_len]),
                                        point,
                                        (record.causal_key() >> 8) as u8,
                                        query,
                                    ) {
                                        continue;
                                    }
                                } else if self
                                    .check_next(
                                        execution::points(&word[..word_len]),
                                        point,
                                        word_len / 2,
                                    )
                                    .is_err()
                                {
                                    continue;
                                }
                            } else if matches!(
                                record.id(),
                                tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION
                            ) && ![
                                SourcePoint::Local(event),
                                SourcePoint::Accepted(event),
                                SourcePoint::Received(event),
                            ]
                            .into_iter()
                            .any(|point| {
                                self.query_ready(
                                    execution::points(&word[..word_len]),
                                    point,
                                    (record.causal_key() >> 8) as u8,
                                    query,
                                )
                            }) {
                                continue;
                            }
                            if accepts
                                && self
                                    .check_next(
                                        execution::points(&word[..word_len]),
                                        SourcePoint::Accepted(event),
                                        word_len / 2,
                                    )
                                    .is_err()
                            {
                                continue;
                            }
                            occurrences[depth] = Some(event);
                            if execution::committed(record) {
                                let point = execution::operation_point(row, record, event).unwrap();
                                execution::put(&mut word[word_len..word_len + 2], point);
                                word_len += 2;
                            }
                            if accepts {
                                if accepted == acceptances.len() {
                                    return Err(InterpretationError::Acceptances {
                                        required: accepted + 1,
                                        actual: acceptances.len(),
                                    });
                                }
                                acceptances[accepted] = Acceptance {
                                    first_poll: id,
                                    before: depth + 1,
                                };
                                accepted += 1;
                                execution::put(
                                    &mut word[word_len..word_len + 2],
                                    SourcePoint::Accepted(event),
                                );
                                word_len += 2;
                            }
                        } else {
                            occurrences[depth] = None;
                        }
                        depth += 1;
                        if depth < count {
                            next_producer[depth] = 0;
                            next_event[depth] = 0;
                        }
                        continue 'search;
                    }
                    taken[producer] -= 1;
                    next_producer[depth] += 1;
                    next_event[depth] = 0;
                }
            }
            if depth == 0 {
                return Err(InterpretationError::NoInterpretation);
            }
            depth -= 1;
            taken[order[depth].producer] -= 1;
            let (word_cuts, rest) = tail.split_at_mut(count);
            let (acceptance_cuts, _) = rest.split_at_mut(count);
            word_len = word_cuts[depth];
            accepted = acceptance_cuts[depth];
        }
    }

    fn prepare_custody(
        &self,
        captures: &[Capture<'_>],
        workspace: &mut [usize],
    ) -> Result<(), InterpretationError> {
        let count: usize = captures.iter().map(|capture| capture.records().len()).sum();
        // The preceding four rows hold cuts and the reconstructed source word.
        // Completion preparation and final checking reuse that region, so
        // restore the immutable roots whenever either has overwritten it.
        self.unfolding()
            .protocol()
            .prepare_custody(captures, &mut workspace[4 * count..])
            .map_err(|error| {
                InterpretationError::Evidence(ExecutionError::History(RouteHistoryError::Custody(
                    error,
                )))
            })
    }

    fn prepare_completions(
        &self,
        captures: &[Capture<'_>],
        completion: &mut [usize],
        workspace: &mut [usize],
    ) -> Result<(), InterpretationError> {
        let source = self.unfolding();
        let protocol = source.protocol();
        let links = protocol
            .custody_prefix(captures, &[], workspace)
            .map_err(|error| {
                InterpretationError::Evidence(ExecutionError::History(RouteHistoryError::Custody(
                    error,
                )))
            })?;
        completion.fill(0);
        for (producer, capture) in captures.iter().enumerate() {
            for (ordinal, record) in capture.records().iter().enumerate() {
                let id = RecordId { producer, ordinal };
                if let Some(root) = links.root(id) {
                    if record.id() == tap::SEND_POLL && links.index(id) == root {
                        completion[root] = 2; // A later receipt may support this open call.
                    } else if execution::committed(*record) {
                        completion[root] = 1;
                    }
                }
            }
        }
        match protocol.deliveries(captures, workspace) {
            Ok(deliveries) => {
                for state in completion.iter_mut() {
                    if *state == 2 {
                        *state = 0;
                    }
                }
                for delivery in deliveries {
                    let id = delivery.first_poll;
                    let index = captures[..id.producer]
                        .iter()
                        .map(|c| c.records().len())
                        .sum::<usize>()
                        + id.ordinal;
                    completion[index] = 1;
                }
            }
            // Custody search chooses the actual FIFO order of streams that span
            // producers. Retain both completion alternatives until it does.
            Err(DeliveryError::Ambiguous { .. }) => {}
            Err(DeliveryError::Workspace { required, actual }) => {
                return Err(InterpretationError::Workspace { required, actual });
            }
            Err(DeliveryError::History { producer, error }) => {
                return Err(InterpretationError::Evidence(ExecutionError::History(
                    RouteHistoryError::Custody(CustodyError::History { producer, error }),
                )));
            }
            Err(DeliveryError::Cycle | DeliveryError::Unmatched { .. }) => {
                return Err(InterpretationError::NoInterpretation);
            }
        }
        Ok(())
    }

    fn matches_record(&self, record: TapEvent, event: usize) -> bool {
        let source = self.unfolding();
        let Some(origin) = self.origin(event) else {
            return false;
        };
        let protocol = source.protocol();
        let row = protocol.records[Layout::checked(protocol).sources.start + usize::from(origin)];
        let actor = (record.causal_key() >> 8) as u8;
        if !matches!(record.id(), tap::SEND_POLL | tap::RESOLVER_AUDIT)
            && self.actors(event).is_none()
        {
            return false;
        }
        if execution::operation(record) {
            return origin == record.arg1() as u16
                && (record.id() == tap::SEND_POLL
                    || execution::operation_point(row, record, event)
                        .is_some_and(|point| self.point_actor(point) == Some(actor)));
        }
        let scope = (record.arg1() >> 16) as u16;
        if record.id() == tap::SCOPE_REENTRY && scope >> 13 == 1 {
            return origin == record.arg1() as u16 && source.reentered(event, scope);
        }
        let choice = if record.id() == tap::RESOLVER_AUDIT {
            self.route_at(event, scope).map(|(_, right)| right)
        } else {
            self.choice_at(event, scope)
        };
        let arm = if record.id() == tap::RESOLVER_AUDIT {
            u16::from(record.causal_key() as u8)
        } else {
            record.arg1() as u16
        };
        choice.is_some_and(|right| {
            (arm == u16::from(right) || record.id() == tap::RESOLVER_AUDIT && arm == 255)
                && (record.id() != tap::SCOPE_REENTRY || source.reentered(event, scope))
        })
    }

    fn restore_prefix(
        &self,
        captures: &[Capture<'_>],
        witness: &ExecutionWitness<'_>,
        workspace: &mut [usize],
    ) -> Result<(), InterpretationError> {
        self.prepare_custody(captures, workspace)?;
        let count = witness.order.len();
        let (word_cuts, rest) = workspace.split_at_mut(count);
        let (acceptance_cuts, rest) = rest.split_at_mut(count);
        let (word, _) = rest.split_at_mut(2 * count);
        let source = self.unfolding();
        let protocol = source.protocol();
        let layout = Layout::checked(protocol);
        let mut used = 0;
        let mut accepted = 0;
        for (position, &id) in witness.order.iter().enumerate() {
            word_cuts[position] = used;
            acceptance_cuts[position] = accepted;
            let record = captures[id.producer].records()[id.ordinal];
            if record.arg0() == witness.session && execution::committed(record) {
                let event = witness.occurrences[position].unwrap();
                let row = protocol.records
                    [layout.sources.start + usize::from(self.origin(event).unwrap())];
                execution::put(
                    &mut word[used..used + 2],
                    execution::operation_point(row, record, event).unwrap(),
                );
                used += 2;
            }
            if witness
                .acceptances
                .get(accepted)
                .is_some_and(|a| a.before == position + 1)
            {
                execution::put(
                    &mut word[used..used + 2],
                    SourcePoint::Accepted(witness.occurrences[position].unwrap()),
                );
                used += 2;
                accepted += 1;
            }
        }
        Ok(())
    }
}
