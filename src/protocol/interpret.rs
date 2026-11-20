//! Construct and independently check a finite capture interpretation.
use super::{
    Acceptance, CustodyError, DeliveryError, ExecutionError, ExecutionWitness, Layout, RecordId,
    RouteHistoryError, SourcePath, SourcePoint, execution,
};
use crate::Capture;
use hibana::runtime::tap::{self, TapEvent};

// SourcePoint membership occupies bits 2..=5. This separate marker says only
// that a captured operation already names an occurrence, even before commit.
const ATTRIBUTED: usize = 1;

pub(super) fn mark_attributions(
    captures: &[Capture<'_>],
    witness: &ExecutionWitness<'_>,
    prefix: &mut [usize],
) {
    for (&id, event) in witness.order.iter().zip(witness.occurrences) {
        let record = captures[id.producer].records()[id.ordinal];
        if let Some(event) = event
            && record.arg0() == witness.session
            && execution::operation(record)
        {
            prefix[*event] |= ATTRIBUTED;
        }
    }
}

/// Caller-owned observations and evidence outputs for complete producer captures.
/// These arrays never hold application progress or permissions.
pub struct ExecutionStorage<'a> {
    /// Session whose source interpretation is being constructed.
    pub session: u32,
    /// Producer index of each record in the observer's arrival order. Each
    /// producer's records occur in ordinal order. This is a search preference,
    /// not a distributed clock or an asserted causal order. All other producer
    /// interleavings remain candidates and the final checker decides validity.
    pub observed_producers: &'a [usize],
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
    /// The first missing, excessive or unknown observation in the inventory.
    ObservationOrder { index: usize },
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
    /// Nine words per captured record, two per producer, one per expanded
    /// source event, custody space and readiness-query selection space.
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
                    .checked_mul(9)?
                    .checked_add(captures.len().checked_mul(2)?)?
                    .checked_add(n)
                    .and_then(|n| n.checked_add(source.event_count()))
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
            observed_producers,
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
        let (observation_positions, rest) = rest.split_at_mut(count);
        let (taken, rest) = rest.split_at_mut(captures.len());
        let (producer_offsets, tail) = rest.split_at_mut(captures.len());
        if observed_producers.len() != count {
            return Err(InterpretationError::ObservationOrder {
                index: observed_producers.len().min(count),
            });
        }
        taken.fill(0);
        let mut offset = 0;
        for (producer, capture) in captures.iter().enumerate() {
            producer_offsets[producer] = offset;
            offset += capture.records().len();
        }
        for (index, &producer) in observed_producers.iter().enumerate() {
            let Some(capture) = captures.get(producer) else {
                return Err(InterpretationError::ObservationOrder { index });
            };
            if taken[producer] == capture.records().len() {
                return Err(InterpretationError::ObservationOrder { index });
            }
            observation_positions[producer_offsets[producer] + taken[producer]] = index;
            taken[producer] += 1;
        }
        self.prepare_completions(captures, completion, tail)?;
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
        if captures.len() == 1 {
            // A complete ordinal-preserving order of one producer is unique.
            // Check its custody once, independently of source attribution.
            for (ordinal, id) in order.iter_mut().enumerate() {
                *id = RecordId {
                    producer: 0,
                    ordinal,
                };
            }
        }
        self.prepare_custody(captures, order, tail)?;
        next_producer.fill(0);
        next_event.fill(0);
        taken.fill(0);
        occurrences.fill(None);
        let layout = Layout::checked(protocol);
        let observed = |id: RecordId| captures[id.producer].records()[id.ordinal];
        let prefix_start = 4 * count + protocol.custody_workspace_len(captures);
        tail[prefix_start..prefix_start + source.event_count()].fill(0);
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
                let (custody, scratch) =
                    scratch.split_at_mut(protocol.custody_workspace_len(captures));
                let (prefix, query) = scratch.split_at_mut(source.event_count());
                // Appends below extend the index of this exact prefix. A
                // rewind rebuilds it from the retained word and attributions;
                // advancing through diagnostics does not rescan that history.
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
                // Prefer the earliest still-unconsumed arrival. Diagnostics
                // and earlier causal repairs may have moved records away from
                // their arrival positions, so depth alone is not a locator.
                let preferred = (0..captures.len())
                    .filter(|&producer| taken[producer] < captures[producer].records().len())
                    .min_by_key(|&producer| {
                        observation_positions[producer_offsets[producer] + taken[producer]]
                    })
                    .expect("an incomplete prefix has an unconsumed record");
                while next_producer[depth] < captures.len() {
                    let rank = next_producer[depth];
                    // Rotate the full producer domain, without overflowing
                    // preferred + rank. Arrival order never prunes a candidate.
                    let producer = if rank < captures.len() - preferred {
                        preferred + rank
                    } else {
                        rank - (captures.len() - preferred)
                    };
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
                    if next_event[depth] == 0 {
                        // A new producer or source prefix cannot reuse the
                        // previous prefix's successful record attribution.
                        occurrences[depth] = None;
                    }
                    order[depth] = id;
                    taken[producer] += 1;
                    let links = if captures.len() == 1 {
                        protocol.prepared_custody_links(captures, custody)
                    } else {
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
                        }
                    };
                    let record = observed(id);
                    let relevant = execution::relevant(record) && record.arg0() == session;
                    let root = links.root_rank(id);
                    let first_poll =
                        relevant && record.id() == tap::SEND_POLL && root == Some(depth);
                    let evidence = completion[links.index(id)];
                    let alternatives = if relevant { alternatives } else { 1 };
                    // Identity and a prior call's attribution are immutable
                    // candidate constraints, not readiness decisions. Jump to
                    // matching occurrences; retain both acceptance variants
                    // and every later admissibility/independent check.
                    let anchored = if relevant && execution::operation(record) {
                        root.filter(|&first| first < depth)
                            .and_then(|first| occurrences[first])
                    } else if relevant
                        && captures.len() == 1
                        && record.id() == tap::SCOPE_REENTRY
                        && record.arg1() >> 29 == 1
                    {
                        // Final checking binds this reset to the next commit
                        // by its actor/view. In a fixed producer order, that
                        // receive may already have an attributed sender call.
                        // Reuse that exact occurrence before guessing resets;
                        // without an earlier root, retain the full search.
                        captures[0].records()[id.ordinal + 1..]
                            .iter()
                            .enumerate()
                            .find(|(_, next)| {
                                next.arg0() == session
                                    && next.causal_key() >> 8 == record.causal_key() >> 8
                                    && execution::committed(**next)
                                    && (next.arg1() >> 24) as u8 == record.causal_key() as u8
                            })
                            .and_then(|(offset, _)| {
                                links.root_rank(RecordId {
                                    producer: 0,
                                    ordinal: id.ordinal + 1 + offset,
                                })
                            })
                            .filter(|&first| first < depth)
                            .and_then(|first| occurrences[first])
                    } else {
                        None
                    };
                    let named_origin = if relevant
                        && (execution::operation(record)
                            || record.id() == tap::SCOPE_REENTRY && record.arg1() >> 29 == 1)
                    {
                        Some(record.arg1() as u16)
                    } else {
                        None
                    };
                    // A selection often immediately precedes a receive whose
                    // sender call already has an occurrence. Prefer that
                    // occurrence before enumerating every visit of this route.
                    // This is only a preference: the next same-actor commit
                    // can belong to an independent view or a later visit.
                    // The initial hint is followed by the remaining original
                    // domain, using the existing per-depth rank.
                    let next_commit = if relevant
                        && captures.len() == 1
                        && matches!(record.id(), tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION)
                    {
                        captures[0].records()[id.ordinal + 1..]
                            .iter()
                            .enumerate()
                            .find(|(_, next)| {
                                next.arg0() == session
                                    && next.causal_key() >> 8 == record.causal_key() >> 8
                                    && execution::committed(**next)
                            })
                    } else {
                        None
                    };
                    let preferred = next_commit
                        .and_then(|(offset, _)| {
                            links.root_rank(RecordId {
                                producer: 0,
                                ordinal: id.ordinal + 1 + offset,
                            })
                        })
                        .filter(|&first| first < depth)
                        .and_then(|first| occurrences[first]);
                    // An outgoing callback's next commit usually has a future
                    // sender root, so it has no attributed occurrence yet.
                    // Its observed static source still supplies a useful order
                    // over all visits. The first hint is always tried; later
                    // hints may be skipped when a whole arm is consumed.
                    let preferred_origins = if preferred.is_none() {
                        next_commit
                            .map_or(&[][..], |(_, next)| self.origin_events(next.arg1() as u16))
                    } else {
                        &[]
                    };
                    let preference = 2 * preferred_origins
                        .len()
                        .max(usize::from(preferred.is_some()));
                    let first_hint = preferred.or(preferred_origins.first().copied());
                    let alternatives = alternatives
                        .checked_add(preference)
                        .ok_or(InterpretationError::Overflow)?;
                    while next_event[depth] < alternatives {
                        if let Some(event) = anchored {
                            if next_event[depth] >= 2 * (event + 1) {
                                break;
                            }
                            next_event[depth] = next_event[depth].max(2 * event);
                        } else if let Some(origin) = named_origin {
                            let Some(event) = self.next_origin_event(origin, next_event[depth] / 2)
                            else {
                                break;
                            };
                            next_event[depth] = next_event[depth].max(2 * event);
                        }
                        let hinted = next_event[depth] < preference;
                        let candidate = if hinted {
                            let event = preferred
                                .unwrap_or_else(|| preferred_origins[next_event[depth] / 2]);
                            2 * event + next_event[depth] % 2
                        } else {
                            next_event[depth] - preference
                        };
                        next_event[depth] += 1;
                        let event = candidate / 2;
                        if !hinted && first_hint == Some(event) {
                            continue;
                        }
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
                            if matches!(record.id(), tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION)
                            {
                                let (span, right) = self
                                    .route_at(event, (record.arg1() >> 16) as u16)
                                    .expect("the record matches this route occurrence");
                                let (_, split) = source
                                    .indexed_parts(span, self.index)
                                    .expect("the immutable index contains this checked subtree");
                                let opposite = if right {
                                    span[0]..split
                                } else {
                                    split..span[1]
                                };
                                if prefix[opposite].iter().any(|points| points & 56 != 0) {
                                    // Every readiness query would force this
                                    // arm and the already committed opposite
                                    // arm. Reject that same demand conflict
                                    // once for the whole arm, independent of
                                    // its actors or leaf directions. Accepted
                                    // but unpublished sends do not force it.
                                    next_event[depth] = if hinted {
                                        preference
                                    } else {
                                        preference + 2 * if right { span[1] } else { split }
                                    };
                                    continue;
                                }
                            }
                            // The full checker reads only the prior prefix for
                            // these choice constraints. Reject the candidate
                            // here instead of constructing an impossible suffix.
                            let previous = occurrences[depth].replace(event);
                            let prefix_witness = ExecutionWitness {
                                session,
                                order: &order[..=depth],
                                occurrences: &occurrences[..=depth],
                                acceptances: &[],
                            };
                            let agrees = self.resolver_agrees(captures, &prefix_witness, depth)
                                && self.poll_agrees(captures, &prefix_witness, depth);
                            occurrences[depth] = previous;
                            if !agrees {
                                continue;
                            }
                            if execution::operation(record) {
                                if let Some(first) = root.filter(|&first| first < depth) {
                                    if occurrences[first] != Some(event) {
                                        continue;
                                    }
                                } else if prefix[event] & ATTRIBUTED != 0 {
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
                            if record.id() == tap::SCOPE_REENTRY && record.arg1() >> 29 == 1 {
                                // This reset must name the next commit through
                                // its logical view. A point already committed
                                // in this prefix cannot be that future commit,
                                // regardless of producer interleaving or actor
                                // custody. Do not explore an obsolete visit's
                                // entire suffix before discovering the duplicate.
                                let view = record.causal_key() as u8;
                                let sender = (row.arg0() >> 24) as u8;
                                let receiver = (row.arg0() >> 16) as u8;
                                let point = if sender == receiver && sender == view {
                                    Some(SourcePoint::Local(event))
                                } else if sender == view {
                                    Some(SourcePoint::Sent(event))
                                } else if receiver == view {
                                    Some(SourcePoint::Received(event))
                                } else {
                                    None
                                };
                                if point.is_some_and(|point| prefix[event] & point.bit() != 0) {
                                    continue;
                                }
                            }
                            // This certificate is for outgoing admission.
                            // Choice observations may instead name a credited
                            // incoming continuation; query those directions
                            // separately below before rejecting the record.
                            if record.id() == tap::SEND_POLL
                                && let Some(end) = self.fixed_prefix_blocked_until(
                                    SourcePoint::Accepted(event),
                                    (record.causal_key() >> 8) as u8,
                                    prefix,
                                )
                            {
                                // An empty mandatory predecessor excludes
                                // this actor throughout the same sequential
                                // right child. This proof is independent of
                                // later route choices and leaf identities.
                                next_event[depth] = if hinted {
                                    preference
                                } else {
                                    preference + 2 * end
                                };
                                continue;
                            }
                            if let Some(point) = execution::operation_point(row, record, event) {
                                if record.id() == tap::SEND_POLL {
                                    if !self.query_ready(
                                        (execution::points(&word[..word_len]), prefix),
                                        (point, (record.causal_key() >> 8) as u8),
                                        query,
                                    ) {
                                        continue;
                                    }
                                } else if self
                                    .check_next(
                                        execution::points(&word[..word_len]),
                                        (point, word_len / 2),
                                        |prior| prefix[prior.event()] & prior.bit() != 0,
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
                                point.query_preconditions(|prior| {
                                    prefix[prior.event()] & prior.bit() != 0
                                }) && self.query_ready(
                                    (execution::points(&word[..word_len]), prefix),
                                    (point, (record.causal_key() >> 8) as u8),
                                    query,
                                )
                            }) {
                                continue;
                            }
                            if accepts
                                && self
                                    .check_next(
                                        execution::points(&word[..word_len]),
                                        (SourcePoint::Accepted(event), word_len / 2),
                                        |prior| prefix[prior.event()] & prior.bit() != 0,
                                    )
                                    .is_err()
                            {
                                continue;
                            }
                            occurrences[depth] = Some(event);
                            if matches!(record.id(), tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION)
                            {
                                let (span, right) = self
                                    .route_at(event, (record.arg1() >> 16) as u16)
                                    .expect("the record matches this route occurrence");
                                let (_, split) = source
                                    .indexed_parts(span, self.index)
                                    .expect("the immutable index contains this checked subtree");
                                // Read-only attributions within this whole arm
                                // share one source prefix and every later choice
                                // constraint. Advance past that entire class.
                                next_event[depth] = if hinted {
                                    preference
                                } else {
                                    preference + 2 * if right { span[1] } else { split }
                                };
                            }
                            if execution::committed(record) {
                                let point = execution::operation_point(row, record, event).unwrap();
                                execution::put(&mut word[word_len..word_len + 2], point);
                                word_len += 2;
                                prefix[point.event()] |= point.bit();
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
                                prefix[event] |= SourcePoint::Accepted(event).bit();
                            }
                            if execution::operation(record) {
                                prefix[event] |= ATTRIBUTED;
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
            let (acceptance_cuts, rest) = rest.split_at_mut(count);
            word_len = word_cuts[depth];
            accepted = acceptance_cuts[depth];
            let (word, scratch) = rest.split_at_mut(2 * count);
            let (_, scratch) = scratch.split_at_mut(protocol.custody_workspace_len(captures));
            let prefix = &mut scratch[..source.event_count()];
            prefix.fill(0);
            for point in execution::points(&word[..word_len]) {
                prefix[point.event()] |= point.bit();
            }
            mark_attributions(
                captures,
                &ExecutionWitness {
                    session,
                    order: &order[..depth],
                    occurrences: &occurrences[..depth],
                    acceptances: &[],
                },
                prefix,
            );
        }
    }

    fn prepare_custody(
        &self,
        captures: &[Capture<'_>],
        order: &[RecordId],
        workspace: &mut [usize],
    ) -> Result<(), InterpretationError> {
        let count: usize = captures.iter().map(|capture| capture.records().len()).sum();
        // The preceding four rows hold cuts and the reconstructed source word.
        // Completion preparation and final checking reuse that region, so
        // restore the immutable roots whenever either has overwritten it.
        let source = self.unfolding();
        let protocol = source.protocol();
        let custody = &mut workspace[4 * count..];
        protocol
            .prepare_custody(captures, custody)
            .map_err(|error| {
                InterpretationError::Evidence(ExecutionError::History(RouteHistoryError::Custody(
                    error,
                )))
            })?;
        if captures.len() == 1 {
            protocol
                .prepared_custody_prefix(captures, order, custody)
                .map_err(|error| match error {
                    CustodyError::Unmatched { .. } | CustodyError::Owner { .. } => {
                        InterpretationError::NoInterpretation
                    }
                    other => InterpretationError::Evidence(ExecutionError::History(
                        RouteHistoryError::Custody(other),
                    )),
                })?;
        }
        Ok(())
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
        self.prepare_custody(captures, witness.order, workspace)?;
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
