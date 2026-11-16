//! Readiness of an uncommitted attempt against the committed source prefix.
use super::{Layout, PathError, SourcePath, SourcePoint, unfolding::NodeKind, word::SOURCE_ORDER};

impl SourcePath<'_, '_, '_> {
    pub(super) fn query_workspace_len(&self) -> Option<usize> {
        let source = self.unfolding();
        Layout::checked(source.protocol()).query_words(source.event_count())
    }

    // A selected sequence's earlier child cannot be empty. An unavoidable
    // fixed-actor operation there remains necessary even when other actors
    // also participate. If every leaf belongs to this actor, nonemptiness
    // additionally covers alternatives without one shared mandatory leaf.
    // Mandatory right children of a sequence/par remain necessary too.
    // This is only a necessary condition: uncertified spans and conditional
    // ownership still use full readiness.
    // The returned end bounds the remaining ordered suffix, initially that
    // sequence's right child and any later sequential children. Every later
    // query in this span has the same missing mandatory predecessor; do not
    // retry each leaf or later visit of the same impossible sequence.
    pub(super) fn fixed_prefix_blocked_until(
        &self,
        point: SourcePoint,
        actor: u8,
        prefix: &[usize],
    ) -> Option<usize> {
        let count = self.unfolding().event_count();
        let event = point.event();
        if (matches!(point, SourcePoint::Sent(_))
            || matches!(point, SourcePoint::Received(_)) && self.unfolding().has_repeated_visits())
            || count < 2
            || event >= count
        {
            return None;
        }
        let mut node = if event > 0 && self.index[3 * (event - 1) + 1] == event + 1 {
            event - 1
        } else {
            event
        };
        loop {
            // Binary boundaries are their split minus one; tag zero is seq.
            if node < event && self.index[3 * node + 2] == 0 {
                let mut ancestor = node;
                let mut start = 0;
                loop {
                    let parent = self.index[3 * ancestor];
                    if parent == usize::MAX {
                        break;
                    }
                    if ancestor > parent {
                        start = parent + 1;
                        break;
                    }
                    ancestor = parent;
                }
                let mut span = [start, node + 1];
                // These earlier siblings on the query's ancestor path are
                // disjoint. A mandatory missing leaf certifies the entire
                // right child, rather than retrying every later occurrence
                // merely because this earlier child also uses another actor.
                let missing = (span[0]..span[1]).any(|prior| {
                    prefix[prior] & 56 == 0
                        && self
                            .actors(prior)
                            .is_some_and(|actors| actors.contains(&actor))
                        && [
                            SourcePoint::Local(prior),
                            SourcePoint::Sent(prior),
                            SourcePoint::Received(prior),
                        ]
                        .into_iter()
                        .any(|point| {
                            self.point_binding(point)
                                .is_some_and(|(_, binding)| binding == u32::from(actor))
                        })
                        && self.unavoidable_before(prior, event, |span| {
                            prefix[span[0]..span[1]]
                                .iter()
                                .any(|points| points & 56 != 0)
                        })
                });
                let last_commit = prefix[start..span[1]]
                    .iter()
                    .rposition(|points| points & 56 != 0)
                    .map(|offset| start + offset);
                let mut different = None;
                loop {
                    // These sibling subtrees on the query's ancestor path
                    // are disjoint. During right descent, reuse the last
                    // commit and the first nonmatching leaf, so overlapping
                    // suffixes do not rescan the same prefix or binding rows.
                    if missing
                        || last_commit.is_none_or(|at| at < span[0])
                            && different.is_none_or(|at| at < span[0])
                    {
                        if !missing {
                            different = (span[0]..span[1]).find(|&event| {
                                ![
                                    SourcePoint::Local(event),
                                    SourcePoint::Sent(event),
                                    SourcePoint::Received(event),
                                ]
                                .into_iter()
                                .any(|prior| {
                                    self.point_binding(prior)
                                        .is_some_and(|(_, binding)| binding == u32::from(actor))
                                })
                            });
                        }
                        if missing || different.is_none() {
                            let mut blocked = node;
                            loop {
                                let parent = self.index[3 * blocked];
                                if parent == usize::MAX {
                                    break;
                                }
                                let kind = self.index[3 * parent + 2];
                                if kind >= 2 || kind == 1 && blocked < parent {
                                    break;
                                }
                                // A later sequence child also needs this
                                // missing operation. A right parallel child
                                // has the same end and preserves that fact.
                                // Stop at choices and before independent
                                // right parallel siblings: those can omit or
                                // run independently of the missing operation.
                                blocked = parent;
                            }
                            return Some(self.index[3 * blocked + 1]);
                        }
                    }
                    match self.unfolding().indexed_parts(span, self.index) {
                        Some((NodeKind::Sequence | NodeKind::Parallel, split)) => span[0] = split,
                        _ => break,
                    }
                }
            }
            node = self.index[3 * node];
            if node == usize::MAX {
                return None;
            }
        }
    }

    /// A query may select an uncommitted arm, but cannot change the actors,
    /// presence or prerequisites of any operation that already committed.
    /// Search only constructs retrospective evidence; it never drives a view.
    pub(super) fn query_ready(
        &self,
        (history, prefix): (impl Clone + Iterator<Item = SourcePoint>, &[usize]),
        (point, actor): (SourcePoint, u8),
        workspace: &mut [usize],
    ) -> bool {
        let Some((side, binding)) = self.point_binding(point) else {
            return false;
        };
        if binding < 256 && binding != u32::from(actor) {
            return false;
        }
        // A different choice cannot undo publication or repeat a committed
        // point of this same unfolding. Acceptance alone is not publication.
        if !point.query_preconditions(|prior| {
            prefix
                .get(prior.event())
                .is_some_and(|points| points & prior.bit() != 0)
        }) {
            return false;
        }
        let mandatory = |prior: SourcePoint, prefix: Option<&[usize]>| {
            !matches!(point, SourcePoint::Sent(_))
                && !self.may_credit_incoming(prior, point)
                && self
                    .point_binding(prior)
                    .is_some_and(|(_, binding)| binding == u32::from(actor))
                && self.unavoidable_before(prior.event(), point.event(), |span| {
                    prefix.is_some_and(|prefix| {
                        prefix[span[0]..span[1]]
                            .iter()
                            .any(|points| points & 56 != 0)
                    })
                })
        };
        // A request/reply pair in an unselected arm has no current actor row
        // yet. Its fixed-actor request is still mandatory for that reply in
        // every selection containing it. Test this adjacent source leaf
        // before scanning the full prefix or propagating source boundaries.
        if let Some(event) = point.event().checked_sub(1)
            && [
                SourcePoint::Local(event),
                SourcePoint::Sent(event),
                SourcePoint::Received(event),
            ]
            .into_iter()
            .any(|prior| mandatory(prior, None) && prefix[prior.event()] & prior.bit() == 0)
        {
            return false;
        }
        let source = self.unfolding();
        let count = source.event_count();
        assert_eq!(prefix.len(), count, "checked source word index length");
        let (domains, storage) = workspace.split_at_mut(count);
        let (choices, storage) = storage.split_at_mut(count);
        let (actors, scratch) = storage.split_at_mut(count);
        // Bits above each binary domain retain this event's observed points.
        // The immutable word is indexed once; it is not an execution cursor.
        let bit = SourcePoint::bit;
        // Selecting an inactive fixed-actor leaf also introduces its
        // publication/receipt. It cannot become a new prerequisite of an
        // already committed local/receive point. Reuse the prefix-indexing
        // pass for the same `newly_required` contradiction checked below,
        // before walking unrelated source arms. Conditional actors still
        // require the full selection check.
        let introduced = match point {
            SourcePoint::Accepted(event) => SourcePoint::Sent(event),
            other => other,
        };
        let introduced = (binding == u32::from(actor)
            && self.point_actor(introduced) != Some(actor))
        .then_some(introduced);
        // The interpreter and final checker already maintain exact membership
        // of this checked word. Copy only point bits; attribution and choice
        // bookkeeping are not committed source points. Keep the full word
        // for the independent resumption/conditional-actor checks below.
        for (domain, points) in domains.iter_mut().zip(prefix) {
            *domain = points & 60;
        }
        if let Some(introduced) = introduced {
            self.mark_source_after(introduced.event(), domains);
            for prior in history.clone() {
                if matches!(prior, SourcePoint::Local(_) | SourcePoint::Received(_))
                    && prior.event() >= introduced.event()
                    && !self.may_credit_incoming(introduced, prior)
                    && self.prerequisite_ordered(history.clone(), prior)(
                        introduced,
                        actor,
                        domains[prior.event()] & SOURCE_ORDER != 0,
                    )
                    && self.point_actor(prior) == Some(actor)
                {
                    return false;
                }
            }
        }
        self.mark_source_before(point.event(), domains);
        let exact = self.prerequisite_ordered(history.clone(), point);
        // A different uncommitted arm can remove a missing actor-local row
        // from the old visit. Pruning cannot assume its completion credit is
        // unchanged; the candidate's final readiness rechecks that credit.
        let required = |prior, actor, ordered| {
            !self.may_credit_incoming(prior, point) && exact(prior, actor, ordered)
        };
        if self
            .fixed_prefix_blocked_until(point, actor, domains)
            .is_some()
        {
            return false;
        }
        if self.point_actor(point) == Some(actor) {
            let missing = self.missing_with(
                point,
                |prior| domains[prior.event()] & bit(prior) != 0,
                |prior, actor| exact(prior, actor, domains[prior.event()] & SOURCE_ORDER != 0),
            );
            let Some(prior) = missing else {
                return true;
            };
            // No compatible alternative can remove this fixed-actor source
            // predecessor: every intervening choice is either absent or
            // forced by a commit in that arm. Acceptance alone does not
            // force an arm. Conditional actors and resumption-only
            // prerequisites still use the full selection checks below.
            if mandatory(prior, Some(domains)) {
                return false;
            }
        }

        // Propagate necessary conditions through the same immutable source
        // index before enumerating alternatives. A fixed-actor predecessor
        // absent from history forbids its leaf; committed points and the query
        // force their containing arms. Sequence/par need both children, while
        // a choice needs one viable child. Conditional holders are left to
        // full selection and execution checking below.
        let mut viable = false;
        {
            // Reuse the future choice/actor arrays and selection scratch as a
            // depth-bounded traversal stack; only `domains` survives this pass.
            let (states, rest) = scratch.split_at_mut(count);
            let (demands, rest) = rest.split_at_mut(count);
            let (left, rest) = rest.split_at_mut(count);
            let right = &mut rest[..count];
            // Each binary boundary already names its parent. Inverting those
            // edges once gives direct child navigation; looking up every span
            // from its first leaf would repeatedly climb a skewed seq tree.
            left.fill(usize::MAX);
            right.fill(usize::MAX);
            let mut root = usize::MAX;
            for node in 0..count - 1 {
                let parent = self.index[3 * node];
                if parent == usize::MAX {
                    root = node;
                } else if node < parent {
                    left[parent] = node;
                } else {
                    right[parent] = node;
                }
            }
            let mut total = 0;
            for (event, before) in demands.iter_mut().enumerate() {
                *before = total;
                total += usize::from(event == point.event() || domains[event] & 56 != 0);
            }
            choices[0] = 0;
            actors[0] = root;
            states[0] = 0;
            let mut depth = 1;
            while depth != 0 {
                let frame = depth - 1;
                let node = actors[frame];
                let (kind, split, end) = if node == usize::MAX {
                    (NodeKind::Message, choices[frame] + 1, choices[frame] + 1)
                } else {
                    source
                        .indexed_branch(node, self.index)
                        .expect("checked path contains every source boundary")
                };
                let span = [choices[frame], end];
                let end_demands = if end == count { total } else { demands[end] };
                if states[frame] == 0 && span[0] > point.event() && end_demands == demands[span[0]]
                {
                    // Every leaf here is after the query, and no committed
                    // point forces either arm. The ordinary traversal would
                    // mark every leaf viable and every internal domain 3.
                    // Binary boundaries fill exactly this contiguous range;
                    // preserve the independent observation bits in each word.
                    for domain in &mut domains[span[0]..end - 1] {
                        *domain |= 3;
                    }
                    viable = true;
                    depth -= 1;
                    continue;
                }
                if kind == NodeKind::Message {
                    viable = span[0] > point.event()
                        || ![
                            SourcePoint::Local(span[0]),
                            SourcePoint::Sent(span[0]),
                            SourcePoint::Received(span[0]),
                        ]
                        .into_iter()
                        .any(|prior| {
                            self.point_binding(prior).is_some_and(|(_, binding)| {
                                binding == u32::from(actor)
                                    && domains[prior.event()] & bit(prior) == 0
                                    && required(
                                        prior,
                                        actor,
                                        domains[prior.event()] & SOURCE_ORDER != 0,
                                    )
                            })
                        });
                    depth -= 1;
                } else if states[frame] == 0 {
                    let mut mask = 3;
                    if matches!(kind, NodeKind::Choice(_)) {
                        let end = if span[1] == count {
                            total
                        } else {
                            demands[span[1]]
                        };
                        if demands[split] != demands[span[0]] {
                            mask &= 1;
                        }
                        if end != demands[split] {
                            mask &= 2;
                        }
                    }
                    if mask == 0 {
                        domains[split - 1] &= !3;
                        viable = false;
                        depth -= 1;
                    } else {
                        // Low two bits: traversal phase. Next two bits:
                        // permitted arms. Bit four: left child's result.
                        states[frame] = (mask << 2) | 1;
                        viable = false;
                        if mask & 1 != 0 {
                            choices[depth] = span[0];
                            actors[depth] = left[node];
                            states[depth] = 0;
                            depth += 1;
                        }
                    }
                } else if states[frame] & 3 == 1 {
                    if !matches!(kind, NodeKind::Choice(_)) && !viable {
                        // An impossible sequence/par child makes its sibling
                        // irrelevant. No domain from that sibling is consumed.
                        domains[split - 1] &= !3;
                        depth -= 1;
                    } else {
                        let mask = (states[frame] >> 2) & 3;
                        states[frame] = (mask << 2) | 2 | (usize::from(viable) << 4);
                        viable = false;
                        if mask & 2 != 0 {
                            choices[depth] = split;
                            actors[depth] = right[node];
                            states[depth] = 0;
                            depth += 1;
                        }
                    }
                } else {
                    let left = states[frame] & 16 != 0;
                    let mask = if matches!(kind, NodeKind::Choice(_)) {
                        usize::from(left) | (usize::from(viable) << 1)
                    } else if left && viable {
                        3
                    } else {
                        0
                    };
                    domains[split - 1] = (domains[split - 1] & !3) | mask;
                    viable = mask != 0;
                    depth -= 1;
                }
            }
        }
        if !viable {
            return false;
        }
        // Index every observed local/receive commit by actor and decreasing
        // source event. This reuses the propagation stack after that pass;
        // it neither discards a commit nor adds mutable execution state.
        let (previous, scratch) = scratch.split_at_mut(count);
        let mut committed = [usize::MAX; u8::MAX as usize + 1];
        for (event, points) in domains.iter().enumerate() {
            let point = if points & 32 != 0 {
                SourcePoint::Local(event)
            } else if points & 16 != 0 {
                SourcePoint::Received(event)
            } else {
                continue;
            };
            let actor = self
                .point_actor(point)
                .expect("checked history only contains selected source points");
            previous[event] = committed[usize::from(actor)];
            committed[usize::from(actor)] = event;
        }
        let newly_required = |prior: SourcePoint, actor: u8| {
            let mut event = committed[usize::from(actor)];
            while event != usize::MAX && event >= prior.event() {
                let point = if domains[event] & 32 != 0 {
                    SourcePoint::Local(event)
                } else {
                    SourcePoint::Received(event)
                };
                if !self.may_credit_incoming(prior, point)
                    && self.prerequisite(history.clone(), point)(prior, actor)
                {
                    return true;
                }
                event = previous[event];
            }
            false
        };
        let available = |path: &SourcePath<'_, '_, '_>| {
            path.point_actor(point) == Some(actor)
                && path
                    .missing_with(
                        point,
                        |prior| domains[prior.event()] & bit(prior) != 0,
                        |prior, actor| {
                            path.prerequisite_ordered(history.clone(), point)(
                                prior,
                                actor,
                                domains[prior.event()] & SOURCE_ORDER != 0,
                            )
                        },
                    )
                    .is_none()
        };
        choices.fill(0);
        loop {
            let mut used = 0;
            let candidate = source.select_by(
                |span, _, split| {
                    let slot = &mut choices[used];
                    used += 1;
                    match domains[split - 1] & 3 {
                        1 | 2 => {
                            let right = domains[split - 1] & 3 == 2;
                            // Forced choices are not alternatives when backtracking.
                            *slot = 2 + usize::from(right);
                            Ok(right)
                        }
                        3 => {
                            let preferred = self.selection(span).unwrap_or(false);
                            Ok(if *slot == 1 { !preferred } else { preferred })
                        }
                        _ => Err(PathError::Choice { index: used - 1 }),
                    }
                },
                |event, actual| {
                    if event == point.event() && actual[side] != actor {
                        return false;
                    }
                    // These are necessary conditions of the unchanged final
                    // compatibility/readiness checks. Reject a determined
                    // contradiction before enumerating suffix choices that
                    // cannot change this earlier row.
                    for prior in [
                        SourcePoint::Local(event),
                        SourcePoint::Sent(event),
                        SourcePoint::Received(event),
                    ] {
                        let Some((side, _)) = self.point_binding(prior) else {
                            continue;
                        };
                        if domains[event] & bit(prior) != 0 {
                            if self.point_actor(prior) != Some(actual[side]) {
                                return false;
                            }
                        } else if (actual[side] == actor
                            && event <= point.event()
                            && required(prior, actor, domains[prior.event()] & SOURCE_ORDER != 0))
                            || (self.point_actor(prior) != Some(actual[side])
                                && newly_required(prior, actual[side]))
                        {
                            // A newly present predecessor cannot be inserted
                            // before an already committed action. Existing
                            // predecessors were checked in the original path.
                            return false;
                        }
                    }
                    true
                },
                actors,
                self.index,
                scratch,
            );
            if let Ok(path) = candidate
                && available(&path)
            {
                // Forced domains retain the checked prefix's committed
                // leaves. The row predicate retains their actors and rejects
                // newly required predecessors in ordinary source order.
                // An alternative can introduce an actor-local operation in
                // an earlier visit that supplied completion credit. Preserve
                // the actual prefix at every incoming receipt; retaining the
                // old actors alone would not preserve that credit.
                if !source.has_repeated_visits()
                    || history.clone().enumerate().all(|(index, committed)| {
                        !matches!(committed, SourcePoint::Received(_))
                            || path
                                .missing(history.clone().take(index), committed, |prior| {
                                    history.clone().take(index).any(|entry| entry == prior)
                                })
                                .is_none()
                    })
                {
                    return true;
                }
            }
            let Some(index) = choices[..used].iter().rposition(|&choice| choice == 0) else {
                return false;
            };
            choices[index] = 1;
            choices[index + 1..].fill(0);
        }
    }
}

#[cfg(test)]
mod tests;
