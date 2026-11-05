//! Readiness of an uncommitted attempt against the committed source prefix.
use super::{Layout, PathError, SourcePath, SourcePoint, unfolding::NodeKind};

impl SourcePath<'_, '_, '_> {
    pub(super) fn query_workspace_len(&self) -> Option<usize> {
        let source = self.unfolding();
        Layout::checked(source.protocol()).query_words(source.event_count())
    }

    /// A query may select an uncommitted arm, but cannot change the actors,
    /// presence or prerequisites of any operation that already committed.
    /// Search only constructs retrospective evidence; it never drives a view.
    pub(super) fn query_ready(
        &self,
        history: impl Clone + Iterator<Item = SourcePoint>,
        point: SourcePoint,
        actor: u8,
        workspace: &mut [usize],
    ) -> bool {
        let Some((_, binding)) = self.point_binding(point) else {
            return false;
        };
        if binding < 256 && binding != u32::from(actor) {
            return false;
        }
        let finish = match point {
            SourcePoint::Accepted(event) => SourcePoint::Sent(event),
            other => other,
        };
        // A different choice cannot undo publication or repeat a committed
        // point of this same unfolding. Acceptance alone is not publication.
        if history.clone().any(|prior| prior == finish) {
            return false;
        }
        if matches!(point, SourcePoint::Sent(_) | SourcePoint::Received(_))
            && !history
                .clone()
                .any(|prior| prior == SourcePoint::Accepted(point.event()))
        {
            return false;
        }
        let source = self.unfolding();
        let count = source.event_count();
        let (domains, storage) = workspace.split_at_mut(count);
        let (choices, storage) = storage.split_at_mut(count);
        let (actors, scratch) = storage.split_at_mut(count);
        // Bits above each binary domain retain this event's observed points.
        // The immutable word is indexed once; it is not an execution cursor.
        let bit = |prior| match prior {
            SourcePoint::Accepted(_) => 4,
            SourcePoint::Sent(_) => 8,
            SourcePoint::Received(_) => 16,
            SourcePoint::Local(_) => 32,
        };
        domains.fill(0);
        for prior in history.clone() {
            if let Some(row) = domains.get_mut(prior.event()) {
                *row |= bit(prior);
            }
        }
        if self.point_actor(point) == Some(actor)
            && self
                .missing(history.clone(), point, |prior| {
                    domains
                        .get(prior.event())
                        .is_some_and(|row| row & bit(prior) != 0)
                })
                .is_none()
        {
            return true;
        }

        // Propagate necessary conditions through the same immutable source
        // index before enumerating alternatives. A fixed-actor predecessor
        // absent from history forbids its leaf; committed points and the query
        // force their containing arms. Sequence/par need both children, while
        // a choice needs one viable child. Conditional holders are left to
        // full selection and execution checking below.
        let required = self.prerequisite(history.clone(), point);
        let mut viable = false;
        {
            // Reuse the future choice/actor arrays and selection scratch as a
            // depth-bounded traversal stack; only `domains` survives this pass.
            let (states, rest) = scratch.split_at_mut(count);
            let demands = &mut rest[..count];
            let mut total = 0;
            for (event, before) in demands.iter_mut().enumerate() {
                *before = total;
                total += usize::from(event == point.event() || domains[event] & 56 != 0);
            }
            choices[0] = 0;
            actors[0] = count;
            states[0] = 0;
            let mut depth = 1;
            while depth != 0 {
                let frame = depth - 1;
                let span = [choices[frame], actors[frame]];
                let (kind, split) = source
                    .indexed_parts(span, self.index)
                    .expect("checked path contains every source subtree");
                if kind == NodeKind::Message {
                    viable = ![
                        SourcePoint::Local(span[0]),
                        SourcePoint::Sent(span[0]),
                        SourcePoint::Received(span[0]),
                    ]
                    .into_iter()
                    .any(|prior| {
                        self.point_binding(prior).is_some_and(|(_, binding)| {
                            binding == u32::from(actor)
                                && domains[prior.event()] & bit(prior) == 0
                                && required(prior, actor)
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
                            actors[depth] = split;
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
                            actors[depth] = span[1];
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
        let available = |path: &SourcePath<'_, '_, '_>| {
            path.point_actor(point) == Some(actor)
                && path
                    .missing(history.clone(), point, |prior| {
                        domains
                            .get(prior.event())
                            .is_some_and(|row| row & bit(prior) != 0)
                    })
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
                actors,
                self.index,
                scratch,
            );
            if let Ok(path) = candidate {
                let compatible = history.clone().enumerate().all(|(index, prior)| {
                    if matches!(prior, SourcePoint::Accepted(_)) {
                        return true;
                    }
                    path.point_actor(prior) == self.point_actor(prior)
                        && path
                            .check_next(history.clone().take(index), prior, index)
                            .is_ok()
                });
                if compatible && available(&path) {
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
