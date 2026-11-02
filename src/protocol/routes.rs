//! Route evidence and observed operations must describe the same selected arm.
use super::{CustodyError, Layout, Protocol, RecordId, Scope};
use crate::Capture;
use hibana::runtime::tap::{self, TapEvent};

/// Inconsistent choices within one actor's observed route visit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteHistoryError {
    /// The causal witness or delegated-role custody is invalid.
    Custody(CustodyError),
    /// An observation names an unknown choice, arm or resolver mechanism.
    Record { record: RecordId },
    /// Earlier evidence in the same visit selects a different arm.
    Arm {
        record: RecordId,
        prior: RecordId,
        scope: u16,
    },
    /// A completed operation was repeated without an enclosing new visit.
    Duplicate { record: RecordId, prior: RecordId },
    /// A reset names no appropriate source scope or its claimed commit is missing.
    Reentry { record: RecordId },
}

impl Protocol<'_> {
    /// Check route observations against the actual operations in a causal witness.
    ///
    /// Uses `custody_workspace_len` space and also performs `check_custody`.
    /// Each actor shares branch knowledge across its views. A prepared send may
    /// enter a fresh roll before its reset commits; the preparation is local to
    /// that poll. An observed enclosing reset permits a new route visit.
    ///
    /// This checks agreement within observed visits, including resolver results
    /// and passive learning. It does not establish that a reset was enabled or
    /// that source predecessors had completed. Full dynamic conformance also
    /// requires those source-execution checks.
    pub fn check_routes(
        &self,
        captures: &[Capture<'_>],
        order: &[RecordId],
        workspace: &mut [usize],
    ) -> Result<(), RouteHistoryError> {
        self.check_custody(captures, order, workspace)
            .map_err(RouteHistoryError::Custody)?;
        let layout = Layout::checked(*self);
        let observed = |id: RecordId| captures[id.producer].records()[id.ordinal];
        for (position, &id) in order.iter().enumerate() {
            let current = observed(id);
            if current.id() == tap::SCOPE_REENTRY {
                let key = (current.arg1() >> 16) as u16;
                let bounds = layout
                    .scope(self.records, key)
                    .ok_or(RouteHistoryError::Reentry { record: id })?;
                let valid = match key >> 13 {
                    0 => current.arg1() as u16 <= 1 && self.records[bounds.first].arg1() & 4 != 0,
                    1 => {
                        let source = u32::from(current.arg1() as u16);
                        let commit =
                            order[position + 1..]
                                .iter()
                                .map(|&id| observed(id))
                                .find(|next| {
                                    committed(*next)
                                        && next.arg0() == current.arg0()
                                        && next.causal_key() >> 8 == current.causal_key() >> 8
                                        && (next.arg1() >> 24) as u8 == current.causal_key() as u8
                                });
                        bounds.start <= source
                            && source < bounds.end
                            && commit
                                .is_some_and(|next| next.arg1() as u16 == current.arg1() as u16)
                    }
                    _ => false,
                };
                if !valid {
                    return Err(RouteHistoryError::Reentry { record: id });
                }
            }
            if committed(current) || current.id() == tap::SEND_POLL {
                let event = usize::from(current.arg1() as u16);
                let source = self.records[layout.sources.start + event];
                let local = source.arg0() >> 24 == (source.arg0() >> 16) & 255;
                let direction = if local {
                    0
                } else if current.id() == tap::SEND_POLL {
                    1
                } else {
                    current.causal_key() as u8
                };
                let prepared = if current.id() == tap::SEND_POLL {
                    (current.arg1() >> 16) as u16
                } else {
                    u16::MAX
                };
                let fresh = prepared != u16::MAX
                    && layout.scope(self.records, prepared).is_some_and(|scope| {
                        scope.start <= event as u32 && (event as u32) < scope.end
                    });
                if !fresh {
                    for &prior_id in order[..position].iter().rev() {
                        let prior = observed(prior_id);
                        if prior.arg0() != current.arg0()
                            || prior.causal_key() >> 8 != current.causal_key() >> 8
                        {
                            continue;
                        }
                        if prior.id() == tap::SCOPE_REENTRY
                            && layout
                                .scope(self.records, (prior.arg1() >> 16) as u16)
                                .is_some_and(|scope| {
                                    scope.start <= event as u32 && (event as u32) < scope.end
                                })
                        {
                            break;
                        }
                        if committed(prior)
                            && prior.arg1() as u16 == current.arg1() as u16
                            && (local || prior.causal_key() as u8 == direction)
                        {
                            return Err(RouteHistoryError::Duplicate {
                                record: id,
                                prior: prior_id,
                            });
                        }
                    }
                }
            }
            if matches!(current.id(), tap::RESOLVER_AUDIT | tap::ROUTE_ARM_SELECTION) {
                let choice = self.records[layout.choices.clone()]
                    .iter()
                    .find(|choice| u32::from(choice.causal_key()) == current.arg1() >> 16)
                    .ok_or(RouteHistoryError::Record { record: id })?;
                let result = current.causal_key() as u8;
                let valid = if current.id() == tap::RESOLVER_AUDIT {
                    choice.arg1() == u32::from(current.arg1() as u16) + 1
                        && matches!(result, 0 | 1 | 255)
                } else {
                    current.arg1() as u16 <= 1
                        && matches!(result, 1..=3)
                        && (result != 2 || choice.arg1() != 0)
                };
                if !valid {
                    return Err(RouteHistoryError::Record { record: id });
                }
                if current.id() == tap::ROUTE_ARM_SELECTION && result == 2 {
                    let audit =
                        order[..position]
                            .iter()
                            .rev()
                            .map(|&id| observed(id))
                            .find(|prior| {
                                prior.id() == tap::RESOLVER_AUDIT
                                    && prior.arg0() == current.arg0()
                                    && prior.causal_key() >> 8 == current.causal_key() >> 8
                                    && prior.arg1() >> 16 == current.arg1() >> 16
                            });
                    if audit.is_none_or(|audit| {
                        u16::from(audit.causal_key() as u8) != current.arg1() as u16
                    }) {
                        return Err(RouteHistoryError::Record { record: id });
                    }
                }
            }
            for choice in &self.records[layout.choices.clone()] {
                let key = choice.causal_key();
                let bounds = layout
                    .scope(self.records, key)
                    .expect("checked choice has a source scope");
                let Some(arm) = selected(current, key, &bounds) else {
                    continue;
                };
                if current.id() == tap::SEND_POLL {
                    let prepared = (current.arg1() >> 16) as u16;
                    if prepared != u16::MAX
                        && layout
                            .scope(self.records, prepared)
                            .is_some_and(|outer| contains(&outer, &bounds))
                    {
                        continue;
                    }
                }
                for &prior_id in order[..position].iter().rev() {
                    let prior = observed(prior_id);
                    if prior.arg0() != current.arg0()
                        || prior.causal_key() >> 8 != current.causal_key() >> 8
                    {
                        continue;
                    }
                    if prior.id() == tap::SCOPE_REENTRY {
                        let reset_key = (prior.arg1() >> 16) as u16;
                        if layout
                            .scope(self.records, reset_key)
                            .is_some_and(|outer| contains(&outer, &bounds))
                        {
                            if reset_key == key && prior.arg1() as u16 != u16::from(arm) {
                                return Err(RouteHistoryError::Arm {
                                    record: id,
                                    prior: prior_id,
                                    scope: key,
                                });
                            }
                            break;
                        }
                    }
                    if prior.id() == tap::SEND_POLL {
                        let prepared = (prior.arg1() >> 16) as u16;
                        if prepared != u16::MAX
                            && layout
                                .scope(self.records, prepared)
                                .is_some_and(|outer| contains(&outer, &bounds))
                        {
                            continue;
                        }
                    }
                    if let Some(earlier) = selected(prior, key, &bounds) {
                        if earlier != arm {
                            return Err(RouteHistoryError::Arm {
                                record: id,
                                prior: prior_id,
                                scope: key,
                            });
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}

fn contains(outer: &Scope, inner: &Scope) -> bool {
    outer.first <= inner.first && inner.last <= outer.last
}

fn committed(record: TapEvent) -> bool {
    matches!(
        record.id(),
        tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ENDPOINT_SESSION
    )
}

fn selected(record: TapEvent, key: u16, bounds: &Scope) -> Option<u8> {
    if record.id() == tap::ROUTE_ARM_SELECTION && record.arg1() >> 16 == u32::from(key) {
        return Some(record.arg1() as u8);
    }
    if !matches!(
        record.id(),
        tap::SEND_POLL | tap::ENDPOINT_SEND | tap::ENDPOINT_RECV | tap::ENDPOINT_SESSION
    ) {
        return None;
    }
    let event = u32::from(record.arg1() as u16);
    (bounds.start <= event && event < bounds.end).then(|| u8::from(event >= bounds.split.unwrap()))
}
