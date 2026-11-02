//! Construct source, route and execution witnesses from the compiled protocol.
use super::{
    ExecutionStorage, ExecutionWitness, InterpretationError, Layout, Protocol, RouteChoice,
    SourcePath, Unfold, Unfolded,
    unfolding::{NodeKind, generate::Derivations},
};
use crate::Capture;
use hibana::runtime::tap;

/// Caller-owned witness outputs. No application state or authority is stored.
pub struct AuditStorage<'a> {
    /// Maximum number of source-derivation nodes to search.
    pub unfolding: &'a mut [Unfold],
    /// Space for route occurrences in the largest searched expansion.
    pub choices: &'a mut [RouteChoice],
    /// Complete capture ordering, occurrence and acceptance outputs.
    pub execution: ExecutionStorage<'a>,
}

/// A checked interpretation, borrowing its source and all evidence outputs.
///
/// It can only be constructed by the checker, rather than by pairing a valid
/// path with an unchecked proposed execution.
///
/// ```compile_fail
/// use hibana_epf::{Audit, ExecutionWitness, SourcePath};
/// fn forge<'p, 'a>(path: SourcePath<'p, 'a, 'a>, execution: ExecutionWitness<'a>)
///     -> Audit<'p, 'a>
/// {
///     Audit { path, execution }
/// }
/// ```
pub struct Audit<'p, 'a> {
    path: SourcePath<'p, 'a, 'a>,
    execution: ExecutionWitness<'a>,
}

impl<'p, 'a> Audit<'p, 'a> {
    /// Source-derived path, including each selected dynamic route occurrence.
    pub fn path(&self) -> SourcePath<'p, 'a, 'a> {
        self.path
    }

    /// Checked producer order, source attribution and acceptance intervals.
    pub fn execution(&self) -> &ExecutionWitness<'a> {
        &self.execution
    }
}

/// Failure to construct a certificate; exhaustion never means an illegal global.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// Temporary and retained caller storage is too short.
    Workspace { required: usize, actual: usize },
    /// Route output cannot hold the largest searched expansion's choices.
    Choices { required: usize, actual: usize },
    /// Invalid capture evidence or insufficient execution output storage.
    Evidence(InterpretationError),
    /// No derivation within the caller's capacity yielded a checked execution.
    Exhausted { derivation_capacity: usize },
    /// Required arithmetic cannot be represented on this target.
    Overflow,
}

impl<'p> Protocol<'p> {
    /// Maximum expanded message count for trees of this many proof nodes.
    pub fn audit_choice_capacity(&self, derivation_capacity: usize) -> Result<usize, AuditError> {
        Layout::checked(*self)
            .sources
            .len()
            .checked_mul(derivation_capacity)
            .ok_or(AuditError::Overflow)
    }

    /// Eight search words and five retained words per derivation node, three
    /// retained words per possible message, and execution-checking workspace.
    /// All capacities derive from the supplied source, captures and proof size.
    pub fn audit_workspace_len(
        &self,
        captures: &[Capture<'_>],
        derivation_capacity: usize,
    ) -> Result<usize, AuditError> {
        let layout = Layout::checked(*self);
        let events = self.audit_choice_capacity(derivation_capacity)?;
        // Also ensure every insertion interval's enumeration is representable.
        events
            .checked_mul(events.checked_add(1).ok_or(AuditError::Overflow)?)
            .ok_or(AuditError::Overflow)?;
        let records = captures
            .iter()
            .try_fold(0usize, |n, c| n.checked_add(c.records().len()))
            .ok_or(AuditError::Overflow)?;
        let execution = records
            .checked_mul(8)
            .and_then(|n| n.checked_add(captures.len()))
            .and_then(|n| n.checked_add(self.custody_words(captures)?))
            .ok_or(AuditError::Overflow)?;
        derivation_capacity
            .checked_mul(13)
            .and_then(|n| n.checked_add(layout.sources.len().checked_mul(2)?))
            .and_then(|n| n.checked_add(events.checked_mul(3)?))
            .and_then(|n| n.checked_add(layout.initial.len()))
            .and_then(|n| n.checked_add(layout.choices.len()))
            .and_then(|n| n.checked_add(execution.max(events.checked_mul(2)?)))
            .ok_or(AuditError::Overflow)
    }

    /// Construct a finite dynamic interpretation without a handwritten audit
    /// global, unfolding, route selection, record order or occurrence mapping.
    ///
    /// Enumerates source-typed trees in increasing proof size. Every source
    /// constructor and retained-roll insertion is included; there is no fixed
    /// depth, visit or step limit. Caller capacity bounds the finite search.
    /// Search may be exponential. Exhaustion or missing evidence returns no
    /// certificate, rather than authorizing an operation or rejecting a global.
    ///
    /// A successful candidate passes the independent execution checker. This
    /// certifies compatibility with a source execution, not a recovered clock,
    /// session termination, authenticated transport or application effects.
    pub fn audit<'a>(
        &self,
        captures: &[Capture<'_>],
        storage: AuditStorage<'a>,
        workspace: &'a mut [usize],
    ) -> Result<Audit<'p, 'a>, AuditError> {
        let AuditStorage {
            unfolding,
            choices,
            execution,
        } = storage;
        let capacity = unfolding.len();
        let events = self.audit_choice_capacity(capacity)?;
        if choices.len() < events {
            return Err(AuditError::Choices {
                required: events,
                actual: choices.len(),
            });
        }
        let required = self.audit_workspace_len(captures, capacity)?;
        if workspace.len() < required {
            return Err(AuditError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let layout = Layout::checked(*self);
        let (search, rest) =
            workspace[..required].split_at_mut(8 * capacity + 2 * layout.sources.len());
        let (proof, rest) = rest.split_at_mut(5 * capacity);
        let (actors, scratch) =
            rest.split_at_mut(3 * events + layout.initial.len() + layout.choices.len());
        let ExecutionStorage {
            session,
            order,
            occurrences,
            acceptances,
        } = execution;
        let (size, selected, accepted) = {
            let mut seed =
                super::unfolding::generate::seed(*self, captures, session, &mut *unfolding, search);
            let mut derivations = Derivations::new(*self, &mut *unfolding, search);
            'search: loop {
                let Some(size) = seed.take().or_else(|| derivations.next()) else {
                    return Err(AuditError::Exhausted {
                        derivation_capacity: capacity,
                    });
                };
                let Ok(source) = self.unfolding(&derivations.steps[..size], proof) else {
                    continue;
                };
                if source.event_count() > events {
                    continue;
                }
                if !enough_occurrences(source, captures, session) {
                    continue;
                }
                let mut retained = 0;
                loop {
                    let selected =
                        route_choices(source, choices, retained, captures, session, scratch);
                    if let Ok(path) = source.select(&choices[..selected], actors) {
                        match path.interpret(
                            captures,
                            ExecutionStorage {
                                session,
                                order: &mut *order,
                                occurrences: &mut *occurrences,
                                acceptances: &mut *acceptances,
                            },
                            scratch,
                        ) {
                            Ok(witness) => {
                                break 'search (size, selected, witness.acceptances.len());
                            }
                            Err(InterpretationError::NoInterpretation) => {}
                            Err(error) => return Err(AuditError::Evidence(error)),
                        }
                    }
                    let Some(index) = (0..selected).rev().find(|&i| {
                        choices[i].right
                            == route_preference(
                                source,
                                &choices[..i],
                                choices[i].span,
                                captures,
                                session,
                            )
                    }) else {
                        break;
                    };
                    choices[index].right = !choices[index].right;
                    retained = index + 1;
                }
            }
        };
        // Publish only immutable witnesses reconstructed from the winning
        // outputs, and check the exact returned combination once more.
        let source = self
            .unfolding(&unfolding[..size], proof)
            .expect("checked derivation");
        let path = source
            .select(&choices[..selected], actors)
            .expect("checked selections");
        let execution = ExecutionWitness {
            session,
            order,
            occurrences,
            acceptances: &acceptances[..accepted],
        };
        path.check_execution(captures, &execution, scratch)
            .map_err(|e| AuditError::Evidence(InterpretationError::Evidence(e)))?;
        Ok(Audit { path, execution })
    }
}

fn enough_occurrences(source: Unfolded<'_, '_>, captures: &[Capture<'_>], session: u32) -> bool {
    let protocol = source.protocol();
    let layout = Layout::checked(protocol);
    for origin in 0..layout.sources.len() {
        let copies = (0..source.event_count())
            .filter(|&i| source.origin(i) == Some(origin as u16))
            .count();
        for kind in [tap::ENDPOINT_SEND, tap::ENDPOINT_RECV] {
            let commits = captures
                .iter()
                .flat_map(|c| c.records())
                .filter(|row| {
                    row.id() == kind && row.arg0() == session && row.arg1() as u16 == origin as u16
                })
                .count();
            if commits > copies {
                return false;
            }
        }
    }
    true
}

fn route_choices(
    source: Unfolded<'_, '_>,
    choices: &mut [RouteChoice],
    retained: usize,
    captures: &[Capture<'_>],
    session: u32,
    stack: &mut [usize],
) -> usize {
    let mut depth = 2;
    stack[..2].copy_from_slice(&[0, source.event_count()]);
    let mut count = 0;
    while depth != 0 {
        depth -= 2;
        let span = [stack[depth], stack[depth + 1]];
        let (kind, split) = source.parts(span).expect("checked source subtree");
        match kind {
            NodeKind::Message => {}
            NodeKind::Choice(_) => {
                let right = if count < retained {
                    choices[count].right
                } else {
                    route_preference(source, &choices[..count], span, captures, session)
                };
                choices[count] = RouteChoice { span, right };
                count += 1;
                stack[depth..depth + 2].copy_from_slice(&if right {
                    [split, span[1]]
                } else {
                    [span[0], split]
                });
                depth += 2;
            }
            NodeKind::Sequence | NodeKind::Parallel => {
                stack[depth..depth + 4].copy_from_slice(&[split, span[1], span[0], split]);
                depth += 4;
            }
        }
    }
    count
}

// Search the observed arm first. This is a preference, not a reconstructed
// distributed visit number: the opposite arm remains in the exhaustive search
// and every completed candidate still passes check_execution. Use one
// producer's actor stream rather than treating producer ordinals as a clock.
fn route_preference(
    source: Unfolded<'_, '_>,
    earlier: &[RouteChoice],
    span: [usize; 2],
    captures: &[Capture<'_>],
    session: u32,
) -> bool {
    let Some((NodeKind::Choice(key), _)) = source.parts(span) else {
        return false;
    };
    let visit = earlier.iter().filter(|choice|
        matches!(source.parts(choice.span), Some((NodeKind::Choice(prior), _)) if prior == key)
    ).count();
    let matches = |record: &&tap::TapEvent| {
        record.id() == tap::ROUTE_ARM_SELECTION
            && record.arg0() == session
            && record.arg1() >> 16 == u32::from(key)
    };
    for capture in captures {
        let Some(first) = capture.records().iter().find(matches) else {
            continue;
        };
        let actor = first.causal_key() >> 8;
        return capture
            .records()
            .iter()
            .filter(matches)
            .filter(|record| record.causal_key() >> 8 == actor)
            .nth(visit)
            .is_some_and(|record| record.arg1() as u16 == 1);
    }
    false
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use hibana::{g, runtime::program::project};
    use std::vec;

    #[test]
    fn an_observed_arm_changes_search_order_without_removing_the_opposite_arm() {
        let global = g::route(
            g::send::<7, 7, g::Msg<1, ()>>(),
            g::send::<7, 7, g::Msg<2, ()>>(),
        );
        let snapshot = tap::projected(&project::<7>(&global)).collect::<std::vec::Vec<_>>();
        let key = snapshot
            .iter()
            .find(|r| r.id() == tap::PROJECTED_CHOICE)
            .unwrap()
            .causal_key();
        let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
        let steps = [Unfold::Source];
        let mut proof = [0; 5];
        let source = protocol.unfolding(&steps, &mut proof).unwrap();
        let mut bytes = [0; 16];
        bytes[4..6].copy_from_slice(&tap::ROUTE_ARM_SELECTION.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x0707u16.to_be_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..].copy_from_slice(&(u32::from(key) << 16 | 1).to_be_bytes());
        let records = [bytes.into()];
        let captures = [Capture::new(&records, Some(1)).unwrap()];
        let mut choices = [RouteChoice {
            span: [0, 0],
            right: false,
        }; 2];
        let mut stack = [0; 4];
        assert_eq!(
            route_choices(source, &mut choices, 0, &captures, 1, &mut stack),
            1
        );
        assert!(choices[0].right);
        assert_eq!(
            choices[0].right,
            route_preference(source, &[], choices[0].span, &captures, 1)
        );
        choices[0].right = !choices[0].right;
        assert_eq!(
            route_choices(source, &mut choices, 1, &captures, 1, &mut stack),
            1
        );
        assert!(!choices[0].right);
        assert_ne!(
            choices[0].right,
            route_preference(source, &[], choices[0].span, &captures, 1)
        );
    }
}
