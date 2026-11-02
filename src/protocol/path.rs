//! Select a finite source path and reconstruct its physical actor bindings.
use super::{Layout, Unfold, Unfolded, unfolding::NodeKind};

/// One selected occurrence of a route in a finite source unfolding.
///
/// The half-open event range identifies a real expanded choice subtree.
/// Different visits of one original route have different ranges.
#[derive(Clone, Copy, Debug)]
pub struct RouteChoice {
    /// Expanded subtree containing both arms of this route visit.
    pub span: [usize; 2],
    /// Select the right arm; false selects the left arm.
    pub right: bool,
}

/// The proposed path disagrees with its source or physical actor bindings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// Caller-owned words needed for the actual expansion size.
    Workspace { required: usize, actual: usize },
    /// The expansion's storage requirement is not representable on this target.
    Overflow,
    /// A choice is duplicated, inactive, missing or not a route subtree.
    Choice { index: usize },
    /// A source actor binding is unresolved or disagrees with source ownership.
    Binding { event: usize },
    /// A source transfer is made by someone other than the resource's holder.
    Owner { event: usize, role: u8 },
    /// A transfer conflicts with an unordered operation on the same resource.
    ParallelResource {
        first: usize,
        second: usize,
        role: u8,
    },
    /// Independently unfolded parallel visits share a physical participant.
    ParallelActor { first: usize, second: usize },
    /// A checked unfolding failed to expose its expected binary subtree.
    Structure { start: usize, end: usize },
    /// A resumed body has no selected earlier entry in this source path.
    Anchor { event: usize },
    /// A resource used by a resumed operation changed holder since its entry.
    EntryOwner { event: usize, role: u8 },
}

/// A selected source path with reconstructed, compiler-matched physical actors.
///
/// This checks source-path ownership and parallel separation, not execution
/// history. Retained entries and their ownership are checked against this same
/// selected path. Operation readiness remains an additional obligation before
/// a dynamic execution can be certified.
#[derive(Clone, Copy)]
pub struct SourcePath<'p, 'u, 'w> {
    source: Unfolded<'p, 'u>,
    actors: &'w [usize],
    choices: &'w [RouteChoice],
}

impl<'p, 'u> Unfolded<'p, 'u> {
    /// Temporary words for selecting and normalizing this finite source.
    pub fn path_workspace_len(&self) -> Result<usize, PathError> {
        let layout = Layout::checked(self.protocol());
        self.event_count()
            .checked_mul(3)
            .and_then(|n| n.checked_add(layout.initial.len()))
            .and_then(|n| n.checked_add(layout.choices.len()))
            .ok_or(PathError::Overflow)
    }

    /// Check the active choices and reconstruct actors from the source's sole
    /// initial bindings and its selected transfers. The completed source rows
    /// are also compared with the compiled conditional actor references using
    /// the same selected source choices, rather than candidate-set membership.
    ///
    /// Sequence and parallel children are visited in source order. Conflicting
    /// parallel transfer/use pairs are then rejected, and independent visit
    /// counts require disjoint physical participants. No execution authority
    /// or Endpoint is created by this retrospective computation.
    pub fn select<'w>(
        &self,
        choices: &'w [RouteChoice],
        workspace: &'w mut [usize],
    ) -> Result<SourcePath<'p, 'u, 'w>, PathError> {
        let required = self.path_workspace_len()?;
        if workspace.len() < required {
            return Err(PathError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        for (index, choice) in choices.iter().enumerate() {
            if choices[..index]
                .iter()
                .any(|prior| prior.span == choice.span)
                || !matches!(self.parts(choice.span), Some((NodeKind::Choice(_), _)))
            {
                return Err(PathError::Choice { index });
            }
        }
        let protocol = self.protocol();
        let records = protocol.records;
        let layout = Layout::checked(protocol);
        let count = self.event_count();
        let (actors, rest) = workspace[..required].split_at_mut(count);
        let (stack, rest) = rest.split_at_mut(2 * count);
        let (owners, selected) = rest.split_at_mut(layout.initial.len());
        actors.fill(usize::MAX);
        selected.fill(0);
        for (owner, initial) in owners.iter_mut().zip(&records[layout.initial.clone()]) {
            *owner = initial.arg1() as usize;
        }
        stack[..2].copy_from_slice(&[0, count]);
        let mut depth = 2;
        let mut used = 0;
        while depth != 0 {
            depth -= 2;
            let span = [stack[depth], stack[depth + 1]];
            let (kind, split) = self.parts(span).ok_or(PathError::Structure {
                start: span[0],
                end: span[1],
            })?;
            match kind {
                NodeKind::Message => {
                    let event = span[0];
                    let origin = usize::from(self.origin(event).ok_or(PathError::Structure {
                        start: event,
                        end: event + 1,
                    })?);
                    let source = records[layout.sources.start + origin];
                    let from = (source.arg0() >> 24) as u8;
                    let to = (source.arg0() >> 16) as u8;
                    let held = |role: u8| {
                        records[layout.initial.clone()]
                            .iter()
                            .position(|initial| initial.arg0() == u32::from(role))
                            .map_or(usize::from(role), |index| owners[index])
                    };
                    let sender = held(from);
                    let receiver = held(to);
                    let expected = if layout.bindings.is_empty() {
                        [usize::from(from), usize::from(to)]
                    } else {
                        let binding = records[layout.bindings.start + origin];
                        [
                            layout
                                .actor(records, selected, binding.arg0())
                                .ok_or(PathError::Binding { event })?,
                            layout
                                .actor(records, selected, binding.arg1())
                                .ok_or(PathError::Binding { event })?,
                        ]
                    };
                    if expected != [sender, receiver] {
                        return Err(PathError::Binding { event });
                    }
                    actors[event] = sender << 8 | receiver;
                    if source.causal_key() >> 8 == 1 {
                        let role = source.arg1() as u8;
                        let resource = records[layout.initial.clone()]
                            .iter()
                            .position(|initial| initial.arg0() == u32::from(role))
                            .expect("compiled endpoint payload has one initial binding");
                        if owners[resource] != sender {
                            return Err(PathError::Owner { event, role });
                        }
                        owners[resource] = receiver;
                    }
                }
                NodeKind::Choice(scope) => {
                    let (index, choice) = choices
                        .iter()
                        .enumerate()
                        .find(|(_, choice)| choice.span == span)
                        .ok_or(PathError::Choice {
                            index: choices.len(),
                        })?;
                    let ordinal = records[layout.choices.clone()]
                        .iter()
                        .position(|row| row.causal_key() == scope)
                        .ok_or(PathError::Choice { index })?;
                    selected[ordinal] = 1 + usize::from(choice.right);
                    used += 1;
                    stack[depth..depth + 2].copy_from_slice(&if choice.right {
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
        if used != choices.len() {
            return Err(PathError::Choice {
                index: choices.len(),
            });
        }
        for first in 0..count {
            if actors[first] == usize::MAX {
                continue;
            }
            for second in first + 1..count {
                if actors[second] == usize::MAX {
                    continue;
                }
                let sides = |packed: usize| [packed >> 8, packed & 255];
                if self.independent_between(first, second)
                    && sides(actors[first])
                        .iter()
                        .any(|actor| sides(actors[second]).contains(actor))
                {
                    return Err(PathError::ParallelActor { first, second });
                }
                if self.before(first, second) {
                    continue;
                }
                let a = records[layout.sources.start + usize::from(self.origin(first).unwrap())];
                let b = records[layout.sources.start + usize::from(self.origin(second).unwrap())];
                for (transfer, other) in [(a, b), (b, a)] {
                    if transfer.causal_key() >> 8 != 1 {
                        continue;
                    }
                    let role = transfer.arg1() as u8;
                    let used = (other.arg0() >> 24) as u8 == role
                        || (other.arg0() >> 16) as u8 == role
                        || (other.causal_key() >> 8 == 1 && other.arg1() as u8 == role);
                    if used {
                        return Err(PathError::ParallelResource {
                            first,
                            second,
                            role,
                        });
                    }
                }
            }
        }
        let path = SourcePath {
            source: *self,
            actors,
            choices,
        };
        path.check_entries()?;
        Ok(path)
    }
}

impl SourcePath<'_, '_, '_> {
    pub(super) fn choice_at(&self, event: usize, scope: u16) -> Option<bool> {
        self.choices.iter().find_map(|choice| {
            let (kind, _) = self.source.parts(choice.span)?;
            let NodeKind::Choice(found) = kind else {
                return None;
            };
            (choice.span[0] <= event && event < choice.span[1] && found == scope)
                .then_some(choice.right)
        })
    }

    fn check_entries(&self) -> Result<(), PathError> {
        let source = self.source;
        let protocol = source.protocol();
        let layout = Layout::checked(protocol);
        for event in 0..source.event_count() {
            if self.actors(event).is_none() {
                continue;
            }
            let mut result = Ok(());
            source.contexts(event, |proof, base, local| {
                let body = match source.step(proof) {
                    Unfold::After { earlier, .. } if local >= source.count(earlier) => {
                        Some(source.count(earlier))
                    }
                    Unfold::Alongside {
                        earlier,
                        next,
                        focus,
                        ..
                    }
                    | Unfold::Before {
                        earlier,
                        next,
                        focus,
                        ..
                    } => {
                        let start = source.count(earlier) + focus[0];
                        if start <= local && local - start < source.count(next) {
                            source
                                .copy_range(next, local - start)
                                .map(|copy| start + copy[0])
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                let Some(body) = body else {
                    return true;
                };
                let Some(anchor) = source.resumption_anchor(proof) else {
                    result = Err(PathError::Anchor { event });
                    return false;
                };
                let selected = (0..source.event_count()).any(|candidate| {
                    self.actors(candidate).is_some()
                        && source
                            .local_position(candidate, proof, base)
                            .is_some_and(|position| anchor[0] <= position && position < anchor[1])
                });
                if !selected {
                    result = Err(PathError::Anchor { event });
                    return false;
                }
                let (Some(first), Some(next)) = (
                    source.global_position(proof, base, anchor[0]),
                    source.global_position(proof, base, body),
                ) else {
                    result = Err(PathError::Anchor { event });
                    return false;
                };
                let row = protocol.records
                    [layout.sources.start + usize::from(source.origin(event).unwrap())];
                let from = (row.arg0() >> 24) as u8;
                let to = (row.arg0() >> 16) as u8;
                let uses = core::iter::once(from)
                    .chain((to != from).then_some(to))
                    .chain((row.causal_key() >> 8 == 1).then_some(row.arg1() as u8));
                for role in uses {
                    if self.owner_before(first, role) != self.owner_before(next, role) {
                        result = Err(PathError::EntryOwner { event, role });
                        return false;
                    }
                }
                true
            });
            result?;
        }
        Ok(())
    }

    fn owner_before(&self, boundary: usize, role: u8) -> usize {
        let protocol = self.source.protocol();
        let layout = Layout::checked(protocol);
        let mut owner = protocol.records[layout.initial.clone()]
            .iter()
            .find(|initial| initial.arg0() == u32::from(role))
            .map_or(usize::from(role), |initial| initial.arg1() as usize);
        for event in 0..boundary {
            let Some([_, receiver]) = self.actors(event) else {
                continue;
            };
            let row = protocol.records
                [layout.sources.start + usize::from(self.source.origin(event).unwrap())];
            if row.causal_key() >> 8 == 1 && row.arg1() == u32::from(role) {
                owner = usize::from(receiver);
            }
        }
        owner
    }

    /// Physical sender and receiver of a selected expanded event.
    /// Unselected arms and out-of-range positions return None.
    pub fn actors(&self, event: usize) -> Option<[u8; 2]> {
        let &packed = self.actors.get(event)?;
        (packed != usize::MAX).then_some([(packed >> 8) as u8, packed as u8])
    }

    /// The same source witness, without changing or copying its expansion.
    pub fn unfolding(&self) -> Unfolded<'_, '_> {
        self.source
    }
}

impl Layout {
    fn actor(
        &self,
        records: &[hibana::runtime::tap::TapEvent],
        selected: &[usize],
        mut reference: u32,
    ) -> Option<usize> {
        while reference >= 256 {
            let decision = records[self.decisions.start + (reference - 256) as usize];
            let choice = records[self.choices.clone()]
                .iter()
                .position(|choice| choice.causal_key() == decision.causal_key())?;
            reference = match selected[choice] {
                1 => decision.arg0(),
                2 => decision.arg1(),
                _ => return None,
            };
        }
        Some(reference as usize)
    }
}
