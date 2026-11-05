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
    pub(super) index: &'w [usize],
}

impl<'p, 'u> Unfolded<'p, 'u> {
    /// Caller-owned actor rows, immutable binary index and selection scratch.
    pub fn path_workspace_len(&self) -> Result<usize, PathError> {
        let layout = Layout::checked(self.protocol());
        layout
            .path_words(self.event_count())
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
        choices: &[RouteChoice],
        workspace: &'w mut [usize],
    ) -> Result<SourcePath<'p, 'u, 'w>, PathError> {
        let required = self.path_workspace_len()?;
        if workspace.len() < required {
            return Err(PathError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let (actors, scratch) = workspace[..required].split_at_mut(self.event_count());
        let (parts, scratch) =
            scratch.split_at_mut(Layout::path_index_words(self.event_count()).unwrap());
        self.select_in(choices, actors, parts, scratch)
    }

    pub(super) fn select_in<'w>(
        &self,
        choices: &[RouteChoice],
        actors: &'w mut [usize],
        parts: &'w mut [usize],
        scratch: &mut [usize],
    ) -> Result<SourcePath<'p, 'u, 'w>, PathError> {
        self.index_source(parts, actors, scratch)?;
        for (index, choice) in choices.iter().enumerate() {
            if choices[..index]
                .iter()
                .any(|prior| prior.span == choice.span)
                || !matches!(self.kind(choice.span), Some(NodeKind::Choice(_)))
            {
                return Err(PathError::Choice { index });
            }
        }
        let mut used = 0;
        let path =
            self.select_by(
                |span, _, _| {
                    let choice = choices.iter().find(|choice| choice.span == span).ok_or(
                        PathError::Choice {
                            index: choices.len(),
                        },
                    )?;
                    used += 1;
                    Ok(choice.right)
                },
                actors,
                parts,
                scratch,
            )?;
        if used != choices.len() {
            return Err(PathError::Choice {
                index: choices.len(),
            });
        }
        Ok(path)
    }

    pub(super) fn select_by<'w>(
        &self,
        mut choose: impl FnMut([usize; 2], u16, usize) -> Result<bool, PathError>,
        actors: &'w mut [usize],
        parts: &'w [usize],
        workspace: &mut [usize],
    ) -> Result<SourcePath<'p, 'u, 'w>, PathError> {
        let required = self.path_workspace_len()?;
        let count = self.event_count();
        let layout = Layout::checked(self.protocol());
        let temporary = layout.path_scratch_words(count).unwrap();
        if actors.len() < count
            || parts.len() < Layout::path_index_words(count).unwrap()
            || workspace.len() < temporary
        {
            return Err(PathError::Workspace {
                required,
                actual: workspace.len() + actors.len() + parts.len(),
            });
        }
        let protocol = self.protocol();
        let records = protocol.records;
        let actors = &mut actors[..count];
        let parts = &parts[..Layout::path_index_words(count).unwrap()];
        let (origins, order) = parts[Layout::binary_words(count).unwrap()..].split_at(count);
        let (stack, rest) = workspace[..temporary].split_at_mut(2 * count);
        let (owners, rest) = rest.split_at_mut(layout.initial.len());
        let (selected, last) = rest.split_at_mut(layout.choices.len());
        actors.fill(usize::MAX);
        selected.fill(0);
        for (owner, initial) in owners.iter_mut().zip(&records[layout.initial.clone()]) {
            *owner = initial.arg1() as usize;
        }
        stack[..2].copy_from_slice(&[0, count]);
        let mut depth = 2;
        while depth != 0 {
            depth -= 2;
            let span = [stack[depth], stack[depth + 1]];
            let (kind, split) = self
                .indexed_parts(span, parts)
                .ok_or(PathError::Structure {
                    start: span[0],
                    end: span[1],
                })?;
            match kind {
                NodeKind::Message => {
                    let event = span[0];
                    let origin = origins[event];
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
                    let right = choose(span, scope, split)?;
                    let ordinal = records[layout.choices.clone()]
                        .iter()
                        .position(|row| row.causal_key() == scope)
                        .ok_or(PathError::Choice { index: 0 })?;
                    selected[ordinal] = 1 + usize::from(right);
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
        if let Some((first, second)) = self.independent_conflict(actors, order, last) {
            return Err(PathError::ParallelActor { first, second });
        }
        for transfer in 0..count {
            if actors[transfer] == usize::MAX {
                continue;
            }
            let loan = records[layout.sources.start + origins[transfer]];
            if loan.causal_key() >> 8 != 1 {
                continue;
            }
            let role = loan.arg1() as u8;
            for other in 0..count {
                if other == transfer || actors[other] == usize::MAX {
                    continue;
                }
                let row = records[layout.sources.start + origins[other]];
                let used = (row.arg0() >> 24) as u8 == role
                    || (row.arg0() >> 16) as u8 == role
                    || (row.causal_key() >> 8 == 1 && row.arg1() as u8 == role);
                if !used {
                    continue;
                }
                let first = transfer.min(other);
                let second = transfer.max(other);
                if !self.before(first, second) {
                    return Err(PathError::ParallelResource {
                        first,
                        second,
                        role,
                    });
                }
            }
        }
        let path = SourcePath {
            source: *self,
            actors,
            index: parts,
        };
        path.check_entries()?;
        Ok(path)
    }

    // One row per binary boundary: parent boundary, subtree end and kind;
    // followed by source origins and the permutation into proof-leaf order.
    // The actor output is not live yet, so it supplies the DFS's parent slots.
    pub(super) fn index_source(
        &self,
        parts: &mut [usize],
        parents: &mut [usize],
        stack: &mut [usize],
    ) -> Result<(), PathError> {
        let count = self.event_count();
        let required = self.path_workspace_len()?;
        if parts.len() < Layout::path_index_words(count).unwrap()
            || parents.len() < count
            || stack.len() < 2 * count
        {
            return Err(PathError::Workspace {
                required,
                actual: parts.len() + parents.len() + stack.len(),
            });
        }
        let (parts, locators) = parts[..Layout::path_index_words(count).unwrap()]
            .split_at_mut(Layout::binary_words(count).unwrap());
        stack[..2].copy_from_slice(&[0, count]);
        parents[0] = usize::MAX;
        let mut depth = 2;
        while depth != 0 {
            depth -= 2;
            let span = [stack[depth], stack[depth + 1]];
            let parent = parents[depth / 2];
            let (kind, split) = self.parts(span).ok_or(PathError::Structure {
                start: span[0],
                end: span[1],
            })?;
            let tag = match kind {
                NodeKind::Message => continue,
                NodeKind::Sequence => 0,
                NodeKind::Parallel => 1,
                NodeKind::Choice(scope) => usize::from(scope) + 2,
            };
            let node = split - 1;
            parts[3 * node..3 * node + 3].copy_from_slice(&[parent, span[1], tag]);
            stack[depth..depth + 4].copy_from_slice(&[split, span[1], span[0], split]);
            parents[depth / 2..depth / 2 + 2].fill(node);
            depth += 4;
        }
        let (origins, order) = locators.split_at_mut(count);
        order.fill(usize::MAX);
        for (event, origin) in origins.iter_mut().enumerate() {
            *origin = usize::from(self.origin(event).unwrap());
            self.contexts(event, |proof, base, position| {
                if matches!(self.step(proof), Unfold::Source) {
                    order[base + position] = event;
                    false
                } else {
                    true
                }
            });
        }
        parents[..count].fill(0);
        for (position, &event) in order.iter().enumerate() {
            if event >= count || parents[event] != 0 {
                return Err(PathError::Structure {
                    start: position,
                    end: position + 1,
                });
            }
            parents[event] = 1;
        }
        Ok(())
    }

    // The caller visits actual subtrees of the checked root. The boundary
    // between its first two leaves is inside it; climb until its end matches.
    // Below that root every such ancestor is a left child, so ends increase.
    pub(super) fn indexed_parts(
        &self,
        span: [usize; 2],
        parts: &[usize],
    ) -> Option<(NodeKind, usize)> {
        if span[0] >= span[1] || span[1] > self.event_count() {
            return None;
        }
        if span[1] - span[0] == 1 {
            return Some((NodeKind::Message, span[1]));
        }
        let mut node = span[0];
        loop {
            let row = parts.get(3 * node..3 * node + 3)?;
            if row[1] == span[1] {
                return Some((
                    match row[2] {
                        0 => NodeKind::Sequence,
                        1 => NodeKind::Parallel,
                        scope => NodeKind::Choice((scope - 2) as u16),
                    },
                    node + 1,
                ));
            }
            if row[1] > span[1] || row[0] == usize::MAX {
                return None;
            }
            node = row[0];
        }
    }

    fn independent_conflict(
        &self,
        actors: &[usize],
        order: &[usize],
        last: &mut [usize],
    ) -> Option<(usize, usize)> {
        last.fill(usize::MAX);
        // Proof-leaf order keeps every independent child contiguous, including
        // tails split by an insertion. A shared actor across such a cut has
        // adjacent occurrences straddling it in this order.
        for &event in order.iter() {
            if actors[event] == usize::MAX {
                continue;
            }
            let sides = [actors[event] >> 8, actors[event] & 255];
            for (side, actor) in sides.into_iter().enumerate() {
                if side == 1 && sides[0] == actor {
                    continue;
                }
                let previous = last[actor];
                if previous != usize::MAX {
                    let first = previous.min(event);
                    let second = previous.max(event);
                    if self.independent_between(first, second) {
                        return Some((first, second));
                    }
                }
                last[actor] = event;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests;

impl SourcePath<'_, '_, '_> {
    pub(super) fn choice_at(&self, event: usize, scope: u16) -> Option<bool> {
        let (span, right) = self.route_at(event, scope)?;
        if self.actors(event).is_some() {
            // A live occurrence already identifies the selected arm of this
            // checked choice visit. Do not scan its inactive sibling again.
            Some(right)
        } else {
            self.selection(span)
        }
    }

    pub(super) fn selection(&self, span: [usize; 2]) -> Option<bool> {
        let (_, split) = self.source.indexed_parts(span, self.index)?;
        self.actors[span[0]..span[1]]
            .iter()
            .position(|&actor| actor != usize::MAX)
            .map(|index| span[0] + index >= split)
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

    pub(super) fn origin(&self, event: usize) -> Option<u16> {
        let count = self.source.event_count();
        if event >= count {
            return None;
        }
        Some(self.index[Layout::binary_words(count).unwrap() + event] as u16)
    }
}

impl SourcePath<'_, '_, '_> {
    /// The concrete visit containing this event, including unselected arms.
    pub(super) fn route_at(&self, event: usize, scope: u16) -> Option<([usize; 2], bool)> {
        let count = self.source.event_count();
        if event >= count || count < 2 {
            return None;
        }
        // A binary leaf's parent is one of its two adjacent split boundaries.
        // Both adjacent boundaries are ancestors, so their parent chains cover
        // every enclosing choice. Keep the outermost matching visit, as in a
        // descent from the root, including repeated scope IDs.
        let mut found = None;
        for mut node in [event.checked_sub(1), (event < count - 1).then_some(event)]
            .into_iter()
            .flatten()
        {
            loop {
                let row = &self.index[3 * node..3 * node + 3];
                if row[2] == usize::from(scope) + 2 {
                    found = Some((node, row[1]));
                }
                if row[0] == usize::MAX {
                    break;
                }
                node = row[0];
            }
        }
        let (node, end) = found?;
        let mut start = 0;
        let mut child = node;
        loop {
            let parent = self.index[3 * child];
            if parent == usize::MAX {
                break;
            }
            if child > parent {
                start = parent + 1;
                break;
            }
            child = parent;
        }
        Some(([start, end], event > node))
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
