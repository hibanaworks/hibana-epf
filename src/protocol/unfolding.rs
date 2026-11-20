//! Check finite source unfoldings without enumerating a fixed catalogue of visits.
use super::{Layout, PathError, Protocol, SourcePath};

pub(super) mod generate;

/// One postorder step of a proposed finite source unfolding.
///
/// Child indices must precede this step. The source of every child is derived
/// from the compiled protocol, starting at its root. These are audit witnesses,
/// not instructions that authorize or schedule application operations.
#[derive(Clone, Copy, Debug)]
pub enum Unfold {
    /// Borrow this compiled subtree, taking one copy of each nested roll.
    /// Its messages and constructor structure are read directly from `Protocol`.
    Source,
    /// Preserve a source sequence.
    Sequence([usize; 2]),
    /// Preserve a parallel composition.
    Parallel([usize; 2]),
    /// Preserve both arms of a choice.
    Choice([usize; 2]),
    /// Execute one copy of the source roll's body.
    Once(usize),
    /// Append a body to an earlier unfolding of the same roll.
    More([usize; 2]),
    /// Unfold the two parallel children of a roll independently.
    /// Physical participant separation must subsequently be checked.
    Independent([usize; 2]),
    /// Resume a retained roll after its source continuation.
    After {
        retained: u16,
        earlier: usize,
        next: usize,
    },
    /// Insert a resumed roll alongside one subtree of its continuation.
    Alongside {
        retained: u16,
        earlier: usize,
        next: usize,
        /// Subtree in the complete earlier expansion, including prior insertions.
        focus: [usize; 2],
    },
    /// Insert a resumed roll before one subtree of its continuation.
    Before {
        retained: u16,
        earlier: usize,
        next: usize,
        focus: [usize; 2],
    },
}

/// A syntactically invalid unfolding or insufficient temporary space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnfoldingError {
    /// The first invalid proof step, including an unreachable extra step.
    Step { index: usize },
    /// Five temporary words are needed per proof step.
    Workspace { required: usize, actual: usize },
    /// The unfolded event count cannot be represented on this machine.
    Overflow { index: usize },
}

/// A finite unfolding checked against the actual compiled source structure.
///
/// This proves syntactic source correspondence only. Choices, original actor
/// compatibility, parallel participant separation, resumption anchors, ownership
/// and operation readiness still need checking before certifying an execution.
#[derive(Clone, Copy)]
pub struct Unfolded<'p, 'w> {
    protocol: Protocol<'p>,
    steps: &'w [Unfold],
    rows: &'w [usize],
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Region {
    start: usize,
    end: usize,
    first: usize,
    last: usize,
    // A synthetic roll wraps a parallel child for Independent. This is source
    // syntax, not an indication that the running protocol entered a visit.
    rolled: bool,
}

#[derive(Clone, Copy)]
enum Head {
    Message,
    Sequence([Region; 2]),
    Parallel([Region; 2]),
    Choice(u16, [Region; 2]),
    Roll(Region),
}

enum InsertPart {
    Earlier(usize),
    Resumed(usize),
}

fn insertion_part(event: usize, start: usize, added: usize) -> InsertPart {
    if event < start {
        InsertPart::Earlier(event)
    } else if event - start < added {
        InsertPart::Resumed(event - start)
    } else {
        InsertPart::Earlier(event - added)
    }
}

impl<'p> Protocol<'p> {
    /// Words retained by a checked unfolding; independent of its visit counts.
    pub fn unfolding_workspace_len(steps: &[Unfold]) -> usize {
        5 * steps.len()
    }

    /// Check all source constructors and retain a compact read-only witness.
    ///
    /// The proof has no fixed visit/depth limit. Checked arithmetic rejects an
    /// unrepresentable expansion. Shared proof steps can describe repeated
    /// copies without copying their bodies into memory. Insertion ranges must
    /// name an actual expanded subtree, not an arbitrary interval.
    pub fn unfolding<'a: 'w, 'w>(
        &self,
        steps: &'a [Unfold],
        workspace: &'w mut [usize],
    ) -> Result<Unfolded<'p, 'w>, UnfoldingError> {
        let required = Self::unfolding_workspace_len(steps);
        if workspace.len() < required {
            return Err(UnfoldingError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        if steps.is_empty() {
            return Err(UnfoldingError::Step { index: 0 });
        }
        let rows = &mut workspace[..required];
        rows.fill(usize::MAX);
        let layout = Layout::checked(*self);
        put(
            rows,
            steps.len() - 1,
            Region {
                start: 0,
                end: layout.sources.len(),
                first: 0,
                last: layout.scopes.len(),
                rolled: false,
            },
        );
        // Every parent follows its children. Propagate the required source
        // region from the root; a shared step must have exactly one source.
        for index in (0..steps.len()).rev() {
            if rows[5 * index] == usize::MAX {
                return Err(UnfoldingError::Step { index });
            }
            let expected = get(rows, index);
            let head = layout
                .head(*self, expected)
                .ok_or(UnfoldingError::Step { index })?;
            let mut assign = |child: usize, source: Region| {
                let source = layout.canonical(*self, source);
                if child >= index {
                    return Err(UnfoldingError::Step { index });
                }
                if rows[5 * child] != usize::MAX && get(rows, child) != source {
                    return Err(UnfoldingError::Step { index });
                }
                put(rows, child, source);
                Ok(())
            };
            match (steps[index], head) {
                (Unfold::Source, _) => {}
                (Unfold::Sequence(children), Head::Sequence(sources))
                | (Unfold::Parallel(children), Head::Parallel(sources))
                | (Unfold::Choice(children), Head::Choice(_, sources)) => {
                    assign(children[0], sources[0])?;
                    assign(children[1], sources[1])?;
                }
                (Unfold::Once(body), Head::Roll(source)) => assign(body, source)?,
                (Unfold::More([earlier, next]), Head::Roll(source)) => {
                    assign(earlier, expected)?;
                    assign(next, source)?;
                }
                (Unfold::Independent(children), Head::Roll(source)) => {
                    let Some(Head::Parallel(mut sources)) = layout.head(*self, source) else {
                        return Err(UnfoldingError::Step { index });
                    };
                    for source in &mut sources {
                        source.rolled = true;
                    }
                    assign(children[0], sources[0])?;
                    assign(children[1], sources[1])?;
                }
                (
                    Unfold::After {
                        retained,
                        earlier,
                        next,
                    },
                    Head::Sequence([left, _]),
                ) => {
                    let source = layout
                        .retained(*self, left, retained)
                        .ok_or(UnfoldingError::Step { index })?;
                    let Some(Head::Roll(body)) = layout.head(*self, source) else {
                        return Err(UnfoldingError::Step { index });
                    };
                    assign(earlier, expected)?;
                    assign(next, body)?;
                }
                (
                    Unfold::Alongside {
                        retained,
                        earlier,
                        next,
                        ..
                    }
                    | Unfold::Before {
                        retained,
                        earlier,
                        next,
                        ..
                    },
                    Head::Sequence([left, _]),
                ) => {
                    let source = layout
                        .retained(*self, left, retained)
                        .ok_or(UnfoldingError::Step { index })?;
                    assign(earlier, expected)?;
                    assign(next, source)?;
                }
                _ => return Err(UnfoldingError::Step { index }),
            }
        }
        for (index, step) in steps.iter().enumerate() {
            let count = |child| rows[5 * child + 4];
            let events = match *step {
                Unfold::Source => {
                    let region = get(rows, index);
                    region.end - region.start
                }
                Unfold::Once(body) => count(body),
                Unfold::Sequence([a, b])
                | Unfold::Parallel([a, b])
                | Unfold::Choice([a, b])
                | Unfold::More([a, b])
                | Unfold::Independent([a, b])
                | Unfold::After {
                    earlier: a,
                    next: b,
                    ..
                } => count(a)
                    .checked_add(count(b))
                    .ok_or(UnfoldingError::Overflow { index })?,
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
                    if subtree_at(*self, steps, rows, earlier, focus, focus[0]).is_none() {
                        return Err(UnfoldingError::Step { index });
                    }
                    let Some(Head::Sequence([_, right])) = layout.head(*self, get(rows, index))
                    else {
                        return Err(UnfoldingError::Step { index });
                    };
                    let prior = Unfolded {
                        protocol: *self,
                        steps: &steps[..=earlier],
                        rows: &rows[..5 * (earlier + 1)],
                    };
                    if (focus[0]..focus[1]).any(|event| {
                        !prior.origin(event).is_some_and(|origin| {
                            right.start <= usize::from(origin) && usize::from(origin) < right.end
                        })
                    }) {
                        return Err(UnfoldingError::Step { index });
                    }
                    count(earlier)
                        .checked_add(count(next))
                        .ok_or(UnfoldingError::Overflow { index })?
                }
            };
            rows[5 * index + 4] = events;
        }
        Ok(Unfolded {
            protocol: *self,
            steps,
            rows,
        })
    }
}

impl Unfolded<'_, '_> {
    pub(super) fn count(&self, proof: usize) -> usize {
        self.rows[5 * proof + 4]
    }
    pub(super) fn step(&self, proof: usize) -> Unfold {
        self.steps[proof]
    }

    pub(super) fn reentered(&self, event: usize, key: u16) -> bool {
        let layout = Layout::checked(self.protocol);
        let records = self.protocol.records;
        let Some(target) = self.protocol.scope(key) else {
            return false;
        };
        let contains = |outer: u16| {
            self.protocol
                .scope(outer)
                .is_some_and(|bounds| bounds.first <= target.first && target.last <= bounds.last)
        };
        let mut resumed = false;
        self.contexts(event, |proof, _, local| {
            let region = get(self.rows, proof);
            let original = records.get(layout.scopes.start + region.first);
            match self.steps[proof] {
                Unfold::More([earlier, _]) if local >= self.count(earlier) => {
                    if !region.rolled && original.is_some_and(|row| contains(row.causal_key())) {
                        resumed = true;
                    }
                }
                Unfold::Independent([left, right]) => {
                    let (child, at) = if local < self.count(left) {
                        (left, local)
                    } else {
                        (right, local - self.count(left))
                    };
                    if original.is_some_and(|row| contains(row.causal_key()))
                        && self.copy_range(child, at).is_some_and(|copy| copy[0] != 0)
                    {
                        resumed = true;
                    }
                }
                Unfold::After {
                    retained, earlier, ..
                } if local >= self.count(earlier) && contains(retained) => resumed = true,
                Unfold::Alongside {
                    retained,
                    next,
                    focus,
                    ..
                }
                | Unfold::Before {
                    retained,
                    next,
                    focus,
                    ..
                } => {
                    let start = focus[0];
                    if start <= local && local - start < self.count(next) && contains(retained) {
                        resumed = true;
                    }
                }
                _ => (),
            }
            !resumed
        });
        resumed
    }

    // A proof step plus its base in proof-leaf order uniquely identifies an
    // invocation even when the same DAG step is reused in several visits.
    fn context_child(&self, proof: usize, event: usize) -> Option<(usize, usize, usize)> {
        match self.steps[proof] {
            Unfold::Source => None,
            Unfold::Once(body) => Some((body, 0, event)),
            Unfold::Sequence([a, b])
            | Unfold::Parallel([a, b])
            | Unfold::Choice([a, b])
            | Unfold::More([a, b])
            | Unfold::Independent([a, b])
            | Unfold::After {
                earlier: a,
                next: b,
                ..
            } => {
                if event < self.count(a) {
                    Some((a, 0, event))
                } else {
                    Some((b, self.count(a), event - self.count(a)))
                }
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
            } => match insertion_part(event, focus[0], self.count(next)) {
                InsertPart::Resumed(local) => Some((next, 0, local)),
                InsertPart::Earlier(local) => Some((earlier, self.count(next), local)),
            },
        }
    }

    pub(super) fn contexts(
        &self,
        mut event: usize,
        mut inspect: impl FnMut(usize, usize, usize) -> bool,
    ) {
        if event >= self.event_count() {
            return;
        }
        let mut at = self.steps.len() - 1;
        let mut base = 0;
        loop {
            if !inspect(at, base, event) {
                return;
            }
            let Some((child, offset, local)) = self.context_child(at, event) else {
                return;
            };
            at = child;
            base += offset;
            event = local;
        }
    }

    // Walk the two paths together once. Re-querying target membership from
    // the root at every prior ancestor would make this quadratic in depth.
    fn common_context(&self, mut first: usize, mut second: usize) -> Option<(usize, usize)> {
        if first >= self.event_count() || second >= self.event_count() {
            return None;
        }
        let mut at = self.steps.len() - 1;
        let mut base = 0;
        loop {
            match (
                self.context_child(at, first),
                self.context_child(at, second),
            ) {
                (Some((a, offset_a, local_a)), Some((b, offset_b, local_b)))
                    if a == b && offset_a == offset_b =>
                {
                    at = a;
                    base += offset_a;
                    first = local_a;
                    second = local_b;
                }
                _ => return Some((at, base)),
            }
        }
    }

    pub(super) fn local_position(&self, event: usize, proof: usize, base: usize) -> Option<usize> {
        let mut position = None;
        self.contexts(event, |at, start, here| {
            if at == proof && start == base {
                position = Some(here);
                false
            } else {
                true
            }
        });
        position
    }

    pub(super) fn global_position(&self, proof: usize, base: usize, local: usize) -> Option<usize> {
        (0..self.event_count())
            .find(|&event| self.local_position(event, proof, base) == Some(local))
    }

    pub(super) fn copy_range(&self, mut at: usize, event: usize) -> Option<[usize; 2]> {
        loop {
            match self.steps[at] {
                Unfold::Source => {
                    return matches!(
                        Layout::checked(self.protocol).head(self.protocol, get(self.rows, at)),
                        Some(Head::Roll(_))
                    )
                    .then_some([0, self.count(at)]);
                }
                Unfold::Once(_) | Unfold::Independent(_) => return Some([0, self.count(at)]),
                Unfold::More([earlier, next]) => {
                    if event < self.count(earlier) {
                        at = earlier;
                    } else {
                        return Some([self.count(earlier), self.count(earlier) + self.count(next)]);
                    }
                }
                _ => return None,
            }
        }
    }

    // A Before graft places a new visit before one subtree of an existing
    // continuation. Its retained anchor is still an earlier visit of this
    // same invocation, even though the common proof node is not Sequence.
    // Return only membership in that anchor; completion belongs to the
    // selected physical actor and is checked by the common visit predicate.
    pub(super) fn earlier_graft(
        &self,
        prior: usize,
        target: usize,
    ) -> Option<impl Fn(usize) -> bool + '_> {
        let (proof, base) = self.common_context(prior, target)?;
        let Unfold::Before {
            retained,
            earlier,
            next,
            focus,
        } = self.steps[proof]
        else {
            return None;
        };
        let added = self.count(next);
        if !matches!(
            insertion_part(self.local_position(prior, proof, base)?, focus[0], added),
            InsertPart::Resumed(_)
        ) {
            return None;
        }
        let InsertPart::Earlier(target) =
            insertion_part(self.local_position(target, proof, base)?, focus[0], added)
        else {
            return None;
        };
        if target < focus[0] {
            return None;
        }
        Some(move |event| {
            self.local_position(event, proof, base)
                .is_some_and(|local| match insertion_part(local, focus[0], added) {
                    InsertPart::Earlier(local) => self.anchor_contains(earlier, retained, local),
                    InsertPart::Resumed(_) => false,
                })
        })
    }

    // Index only More invocations whose nonempty earlier copy precedes the
    // event in proof-leaf order. Unary and empty children add no index rows;
    // the actual expansion bounds both the rows and the pending DFS stack.
    // This immutable data never records execution progress or grants credit.
    pub(super) fn index_prior_rolls(
        &self,
        order: &[usize],
        index: &mut [usize],
        parents: &mut [usize],
        stack: &mut [usize],
    ) -> Result<(), PathError> {
        let count = self.event_count();
        let (heads, rest) = index.split_at_mut(count);
        let (ranks, rows) = rest.split_at_mut(count);
        let rows = rows.as_chunks_mut::<3>().0;
        heads.fill(usize::MAX);
        ranks.fill(usize::MAX);
        let mut used = 0;
        let mut pending = 0;
        let (mut proof, mut base, mut enclosing) = (self.steps.len() - 1, 0, usize::MAX);
        loop {
            match self.steps[proof] {
                Unfold::Source => {
                    for (rank, &event) in
                        order.iter().enumerate().skip(base).take(self.count(proof))
                    {
                        heads[event] = enclosing;
                        ranks[event] = rank;
                    }
                }
                Unfold::Once(body) => {
                    proof = body;
                    continue;
                }
                step => {
                    let [a, b] = match step {
                        Unfold::Sequence(children)
                        | Unfold::Parallel(children)
                        | Unfold::Choice(children)
                        | Unfold::More(children)
                        | Unfold::Independent(children) => children,
                        Unfold::After { earlier, next, .. } => [earlier, next],
                        Unfold::Alongside { earlier, next, .. }
                        | Unfold::Before { earlier, next, .. } => [next, earlier],
                        Unfold::Source | Unfold::Once(_) => unreachable!(),
                    };
                    let left = self.count(a);
                    if left == 0 {
                        proof = b;
                        continue;
                    }
                    if self.count(b) == 0 {
                        proof = a;
                        continue;
                    }
                    let next_enclosing = if matches!(step, Unfold::More(_)) {
                        rows[used] = [proof, base, enclosing];
                        used += 1;
                        used - 1
                    } else {
                        enclosing
                    };
                    stack[2 * pending..2 * pending + 2].copy_from_slice(&[b, base + left]);
                    parents[pending] = next_enclosing;
                    pending += 1;
                    proof = a;
                    continue;
                }
            }
            if pending == 0 {
                break;
            }
            pending -= 1;
            proof = stack[2 * pending];
            base = stack[2 * pending + 1];
            enclosing = parents[pending];
        }

        // Validate each indexed chain against the established context walk,
        // once at construction. Insertion order differs from source order,
        // so check the inverse permutation too before publishing SourcePath.
        for event in 0..count {
            let mut next = heads[event];
            let mut depth = 0;
            while next != usize::MAX {
                stack[depth] = next;
                depth += 1;
                next = rows[next][2];
            }
            let mut valid = true;
            self.contexts(event, |proof, base, local| {
                if let Unfold::More([earlier, _]) = self.steps[proof]
                    && self.count(earlier) != 0
                    && local >= self.count(earlier)
                {
                    if depth == 0 {
                        valid = false;
                        return false;
                    }
                    depth -= 1;
                    valid &= rows[stack[depth]][..2] == [proof, base];
                }
                if matches!(self.steps[proof], Unfold::Source) {
                    valid &= ranks[event] == base + local;
                }
                valid
            });
            if !valid || depth != 0 || ranks[event] == usize::MAX {
                return Err(PathError::Structure {
                    start: event,
                    end: event + 1,
                });
            }
        }
        Ok(())
    }

    pub(super) fn has_repeated_visits(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, Unfold::More(_)))
    }

    pub(super) fn resumption_target(&self, event: usize) -> bool {
        let mut target = false;
        self.contexts(event, |proof, _, local| {
            if let Unfold::Alongside { next, focus, .. } | Unfold::Before { next, focus, .. } =
                self.steps[proof]
            {
                let added = self.count(next);
                target = focus[0] + added <= local && local < focus[1] + added;
            }
            !target
        });
        target
    }

    pub(super) fn same_resumption(
        &self,
        mut prior: usize,
        mut target: usize,
        mut entered: usize,
    ) -> bool {
        if [prior, target, entered]
            .iter()
            .any(|&event| event >= self.event_count())
        {
            return false;
        }
        let mut at = self.steps.len() - 1;
        loop {
            match self.steps[at] {
                Unfold::Source => return false,
                Unfold::Once(body) => at = body,
                Unfold::Sequence([a, b])
                | Unfold::Parallel([a, b])
                | Unfold::Choice([a, b])
                | Unfold::More([a, b])
                | Unfold::Independent([a, b])
                | Unfold::After {
                    earlier: a,
                    next: b,
                    ..
                } => {
                    if [prior, target, entered]
                        .iter()
                        .all(|&event| event < self.count(a))
                    {
                        at = a;
                    } else if [prior, target, entered]
                        .iter()
                        .all(|&event| event >= self.count(a))
                    {
                        prior -= self.count(a);
                        target -= self.count(a);
                        entered -= self.count(a);
                        at = b;
                    } else {
                        return false;
                    }
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
                    let start = focus[0];
                    let stop = start + self.count(next);
                    if start <= prior
                        && prior < stop
                        && start <= entered
                        && entered < stop
                        && stop <= target
                        && target < focus[1] + self.count(next)
                        && self.copy_range(next, prior - start).is_some_and(|copy| {
                            self.copy_range(next, entered - start) == Some(copy)
                        })
                    {
                        return true;
                    }
                    let locate = |event| insertion_part(event, start, self.count(next));
                    let (child, positions) = match (locate(prior), locate(target), locate(entered))
                    {
                        (
                            InsertPart::Earlier(p),
                            InsertPart::Earlier(t),
                            InsertPart::Earlier(e),
                        ) => (earlier, [p, t, e]),
                        (
                            InsertPart::Resumed(p),
                            InsertPart::Resumed(t),
                            InsertPart::Resumed(e),
                        ) => (next, [p, t, e]),
                        _ => return false,
                    };
                    at = child;
                    [prior, target, entered] = positions;
                }
            }
        }
    }

    pub(super) fn resumption_anchor_contains(&self, proof: usize, event: usize) -> bool {
        match self.steps[proof] {
            Unfold::After {
                retained, earlier, ..
            } => event < self.count(earlier) && self.anchor_contains(earlier, retained, event),
            Unfold::Alongside {
                retained,
                earlier,
                next,
                focus,
            }
            | Unfold::Before {
                retained,
                earlier,
                next,
                focus,
            } => match insertion_part(event, focus[0], self.count(next)) {
                InsertPart::Earlier(local) => self.anchor_contains(earlier, retained, local),
                InsertPart::Resumed(_) => false,
            },
            _ => false,
        }
    }

    fn anchor_contains(&self, mut at: usize, retained: u16, mut event: usize) -> bool {
        let layout = Layout::checked(self.protocol);
        let Some(scope) = layout.retained(self.protocol, get(self.rows, at), retained) else {
            return false;
        };
        let target = layout.canonical(self.protocol, scope);
        loop {
            if event >= self.count(at) {
                return false;
            }
            if get(self.rows, at) == target {
                return match self.steps[at] {
                    Unfold::Source | Unfold::Once(_) => true,
                    Unfold::More([earlier, _]) => self.count(earlier) <= event,
                    _ => false,
                };
            }
            match self.steps[at] {
                Unfold::Sequence([a, b])
                | Unfold::Parallel([a, b])
                | Unfold::Choice([a, b])
                | Unfold::Independent([a, b]) => {
                    if layout
                        .retained(self.protocol, get(self.rows, a), retained)
                        .is_some()
                    {
                        at = a;
                    } else if layout
                        .retained(self.protocol, get(self.rows, b), retained)
                        .is_some()
                    {
                        if event < self.count(a) {
                            return false;
                        }
                        event -= self.count(a);
                        at = b;
                    } else {
                        return false;
                    }
                }
                Unfold::Source => {
                    let region = get(self.rows, at);
                    return scope.start - region.start <= event && event < scope.end - region.start;
                }
                Unfold::Once(body) => at = body,
                Unfold::More([earlier, next]) => {
                    if event < self.count(earlier) {
                        return false;
                    }
                    event -= self.count(earlier);
                    at = next;
                }
                Unfold::After {
                    retained: resumed,
                    earlier,
                    next,
                } => {
                    if resumed == retained {
                        return self.count(earlier) <= event;
                    }
                    if layout
                        .retained(self.protocol, get(self.rows, next), retained)
                        .is_some()
                    {
                        if event < self.count(earlier) {
                            return false;
                        }
                        event -= self.count(earlier);
                        at = next;
                    } else {
                        at = earlier;
                    }
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
                } => match insertion_part(event, focus[0], self.count(next)) {
                    InsertPart::Resumed(local) => {
                        if layout
                            .retained(self.protocol, get(self.rows, next), retained)
                            .is_none()
                        {
                            return false;
                        }
                        event = local;
                        at = next;
                    }
                    InsertPart::Earlier(local) => {
                        if layout
                            .retained(self.protocol, get(self.rows, next), retained)
                            .is_some()
                        {
                            return false;
                        }
                        event = local;
                        at = earlier;
                    }
                },
            }
        }
    }

    pub(super) fn kind(&self, span: [usize; 2]) -> Option<NodeKind> {
        let root = self.steps.len() - 1;
        subtree_at(self.protocol, self.steps, self.rows, root, span, span[0]).map(|(kind, _)| kind)
    }

    pub(super) fn parts(&self, span: [usize; 2]) -> Option<(NodeKind, usize)> {
        let root = self.steps.len() - 1;
        let kind = self.kind(span)?;
        if matches!(kind, NodeKind::Message) {
            return Some((kind, span[1]));
        }
        // Each binary subtree has two contiguous, nonempty children. Classify
        // an event through the derivation instead of testing every possible
        // split by reconstructing two subtrees from the root.
        let mut first = span[0] + 1;
        let mut last = span[1];
        while first < last {
            let middle = first + (last - first) / 2;
            let (_, left) = subtree_at(self.protocol, self.steps, self.rows, root, span, middle)?;
            if left {
                first = middle + 1;
            } else {
                last = middle;
            }
        }
        (first < span[1]).then_some((kind, first))
    }

    pub(super) fn independent_between(&self, mut first: usize, mut second: usize) -> bool {
        if first >= second || second >= self.event_count() {
            return false;
        }
        let mut at = self.steps.len() - 1;
        loop {
            let count = |node| self.rows[5 * node + 4];
            match self.steps[at] {
                Unfold::Source => return false,
                Unfold::Once(body) => at = body,
                Unfold::Sequence([a, b])
                | Unfold::Parallel([a, b])
                | Unfold::Choice([a, b])
                | Unfold::More([a, b])
                | Unfold::Independent([a, b])
                | Unfold::After {
                    earlier: a,
                    next: b,
                    ..
                } => {
                    if second < count(a) {
                        at = a;
                    } else if first >= count(a) {
                        first -= count(a);
                        second -= count(a);
                        at = b;
                    } else {
                        return matches!(self.steps[at], Unfold::Independent(_));
                    }
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
                    match (
                        insertion_part(first, focus[0], count(next)),
                        insertion_part(second, focus[0], count(next)),
                    ) {
                        (InsertPart::Earlier(a), InsertPart::Earlier(b)) => {
                            first = a;
                            second = b;
                            at = earlier;
                        }
                        (InsertPart::Resumed(a), InsertPart::Resumed(b)) => {
                            first = a;
                            second = b;
                            at = next;
                        }
                        _ => return false,
                    }
                }
            }
        }
    }

    /// Number of distinct positions in this finite expansion.
    pub fn event_count(&self) -> usize {
        self.rows[5 * (self.steps.len() - 1) + 4]
    }

    /// Original 16-bit source event for one expanded occurrence.
    pub fn origin(&self, mut event: usize) -> Option<u16> {
        if event >= self.event_count() {
            return None;
        }
        let mut at = self.steps.len() - 1;
        loop {
            let count = |node| self.rows[5 * node + 4];
            match self.steps[at] {
                Unfold::Source => return Some((get(self.rows, at).start + event) as u16),
                Unfold::Once(body) => at = body,
                Unfold::Sequence([a, b])
                | Unfold::Parallel([a, b])
                | Unfold::Choice([a, b])
                | Unfold::More([a, b])
                | Unfold::Independent([a, b])
                | Unfold::After {
                    earlier: a,
                    next: b,
                    ..
                } => {
                    if event < count(a) {
                        at = a;
                    } else {
                        event -= count(a);
                        at = b;
                    }
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
                } => match insertion_part(event, focus[0], count(next)) {
                    InsertPart::Earlier(local) => {
                        event = local;
                        at = earlier;
                    }
                    InsertPart::Resumed(local) => {
                        event = local;
                        at = next;
                    }
                },
            }
        }
    }

    /// Source sequence order of two expanded events. Parallel siblings and
    /// different choice arms have no sequence edge. This is not actor readiness.
    pub fn before(&self, mut first: usize, mut second: usize) -> bool {
        if first >= self.event_count() || second >= self.event_count() || first >= second {
            return false;
        }
        let mut at = self.steps.len() - 1;
        loop {
            let count = |node| self.rows[5 * node + 4];
            match self.steps[at] {
                Unfold::Source => {
                    return Layout::checked(self.protocol).source_before(
                        self.protocol,
                        get(self.rows, at),
                        first,
                        second,
                    );
                }
                Unfold::Once(body) => at = body,
                Unfold::Sequence([a, b])
                | Unfold::More([a, b])
                | Unfold::After {
                    earlier: a,
                    next: b,
                    ..
                }
                | Unfold::Parallel([a, b])
                | Unfold::Choice([a, b])
                | Unfold::Independent([a, b]) => {
                    if second < count(a) {
                        at = a;
                    } else if first >= count(a) {
                        first -= count(a);
                        second -= count(a);
                        at = b;
                    } else {
                        return matches!(
                            self.steps[at],
                            Unfold::Sequence(_) | Unfold::More(_) | Unfold::After { .. }
                        );
                    }
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
                    let preceding = matches!(self.steps[at], Unfold::Before { .. });
                    match (
                        insertion_part(first, focus[0], count(next)),
                        insertion_part(second, focus[0], count(next)),
                    ) {
                        (InsertPart::Earlier(a), InsertPart::Earlier(b)) => {
                            first = a;
                            second = b;
                            at = earlier;
                        }
                        (InsertPart::Resumed(a), InsertPart::Resumed(b)) => {
                            first = a;
                            second = b;
                            at = next;
                        }
                        (InsertPart::Resumed(_), InsertPart::Earlier(b)) => {
                            if b < focus[1] {
                                return preceding;
                            }
                            first = focus[0];
                            second = b;
                            at = earlier;
                        }
                        (InsertPart::Earlier(a), InsertPart::Resumed(_)) => {
                            first = a;
                            second = focus[0];
                            at = earlier;
                        }
                    }
                }
            }
        }
    }

    /// The unchanged compiled snapshot this witness was checked against.
    pub fn protocol(&self) -> Protocol<'_> {
        self.protocol
    }
}

fn put(rows: &mut [usize], index: usize, region: Region) {
    rows[5 * index..5 * index + 4].copy_from_slice(&[
        region.start,
        region.end,
        region.first | (usize::from(region.rolled) << 16),
        region.last,
    ]);
}
fn get(rows: &[usize], index: usize) -> Region {
    Region {
        start: rows[5 * index],
        end: rows[5 * index + 1],
        first: rows[5 * index + 2] & 0xffff,
        last: rows[5 * index + 3],
        rolled: rows[5 * index + 2] >> 16 != 0,
    }
}

impl SourcePath<'_, '_, '_> {
    // Locate nonempty earlier copies in the same source-sequence invocation.
    // The chain contains only rolls whose next child contains prior. A roll
    // also containing target is above the divergence, so cannot provide credit.
    pub(super) fn earlier_rolls(
        &self,
        prior: usize,
        target: usize,
        mut complete: impl FnMut(usize, usize, usize) -> bool,
    ) -> bool {
        let source = self.unfolding();
        let count = source.event_count();
        let Some((common, _)) = source.common_context(prior, target) else {
            return false;
        };
        if !matches!(source.steps[common], Unfold::Sequence(_)) {
            return false;
        }
        let target_origin = usize::from(self.origin(target).unwrap());
        let region = get(source.rows, common);
        let layout = Layout::checked(source.protocol);
        let index = &self.index[Layout::source_index_words(count).unwrap()..];
        let (heads, rest) = index.split_at(count);
        let (ranks, rows) = rest.split_at(count);
        let rows = rows.as_chunks::<3>().0;
        let mut next = heads[prior];
        while next != usize::MAX {
            let [proof, base, parent] = rows[next];
            next = parent;
            if base <= ranks[target] && ranks[target] - base < source.count(proof) {
                continue;
            }
            let body = get(source.rows, proof);
            if region.start <= body.start
                && body.end <= region.end
                && body.end <= target_origin
                && target_origin < region.end
                && layout.source_before(
                    source.protocol,
                    region,
                    body.end - 1 - region.start,
                    target_origin - region.start,
                )
            {
                let Unfold::More([earlier, _]) = source.steps[proof] else {
                    unreachable!();
                };
                if complete(proof, base, earlier) {
                    return true;
                }
            }
        }
        false
    }
}

impl Layout {
    fn canonical(&self, protocol: Protocol<'_>, region: Region) -> Region {
        let records = protocol.records;
        let mut first = region.last;
        let mut last = 0;
        let candidates =
            &records[self.scopes.start + region.first..self.scopes.start + region.last];
        let skip = candidates.partition_point(|row| (row.arg0() as usize) < region.start);
        for marker in region.first + skip..region.last {
            let index = self.scopes.start + marker;
            let row = records[index];
            if row.arg1() & 3 != 0 {
                continue;
            }
            let Some(scope) = protocol.scope(row.causal_key()) else {
                continue;
            };
            if scope.first != index
                || scope.last >= self.scopes.start + region.last
                || (scope.start as usize) < region.start
                || scope.end as usize > region.end
            {
                continue;
            }
            first = first.min(marker);
            last = last.max(scope.last - self.scopes.start + 1);
        }
        if last == 0 {
            first = 0;
        }
        Region {
            first,
            last,
            ..region
        }
    }

    fn head(&self, protocol: Protocol<'_>, region: Region) -> Option<Head> {
        let records = protocol.records;
        if region.start >= region.end {
            return None;
        }
        if region.rolled {
            return Some(Head::Roll(Region {
                rolled: false,
                ..region
            }));
        }
        let candidates =
            &records[self.scopes.start + region.first..self.scopes.start + region.last];
        let skip = candidates.partition_point(|row| (row.arg0() as usize) < region.start);
        for marker in region.first + skip..region.last {
            let index = self.scopes.start + marker;
            let row = records[index];
            if row.arg0() as usize > region.start {
                break;
            }
            if row.arg1() & 3 != 0 || row.arg0() as usize != region.start {
                continue;
            }
            let scope = protocol.scope(row.causal_key())?;
            if scope.first != index
                || scope.last >= self.scopes.start + region.last
                || scope.end as usize > region.end
            {
                continue;
            }
            if (scope.end as usize) < region.end {
                return Some(Head::Sequence([
                    Region {
                        end: scope.end as usize,
                        ..region
                    },
                    Region {
                        start: scope.end as usize,
                        ..region
                    },
                ]));
            }
            let inside = Region {
                first: marker + 1,
                last: scope.last - self.scopes.start,
                ..region
            };
            return match row.causal_key() >> 13 {
                0 | 2 => {
                    let split = scope.split? as usize;
                    let children = [
                        Region {
                            end: split,
                            ..inside
                        },
                        Region {
                            start: split,
                            ..inside
                        },
                    ];
                    Some(if row.causal_key() >> 13 == 0 {
                        Head::Choice(row.causal_key(), children)
                    } else {
                        Head::Parallel(children)
                    })
                }
                1 => Some(Head::Roll(inside)),
                _ => None,
            };
        }
        Some(if region.end - region.start == 1 {
            Head::Message
        } else {
            Head::Sequence([
                Region {
                    end: region.start + 1,
                    ..region
                },
                Region {
                    start: region.start + 1,
                    ..region
                },
            ])
        })
    }

    fn source_at(
        &self,
        protocol: Protocol<'_>,
        mut region: Region,
        mut span: [usize; 2],
        mut event: usize,
    ) -> Option<(NodeKind, bool)> {
        loop {
            if span[0] >= span[1] || span[1] > region.end - region.start {
                return None;
            }
            let head = self.head(protocol, region)?;
            match head {
                Head::Roll(body) => region = body,
                Head::Message => return (span == [0, 1]).then_some((NodeKind::Message, false)),
                Head::Sequence(children) | Head::Parallel(children) | Head::Choice(_, children) => {
                    if span == [0, region.end - region.start] {
                        let kind = match head {
                            Head::Sequence(_) => NodeKind::Sequence,
                            Head::Parallel(_) => NodeKind::Parallel,
                            Head::Choice(key, _) => NodeKind::Choice(key),
                            Head::Message | Head::Roll(_) => unreachable!(),
                        };
                        return Some((kind, event < children[0].end - children[0].start));
                    }
                    let split = children[0].end - children[0].start;
                    if span[1] <= split {
                        region = children[0];
                    } else if span[0] >= split {
                        span[0] -= split;
                        span[1] -= split;
                        event -= split;
                        region = children[1];
                    } else {
                        return None;
                    }
                }
            }
        }
    }

    fn source_before(
        &self,
        protocol: Protocol<'_>,
        mut region: Region,
        mut first: usize,
        mut second: usize,
    ) -> bool {
        loop {
            let Some(head) = self.head(protocol, region) else {
                return false;
            };
            match head {
                Head::Roll(body) => region = body,
                Head::Message => return false,
                Head::Sequence(children) | Head::Parallel(children) | Head::Choice(_, children) => {
                    let split = children[0].end - children[0].start;
                    if second < split {
                        region = children[0];
                    } else if first >= split {
                        first -= split;
                        second -= split;
                        region = children[1];
                    } else {
                        return matches!(head, Head::Sequence(_));
                    }
                }
            }
        }
    }

    fn retained(&self, protocol: Protocol<'_>, parent: Region, key: u16) -> Option<Region> {
        if key >> 13 != 1 {
            return None;
        }
        let scope = protocol.scope(key)?;
        let first = scope.first - self.scopes.start;
        let last = scope.last - self.scopes.start + 1;
        (parent.start <= scope.start as usize
            && scope.end as usize <= parent.end
            && parent.first <= first
            && last <= parent.last)
            .then_some(Region {
                start: scope.start as usize,
                end: scope.end as usize,
                first,
                last,
                rolled: false,
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NodeKind {
    Message,
    Sequence,
    Parallel,
    Choice(u16),
}

#[cfg(test)]
mod tests;

fn subtree_at(
    protocol: Protocol<'_>,
    steps: &[Unfold],
    rows: &[usize],
    mut at: usize,
    mut span: [usize; 2],
    mut event: usize,
) -> Option<(NodeKind, bool)> {
    if !(span[0] <= event && event < span[1]) {
        return None;
    }
    loop {
        let count = |node| rows[5 * node + 4];
        if span[0] >= span[1] || span[1] > count(at) {
            return None;
        }
        if span == [0, count(at)]
            && !matches!(steps[at], Unfold::Alongside { .. } | Unfold::Before { .. })
        {
            return Some(match steps[at] {
                Unfold::Source => {
                    return Layout::checked(protocol).source_at(
                        protocol,
                        get(rows, at),
                        span,
                        event,
                    );
                }
                Unfold::Once(body) => {
                    at = body;
                    continue;
                }
                Unfold::Sequence([a, _])
                | Unfold::More([a, _])
                | Unfold::After { earlier: a, .. } => (NodeKind::Sequence, event < count(a)),
                Unfold::Parallel([a, _]) | Unfold::Independent([a, _]) => {
                    (NodeKind::Parallel, event < count(a))
                }
                Unfold::Choice([a, _]) => (
                    NodeKind::Choice(
                        protocol.records
                            [Layout::checked(protocol).scopes.start + get(rows, at).first]
                            .causal_key(),
                    ),
                    event < count(a),
                ),
                Unfold::Alongside { .. } | Unfold::Before { .. } => {
                    unreachable!("insertions use the graft traversal below");
                }
            });
        }
        match steps[at] {
            Unfold::Source => {
                return Layout::checked(protocol).source_at(protocol, get(rows, at), span, event);
            }
            Unfold::Once(body) => at = body,
            Unfold::Sequence([a, b])
            | Unfold::Parallel([a, b])
            | Unfold::Choice([a, b])
            | Unfold::More([a, b])
            | Unfold::Independent([a, b])
            | Unfold::After {
                earlier: a,
                next: b,
                ..
            } => {
                if span[1] <= count(a) {
                    at = a;
                } else if span[0] >= count(a) {
                    span[0] -= count(a);
                    span[1] -= count(a);
                    event -= count(a);
                    at = b;
                } else {
                    return None;
                }
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
                let added = count(next);
                if span == [focus[0], focus[1] + added] {
                    return Some((
                        if matches!(steps[at], Unfold::Before { .. }) {
                            NodeKind::Sequence
                        } else {
                            NodeKind::Parallel
                        },
                        event < focus[0] + added,
                    ));
                }
                if focus[0] <= span[0] && span[1] <= focus[0] + added {
                    span[0] -= focus[0];
                    span[1] -= focus[0];
                    event -= focus[0];
                    at = next;
                } else {
                    if span[1] <= focus[0] {
                    } else if span[0] >= focus[0] + added {
                        span[0] -= added;
                        span[1] -= added;
                        event -= added;
                    } else if span[0] <= focus[0] && span[1] >= focus[1] + added {
                        span[1] -= added;
                        if event >= focus[0] {
                            event = focus[0] + event.saturating_sub(focus[0] + added);
                        }
                    } else {
                        return None;
                    }
                    at = earlier;
                }
            }
        }
    }
}
