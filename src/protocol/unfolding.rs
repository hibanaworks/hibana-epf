//! Check finite source unfoldings without enumerating a fixed catalogue of visits.
use super::{Layout, Protocol};

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
        tail: usize,
        focus: [usize; 2],
    },
    /// Insert a resumed roll before one subtree of its continuation.
    Before {
        retained: u16,
        earlier: usize,
        next: usize,
        tail: usize,
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
    Continuation(usize),
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
                        tail,
                        ..
                    }
                    | Unfold::Before {
                        retained,
                        earlier,
                        next,
                        tail,
                        ..
                    },
                    Head::Sequence([left, right]),
                ) => {
                    let source = layout
                        .retained(*self, left, retained)
                        .ok_or(UnfoldingError::Step { index })?;
                    assign(earlier, left)?;
                    assign(next, source)?;
                    assign(tail, right)?;
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
                    tail,
                    focus,
                    ..
                }
                | Unfold::Before {
                    earlier,
                    next,
                    tail,
                    focus,
                    ..
                } => {
                    if subtree_at(*self, steps, rows, tail, focus, focus[0]).is_none() {
                        return Err(UnfoldingError::Step { index });
                    }
                    count(earlier)
                        .checked_add(count(next))
                        .and_then(|n| n.checked_add(count(tail)))
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
                    earlier,
                    next,
                    focus,
                    ..
                }
                | Unfold::Before {
                    retained,
                    earlier,
                    next,
                    focus,
                    ..
                } => {
                    let start = self.count(earlier) + focus[0];
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
            match self.steps[at] {
                Unfold::Source => return,
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
                    if event < self.count(a) {
                        at = a;
                    } else {
                        event -= self.count(a);
                        base += self.count(a);
                        at = b;
                    }
                }
                Unfold::Alongside {
                    earlier,
                    next,
                    tail,
                    focus,
                    ..
                }
                | Unfold::Before {
                    earlier,
                    next,
                    tail,
                    focus,
                    ..
                } => {
                    if event < self.count(earlier) {
                        at = earlier;
                        continue;
                    }
                    event -= self.count(earlier);
                    base += self.count(earlier);
                    if focus[0] <= event && event - focus[0] < self.count(next) {
                        event -= focus[0];
                        at = next;
                    } else {
                        if event >= focus[0] {
                            event -= self.count(next);
                        }
                        base += self.count(next);
                        at = tail;
                    }
                }
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

    pub(super) fn has_insertions(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, Unfold::Alongside { .. } | Unfold::Before { .. }))
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
                    tail,
                    focus,
                    ..
                }
                | Unfold::Before {
                    earlier,
                    next,
                    tail,
                    focus,
                    ..
                } => {
                    let start = self.count(earlier) + focus[0];
                    let stop = start + self.count(next);
                    if start <= prior
                        && prior < stop
                        && start <= entered
                        && entered < stop
                        && stop <= target
                        && target < self.count(earlier) + focus[1] + self.count(next)
                        && self.copy_range(next, prior - start).is_some_and(|copy| {
                            self.copy_range(next, entered - start) == Some(copy)
                        })
                    {
                        return true;
                    }
                    let locate = |event: usize| {
                        if event < self.count(earlier) {
                            InsertPart::Earlier(event)
                        } else if start <= event && event < stop {
                            InsertPart::Resumed(event - start)
                        } else {
                            let local = event - self.count(earlier);
                            InsertPart::Continuation(if local >= focus[0] {
                                local - self.count(next)
                            } else {
                                local
                            })
                        }
                    };
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
                        (
                            InsertPart::Continuation(p),
                            InsertPart::Continuation(t),
                            InsertPart::Continuation(e),
                        ) => (tail, [p, t, e]),
                        _ => return false,
                    };
                    at = child;
                    [prior, target, entered] = positions;
                }
            }
        }
    }

    pub(super) fn resumption_anchor(&self, proof: usize) -> Option<[usize; 2]> {
        match self.steps[proof] {
            Unfold::After {
                retained, earlier, ..
            } => match self.steps[earlier] {
                Unfold::Sequence([focused, _]) => self.anchor(focused, retained),
                Unfold::Source => {
                    let layout = Layout::checked(self.protocol);
                    let region = get(self.rows, earlier);
                    let Head::Sequence([left, _]) = layout.head(self.protocol, region)? else {
                        return None;
                    };
                    let scope = layout.retained(self.protocol, left, retained)?;
                    Some([scope.start - region.start, scope.end - region.start])
                }
                _ => None,
            },
            Unfold::Alongside {
                retained, earlier, ..
            }
            | Unfold::Before {
                retained, earlier, ..
            } => self.anchor(earlier, retained),
            _ => None,
        }
    }

    fn anchor(&self, mut at: usize, retained: u16) -> Option<[usize; 2]> {
        let layout = Layout::checked(self.protocol);
        let target = layout.canonical(
            self.protocol,
            layout.retained(self.protocol, get(self.rows, at), retained)?,
        );
        let mut base = 0;
        loop {
            if get(self.rows, at) == target {
                return match self.steps[at] {
                    Unfold::Source | Unfold::Once(_) => Some([base, base + self.count(at)]),
                    Unfold::More([earlier, next]) => Some([
                        base + self.count(earlier),
                        base + self.count(earlier) + self.count(next),
                    ]),
                    _ => None,
                };
            }
            match self.steps[at] {
                Unfold::Sequence([a, b]) | Unfold::Parallel([a, b]) | Unfold::Choice([a, b]) => {
                    if layout
                        .retained(self.protocol, get(self.rows, a), retained)
                        .is_some()
                    {
                        at = a;
                    } else if layout
                        .retained(self.protocol, get(self.rows, b), retained)
                        .is_some()
                    {
                        base += self.count(a);
                        at = b;
                    } else {
                        return None;
                    }
                }
                Unfold::Source => {
                    let region = get(self.rows, at);
                    let scope = layout.retained(self.protocol, region, retained)?;
                    return Some([
                        base + scope.start - region.start,
                        base + scope.end - region.start,
                    ]);
                }
                Unfold::Once(body) => at = body,
                Unfold::More([earlier, next]) => {
                    base += self.count(earlier);
                    at = next;
                }
                _ => return None,
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
                    tail,
                    focus,
                    ..
                }
                | Unfold::Before {
                    earlier,
                    next,
                    tail,
                    focus,
                    ..
                } => {
                    if second < count(earlier) {
                        at = earlier;
                        continue;
                    }
                    if first < count(earlier) {
                        return false;
                    }
                    first -= count(earlier);
                    second -= count(earlier);
                    let inserted =
                        |event: usize| focus[0] <= event && event - focus[0] < count(next);
                    match (inserted(first), inserted(second)) {
                        (true, true) => {
                            first -= focus[0];
                            second -= focus[0];
                            at = next;
                        }
                        (false, false) => {
                            if first >= focus[0] {
                                first -= count(next);
                            }
                            if second >= focus[0] {
                                second -= count(next);
                            }
                            at = tail;
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
                    tail,
                    focus,
                    ..
                }
                | Unfold::Before {
                    earlier,
                    next,
                    tail,
                    focus,
                    ..
                } => {
                    if event < count(earlier) {
                        at = earlier;
                        continue;
                    }
                    event -= count(earlier);
                    if focus[0] <= event && event - focus[0] < count(next) {
                        event -= focus[0];
                        at = next;
                    } else {
                        if event >= focus[0] {
                            event -= count(next);
                        }
                        at = tail;
                    }
                }
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
                    tail,
                    focus,
                    ..
                }
                | Unfold::Before {
                    earlier,
                    next,
                    tail,
                    focus,
                    ..
                } => {
                    let preceding = matches!(self.steps[at], Unfold::Before { .. });
                    if second < count(earlier) {
                        at = earlier;
                        continue;
                    }
                    if first < count(earlier) {
                        return true;
                    }
                    first -= count(earlier);
                    second -= count(earlier);
                    let inserted =
                        |event: usize| focus[0] <= event && event - focus[0] < count(next);
                    match (inserted(first), inserted(second)) {
                        (true, true) => {
                            first -= focus[0];
                            second -= focus[0];
                            at = next;
                        }
                        (false, false) => {
                            if first >= focus[0] {
                                first -= count(next);
                            }
                            if second >= focus[0] {
                                second -= count(next);
                            }
                            at = tail;
                        }
                        (true, false) => {
                            second -= count(next);
                            if second < focus[1] {
                                return preceding;
                            }
                            first = focus[0];
                            at = tail;
                        }
                        (false, true) => {
                            second = focus[0];
                            at = tail;
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
        if span == [0, count(at)] {
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
                Unfold::Alongside { earlier, .. } | Unfold::Before { earlier, .. } => {
                    (NodeKind::Sequence, event < count(earlier))
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
                tail,
                focus,
                ..
            }
            | Unfold::Before {
                earlier,
                next,
                tail,
                focus,
                ..
            } => {
                if span[1] <= count(earlier) {
                    at = earlier;
                    continue;
                }
                if span[0] < count(earlier) {
                    return None;
                }
                span[0] -= count(earlier);
                span[1] -= count(earlier);
                event -= count(earlier);
                if span == [focus[0], focus[1] + count(next)] {
                    return Some((
                        if matches!(steps[at], Unfold::Before { .. }) {
                            NodeKind::Sequence
                        } else {
                            NodeKind::Parallel
                        },
                        event < focus[0] + count(next),
                    ));
                }
                if focus[0] <= span[0] && span[1] <= focus[0] + count(next) {
                    span[0] -= focus[0];
                    span[1] -= focus[0];
                    event -= focus[0];
                    at = next;
                } else {
                    if span[1] <= focus[0] { /* unchanged prefix */
                    } else if span[0] >= focus[0] + count(next) {
                        span[0] -= count(next);
                        span[1] -= count(next);
                        event -= count(next);
                    } else if span[0] <= focus[0] && span[1] >= focus[1] + count(next) {
                        span[1] -= count(next);
                        // All inserted events occupy the original focus's
                        // side of every enclosing binary node.
                        if event >= focus[0] {
                            event = focus[0] + event.saturating_sub(focus[0] + count(next));
                        }
                    } else {
                        return None;
                    }
                    at = tail;
                }
            }
        }
    }
}
