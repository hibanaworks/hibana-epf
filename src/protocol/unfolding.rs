//! Check finite source unfoldings without enumerating a fixed catalogue of visits.
use super::{Layout, Protocol};

/// One postorder step of a proposed finite source unfolding.
///
/// Child indices must precede this step. The source of every child is derived
/// from the compiled protocol, starting at its root. These are audit witnesses,
/// not instructions that authorize or schedule application operations.
#[derive(Clone, Copy, Debug)]
pub enum Unfold {
    /// Keep the source message at this position.
    Message,
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

enum Head {
    Message,
    Sequence([Region; 2]),
    Parallel([Region; 2]),
    Choice([Region; 2]),
    Roll(Region),
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
                .head(self.records, expected)
                .ok_or(UnfoldingError::Step { index })?;
            let mut assign = |child: usize, source: Region| {
                let source = layout.canonical(self.records, source);
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
                (Unfold::Message, Head::Message) => {}
                (Unfold::Sequence(children), Head::Sequence(sources))
                | (Unfold::Parallel(children), Head::Parallel(sources))
                | (Unfold::Choice(children), Head::Choice(sources)) => {
                    assign(children[0], sources[0])?;
                    assign(children[1], sources[1])?;
                }
                (Unfold::Once(body), Head::Roll(source)) => assign(body, source)?,
                (Unfold::More([earlier, next]), Head::Roll(source)) => {
                    assign(earlier, expected)?;
                    assign(next, source)?;
                }
                (Unfold::Independent(children), Head::Roll(source)) => {
                    let Some(Head::Parallel(mut sources)) = layout.head(self.records, source)
                    else {
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
                        .retained(self.records, left, retained)
                        .ok_or(UnfoldingError::Step { index })?;
                    let Some(Head::Roll(body)) = layout.head(self.records, source) else {
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
                        .retained(self.records, left, retained)
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
                Unfold::Message => 1,
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
                    if !subtree(steps, rows, tail, focus) {
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
                Unfold::Message => return Some(get(self.rows, at).start as u16),
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
                Unfold::Message => return false,
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
    fn canonical(&self, records: &[hibana::runtime::tap::TapEvent], region: Region) -> Region {
        let mut first = region.last;
        let mut last = 0;
        for marker in region.first..region.last {
            let index = self.scopes.start + marker;
            let row = records[index];
            if row.arg1() & 3 != 0 {
                continue;
            }
            let Some(scope) = self.scope(records, row.causal_key()) else {
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

    fn head(&self, records: &[hibana::runtime::tap::TapEvent], region: Region) -> Option<Head> {
        if region.start >= region.end {
            return None;
        }
        if region.rolled {
            return Some(Head::Roll(Region {
                rolled: false,
                ..region
            }));
        }
        for marker in region.first..region.last {
            let index = self.scopes.start + marker;
            let row = records[index];
            if row.arg1() & 3 != 0 || row.arg0() as usize != region.start {
                continue;
            }
            let scope = self.scope(records, row.causal_key())?;
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
                        Head::Choice(children)
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

    fn retained(
        &self,
        records: &[hibana::runtime::tap::TapEvent],
        parent: Region,
        key: u16,
    ) -> Option<Region> {
        if key >> 13 != 1 {
            return None;
        }
        let scope = self.scope(records, key)?;
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

fn subtree(steps: &[Unfold], rows: &[usize], mut at: usize, mut span: [usize; 2]) -> bool {
    loop {
        let count = |node| rows[5 * node + 4];
        if span[0] >= span[1] || span[1] > count(at) {
            return false;
        }
        if span == [0, count(at)] {
            return true;
        }
        match steps[at] {
            Unfold::Message => return false,
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
                if span[1] <= count(earlier) {
                    at = earlier;
                    continue;
                }
                if span[0] < count(earlier) {
                    return false;
                }
                span[0] -= count(earlier);
                span[1] -= count(earlier);
                if span == [focus[0], focus[1] + count(next)] {
                    return true;
                }
                if focus[0] <= span[0] && span[1] <= focus[0] + count(next) {
                    span[0] -= focus[0];
                    span[1] -= focus[0];
                    at = next;
                } else {
                    if span[1] <= focus[0] { /* unchanged prefix */
                    } else if span[0] >= focus[0] + count(next) {
                        span[0] -= count(next);
                        span[1] -= count(next);
                    } else if span[0] <= focus[0] && span[1] >= focus[1] + count(next) {
                        span[1] -= count(next);
                    } else {
                        return false;
                    }
                    at = tail;
                }
            }
        }
    }
}
