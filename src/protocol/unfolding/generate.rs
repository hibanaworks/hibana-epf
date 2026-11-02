//! Enumerate source-typed finite derivations in caller-owned storage.
//!
//! Every child occupies a contiguous postorder interval. Shared derivations
//! have an equivalent tree, so this covers the unfolding grammar without
//! enumerating arbitrary DAG references or unrelated source constructors.
use super::{Head, Layout, Protocol, Region, Unfold, get, put};
use crate::Capture;
use hibana::runtime::tap;

/// A cheap first candidate for common, uniformly repeated bodies. Counts only
/// guide construction: they never establish a visit or bypass checking. The
/// exhaustive source-typed search still follows if this candidate fails.
pub(crate) fn seed(
    protocol: Protocol<'_>,
    captures: &[Capture<'_>],
    session: u32,
    steps: &mut [Unfold],
    workspace: &mut [usize],
) -> Option<usize> {
    if steps.is_empty() {
        return None;
    }
    let layout = Layout::checked(protocol);
    let capacity = steps.len();
    let (frames, rest) = workspace.split_at_mut(5 * capacity);
    let (factors, rest) = rest.split_at_mut(capacity);
    let (first, rest) = rest.split_at_mut(capacity);
    let (counts, receives) = rest[capacity..].split_at_mut(layout.sources.len());
    counts.fill(0);
    receives.fill(0);
    for row in captures.iter().flat_map(|c| c.records()) {
        let source = row.arg1() as u16 as usize;
        if row.arg0() == session && source < counts.len() {
            match row.id() {
                tap::ENDPOINT_SEND => counts[source] += 1,
                tap::ENDPOINT_RECV => receives[source] += 1,
                _ => {}
            }
        }
    }
    for (count, received) in counts.iter_mut().zip(receives) {
        *count = (*count).max(*received);
    }
    let root = Region {
        start: 0,
        end: layout.sources.len(),
        first: 0,
        last: layout.scopes.len(),
        rolled: false,
    };
    put(frames, 0, root);
    frames[4] = 0;
    factors[0] = 1;
    let mut depth = 0;
    let mut output = 0;
    let mut returned = None;
    loop {
        let region = layout.canonical(protocol.records, get(frames, depth));
        let head = layout.head(protocol.records, region)?;
        let phase = frames[5 * depth + 4];
        let factor = factors[depth];
        let append = |step, output: &mut usize, steps: &mut [Unfold]| {
            let slot = *output;
            *steps.get_mut(slot)? = step;
            *output += 1;
            Some(slot)
        };
        let result = match (phase, head) {
            (0, _)
                if counts[region.start..region.end]
                    .iter()
                    .all(|&n| n <= factor) =>
            {
                Some(append(Unfold::Source, &mut output, steps)?)
            }
            (0, Head::Message) => Some(append(Unfold::Source, &mut output, steps)?),
            (
                0,
                Head::Sequence(children) | Head::Parallel(children) | Head::Choice(_, children),
            ) => {
                frames[5 * depth + 4] = 1;
                let child = depth + 1;
                if child >= capacity {
                    return None;
                }
                put(
                    frames,
                    child,
                    layout.canonical(protocol.records, children[0]),
                );
                frames[5 * child + 4] = 0;
                factors[child] = factor;
                depth = child;
                continue;
            }
            (
                1,
                Head::Sequence(children) | Head::Parallel(children) | Head::Choice(_, children),
            ) => {
                first[depth] = returned.take()?;
                frames[5 * depth + 4] = 2;
                let child = depth + 1;
                if child >= capacity {
                    return None;
                }
                put(
                    frames,
                    child,
                    layout.canonical(protocol.records, children[1]),
                );
                frames[5 * child + 4] = 0;
                factors[child] = factor;
                depth = child;
                continue;
            }
            (2, Head::Sequence(_) | Head::Parallel(_) | Head::Choice(_, _)) => {
                let children = [first[depth], returned.take()?];
                Some(append(
                    match head {
                        Head::Sequence(_) => Unfold::Sequence(children),
                        Head::Parallel(_) => Unfold::Parallel(children),
                        Head::Choice(_, _) => Unfold::Choice(children),
                        Head::Message | Head::Roll(_) => unreachable!(),
                    },
                    &mut output,
                    steps,
                )?)
            }
            (0, Head::Roll(body)) => {
                frames[5 * depth + 4] = 1;
                let child = depth + 1;
                if child >= capacity {
                    return None;
                }
                let visits = visits(&layout, protocol, body, counts, factor);
                first[depth] = visits;
                put(frames, child, layout.canonical(protocol.records, body));
                frames[5 * child + 4] = 0;
                factors[child] = factor.checked_mul(visits)?;
                depth = child;
                continue;
            }
            (1, Head::Roll(_)) => {
                let body = returned.take()?;
                let mut earlier = append(Unfold::Once(body), &mut output, steps)?;
                for _ in 1..first[depth] {
                    earlier = append(Unfold::More([earlier, body]), &mut output, steps)?;
                }
                Some(earlier)
            }
            _ => unreachable!("source traversal phase"),
        };
        returned = result;
        if depth == 0 {
            return Some(output);
        }
        depth -= 1;
    }
}

fn visits(
    layout: &Layout,
    protocol: Protocol<'_>,
    body: Region,
    counts: &[usize],
    factor: usize,
) -> usize {
    let mut visits = 1;
    for (source, &count) in counts.iter().enumerate().take(body.end).skip(body.start) {
        let in_nested_roll = (body.first..body.last).any(|marker| {
            let row = protocol.records[layout.scopes.start + marker];
            row.causal_key() >> 13 == 1
                && row.arg1() & 3 == 0
                && layout
                    .scope(protocol.records, row.causal_key())
                    .is_some_and(|scope| {
                        scope.first >= layout.scopes.start + body.first
                            && scope.last < layout.scopes.start + body.last
                            && scope.start as usize <= source
                            && source < scope.end as usize
                    })
        });
        if !in_nested_roll {
            visits = visits.max(count.div_ceil(factor));
        }
    }
    visits
}

pub(crate) struct Derivations<'p, 'w> {
    protocol: Protocol<'p>,
    pub(crate) steps: &'w mut [Unfold],
    rows: &'w mut [usize],
    digits: &'w mut [usize],
    size: usize,
}

impl<'p, 'w> Derivations<'p, 'w> {
    pub(crate) fn new(
        protocol: Protocol<'p>,
        steps: &'w mut [Unfold],
        workspace: &'w mut [usize],
    ) -> Self {
        let (rows, digits) = workspace.split_at_mut(5 * steps.len());
        Self {
            protocol,
            steps,
            rows,
            digits,
            size: 0,
        }
    }

    pub(crate) fn next(&mut self) -> Option<usize> {
        let layout = Layout::checked(self.protocol);
        let root = Region {
            start: 0,
            end: layout.sources.len(),
            first: 0,
            last: layout.scopes.len(),
            rolled: false,
        };
        let mut index = 0;
        loop {
            if self.size == 0 || index == self.size {
                self.size += 1;
                if self.size > self.steps.len() {
                    return None;
                }
                index = self.size - 1;
                self.digits[..self.size].fill(0);
                put(self.rows, index, root);
                self.rows[5 * index + 4] = 0;
            }
            let begin = self.rows[5 * index + 4];
            let region = layout.canonical(self.protocol.records, get(self.rows, index));
            let head = layout.head(self.protocol.records, region)?;
            let candidate = configuration(
                &layout,
                self.protocol,
                region,
                head,
                begin,
                index,
                self.digits[index],
            );
            let Some((step, children)) = candidate else {
                index += 1;
                continue;
            };
            self.digits[index] += 1;
            self.steps[index] = step;
            self.digits[..index].fill(0);
            for (child, start, source) in children.into_iter().flatten() {
                put(
                    self.rows,
                    child,
                    layout.canonical(self.protocol.records, source),
                );
                self.rows[5 * child + 4] = start;
            }
            if index == 0 {
                return Some(self.size);
            }
            index -= 1;
        }
    }
}

type Children = [Option<(usize, usize, Region)>; 3];

fn binary(begin: usize, end: usize, left: usize, sources: [Region; 2]) -> ([usize; 2], Children) {
    let split = begin + left;
    (
        [split - 1, end - 1],
        [
            Some((split - 1, begin, sources[0])),
            Some((end - 1, split, sources[1])),
            None,
        ],
    )
}

fn configuration(
    layout: &Layout,
    protocol: Protocol<'_>,
    region: Region,
    head: Head,
    begin: usize,
    end: usize,
    mut rank: usize,
) -> Option<(Unfold, Children)> {
    let size = end - begin + 1;
    if size == 1 {
        return (rank == 0).then_some((Unfold::Source, [None; 3]));
    }
    let partitions = size.saturating_sub(2);
    match head {
        Head::Message => None,
        Head::Roll(body) => {
            if rank == 0 {
                return Some((
                    Unfold::Once(end - 1),
                    [Some((end - 1, begin, body)), None, None],
                ));
            }
            rank -= 1;
            if rank < partitions {
                let (children, rows) = binary(begin, end, rank + 1, [region, body]);
                return Some((Unfold::More(children), rows));
            }
            rank -= partitions;
            if let Some(Head::Parallel(mut sources)) = layout.head(protocol.records, body)
                && rank < partitions
            {
                for source in &mut sources {
                    source.rolled = true;
                }
                let (children, rows) = binary(begin, end, rank + 1, sources);
                return Some((Unfold::Independent(children), rows));
            }
            None
        }
        Head::Parallel(sources) | Head::Choice(_, sources) => {
            if rank >= partitions {
                return None;
            }
            let (children, rows) = binary(begin, end, rank + 1, sources);
            Some((
                if matches!(head, Head::Parallel(_)) {
                    Unfold::Parallel(children)
                } else {
                    Unfold::Choice(children)
                },
                rows,
            ))
        }
        Head::Sequence([left, right]) => {
            if rank < partitions {
                let (children, rows) = binary(begin, end, rank + 1, [left, right]);
                return Some((Unfold::Sequence(children), rows));
            }
            rank -= partitions;
            for marker in left.first..left.last {
                let row = protocol.records[layout.scopes.start + marker];
                if row.arg1() & 3 != 0 {
                    continue;
                }
                let retained = row.causal_key();
                let Some(source) = layout.retained(protocol.records, left, retained) else {
                    continue;
                };
                let Head::Roll(body) = layout.head(protocol.records, source)? else {
                    continue;
                };
                if rank < partitions {
                    let ([earlier, next], rows) = binary(begin, end, rank + 1, [region, body]);
                    return Some((
                        Unfold::After {
                            retained,
                            earlier,
                            next,
                        },
                        rows,
                    ));
                }
                rank -= partitions;
                for earlier_size in 1..size.saturating_sub(2) {
                    for next_size in 1..size - earlier_size - 1 {
                        let tail_size = size - 1 - earlier_size - next_size;
                        // A tree has at most this many messages in its tail.
                        // Invalid intervals are rejected by Protocol::unfolding.
                        let bound = tail_size.checked_mul(layout.sources.len())?;
                        let intervals = bound.checked_mul(bound.checked_add(1)?)? / 2;
                        for before in [false, true] {
                            if rank >= intervals {
                                rank -= intervals;
                                continue;
                            }
                            let mut start = 0;
                            while rank >= bound - start {
                                rank -= bound - start;
                                start += 1;
                            }
                            let focus = [start, start + 1 + rank];
                            let earlier = begin + earlier_size - 1;
                            let next = earlier + next_size;
                            let tail = end - 1;
                            let rows = [
                                Some((earlier, begin, left)),
                                Some((next, earlier + 1, source)),
                                Some((tail, next + 1, right)),
                            ];
                            return Some((
                                if before {
                                    Unfold::Before {
                                        retained,
                                        earlier,
                                        next,
                                        tail,
                                        focus,
                                    }
                                } else {
                                    Unfold::Alongside {
                                        retained,
                                        earlier,
                                        next,
                                        tail,
                                        focus,
                                    }
                                },
                                rows,
                            ));
                        }
                    }
                }
            }
            None
        }
    }
}
