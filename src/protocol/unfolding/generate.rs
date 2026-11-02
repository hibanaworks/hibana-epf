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
    for (count, received) in counts.iter_mut().zip(receives.iter()) {
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
        let region = layout.canonical(protocol, get(frames, depth));
        let head = layout.head(protocol, region)?;
        let phase = frames[5 * depth + 4];
        let factor = factors[depth];
        let append = |step, output: &mut usize, steps: &mut [Unfold]| {
            let slot = *output;
            *steps.get_mut(slot)? = step;
            *output += 1;
            Some(slot)
        };
        let compact = phase == 0
            && counts[region.start..region.end]
                .iter()
                .all(|&n| n <= factor)
            && (region.first..region.last).all(|marker| {
                let row = protocol.records[layout.scopes.start + marker];
                if row.causal_key() >> 13 != 1 || row.arg1() & 3 != 0 {
                    return true;
                }
                let scope = protocol.scope(row.causal_key()).expect("checked scope");
                let body = Region {
                    start: scope.start as usize,
                    end: scope.end as usize,
                    first: marker + 1,
                    last: scope.last - layout.scopes.start,
                    rolled: false,
                };
                visits(&layout, protocol, body, counts, factor, receives) == 1
            });
        let result = match (phase, head) {
            (0, _) if compact => Some(append(Unfold::Source, &mut output, steps)?),
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
                put(frames, child, layout.canonical(protocol, children[0]));
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
                put(frames, child, layout.canonical(protocol, children[1]));
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
                let visits = visits(&layout, protocol, body, counts, factor, receives);
                first[depth] = visits;
                put(frames, child, layout.canonical(protocol, body));
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
    scratch: &mut [usize],
) -> usize {
    // Collapse completed source subtrees in marker order. A sequence or par
    // shares visits; opposite route arms need separate visits. A nested roll
    // can account for its own repetitions within one enclosing visit.
    scratch[body.start..body.end].copy_from_slice(&counts[body.start..body.end]);
    for marker in body.first..body.last {
        let index = layout.scopes.start + marker;
        let row = protocol.records[index];
        let scope = protocol.scope(row.causal_key()).unwrap();
        if scope.last != index
            || scope.first < layout.scopes.start + body.first
            || (scope.start as usize) < body.start
            || scope.end as usize > body.end
        {
            continue;
        }
        let start = scope.start as usize;
        let end = scope.end as usize;
        let value = match row.causal_key() >> 13 {
            0 => {
                let split = scope.split.unwrap() as usize;
                scratch[start..split].iter().max().copied().unwrap_or(0)
                    + scratch[split..end].iter().max().copied().unwrap_or(0)
            }
            1 => usize::from(scratch[start..end].iter().any(|&n| n != 0)),
            _ => scratch[start..end].iter().max().copied().unwrap_or(0),
        };
        scratch[start..end].fill(0);
        scratch[start] = value;
    }
    scratch[body.start..body.end]
        .iter()
        .max()
        .copied()
        .unwrap_or(0)
        .div_ceil(factor)
        .max(1)
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
            let region = layout.canonical(self.protocol, get(self.rows, index));
            let head = layout.head(self.protocol, region)?;
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
                put(self.rows, child, layout.canonical(self.protocol, source));
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
            if let Some(Head::Parallel(mut sources)) = layout.head(protocol, body)
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
                let Some(source) = layout.retained(protocol, left, retained) else {
                    continue;
                };
                let Head::Roll(body) = layout.head(protocol, source)? else {
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use hibana::{g, runtime::program::project};
    use std::vec;

    #[test]
    fn branch_demands_add_while_sequence_parallel_and_nested_roll_share_visits() {
        let global = g::par(
            g::route(
                g::seq(
                    g::send::<7, 7, g::Msg<1, ()>>(),
                    g::send::<7, 7, g::Msg<2, ()>>(),
                ),
                g::seq(
                    g::send::<7, 7, g::Msg<3, ()>>(),
                    g::send::<7, 7, g::Msg<4, ()>>(),
                ),
            ),
            g::send::<7, 7, g::Msg<5, ()>>().roll(),
        )
        .roll();
        let snapshot = tap::projected(&project::<7>(&global)).collect::<std::vec::Vec<_>>();
        let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
        let layout = Layout::checked(protocol);
        let root = Region {
            start: 0,
            end: 5,
            first: 0,
            last: layout.scopes.len(),
            rolled: false,
        };
        let Head::Roll(body) = layout.head(protocol, root).unwrap() else {
            panic!("outer roll");
        };
        let mut scratch = [0; 5];
        assert_eq!(
            visits(&layout, protocol, body, &[3, 3, 2, 2, 100], 1, &mut scratch),
            5
        );
        assert_eq!(
            visits(&layout, protocol, body, &[3, 3, 2, 2, 100], 2, &mut scratch),
            3
        );
    }
}
