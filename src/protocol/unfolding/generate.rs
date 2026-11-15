//! Enumerate source-typed finite derivations in caller-owned storage.
//!
//! Every child occupies a contiguous postorder interval. Shared derivations
//! have an equivalent tree, so this covers the unfolding grammar without
//! enumerating arbitrary DAG references or unrelated source constructors.
use super::{Head, InsertPart, Layout, Protocol, Region, Unfold, get, insertion_part, put};
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
    // This seed may need both observed demand and demand outside nested
    // rolls. Reuse the derivation-rank row, which the seed otherwise leaves
    // untouched. Short temporary storage only declines this preference; the
    // complete derivation enumeration is unchanged.
    let (direct, rest) = rest.split_at_mut(capacity);
    let direct = direct.get_mut(..layout.sources.len())?;
    let (counts, receives) = rest.split_at_mut(layout.sources.len());
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
        let mut factor = factors[depth];
        if phase == 0 && depth != 0 {
            let parent = layout.canonical(protocol, get(frames, depth - 1));
            if matches!(layout.head(protocol, parent), Some(Head::Choice(_, _))) {
                // An arm may occur in only some enclosing visits. Its
                // nonnested observations guide that arm's divisor; dividing
                // an inner retry by every enclosing visit loses repetitions.
                let (_, anchors) = visits(&layout, protocol, region, counts, 1, receives, direct);
                if anchors != 0 {
                    factor = factor.min(anchors);
                    factors[depth] = factor;
                }
            }
        }
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
                protocol.records[layout.scopes.start + marker].causal_key() >> 13 != 1
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
                let (visits, _) = visits(&layout, protocol, body, counts, factor, receives, direct);
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
            return Some(retained_seed(
                protocol, captures, session, steps, output, workspace,
            ));
        }
        depth -= 1;
    }
}

// A producer can observe one actor in a roll, then in its continuation, then
// in the roll again. Counts alone put every visit before the continuation.
// Prefer checked grafts for its later visits in that case. This only constructs
// a candidate: source placement, selected ownership and every record are still
// checked by the same independent path/execution checks as every other tree.
fn retained_seed(
    protocol: Protocol<'_>,
    captures: &[Capture<'_>],
    session: u32,
    steps: &mut [Unfold],
    size: usize,
    workspace: &mut [usize],
) -> usize {
    let capacity = steps.len();
    let layout = Layout::checked(protocol);
    let (rows, rest) = workspace.split_at_mut(5 * capacity);
    let (mapped, rest) = rest.split_at_mut(capacity);
    let (counts, rest) = rest.split_at_mut(capacity);
    let targets = &mut rest[..capacity];
    targets.fill(usize::MAX);
    {
        let Ok(source) = protocol.unfolding(&steps[..size], rows) else {
            return size;
        };
        for parent in 0..size {
            let Unfold::Sequence([left, _]) = steps[parent] else {
                continue;
            };
            let Some(Head::Sequence([region, tail])) =
                layout.head(protocol, get(source.rows, parent))
            else {
                continue;
            };
            let retained = |at: usize| {
                if !matches!(steps[at], Unfold::More(_)) {
                    return None;
                }
                let node = get(source.rows, at);
                if node.rolled {
                    return None;
                }
                let marker = protocol.records.get(layout.scopes.start + node.first)?;
                let key = marker.causal_key();
                if layout.retained(protocol, region, key)? != node {
                    return None;
                }
                // Nested visits have their own per-enclosing-visit demand.
                // Leave that preference to the ordinary structural seed.
                if protocol.records[layout.scopes.clone()].iter().any(|row| {
                    row.causal_key() >> 13 == 1
                        && row.arg1() & 3 == 0
                        && protocol.scope(row.causal_key()).is_some_and(|outer| {
                            outer.first < layout.scopes.start + node.first
                                && layout.scopes.start + node.last - 1 < outer.last
                        })
                }) {
                    return None;
                }
                if (at + 1..=left).any(|later| {
                    matches!(steps[later], Unfold::More(_)) && get(source.rows, later) == node
                }) {
                    return None;
                }
                Some((key, node))
            };
            if !(0..=left).filter_map(retained).any(|(_, body)| {
                captures.iter().any(|capture| {
                    // Actor IDs are u8, so each set is exactly 256 bits.
                    let mut inside = [0u64; 4];
                    let mut crossed = [0u64; 4];
                    for record in capture.records() {
                        if record.arg0() != session
                            || !matches!(record.id(), tap::ENDPOINT_SEND | tap::ENDPOINT_RECV)
                        {
                            continue;
                        }
                        let actor = usize::from(record.causal_key() >> 8);
                        let (word, bit) = (actor / 64, 1u64 << (actor % 64));
                        let origin = usize::from(record.arg1() as u16);
                        if body.start <= origin && origin < body.end {
                            if crossed[word] & bit != 0 {
                                return true;
                            }
                            inside[word] |= bit;
                        } else if tail.start <= origin
                            && origin < tail.end
                            && inside[word] & bit != 0
                        {
                            crossed[word] |= bit;
                        }
                    }
                    false
                })
            }) {
                continue;
            }
            for (at, target) in targets[..=left].iter_mut().enumerate() {
                if retained(at).is_some() {
                    *target = parent;
                }
            }
        }
    }
    if targets[..size].iter().all(|&parent| parent == usize::MAX) {
        return size;
    }
    let mut pending = size;
    while pending != 0 {
        pending -= 1;
        if targets[pending] != usize::MAX
            && let Unfold::More([earlier, _]) = steps[pending]
            && matches!(steps[earlier], Unfold::More(_))
        {
            targets[earlier] = targets[pending];
        }
    }
    // Keep the original candidate intact until its replacement fits. The same
    // caller storage holds the new postorder tree and the remapping; no source
    // AST, task state or additional permission representation is introduced.
    let append = |step, count, output: &mut usize, steps: &mut [Unfold], counts: &mut [usize]| {
        let at = *output;
        *steps.get_mut(at)? = step;
        counts[at] = count;
        *output += 1;
        Some(at)
    };
    let mut output = size;
    for at in 0..size {
        if targets[at] != usize::MAX {
            let Unfold::More([earlier, _]) = steps[at] else {
                unreachable!();
            };
            mapped[at] = mapped[earlier];
            continue;
        }
        let (step, count) = match steps[at] {
            Unfold::Source => (Unfold::Source, rows[5 * at + 4]),
            Unfold::Once(body) => (Unfold::Once(mapped[body]), counts[mapped[body]]),
            Unfold::Sequence([a, b])
            | Unfold::Parallel([a, b])
            | Unfold::Choice([a, b])
            | Unfold::More([a, b])
            | Unfold::Independent([a, b]) => {
                let children = [mapped[a], mapped[b]];
                let Some(count) = counts[children[0]].checked_add(counts[children[1]]) else {
                    return size;
                };
                let step = match steps[at] {
                    Unfold::Sequence(_) => Unfold::Sequence(children),
                    Unfold::Parallel(_) => Unfold::Parallel(children),
                    Unfold::Choice(_) => Unfold::Choice(children),
                    Unfold::More(_) => Unfold::More(children),
                    Unfold::Independent(_) => Unfold::Independent(children),
                    _ => unreachable!(),
                };
                (step, count)
            }
            Unfold::After { .. } | Unfold::Alongside { .. } | Unfold::Before { .. } => {
                unreachable!("the uniform seed has no retained insertions")
            }
        };
        let Some(node) = append(step, count, &mut output, steps, counts) else {
            return size;
        };
        mapped[at] = node;
        let Unfold::Sequence([_, right]) = steps[at] else {
            continue;
        };
        let continuation = get(rows, right);
        while let Some(retained) = (0..at)
            .filter(|&index| targets[index] == at)
            .min_by(|&a, &b| {
                let visit = |index| {
                    let region = get(rows, index);
                    (
                        protocol.records[layout.scopes.start + region.first].causal_key(),
                        more_visit(steps, index),
                        [region.start, region.end],
                    )
                };
                observed_before(captures, session, visit(a), visit(b))
                    .map(|before| {
                        if before {
                            core::cmp::Ordering::Less
                        } else {
                            core::cmp::Ordering::Greater
                        }
                    })
                    .unwrap_or_else(|| a.cmp(&b))
            })
        {
            targets[retained] = usize::MAX;
            let Unfold::More([_, body]) = steps[retained] else {
                unreachable!();
            };
            let visit = more_visit(steps, retained);
            let key =
                protocol.records[layout.scopes.start + get(rows, retained).first].causal_key();
            let region = get(rows, retained);
            let count = counts[mapped[body]];
            let mut focus: Option<[usize; 2]> = None;
            for pivot in 0..=right {
                let Unfold::More([_, pivot_body]) = steps[pivot] else {
                    continue;
                };
                let node = get(rows, pivot);
                if node.rolled {
                    continue;
                }
                let Some(marker) = protocol.records.get(layout.scopes.start + node.first) else {
                    continue;
                };
                if layout.retained(protocol, continuation, marker.causal_key()) != Some(node) {
                    continue;
                }
                let mut rank = 0;
                while let Some(span) =
                    visit_range((steps, counts), (mapped[at], mapped[pivot_body]), rank)
                {
                    let preferred = observed_before(
                        captures,
                        session,
                        (key, visit, [region.start, region.end]),
                        (marker.causal_key(), rank, [node.start, node.end]),
                    )
                    .unwrap_or(rank == visit);
                    if preferred && focus.is_none_or(|current| span[0] < current[0]) {
                        focus = Some(span);
                    }
                    rank += 1;
                }
            }
            let step = if let Some(focus) = focus {
                let Some(next) = append(
                    Unfold::Once(mapped[body]),
                    count,
                    &mut output,
                    steps,
                    counts,
                ) else {
                    return size;
                };
                Unfold::Before {
                    retained: key,
                    earlier: mapped[at],
                    next,
                    focus,
                }
            } else {
                Unfold::After {
                    retained: key,
                    earlier: mapped[at],
                    next: mapped[body],
                }
            };
            let Some(total) = counts[mapped[at]].checked_add(count) else {
                return size;
            };
            let Some(node) = append(step, total, &mut output, steps, counts) else {
                return size;
            };
            mapped[at] = node;
        }
    }
    // A removed More node can leave only its unused wrapper behind; each body
    // remains reachable through its resumed Once. Discard the original prefix.
    let count = output - size;
    steps.copy_within(size..output, 0);
    for step in &mut steps[..count] {
        match step {
            Unfold::Source => (),
            Unfold::Once(body) => *body -= size,
            Unfold::Sequence(children)
            | Unfold::Parallel(children)
            | Unfold::Choice(children)
            | Unfold::More(children)
            | Unfold::Independent(children) => {
                children[0] -= size;
                children[1] -= size;
            }
            Unfold::After { earlier, next, .. }
            | Unfold::Alongside { earlier, next, .. }
            | Unfold::Before { earlier, next, .. } => {
                *earlier -= size;
                *next -= size;
            }
        }
    }
    count
}

fn more_visit(steps: &[Unfold], index: usize) -> usize {
    let Unfold::More([mut earlier, _]) = steps[index] else {
        unreachable!("a retained visit is a More node");
    };
    let mut visit = 1;
    while let Unfold::More([previous, _]) = steps[earlier] {
        visit += 1;
        earlier = previous;
    }
    visit
}

// Only compare visits witnessed by the same actor. Different senders can enter
// in one order while a shared receiver consumes their frames in the other.
// Producer ordinals never order different streams. Conflicting or missing
// hints leave the source preference intact; the independent checker still
// decides every proposal.
fn observed_before(
    captures: &[Capture<'_>],
    session: u32,
    prior: (u16, usize, [usize; 2]),
    next: (u16, usize, [usize; 2]),
) -> Option<bool> {
    let mut preference = None;
    for capture in captures {
        let inside = |record: &tap::TapEvent, range: [usize; 2]| {
            let origin = usize::from(record.arg1() as u16);
            record.arg0() == session
                && range[0] <= origin
                && origin < range[1]
                && (record.id() == tap::SEND_POLL || super::super::execution::committed(*record))
        };
        let mut actors = [0u64; 4];
        for record in capture
            .records()
            .iter()
            .filter(|record| inside(record, prior.2))
        {
            let actor = usize::from(record.causal_key() >> 8);
            actors[actor / 64] |= 1 << (actor % 64);
        }
        for record in capture
            .records()
            .iter()
            .filter(|record| inside(record, next.2))
        {
            let actor = record.causal_key() >> 8;
            let word = usize::from(actor / 64);
            let bit = 1 << (actor % 64);
            if actors[word] & bit == 0 {
                continue;
            }
            actors[word] &= !bit;
            let entry = |(key, visit, range): (u16, usize, [usize; 2])| {
                if visit == 0 {
                    capture
                        .records()
                        .iter()
                        .find(|record| inside(record, range) && record.causal_key() >> 8 == actor)
                } else {
                    capture
                        .records()
                        .iter()
                        .filter(|record| {
                            record.arg0() == session
                                && record.id() == tap::SCOPE_REENTRY
                                && record.arg1() >> 16 == u32::from(key)
                                && record.causal_key() >> 8 == actor
                        })
                        .nth(visit - 1)
                }
            };
            if let (Some(a), Some(b)) = (entry(prior), entry(next)) {
                let observed = a.ts() < b.ts();
                if preference.is_some_and(|previous| previous != observed) {
                    return None;
                }
                preference = Some(observed);
            }
        }
    }
    preference
}

// Locate an invocation of an immutable body in the candidate just constructed.
// Whole-body grafts keep that body's leaves contiguous. Walk its existing
// proof coordinates without recursion, another source tree or a task cursor.
fn visit_range(
    (steps, counts): (&[Unfold], &[usize]),
    (root, body): (usize, usize),
    mut visit: usize,
) -> Option<[usize; 2]> {
    let mut event = 0;
    while event < counts[root] {
        let (mut at, mut local) = (root, event);
        loop {
            if at == body {
                let start = event - local;
                if visit == 0 {
                    return Some([start, start + counts[body]]);
                }
                visit -= 1;
                event = start + counts[body];
                break;
            }
            match steps[at] {
                Unfold::Source => {
                    event += 1;
                    break;
                }
                Unfold::Once(child) => at = child,
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
                    if local < counts[a] {
                        at = a;
                    } else {
                        local -= counts[a];
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
                } => match insertion_part(local, focus[0], counts[next]) {
                    InsertPart::Earlier(position) => {
                        local = position;
                        at = earlier;
                    }
                    InsertPart::Resumed(position) => {
                        local = position;
                        at = next;
                    }
                },
            }
        }
    }
    None
}

fn visits(
    layout: &Layout,
    protocol: Protocol<'_>,
    body: Region,
    counts: &[usize],
    factor: usize,
    scratch: &mut [usize],
    direct: &mut [usize],
) -> (usize, usize) {
    // Collapse completed source subtrees in marker order. A sequence or par
    // shares visits; opposite route arms need separate visits. A nested roll
    // can account for its own repetitions within one enclosing visit. The
    // second summary excludes those repetitions and retains only observations
    // outside nested rolls, for the selective-arm factor above.
    scratch[body.start..body.end].copy_from_slice(&counts[body.start..body.end]);
    direct[body.start..body.end].copy_from_slice(&counts[body.start..body.end]);
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
        let (value, anchors) = match row.causal_key() >> 13 {
            0 => {
                let split = scope.split.unwrap() as usize;
                (
                    scratch[start..split].iter().max().copied().unwrap_or(0)
                        + scratch[split..end].iter().max().copied().unwrap_or(0),
                    direct[start..split].iter().max().copied().unwrap_or(0)
                        + direct[split..end].iter().max().copied().unwrap_or(0),
                )
            }
            1 => (usize::from(scratch[start..end].iter().any(|&n| n != 0)), 0),
            _ => (
                scratch[start..end].iter().max().copied().unwrap_or(0),
                direct[start..end].iter().max().copied().unwrap_or(0),
            ),
        };
        scratch[start..end].fill(0);
        scratch[start] = value;
        direct[start..end].fill(0);
        direct[start] = anchors;
    }
    (
        scratch[body.start..body.end]
            .iter()
            .max()
            .copied()
            .unwrap_or(0)
            .div_ceil(factor)
            .max(1),
        direct[body.start..body.end]
            .iter()
            .max()
            .copied()
            .unwrap_or(0),
    )
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
                for earlier_size in 1..size - 1 {
                    let bound = earlier_size.checked_mul(layout.sources.len())?;
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
                        let ([earlier, next], rows) =
                            binary(begin, end, earlier_size, [region, source]);
                        return Some((
                            if before {
                                Unfold::Before {
                                    retained,
                                    earlier,
                                    next,
                                    focus,
                                }
                            } else {
                                Unfold::Alongside {
                                    retained,
                                    earlier,
                                    next,
                                    focus,
                                }
                            },
                            rows,
                        ));
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
    fn shared_receiver_order_guides_visits_independently_of_sender_entry_order() {
        for receiver_first in [0, 1] {
            let fields = [
                (tap::ENDPOINT_SEND, 0, 0),
                (tap::ENDPOINT_SEND, 1, 1),
                (tap::ENDPOINT_RECV, 2, 0),
                (tap::ENDPOINT_RECV, 2, 1),
                (tap::SCOPE_REENTRY, 0, 20 << 16),
                (tap::SEND_POLL, 0, 0),
                (tap::SCOPE_REENTRY, 1, 21 << 16 | 1),
                (tap::SEND_POLL, 1, 1),
                (
                    tap::SCOPE_REENTRY,
                    2,
                    (20 + receiver_first) << 16 | receiver_first,
                ),
                (tap::ENDPOINT_RECV, 2, receiver_first),
                (
                    tap::SCOPE_REENTRY,
                    2,
                    (21 - receiver_first) << 16 | (1 - receiver_first),
                ),
                (tap::ENDPOINT_RECV, 2, 1 - receiver_first),
            ];
            let rows: std::vec::Vec<_> = fields
                .into_iter()
                .enumerate()
                .map(|(ordinal, (kind, actor, detail))| {
                    let mut bytes = [0; 16];
                    bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
                    bytes[4..6].copy_from_slice(&kind.to_be_bytes());
                    bytes[6..8].copy_from_slice(&((actor as u16) << 8).to_be_bytes());
                    bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
                    bytes[12..].copy_from_slice(&(detail as u32).to_be_bytes());
                    tap::TapEvent::from(bytes)
                })
                .collect();
            let captures = [Capture::new(&rows, Some(rows.len() as u32)).unwrap()];
            assert_eq!(
                observed_before(&captures, 1, (20, 0, [0, 1]), (21, 0, [1, 2])),
                Some(true)
            );
            assert_eq!(
                observed_before(&captures, 1, (20, 1, [0, 1]), (21, 1, [1, 2])),
                Some(receiver_first == 0)
            );
            // A missing visit supplies no order constraint.
            assert_eq!(
                observed_before(&captures, 1, (20, 2, [0, 1]), (21, 1, [1, 2])),
                None
            );
            // Neither another session nor independent producer counters order these visits.
            assert_eq!(
                observed_before(&captures, 2, (20, 1, [0, 1]), (21, 1, [1, 2])),
                None
            );
            let split: std::vec::Vec<_> = [0, 1]
                .into_iter()
                .map(|origin| {
                    let row = rows[origin];
                    let mut bytes: [u8; 16] = row.into();
                    bytes[..4].copy_from_slice(&0u32.to_be_bytes());
                    [tap::TapEvent::from(bytes)]
                })
                .collect();
            let separate: std::vec::Vec<_> = split
                .iter()
                .map(|records| Capture::new(records, Some(1)).unwrap())
                .collect();
            assert_eq!(
                observed_before(&separate, 1, (20, 0, [0, 1]), (21, 0, [1, 2])),
                None
            );
        }
    }

    #[test]
    fn a_selective_outer_arm_keeps_both_of_its_inner_visits() {
        let global = g::seq(
            g::route(
                g::send::<7, 7, g::Msg<1, ()>>(),
                g::seq(
                    g::send::<7, 7, g::Msg<2, ()>>().roll(),
                    g::send::<7, 7, g::Msg<3, ()>>(),
                ),
            ),
            g::send::<7, 7, g::Msg<4, ()>>(),
        )
        .roll();
        let snapshot = tap::projected(&project::<7>(&global)).collect::<std::vec::Vec<_>>();
        let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
        let expected = [1u16, 1, 2, 3, 0, 3];
        let records = expected
            .iter()
            .enumerate()
            .map(|(ordinal, &origin)| {
                let lane = (snapshot[2 + usize::from(origin)].arg0() >> 8) as u8;
                let mut bytes = [0; 16];
                bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
                bytes[4..6].copy_from_slice(&tap::ENDPOINT_SEND.to_be_bytes());
                bytes[6..8].copy_from_slice(&(7u16 << 8 | 1).to_be_bytes());
                bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
                bytes[12..].copy_from_slice(
                    &(7u32 << 24 | u32::from(lane) << 16 | u32::from(origin)).to_be_bytes(),
                );
                tap::TapEvent::from(bytes)
            })
            .collect::<std::vec::Vec<_>>();
        let captures = [Capture::new(&records, Some(6)).unwrap()];
        let mut steps = [Unfold::Source; 16];
        let mut scratch = vec![0; 8 * steps.len() + 2 * 4];
        let count = seed(protocol, &captures, 1, &mut steps, &mut scratch).unwrap();
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps[..count])];
        let source = protocol.unfolding(&steps[..count], &mut proof).unwrap();
        let mut workspace = vec![0; source.path_workspace_len().unwrap()];
        let (actors, rest) = workspace.split_at_mut(source.event_count());
        let (parts, scratch) =
            rest.split_at_mut(Layout::path_index_words(source.event_count()).unwrap());
        source.index_source(parts, actors, scratch).unwrap();
        let mut arms = [true, false].into_iter();
        let path = source
            .select_by(
                |_, _, _| Ok(arms.next().unwrap()),
                |_, _| true,
                actors,
                parts,
                scratch,
            )
            .unwrap();
        let selected = (0..source.event_count())
            .filter(|&event| path.actors(event).is_some())
            .map(|event| source.origin(event).unwrap())
            .collect::<std::vec::Vec<_>>();
        assert_eq!(selected, expected);
    }

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
        let mut direct = [0; 5];
        assert_eq!(
            visits(
                &layout,
                protocol,
                body,
                &[3, 3, 2, 2, 100],
                1,
                &mut scratch,
                &mut direct
            ),
            (5, 5)
        );
        assert_eq!(
            visits(
                &layout,
                protocol,
                body,
                &[3, 3, 2, 2, 100],
                2,
                &mut scratch,
                &mut direct
            ),
            (3, 5)
        );
    }
}
