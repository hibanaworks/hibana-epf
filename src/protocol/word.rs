//! Check occurrence words using source actor order and retained-body dependencies.
use super::{Layout, SourcePath};

// Query-local structural order, separate from choice and observation bits.
pub(super) const SOURCE_ORDER: usize = 64;

#[cfg(test)]
mod tests;

/// One point of a proposed source execution, indexed in its checked unfolding.
///
/// Acceptance, sender publication and receiver commit are separate points.
/// `Accepted` witnesses transport acceptance, not a `SEND_POLL` observation.
/// Correspondence to actual captures is a separate obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourcePoint {
    /// Transport accepted this wire-message occurrence.
    Accepted(usize),
    /// Its sender committed publication locally.
    Sent(usize),
    /// Its receiver validated the frame and committed receipt.
    Received(usize),
    /// One logical self-message, without a wire send/receive pair.
    Local(usize),
}

/// A finite source word violates the checked selected path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordError {
    /// A point is outside the path or has the wrong operation direction.
    Point { index: usize },
    /// This exact occurrence point was already executed.
    Duplicate { index: usize, earlier: usize },
    /// A required source or resumption predecessor has not committed.
    Predecessor { index: usize, prior: SourcePoint },
}

impl SourcePoint {
    pub(super) fn event(self) -> usize {
        match self {
            Self::Accepted(event)
            | Self::Sent(event)
            | Self::Received(event)
            | Self::Local(event) => event,
        }
    }

    // Low two bits belong to temporary choice domains in readiness queries.
    pub(super) fn bit(self) -> usize {
        match self {
            Self::Accepted(_) => 4,
            Self::Sent(_) => 8,
            Self::Received(_) => 16,
            Self::Local(_) => 32,
        }
    }

    // Necessary prefix conditions only. Full source readiness is checked
    // separately, including actor bindings, choices and retained visits.
    pub(super) fn query_preconditions(self, contains: impl Fn(Self) -> bool) -> bool {
        let finish = match self {
            Self::Accepted(event) => Self::Sent(event),
            other => other,
        };
        !contains(finish)
            && match self {
                Self::Sent(event) | Self::Received(event) => contains(Self::Accepted(event)),
                _ => true,
            }
    }
}

impl SourcePath<'_, '_, '_> {
    /// Check every prefix of a finite source execution from empty.
    ///
    /// Checks actor-local source order, acceptance before both wire halves,
    /// uniqueness and outgoing-continuation prerequisites activated by this
    /// actor's committed resumed body. An old incoming continuation acquires
    /// no new outgoing prerequisite.
    ///
    /// This checks a source word, not runtime-record provenance. Physical
    /// acceptance and application effects cannot be inferred from a supplied
    /// word. Capture correspondence must establish those boundaries as well.
    pub fn check_word(&self, word: &[SourcePoint]) -> Result<(), WordError> {
        for (index, &point) in word.iter().enumerate() {
            let prefix = &word[..index];
            self.check_next(prefix.iter().copied(), (point, index), |prior| {
                prefix.contains(&prior)
            })?;
        }
        Ok(())
    }

    pub(super) fn check_next(
        &self,
        history: impl Clone + Iterator<Item = SourcePoint>,
        (point, index): (SourcePoint, usize),
        contains: impl Fn(SourcePoint) -> bool,
    ) -> Result<(), WordError> {
        if self.point_actor(point).is_none() {
            return Err(WordError::Point { index });
        }
        if let Some(earlier) = history.clone().position(|prior| prior == point) {
            return Err(WordError::Duplicate { index, earlier });
        }
        if let Some(prior) = self.missing(history, point, contains) {
            return Err(WordError::Predecessor { index, prior });
        }
        Ok(())
    }

    // A readiness query does not append a source point. In particular, another
    // poll of an already accepted send checks admission without duplicating it.
    pub(super) fn missing(
        &self,
        history: impl Clone + Iterator<Item = SourcePoint>,
        point: SourcePoint,
        contains: impl Fn(SourcePoint) -> bool,
    ) -> Option<SourcePoint> {
        self.missing_with(point, contains, self.prerequisite(history, point))
    }

    pub(super) fn missing_with(
        &self,
        point: SourcePoint,
        contains: impl Fn(SourcePoint) -> bool,
        required: impl Fn(SourcePoint, u8) -> bool,
    ) -> Option<SourcePoint> {
        if let SourcePoint::Sent(event) | SourcePoint::Received(event) = point
            && !contains(SourcePoint::Accepted(event))
        {
            return Some(SourcePoint::Accepted(event));
        }
        // Publication depends only on the already checked acceptance. Source
        // and resumed-body prerequisites belong to that acceptance, not to
        // another scan of every event when its sender publishes.
        if matches!(point, SourcePoint::Sent(_)) {
            return None;
        }
        let target_actor = self.point_actor(point);
        // Both source order and resumption prerequisites point forward in
        // this expansion. Keep the target itself for the send/receive pair.
        let end = self
            .unfolding()
            .event_count()
            .min(point.event().saturating_add(1));
        for event in 0..end {
            // Most source rows belong to other physical participants. Their
            // indexed actors suffice to skip all direction/header decoding.
            if !self
                .actors(event)
                .is_some_and(|actors| actors.into_iter().any(|actor| Some(actor) == target_actor))
            {
                continue;
            }
            for prior in [
                SourcePoint::Local(event),
                SourcePoint::Sent(event),
                SourcePoint::Received(event),
            ] {
                let Some(actor) = self.point_actor(prior) else {
                    continue;
                };
                if Some(actor) != target_actor || contains(prior) {
                    continue;
                }
                if required(prior, actor) {
                    return Some(prior);
                }
            }
        }
        None
    }

    // The same prerequisite predicate is used by complete-path checking and
    // partial-choice search. Its resumption inputs are committed history,
    // whose actors every compatible alternative must preserve.
    pub(super) fn prerequisite(
        &self,
        history: impl Clone + Iterator<Item = SourcePoint>,
        point: SourcePoint,
    ) -> impl Fn(SourcePoint, u8) -> bool {
        let required = self.prerequisite_ordered(history, point);
        move |prior, actor| {
            let ordered = !matches!(point, SourcePoint::Sent(_))
                && prior.event() != point.event()
                && self.source_before(prior.event(), point.event());
            required(prior, actor, ordered)
        }
    }

    pub(super) fn prerequisite_ordered(
        &self,
        history: impl Clone + Iterator<Item = SourcePoint>,
        point: SourcePoint,
    ) -> impl Fn(SourcePoint, u8, bool) -> bool {
        let source = self.unfolding();
        let can_resume =
            matches!(point, SourcePoint::Accepted(_)) && source.resumption_target(point.event());
        move |prior, actor, source_before| {
            let ordered = match point {
                SourcePoint::Sent(_) => false,
                _ if prior.event() == point.event() => matches!(
                    (prior, point),
                    (SourcePoint::Sent(_), SourcePoint::Received(_))
                ),
                _ => source_before,
            };
            ordered
                || can_resume
                    && prior.event() < point.event()
                    && history.clone().any(|entry| {
                        !matches!(entry, SourcePoint::Accepted(_))
                            && self.point_actor(entry) == Some(actor)
                            && source.same_resumption(prior.event(), point.event(), entry.event())
                    })
        }
    }

    // For a fixed target, the nearest boundary at or after `first` whose
    // subtree contains the target is their lowest common ancestor. Sweep
    // backwards once instead of climbing the same parent chain per pair.
    // All paths of this unfolding share this immutable structural relation.
    pub(super) fn mark_source_before(&self, target: usize, rows: &mut [usize]) {
        let mut ordered = false;
        for first in (0..rows.len()).rev() {
            if first >= target {
                ordered = false;
            } else if target < self.index[3 * first + 1] {
                ordered = self.index[3 * first + 2] == 0;
            }
            rows[first] = (rows[first] & !SOURCE_ORDER) | if ordered { SOURCE_ORDER } else { 0 };
        }
    }

    // Transpose of the same relation. Ancestors extend the covered suffix in
    // disjoint intervals; each interval inherits its first containing node's
    // sequence/par/route kind. Used before the backwards query sweep so both
    // directions share one temporary bit in the existing observation words.
    pub(super) fn mark_source_after(&self, target: usize, rows: &mut [usize]) {
        for row in rows.iter_mut() {
            *row &= !SOURCE_ORDER;
        }
        let mut start = target + 1;
        if start == rows.len() {
            return;
        }
        let mut boundary = target;
        loop {
            let row = &self.index[3 * boundary..3 * boundary + 3];
            if row[2] == 0 {
                for point in &mut rows[start..row[1]] {
                    *point |= SOURCE_ORDER;
                }
            }
            start = row[1];
            if row[0] == usize::MAX {
                return;
            }
            boundary = row[0];
        }
    }

    // Boundary `first` separates leaves first and first + 1. Its first
    // ancestor whose end contains `second` is their lowest common ancestor;
    // only a sequence boundary contributes source order across its children.
    pub(super) fn source_before(&self, first: usize, second: usize) -> bool {
        if first >= second || second >= self.unfolding().event_count() {
            return false;
        }
        let mut boundary = first;
        loop {
            let row = &self.index[3 * boundary..3 * boundary + 3];
            if second < row[1] {
                return row[2] == 0;
            }
            boundary = row[0];
        }
    }

    // A predecessor can be omitted only by a choice below the leaves' common
    // ancestor. Such a choice must retain its arm when that arm already has
    // a committed point. The caller supplies exact prefix membership; the
    // current selection alone is never evidence that an arm is forced.
    pub(super) fn unavoidable_before(
        &self,
        first: usize,
        second: usize,
        committed: impl Fn([usize; 2]) -> bool,
    ) -> bool {
        if first >= second || second >= self.unfolding().event_count() {
            return false;
        }
        // A leaf's parent is one of its adjacent boundaries. The left one is
        // its direct parent precisely when that subtree ends after this leaf.
        let mut boundary = if first > 0 && self.index[3 * (first - 1) + 1] == first + 1 {
            first - 1
        } else {
            first
        };
        loop {
            let row = &self.index[3 * boundary..3 * boundary + 3];
            if second < row[1] {
                return row[2] == 0;
            }
            if row[2] >= 2 {
                let span = if first > boundary {
                    [boundary + 1, row[1]]
                } else {
                    let mut ancestor = boundary;
                    let mut start = 0;
                    loop {
                        let parent = self.index[3 * ancestor];
                        if parent == usize::MAX {
                            break;
                        }
                        if ancestor > parent {
                            start = parent + 1;
                            break;
                        }
                        ancestor = parent;
                    }
                    [start, boundary + 1]
                };
                if !committed(span) {
                    return false;
                }
            }
            boundary = row[0];
        }
    }

    pub(super) fn point_actor(&self, point: SourcePoint) -> Option<u8> {
        let (side, _) = self.point_binding(point)?;
        Some(self.actors(point.event())?[side])
    }

    // Direction is fixed by the logical source message, independently of the
    // selected arm or current holder. A terminal binding is likewise constant.
    pub(super) fn point_binding(&self, point: SourcePoint) -> Option<(usize, u32)> {
        let event = point.event();
        let source = self.unfolding();
        let protocol = source.protocol();
        let layout = Layout::checked(protocol);
        let origin = usize::from(self.origin(event)?);
        let row = protocol.records[layout.sources.start + origin];
        let local = row.arg0() >> 24 == (row.arg0() >> 16) & 255;
        let side = match point {
            SourcePoint::Local(_) if local => 0,
            SourcePoint::Accepted(_) | SourcePoint::Sent(_) if !local => 0,
            SourcePoint::Received(_) if !local => 1,
            _ => return None,
        };
        let binding = if layout.bindings.is_empty() {
            if side == 0 {
                row.arg0() >> 24
            } else {
                (row.arg0() >> 16) & 255
            }
        } else {
            let row = protocol.records[layout.bindings.start + origin];
            if side == 0 { row.arg0() } else { row.arg1() }
        };
        Some((side, binding))
    }
}
