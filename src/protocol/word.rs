//! Check occurrence words using source actor order and retained-body dependencies.
use super::{Layout, SourcePath};

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
            let history = &word[..index];
            if self.point_actor(point).is_none() {
                return Err(WordError::Point { index });
            }
            if let Some(earlier) = history.iter().position(|&prior| prior == point) {
                return Err(WordError::Duplicate { index, earlier });
            }
            if let SourcePoint::Sent(event) | SourcePoint::Received(event) = point
                && !history.contains(&SourcePoint::Accepted(event))
            {
                return Err(WordError::Predecessor {
                    index,
                    prior: SourcePoint::Accepted(event),
                });
            }
            let source = self.unfolding();
            for event in 0..source.event_count() {
                for prior in [
                    SourcePoint::Local(event),
                    SourcePoint::Sent(event),
                    SourcePoint::Received(event),
                ] {
                    let Some(actor) = self.point_actor(prior) else {
                        continue;
                    };
                    if Some(actor) != self.point_actor(point) {
                        continue;
                    }
                    let ordered = match point {
                        SourcePoint::Sent(_) => false,
                        _ => {
                            if event == point.event() {
                                matches!(
                                    (prior, point),
                                    (SourcePoint::Sent(_), SourcePoint::Received(_))
                                )
                            } else {
                                source.before(event, point.event())
                            }
                        }
                    };
                    let resumption = matches!(point, SourcePoint::Accepted(_))
                        && history.iter().any(|&entry| {
                            !matches!(entry, SourcePoint::Accepted(_))
                                && self.point_actor(entry) == Some(actor)
                                && source.same_resumption(event, point.event(), entry.event())
                        });
                    if (ordered || resumption) && !history.contains(&prior) {
                        return Err(WordError::Predecessor { index, prior });
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn point_actor(&self, point: SourcePoint) -> Option<u8> {
        let event = point.event();
        let actors = self.actors(event)?;
        let source = self.unfolding();
        let protocol = source.protocol();
        let layout = Layout::checked(protocol);
        let row = protocol.records[layout.sources.start + usize::from(source.origin(event)?)];
        let local = row.arg0() >> 24 == (row.arg0() >> 16) & 255;
        match point {
            SourcePoint::Local(_) if local => Some(actors[0]),
            SourcePoint::Accepted(_) | SourcePoint::Sent(_) if !local => Some(actors[0]),
            SourcePoint::Received(_) if !local => Some(actors[1]),
            _ => None,
        }
    }
}
