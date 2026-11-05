//! Readiness of an uncommitted attempt against the committed source prefix.
use super::{PathError, SourcePath, SourcePoint};

impl SourcePath<'_, '_, '_> {
    pub(super) fn query_workspace_len(&self) -> Option<usize> {
        self.unfolding()
            .event_count()
            .checked_add(self.unfolding().path_workspace_len().ok()?)
    }

    /// A query may select an uncommitted arm, but cannot change the actors,
    /// presence or prerequisites of any operation that already committed.
    /// Search only constructs retrospective evidence; it never drives a view.
    pub(super) fn query_ready(
        &self,
        history: impl Clone + Iterator<Item = SourcePoint>,
        point: SourcePoint,
        actor: u8,
        workspace: &mut [usize],
    ) -> bool {
        let finish = match point {
            SourcePoint::Accepted(event) => SourcePoint::Sent(event),
            other => other,
        };
        // A different choice cannot undo publication or repeat a committed
        // point of this same unfolding. Reject before searching other paths.
        if history.clone().any(|prior| prior == finish) {
            return false;
        }
        let available = |path: &SourcePath<'_, '_, '_>| {
            path.point_actor(point) == Some(actor) && path.missing(history.clone(), point).is_none()
        };
        if available(self) {
            return true;
        }
        let source = self.unfolding();
        let (choices, storage) = workspace.split_at_mut(source.event_count());
        choices.fill(0);
        loop {
            let mut used = 0;
            let candidate =
                source.select_by(
                    |span, _, split| {
                        let mut forced = None;
                        for event in core::iter::once(point.event()).chain(
                            history.clone().filter_map(|prior| match prior {
                                SourcePoint::Accepted(_) => None,
                                _ => Some(prior.event()),
                            }),
                        ) {
                            if span[0] <= event && event < span[1] {
                                let right = event >= split;
                                if forced.is_some_and(|prior| prior != right) {
                                    return Err(PathError::Choice { index: used });
                                }
                                forced = Some(right);
                            }
                        }
                        let slot = &mut choices[used];
                        used += 1;
                        if let Some(right) = forced {
                            // Forced choices are not alternatives when backtracking.
                            *slot = 2 + usize::from(right);
                            Ok(right)
                        } else {
                            let preferred = self.selection(span).unwrap_or(false);
                            Ok(if *slot == 1 { !preferred } else { preferred })
                        }
                    },
                    storage,
                );
            if let Ok(path) = candidate {
                let compatible = history.clone().enumerate().all(|(index, prior)| {
                    if matches!(prior, SourcePoint::Accepted(_)) {
                        return true;
                    }
                    path.point_actor(prior) == self.point_actor(prior)
                        && path
                            .check_next(history.clone().take(index), prior, index)
                            .is_ok()
                });
                if compatible && available(&path) {
                    return true;
                }
            }
            let Some(index) = choices[..used].iter().rposition(|&choice| choice == 0) else {
                return false;
            };
            choices[index] = 1;
            choices[index + 1..].fill(0);
        }
    }
}
