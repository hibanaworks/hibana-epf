//! Read the compiled source used as input to execution-history checking.
use core::ops::Range;
use hibana::runtime::tap::{self, TapEvent};

mod history;
pub use history::{HistoryError, SendCall};

/// A complete, structurally checked snapshot from `tap::projected`.
///
/// This borrows the original records, including source structure and immutable
/// actor bindings. It holds no execution cursor or current resource owners.
/// Checking this input does not establish that an execution followed it.
#[derive(Clone, Copy, Debug)]
pub struct Protocol<'a> {
    records: &'a [TapEvent],
}

/// A malformed compiled snapshot or insufficient caller-supplied workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// The invalid record, or the position of the first missing local row.
    Record { index: usize },
    /// Section counts disagree with the supplied record count.
    Length { expected: usize, actual: usize },
    /// Workspace needs two words per scope marker and one bit per actor decision.
    Workspace { required: usize, actual: usize },
}

impl<'a> Protocol<'a> {
    /// Workspace words required by the snapshot's declared section sizes.
    /// This checks the headers and total length; `new` checks the section data.
    pub fn workspace_len(records: &[TapEvent]) -> Result<usize, ProtocolError> {
        let layout = Layout::read(records)?;
        Ok(2 * layout.scopes.len() + layout.actor_words())
    }

    /// Check a complete snapshot using temporary caller-owned workspace.
    ///
    /// Size `workspace` with `workspace_len`. Only the records remain borrowed
    /// after this call; the workspace may immediately be reused.
    ///
    /// The checks establish section boundaries, scope nesting, choice and actor
    /// references, initial issuance and the presence, direction and order of
    /// local rows. Actor bindings come from the compiled source; this does not
    /// independently prove their correspondence to the original Rust global.
    pub fn new(records: &'a [TapEvent], workspace: &mut [usize]) -> Result<Self, ProtocolError> {
        let layout = Layout::read(records)?;
        let required = 2 * layout.scopes.len() + layout.actor_words();
        if workspace.len() < required {
            return Err(ProtocolError::Workspace {
                required,
                actual: workspace.len(),
            });
        }
        let (markers, rest) = workspace[..required].split_at_mut(layout.scopes.len());
        let (groups, candidates) = rest.split_at_mut(layout.scopes.len());
        let choices = layout.check_scopes(records, markers, groups)?;
        layout.check_choices(records, markers, groups, choices)?;
        layout.check_issuance(records)?;
        layout.check_actors(records, markers, candidates)?;
        layout.check_rows(records, candidates)?;
        Ok(Self { records })
    }

    /// The original complete snapshot, without copying or rewriting its rows.
    pub const fn records(&self) -> &'a [TapEvent] {
        self.records
    }
}

struct Layout {
    sources: Range<usize>,
    scopes: Range<usize>,
    choices: Range<usize>,
    bindings: Range<usize>,
    decisions: Range<usize>,
    initial: Range<usize>,
    locals: Range<usize>,
    key: u16,
    max_role: u8,
}

struct Scope {
    start: u32,
    split: Option<u32>,
    end: u32,
    first: usize,
    last: usize,
}

fn scope(records: &[TapEvent], markers: &[usize], group: usize) -> Scope {
    // The grouping pass checked the exact marker count and tags for this kind.
    let first = markers[group];
    let entry = records[first];
    let kind = entry.causal_key() >> 13;
    let count = match kind {
        0 => 4,
        1 => 2,
        2 => 3,
        _ => unreachable!(),
    };
    let last = markers[group + count - 1];
    Scope {
        start: entry.arg0(),
        split: (kind != 1).then(|| records[markers[group + 1]].arg0()),
        end: records[last].arg0(),
        first,
        last,
    }
}

fn has_scope(records: &[TapEvent], markers: &[usize], key: u16) -> bool {
    markers
        .binary_search_by_key(&key, |&index| records[index].causal_key())
        .is_ok()
}

fn check(condition: bool, index: usize) -> Result<(), ProtocolError> {
    if condition {
        Ok(())
    } else {
        Err(ProtocolError::Record { index })
    }
}

impl Layout {
    fn actor_words(&self) -> usize {
        self.decisions.len().div_ceil(usize::BITS as usize)
    }

    fn read(records: &[TapEvent]) -> Result<Self, ProtocolError> {
        if records.len() < 2 {
            return Err(ProtocolError::Length {
                expected: 2,
                actual: records.len(),
            });
        }
        let program = records[0];
        let role = records[1];
        check(
            program.id() == tap::PROJECTED_PROGRAM && matches!(program.ts(), 1 | 0x1_0001),
            0,
        )?;
        check(
            role.id() == tap::PROJECTED_ROLE
                && role.causal_key() == program.causal_key()
                && role.ts() <= u32::from(u16::MAX)
                && role.arg0() <= u32::from(u16::MAX)
                && role.arg1() <= u32::from(u8::MAX),
            1,
        )?;
        let ownership = program.ts() == 0x1_0001;
        let events = (program.arg0() >> 16) as usize;
        let markers = (program.arg0() & 0xffff) as usize;
        let decisions = (program.arg1() >> 16) as usize;
        let initial = (program.arg1() & 0xffff) as usize;
        check(ownership || (decisions == 0 && initial == 0), 0)?;
        check(
            decisions + 256 <= usize::from(u16::MAX) && initial <= 256,
            0,
        )?;
        let mut end = 2;
        let mut section = |count| {
            let start = end;
            end += count;
            start..end
        };
        let sources = section(events);
        let scopes = section(markers);
        let choices = section(role.arg0() as usize);
        let bindings = section(if ownership { events } else { 0 });
        let decisions = section(decisions);
        let initial = section(initial);
        let locals = section(role.ts() as usize);
        if records.len() != end {
            return Err(ProtocolError::Length {
                expected: end,
                actual: records.len(),
            });
        }
        let key = program.causal_key();
        let max_role = role.arg1() as u8;
        check(
            (key >> 8) <= u16::from(max_role) && (key & 255) <= u16::from(max_role),
            0,
        )?;
        Ok(Self {
            sources,
            scopes,
            choices,
            bindings,
            decisions,
            initial,
            locals,
            key,
            max_role,
        })
    }

    fn check_scopes(
        &self,
        records: &[TapEvent],
        markers: &mut [usize],
        groups: &mut [usize],
    ) -> Result<usize, ProtocolError> {
        let mut boundary = 0;
        for (ordinal, index) in self.scopes.clone().enumerate() {
            let marker = records[index];
            let kind = marker.causal_key() >> 13;
            let tag = marker.arg1() & 3;
            check(
                marker.id() == tap::PROJECTED_SCOPE
                    && marker.ts() == ordinal as u32
                    && kind <= 2
                    && marker.arg1() <= 6
                    && tag <= 2
                    && marker.arg0() >= boundary
                    && marker.arg0() as usize <= self.sources.len(),
                index,
            )?;
            boundary = marker.arg0();
            markers[ordinal] = index;
        }
        // A right child's enter can precede its parent's parallel split at
        // the same boundary. Group by identity before checking interval nesting.
        markers.sort_unstable_by_key(|&index| (records[index].causal_key(), index));
        let (mut at, mut count, mut choices) = (0, 0, 0);
        while at < markers.len() {
            let first = records[markers[at]];
            let mut end = at + 1;
            while end < markers.len() && records[markers[end]].causal_key() == first.causal_key() {
                end += 1;
            }
            let group = &markers[at..end];
            let kind = first.causal_key() >> 13;
            let valid = match kind {
                0 if group.len() == 4 => {
                    let [a, b, c, d] = [
                        records[group[0]],
                        records[group[1]],
                        records[group[2]],
                        records[group[3]],
                    ];
                    a.arg1() & 3 == 0
                        && b.arg1() == 2
                        && c.arg1() == a.arg1()
                        && d.arg1() == 2
                        && a.arg0() < b.arg0()
                        && b.arg0() == c.arg0()
                        && c.arg0() < d.arg0()
                }
                1 if group.len() == 2 => {
                    first.arg1() == 0
                        && records[group[1]].arg1() == 2
                        && first.arg0() < records[group[1]].arg0()
                }
                2 if group.len() == 3 => {
                    first.arg1() == 0
                        && records[group[1]].arg1() == 1
                        && records[group[2]].arg1() == 2
                        && first.arg0() < records[group[1]].arg0()
                        && records[group[1]].arg0() < records[group[2]].arg0()
                }
                _ => false,
            };
            check(valid, markers[at])?;
            groups[count] = at;
            count += 1;
            choices += usize::from(kind == 0);
            at = end;
        }
        groups[..count].sort_unstable_by_key(|&group| {
            let range = scope(records, markers, group);
            (range.start, core::cmp::Reverse(range.end), range.first)
        });
        let mut depth = 0;
        for current in 0..count {
            let group = groups[current];
            let child = scope(records, markers, group);
            while depth != 0 {
                let parent = scope(records, markers, groups[groups.len() - depth]);
                if child.start >= parent.end {
                    depth -= 1;
                    continue;
                }
                check(
                    child.end <= parent.end
                        && child.first > parent.first
                        && child.last < parent.last
                        && parent
                            .split
                            .is_none_or(|split| child.end <= split || child.start >= split),
                    child.first,
                )?;
                break;
            }
            depth += 1;
            let slot = groups.len() - depth;
            groups[slot] = group;
        }
        Ok(choices)
    }

    fn check_choices(
        &self,
        records: &[TapEvent],
        markers: &[usize],
        keys: &mut [usize],
        count: usize,
    ) -> Result<(), ProtocolError> {
        check(count == self.choices.len(), 1)?;
        for (ordinal, index) in self.choices.clone().enumerate() {
            let row = records[index];
            check(
                row.id() == tap::PROJECTED_CHOICE
                    && row.ts() == ordinal as u32
                    && row.causal_key() >> 13 == 0
                    && has_scope(records, markers, row.causal_key())
                    && row.arg0() <= u32::from(self.max_role)
                    && row.arg1() <= 65536,
                index,
            )?;
            keys[ordinal] = usize::from(row.causal_key());
        }
        keys[..count].sort_unstable();
        check(
            keys[..count].windows(2).all(|pair| pair[0] < pair[1]),
            self.choices.start,
        )
    }

    fn check_issuance(&self, records: &[TapEvent]) -> Result<(), ProtocolError> {
        // The bitset covers the u8 logical-role domain, not current custody.
        let mut initial_roles = [0u64; 4];
        let mut resource_roles = [0u64; 4];
        let mut actor = self.key as u8;
        for (ordinal, index) in self.initial.clone().enumerate() {
            let row = records[index];
            check(
                row.id() == tap::PROJECTED_INITIAL_ACTOR
                    && row.ts() == ordinal as u32
                    && row.causal_key() == self.key
                    && row.arg0() <= u32::from(self.max_role)
                    && row.arg1() <= u32::from(self.max_role),
                index,
            )?;
            let role = row.arg0() as usize;
            let bit = 1u64 << (role % 64);
            check(initial_roles[role / 64] & bit == 0, index)?;
            initial_roles[role / 64] |= bit;
            if role == usize::from(self.key as u8) {
                actor = row.arg1() as u8;
            }
        }
        check(u16::from(actor) == self.key >> 8, 0)?;
        for (ordinal, index) in self.sources.clone().enumerate() {
            let row = records[index];
            let from = row.arg0() >> 24;
            let to = (row.arg0() >> 16) & 255;
            let payload = row.causal_key() >> 8;
            check(
                row.id() == tap::PROJECTED_SOURCE
                    && row.ts() == ordinal as u32
                    && row.causal_key() as u8 <= 1
                    && payload <= 1
                    && from <= u32::from(self.max_role)
                    && to <= u32::from(self.max_role),
                index,
            )?;
            if payload == 1 {
                check(
                    row.arg1() <= u32::from(self.max_role)
                        && row.arg1() != from
                        && row.arg1() != to,
                    index,
                )?;
                let role = row.arg1() as usize;
                resource_roles[role / 64] |= 1 << (role % 64);
            }
        }
        check(initial_roles == resource_roles, 0)
    }

    fn check_actors(
        &self,
        records: &[TapEvent],
        markers: &[usize],
        candidates: &mut [usize],
    ) -> Result<(), ProtocolError> {
        let actor = self.key >> 8;
        candidates.fill(0);
        let valid = |reference: u32, before: usize| {
            if reference < 256 {
                reference <= u32::from(self.max_role)
            } else {
                reference < before as u32 && reference != u32::from(u16::MAX)
            }
        };
        for (ordinal, index) in self.decisions.clone().enumerate() {
            let row = records[index];
            let reference = 256 + ordinal;
            check(
                row.id() == tap::PROJECTED_ACTOR_DECISION
                    && row.ts() == reference as u32
                    && row.causal_key() >> 13 == 0
                    && has_scope(records, markers, row.causal_key())
                    && valid(row.arg0(), reference)
                    && valid(row.arg1(), reference),
                index,
            )?;
            let belongs = contains_actor(row.arg0(), actor, candidates)
                || contains_actor(row.arg1(), actor, candidates);
            if belongs {
                candidates[ordinal / usize::BITS as usize] |= 1 << (ordinal % usize::BITS as usize);
            }
        }
        for (ordinal, index) in self.bindings.clone().enumerate() {
            let row = records[index];
            check(
                row.id() == tap::PROJECTED_BINDING
                    && row.ts() == ordinal as u32
                    && row.causal_key() == self.key
                    && valid(row.arg0(), 256 + self.decisions.len())
                    && valid(row.arg1(), 256 + self.decisions.len()),
                index,
            )?;
        }
        Ok(())
    }

    fn check_rows(&self, records: &[TapEvent], candidates: &[usize]) -> Result<(), ProtocolError> {
        let mut local = self.locals.start;
        for (ordinal, index) in self.sources.clone().enumerate() {
            let source = records[index];
            let from = source.arg0() >> 24;
            let to = (source.arg0() >> 16) & 255;
            let (sender, receiver) = if self.bindings.is_empty() {
                (from, to)
            } else {
                let binding = records[self.bindings.start + ordinal];
                (binding.arg0(), binding.arg1())
            };
            let actor = self.key >> 8;
            let send = contains_actor(sender, actor, candidates);
            let recv = contains_actor(receiver, actor, candidates);
            if from == to {
                check(send == recv, index)?;
                if send {
                    self.check_local(records, &mut local, ordinal, source, tap::PROJECTED_LOCAL)?;
                }
            } else {
                if send {
                    self.check_local(records, &mut local, ordinal, source, tap::PROJECTED_SEND)?;
                }
                if recv {
                    self.check_local(records, &mut local, ordinal, source, tap::PROJECTED_RECV)?;
                }
            }
        }
        check(local == self.locals.end, local)
    }

    fn check_local(
        &self,
        records: &[TapEvent],
        local: &mut usize,
        event: usize,
        source: TapEvent,
        direction: u16,
    ) -> Result<(), ProtocolError> {
        check(*local < self.locals.end, *local)?;
        let row = records[*local];
        let payload = if source.causal_key() >> 8 == 1 {
            256 | source.arg1()
        } else {
            0
        };
        check(
            row.id() == direction
                && row.ts() == (*local - self.locals.start) as u32
                && row.causal_key() == self.key
                && row.arg0() == ((event as u32) << 16 | (source.arg0() & 0xffff))
                && row.arg1() == ((source.arg0() & 0xffff_0000) | payload),
            *local,
        )?;
        *local += 1;
        Ok(())
    }
}

fn contains_actor(reference: u32, actor: u16, candidates: &[usize]) -> bool {
    if reference < 256 {
        reference == u32::from(actor)
    } else {
        let index = reference as usize - 256;
        candidates[index / usize::BITS as usize] & (1 << (index % usize::BITS as usize)) != 0
    }
}
