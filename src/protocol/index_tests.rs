extern crate std;

use super::*;
use hibana::{g, runtime::program::project};
use std::{collections::BTreeSet, vec, vec::Vec};

fn scanned_scope(records: &[TapEvent], range: Range<usize>, key: u16) -> Option<Scope> {
    let mut first = None;
    let mut split = None;
    let mut last = None;
    for index in range {
        let row = records[index];
        if row.causal_key() != key {
            continue;
        }
        if key >> 13 == 0 && first.is_some() && split.is_none() {
            split = Some(row.arg0());
        }
        first.get_or_insert(index);
        if row.arg1() & 3 == 1 {
            split = Some(row.arg0());
        }
        last = Some(index);
    }
    let first = first?;
    let last = last?;
    Some(Scope {
        start: records[first].arg0(),
        split,
        end: records[last].arg0(),
        first,
        last,
    })
}

#[test]
fn retained_scope_index_matches_exhaustive_marker_lookup() {
    let source = g::par(
        g::route(
            g::send::<0, 0, g::Msg<1, ()>>(),
            g::send::<0, 0, g::Msg<2, ()>>(),
        )
        .roll()
        .roll(),
        g::seq(
            g::send::<0, 0, g::Msg<3, ()>>(),
            g::send::<0, 0, g::Msg<4, ()>>().roll(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&source)).collect();
    let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
    let layout = Layout::checked(protocol);
    let mut keys = BTreeSet::from([0, 0x1fff, 0x2000, 0x3fff, 0x4000, 0x5fff, 0x6000, u16::MAX]);
    for row in &snapshot[layout.scopes.clone()] {
        let key = row.causal_key();
        keys.insert(key);
        keys.extend(key.checked_sub(1));
        keys.extend(key.checked_add(1));
    }
    let fields = |value: Option<Scope>| value.map(|s| (s.start, s.split, s.end, s.first, s.last));
    for key in keys {
        assert_eq!(
            fields(protocol.scope(key)),
            fields(scanned_scope(&snapshot, layout.scopes.clone(), key)),
            "scope {key}"
        );
    }
}
