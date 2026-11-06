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

#[test]
fn prepared_custody_matches_fresh_for_every_prefix_and_rewind() {
    let source = g::seq(
        g::send::<0, 1, g::Msg<1, ()>>(),
        g::send::<0, 1, g::Msg<2, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&source)).collect();
    let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
    let record = |ordinal: u32, kind: u16, (key, detail): (u16, u32)| {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&ordinal.to_be_bytes());
        bytes[4..6].copy_from_slice(&kind.to_be_bytes());
        bytes[6..8].copy_from_slice(&key.to_be_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..].copy_from_slice(&detail.to_be_bytes());
        TapEvent::from(bytes)
    };
    let sender = [
        record(0, tap::SEND_POLL, (0, 0xffff_0000)),
        record(1, tap::ENDPOINT_SEND, (1, 0)),
        record(2, tap::SEND_POLL, (0, 0xffff_0001)),
        record(3, tap::ENDPOINT_SEND, (1, 1)),
    ];
    let receiver = [
        record(0, tap::ENDPOINT_RECV, (0x102, 1 << 24)),
        record(1, tap::ENDPOINT_RECV, (0x102, 1 << 24 | 1)),
    ];
    let captures = [
        crate::Capture::new(&sender, Some(4)).unwrap(),
        crate::Capture::new(&receiver, Some(2)).unwrap(),
    ];
    let size = protocol.custody_workspace_len(&captures);
    let mut cached = vec![usize::MAX; size];
    let mut fresh = vec![usize::MAX; size];
    protocol.prepare_custody(&captures, &mut cached).unwrap();
    let mut legal = 0;
    let mut rejected = 0;
    // All fifteen producer-preserving interleavings, including unmatched
    // receives. Rewind through their prefixes as well as extending them.
    for mask in 0u8..64 {
        if mask.count_ones() != 2 {
            continue;
        }
        let mut taken = [0; 2];
        let order: Vec<_> = (0..6)
            .map(|position| {
                let producer = usize::from(mask >> position & 1);
                let id = RecordId {
                    producer,
                    ordinal: taken[producer],
                };
                taken[producer] += 1;
                id
            })
            .collect();
        for cut in (0..=6).chain((0..6).rev()) {
            fresh.fill(usize::MAX);
            let prepared = protocol.prepared_custody_prefix(&captures, &order[..cut], &mut cached);
            let original = protocol.custody_prefix(&captures, &order[..cut], &mut fresh);
            match (prepared, original) {
                (Ok(prepared), Ok(original)) => {
                    legal += 1;
                    for (producer, capture) in captures.iter().enumerate() {
                        for ordinal in 0..capture.records().len() {
                            let id = RecordId { producer, ordinal };
                            assert_eq!(prepared.root(id), original.root(id));
                            assert_eq!(prepared.rank(id), original.rank(id));
                            assert_eq!(prepared.root_rank(id), original.root_rank(id));
                        }
                    }
                }
                (Err(prepared), Err(original)) => {
                    rejected += 1;
                    assert_eq!(prepared, original);
                }
                _ => panic!("prepared custody changed prefix {cut} of {mask:06b}"),
            }
        }
    }
    assert!(legal > 0 && rejected > 0);
}

#[test]
fn indexed_fifo_matches_direct_pairing_across_all_producer_interleavings() {
    let source = g::seq(
        g::send::<0, 1, g::Msg<1, ()>>().roll(),
        g::send::<0, 1, g::Msg<2, ()>>().roll(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<0>(&source)).collect();
    let mut storage = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
    let protocol = Protocol::new(&snapshot, &mut storage).unwrap();
    let record = |ordinal: u32, kind: u16, session: u32, origin: u16| {
        let sending = kind != tap::ENDPOINT_RECV;
        let key: u16 = if sending {
            u16::from(kind == tap::ENDPOINT_SEND)
        } else {
            0x102
        };
        let detail = u32::from(origin)
            | if kind == tap::SEND_POLL {
                0xffff_0000
            } else if sending {
                0
            } else {
                1 << 24
            };
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&ordinal.to_be_bytes());
        bytes[4..6].copy_from_slice(&kind.to_be_bytes());
        bytes[6..8].copy_from_slice(&key.to_be_bytes());
        bytes[8..12].copy_from_slice(&session.to_be_bytes());
        bytes[12..].copy_from_slice(&detail.to_be_bytes());
        TapEvent::from(bytes)
    };
    for second in [(1, 0), (2, 0), (1, 1)] {
        let first_sender = [
            record(0, tap::SEND_POLL, 1, 0),
            record(1, tap::ENDPOINT_SEND, 1, 0),
        ];
        let second_sender = [
            record(0, tap::SEND_POLL, second.0, second.1),
            record(1, tap::ENDPOINT_SEND, second.0, second.1),
        ];
        let receiver = [
            record(0, tap::ENDPOINT_RECV, 1, 0),
            record(1, tap::ENDPOINT_RECV, second.0, second.1),
        ];
        let captures = [
            crate::Capture::new(&first_sender, Some(2)).unwrap(),
            crate::Capture::new(&second_sender, Some(2)).unwrap(),
            crate::Capture::new(&receiver, Some(2)).unwrap(),
        ];
        let mut workspace = vec![usize::MAX; protocol.custody_workspace_len(&captures)];
        protocol.prepare_custody(&captures, &mut workspace).unwrap();
        let mut interleavings = 0;
        for mut encoded in 0..3usize.pow(6) {
            let mut taken = [0; 3];
            let order: Vec<_> = (0..6)
                .map(|_| {
                    let producer = encoded % 3;
                    encoded /= 3;
                    let id = RecordId {
                        producer,
                        ordinal: taken[producer],
                    };
                    taken[producer] += 1;
                    id
                })
                .collect();
            if taken != [2; 3] {
                continue;
            }
            interleavings += 1;
            for cut in (0..=6).chain((0..6).rev()) {
                let prefix = &order[..cut];
                let observed = |id: RecordId| captures[id.producer].records()[id.ordinal];
                let mut used = [false; 2];
                let mut received = [None; 2];
                let mut missing = None;
                for (position, &id) in prefix.iter().enumerate().filter(|(_, id)| id.producer == 2)
                {
                    let target = observed(id);
                    let sender = prefix[..position].iter().copied().find(|candidate| {
                        candidate.producer < 2
                            && candidate.ordinal == 0
                            && !used[candidate.producer]
                            && observed(*candidate).arg0() == target.arg0()
                            && observed(*candidate).arg1() as u16 == target.arg1() as u16
                    });
                    let Some(sender) = sender else {
                        missing = Some(id);
                        break;
                    };
                    used[sender.producer] = true;
                    received[id.ordinal] = Some(2 * sender.producer);
                }
                match (
                    protocol.prepared_custody_prefix(&captures, prefix, &mut workspace),
                    missing,
                ) {
                    (Err(CustodyError::Unmatched { receive }), Some(expected)) => {
                        assert_eq!(receive, expected)
                    }
                    (Ok(links), None) => {
                        for (ordinal, expected) in received.into_iter().enumerate() {
                            assert_eq!(
                                links.root(RecordId {
                                    producer: 2,
                                    ordinal
                                }),
                                expected
                            );
                        }
                    }
                    _ => panic!("FIFO pairing differs for prefix {prefix:?}"),
                }
            }
        }
        assert_eq!(interleavings, 90);
    }
}
