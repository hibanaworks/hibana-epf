use hibana::runtime::tap::TapEvent;
use hibana_epf::{Capture, CaptureError};

fn record(ordinal: u32) -> TapEvent {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&ordinal.to_be_bytes());
    bytes[4..6].copy_from_slice(&0x0202u16.to_be_bytes());
    bytes.into()
}

#[test]
fn checking_a_complete_prefix_borrows_the_original_records() {
    let records: Vec<_> = (0..6).map(record).collect();
    let capture = Capture::new(&records, Some(6)).unwrap();
    assert_eq!(capture.records(), records);
    assert_eq!(capture.records().as_ptr(), records.as_ptr());
    assert_eq!(
        core::mem::size_of::<Capture>(),
        core::mem::size_of::<&[TapEvent]>()
    );
    assert!(Capture::new(&[], Some(0)).unwrap().records().is_empty());
}

#[test]
fn deleting_any_record_including_the_last_is_incomplete() {
    let records: Vec<_> = (0..6).map(record).collect();
    for missing in 0..records.len() {
        let mut changed = records.clone();
        changed.remove(missing);
        assert_eq!(
            Capture::new(&changed, Some(6)).unwrap_err(),
            CaptureError::Length {
                expected: 6,
                actual: 5
            },
        );
    }
    assert_eq!(
        Capture::new(&records[..3], Some(6)).unwrap_err(),
        CaptureError::Length {
            expected: 6,
            actual: 3
        },
    );
    assert_eq!(
        Capture::new(&records, Some(3)).unwrap_err(),
        CaptureError::Length {
            expected: 3,
            actual: 6
        },
    );
}

#[test]
fn duplicate_reordered_and_saturated_ordinals_cannot_replace_missing_records() {
    let records: Vec<_> = (0..6).map(record).collect();
    for index in 0..records.len() {
        for other in 0..records.len() {
            if index == other {
                continue;
            }
            let mut changed = records.clone();
            changed[index] = records[other];
            assert_eq!(
                Capture::new(&changed, Some(6)).unwrap_err(),
                CaptureError::Ordinal {
                    index,
                    actual: other as u32
                },
            );
            changed = records.clone();
            changed.swap(index, other);
            assert!(matches!(
                Capture::new(&changed, Some(6)),
                Err(CaptureError::Ordinal { .. })
            ));
        }
        let mut changed = records.clone();
        changed[index] = record(u32::MAX);
        assert_eq!(
            Capture::new(&changed, Some(6)).unwrap_err(),
            CaptureError::Ordinal {
                index,
                actual: u32::MAX
            },
        );
    }
}

#[test]
fn counter_exhaustion_cannot_produce_a_checked_capture() {
    for checkpoint in [None, Some(u32::MAX)] {
        assert_eq!(
            Capture::new(&[], checkpoint).unwrap_err(),
            CaptureError::CounterExhausted
        );
    }
}
