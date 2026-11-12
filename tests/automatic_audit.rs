use hibana::{
    g,
    runtime::{
        program::project,
        tap::{self, TapEvent},
    },
};
use hibana_epf::{
    Acceptance, AuditError, AuditStorage, Capture, ExecutionStorage, Protocol, RecordId,
    RouteChoice, Unfold,
};

fn local(ordinal: usize, source: u16, lane: u8) -> TapEvent {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
    bytes[4..6].copy_from_slice(&tap::ENDPOINT_SEND.to_be_bytes());
    bytes[6] = 7;
    bytes[7] = 1;
    bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
    bytes[12..]
        .copy_from_slice(&(7u32 << 24 | u32::from(lane) << 16 | u32::from(source)).to_be_bytes());
    bytes.into()
}

fn check(
    snapshot: &[TapEvent],
    records: &[TapEvent],
    capacity: usize,
) -> Result<usize, AuditError> {
    let mut source_storage = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut source_storage).unwrap();
    let captures = [Capture::new(records, Some(records.len() as u32)).unwrap()];
    let mut steps = vec![Unfold::Source; capacity];
    let mut choices = vec![
        RouteChoice {
            span: [0, 0],
            right: false
        };
        protocol.audit_choice_capacity(capacity).unwrap()
    ];
    let mut order = vec![
        RecordId {
            producer: usize::MAX,
            ordinal: usize::MAX
        };
        records.len()
    ];
    let mut occurrences = vec![None; records.len()];
    let mut acceptances = vec![
        Acceptance {
            first_poll: RecordId {
                producer: 0,
                ordinal: 0
            },
            before: 0
        };
        records.len()
    ];
    let mut scratch = std::vec![0; protocol.audit_workspace_len(&captures, capacity).unwrap()];
    let observed_producers = vec![0; records.len()];
    let audit = protocol.audit(
        &captures,
        AuditStorage {
            unfolding: &mut steps,
            choices: &mut choices,
            execution: ExecutionStorage {
                session: 1,
                observed_producers: &observed_producers,
                order: &mut order,
                occurrences: &mut occurrences,
                acceptances: &mut acceptances,
            },
        },
        &mut scratch,
    )?;
    Ok(audit.path().unfolding().event_count())
}

#[test]
fn nested_visits_are_not_averaged_over_unselected_enclosing_arms() {
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
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    let scope = |start| {
        snapshot
            .iter()
            .find(|row| {
                row.id() == tap::PROJECTED_SCOPE
                    && row.causal_key() >> 13 == 1
                    && row.arg1() & 3 == 0
                    && row.arg0() == start
            })
            .unwrap()
            .causal_key()
    };
    let reset = |ordinal: usize, scope: u16, origin: u16| {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
        bytes[4..6].copy_from_slice(&tap::SCOPE_REENTRY.to_be_bytes());
        bytes[6..8].copy_from_slice(&(7u16 << 8 | 7).to_be_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
        bytes[12..].copy_from_slice(&(u32::from(scope) << 16 | u32::from(origin)).to_be_bytes());
        TapEvent::from(bytes)
    };
    for repeats in 1..=3 {
        for revised_first in [false, true] {
            let revised = std::iter::repeat_n(1u16, repeats)
                .chain([2, 3])
                .collect::<Vec<_>>();
            let visits = if revised_first {
                [revised, vec![0, 3]]
            } else {
                [vec![0, 3], revised]
            };
            let mut records = Vec::new();
            for (visit, word) in visits.iter().enumerate() {
                if visit != 0 {
                    records.push(reset(records.len(), scope(0), word[0]));
                }
                for (index, &origin) in word.iter().enumerate() {
                    if origin == 1 && index != 0 {
                        records.push(reset(records.len(), scope(1), origin));
                    }
                    let lane = (snapshot[2 + usize::from(origin)].arg0() >> 8) as u8;
                    records.push(local(records.len(), origin, lane));
                }
            }
            check(&snapshot, &records, 32).unwrap();
        }
    }
}

#[test]
fn source_and_routes_are_constructed_without_a_second_global() {
    let global = g::seq(
        g::send::<7, 7, g::Msg<1, ()>>(),
        g::route(
            g::send::<7, 7, g::Msg<2, ()>>(),
            g::send::<7, 7, g::Msg<3, ()>>(),
        ),
    );
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    for selected in [1, 2] {
        let first_lane = (snapshot[2].arg0() >> 8) as u8;
        let selected_lane = (snapshot[2 + selected].arg0() >> 8) as u8;
        assert_eq!(
            check(
                &snapshot,
                &[
                    local(0, 0, first_lane),
                    local(1, selected as u16, selected_lane)
                ],
                1
            ),
            Ok(3)
        );
    }
}

#[test]
fn exhausted_search_never_certifies_a_duplicate_single_operation() {
    let global = g::send::<7, 7, g::Msg<1, ()>>();
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    let lane = (snapshot[2].arg0() >> 8) as u8;
    assert!(check(&snapshot, &[local(0, 0, lane)], 1).is_ok());
    assert!(matches!(
        check(&snapshot, &[local(0, 0, lane), local(1, 0, lane)], 5),
        Err(AuditError::Exhausted { .. })
    ));
}

#[test]
fn a_repeat_is_inferred_only_when_the_compiled_source_contains_a_roll() {
    let global = g::send::<7, 7, g::Msg<1, ()>>().roll();
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    let lane = (snapshot[2].arg0() >> 8) as u8;
    let scope = snapshot
        .iter()
        .find(|r| r.id() == tap::PROJECTED_SCOPE)
        .unwrap()
        .causal_key();
    let mut reentry: [u8; 16] = local(1, 0, lane).into();
    reentry[4..6].copy_from_slice(&tap::SCOPE_REENTRY.to_be_bytes());
    reentry[7] = 7;
    reentry[12..].copy_from_slice(&(u32::from(scope) << 16).to_be_bytes());
    let records = [local(0, 0, lane), reentry.into(), local(2, 0, lane)];
    assert!(matches!(
        check(&snapshot, &records, 1),
        Err(AuditError::Exhausted { .. })
    ));
    assert_eq!(check(&snapshot, &records, 3), Ok(2));
}

#[test]
fn a_retained_roll_can_resume_after_its_continuation_without_repeating_that_continuation() {
    let global = g::seq(
        g::send::<7, 7, g::Msg<1, ()>>().roll(),
        g::send::<7, 7, g::Msg<2, ()>>(),
    );
    let snapshot: Vec<_> = tap::projected(&project::<7>(&global)).collect();
    let lanes = [
        (snapshot[2].arg0() >> 8) as u8,
        (snapshot[3].arg0() >> 8) as u8,
    ];
    let scope = snapshot
        .iter()
        .find(|r| r.id() == tap::PROJECTED_SCOPE)
        .unwrap()
        .causal_key();
    let mut reentry: [u8; 16] = local(2, 0, lanes[0]).into();
    reentry[4..6].copy_from_slice(&tap::SCOPE_REENTRY.to_be_bytes());
    reentry[7] = 7;
    reentry[12..].copy_from_slice(&(u32::from(scope) << 16).to_be_bytes());
    assert_eq!(
        check(
            &snapshot,
            &[
                local(0, 0, lanes[0]),
                local(1, 1, lanes[1]),
                reentry.into(),
                local(3, 0, lanes[0])
            ],
            3
        ),
        Ok(3)
    );
}
