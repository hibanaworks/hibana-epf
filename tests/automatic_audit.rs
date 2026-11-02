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
    let mut scratch = vec![0; Protocol::workspace_len(snapshot).unwrap()];
    let protocol = Protocol::new(snapshot, &mut scratch).unwrap();
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
    scratch.resize(
        protocol.audit_workspace_len(&captures, capacity).unwrap(),
        0,
    );
    let audit = protocol.audit(
        &captures,
        AuditStorage {
            unfolding: &mut steps,
            choices: &mut choices,
            execution: ExecutionStorage {
                session: 1,
                order: &mut order,
                occurrences: &mut occurrences,
                acceptances: &mut acceptances,
            },
        },
        &mut scratch,
    )?;
    Ok(audit.path.unfolding().event_count())
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
