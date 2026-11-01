use hibana::{
    Endpoint, g,
    runtime::{
        program::project,
        tap::{self, TapEvent},
    },
};
use hibana_epf::{Protocol, ProtocolError};

fn check_snapshot(snapshot: &[TapEvent]) {
    let mut workspace = vec![usize::MAX; Protocol::workspace_len(snapshot).unwrap()];
    let program = Protocol::new(snapshot, &mut workspace).unwrap();
    workspace.fill(usize::MAX);
    assert_eq!(program.records(), snapshot);
    assert_eq!(program.records().as_ptr(), snapshot.as_ptr());
}

fn word(event: TapEvent, offset: usize, value: u32) -> TapEvent {
    let mut bytes: [u8; 16] = event.into();
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    bytes.into()
}

#[test]
fn imported_sources_keep_parallel_choice_and_identically_bounded_nested_rolls() {
    let source = g::par(
        g::seq(
            g::send::<0, 1, g::Msg<1, ()>>(),
            g::send::<1, 0, g::Msg<2, ()>>(),
        ),
        g::route(
            g::send::<2, 3, g::Msg<3, ()>>(),
            g::send::<2, 3, g::Msg<4, ()>>(),
        )
        .resolve::<65535>(),
    )
    .roll()
    .roll();
    for snapshot in [
        tap::projected(&project::<0>(&source)).collect::<Vec<_>>(),
        tap::projected(&project::<1>(&source)).collect(),
        tap::projected(&project::<2>(&source)).collect(),
        tap::projected(&project::<3>(&source)).collect(),
    ] {
        check_snapshot(&snapshot);
    }
    let intrinsic = g::route(
        g::send::<0, 0, g::Msg<5, ()>>(),
        g::send::<0, 0, g::Msg<6, ()>>(),
    );
    check_snapshot(&tap::projected(&project::<0>(&intrinsic)).collect::<Vec<_>>());
}

#[test]
fn conditional_actor_references_and_full_range_ids_survive_import() {
    type Loan<'r> = g::Msg<1, Endpoint<'r, 255>>;
    let source = g::seq(
        g::send::<0, 1, Loan>(),
        g::seq(
            g::route(g::send::<1, 2, g::Msg<4, ()>>(), g::send::<1, 2, Loan>()).resolve::<65535>(),
            g::send::<255, 3, g::Msg<2, ()>>(),
        ),
    );
    for snapshot in [
        tap::projected(&project::<0>(&source)).collect::<Vec<_>>(),
        tap::projected(&project::<1>(&source)).collect(),
        tap::projected(&project::<2>(&source)).collect(),
        tap::projected(&project::<3>(&source)).collect(),
        tap::projected(&project::<255>(&source)).collect(),
    ] {
        assert!(
            snapshot
                .iter()
                .any(|row| row.id() == tap::PROJECTED_ACTOR_DECISION)
        );
        assert_eq!(
            snapshot
                .iter()
                .find(|row| row.id() == tap::PROJECTED_CHOICE)
                .unwrap()
                .arg1(),
            65536
        );
        check_snapshot(&snapshot);
    }
}

#[test]
fn all_257_reused_contract_occurrences_keep_their_complete_source_identity() {
    type Step = g::Msg<231, u32>;
    let source = g::send::<0, 1, Step>();
    let source = g::seq(source, source);
    let source = g::seq(source, source);
    let source = g::seq(source, source);
    let source = g::seq(source, source);
    let source = g::seq(source, source);
    let source = g::seq(source, source);
    let source = g::seq(source, source);
    let source = g::seq(source, source);
    let source = g::seq(source, g::send::<0, 1, Step>());
    for snapshot in [
        tap::projected(&project::<0>(&source)).collect::<Vec<_>>(),
        tap::projected(&project::<1>(&source)).collect(),
    ] {
        assert_eq!(snapshot[0].arg0() >> 16, 257);
        check_snapshot(&snapshot);
        let mut malformed = snapshot.clone();
        let index = malformed
            .iter()
            .position(|row| {
                matches!(row.id(), tap::PROJECTED_SEND | tap::PROJECTED_RECV)
                    && row.arg0() >> 16 == 256
            })
            .unwrap();
        malformed[index] = word(malformed[index], 8, malformed[index].arg0() & 0xffff);
        assert!(
            matches!(Protocol::new(&malformed, &mut vec![0; 2 * malformed.len()]),
            Err(ProtocolError::Record { index: rejected }) if rejected == index)
        );
    }
}

#[test]
fn an_imported_scope_cannot_span_both_parallel_children() {
    let source = g::par(
        g::seq(
            g::send::<0, 1, g::Msg<0, ()>>(),
            g::send::<0, 1, g::Msg<1, ()>>().roll(),
        ),
        g::send::<2, 3, g::Msg<2, ()>>(),
    );
    let mut snapshot = tap::projected(&project::<0>(&source)).collect::<Vec<_>>();
    check_snapshot(&snapshot);
    let positions = snapshot
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (row.id() == tap::PROJECTED_SCOPE).then_some(index))
        .collect::<Vec<_>>();
    let mut markers = positions
        .iter()
        .map(|&index| snapshot[index])
        .collect::<Vec<_>>();
    let exit = markers
        .iter_mut()
        .find(|row| row.causal_key() >> 13 == 1 && row.arg1() == 2)
        .unwrap();
    *exit = word(*exit, 8, 3);
    markers.sort_by_key(|row| row.arg0());
    for (ordinal, (index, row)) in positions.into_iter().zip(markers).enumerate() {
        snapshot[index] = word(row, 0, ordinal as u32);
    }
    assert!(matches!(
        Protocol::new(&snapshot, &mut vec![0; 2 * snapshot.len()]),
        Err(ProtocolError::Record { .. })
    ));
}

#[test]
fn two_resource_import_keeps_both_directions_between_views_of_one_actor() {
    type Notice = g::Msg<0, ()>;
    type Loan<'r> = g::Msg<1, Endpoint<'r, 3>>;
    type Proxy<'r> = g::Msg<2, Endpoint<'r, 2>>;
    type Work = g::Msg<3, ()>;
    type Returned<'r> = g::Msg<4, Endpoint<'r, 3>>;
    let source = g::seq(
        g::route(
            g::send::<0, 1, Notice>(),
            g::seq(g::send::<0, 1, Loan>(), g::send::<0, 1, Proxy>()),
        ),
        g::seq(g::send::<3, 0, Work>().roll(), g::send::<2, 0, Returned>()),
    );
    for snapshot in [
        tap::projected(&project::<0>(&source)).collect::<Vec<_>>(),
        tap::projected(&project::<1>(&source)).collect(),
        tap::projected(&project::<2>(&source)).collect(),
        tap::projected(&project::<3>(&source)).collect(),
    ] {
        assert_eq!(snapshot[0].arg1() & 65535, 2);
        check_snapshot(&snapshot);
    }
    let snapshot = tap::projected(&project::<0>(&source)).collect::<Vec<_>>();
    for direction in [tap::PROJECTED_SEND, tap::PROJECTED_RECV] {
        assert!(
            snapshot
                .iter()
                .any(|row| row.id() == direction && row.arg0() >> 16 == 3)
        );
    }
    for remove in [tap::PROJECTED_SEND, tap::PROJECTED_RECV] {
        let mut malformed = snapshot.clone();
        let index = malformed
            .iter()
            .position(|row| row.id() == remove && row.arg0() >> 16 == 3)
            .unwrap();
        malformed.remove(index);
        malformed[1] = word(malformed[1], 0, malformed[1].ts() - 1);
        let mut ordinal = 0;
        for row in &mut malformed {
            if matches!(
                row.id(),
                tap::PROJECTED_LOCAL | tap::PROJECTED_SEND | tap::PROJECTED_RECV
            ) {
                *row = word(*row, 0, ordinal);
                ordinal += 1;
            }
        }
        let mut workspace = vec![0; 2 * malformed.len()];
        assert!(
            matches!(
                Protocol::new(&malformed, &mut workspace),
                Err(ProtocolError::Record { .. })
            ),
            "one direction disappeared but the source binding still requires it"
        );
    }
}

#[test]
fn import_rejects_truncation_extra_records_and_insufficient_workspace() {
    let source = g::send::<0, 1, g::Msg<7, ()>>().roll().roll();
    let snapshot = tap::projected(&project::<0>(&source)).collect::<Vec<_>>();
    for length in 0..snapshot.len() {
        let mut workspace = vec![0; 2 * snapshot.len()];
        assert!(matches!(
            Protocol::new(&snapshot[..length], &mut workspace),
            Err(ProtocolError::Length { .. })
        ));
    }
    let mut extra = snapshot.clone();
    extra.push(snapshot[0]);
    assert!(matches!(
        Protocol::new(&extra, &mut vec![0; 2 * extra.len()]),
        Err(ProtocolError::Length { .. })
    ));
    assert_eq!(
        Protocol::new(&snapshot, &mut []).unwrap_err(),
        ProtocolError::Workspace {
            required: 8,
            actual: 0
        }
    );
    check_snapshot(&snapshot);
}

#[test]
fn nested_scopes_cannot_share_an_identity_or_cross_their_closing_markers() {
    let source = g::send::<0, 1, g::Msg<7, ()>>().roll().roll();
    let snapshot = tap::projected(&project::<0>(&source)).collect::<Vec<_>>();
    let markers = snapshot
        .iter()
        .enumerate()
        .filter_map(|(index, row)| (row.id() == tap::PROJECTED_SCOPE).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(markers.len(), 4);
    let outer = snapshot[markers[0]].causal_key();
    let inner = snapshot[markers[1]].causal_key();
    assert_ne!(outer, inner);
    let mut duplicated = snapshot.clone();
    for &index in &markers {
        duplicated[index] = word(
            duplicated[index],
            4,
            u32::from(tap::PROJECTED_SCOPE) << 16 | u32::from(outer),
        );
    }
    assert!(matches!(
        Protocol::new(&duplicated, &mut vec![0; 2 * duplicated.len()]),
        Err(ProtocolError::Record { .. })
    ));
    let mut crossed = snapshot.clone();
    crossed[markers[2]] = word(
        crossed[markers[2]],
        4,
        u32::from(tap::PROJECTED_SCOPE) << 16 | u32::from(outer),
    );
    crossed[markers[3]] = word(
        crossed[markers[3]],
        4,
        u32::from(tap::PROJECTED_SCOPE) << 16 | u32::from(inner),
    );
    assert!(matches!(
        Protocol::new(&crossed, &mut vec![0; 2 * crossed.len()]),
        Err(ProtocolError::Record { .. })
    ));
}

#[test]
fn malformed_section_fields_and_actor_references_cannot_publish_a_protocol() {
    type Loan<'r> = g::Msg<1, Endpoint<'r, 3>>;
    let source = g::seq(
        g::send::<0, 1, Loan>(),
        g::seq(
            g::route(g::send::<1, 2, g::Msg<4, ()>>(), g::send::<1, 2, Loan>()).resolve::<17>(),
            g::send::<3, 0, g::Msg<2, ()>>(),
        ),
    );
    let snapshot = tap::projected(&project::<1>(&source)).collect::<Vec<_>>();
    for (id, offset, value) in [
        (tap::PROJECTED_SOURCE, 0, 65536),
        (tap::PROJECTED_SCOPE, 12, 7),
        (tap::PROJECTED_CHOICE, 12, 65537),
        (tap::PROJECTED_BINDING, 8, 65535),
        (tap::PROJECTED_ACTOR_DECISION, 8, 256),
        (tap::PROJECTED_INITIAL_ACTOR, 12, 256),
        (tap::PROJECTED_RECV, 8, u32::MAX),
    ] {
        let mut malformed = snapshot.clone();
        let index = malformed.iter().position(|row| row.id() == id).unwrap();
        malformed[index] = word(malformed[index], offset, value);
        assert!(
            matches!(Protocol::new(&malformed, &mut vec![0; 2 * malformed.len()]), Err(ProtocolError::Record { index: rejected }) if rejected == index),
            "did not reject section record {index} for id {id}"
        );
    }
}
