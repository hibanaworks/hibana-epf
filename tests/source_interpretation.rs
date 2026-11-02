use hibana::{
    g,
    runtime::{
        program::project,
        tap::{self, TapEvent},
    },
};
use hibana_epf::{
    Acceptance, Capture, ExecutionStorage, ExecutionWitness, Protocol, RecordId, Unfold,
};

fn record(ordinal: usize, id: u16, view: u8, detail: u32) -> TapEvent {
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&(ordinal as u32).to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6] = 7;
    bytes[7] = view;
    bytes[8..12].copy_from_slice(&1u32.to_be_bytes());
    bytes[12..].copy_from_slice(&detail.to_be_bytes());
    bytes.into()
}

#[test]
fn finite_attribution_search_matches_enumeration_of_every_small_assignment() {
    let sequential = g::seq(
        g::send::<7, 7, g::Msg<1, ()>>(),
        g::send::<7, 7, g::Msg<2, ()>>(),
    )
    .roll();
    let parallel = g::par(
        g::send::<7, 7, g::Msg<1, ()>>(),
        g::send::<7, 7, g::Msg<2, ()>>(),
    )
    .roll();
    for (is_parallel, snapshot) in [
        (
            false,
            tap::projected(&project::<7>(&sequential)).collect::<Vec<_>>(),
        ),
        (
            true,
            tap::projected(&project::<7>(&parallel)).collect::<Vec<_>>(),
        ),
    ] {
        let scope = snapshot
            .iter()
            .find(|row| row.id() == tap::PROJECTED_SCOPE && row.causal_key() >> 13 == 1)
            .unwrap()
            .causal_key();
        let mut workspace = vec![0; Protocol::workspace_len(&snapshot).unwrap()];
        let protocol = Protocol::new(&snapshot, &mut workspace).unwrap();
        let steps = [
            Unfold::Message,
            Unfold::Message,
            if is_parallel {
                Unfold::Parallel([0, 1])
            } else {
                Unfold::Sequence([0, 1])
            },
            Unfold::Once(2),
            Unfold::More([3, 2]),
        ];
        let mut proof = vec![0; Protocol::unfolding_workspace_len(&steps)];
        let source = protocol.unfolding(&steps, &mut proof).unwrap();
        let mut rows = vec![0; source.path_workspace_len().unwrap()];
        let path = source.select(&[], &mut rows).unwrap();
        let mut successful = 0;
        for length in 0..=4 {
            for sequence in 0..1usize << length {
                let mut records = Vec::new();
                let mut seen = [false; 2];
                for position in 0..length {
                    let original = sequence >> position & 1;
                    if seen[original] {
                        records.push(record(
                            records.len(),
                            tap::SCOPE_REENTRY,
                            7,
                            u32::from(scope) << 16 | original as u32,
                        ));
                        seen.fill(false);
                    }
                    seen[original] = true;
                    let lane = (snapshot[2 + original].arg0() >> 8) as u8;
                    records.push(record(
                        records.len(),
                        tap::ENDPOINT_SEND,
                        1,
                        7 << 24 | u32::from(lane) << 16 | original as u32,
                    ));
                }
                // These are synthetic record fixtures with a declared full
                // checkpoint, not reports of actual Endpoint executions.
                let capture = Capture::new(&records, Some(records.len() as u32)).unwrap();
                let order: Vec<_> = (0..records.len())
                    .map(|ordinal| RecordId {
                        producer: 0,
                        ordinal,
                    })
                    .collect();
                workspace.resize(path.interpretation_workspace_len(&[capture]).unwrap(), 0);
                let mut expected = false;
                let mut assignments = vec![None; records.len()];
                for mut assignment in 0..4usize.pow(length as u32) {
                    let choices: Vec<_> = (0..length)
                        .map(|_| {
                            let event = assignment % 4;
                            assignment /= 4;
                            event
                        })
                        .collect();
                    let mut at = 0;
                    for (position, record) in records.iter().enumerate() {
                        assignments[position] = Some(choices[at]);
                        if record.id() == tap::ENDPOINT_SEND {
                            at += 1;
                        }
                    }
                    let witness = ExecutionWitness {
                        session: 1,
                        order: &order,
                        occurrences: &assignments,
                        acceptances: &[],
                    };
                    expected |= path
                        .check_execution(&[capture], &witness, &mut workspace)
                        .is_ok();
                }
                let mut occurrences = vec![None; records.len()];
                let mut acceptances: [Acceptance; 0] = [];
                let actual = path.interpret(
                    &[capture],
                    ExecutionStorage {
                        session: 1,
                        order: &order,
                        occurrences: &mut occurrences,
                        acceptances: &mut acceptances,
                    },
                    &mut workspace,
                );
                assert_eq!(
                    actual.is_ok(),
                    expected,
                    "par={is_parallel}, length={length}, sequence={sequence}"
                );
                if let Ok(witness) = actual {
                    path.check_execution(&[capture], &witness, &mut workspace)
                        .unwrap();
                    successful += 1;
                }
            }
        }
        assert_eq!(successful, if is_parallel { 13 } else { 5 });
    }
}
