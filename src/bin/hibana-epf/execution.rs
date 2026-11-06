//! Host codecs for the allocation-free source-execution checker.
use hibana::runtime::tap::TapEvent;
use hibana_epf::{
    Acceptance, Capture, ExecutionWitness, Protocol, RecordId, RouteChoice, Unfold, Unfolded,
};
use std::{
    fs,
    io::{self, Write},
};

pub(super) fn audit(args: Vec<String>) -> Result<(), String> {
    use hibana_epf::{AuditStorage, ExecutionStorage};
    if args.len() < 5 || !(args.len() - 3).is_multiple_of(2) {
        return Err("usage: hibana-epf audit PROTOCOL.bin SESSION DERIVATION_CAPACITY CAPTURE.bin CHECKPOINT [CAPTURE.bin CHECKPOINT ...]".into());
    }
    let compiled = records(&args[0])?;
    let session = args[1].parse::<u32>().map_err(|_| "invalid session")?;
    let capacity = args[2]
        .parse::<usize>()
        .map_err(|_| "invalid derivation capacity")?;
    let inputs = inputs(&args[3..])?;
    let captures = captures(&inputs)?;
    let mut source_storage =
        vec![0; Protocol::workspace_len(&compiled).map_err(|e| format!("protocol: {e:?}"))?];
    let protocol =
        Protocol::new(&compiled, &mut source_storage).map_err(|e| format!("protocol: {e:?}"))?;
    let count = captures.iter().map(|capture| capture.records().len()).sum();
    let mut unfolding = vec![Unfold::Source; capacity];
    let mut choices = vec![
        RouteChoice {
            span: [0, 0],
            right: false
        };
        protocol
            .audit_choice_capacity(capacity)
            .map_err(|e| format!("audit: {e:?}"))?
    ];
    let mut order = vec![
        RecordId {
            producer: 0,
            ordinal: 0
        };
        count
    ];
    let mut occurrences = vec![None; count];
    let mut acceptances = vec![
        Acceptance {
            first_poll: RecordId {
                producer: 0,
                ordinal: 0
            },
            before: 0
        };
        count
    ];
    let mut workspace = std::vec![0; protocol
            .audit_workspace_len(&captures, capacity)
            .map_err(|e| format!("audit: {e:?}"))?];
    let checked = protocol
        .audit(
            &captures,
            AuditStorage {
                unfolding: &mut unfolding,
                choices: &mut choices,
                execution: ExecutionStorage {
                    session,
                    order: &mut order,
                    occurrences: &mut occurrences,
                    acceptances: &mut acceptances,
                },
            },
            &mut workspace,
        )
        .map_err(|e| format!("no dynamic audit certificate: {e:?}"))?;
    write_execution(checked.path().unfolding(), checked.execution())
}

fn records(path: &str) -> Result<Vec<TapEvent>, String> {
    let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let (chunks, trailing) = bytes.as_chunks::<16>();
    if !trailing.is_empty() {
        return Err(format!("{path}: incomplete 16-byte record"));
    }
    Ok(chunks.iter().copied().map(TapEvent::from).collect())
}

fn inputs(args: &[String]) -> Result<Vec<(Vec<TapEvent>, u32)>, String> {
    args.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let checkpoint = pair[1].parse().map_err(|_| "invalid producer checkpoint")?;
            Ok((records(&pair[0])?, checkpoint))
        })
        .collect()
}

fn captures(inputs: &[(Vec<TapEvent>, u32)]) -> Result<Vec<Capture<'_>>, String> {
    inputs
        .iter()
        .map(|(records, checkpoint)| {
            Capture::new(records, Some(*checkpoint)).map_err(|e| format!("capture: {e:?}"))
        })
        .collect()
}

/// Check an untrusted, finite witness without searching for another one.
pub(super) fn check(args: Vec<String>) -> Result<(), String> {
    if args.len() < 4 || !(args.len() - 2).is_multiple_of(2) {
        return Err("usage: hibana-epf check PROTOCOL.bin WITNESS.bin CAPTURE.bin CHECKPOINT [CAPTURE.bin CHECKPOINT ...]".into());
    }
    let compiled = records(&args[0])?;
    let bytes = fs::read(&args[1]).map_err(|e| format!("{}: {e}", args[1]))?;
    let candidate = Candidate::decode(&bytes)?;
    let inputs = inputs(&args[2..])?;
    let captures = captures(&inputs)?;
    let mut protocol_storage =
        vec![0; Protocol::workspace_len(&compiled).map_err(|e| format!("protocol: {e:?}"))?];
    let protocol =
        Protocol::new(&compiled, &mut protocol_storage).map_err(|e| format!("protocol: {e:?}"))?;
    let mut unfolding_storage = vec![0; Protocol::unfolding_workspace_len(&candidate.unfolding)];
    let unfolding = protocol
        .unfolding(&candidate.unfolding, &mut unfolding_storage)
        .map_err(|e| format!("unfolding: {e:?}"))?;
    let mut path_storage = vec![
        0;
        unfolding
            .path_workspace_len()
            .map_err(|e| format!("path: {e:?}"))?
    ];
    let path = unfolding
        .select(&candidate.choices, &mut path_storage)
        .map_err(|e| format!("path: {e:?}"))?;
    let witness = ExecutionWitness {
        session: candidate.session,
        order: &candidate.order,
        occurrences: &candidate.occurrences,
        acceptances: &candidate.acceptances,
    };
    let mut workspace = vec![
        0;
        path.execution_workspace_len(&captures, &witness)
            .map_err(|e| format!("execution: {e:?}"))?
    ];
    path.check_execution(&captures, &witness, &mut workspace)
        .map_err(|e| format!("execution: {e:?}"))?;
    write_execution(unfolding, &witness)
}

// Big-endian host evidence format, version 1: magic, session:u32, four u64
// counts; then seven-u64 unfolding rows and three-u64 choice/order/acceptance
// rows. An absent occurrence is u64::MAX. Counts must exactly fit the file.
// This codec grants no authority; the library checks every proposed relation.
struct Candidate {
    session: u32,
    unfolding: Vec<Unfold>,
    choices: Vec<RouteChoice>,
    order: Vec<RecordId>,
    occurrences: Vec<Option<usize>>,
    acceptances: Vec<Acceptance>,
}

impl Candidate {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 44 || &bytes[..8] != b"HEPC\0\0\0\x01" {
            return Err("invalid execution-witness header".into());
        }
        let session = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let word = |offset| u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let number = |value| {
            usize::try_from(value).map_err(|_| "witness integer exceeds this target".to_owned())
        };
        let counts = [
            number(word(12))?,
            number(word(20))?,
            number(word(28))?,
            number(word(36))?,
        ];
        let length =
            counts
                .iter()
                .zip([56usize, 24, 24, 24])
                .try_fold(44usize, |total, (count, stride)| {
                    count
                        .checked_mul(stride)
                        .and_then(|size| total.checked_add(size))
                });
        if length != Some(bytes.len()) {
            return Err("witness counts do not match its complete byte length".into());
        }
        let mut offset = 44;
        let mut row = |width: usize| {
            let start = offset;
            offset += 8 * width;
            (start..offset).step_by(8).map(word).collect::<Vec<_>>()
        };
        let mut unfolding = Vec::with_capacity(counts[0]);
        for _ in 0..counts[0] {
            let values = row(7);
            let [tag, a, b, c, d, e, f] = values[..] else {
                unreachable!()
            };
            unfolding.push(match tag {
                0 if values[1..].iter().all(|&value| value == 0) => Unfold::Source,
                1..=6 if values[3..].iter().all(|&value| value == 0) => {
                    let children = [number(a)?, number(b)?];
                    match tag {
                        1 => Unfold::Sequence(children),
                        2 => Unfold::Parallel(children),
                        3 => Unfold::Choice(children),
                        4 if b == 0 => Unfold::Once(children[0]),
                        5 => Unfold::More(children),
                        6 => Unfold::Independent(children),
                        _ => return Err("invalid unfolding row".into()),
                    }
                }
                7..=9 => {
                    let retained = u16::try_from(a).map_err(|_| "invalid retained scope")?;
                    match tag {
                        7 if [d, e, f] == [0; 3] => Unfold::After {
                            retained,
                            earlier: number(b)?,
                            next: number(c)?,
                        },
                        8 => Unfold::Alongside {
                            retained,
                            earlier: number(b)?,
                            next: number(c)?,
                            tail: number(d)?,
                            focus: [number(e)?, number(f)?],
                        },
                        9 => Unfold::Before {
                            retained,
                            earlier: number(b)?,
                            next: number(c)?,
                            tail: number(d)?,
                            focus: [number(e)?, number(f)?],
                        },
                        _ => return Err("invalid unfolding row".into()),
                    }
                }
                _ => return Err("invalid unfolding row".into()),
            });
        }
        let mut choices = Vec::with_capacity(counts[1]);
        for _ in 0..counts[1] {
            let values = row(3);
            let right = match values[2] {
                0 => false,
                1 => true,
                _ => return Err("invalid choice arm".into()),
            };
            choices.push(RouteChoice {
                span: [number(values[0])?, number(values[1])?],
                right,
            });
        }
        let mut order = Vec::with_capacity(counts[2]);
        let mut occurrences = Vec::with_capacity(counts[2]);
        for _ in 0..counts[2] {
            let values = row(3);
            order.push(RecordId {
                producer: number(values[0])?,
                ordinal: number(values[1])?,
            });
            occurrences.push(if values[2] == u64::MAX {
                None
            } else {
                Some(number(values[2])?)
            });
        }
        let mut acceptances = Vec::with_capacity(counts[3]);
        for _ in 0..counts[3] {
            let values = row(3);
            acceptances.push(Acceptance {
                first_poll: RecordId {
                    producer: number(values[0])?,
                    ordinal: number(values[1])?,
                },
                before: number(values[2])?,
            });
        }
        Ok(Self {
            session,
            unfolding,
            choices,
            order,
            occurrences,
            acceptances,
        })
    }
}

fn write_execution(
    source: Unfolded<'_, '_>,
    execution: &ExecutionWitness<'_>,
) -> Result<(), String> {
    let session = execution.session;
    let mut output = io::BufWriter::new(io::stdout().lock());
    write!(output, "{{\"kind\":\"source_interpretation\",\"session\":{session},\"expanded_events\":{},\"order\":[", source.event_count()).map_err(|e| e.to_string())?;
    for (index, (id, occurrence)) in execution
        .order
        .iter()
        .zip(execution.occurrences)
        .enumerate()
    {
        if index != 0 {
            write!(output, ",").map_err(|e| e.to_string())?;
        }
        write!(
            output,
            "{{\"producer\":{},\"ordinal\":{},\"occurrence\":",
            id.producer, id.ordinal
        )
        .map_err(|e| e.to_string())?;
        if let Some(event) = occurrence {
            write!(
                output,
                "{event},\"source_event\":{}",
                source.origin(*event).unwrap()
            )
            .map_err(|e| e.to_string())?;
        } else {
            write!(output, "null,\"source_event\":null").map_err(|e| e.to_string())?;
        }
        write!(output, "}}").map_err(|e| e.to_string())?;
    }
    write!(output, "],\"acceptances\":[").map_err(|e| e.to_string())?;
    for (index, acceptance) in execution.acceptances.iter().enumerate() {
        if index != 0 {
            write!(output, ",").map_err(|e| e.to_string())?;
        }
        write!(
            output,
            "{{\"producer\":{},\"first_poll\":{},\"before\":{}}}",
            acceptance.first_poll.producer, acceptance.first_poll.ordinal, acceptance.before
        )
        .map_err(|e| e.to_string())?;
    }
    writeln!(output, "]}}").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}
