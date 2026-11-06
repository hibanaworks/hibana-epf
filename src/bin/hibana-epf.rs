use std::{
    env, fs,
    io::{self, Read, Write},
    process,
};

use hibana::runtime::tap::{
    TRANSPORT_FAULT, TRANSPORT_FAULT_CAPACITY, TRANSPORT_FAULT_DEADLINE, TRANSPORT_FAULT_FAILED,
    TRANSPORT_FAULT_OFFLINE, TRANSPORT_FRAME, TRANSPORT_MISMATCH, TRANSPORT_MISMATCH_LABEL,
    TRANSPORT_MISMATCH_LANE, TRANSPORT_MISMATCH_PEER_ROLE, TRANSPORT_MISMATCH_SESSION,
    TRANSPORT_MISMATCH_SOURCE_ROLE,
};
use hibana_epf::{
    CompactOutRecord, Epf, EpfStorage, ImageIngress, ImageSpec, Target, compute_hash,
};

#[path = "hibana-epf/execution.rs"]
mod execution;

const IMAGE_BYTES: usize = 4096;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        help();
        return Ok(());
    };
    match command.as_str() {
        "recipes" => {
            recipes();
            Ok(())
        }
        "image" => image_command(args.collect()),
        "wrap-image" => wrap_image(args.collect()),
        "explain-tap" => explain_tap(require_arg(&mut args, "explain-tap <tap-record-file|->")?),
        "explain-out" => explain_out(require_arg(&mut args, "explain-out <compact-out-file|->")?),
        "replay" => replay(args.collect(), ReplayInput::File),
        "stream" => replay(args.collect(), ReplayInput::Stdin),
        "diagnose" => diagnose(args.collect()),
        "audit" => execution::audit(args.collect()),
        "check" => execution::check(args.collect()),
        "help" | "--help" | "-h" => {
            help();
            Ok(())
        }
        other => Err(format!("unknown command: {other}")),
    }
}

fn image_command(args: Vec<String>) -> Result<(), String> {
    let (spec, consumed, _) = parse_recipe(&args)?;
    let options = ImageCommandOptions::parse(&args[consumed..])?;
    let image = build_image(spec)?;
    let bytes = if options.wrap {
        wrap_bytes(&image)?
    } else {
        image
    };
    write_bytes(options.out_path.as_deref(), &bytes)
}

fn wrap_image(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: hibana-epf wrap-image <epf-image-file|-> [-o output.hepf]".into());
    }
    let input = args[0].clone();
    let options = ImageCommandOptions::parse(&args[1..])?;
    let image = read_file_or_stdin(&input)?;
    let bytes = wrap_bytes(&image)?;
    write_bytes(options.out_path.as_deref(), &bytes)
}

fn diagnose(args: Vec<String>) -> Result<(), String> {
    let (spec, consumed, recipe_name) = parse_recipe(&args)?;
    let mut options = ReplayOptions::parse(&args[consumed..], ReplayInput::File)?;
    if options.image_path.is_some() || options.recipe.is_some() {
        return Err("diagnose takes its recipe before the input path".into());
    }
    options.recipe = Some(spec);
    let path = options.tap_path.as_deref().ok_or_else(|| {
        format!("usage: hibana-epf diagnose {recipe_name} [--out out.hepo] <trace.hbt|->")
    })?;
    run_tap_input(path, &options)
}

fn replay(args: Vec<String>, input: ReplayInput) -> Result<(), String> {
    let options = ReplayOptions::parse(&args, input)?;
    let path = match input {
        ReplayInput::File => options.tap_path.as_deref().ok_or_else(|| {
            "usage: hibana-epf replay [--recipe name|--image image.epf] [--out out.hepo] <trace.hbt|->".to_string()
        })?,
        ReplayInput::Stdin => "-",
    };
    run_tap_input(path, &options)
}

fn run_tap_input(path: &str, options: &ReplayOptions) -> Result<(), String> {
    if path == "-" {
        if options.image_path.as_deref() == Some("-") {
            return Err("image and tap records cannot both read stdin".into());
        }
        run_replay(io::stdin().lock(), options)
    } else {
        let file = fs::File::open(path).map_err(|error| format!("read {path}: {error}"))?;
        run_replay(file, options)
    }
}

fn run_replay(mut input: impl Read, options: &ReplayOptions) -> Result<(), String> {
    let mut storage = EpfStorage::<0, IMAGE_BYTES>::new();
    let epf = Epf::new(&mut storage);
    let image = match (options.recipe, options.image_path.as_deref()) {
        (Some(spec), None) => Some(build_image(spec)?),
        (None, Some(path)) => Some(read_file_or_stdin(path)?),
        (None, None) => None,
        (Some(_), Some(_)) => return Err("--image and --recipe are mutually exclusive".into()),
    };
    if let Some(image) = image {
        epf.load(&image).map_err(|error| match error {
            hibana_epf::Error::PolicySlotUnavailable { .. } =>
                "this command requires an observation image; install policy images with the application's resolver".to_string(),
            error => format!("load observation image: {error:?}"),
        })?;
    }
    let mut output = options
        .out_path
        .as_ref()
        .map(|path| fs::File::create_new(path).map_err(|error| format!("write {path}: {error}")))
        .transpose()?;
    let mut stdout = io::stdout().lock();
    let mut index = 0usize;
    loop {
        let mut bytes = [0u8; 16];
        match input.read(&mut bytes[..1]) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("read tap record #{index}: {error}")),
        }
        input
            .read_exact(&mut bytes[1..])
            .map_err(|error| format!("read tap record #{index} (expected 16 bytes): {error}"))?;
        let event = hibana::runtime::tap::TapEvent::from(bytes);
        let out = epf.run(event);
        if out.emitted() {
            let record = CompactOutRecord::from_out(options.site, out);
            if let Some(output) = output.as_mut() {
                let mut encoded = [0u8; CompactOutRecord::SIZE];
                record.encode(&mut encoded);
                output
                    .write_all(&encoded)
                    .map_err(|error| format!("write output: {error}"))?;
            }
            writeln!(
                stdout,
                "{} tap_ts={}",
                render_record(index, record),
                event.ts()
            )
            .and_then(|()| stdout.flush())
            .map_err(|error| format!("write stdout: {error}"))?;
        }
        index = index.checked_add(1).ok_or("tap record index exhausted")?;
    }
}

fn explain_tap(path: String) -> Result<(), String> {
    let bytes = read_file_or_stdin(&path)?;
    for (index, event) in decode_tap_stream(&bytes)?.into_iter().enumerate() {
        let evidence = event.evidence();
        let input = evidence.input();
        println!(
            "#{index} {} ts={} id=0x{:04x} causal=0x{:04x} kind=0x{:04x} reason={} input=[0x{:08x},0x{:08x},0x{:08x},0x{:08x}]",
            evidence_name(evidence.kind() as u32, evidence.reason() as u32),
            event.ts(),
            event.id(),
            event.causal_key(),
            evidence.kind(),
            evidence.reason(),
            input[0],
            input[1],
            input[2],
            input[3],
        );
    }
    Ok(())
}

fn explain_out(path: String) -> Result<(), String> {
    let bytes = read_file_or_stdin(&path)?;
    let (records, remainder) = bytes.as_chunks::<{ CompactOutRecord::SIZE }>();
    if !remainder.is_empty() {
        return Err(format!(
            "compact output length {} is not a multiple of {}",
            bytes.len(),
            CompactOutRecord::SIZE
        ));
    }
    for (index, chunk) in records.iter().enumerate() {
        let record = CompactOutRecord::decode(chunk)
            .map_err(|error| format!("decode out #{index}: {error:?}"))?;
        println!("{}", render_record(index, record));
    }
    Ok(())
}

fn parse_recipe(args: &[String]) -> Result<(ImageSpec, usize, &'static str), String> {
    let Some(name) = args.first().map(String::as_str) else {
        return Err("missing recipe name; run `hibana-epf recipes`".into());
    };
    match name {
        "echo" | "observe-echo" => Ok((ImageSpec::ObserveEcho, 1, "echo")),
        "session-mismatch" | "observe-session-mismatch" => {
            Ok((ImageSpec::ObserveSessionMismatch, 1, "session-mismatch"))
        }
        "deadline-fault" | "observe-deadline-fault" => {
            Ok((ImageSpec::ObserveDeadlineFault, 1, "deadline-fault"))
        }
        "capacity-fault" | "observe-capacity-fault" => {
            Ok((ImageSpec::ObserveCapacityFault, 1, "capacity-fault"))
        }
        "match" | "observe-match" => {
            require_len(args, 5, "image match <input> <value> <kind> <reason>")?;
            Ok((
                ImageSpec::ObserveMatch {
                    input: parse_u8(&args[1])?,
                    value: parse_u32(&args[2])?,
                    kind: parse_u32(&args[3])?,
                    reason: parse_u32(&args[4])?,
                },
                5,
                "match",
            ))
        }
        "policy-choose" => {
            require_len(args, 3, "image policy-choose <policy-id> <arm>")?;
            Ok((
                ImageSpec::PolicyChoose {
                    policy_id: parse_u16(&args[1])?,
                    arm: parse_u8(&args[2])?,
                },
                3,
                "policy-choose",
            ))
        }
        "policy-choose-on-input" => {
            require_len(
                args,
                5,
                "image policy-choose-on-input <policy-id> <input> <value> <arm>",
            )?;
            Ok((
                ImageSpec::PolicyChooseOnInput {
                    policy_id: parse_u16(&args[1])?,
                    input: parse_u8(&args[2])?,
                    value: parse_u32(&args[3])?,
                    arm: parse_u8(&args[4])?,
                },
                5,
                "policy-choose-on-input",
            ))
        }
        other => Err(format!("unknown recipe: {other}; run `hibana-epf recipes`")),
    }
}

fn build_image(spec: ImageSpec) -> Result<Vec<u8>, String> {
    let mut image = [0u8; IMAGE_BYTES];
    let len = spec
        .write(&mut image)
        .map_err(|error| format!("build image: {error:?}"))?;
    Ok(image[..len].to_vec())
}

fn wrap_bytes(image: &[u8]) -> Result<Vec<u8>, String> {
    if image.is_empty() || image.len() > u16::MAX as usize {
        return Err(format!(
            "image length {} is outside envelope bounds",
            image.len()
        ));
    }
    let len = image.len() as u16;
    let hash = compute_hash(image);
    let mut out = Vec::with_capacity(ImageIngress::<0>::HEADER_BYTES + image.len());
    out.extend_from_slice(&ImageIngress::<0>::MAGIC);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&hash.to_le_bytes());
    out.extend_from_slice(image);
    Ok(out)
}

fn decode_tap_stream(bytes: &[u8]) -> Result<Vec<hibana::runtime::tap::TapEvent>, String> {
    let (records, remainder) = bytes.as_chunks::<16>();
    if !remainder.is_empty() {
        return Err(format!(
            "tap stream length {} is not a multiple of 16",
            bytes.len()
        ));
    }
    Ok(records
        .iter()
        .copied()
        .map(hibana::runtime::tap::TapEvent::from)
        .collect())
}

#[derive(Clone, Copy)]
enum ReplayInput {
    File,
    Stdin,
}

#[derive(Default)]
struct ReplayOptions {
    image_path: Option<String>,
    recipe: Option<ImageSpec>,
    out_path: Option<String>,
    tap_path: Option<String>,
    site: u8,
}

impl ReplayOptions {
    fn parse(args: &[String], input: ReplayInput) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--image" => {
                    index += 1;
                    options.image_path = Some(required_option(args, index, "--image")?);
                }
                "--recipe" => {
                    let (spec, consumed, _) = parse_recipe(&args[index + 1..])?;
                    options.recipe = Some(spec);
                    index += consumed;
                }
                "--out" | "-o" => {
                    index += 1;
                    options.out_path = Some(required_option(args, index, "--out")?);
                }
                "--site" => {
                    index += 1;
                    options.site = parse_u8(&required_option(args, index, "--site")?)?;
                }
                path if path != "-" && path.starts_with('-') => {
                    return Err(format!("unknown option: {path}"));
                }
                path => {
                    if matches!(input, ReplayInput::Stdin) {
                        return Err(format!(
                            "stream reads TapEvent records from stdin, got path {path}"
                        ));
                    }
                    if options.tap_path.is_some() {
                        return Err(format!("multiple tap inputs supplied, extra: {path}"));
                    }
                    options.tap_path = Some(path.to_string());
                }
            }
            index += 1;
        }
        if options.image_path.is_some() && options.recipe.is_some() {
            return Err("--image and --recipe are mutually exclusive".into());
        }
        Ok(options)
    }
}

#[derive(Default)]
struct ImageCommandOptions {
    wrap: bool,
    out_path: Option<String>,
}

impl ImageCommandOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--wrap" => options.wrap = true,
                "--out" | "-o" => {
                    index += 1;
                    options.out_path = Some(required_option(args, index, "--out")?);
                }
                other => return Err(format!("unknown image option: {other}")),
            }
            index += 1;
        }
        Ok(options)
    }
}

fn required_option(args: &[String], index: usize, option: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn require_arg(args: &mut impl Iterator<Item = String>, usage: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("usage: hibana-epf {usage}"))
}

fn require_len(args: &[String], min: usize, usage: &str) -> Result<(), String> {
    if args.len() >= min {
        Ok(())
    } else {
        Err(format!("usage: hibana-epf {usage}"))
    }
}

fn read_file_or_stdin(path: &str) -> Result<Vec<u8>, String> {
    if path == "-" {
        read_stdin()
    } else {
        fs::read(path).map_err(|error| format!("read {path}: {error}"))
    }
}

fn read_stdin() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read stdin: {error}"))?;
    Ok(bytes)
}

fn write_bytes(path: Option<&str>, bytes: &[u8]) -> Result<(), String> {
    if let Some(path) = path {
        fs::write(path, bytes).map_err(|error| format!("write {path}: {error}"))
    } else {
        io::stdout()
            .lock()
            .write_all(bytes)
            .map_err(|error| format!("write stdout: {error}"))
    }
}

fn render_record(index: usize, record: CompactOutRecord) -> String {
    format!(
        "#{index} {} site={} target={} epoch={} kind={} reason={} arg0=0x{:08x} arg1=0x{:08x} arg2=0x{:08x} fuel={} flags=0x{:04x}",
        evidence_name(record.kind, record.reason),
        record.site,
        format_target(record.target),
        record.epoch,
        record.kind,
        record.reason,
        record.arg0,
        record.arg1,
        record.arg2,
        record.fuel_used,
        record.flags,
    )
}

fn evidence_name(kind: u32, reason: u32) -> &'static str {
    match (kind, reason) {
        (1, 1) => "epf.observe.transport.session_mismatch",
        (2, 2) => "epf.observe.transport.deadline_fault",
        (2, 3) => "epf.observe.transport.capacity_fault",
        (value, 0) if value == TRANSPORT_FRAME as u32 => "hibana.transport.frame",
        (value, value_reason)
            if value == TRANSPORT_MISMATCH as u32
                && value_reason == TRANSPORT_MISMATCH_SESSION as u32 =>
        {
            "hibana.transport.session_mismatch"
        }
        (value, value_reason)
            if value == TRANSPORT_MISMATCH as u32
                && value_reason == TRANSPORT_MISMATCH_LANE as u32 =>
        {
            "hibana.transport.lane_mismatch"
        }
        (value, value_reason)
            if value == TRANSPORT_MISMATCH as u32
                && value_reason == TRANSPORT_MISMATCH_SOURCE_ROLE as u32 =>
        {
            "hibana.transport.source_role_mismatch"
        }
        (value, value_reason)
            if value == TRANSPORT_MISMATCH as u32
                && value_reason == TRANSPORT_MISMATCH_PEER_ROLE as u32 =>
        {
            "hibana.transport.peer_role_mismatch"
        }
        (value, value_reason)
            if value == TRANSPORT_MISMATCH as u32
                && value_reason == TRANSPORT_MISMATCH_LABEL as u32 =>
        {
            "hibana.transport.label_mismatch"
        }
        (value, value_reason)
            if value == TRANSPORT_FAULT as u32
                && value_reason == TRANSPORT_FAULT_OFFLINE as u32 =>
        {
            "hibana.transport.offline_fault"
        }
        (value, value_reason)
            if value == TRANSPORT_FAULT as u32
                && value_reason == TRANSPORT_FAULT_DEADLINE as u32 =>
        {
            "hibana.transport.deadline_fault"
        }
        (value, value_reason)
            if value == TRANSPORT_FAULT as u32
                && value_reason == TRANSPORT_FAULT_CAPACITY as u32 =>
        {
            "hibana.transport.capacity_fault"
        }
        (value, value_reason)
            if value == TRANSPORT_FAULT as u32 && value_reason == TRANSPORT_FAULT_FAILED as u32 =>
        {
            "hibana.transport.failed_fault"
        }
        _ => "epf.out",
    }
}

fn format_target(target: Target) -> String {
    match target {
        Target::Observe => "observe".into(),
        Target::Policy(policy_id) => format!("policy({policy_id})"),
    }
}

fn parse_u8(text: &str) -> Result<u8, String> {
    let value = parse_u32(text)?;
    u8::try_from(value).map_err(|_| format!("value out of u8 range: {text}"))
}

fn parse_u16(text: &str) -> Result<u16, String> {
    let value = parse_u32(text)?;
    u16::try_from(value).map_err(|_| format!("value out of u16 range: {text}"))
}

fn parse_u32(text: &str) -> Result<u32, String> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|error| format!("parse {text}: {error}"))
    } else {
        text.parse::<u32>()
            .map_err(|error| format!("parse {text}: {error}"))
    }
}

fn recipes() {
    println!(
        "EPF recipes

observe:
  echo
  session-mismatch
  deadline-fault
  capacity-fault
  match <input> <value> <kind> <reason>

policy:
  policy-choose <policy-id> <arm>
  policy-choose-on-input <policy-id> <input> <value> <arm>

golden path:
  hibana-epf image session-mismatch --wrap -o session-mismatch.hepf
  hibana-epf diagnose session-mismatch trace.hbt
  hibana-epf stream --recipe session-mismatch < trace.hbt
  hibana-epf explain-out out.hepo"
    );
}

fn help() {
    eprintln!(
        "hibana-epf

commands:
  recipes
  image <recipe> [--wrap] [-o output]
  diagnose <recipe> [--out out.hepo] [--site n] <trace.hbt|->
  replay [--recipe recipe|--image image.epf] [--out out.hepo] [--site n] <trace.hbt|->
  stream [--recipe recipe|--image image.epf] [--out out.hepo] [--site n] < tap-record-stream
  audit PROTOCOL.bin SESSION DERIVATION_CAPACITY CAPTURE.bin CHECKPOINT [CAPTURE.bin CHECKPOINT ...]
  check PROTOCOL.bin WITNESS.bin CAPTURE.bin CHECKPOINT [CAPTURE.bin CHECKPOINT ...]
  explain-tap <trace.hbt|->
  explain-out <out.hepo|->
  wrap-image <image.epf|-> [-o image.hepf]"
    );
}
