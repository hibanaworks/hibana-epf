# hibana-epf

EPF observes running Hibana programs and controls registered route decisions.
Observation programs process events; policy programs return left, right or
rejection through Hibana's resolver API. The library uses `no_std`, no heap
allocation and caller-owned storage. The optional command-line tool processes
live or recorded observations and emits diagnostics.

## Observe a running endpoint

Read the runtime's tap and pass each event to EPF:

```rust
let mut tap = rendezvous.tap();
let mut storage = hibana_epf::EpfStorage::<0, 0>::new();
let epf = hibana_epf::Epf::new(&mut storage);

for event in tap.by_ref() {
    let diagnostic = epf.run(event);
    // Send or display the diagnostic using the device's I/O.
}
```

Keep `tap` and drain it again as the endpoint runs. Reading observations does
not advance the protocol. Hibana's bounded ring can overwrite unread events;
retain raw events and check their ordinals when completeness matters.

The built-in observation program reports each event. Load a filter to select
specific observations, such as transport session mismatches:

```rust
let mut image = [0u8; 64];
let len = hibana_epf::ImageSpec::ObserveSessionMismatch.write(&mut image)?;
epf.load(&image[..len])?;
```

Reserve enough image storage in `EpfStorage` when loading a program. Loading
validates the whole image before replacing the active program. A failed load
leaves the active program available; `revert` restores its previous version.

## Host tool

```sh
cargo build --locked --features std --bin hibana-epf
./target/debug/hibana-epf stream --recipe echo --out observations.hepo
```

`stream` reads canonical 16-byte `TapEvent` records from standard input. It
processes each complete record immediately, flushes its text output and writes
any binary output before waiting for the next record. The producer can keep the
pipe open. Reads may split a record across writes; EOF partway through a record
returns an error. The tool retains one input record rather than the entire
stream. These commands run observation images; build policy images with `image`
and install them in the application that registers the resolver.
Filtered events produce no output. `--out` creates a new file and
rejects an existing path, preserving earlier captures.

After adding the built tool to `PATH`, use captured input:

```sh
hibana-epf explain-tap trace.hbt
hibana-epf diagnose session-mismatch trace.hbt
hibana-epf replay --recipe echo --out observations.hepo trace.hbt
hibana-epf explain-out observations.hepo
```

Hibana owns the tap format and its field interpretation. EPF preserves the ring
ordinal, causal key and full 16-bit wire label. The ordinal is a record counter,
not elapsed time. `--out` contains compact diagnostics; keep the original tap
records for later audit because filtering can remove observations.

Observation images receive the ordinal in input word 2. Committed Endpoint
records identify the executing actor, logical role, lane and full source-event
number using Hibana's field layout. The image schema binds these interpretations;
an image for an older layout is rejected before replacing the active program.
Route selections and resolver decisions also identify their executing actor.
Match their route site to the compiled choice row to obtain the logical
controller. A delegated controller can be operated by a different actor;
rejected decisions retain that actor even without a later Endpoint commit.
The input format is versioned by the EPF image's evidence schema. Raw tap
records have no format header, so retain their runtime revision and build
receipt when saving a capture.

## Device transport and decisions

`ImageIngress` accepts a length- and hash-checked image envelope assembled by
the host tool. `TapSpool` retains a caller-sized set of observations for replay;
a full spool returns an error. UART, USB and file transport remain the device's
I/O responsibility.

```sh
hibana-epf image session-mismatch --wrap -o observe.hepf
hibana-epf recipes
```

A policy image supplies a local resolver's decision through
`epf.resolver::<ID>(fallback)?`. Register it on the compiled program:

```rust
let global = g::route(left, right).resolve::<17>();
let program = project::<ROLE>(&global);
kit.set_resolver(&program, epf.resolver::<17>(fallback)?)?;
```

As execution proceeds, `epf.run(event)` updates the observed input available to
policy programs. Endpoint operations still run directly in their localsides;
EPF supplies a decision when Hibana invokes the registered resolver. Capacity
errors are reported at registration. Policy IDs use Hibana's full `u16` range.
Without an active policy
image, the registered fallback runs. Invalid decisions and VM traps reject the
decision. A conditional policy whose input does not match also rejects; it does
not wait or invoke the fallback. Hibana still checks which endpoint may choose
and when it may act.

## What the observations establish

EPF reports actual endpoint, resolver, transport and lane observations. A staged
transport frame is distinct from a committed receive. Matching a label and lane
to a compiled operation establishes static membership only.

Full dynamic protocol auditing is unfinished. It requires unambiguous links to
the run, actor, source occurrence, route choices and nested roll visits, plus a
complete history. The current diagnostic VM does not replay that history or
certify that every observed operation was enabled. Missing records, counter
exhaustion or a truncated stream cannot support a completed audit. Application
effects require their own correspondence to accepted endpoint requests.

Local operation rows alone omit control structure. A single
local send and that send inside `roll` have the same rows but disagree about
whether a second call is permitted. Two local sends in `seq` and in `route`
also have the same rows but disagree about executing the second after the
first. `endpoint_observation` exercises both pairs through actual Endpoints
and requires their complete compiled snapshots to differ.

`hibana::runtime::tap::projected(&program)` reads the same sealed program as
execution. Its snapshot includes global source operations, ordered
route/par/roll markers, choice authorities and delegation bindings before the
local rows. The two headers supply format version and section counts. These
records provide the protocol input needed to audit a history. They do not
report that history's branch selections, roll visits or completed operations.
Replaying row labels alone cannot establish dynamic eligibility, even when
every observation is retained. The source snapshot and history replay still
need to be connected before EPF can certify an execution.

`Protocol::new(snapshot, workspace)` checks that input before history replay.
It borrows the original snapshot and releases its temporary workspace after
checking section counts, scope intervals, choice and actor references, initial
issuance and local-operation coverage. `Protocol::workspace_len(snapshot)`
derives the workspace size from the declared markers and actor decisions.
The reader handles nested `par`/`route`/`roll` and multiple delegated resources.
It checks the actor bindings supplied by the compiler; it does not prove their
derivation from the Rust global or check a dynamic execution history.

## Check locally

```sh
./tools/check.sh
```

The checks include actual Endpoint choices and roll reentry, live pipe output
before EOF, partial-record rejection, image replacement, resolver behavior,
Clippy, no_std builds and strict-provenance Miri. They require Rust stable, the
Miri toolchain recorded in `tools/miri-toolchain`, and `thumbv6m-none-eabi`.
