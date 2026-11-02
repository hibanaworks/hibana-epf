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
`SEND_POLL` is emitted after source admission and encoding, immediately before
each actual transport send poll. It names the actor, logical view, session,
source event and prepared repetition reset. It is available even when the poll
returns `Pending`. Repeated polls can describe the same outstanding operation;
they do not count accepted frames, completed sends or new roll visits.
Route selections identify the actor applying or learning the selection;
resolver decisions identify the actor invoking the resolver. Match the route
site to the compiled choice row to obtain the logical controller. An incoming
frame can teach a passive receiver the arm without giving it control of the
choice. A delegated controller can be operated by a different actor. Rejected
resolver decisions retain that actor even without a later Endpoint commit.
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

`SCOPE_REENTRY` reports the scope actually reused by a progress commit, including
the actor, logical view, session and full scope identifier. A roll record also
names its entry source event; a route-only record names its selected arm. EPF
can observe and filter these records. The `endpoint_observation` test drives
inner and outer roll reentry and distinguishes them through the canonical
record codec and an installed observation image. This adds execution context;
it does not make filtered diagnostic output a complete history certificate.

Save `tap.checkpoint()` independently when ending a capture. Then
`Capture::new(records, checkpoint)` checks the full unfiltered prefix from that
producer. It rejects missing first or final records, gaps, duplicates,
reordering and exhausted ordinals without allocating or copying the history.
An empty prefix at checkpoint zero is valid. A checked capture establishes
record completeness relative to that trusted checkpoint, not a completed
session, authentic records or dynamic protocol eligibility. Keep each
producer's capture separate; ordinals are not a distributed clock.
`proofs/Capture.lean` proves that the length and ordinal checks accept exactly
the required ordinal prefix, reject a missing suffix and give it one end
checkpoint. It specifies completeness of ordinals, not authenticity of record
contents or protocol execution. Rust and Miri tests exercise the capture reader
and actual Endpoint runs with overwritten or continuously drained tap records.
Two defect controls omit either the count check or the ordinal check; each must
fail its corresponding Rust regression test.

`endpoint_history` drives a transport that exposes a unit frame before its
send future completes. The actual receive commits before the sender's commit
observation, between two send-poll records for the same operation. An installed
observation filter retains their full checked-operation identity. An ordered
fixture also checks that its local predecessor commits before the first poll;
an out-of-order send emits neither a send-poll record nor a frame. The tests
exercise all four transport errors after an observed poll and require no frame
or Endpoint commit. Observing a checked poll therefore cannot substitute for
evidence of acceptance. The tests also check both resolved arms and distinguish
the receiver's learned selection from the sender's resolver decision. These are legal history
fixtures for the auditor; a send-publication-before-receive rule would reject
them. They do not implement or certify the history replay described above.

`proofs/CommitObservations.lean` erases acceptance points from Hibana's existing
source-occurrence semantics. It proves that the ordinary-message fixture has
valid source executions in either completion order, and that a receipt still
requires acceptance. Omitting that acceptance leaves the same endpoint-only
projection. The other claim is a general append law for this projection.
The ordered-send regression adds a local predecessor. A legal word sends after
that predecessor, while an early-send word violates its first readiness check.
If publication is delayed until after the predecessor, both words have exactly
the same complete endpoint-commit projection. A replay that invents acceptance
at publication cannot detect this early-send violation. Checking admission needs
evidence from before the frame can become available to a receiver.
These ten claims specify the observation boundary; they do not establish
general Rust-to-source trace refinement. The local gate imports the model from
the exact core selected in Cargo metadata, checks its revision and source
hashes, and audits the Lean axioms. Install that core's `proofs/lean/lean-toolchain`
with elan before running the gate. CI installs the same compiler.

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
Its temporary actor-membership workspace uses one bit per decision.

`Protocol::send_calls(capture, workspace)` links the producer's actual checked
polls to sender publication. Size the caller-owned workspace with
`send_call_workspace_len`. The calls are returned in first-poll order; iterating
their polls follows checked forward links and does not scan overlapping calls.
Repeated polls of one pending future form one call. A later roll execution of
the same source event forms another. Failed or unfinished calls retain no
publication, and a receive can occur before publication.

Preparation belongs to each poll. If another view commits a roll reentry while
a send is pending, the next poll can require a different reset. EPF requires an
intervening reset record on the same actor and session, covering that source
event. Resets on another actor, another session or another source interval do
not justify the change. This checks observed correspondence, not whether the
reset itself was enabled. A range index checks these intervals without scanning
each pending call's whole history. Workspace uses `4N + 2E + M + ceil(D / W)`
words for N capture records, E source events, M scope markers, D immutable actor
decisions and machine word width W; it is caller-owned audit scratch space.

Before yielding calls, the reader checks source identity, logical view, direction,
lane, possible actor and enclosing prepared roll. It then checks the generated
links separately: every poll occurs once, every transport publication occurs
once, links move forward and same-key calls do not overlap. Both phases use
temporary caller-owned storage; the resulting links borrow that storage.
Different producers still require separate captures, and each SessionId must
identify one run. The supplied protocol must match the executable's saved
build evidence. This correspondence does not authenticate records, establish
physical acceptance, determine current ownership or certify source eligibility.
Route/roll replay and correspondence across changing producer ownership remain unfinished.

`Protocol::deliveries(captures, workspace)` connects successful receives across
producer captures to send calls. Within each session/source stream it uses the
transport's affine FIFO contract, with one producer per side. Several producers
on either side require further handoff evidence and return `Ambiguous`; their
unrelated ordinals cannot resolve the order. A missing send, reused receipt or
inconsistent producer history is rejected. It checks a common causal ordering
of every producer's records and the poll-before-receive edges, then verifies
that ordering by its defining inequalities. A cyclic exchange is rejected even
when each individual frame has a matching send. Neither this ordering nor the
first poll fixes the time of physical acceptance. Sender publication may still
follow receipt. Open sends are retained as unmatched prefix operations, without
claiming a completed session, source eligibility or payload agreement.

The temporary storage is four words per input record, one per producer plus
one, and the largest producer's send-call workspace. Captures are borrowed
unchanged; the resulting delivery links refer to producer/ordinal coordinates.
Tests drive actual owned Endpoint transfers and rolled resource requests across
three runtimes, including receipt and resource use before loan publication.
Small directed graphs are compared exhaustively with independent reachability.
`DeliveryOrder.lean` proves that increasing ranks exclude causal cycles and
allow receipt before publication. These claims specify the final order check;
they do not prove FIFO transport, the entire Rust matcher or dynamic replay.

Actual Endpoint tests include interleaved parallel calls finishing in reverse,
two rolled executions of one source event, both resolved arms, transport faults
and conditional resource holders using the resource before loan publication.
Pending continuations and both completion orders of rolled parallel views are
also driven through actual Endpoint operations. Nineteen record mutations and
eight malformed-link cases exercise rejection. The range index is compared
with direct interval updates for odd and even event counts and interleaved
actor/session groups. Four call-link defect controls remove interval,
poll-coverage or reset-evidence checks or restore the invalid preparation-immutability condition;
each must fail its named regression. `SendCalls.lean` proves five general facts
about successful record-position marking and word/bit coordinates, plus two
claims requiring a reset from the same actor/session, inside the poll interval
and covering the source event. Six exact `BitVec` claims prove mask presence,
preservation, distinctness and a truncated-index counterexample for every word
width, including 32 and 64 bits.
These models specify those checks, not a refinement proof of the whole Rust
link constructor or dynamic source replay.

## Check locally

```sh
./tools/check.sh
```

The checks include actual Endpoint choices and roll reentry, live pipe output
before EOF, partial-record rejection, image replacement, resolver behavior,
Clippy, no_std builds and strict-provenance Miri. They require Rust stable, the
Miri toolchain recorded in `tools/miri-toolchain`, `thumbv6m-none-eabi`, Lean
selected by the core dependency.
