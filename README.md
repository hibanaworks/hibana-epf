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

Dynamic protocol auditing is under development. The source checker below
connects complete captures to a proposed finite execution of the compiled
protocol. The diagnostic VM observes and filters records; it does not perform
that source check. Automatic unfolding/choice/order construction, general Rust/Lean
correspondence and qualification of the combined consumer remain unfinished.
Missing records, counter exhaustion or a truncated stream cannot support an
audit. Application effects require their own correspondence to accepted requests.

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
them. Selected fixtures also pass through the source-execution checker below.

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
every observation is retained. The source-execution checker uses the complete
snapshot rather than treating local rows as an audit choreography.

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
Source eligibility requires the selected unfolding and execution check below.

`Protocol::check_custody(captures, order, workspace)` replays actual resource
transfers in a supplied causal ordering. The order must contain every record
exactly once and preserve each producer's ordinals. Send calls and FIFO receipts
are matched in that witnessed order; unrelated producer ordinals are never
treated as a shared clock. The first poll makes the transferred role unavailable
until its committed receive grants it to the recipient. Later publication does
not revoke the recipient's right or restore the sender's. Operations through a
delegated view, transfers and resolver invocations require the actual holder.
Storage is derived by `custody_workspace_len`; it is temporary audit memory,
without allocation or an application-side permission service.

`Protocol::check_routes` includes those checks, then checks observed choices
against operations and resolver results. Views on the same actor share choice
history. A poll's prepared reentry is tentative; a committed enclosing reset
starts a new visit. Repeating a completed operation requires a covering reset;
a roll reset must lead to its claimed Endpoint commit. Tests accept changing
arms through nested rolls, pending siblings sharing a reset, delayed
publication and transfers across three separate runtimes. Mutations preserve
static membership while changing the holder, choice or resolver result and
must fail the corresponding dynamic check.

These methods alone check history agreement, not source eligibility or retained
body completion. The source-execution checker combines them with a checked
finite source interpretation. A witnessed order establishes compatibility with
that order, not a unique distributed execution time.

`Protocol::unfolding` checks a finite source-unfolding witness against the
compiled source. Its postorder steps preserve sequence, parallel composition,
both choice arms, repeated and independently unfolded rolls, and resumption
before, alongside or after the continuation. Source regions are derived from
the compiled root. A shared proof step must refer to the same source region;
an insertion must name an actual subtree. No catalogue of fixed visit counts
limits the witness. The checker retains five words per proof step and reads
expanded origins and source order without constructing an expanded tree.

`Unfolded::select` checks a choice for each active expanded route and derives
physical actors from the original resource bindings and selected transfers.
It compares them with the compiled conditional bindings under those same
choices. Separate visits can choose different arms. Parallel transfer/use
conflicts, overlapping physical actors in independent visits, unselected
resumption anchors and changed entry owners are rejected. Temporary storage
is derived from expanded event, initial binding and compiled choice counts.

`SourcePath::check_word` checks every prefix of a proposed source word.
Acceptance, sender publication, receiver commit and a local action are
different points. It checks source order, uniqueness, wire prerequisites and
outgoing-continuation prerequisites activated by a committed resumed body.
An incoming continuation already accepted by its sender does not acquire a
new outgoing prerequisite. Reusing a proof DAG in two visits does not share
their dynamic entry history.

`SourcePath::check_execution(captures, witness, workspace)` connects the complete
captures to that selected path for one named session. The witness supplies an
expanded occurrence for every operation and control observation of that run,
and proposed acceptance boundaries. It reuses the checked call/FIFO links:
repeated polls, publication and receipt must name the same dynamic occurrence,
and different calls cannot reuse it. Choices must belong to the corresponding
selected route visit, and each observed reset must lead to its attributed
reentry. The source word is reconstructed from actual Endpoint commits and
supported acceptances, rather than supplied as an unchecked operation list.

Each acceptance must fall after its call's first poll and before its checked
publication or receipt. A call with neither completion cannot support an
acceptance. Every poll separately checks source admission at its own boundary,
including retries; it never appends acceptance or commits source progress.
Thus moving a first poll before its required local predecessor is rejected even
when every successful commit is unchanged and acceptance is proposed later.
Unfinished or failed calls remain admission queries. Workspace is caller-owned
and derived from actual capture and witness sizes, with checked arithmetic.

Actual Endpoint tests cover separate-runtime loans and unequal publication
order, changing arms through nested rolls, shared parallel resets in both
completion orders and a pending old continuation during elastic reentry.
They also reject invented acceptance after each transport error, reused dynamic
occurrences, invalid boundaries and short or malformed correspondence input.
Defect controls omit the per-poll query or completion-evidence requirement;
each must fail its named regression.

Success is a source interpretation compatible with the witnessed causal order
and acceptance intervals under the transport contract. It does not establish
authenticity, a recovered physical acceptance time, completion of a session or
agreement with application effects. Other runs need their own witness.
Construction of source unfoldings, selections and causal order, and general
formal correspondence of the new Rust checks remain unfinished. The existing
Lean claims below do not prove those components.

`SourcePath::interpret(captures, storage, workspace)` constructs the record
attribution and supported acceptance boundaries for an already checked source
path and complete proposed record order. `ExecutionStorage` supplies writable
output arrays; the returned `ExecutionWitness` borrows their used portions.
Send polls, publications and FIFO receipts share one search variable. Roll
reset attribution follows its exact next committed operation, and distinct
calls cannot reuse an expanded event. The constructor searches the finite
expanded domain and validates each finished candidate with `check_execution`.
It cannot substitute its own acceptance for that check.

Acceptance is proposed after the first poll only for calls with completion
evidence. This is an allowed interval interpretation, not a physical timestamp.
Space is seven words per captured record plus custody checking space, without
a fixed depth or visit horizon. Worst-case search is exponential; no large-task
throughput claim is established. Failure to interpret one supplied finite path
does not reject the global or exclude another unfolding. Construction of the
unfolding, branch selections and causal order remains unfinished.

Actual Endpoint fixtures check constructed attributions for three-runtime
delegation, nested choices and predecessor violations. A separate synthetic
test compares the constructor with all 9,362 assignments for 62 small sequence
and parallel record words, including legal prefixes and impossible orderings.
The constructor's final validation is also removed in a defect control, which
must fail the early-poll regression. These checks do not prove general search
completeness or Rust/Lean refinement.

`CaptureExecution.lean` interprets poll queries and source advances using the
selected core's existing source-occurrence semantics. It proves that a checked
record list has a source execution, preserves the exact source prefix at every
append, and retains each advance's resumption check. Polling does not append a
source point; repeating a poll cannot duplicate acceptance. Its interval rules
require completion evidence and place acceptance after its poll and before each
observed completion, allowing receipt before sender publication. These are
contracts for the evidence interpreter. They do not prove the Rust snapshot
reader, occurrence matcher or whole checker implements those contracts.

The selected core pin `08d0439` includes committed-body resumption and
independent visits of physically disjoint parallel rolls. The proof gate imports
that exact Git dependency, including the normalization claims: moving supported
acceptance boundaries leaves admission unchanged when the committed prefix is
unchanged. The Rust source checker also uses committed-body entry, exercised by
the pending-continuation fixtures. These claims do not prove general Rust/Lean
refinement. This core preparation still needs whole-core qualification; an EPF
gate pass alone does not establish that result.

The local gate passed at EPF `395e801` with core `08d0439`: 93 native tests,
88 strict-provenance Miri tests, 46 audited Lean claims and all 16 history defect
controls, plus Clippy, doctests and no_std/thumbv6m builds. Input source hashes
matched after the gate. Peak memory across the guarded process tree was
688,160,768 bytes. These are mechanism checks, not application-effect or
whole-core qualification.

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
