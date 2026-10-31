# hibana-epf

EPF processes Hibana observations while a program runs. The library uses
`no_std`, no heap allocation and caller-owned storage. The optional command-line
tool reads live or recorded observations and emits diagnostics.

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

## Device transport and decisions

`ImageIngress` accepts a length- and hash-checked image envelope assembled by
the host tool. `TapSpool` retains a caller-sized set of observations for replay;
a full spool returns an error. UART, USB and file transport remain the device's
I/O responsibility.

```sh
hibana-epf image session-mismatch --wrap -o observe.hepf
hibana-epf recipes
```

A policy image can supply a local resolver's decision through
`epf.resolver::<ID>(fallback)?`. Register that resolver through Hibana's normal
API. Capacity errors are reported at registration. Without an active policy
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

## Check locally

```sh
./tools/check.sh
```

The checks include actual Endpoint choices and roll reentry, live pipe output
before EOF, partial-record rejection, image replacement, resolver behavior,
Clippy, no_std builds and strict-provenance Miri. They require Rust stable, the
Miri toolchain recorded in `tools/miri-toolchain`, and `thumbv6m-none-eabi`.
