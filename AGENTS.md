# EPF verification boundary

EPF observes running Hibana programs and supplies decisions at registered
resolver points. Preserve both capabilities. Hibana determines which view may
resolve a route and when; EPF supplies left, right or rejection within that
contract. Observing an event does not grant permission to modify its operation.

A route-selection record can describe a passive receiver learning the arm.
Its actor is not necessarily the logical controller. Resolver audit records
describe actual resolver invocations; check the selection mechanism and the
compiled choice authority before interpreting either record as a decision.

Dynamic protocol auditing checks the observed history. It must not become an
application's second protocol cursor, owner table, permission service or workflow
scheduler. Audit history never authorizes an Endpoint operation or an
application effect.

Consume the immutable protocol actually compiled into the measured executable.
Do not register a hand-written audit choreography, task-specific allowlist or
duplicate protocol. Keep codecs and host evidence storage separate from the
allocation-free, no_std checker and its caller-owned storage.

Distinguish static wire membership, dynamic protocol eligibility and agreement
with application effects. A matching label and lane do not establish eligibility.
Dynamic checking must distinguish the session run, physical actor, source
operation occurrence, route selection and nested roll visits. Transport
acceptance, sender publication and receiver commit are separate boundaries;
sender publication can follow receipt and later transfers.
`SEND_POLL` records admission before an actual transport poll, including polls
that return Pending or an error. Repeated polls can belong to one operation.
Do not convert these records into frame acceptances, commits or roll visits.
The prepared reset can change between polls after another view commits a
reentry. Preserve each poll's preparation; do not make it part of call identity.

Require evidence that uniquely connects those boundaries. A missing prefix,
ring overwrite, missing final record, ambiguous occurrence, exhausted counter
or insufficient storage cannot produce a completed audit. Do not infer a
successful commit from a staged transport frame. Do not infer that a roll has
permanently ended because its continuation ran.

Save a producer checkpoint independently from the record stream. Deriving it
from the supplied record count hides missing suffixes. Check the complete,
unfiltered prefix separately for each producer; neither EOF nor a checked
capture proves session completion. A filtered diagnostic stream is not an
audit capture, and producer ordinals are not a distributed clock.

Derive the executable audit rules from Hibana's established source-occurrence
semantics and check their correspondence to the exported compiled information.
Use actual Endpoint traces and mutations of timing, choice, visit, actor and
repeated message contracts. Check both rejection of illegal histories and
acceptance of legal concurrent histories, including delayed parent reentry.
Keep conditional model results separate from completed consumer qualification.

Preserve unrelated dirty files. Replace obsolete architecture when necessary,
without compatibility modes, speculative wrappers or silent fallbacks. Do not
claim a diagnostic VM provides dynamic protocol replay. Qualify the selected
core revision and current trace format before using EPF in experiments.

Use latest stable Rust, forbid(long_running_const_eval), and the shared
descendant-memory guard. Run one heavy validation at a time. Do not use Docker,
VMs, development subagents or OS-specific requirements for the checking core.
