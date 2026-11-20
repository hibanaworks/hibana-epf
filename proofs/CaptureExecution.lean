import Hibana.SourceOccurrenceTrace

namespace Hibana.Epf.CaptureExecution
open EndpointDelegation

/-- Observer arrival order only rotates the complete producer domain. -/
def preferredProducer (count first rank : Nat) : Nat :=
  if rank < count - first then first + rank else rank - (count - first)

theorem preferred_producer_is_in_range (count first rank : Nat)
    (preferred : first < count) (candidate : rank < count) :
    preferredProducer count first rank < count := by
  unfold preferredProducer
  split <;> omega

theorem preferred_producer_is_first (count first : Nat) (preferred : first < count) :
    preferredProducer count first 0 = first := by
  unfold preferredProducer
  split <;> omega

theorem preferred_producer_does_not_repeat (count first left right : Nat)
    (preferred : first < count) (leftBound : left < count) (rightBound : right < count)
    (same : preferredProducer count first left = preferredProducer count first right) :
    left = right := by
  unfold preferredProducer at same
  split at same <;> split at same <;> omega

theorem preferred_producer_visits_every_candidate (count first producer : Nat)
    (preferred : first < count) (candidate : producer < count) :
    ∃ rank, rank < count ∧ preferredProducer count first rank = producer := by
  by_cases later : first ≤ producer
  · refine ⟨producer - first, by omega, ?_⟩
    unfold preferredProducer
    split <;> omega
  · refine ⟨count - first + producer, by omega, ?_⟩
    unfold preferredProducer
    split <;> omega

/-- The event and the four observation phases have distinct keys, even when
the same original message is reused in another expanded visit. -/
theorem source_point_rank_is_injective (left right : SourcePoint)
    (same : left.rank = right.rank) : left = right := by
  cases left with
  | accepted event =>
    cases right with
    | accepted other =>
      have equal : event = other := by simp only [SourcePoint.rank] at same; omega
      subst other
      rfl
    | committed action =>
      rcases action with ⟨other, side⟩
      cases side <;> simp only [SourcePoint.rank] at same <;> omega
  | committed action =>
    rcases action with ⟨event, side⟩
    cases right with
    | accepted other =>
      cases side <;> simp only [SourcePoint.rank] at same <;> omega
    | committed action =>
      rcases action with ⟨other, otherSide⟩
      cases side <;> cases otherSide <;> simp only [SourcePoint.rank] at same
      all_goals
        first
        | omega
        | have equal : event = other := by omega
          simp only [equal]

/-- Indexing this exact prefix by event/phase preserves membership. The index
is rebuilt on rewind; it is not a second source word or an application cursor. -/
theorem indexed_prefix_membership (history : List SourcePoint) (point : SourcePoint) :
    (history.map SourcePoint.rank).contains point.rank = history.contains point := by
  apply Bool.eq_iff_iff.mpr
  simp only [List.contains_iff_mem, List.mem_map]
  constructor
  · rintro ⟨prior, member, same⟩
    have equal := source_point_rank_is_injective prior point same
    simpa [equal] using member
  · intro member
    exact ⟨point, member, rfl⟩

/-- Appending observations extends the same membership index. Rebuilding old
entries on every forward step is unnecessary; rewinds still use the exact
retained prefix. This is a source-list identity, not a Rust refinement proof. -/
theorem indexed_prefix_append_membership
    (history extra : List SourcePoint) (point : SourcePoint) :
    ((history ++ extra).map SourcePoint.rank).contains point.rank =
      ((history.map SourcePoint.rank).contains point.rank ||
        (extra.map SourcePoint.rank).contains point.rank) := by
  simp

/-- Attributed operations need their own membership index: a pending poll
can already name an occurrence without adding a committed source point.
Filtering controls, foreign sessions and absent attributions before indexing
preserves exactly the direct existence query on any prefix or rewind. -/
theorem attributed_prefix_membership (history : List (Option Nat)) (event : Nat) :
    (history.filterMap id).contains event =
      history.any (fun attributed => attributed == some event) := by
  apply Bool.eq_iff_iff.mpr
  simp only [List.contains_iff_mem, List.mem_filterMap, List.any_eq_true, beq_iff_eq]
  rfl

/-- Pending polls extend attribution membership without becoming commits.
Controls and foreign sessions are filtered before this identity is applied. -/
theorem attributed_prefix_append_membership
    (history extra : List (Option Nat)) (event : Nat) :
    ((history ++ extra).filterMap id).contains event =
      ((history.filterMap id).contains event || (extra.filterMap id).contains event) := by
  simp

/-- The first preferred pair provides both ranks omitted from ordinary
enumeration. This certifies coverage of the candidate ranks. -/
theorem first_preferred_pair_and_remaining_candidates_cover
    (events first hints rank : Nat) (hasHint : 2 ≤ hints) (within : rank < 2 * events) :
    ∃ index, index < 2 * events + hints ∧
      (index < 2 ∨ hints ≤ index ∧ (index - hints) / 2 ≠ first) ∧
      (if index < hints then 2 * first + index else index - hints) = rank := by
  by_cases preferred : rank / 2 = first
  · refine ⟨rank % 2, by omega, Or.inl (by omega), ?_⟩
    rw [if_pos (by omega)]
    omega
  · refine ⟨rank + hints, by omega, Or.inr ⟨by omega, ?_⟩, ?_⟩
    · simpa using preferred
    · rw [if_neg (by omega)]
      omega

/-- A necessary condition that only reads prefix membership may use that
index. Full source readiness and final execution checking are still required. -/
theorem indexed_prefix_preserves_read_only_conditions
    (history : List SourcePoint) (condition : (SourcePoint → Bool) → Bool) :
    condition (fun point => (history.map SourcePoint.rank).contains point.rank) =
      condition (fun point => history.contains point) := by
  apply congrArg condition
  funext point
  exact indexed_prefix_membership history point

/-- The operation class is fixed by logical endpoints, even if two logical
views happen to have the same physical actor. Changing choices cannot turn a
wire message into a local action. -/
theorem wire_message_cannot_decode_a_local_action
    (bindings : List (Nat × Binding)) (event : Nat) (binding : Binding)
    (found : bindings.find? (fun row => row.1 == event) = some (event, binding))
    (different : binding.message.sender ≠ binding.message.receiver) :
    action? bindings ⟨event, .local⟩ = none := by
  simp [action?, found, different]

theorem logical_self_message_cannot_decode_wire_halves
    (bindings : List (Nat × Binding)) (event : Nat) (binding : Binding)
    (found : bindings.find? (fun row => row.1 == event) = some (event, binding))
    (same : binding.message.sender = binding.message.receiver) :
    action? bindings ⟨event, .send⟩ = none ∧ action? bindings ⟨event, .receive⟩ = none := by
  simp [action?, found, same]

/-- A terminal compiled actor reference has no choice dependence. The checker
does not apply this pruning rule to conditional references at or above 256. -/
theorem terminal_actor_reference_is_choice_independent
    (columns : DecodedProgramColumns) (selected : Nat → Option RouteArm)
    (reference : Nat) (fixed : reference < 256) :
    columns.selectedActor? selected reference = some reference := by
  change (if reference < 256 then some reference else _) = some reference
  rw [if_pos fixed]

theorem a_different_actor_cannot_match_a_terminal_reference
    (columns : DecodedProgramColumns) (selected : Nat → Option RouteArm)
    (reference actor : Nat) (fixed : reference < 256) (different : reference ≠ actor) :
    columns.selectedActor? selected reference ≠ some actor := by
  rw [terminal_actor_reference_is_choice_independent columns selected reference fixed]
  simpa using different

/-- Later selected bindings cannot change an action already reconstructed
from the source prefix. This is not a claim about arbitrary Rust code. -/
theorem a_decoded_prefix_action_survives_a_binding_extension
    (earlier later : List (Nat × Binding)) (id : ActionId) (action : Action)
    (decoded : action? earlier id = some action) :
    action? (earlier ++ later) id = some action := by
  cases found : earlier.find? (fun row => row.1 == id.event) with
  | none => simp [action?, found] at decoded
  | some row => simpa [action?, List.find?_append, found] using decoded

/-- Once selection reconstructed a row's actor, choosing an unrelated source
suffix cannot repair its disagreement with a recorded actor. -/
theorem no_binding_suffix_repairs_a_decoded_actor_mismatch
    (earlier later : List (Nat × Binding)) (id : ActionId) (action : Action)
    (actor : Nat) (decoded : action? earlier id = some action)
    (different : action.actor ≠ actor) :
    ¬ ∃ result, action? (earlier ++ later) id = some result ∧ result.actor = actor := by
  intro ⟨result, found, agrees⟩
  have same : action = result := Option.some.inj
    ((a_decoded_prefix_action_survives_a_binding_extension earlier later id action decoded).symm.trans found)
  subst result
  exact different agrees

/-- A readiness query uses another checked selection of the same unfolding,
not another source, visit expansion or initial resource issuance. -/
structure Query (plan : SourceOccurrenceCut source) where
  path : NormalizedPath
  selected : path ∈ plan.normalized.paths
  separated : plan.unfolding.parallelCompatible path.bindings = true
  guarded : plan.unfolding.guardsCompatible plan.normalized.issuance path.bindings = true

def Query.cut {source : Source} {plan : SourceOccurrenceCut source}
    (query : Query plan) : SourceOccurrenceCut source :=
  { plan with
    path := query.path
    selected := query.selected
    separated := query.separated
    guarded := query.guarded }

/-- Interpret a poll as a query, and a supported acceptance or actual Endpoint
commit as a source advance. Record matching and transport evidence must be
checked separately; this does not model an application scheduler. -/
inductive Record (plan : SourceOccurrenceCut source) where
  | poll (query : Query plan) (event : Nat)
  | advance (point : SourcePoint)

def advances {plan : SourceOccurrenceCut source} : List (Record plan) → List SourcePoint
  | [] => []
  | .poll _ _ :: rest => advances rest
  | .advance point :: rest => point :: advances rest

/-- Retry admission uses the existing source prerequisites and resumption
rule, without requiring a fresh or newly committed acceptance point. -/
def admissionReady (plan : SourceOccurrenceCut source) (points : List SourcePoint)
    (event : Nat) : Bool :=
  let cut := occurrenceCut plan points
  (sourceVisitPoints cut.path.bindings).contains (.accepted event) &&
    (sourceVisitPoints cut.path.bindings).all (fun prior =>
      !sourcePointDepends cut.expanded cut.path.bindings prior (.accepted event) ||
        cut.observed prior) &&
    (cut.resumptionReady (.accepted event) &&
      !points.contains (.committed ⟨event, .send⟩))

/-- A predecessor that is required in every compatible selection cannot be
removed by searching more choices. The Rust index checks this sufficient
condition only for structurally mandatory, fixed-actor source predecessors. -/
theorem a_missing_unavoidable_predecessor_forbids_every_point_query
    (plan : SourceOccurrenceCut source) (points : List SourcePoint)
    (point prior : SourcePoint)
    (absent : points.contains prior = false)
    (required : ∀ query : Query plan,
      prior ∈ sourceVisitPoints query.path.bindings ∧
        sourcePointDepends query.cut.expanded query.path.bindings prior point = true) :
    ∀ query : Query plan, (occurrenceCut query.cut points).ready point = false := by
  intro query
  apply Bool.eq_false_iff.mpr
  intro ready
  have completed := List.all_eq_true.mp (Bool.and_eq_true_iff.mp ready).2
    prior (required query).1
  change (!sourcePointDepends query.cut.expanded query.path.bindings prior point ||
    points.contains prior) = true at completed
  have present : points.contains prior = true := by
    simpa only [(required query).2, Bool.not_true, Bool.false_or] using completed
  rw [absent] at present
  cases present

theorem a_missing_unavoidable_predecessor_forbids_every_query
    (plan : SourceOccurrenceCut source) (points : List SourcePoint)
    (event : Nat) (prior : SourcePoint)
    (absent : points.contains prior = false)
    (required : ∀ query : Query plan,
      prior ∈ sourceVisitPoints query.path.bindings ∧
        sourcePointDepends query.cut.expanded query.path.bindings prior (.accepted event) = true) :
    ∀ query : Query plan, admissionReady query.cut points event = false := by
  intro query
  apply Bool.eq_false_iff.mpr
  intro ready
  have prerequisites := (Bool.and_eq_true_iff.mp
    (Bool.and_eq_true_iff.mp ready).1).2
  have completed := List.all_eq_true.mp prerequisites prior (required query).1
  change (!sourcePointDepends query.cut.expanded query.path.bindings prior
    (.accepted event) || points.contains prior) = true at completed
  have present : points.contains prior = true := by
    simpa only [(required query).2, Bool.not_true, Bool.false_or] using completed
  rw [absent] at present
  cases present

/-- No choice of checked path can admit a send occurrence already published
in this same unfolding. An uncommitted acceptance alone is not publication. -/
theorem a_published_send_is_not_admission_ready
    (plan : SourceOccurrenceCut source) (points : List SourcePoint) (event : Nat)
    (published : points.contains (.committed ⟨event, .send⟩) = true) :
    admissionReady plan points event = false := by
  unfold admissionReady
  simp only [published, Bool.not_true, Bool.and_false]

/-- The full source relation never requires a later event. The Rust word
checker can stop its predecessor scan at the target event; the equal-event
send/receive dependency remains inside that inclusive boundary. -/
theorem actor_prerequisites_are_not_later_events
    (source : Source) (bindings : List (Nat × Binding)) (before after : ActionId)
    (ordered : precedes source bindings before after = true) :
    before.event ≤ after.event := by
  rcases actor_order_has_source_order_or_message_halves ordered with earlier | same
  · omega
  · omega

/-- A newly selected row beyond an actor's observed local/receive prefix
cannot become a missing predecessor of that prefix. The checker still checks
the original source relation for every row inside this bound. -/
theorem a_new_row_beyond_committed_history_is_not_a_predecessor
    (source : Source) (bindings : List (Nat × Binding))
    (history : List ActionId) (before : ActionId) (limit : Nat)
    (bounded : ∀ after ∈ history, after.event < limit)
    (later : limit ≤ before.event) :
    ¬ ∃ after ∈ history, precedes source bindings before after = true := by
  rintro ⟨after, member, ordered⟩
  have forward := actor_prerequisites_are_not_later_events source bindings before after ordered
  have bound := bounded after member
  omega

/-- Grouping history by the relevant actor and skipping smaller source events
preserves every possible predecessor witness. Sorting that retained history
does not require any assumption about the order in which it was observed. -/
theorem predecessor_search_can_filter_actor_and_event
    (source : Source) (bindings : List (Nat × Binding))
    (history : List ActionId) (belongs : ActionId → Bool) (before : ActionId) :
    (∃ after ∈ history, belongs after = true ∧ precedes source bindings before after = true) ↔
    ∃ after ∈ history.filter (fun after => belongs after && decide (before.event ≤ after.event)),
      precedes source bindings before after = true := by
  constructor
  · rintro ⟨after, member, actor, ordered⟩
    refine ⟨after, List.mem_filter.mpr ⟨member, ?_⟩, ordered⟩
    have forward := actor_prerequisites_are_not_later_events source bindings before after ordered
    simp [actor, forward]
  · rintro ⟨after, member, ordered⟩
    have filtered := List.mem_filter.mp member
    exact ⟨after, filtered.1, (Bool.and_eq_true_iff.mp filtered.2).1, ordered⟩

theorem resumption_prerequisites_are_strictly_earlier_events
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (before : ActionId) (after : Nat)
    (depends : plan.resumptionDepends observed (.committed before) (.accepted after) = true) :
    before.event < after := by
  have ranked := a_resumption_dependency_increases_source_rank depends
  cases sideAt : before.side <;> simp only [SourcePoint.rank, sideAt] at ranked <;> omega

/-- Once transport accepted a send, publication has no additional source or
resumption prerequisite. This does not infer acceptance from an earlier poll. -/
theorem sender_publication_has_only_its_acceptance_predecessor
    (source : Source) (bindings : List (Nat × Binding)) (prior : SourcePoint) (event : Nat) :
    sourcePointDepends source bindings prior (.committed ⟨event, .send⟩) =
      decide (prior = .accepted event) := by
  cases prior with
  | accepted before =>
      by_cases same : before = event <;> simp [sourcePointDepends, same]
  | committed before => simp [sourcePointDepends]

/-- A different selection must preserve every committed operation's actor and
all of its prefix prerequisites. Uncommitted acceptances do not freeze an arm. -/
def queryCompatible (plan query : SourceOccurrenceCut source)
    (history : List SourcePoint) : Bool :=
  history.zipIdx.all fun (point, index) => match point with
    | .accepted _ => true
    | .committed _ =>
        decide (occurrenceActor? plan point = occurrenceActor? query point) &&
        (occurrenceCut query (history.take index)).ready point &&
        (occurrenceCut query (history.take index)).resumptionReady point

def check (plan : SourceOccurrenceCut source) (history : List SourcePoint) :
    List (Record plan) → Bool
  | [] => true
  | .poll query event :: rest =>
      (queryCompatible plan query.cut history && admissionReady query.cut history event) &&
      check plan history rest
  | .advance point :: rest =>
      (occurrenceCut plan history).ready point &&
      (occurrenceCut plan history).resumptionReady point &&
      check plan (history ++ [point]) rest

private theorem append_execution
    (first : SourceOccurrenceExecution a b points)
    (rest : SourceOccurrenceExecution b c suffix) :
    SourceOccurrenceExecution a c (points ++ suffix) := by
  induction rest with
  | nil => simpa using first
  | tail prior step ih =>
    simpa only [List.append_assoc] using SourceOccurrenceExecution.tail ih step

theorem checked_records_have_a_source_execution
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (records : List (Record plan)) (accepted : check plan history records = true) :
    SourceOccurrenceExecution (occurrenceCut plan history)
      (occurrenceCut plan (history ++ advances records)) (advances records) := by
  induction records generalizing history with
  | nil => simpa [advances] using
      (SourceOccurrenceExecution.nil (first := occurrenceCut plan history))
  | cons record rest ih =>
    cases record with
    | poll query event =>
      have checked := (Bool.and_eq_true_iff.mp accepted).2
      simpa only [advances] using ih history checked
    | advance point =>
      have fields := Bool.and_eq_true_iff.mp accepted
      have ready := (Bool.and_eq_true_iff.mp fields.1).1
      have step := a_checked_occurrence_call_appends_exactly_its_source_point
        plan history point ready
      have first := SourceOccurrenceExecution.tail SourceOccurrenceExecution.nil step
      have tail := ih (history ++ [point]) fields.2
      simpa [advances, List.append_assoc] using append_execution first tail

theorem a_poll_does_not_append_a_source_point (query : Query plan)
    (event : Nat) (rest : List (Record plan)) :
    advances (.poll query event :: rest) = advances rest := rfl

/-- Once two read-only queries passed their own obligations, neither changes
the source prefix seen by the suffix. The Rust proposer additionally retains
the exact observed choice visit and arm when merging record attributions. -/
theorem accepted_queries_preserve_the_same_suffix
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (first second : Query plan) (firstEvent secondEvent : Nat)
    (firstReady : (queryCompatible plan first.cut history &&
      admissionReady first.cut history firstEvent) = true)
    (secondReady : (queryCompatible plan second.cut history &&
      admissionReady second.cut history secondEvent) = true)
    (rest : List (Record plan)) :
    check plan history (.poll first firstEvent :: rest) =
      check plan history (.poll second secondEvent :: rest) := by
  simp only [check, firstReady, secondReady]

theorem checking_append_preserves_the_exact_source_prefix
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (first rest : List (Record plan)) :
    check plan history (first ++ rest) =
      (check plan history first && check plan (history ++ advances first) rest) := by
  induction first generalizing history with
  | nil => simp [check, advances]
  | cons record first ih =>
    cases record <;> simp [check, advances, ih, Bool.and_assoc, List.append_assoc]

/-- Reject while constructing the actual source prefix: no choice of a later
suffix can repair that same prefix. Record attribution and completion support
remain separate obligations of the capture constructor and final checker. -/
theorem a_rejected_prefix_has_no_accepted_extension
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (first rest : List (Record plan)) (rejected : check plan history first = false) :
    check plan history (first ++ rest) = false := by
  rw [checking_append_preserves_the_exact_source_prefix, rejected]
  rfl

/-- A reset obliges a later commit to name the same point. If that point has
already committed, no intervening queries, commits or producer reordering can
make this attribution valid. This justifies discarding obsolete visits before
enumerating their suffixes; it does not infer the next visit or weaken checking. -/
theorem an_observed_reset_target_cannot_commit_in_any_suffix
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (between rest : List (Record plan)) (point : SourcePoint)
    (observed : history.contains point = true) :
    check plan history (between ++ .advance point :: rest) = false := by
  have retained : (history ++ advances between).contains point = true := by
    rw [List.contains_append, observed]
    rfl
  have rejected : check plan (history ++ advances between) (.advance point :: rest) = false := by
    simp only [check, SourceOccurrenceCut.ready, occurrenceCut, retained,
      Bool.not_true, Bool.and_false, Bool.false_and]
  rw [checking_append_preserves_the_exact_source_prefix, rejected, Bool.and_false]

theorem each_checked_advance_retains_its_resumption_obligation
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (first rest : List (Record plan)) (point : SourcePoint)
    (accepted : check plan history (first ++ .advance point :: rest) = true) :
    (occurrenceCut plan (history ++ advances first)).ready point = true ∧
      (occurrenceCut plan (history ++ advances first)).resumptionReady point = true := by
  rw [checking_append_preserves_the_exact_source_prefix] at accepted
  have tail := (Bool.and_eq_true_iff.mp accepted).2
  exact Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp tail).1

theorem repeating_a_poll_does_not_duplicate_acceptance
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (query : Query plan) (event : Nat) (rest : List (Record plan)) :
    check plan history (.poll query event :: .poll query event :: rest) =
      check plan history (.poll query event :: rest) := by
  cases compatible : queryCompatible plan query.cut history <;>
    cases ready : admissionReady query.cut history event <;> simp [check, compatible, ready]

theorem an_unobserved_predecessor_rejects_admission
    (plan : SourceOccurrenceCut source) (history : List SourcePoint) (event : Nat)
    (present : prior ∈ sourceVisitPoints plan.path.bindings)
    (depends : sourcePointDepends plan.expanded plan.path.bindings prior (.accepted event) = true)
    (missing : (occurrenceCut plan history).observed prior = false) :
    admissionReady plan history event = false := by
  cases result : admissionReady plan history event with
  | false => rfl
  | true =>
    have fields := Bool.and_eq_true_iff.mp result
    have predecessors := (Bool.and_eq_true_iff.mp fields.1).2
    have priorDone := List.all_eq_true.mp predecessors prior present
    simp only [occurrenceCut] at priorDone
    change history.contains prior = false at missing
    simp only [depends, Bool.not_true, Bool.false_or, missing] at priorDone
    contradiction

/-- A query-compatible completion cannot repair a missing, fixed prefix
predecessor by changing unrelated later choices. The binding-prefix and actor
premises are checked by selection; the Rust pruning is also compared with
complete choice enumeration, rather than assumed to refine this theorem. -/
theorem a_missing_fixed_prefix_predecessor_rejects_every_binding_extension
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (earlier later : List (Nat × Binding)) (id : ActionId)
    (prior target : Action) (event : Nat)
    (extension : plan.path.bindings = earlier ++ later)
    (decoded : action? earlier id = some prior)
    (targetAt : action? plan.path.bindings ⟨event, .send⟩ = some target)
    (sameActor : prior.actor = target.actor)
    (different : id.event ≠ event)
    (ordered : plan.expanded.before id.event event = true)
    (missing : history.contains (.committed id) = false) :
    admissionReady plan history event = false := by
  have priorAt : action? plan.path.bindings id = some prior := by
    rw [extension]
    exact a_decoded_prefix_action_survives_a_binding_extension earlier later id prior decoded
  apply an_unobserved_predecessor_rejects_admission plan history event
    (prior := .committed id)
  · apply canonical_visit_contains_exactly_its_committed_actions.mpr
    exact canonical_visit_actions_are_exactly_decodable.mpr (by simp [priorAt])
  · change precedes plan.expanded plan.path.bindings id ⟨event, .send⟩ = true
    simp [precedes, priorAt, targetAt, sameActor, different, ordered]
  · exact missing

/-- Completion evidence for one already matched call. These positions are in a
proposed causal order, rather than a shared physical clock. -/
structure Call where
  firstPoll : Nat
  publication : Option Nat
  receipt : Option Nat

def supportsAcceptance (call : Call) (boundary : Nat) : Bool :=
  decide (call.firstPoll < boundary) &&
    ((call.publication.isSome || call.receipt.isSome) &&
      (call.publication.all (fun finish => decide (boundary ≤ finish)) &&
        call.receipt.all (fun finish => decide (boundary ≤ finish))))

theorem a_poll_alone_cannot_support_acceptance (first boundary : Nat) :
    supportsAcceptance ⟨first, none, none⟩ boundary = false := by
  simp [supportsAcceptance]

theorem supported_acceptance_is_after_its_poll
    (supported : supportsAcceptance call boundary = true) :
    call.firstPoll < boundary :=
  of_decide_eq_true (Bool.and_eq_true_iff.mp supported).1

theorem supported_acceptance_is_before_publication
    (supported : supportsAcceptance call boundary = true)
    (published : call.publication = some finish) : boundary ≤ finish := by
  have bounds := (Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp supported).2).2
  have bound := (Bool.and_eq_true_iff.mp bounds).1
  simp only [published, Option.all_some] at bound
  exact of_decide_eq_true bound

theorem supported_acceptance_is_before_receipt
    (supported : supportsAcceptance call boundary = true)
    (received : call.receipt = some finish) : boundary ≤ finish := by
  have bounds := (Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp supported).2).2
  have bound := (Bool.and_eq_true_iff.mp bounds).2
  simp only [received, Option.all_some] at bound
  exact of_decide_eq_true bound

theorem receipt_before_publication_can_support_acceptance
    (polled : first < received) (later : received ≤ published) :
    supportsAcceptance ⟨first, some published, some received⟩ received = true := by
  simp [supportsAcceptance, polled, later]

theorem resumption_dependencies_read_only_commits
    (plan : SourceOccurrenceCut source) (left right : SourcePoint → Bool)
    (same : ∀ action, left (.committed action) = right (.committed action))
    (before after : SourcePoint) :
    plan.resumptionDepends left before after = plan.resumptionDepends right before after := by
  cases before with
  | accepted => rfl
  | committed before =>
    cases after with
    | committed => rfl
    | accepted after =>
      cases actorAt : occurrenceActor? plan (.accepted after) with
      | none => simp only [SourceOccurrenceCut.resumptionDepends, actorAt]
      | some actor =>
        simp only [SourceOccurrenceCut.resumptionDepends, actorAt]
        apply congrArg (fun value => occurrenceActor? plan (.committed before) == some actor && value)
        apply congrArg (fun predicate => (plan.unfolding.resumptions 0).any predicate)
        funext scope
        congr 1
        apply congrArg (fun predicate => (occurrenceLocalDomain plan actor).any predicate)
        funext point
        cases point with
        | accepted => rfl
        | committed action => rw [same action]

theorem resumption_queries_read_only_commits
    (plan : SourceOccurrenceCut source) (left right : SourcePoint → Bool)
    (same : ∀ action, left (.committed action) = right (.committed action))
    (point : SourcePoint) :
    ({ plan with observed := left } : SourceOccurrenceCut source).resumptionReady point =
      ({ plan with observed := right } : SourceOccurrenceCut source).resumptionReady point := by
  unfold SourceOccurrenceCut.resumptionReady
  apply congrArg (fun predicate => (sourceVisitPoints plan.path.bindings).all predicate)
  funext before
  change (!plan.resumptionDepends left before point || left before) =
    (!plan.resumptionDepends right before point || right before)
  rw [resumption_dependencies_read_only_commits plan left right same before point]
  cases before with
  | accepted => rfl
  | committed action => rw [same action]

/-- Moving supported acceptances between poll and completion does not change
poll admission when the committed prefix is unchanged. Acceptance does not
activate a retained body. This justifies proposing the earliest boundary after
a checked first poll without assuming that physical acceptance happened there. -/
theorem admission_depends_on_the_committed_prefix
    (plan : SourceOccurrenceCut source) (first second : List SourcePoint)
    (same : ∀ action, first.contains (.committed action) = second.contains (.committed action))
    (event : Nat) : admissionReady plan first event = admissionReady plan second event := by
  have resumed := resumption_queries_read_only_commits plan
    (fun point => first.contains point) (fun point => second.contains point) same (.accepted event)
  dsimp only [admissionReady, occurrenceCut]
  rw [resumed, same ⟨event, .send⟩]
  apply congrArg (fun value : Bool => value &&
    (({ plan with observed := fun point => second.contains point } : SourceOccurrenceCut source).resumptionReady (.accepted event) &&
      !second.contains (.committed ⟨event, .send⟩)))
  apply congrArg (fun value : Bool => (sourceVisitPoints plan.path.bindings).contains (.accepted event) && value)
  apply congrArg (fun predicate => (sourceVisitPoints plan.path.bindings).all predicate)
  funext before
  cases before with
  | accepted => rfl
  | committed action => rw [same action]

theorem each_checked_query_preserves_the_committed_prefix
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (first rest : List (Record plan)) (query : Query plan) (event : Nat)
    (accepted : check plan history (first ++ .poll query event :: rest) = true) :
    queryCompatible plan query.cut (history ++ advances first) = true ∧
      admissionReady query.cut (history ++ advances first) event = true := by
  rw [checking_append_preserves_the_exact_source_prefix] at accepted
  exact Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp
    (Bool.and_eq_true_iff.mp accepted).2).1

theorem a_published_sender_cannot_be_queried_again
    (plan : SourceOccurrenceCut source) (history : List SourcePoint) (event : Nat)
    (published : history.contains (.committed ⟨event, .send⟩) = true) :
    admissionReady plan history event = false := by
  unfold admissionReady
  rw [published]
  simp

private def pendingLeft : Message := ⟨⟨0, 7⟩, ⟨0, 8⟩, 1, .wire 0⟩
private def pendingRight : Message := ⟨⟨0, 7⟩, ⟨0, 8⟩, 2, .wire 0⟩
private def pendingSource : Source :=
  .route (some 77) (.send pendingLeft) (.send pendingRight)
private def pendingPath (right : Bool) : NormalizedPath :=
  if right then ⟨[⟨⟨0, 1, 2⟩, .right⟩], [(1, ⟨pendingRight, 7, 8⟩)]⟩
  else ⟨[⟨⟨0, 1, 2⟩, .left⟩], [(0, ⟨pendingLeft, 7, 8⟩)]⟩
private def pendingNormalization : Normalization :=
  ⟨[], [pendingPath false, pendingPath true]⟩
private def pendingPlan : SourceOccurrenceCut pendingSource := {
  original := pendingNormalization
  originalAccepted := by decide
  expanded := pendingSource
  unfolding := .route (some 77) (.send _) (.send _)
  normalized := pendingNormalization
  accepted := by decide
  sameIssuance := rfl
  path := pendingPath false
  selected := by decide
  separated := by decide
  guarded := by decide
  observed := fun _ => false
}
private def pendingQuery (right : Bool) : Query pendingPlan := {
  path := pendingPath right
  selected := by cases right <;> decide
  separated := by cases right <;> decide
  guarded := by cases right <;> decide
}

/-- The actual Endpoint counterexample: opposite withdrawn attempts need no
source advance. Requiring both polls in one selected path rejected this word. -/
theorem opposite_uncommitted_queries_preserve_the_empty_source_word :
    check pendingPlan [] [.poll (pendingQuery false) 0, .poll (pendingQuery true) 1] = true ∧
      advances [.poll (pendingQuery false) 0, .poll (pendingQuery true) 1] = [] ∧
      admissionReady pendingPlan [] 1 = false := by decide

theorem a_committed_branch_cannot_be_replaced_by_an_opposite_query :
    check pendingPlan [] [.advance (.accepted 0), .advance (.committed ⟨0, .send⟩),
      .poll (pendingQuery true) 1] = false := by decide

/-- Actor-local completion of a selected earlier visit. Acceptance is not a
commit, and an actor absent from this visit cannot obtain vacuous completion.
`visit` is an immutable event set from the checked unfolding, not application
state. The Rust extraction of same-roll/same-enclosing-visit event sets remains
a correspondence obligation, exercised by the actual Endpoint and word tests. -/
def completedVisit (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (actor : Nat) (visit : List Nat) : Bool :=
  let owned := fun point => match point with
    | .accepted _ => false
    | .committed action => visit.contains action.event &&
        decide (occurrenceActor? plan point = some actor)
  let domain := sourceVisitPoints plan.path.bindings
  domain.any owned && domain.all (fun point => !owned point || observed point)

theorem completed_visit_has_a_committed_member
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (actor : Nat) (visit : List Nat)
    (complete : completedVisit plan observed actor visit = true) :
    ∃ action, SourcePoint.committed action ∈ sourceVisitPoints plan.path.bindings ∧
      action.event ∈ visit ∧ occurrenceActor? plan (.committed action) = some actor ∧
      observed (.committed action) = true := by
  have fields := Bool.and_eq_true_iff.mp complete
  obtain ⟨point, member, owned⟩ := List.any_eq_true.mp fields.1
  cases point with
  | accepted => contradiction
  | committed action =>
    have facts := Bool.and_eq_true_iff.mp owned
    have present := List.all_eq_true.mp fields.2 _ member
    exact ⟨action, member, List.contains_iff_mem.mp facts.1,
      of_decide_eq_true facts.2, by simpa only [owned, Bool.not_true, Bool.false_or] using present⟩

theorem completed_visit_requires_every_selected_actor_commit
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (actor : Nat) (visit : List Nat) (action : ActionId)
    (complete : completedVisit plan observed actor visit = true)
    (member : .committed action ∈ sourceVisitPoints plan.path.bindings)
    (inside : action.event ∈ visit)
    (same : occurrenceActor? plan (.committed action) = some actor) :
    observed (.committed action) = true := by
  have all := List.all_eq_true.mp (Bool.and_eq_true_iff.mp complete).2 _ member
  simpa only [List.contains_iff_mem.mpr inside, same, decide_true, Bool.and_self,
    Bool.not_true, Bool.false_or] using all

theorem acceptance_alone_cannot_complete_a_visit
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (actor : Nat) (visit : List Nat)
    (noCommits : ∀ action, observed (.committed action) = false) :
    completedVisit plan observed actor visit = false := by
  apply Bool.eq_false_iff.mpr
  intro complete
  obtain ⟨action, _, _, _, done⟩ :=
    completed_visit_has_a_committed_member plan observed actor visit complete
  rw [noCommits action] at done
  contradiction

theorem a_missing_selected_actor_commit_refutes_completion
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (actor : Nat) (visit : List Nat) (action : ActionId)
    (member : .committed action ∈ sourceVisitPoints plan.path.bindings)
    (inside : action.event ∈ visit)
    (same : occurrenceActor? plan (.committed action) = some actor)
    (missing : observed (.committed action) = false) :
    completedVisit plan observed actor visit = false := by
  apply Bool.eq_false_iff.mpr
  intro complete
  have done := completed_visit_requires_every_selected_actor_commit
    plan observed actor visit action complete member inside same
  rw [missing] at done
  contradiction

/-- Only a different event's incoming receipt may use completion credit.
Eligible earlier visits are derived from the checked source invocation. This
component theorem does not certify arbitrary caller-supplied event sets or
establish the complete Rust/source refinement. -/
def incomingCredit (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (eligible : SourcePoint → SourcePoint → List (List Nat)) :
    SourcePoint → SourcePoint → Bool
  | .committed prior, .committed target =>
      decide (target.side = .receive ∧ prior.event ≠ target.event) &&
        match occurrenceActor? plan (.committed target) with
        | none => false
        | some actor =>
            decide (occurrenceActor? plan (.committed prior) = some actor) &&
              (eligible (.committed prior) (.committed target)).any
                (completedVisit plan observed actor)
  | _, _ => false

def creditDepends (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (eligible : SourcePoint → SourcePoint → List (List Nat))
    (prior target : SourcePoint) : Bool :=
  sourcePointDepends plan.expanded plan.path.bindings prior target &&
    !incomingCredit plan observed eligible prior target

theorem outgoing_acceptance_keeps_every_source_dependency
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (eligible : SourcePoint → SourcePoint → List (List Nat)) (prior : SourcePoint) (event : Nat) :
    creditDepends plan observed eligible prior (.accepted event) =
      sourcePointDepends plan.expanded plan.path.bindings prior (.accepted event) := by
  cases prior <;> simp [creditDepends, incomingCredit]

theorem local_actions_keep_every_source_dependency
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (eligible : SourcePoint → SourcePoint → List (List Nat)) (prior : SourcePoint) (event : Nat) :
    creditDepends plan observed eligible prior (.committed ⟨event, .local⟩) =
      sourcePointDepends plan.expanded plan.path.bindings prior (.committed ⟨event, .local⟩) := by
  cases prior <;> simp [creditDepends, incomingCredit]

theorem an_incoming_receipt_keeps_its_acceptance_dependency
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (eligible : SourcePoint → SourcePoint → List (List Nat)) (event : Nat) :
    creditDepends plan observed eligible (.accepted event) (.committed ⟨event, .receive⟩) = true := by
  simp [creditDepends, sourcePointDepends, incomingCredit]

theorem an_incoming_receipt_keeps_the_same_events_colocated_publication
    (plan : SourceOccurrenceCut source) (observed : SourcePoint → Bool)
    (eligible : SourcePoint → SourcePoint → List (List Nat)) (event : Nat) :
    creditDepends plan observed eligible (.committed ⟨event, .send⟩) (.committed ⟨event, .receive⟩) =
      sourcePointDepends plan.expanded plan.path.bindings
        (.committed ⟨event, .send⟩) (.committed ⟨event, .receive⟩) := by
  simp [creditDepends, incomingCredit]

end Hibana.Epf.CaptureExecution
