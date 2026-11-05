import Hibana.SourceOccurrenceTrace

namespace Hibana.Epf.CaptureExecution
open EndpointDelegation

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

/-- No choice of checked path can admit a send occurrence already published
in this same unfolding. An uncommitted acceptance alone is not publication. -/
theorem a_published_send_is_not_admission_ready
    (plan : SourceOccurrenceCut source) (points : List SourcePoint) (event : Nat)
    (published : points.contains (.committed ⟨event, .send⟩) = true) :
    admissionReady plan points event = false := by
  unfold admissionReady
  simp only [published, Bool.not_true, Bool.and_false]

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

end Hibana.Epf.CaptureExecution
