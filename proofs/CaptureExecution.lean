import Hibana.SourceOccurrenceTrace

namespace Hibana.Epf.CaptureExecution
open EndpointDelegation

/-- Interpret a poll as a query, and a supported acceptance or actual Endpoint
commit as a source advance. Record matching and transport evidence must be
checked separately; this does not model an application scheduler. -/
inductive Record where
  | poll (event : Nat)
  | advance (point : SourcePoint)

def advances : List Record → List SourcePoint
  | [] => []
  | .poll _ :: rest => advances rest
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
    cut.resumptionReady (.accepted event)

def check (plan : SourceOccurrenceCut source) (history : List SourcePoint) :
    List Record → Bool
  | [] => true
  | .poll event :: rest => admissionReady plan history event && check plan history rest
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
    (records : List Record) (accepted : check plan history records = true) :
    SourceOccurrenceExecution (occurrenceCut plan history)
      (occurrenceCut plan (history ++ advances records)) (advances records) := by
  induction records generalizing history with
  | nil => simpa [advances] using
      (SourceOccurrenceExecution.nil (first := occurrenceCut plan history))
  | cons record rest ih =>
    cases record with
    | poll event =>
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

theorem a_poll_does_not_append_a_source_point (event : Nat) (rest : List Record) :
    advances (.poll event :: rest) = advances rest := rfl

theorem checking_append_preserves_the_exact_source_prefix
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (first rest : List Record) :
    check plan history (first ++ rest) =
      (check plan history first && check plan (history ++ advances first) rest) := by
  induction first generalizing history with
  | nil => simp [check, advances]
  | cons record first ih =>
    cases record <;> simp [check, advances, ih, Bool.and_assoc, List.append_assoc]

theorem each_checked_advance_retains_its_resumption_obligation
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (first rest : List Record) (point : SourcePoint)
    (accepted : check plan history (first ++ .advance point :: rest) = true) :
    (occurrenceCut plan (history ++ advances first)).ready point = true ∧
      (occurrenceCut plan (history ++ advances first)).resumptionReady point = true := by
  rw [checking_append_preserves_the_exact_source_prefix] at accepted
  have tail := (Bool.and_eq_true_iff.mp accepted).2
  exact Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp tail).1

theorem repeating_a_poll_does_not_duplicate_acceptance
    (plan : SourceOccurrenceCut source) (history : List SourcePoint)
    (event : Nat) (rest : List Record) :
    check plan history (.poll event :: .poll event :: rest) =
      check plan history (.poll event :: rest) := by
  cases ready : admissionReady plan history event <;> simp [check, ready]

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

#print axioms checked_records_have_a_source_execution
#print axioms a_poll_does_not_append_a_source_point
#print axioms checking_append_preserves_the_exact_source_prefix
#print axioms each_checked_advance_retains_its_resumption_obligation
#print axioms repeating_a_poll_does_not_duplicate_acceptance
#print axioms an_unobserved_predecessor_rejects_admission
#print axioms a_poll_alone_cannot_support_acceptance
#print axioms supported_acceptance_is_after_its_poll
#print axioms supported_acceptance_is_before_publication
#print axioms supported_acceptance_is_before_receipt
#print axioms receipt_before_publication_can_support_acceptance

end Hibana.Epf.CaptureExecution
