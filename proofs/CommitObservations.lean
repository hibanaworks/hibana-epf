import Hibana.SourceOccurrenceTrace

namespace Hibana.Epf
open EndpointDelegation

/-- Endpoint commit observations omit transport acceptance. This is an erasure
of the established source semantics, not another protocol transition system. -/
def endpointCommits : List SourcePoint → List ActionId
  | [] => []
  | .accepted _ :: rest => endpointCommits rest
  | .committed action :: rest => action :: endpointCommits rest

theorem endpoint_projection_preserves_append (first rest : List SourcePoint) :
    endpointCommits (first ++ rest) = endpointCommits first ++ endpointCommits rest := by
  induction first with
  | nil => rfl
  | cons point first ih =>
    cases point <;> simp [endpointCommits, ih]

private def message : Message := ⟨⟨0, 0⟩, ⟨0, 1⟩, 7, .wire 0⟩
private def source : Source := .send message
private def bindings : List (Nat × Binding) := [(0, ⟨message, 0, 1⟩)]
private def normal : Normalization := ⟨[], [⟨[], bindings⟩]⟩
private def plan : SourceOccurrenceCut source := {
  original := normal
  originalAccepted := by decide
  expanded := source
  unfolding := .send message
  normalized := normal
  accepted := by decide
  sameIssuance := rfl
  path := ⟨[], bindings⟩
  selected := by decide
  separated := by decide
  guarded := by decide
  observed := fun _ => false
}

private def receiveFirst : List SourcePoint :=
  [.accepted 0, .committed ⟨0, .receive⟩, .committed ⟨0, .send⟩]
private def publishFirst : List SourcePoint :=
  [.accepted 0, .committed ⟨0, .send⟩, .committed ⟨0, .receive⟩]

theorem acceptance_enables_both_completion_sides :
    (occurrenceCut plan [.accepted 0]).ready (.committed ⟨0, .receive⟩) = true ∧
    (occurrenceCut plan [.accepted 0]).ready (.committed ⟨0, .send⟩) = true := by decide

theorem a_receipt_needs_acceptance :
    (occurrenceCut plan []).ready (.committed ⟨0, .receive⟩) = false := by decide

theorem receiver_before_publication_has_a_source_execution :
    SourceOccurrenceExecution (occurrenceCut plan []) (occurrenceCut plan receiveFirst)
      receiveFirst := by
  have first := a_checked_occurrence_call_appends_exactly_its_source_point
    plan [] (.accepted 0) (by decide)
  have second := a_checked_occurrence_call_appends_exactly_its_source_point
    plan [.accepted 0] (.committed ⟨0, .receive⟩) (by decide)
  have third := a_checked_occurrence_call_appends_exactly_its_source_point
    plan [.accepted 0, .committed ⟨0, .receive⟩] (.committed ⟨0, .send⟩) (by decide)
  exact .tail (.tail (.tail .nil first) second) third

theorem publication_before_receiver_has_a_source_execution :
    SourceOccurrenceExecution (occurrenceCut plan []) (occurrenceCut plan publishFirst)
      publishFirst := by
  have first := a_checked_occurrence_call_appends_exactly_its_source_point
    plan [] (.accepted 0) (by decide)
  have second := a_checked_occurrence_call_appends_exactly_its_source_point
    plan [.accepted 0] (.committed ⟨0, .send⟩) (by decide)
  have third := a_checked_occurrence_call_appends_exactly_its_source_point
    plan [.accepted 0, .committed ⟨0, .send⟩] (.committed ⟨0, .receive⟩) (by decide)
  exact .tail (.tail (.tail .nil first) second) third

theorem a_legal_endpoint_projection_can_start_with_receipt :
    endpointCommits receiveFirst = [⟨0, .receive⟩, ⟨0, .send⟩] := rfl

theorem omitting_acceptance_has_the_same_endpoint_projection :
    endpointCommits receiveFirst =
      endpointCommits [.committed ⟨0, .receive⟩, .committed ⟨0, .send⟩] := rfl

private def gate : Message := ⟨⟨0, 0⟩, ⟨0, 0⟩, 6, .wire 0⟩
private def orderedSource : Source := .seq (.send gate) (.send message)
private def orderedBindings : List (Nat × Binding) :=
  [(0, ⟨gate, 0, 0⟩), (1, ⟨message, 0, 1⟩)]
private def orderedNormalization : Normalization := ⟨[], [⟨[], orderedBindings⟩]⟩
private def orderedPlan : SourceOccurrenceCut orderedSource := {
  original := orderedNormalization
  originalAccepted := by decide
  expanded := orderedSource
  unfolding := .seq (.send gate) (.send message)
  normalized := orderedNormalization
  accepted := by decide
  sameIssuance := rfl
  path := ⟨[], orderedBindings⟩
  selected := by decide
  separated := by decide
  guarded := by decide
  observed := fun _ => false
}
private def authorizedSend : List SourcePoint := [
  .committed ⟨0, .local⟩, .accepted 1,
  .committed ⟨1, .receive⟩, .committed ⟨1, .send⟩]
private def earlySend : List SourcePoint := [
  .accepted 1, .committed ⟨0, .local⟩,
  .committed ⟨1, .receive⟩, .committed ⟨1, .send⟩]

theorem a_send_after_its_source_predecessor_has_a_complete_execution :
    SourceOccurrenceExecution (occurrenceCut orderedPlan [])
      (occurrenceCut orderedPlan authorizedSend) authorizedSend := by
  have first := a_checked_occurrence_call_appends_exactly_its_source_point
    orderedPlan [] (.committed ⟨0, .local⟩) (by decide)
  have second := a_checked_occurrence_call_appends_exactly_its_source_point
    orderedPlan [.committed ⟨0, .local⟩] (.accepted 1) (by decide)
  have third := a_checked_occurrence_call_appends_exactly_its_source_point
    orderedPlan [.committed ⟨0, .local⟩, .accepted 1] (.committed ⟨1, .receive⟩) (by decide)
  have fourth := a_checked_occurrence_call_appends_exactly_its_source_point
    orderedPlan [.committed ⟨0, .local⟩, .accepted 1, .committed ⟨1, .receive⟩]
    (.committed ⟨1, .send⟩) (by decide)
  exact .tail (.tail (.tail (.tail .nil first) second) third) fourth

theorem sending_before_that_predecessor_fails_the_source_check :
    (occurrenceCut orderedPlan []).ready (.accepted 1) = false := by decide

theorem delayed_publication_can_hide_an_early_send_in_the_commit_projection :
    endpointCommits authorizedSend = endpointCommits earlySend := rfl

#print axioms endpoint_projection_preserves_append
#print axioms acceptance_enables_both_completion_sides
#print axioms a_receipt_needs_acceptance
#print axioms receiver_before_publication_has_a_source_execution
#print axioms publication_before_receiver_has_a_source_execution
#print axioms a_legal_endpoint_projection_can_start_with_receipt
#print axioms omitting_acceptance_has_the_same_endpoint_projection
#print axioms a_send_after_its_source_predecessor_has_a_complete_execution
#print axioms sending_before_that_predecessor_fails_the_source_check
#print axioms delayed_publication_can_hide_an_early_send_in_the_commit_projection

end Hibana.Epf
