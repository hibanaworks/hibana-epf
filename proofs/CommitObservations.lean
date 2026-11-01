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

#print axioms endpoint_projection_preserves_append
#print axioms acceptance_enables_both_completion_sides
#print axioms a_receipt_needs_acceptance
#print axioms receiver_before_publication_has_a_source_execution
#print axioms publication_before_receiver_has_a_source_execution
#print axioms a_legal_endpoint_projection_can_start_with_receipt
#print axioms omitting_acceptance_has_the_same_endpoint_projection

end Hibana.Epf
