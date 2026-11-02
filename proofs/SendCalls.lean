import Std

namespace Hibana.Epf.SendCalls

/-- Positions visited while checking poll chains and publications. This is
retrospective certificate checking, not endpoint progress or ownership. -/
def markPositions (seen : List Nat) : List Nat → Option (List Nat)
  | [] => some seen
  | position :: rest =>
      if seen.contains position then none else markPositions (position :: seen) rest

theorem checked_marks_preserve_unique_positions
    (unique : seen.Nodup) (checked : markPositions seen positions = some result) :
    result.Nodup := by
  induction positions generalizing seen with
  | nil =>
    have same : seen = result := Option.some.inj checked
    subst result
    exact unique
  | cons position rest ih =>
    cases present : seen.contains position with
    | false =>
      have absent : position ∉ seen := by
        intro member
        have found : seen.contains position = true := List.contains_iff_mem.mpr member
        simp only [present, Bool.false_eq_true] at found
      exact ih (List.nodup_cons.mpr ⟨absent, unique⟩)
        (by simpa only [markPositions, present, Bool.false_eq_true, ↓reduceIte] using checked)
    | true => simp only [markPositions, present, ↓reduceIte, reduceCtorEq] at checked

theorem checked_marks_keep_exactly_the_input_and_prior_positions
    (checked : markPositions seen positions = some result) :
    result = positions.reverse ++ seen := by
  induction positions generalizing seen with
  | nil =>
    have same : seen = result := Option.some.inj checked
    simp only [List.reverse_nil, List.nil_append, same]
  | cons position rest ih =>
    cases present : seen.contains position with
    | false =>
      have tail : markPositions (position :: seen) rest = some result := by
        simpa only [markPositions, present, Bool.false_eq_true, ↓reduceIte] using checked
      simpa only [List.reverse_cons, List.append_assoc, List.singleton_append] using ih tail
    | true => simp only [markPositions, present, ↓reduceIte, reduceCtorEq] at checked

theorem a_successful_prefix_check_never_reuses_a_record_position
    (checked : markPositions [] positions = some result) : positions.Nodup := by
  have unique := checked_marks_preserve_unique_positions (List.nodup_nil) checked
  rw [checked_marks_keep_exactly_the_input_and_prior_positions checked] at unique
  simp only [List.append_nil] at unique
  change positions.reverse.Pairwise (· ≠ ·) at unique
  exact (List.pairwise_reverse.mp unique).imp (fun {_ _} different => Ne.symm different)

theorem an_already_seen_publication_position_is_rejected
    (present : publication ∈ seen) :
    markPositions seen (publication :: rest) = none := by
  have found : seen.contains publication = true := List.contains_iff_mem.mpr present
  simp only [markPositions, found, ↓reduceIte]

theorem word_and_bit_coordinates_are_injective
    {first second width : Nat}
    (sameWord : first / width = second / width)
    (sameBit : first % width = second % width) : first = second := by
  calc
    first = first % width + width * (first / width) := (Nat.mod_add_div first width).symm
    _ = second % width + width * (second / width) := by rw [sameWord, sameBit]
    _ = second := Nat.mod_add_div second width

#print axioms checked_marks_preserve_unique_positions
#print axioms checked_marks_keep_exactly_the_input_and_prior_positions
#print axioms a_successful_prefix_check_never_reuses_a_record_position
#print axioms an_already_seen_publication_position_is_rejected
#print axioms word_and_bit_coordinates_are_injective

end Hibana.Epf.SendCalls
