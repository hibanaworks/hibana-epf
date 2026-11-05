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

/-- An observed roll-reset claim; validation must additionally establish its
membership in the compiled source. This is history, not execution authority. -/
structure ResetClaim where
  actor : Nat
  session : Nat
  start : Nat
  stop : Nat
  ordinal : Nat

def resetBetween (resets : List ResetClaim) (actor session source before after : Nat) : Bool :=
  resets.any fun reset => decide (
    reset.actor = actor ∧ reset.session = session ∧
    reset.start ≤ source ∧ source < reset.stop ∧
    before < reset.ordinal ∧ reset.ordinal < after)

theorem a_changed_poll_requires_its_reset
    (checked : resetBetween resets actor session source before after = true) :
    ∃ reset ∈ resets, reset.actor = actor ∧ reset.session = session ∧
      reset.start ≤ source ∧ source < reset.stop ∧
      before < reset.ordinal ∧ reset.ordinal < after := by
  obtain ⟨reset, present, checked⟩ := List.any_eq_true.mp checked
  exact ⟨reset, present, of_decide_eq_true checked⟩

theorem unrelated_resets_cannot_explain_a_change
    (unrelated : ∀ reset ∈ resets,
      reset.actor ≠ actor ∨ reset.session ≠ session ∨ source < reset.start ∨
      reset.stop ≤ source ∨ reset.ordinal ≤ before ∨ after ≤ reset.ordinal) :
    resetBetween resets actor session source before after = false := by
  cases checked : resetBetween resets actor session source before after with
  | false => rfl
  | true =>
    obtain ⟨reset, present, sameActor, sameSession, start, stop, first, last⟩ :=
      a_changed_poll_requires_its_reset checked
    have outside := unrelated reset present
    rcases outside with otherActor | otherSession | beforeStart | afterStop | earlier | later
    · exact False.elim (otherActor sameActor)
    · exact False.elim (otherSession sameSession)
    · omega
    · omega
    · omega
    · omega

/-- Exact fixed-width masks, for every word width, including Rust's 32- and
64-bit targets. The library definition is `1 <<< index`. -/
theorem mask_is_nonzero (inside : index < width) :
    BitVec.twoPow width index ≠ 0 := by
  intro zero
  have bit := congrArg (fun value : BitVec width => value.getLsbD index) zero
  simp [inside] at bit

theorem marking_sets_the_mask (value mask : BitVec width) :
    (value ||| mask) &&& mask = mask := by
  apply BitVec.eq_of_getLsbD_eq
  intro bit _
  simp only [BitVec.getLsbD_and, BitVec.getLsbD_or]
  cases value.getLsbD bit <;> cases mask.getLsbD bit <;> rfl

theorem marking_keeps_other_bits (value mask : BitVec width) (bit : Nat)
    (unmarked : mask.getLsbD bit = false) :
    (value ||| mask).getLsbD bit = value.getLsbD bit := by
  simp only [BitVec.getLsbD_or, unmarked, Bool.or_false]

theorem masks_are_injective (firstInside : first < width)
    (same : BitVec.twoPow width first = BitVec.twoPow width second) : first = second := by
  have bit := congrArg (fun value : BitVec width => value.getLsbD first) same
  simpa [BitVec.getLsbD_twoPow, firstInside, eq_comm] using bit.symm

theorem different_masks_are_disjoint (different : first ≠ second) :
    BitVec.twoPow width first &&& BitVec.twoPow width second = 0 := by
  apply BitVec.eq_of_getLsbD_eq
  intro bit _
  by_cases same : first = bit
  · subst bit
    simp [BitVec.getLsbD_twoPow, Ne.symm different]
  · simp [BitVec.getLsbD_twoPow, same]

theorem truncating_an_index_loses_its_bit (wide : 8 < width) :
    BitVec.twoPow width (8 % 8) &&& BitVec.twoPow width 8 = 0 ∧
      BitVec.twoPow width 8 ≠ 0 := by
  exact ⟨different_masks_are_disjoint (by decide), mask_is_nonzero wide⟩

end Hibana.Epf.SendCalls
