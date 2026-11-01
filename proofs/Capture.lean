import Std

namespace Hibana.Epf.Capture

def numbered (index : Nat) : List Nat → Bool
  | [] => true
  | ordinal :: rest => Nat.beq ordinal index && numbered (index + 1) rest

/-- The end is independently observed at the producer, not derived from the list. -/
def complete (ordinals : List Nat) (checkpoint : Nat) : Bool :=
  Nat.beq ordinals.length checkpoint && numbered 0 ordinals

private theorem numbered_is_range (ordinals : List Nat) (index : Nat)
    (checked : numbered index ordinals = true) :
    ordinals = List.range' index ordinals.length := by
  induction ordinals generalizing index with
  | nil => rfl
  | cons ordinal rest ih =>
    have fields := Bool.and_eq_true_iff.mp checked
    have same : ordinal = index := Nat.eq_of_beq_eq_true fields.1
    subst ordinal
    change index :: rest = index :: List.range' (index + 1) rest.length
    exact congrArg (List.cons index) (ih (index + 1) fields.2)

private theorem numbered_range (count index : Nat) :
    numbered index (List.range' index count) = true := by
  exact Nat.rec
    (motive := fun count => ∀ index,
      numbered index (List.range' index count) = true)
    (fun _ => rfl)
    (fun count ih index => by
      change (Nat.beq index index && numbered (index + 1) (List.range' (index + 1) count)) = true
      simpa only [Nat.beq_refl, Bool.true_and] using ih (index + 1))
    count index

theorem a_checked_prefix_contains_every_ordinal
    (checked : complete ordinals checkpoint = true) :
    ordinals = List.range' 0 checkpoint := by
  have fields := Bool.and_eq_true_iff.mp checked
  have count : ordinals.length = checkpoint := Nat.eq_of_beq_eq_true fields.1
  simpa only [count] using numbered_is_range ordinals 0 fields.2

theorem every_exact_prefix_passes (checkpoint : Nat) :
    complete (List.range' 0 checkpoint) checkpoint = true := by
  simp only [complete, List.length_range', Nat.beq_refl, Bool.true_and]
  exact numbered_range checkpoint 0

theorem a_missing_suffix_cannot_match_the_saved_checkpoint
    (missing : ordinals.length < checkpoint) :
    complete ordinals checkpoint = false := by
  have different : ordinals.length ≠ checkpoint := Nat.ne_of_lt missing
  have firstFalse : Nat.beq ordinals.length checkpoint = false := by
    cases value : Nat.beq ordinals.length checkpoint with
    | false => rfl
    | true => exact False.elim (different (Nat.eq_of_beq_eq_true value))
  simp only [complete, firstFalse, Bool.false_and]

theorem one_prefix_cannot_match_two_checkpoints
    (first : complete ordinals firstEnd = true)
    (second : complete ordinals secondEnd = true) : firstEnd = secondEnd := by
  have firstCount : ordinals.length = firstEnd := Nat.eq_of_beq_eq_true
    (Bool.and_eq_true_iff.mp first).1
  have secondCount : ordinals.length = secondEnd := Nat.eq_of_beq_eq_true
    (Bool.and_eq_true_iff.mp second).1
  exact firstCount.symm.trans secondCount

#print axioms a_checked_prefix_contains_every_ordinal
#print axioms every_exact_prefix_passes
#print axioms a_missing_suffix_cannot_match_the_saved_checkpoint
#print axioms one_prefix_cannot_match_two_checkpoints

end Hibana.Epf.Capture
