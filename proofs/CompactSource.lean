import Hibana.SourceOccurrenceProgress

namespace Hibana.Epf.CompactSource
open EndpointDelegation

/-- Borrowing an unchanged subtree denotes the existing one-copy unfolding,
not a new rule for enabling or permanently closing a roll. -/
def witness (source : Source) : SourceUnfolding source source.oneCopy :=
  SourceUnfolding.oneCopy source

theorem event_count_is_unchanged (source : Source) :
    source.oneCopy.eventCount = source.eventCount := by
  induction source <;> simp_all [Source.oneCopy, Source.eventCount]

theorem messages_and_source_identities_are_unchanged (source : Source) (start : Nat) :
    source.oneCopy.messageEntries start = source.messageEntries start := by
  induction source generalizing start <;>
    simp_all [Source.oneCopy, Source.messageEntries, event_count_is_unchanged]

theorem sequence_order_is_unchanged (source : Source) (first second : Nat) :
    source.oneCopy.before first second = source.before first second := by
  induction source generalizing first second <;>
    simp_all [Source.oneCopy, Source.before, event_count_is_unchanged]

theorem witness_retains_every_original_occurrence (source : Source) (start : Nat) :
    (witness source).occurrences start = source.messageEntries start := by
  induction source generalizing start
  case roll body ih => exact ih start
  all_goals
    simp_all [witness, SourceUnfolding.oneCopy, SourceUnfolding.occurrences,
      Source.messageEntries]

/-- Mapping an event through the removal of an inserted body. Inserted events
occupy the original focus's side of every enclosing binary subtree. -/
def collapseInsertion (start added event : Nat) : Nat :=
  if event < start then event else start + (event - (start + added))

theorem collapse_before_cut (start added event cut : Nat) (h : cut ≤ start) :
    collapseInsertion start added event < cut ↔ event < cut := by
  unfold collapseInsertion
  split <;> constructor <;> intro bound <;> omega

theorem collapse_after_cut (start added event cut : Nat) (h : start < cut) :
    collapseInsertion start added event < cut ↔ event < cut + added := by
  unfold collapseInsertion
  split <;> constructor <;> intro bound <;> omega

/-- The boundary search used after structural event classification. -/
def splitSearch (cut first last : Nat) : Nat :=
  if h : first < last then
    let middle := first + (last - first) / 2
    if middle < cut then splitSearch cut (middle + 1) last
    else splitSearch cut first middle
  else first
termination_by last - first
decreasing_by all_goals omega

theorem split_search_exact (cut first last : Nat)
    (lower : first ≤ cut) (upper : cut ≤ last) :
    splitSearch cut first last = cut := by
  unfold splitSearch
  split
  next h =>
    dsimp only
    split
    next middle => exact split_search_exact cut _ _ (by omega) upper
    next middle => exact split_search_exact cut _ _ lower (by omega)
  next h => omega
termination_by last - first
decreasing_by all_goals omega

/-- Binary source nodes are indexed by their split between message leaves.
Roll is unary and occupies no binary slot. -/
def binaryBoundaries : Source → Nat → List Nat
  | .send _, _ => []
  | .seq left right, start
  | .par left right, start
  | .route _ left right, start =>
      binaryBoundaries left start ++ [start + left.eventCount] ++
        binaryBoundaries right (start + left.eventCount)
  | .roll body, start => binaryBoundaries body start

theorem source_has_a_message (source : Source) : 0 < source.eventCount := by
  induction source <;> simp_all [Source.eventCount] <;> omega

private theorem join_boundary_ranges (start left right : Nat)
    (positive₁ : 0 < left) (positive₂ : 0 < right) :
    List.range' (start + 1) (left - 1) ++ [start + left] ++
      List.range' (start + left + 1) (right - 1) =
      List.range' (start + 1) (left + right - 1) := by
  have leadingRange : List.range' (start + 1) (left - 1) ++ [start + left] =
      List.range' (start + 1) left := by
    have point : start + left = start + 1 + (left - 1) := by omega
    have size : left - 1 + 1 = left := by omega
    simpa [point, size] using
      (List.range'_concat (s := start + 1) (n := left - 1) (step := 1)).symm
  rw [leadingRange]
  have shifted : start + left + 1 = start + 1 + left := by omega
  rw [shifted, List.range'_append_1]
  congr 1
  omega

theorem binary_boundaries_fill_every_internal_slot (source : Source) (start : Nat) :
    binaryBoundaries source start = List.range' (start + 1) (source.eventCount - 1) := by
  induction source generalizing start with
  | send => simp [binaryBoundaries, Source.eventCount]
  | roll body ih => exact ih start
  | seq left right ih₁ ih₂ | par left right ih₁ ih₂ | route _ left right ih₁ ih₂ =>
      simp only [binaryBoundaries, Source.eventCount, ih₁, ih₂]
      exact join_boundary_ranges start left.eventCount right.eventCount
        (source_has_a_message left) (source_has_a_message right)

theorem binary_boundary_slots_are_unique (source : Source) (start : Nat) :
    (binaryBoundaries source start).Nodup := by
  rw [binary_boundaries_fill_every_internal_slot]
  exact List.nodup_range'

theorem binary_boundary_storage_is_exact (source : Source) (start : Nat) :
    (binaryBoundaries source start).length = source.eventCount - 1 := by
  rw [binary_boundaries_fill_every_internal_slot]
  exact List.length_range'

/-- A live occurrence in a checked selected arm already identifies that arm;
searching its inactive sibling cannot add information. -/
theorem a_live_occurrence_identifies_its_selected_arm
    (start split stop event : Nat) (right : Bool)
    (inside : if right then split ≤ event ∧ event < stop
      else start ≤ event ∧ event < split) :
    decide (split ≤ event) = right := by
  cases right <;> simp_all <;> omega

/-- Independent proof children form cuts in proof-leaf order. Insertion can
permute source positions without splitting these proof-order intervals. -/
def separatedByCut (cuts : Nat → Nat → Nat → Prop) (first second : Nat) : Prop :=
  ∃ left split right, cuts left split right ∧
    left ≤ first ∧ first < split ∧ split ≤ second ∧ second < right

theorem a_cut_separating_endpoints_separates_an_adjacent_subinterval
    (cuts : Nat → Nat → Nat → Prop) {first middle last : Nat}
    (ordered₁ : first < middle) (ordered₂ : middle < last)
    (separated : separatedByCut cuts first last) :
    separatedByCut cuts first middle ∨ separatedByCut cuts middle last := by
  obtain ⟨left, split, right, cut, bounds⟩ := separated
  by_cases side : middle < split
  · right
    exact ⟨left, split, right, cut, by omega⟩
  · left
    exact ⟨left, split, right, cut, by omega⟩

def orderedCompatible (cuts : Nat → Nat → Nat → Prop) (first second : Nat) : Prop :=
  first < second ∧ ¬ separatedByCut cuts first second

theorem ordered_compatibility_is_transitive
    (cuts : Nat → Nat → Nat → Prop) {first middle last : Nat}
    (left : orderedCompatible cuts first middle)
    (right : orderedCompatible cuts middle last) :
    orderedCompatible cuts first last := by
  refine ⟨Nat.lt_trans left.1 right.1, ?_⟩
  intro separated
  rcases a_cut_separating_endpoints_separates_an_adjacent_subinterval
      cuts left.1 right.1 separated with before | after
  · exact left.2 before
  · exact right.2 after

/-- A mathematical adjacent-pair scan, with no protocol state or authority. -/
def adjacent {α : Type} (relation : α → α → Prop) : List α → Prop
  | [] => True
  | [_] => True
  | first :: second :: rest => relation first second ∧ adjacent relation (second :: rest)

theorem adjacent_transitive_checks_cover_every_pair {α : Type}
    (relation : α → α → Prop)
    (transitive : ∀ a b c, relation a b → relation b c → relation a c)
    (positions : List α) : adjacent relation positions → positions.Pairwise relation := by
  induction positions with
  | nil => intro _; exact List.Pairwise.nil
  | cons first rest ih =>
      intro checked
      apply List.pairwise_cons.mpr
      cases rest with
      | nil => exact ⟨by simp, List.Pairwise.nil⟩
      | cons second tail =>
          have parts : relation first second ∧ adjacent relation (second :: tail) := checked
          have remaining := ih parts.2
          have links := (List.pairwise_cons.mp remaining).1
          refine ⟨?_, remaining⟩
          intro last member
          rcases List.mem_cons.mp member with equal | inTail
          · subst last
            exact parts.1
          · exact transitive first second last parts.1 (links last inTail)

theorem every_pair_includes_the_adjacent_checks {α : Type}
    (relation : α → α → Prop) (positions : List α) :
    positions.Pairwise relation → adjacent relation positions := by
  induction positions with
  | nil => intro _; trivial
  | cons first rest ih =>
      intro checked
      cases rest with
      | nil => trivial
      | cons second tail =>
          have parts := List.pairwise_cons.mp checked
          exact ⟨parts.1 second (by simp), ih parts.2⟩

/-- Applied separately to the sorted occurrences of each physical actor, this
permits adjacent checks while retaining every independent-visit exclusion. -/
theorem independent_cuts_require_only_adjacent_actor_occurrences
    (cuts : Nat → Nat → Nat → Prop) (positions : List Nat) :
    positions.Pairwise (orderedCompatible cuts) ↔ adjacent (orderedCompatible cuts) positions := by
  constructor
  · exact every_pair_includes_the_adjacent_checks _ positions
  · exact adjacent_transitive_checks_cover_every_pair (orderedCompatible cuts)
      (fun first middle last a b =>
        ordered_compatibility_is_transitive cuts
          (first := first) (middle := middle) (last := last) a b) positions

/-- Reindex the same transfer/use exclusions from sorted pairs to transfers.
This changes enumeration, not the ownership or source-order predicates. -/
theorem sorted_transfer_pairs_equal_transfer_rows
    (active transfer : Nat → Prop) (uses : Nat → Nat → Prop)
    (unordered : Nat → Nat → Prop) :
    (∃ first second, active first ∧ active second ∧ first < second ∧
      unordered first second ∧
      ((transfer first ∧ uses second first) ∨ (transfer second ∧ uses first second))) ↔
    (∃ loan other, active loan ∧ active other ∧ loan ≠ other ∧
      unordered (min loan other) (max loan other) ∧ transfer loan ∧ uses other loan) := by
  constructor
  · rintro ⟨first, second, a, b, order, before, affected⟩
    rcases affected with left | right
    · exact ⟨first, second, a, b, by omega,
        by simpa [Nat.min_eq_left (Nat.le_of_lt order), Nat.max_eq_right (Nat.le_of_lt order)] using before,
        left⟩
    · exact ⟨second, first, b, a, by omega,
        by simpa [Nat.min_eq_right (Nat.le_of_lt order), Nat.max_eq_left (Nat.le_of_lt order)] using before,
        right⟩
  · rintro ⟨loan, other, a, b, distinct, before, moved, used⟩
    by_cases order : loan < other
    · exact ⟨loan, other, a, b, order,
        by simpa [Nat.min_eq_left (Nat.le_of_lt order), Nat.max_eq_right (Nat.le_of_lt order)] using before,
        Or.inl ⟨moved, used⟩⟩
    · have reverse : other < loan := by omega
      exact ⟨other, loan, b, a, reverse,
        by simpa [Nat.min_eq_right (Nat.le_of_lt reverse), Nat.max_eq_left (Nat.le_of_lt reverse)] using before,
        Or.inr ⟨moved, used⟩⟩

end Hibana.Epf.CompactSource
