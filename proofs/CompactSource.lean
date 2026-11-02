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

#print axioms event_count_is_unchanged
#print axioms messages_and_source_identities_are_unchanged
#print axioms sequence_order_is_unchanged
#print axioms witness_retains_every_original_occurrence

/-- Mapping an event through the removal of an inserted body. Inserted events
occupy the original focus's side of every enclosing binary subtree. -/
def collapseInsertion (start added event : Nat) : Nat :=
  if event < start then event else start + (event - (start + added))

theorem collapse_before_cut (start added event cut : Nat) (h : cut ≤ start) :
    collapseInsertion start added event < cut ↔ event < cut := by
  unfold collapseInsertion
  split <;> omega

theorem collapse_after_cut (start added event cut : Nat) (h : start < cut) :
    collapseInsertion start added event < cut ↔ event < cut + added := by
  unfold collapseInsertion
  split <;> omega

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

#print axioms collapse_before_cut
#print axioms collapse_after_cut
#print axioms split_search_exact

end Hibana.Epf.CompactSource
