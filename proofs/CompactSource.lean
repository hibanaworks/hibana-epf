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

end Hibana.Epf.CompactSource
