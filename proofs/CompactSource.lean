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

/-- Only actual route nodes need interval rows. Unary rolls consume no row. -/
def routeCount : Source → Nat
  | .send _ => 0
  | .seq left right | .par left right => routeCount left + routeCount right
  | .route _ left right => 1 + routeCount left + routeCount right
  | .roll body => routeCount body

theorem route_intervals_fit_the_binary_boundary_capacity (source : Source) :
    routeCount source ≤ source.eventCount - 1 := by
  induction source with
  | send => simp [routeCount, Source.eventCount]
  | roll body ih => exact ih
  | seq left right ih₁ ih₂ | par left right ih₁ ih₂ | route _ left right ih₁ ih₂ =>
      have leftPositive := source_has_a_message left
      have rightPositive := source_has_a_message right
      simp only [routeCount, Source.eventCount]
      omega

/-- The visit span and selected side are the only attribution facts that a
later named-choice constraint reads from a read-only choice observation. -/
def routeKey (start split stop event : Nat) : Option ((Nat × Nat) × Bool) :=
  if start ≤ event ∧ event < stop then some ((start, stop), decide (split ≤ event))
  else none

theorem left_arm_attributions_retain_the_same_visit_and_side
    (start split stop first second : Nat)
    (firstInside : start ≤ first ∧ first < split)
    (secondInside : start ≤ second ∧ second < split)
    (bound : split ≤ stop) :
    routeKey start split stop first = routeKey start split stop second := by
  simp [routeKey, show first < stop by omega, show second < stop by omega,
    firstInside.1, secondInside.1, show ¬ split ≤ first by omega,
    show ¬ split ≤ second by omega]

theorem right_arm_attributions_retain_the_same_visit_and_side
    (start split stop first second : Nat)
    (firstInside : split ≤ first ∧ first < stop)
    (secondInside : split ≤ second ∧ second < stop)
    (bound : start ≤ split) :
    routeKey start split stop first = routeKey start split stop second := by
  simp [routeKey, show start ≤ first by omega, show start ≤ second by omega,
    firstInside.1, firstInside.2, secondInside.1, secondInside.2]

/-- Removing a nested same-scope interval preserves the outermost lookup's
coverage. Distinct repeated visits instead occupy disjoint event intervals. -/
theorem an_outer_interval_covers_every_nested_interval
    (start stop innerStart innerStop event : Nat)
    (nested : start ≤ innerStart ∧ innerStop ≤ stop) :
    ((start ≤ event ∧ event < stop) ∨ (innerStart ≤ event ∧ event < innerStop)) ↔
      (start ≤ event ∧ event < stop) := by omega

theorem an_earlier_disjoint_interval_cannot_contain_the_next_event
    (stop nextStart event : Nat) (disjoint : stop ≤ nextStart)
    (next : nextStart ≤ event) : ¬ event < stop := by omega

/-- With no forced branch in a subtree, seq/par require both children and a
route needs a viable child. Leaf constraints are supplied separately. -/
def viable (source : Source) (leaf : Nat → Bool) (start : Nat) : Bool :=
  match source with
  | .send _ => leaf start
  | .seq left right | .par left right =>
      viable left leaf start && viable right leaf (start + left.eventCount)
  | .route _ left right =>
      viable left leaf start || viable right leaf (start + left.eventCount)
  | .roll body => viable body leaf start

theorem an_unconstrained_subtree_is_viable (source : Source) (leaf : Nat → Bool)
    (start : Nat)
    (allowed : ∀ event, start ≤ event → event < start + source.eventCount →
      leaf event = true) : viable source leaf start = true := by
  induction source generalizing start with
  | send => exact allowed start (by omega) (by simp [Source.eventCount])
  | roll body ih => exact ih start allowed
  | seq left right ih₁ ih₂ | par left right ih₁ ih₂ | route _ left right ih₁ ih₂ =>
      have leftAllowed : ∀ event, start ≤ event → event < start + left.eventCount →
          leaf event = true := by
        intro event lower upper
        apply allowed event lower
        simp only [Source.eventCount]
        omega
      have rightAllowed : ∀ event, start + left.eventCount ≤ event →
          event < start + left.eventCount + right.eventCount → leaf event = true := by
        intro event lower upper
        apply allowed event (by omega)
        simpa [Source.eventCount, Nat.add_assoc] using upper
      simp only [viable, ih₁ start leftAllowed, ih₂ (start + left.eventCount) rightAllowed]
      rfl

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

/-- A valid selected subtree cannot disappear: every source constructor keeps
at least one actual message, even when a route chooses the other arm. -/
theorem selected_subtree_has_a_message
    {source : Source} {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {start : Nat} {run : Elaboration}
    (accepted : elaborate resources owners path source start = some run) :
    run.messageEntries ≠ [] := by
  induction source generalizing owners start run with
  | send message =>
      simp only [elaborate] at accepted
      split at accepted
      next invalid => simp at accepted
      next valid =>
        cases payload : message.payload <;> simp only [payload] at accepted
        all_goals
          have same := Option.some.inj accepted
          subst run
          simp [Elaboration.messageEntries]
  | seq left right leftIH rightIH =>
      change (elaborate resources owners path left start).bind _ = some run at accepted
      obtain ⟨first, firstAt, tail⟩ := Option.bind_eq_some_iff.mp accepted
      obtain ⟨second, secondAt, result⟩ := Option.bind_eq_some_iff.mp tail
      have same := Option.some.inj result
      subst run
      intro empty
      have combined : first.messageEntries ++ second.messageEntries = [] := by
        simpa [Elaboration.messageEntries, List.map_append] using empty
      exact leftIH firstAt (List.append_eq_nil_iff.mp combined).1
  | par left right leftIH rightIH =>
      obtain ⟨first, second, firstAt, secondAt, _, rfl⟩ :=
        accepted_parallel_elaboration_has_separated_children accepted
      intro empty
      have combined : first.messageEntries ++ second.messageEntries = [] := by
        simpa [Elaboration.messageEntries, List.map_append] using empty
      exact leftIH firstAt (List.append_eq_nil_iff.mp combined).1
  | route resolver left right leftIH rightIH =>
      simp only [elaborate] at accepted
      split at accepted
      next invalid => simp at accepted
      next valid =>
        obtain ⟨arm, armAt, selected⟩ := Option.bind_eq_some_iff.mp accepted
        cases arm with
        | left => exact leftIH selected
        | right => exact rightIH selected
  | roll body bodyIH =>
      change (elaborate resources owners path body start).bind _ = some run at accepted
      obtain ⟨inner, innerAt, result⟩ := Option.bind_eq_some_iff.mp accepted
      have same := Option.some.inj result
      subst run
      have inside : inner.messageEntries ≠ [] := bodyIH innerAt
      simpa only [Elaboration.messageEntries] using inside

/-- A source-wide fixed-actor certificate therefore supplies a selected
message too. Rust's prefix pruning additionally checks the sequential span,
the fixed compiled binding and absence of every commit in that span. The
existing source dependency rule then supplies the missing predecessor. This
does not identify the chosen message or replace actor/readiness checking. -/
theorem selected_subtree_retains_a_certified_message
    {source : Source} {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {start : Nat} {run : Elaboration}
    {certified : (Nat × Message) → Prop}
    (accepted : elaborate resources owners path source start = some run)
    (every : ∀ entry ∈ source.messageEntries start, certified entry) :
    ∃ entry ∈ run.messageEntries, certified entry := by
  have nonempty := selected_subtree_has_a_message accepted
  cases entries : run.messageEntries with
  | nil => exact False.elim (nonempty entries)
  | cons entry rest =>
      have member : entry ∈ run.messageEntries := by simp [entries]
      refine ⟨entry, by simp, ?_⟩
      exact every entry
        ((elaboration_retains_exact_source_message_occurrences accepted).subset member)

/-- A completed earlier child of a left-associated sequence cannot hide an
uncommitted later child. Descent into a sequence's right child preserves a
selected certified message regardless of the left child's history. -/
theorem selected_sequence_right_child_retains_a_certified_message
    {left right : Source} {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {start : Nat} {run : Elaboration}
    {certified : (Nat × Message) → Prop}
    (accepted : elaborate resources owners path (.seq left right) start = some run)
    (every : ∀ entry ∈ right.messageEntries (start + left.eventCount), certified entry) :
    ∃ entry ∈ run.messageEntries, certified entry := by
  change (elaborate resources owners path left start).bind _ = some run at accepted
  obtain ⟨first, firstAt, tail⟩ := Option.bind_eq_some_iff.mp accepted
  obtain ⟨second, secondAt, result⟩ := Option.bind_eq_some_iff.mp tail
  have same := Option.some.inj result
  subst run
  obtain ⟨entry, member, holds⟩ := selected_subtree_retains_a_certified_message secondAt every
  refine ⟨entry, ?_, holds⟩
  simpa [Elaboration.messageEntries, List.map_append] using
    (List.mem_append_right first.messageEntries member)

/-- Both parallel children remain mandatory. This only supports pruning a
parallel subtree inside an earlier sequential child; it does not add order
between the parallel children. A route's unselected child has no such rule. -/
theorem selected_parallel_right_child_retains_a_certified_message
    {left right : Source} {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {start : Nat} {run : Elaboration}
    {certified : (Nat × Message) → Prop}
    (accepted : elaborate resources owners path (.par left right) start = some run)
    (every : ∀ entry ∈ right.messageEntries (start + left.eventCount), certified entry) :
    ∃ entry ∈ run.messageEntries, certified entry := by
  obtain ⟨first, second, firstAt, secondAt, _, rfl⟩ :=
    accepted_parallel_elaboration_has_separated_children accepted
  obtain ⟨entry, member, holds⟩ := selected_subtree_retains_a_certified_message secondAt every
  refine ⟨entry, ?_, holds⟩
  simpa [Elaboration.messageEntries, List.map_append] using
    (List.mem_append_right first.messageEntries member)

/-- An independent participant in the right child does not remove a required
message in the left child. The certificate need not cover the other actor. -/
theorem selected_parallel_left_child_retains_a_certified_message
    {left right : Source} {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {start : Nat} {run : Elaboration}
    {certified : (Nat × Message) → Prop}
    (accepted : elaborate resources owners path (.par left right) start = some run)
    (every : ∀ entry ∈ left.messageEntries start, certified entry) :
    ∃ entry ∈ run.messageEntries, certified entry := by
  obtain ⟨first, second, firstAt, secondAt, _, rfl⟩ :=
    accepted_parallel_elaboration_has_separated_children accepted
  obtain ⟨entry, member, holds⟩ := selected_subtree_retains_a_certified_message firstAt every
  refine ⟨entry, ?_, holds⟩
  simpa [Elaboration.messageEntries, List.map_append] using
    (List.mem_append_left second.messageEntries member)

/-- Original occurrence identities stay inside their source subtree, including
both arms before selection and every retained roll copy after unfolding. -/
theorem source_message_is_within_its_subtree
    {source : Source} {start event : Nat} {message : Message}
    (present : (event, message) ∈ source.messageEntries start) :
    start ≤ event ∧ event < start + source.eventCount := by
  induction source generalizing start with
  | send original =>
      have same : event = start := congrArg Prod.fst (List.mem_singleton.mp present)
      subst event
      simp [Source.eventCount]
  | roll body ih => exact ih present
  | seq left right leftIH rightIH | par left right leftIH rightIH | route resolver left right leftIH rightIH =>
      simp only [Source.messageEntries, List.mem_append] at present
      rcases present with inLeft | inRight
      · have bound := leftIH inLeft
        simp only [Source.eventCount]
        omega
      · have bound := rightIH inRight
        simp only [Source.eventCount]
        omega

/-- The selected left message is a source predecessor of every event in the
same sequence's right child, not only the first rejected query. This supplies
the interval bound used to skip later candidates; a parallel sibling outside
that child is not included. Fixed actors and missing commits are checked by
Rust separately and compared with exhaustive small-source selections. -/
theorem a_certified_left_message_precedes_the_whole_right_child
    {left right : Source} {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {run : Elaboration}
    {certified : (Nat × Message) → Prop}
    (accepted : elaborate resources owners path left 0 = some run)
    (every : ∀ entry ∈ left.messageEntries 0, certified entry) :
    ∃ entry ∈ run.messageEntries, certified entry ∧
      ∀ event, left.eventCount ≤ event → event < left.eventCount + right.eventCount →
        (Source.seq left right).before entry.1 event = true := by
  obtain ⟨entry, member, holds⟩ := selected_subtree_retains_a_certified_message accepted every
  have original := (elaboration_retains_exact_source_message_occurrences accepted).subset member
  have inside := source_message_is_within_its_subtree original
  have early : entry.1 < left.eventCount := by simpa only [Nat.zero_add] using inside.2
  refine ⟨entry, member, holds, ?_⟩
  intro event lower upper
  simp [Source.before, early, Nat.not_le.mpr early, Nat.not_lt.mpr lower, lower]

/-- A mixed-actor parallel prefix still contributes its certified predecessor
to every later sequential operation. Other participants need no certificate;
their completion is not made a prerequisite of this actor by this claim. -/
theorem a_certified_parallel_child_precedes_the_whole_continuation
    {left right tail : Source} {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {run : Elaboration}
    {certified : (Nat × Message) → Prop}
    (accepted : elaborate resources owners path (.par left right) 0 = some run)
    (every : ∀ entry ∈ left.messageEntries 0, certified entry) :
    ∃ entry ∈ run.messageEntries, certified entry ∧
      ∀ event, left.eventCount + right.eventCount ≤ event →
        event < left.eventCount + right.eventCount + tail.eventCount →
        (Source.seq (.par left right) tail).before entry.1 event = true := by
  obtain ⟨entry, member, holds⟩ :=
    selected_parallel_left_child_retains_a_certified_message accepted every
  have original := (elaboration_retains_exact_source_message_occurrences accepted).subset member
  have inside := source_message_is_within_its_subtree original
  have early : entry.1 < (Source.par left right).eventCount := by
    simpa only [Nat.zero_add] using inside.2
  refine ⟨entry, member, holds, ?_⟩
  intro event lower upper
  have later : (Source.par left right).eventCount ≤ event := by
    simpa only [Source.eventCount] using lower
  simp [Source.before, early, Nat.not_le.mpr early, Nat.not_lt.mpr later, later]

/-- A source predecessor of a left child's remaining suffix also precedes the
later sequential child. This permits one exclusion for all later roll visits. -/
theorem a_sequence_extends_its_left_child_ordered_suffix
    (left right : Source) (first cut : Nat)
    (early : first < left.eventCount)
    (ordered : ∀ event, cut ≤ event → event < left.eventCount →
      left.before first event = true) :
    ∀ event, cut ≤ event → event < left.eventCount + right.eventCount →
      (Source.seq left right).before first event = true := by
  intro event lower upper
  by_cases inside : event < left.eventCount
  · simpa [Source.before, early, inside] using ordered event lower inside
  · simp [Source.before, early, inside, Nat.not_le.mpr early, Nat.le_of_not_gt inside]

/-- Moving the same interval through an enclosing right sequence child only
adds the left child's occurrence offset. -/
theorem a_sequence_retains_its_right_child_ordered_suffix
    (left right : Source) (first cut : Nat)
    (ordered : ∀ event, cut ≤ event → event < right.eventCount →
      right.before first event = true) :
    ∀ event, left.eventCount + cut ≤ event → event < left.eventCount + right.eventCount →
      (Source.seq left right).before (left.eventCount + first) event = true := by
  intro event lower upper
  have before : left.eventCount ≤ left.eventCount + first := by omega
  have after : left.eventCount ≤ event := by omega
  simpa [Source.before, Nat.not_lt.mpr before, Nat.not_lt.mpr after, before, after] using
    ordered (event - left.eventCount) (by omega) (by omega)

/-- The right parallel child has the same end. Its ordered suffix is retained,
but this claim does not cross from a left child into an independent sibling. -/
theorem a_parallel_retains_its_right_child_ordered_suffix
    (left right : Source) (first cut : Nat)
    (ordered : ∀ event, cut ≤ event → event < right.eventCount →
      right.before first event = true) :
    ∀ event, left.eventCount + cut ≤ event → event < left.eventCount + right.eventCount →
      (Source.par left right).before (left.eventCount + first) event = true := by
  intro event lower upper
  have before : left.eventCount ≤ left.eventCount + first := by omega
  have after : left.eventCount ≤ event := by omega
  simpa [Source.before, Nat.not_lt.mpr before, Nat.not_lt.mpr after, before, after] using
    ordered (event - left.eventCount) (by omega) (by omega)

/-- Any accepted interpretation retaining a committed route message must keep
its arm. Applying this at each choice below a sequential common ancestor
justifies the prefix-forced predecessor pruning. An acceptance-only observation
does not supply this retained-message premise; Rust/Lean conformance is checked
separately from this source lemma. -/
theorem a_retained_route_message_fixes_its_arm
    {left right : Source} {resolver : Option Nat}
    {resources : List EndpointKey} {owners : OwnerMap}
    {path : List Selection} {start event : Nat} {message : Message} {run : Elaboration}
    (accepted : elaborate resources owners path (.route resolver left right) start = some run)
    (retained : (event, message) ∈ run.messageEntries) :
    chosen? path { start, split := start + left.eventCount, stop := start + left.eventCount + right.eventCount } =
        some (if event < start + left.eventCount then .left else .right) := by
  simp only [elaborate] at accepted
  split at accepted
  next invalid => simp at accepted
  next valid =>
    obtain ⟨arm, armAt, selected⟩ := Option.bind_eq_some_iff.mp accepted
    cases arm with
    | left =>
        have original :=
          (elaboration_retains_exact_source_message_occurrences selected).subset retained
        have bound := source_message_is_within_its_subtree original
        simpa only [if_pos bound.2] using armAt
    | right =>
        have original :=
          (elaboration_retains_exact_source_message_occurrences selected).subset retained
        have bound := source_message_is_within_its_subtree original
        have afterSplit : ¬ event < start + left.eventCount := by omega
        simpa only [if_neg afterSplit] using armAt

end Hibana.Epf.CompactSource
