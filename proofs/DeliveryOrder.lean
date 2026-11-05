import Std

namespace Hibana.Epf.DeliveryOrder

/-- Edges are producer succession or a send's first poll to its receive.
The rank is a retrospective certificate, not a shared runtime clock. -/
def checkRanks (edges : List (Nat × Nat)) (rank : Nat → Nat) : Bool :=
  edges.all fun (before, after) => decide (rank before < rank after)

theorem checked_edges_increase_rank
    (checked : checkRanks edges rank = true) (present : (before, after) ∈ edges) :
    rank before < rank after := by
  exact of_decide_eq_true (List.all_eq_true.mp checked (before, after) present)

/-- A nonempty path through the checked causal edges. -/
inductive Path (edges : List (Nat × Nat)) : Nat → Nat → Prop where
  | edge : (before, after) ∈ edges → Path edges before after
  | append : Path edges before middle → (middle, after) ∈ edges → Path edges before after

theorem checked_paths_increase_rank
    (checked : checkRanks edges rank = true) (path : Path edges before after) :
    rank before < rank after := by
  induction path with
  | edge present => exact checked_edges_increase_rank checked present
  | append _ present ih => exact Nat.lt_trans ih (checked_edges_increase_rank checked present)

theorem checked_edges_have_no_cycle
    (checked : checkRanks edges rank = true) : ¬ Path edges point point := by
  intro path
  exact Nat.lt_irrefl _ (checked_paths_increase_rank checked path)

/-- Flat positions 0/1 belong to the sender; 2 belongs to the receiver.
Poll precedes receipt, which precedes publication in this legal witness. -/
private def delayedRank : Nat → Nat
  | 0 => 0
  | 1 => 2
  | _ => 1

theorem receipt_can_precede_publication :
    checkRanks [(0, 1), (0, 2)] delayedRank = true ∧ delayedRank 2 < delayedRank 1 := by
  decide

theorem individually_matched_receives_can_cycle :
    ∀ rank, checkRanks [(0, 1), (2, 3), (1, 2), (3, 0)] rank = false := by
  intro rank
  cases checked : checkRanks [(0, 1), (2, 3), (1, 2), (3, 0)] rank with
  | false => rfl
  | true =>
      have first := checked_edges_increase_rank checked (by decide : (0, 1) ∈ _)
      have second := checked_edges_increase_rank checked (by decide : (2, 3) ∈ _)
      have forward := checked_edges_increase_rank checked (by decide : (1, 2) ∈ _)
      have backward := checked_edges_increase_rank checked (by decide : (3, 0) ∈ _)
      omega

end Hibana.Epf.DeliveryOrder
