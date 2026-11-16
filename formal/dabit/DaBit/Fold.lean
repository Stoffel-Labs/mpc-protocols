/-
The shape of the fold `ReplicatedDaBitNode::run` builds: one multiplication wave per level,
neighbours paired left to right, an odd element carried to the end of the next level.

The security theorems hold for every fold shape; this file only checks that the shape the
code builds visits each set exactly once and spends `C(n,t) - 1` multiplications.
-/
import DaBit.Protocol

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

namespace Shape

/-- The sets at the leaves, left to right. -/
def leaves : Shape n → List (Finset (Fin n))
  | .leaf T => [T]
  | .node l r => l.leaves ++ r.leaves

/-- The number of multiplications, i.e. of double sharings spent. -/
def mults : Shape n → ℕ
  | .leaf _ => 0
  | .node l r => l.mults + r.mults + 1

theorem mults_add_one (s : Shape n) : s.mults + 1 = s.leaves.length := by
  induction s with
  | leaf T => rfl
  | node l r ihl ihr => simp only [mults, leaves, List.length_append]; omega

end Shape

theorem DTree.shape_leaves (tr : DTree F n) : tr.shape.leaves = tr.leaves := by
  induction tr with
  | leaf T => rfl
  | node l r rt r2t ihl ihr => simp only [DTree.shape, Shape.leaves, DTree.leaves, ihl, ihr]

/-- One level of the fold (the body of the `while width > 1` loop). -/
def pairUp : List (Shape n) → List (Shape n)
  | a :: b :: rest => Shape.node a b :: pairUp rest
  | [a] => [a]
  | [] => []

theorem pairUp_leaves : ∀ l : List (Shape n),
    (pairUp l).flatMap Shape.leaves = l.flatMap Shape.leaves
  | [] => rfl
  | [_] => rfl
  | a :: b :: rest => by
    simp [pairUp, Shape.leaves, pairUp_leaves rest]

theorem pairUp_length : ∀ l : List (Shape n), (pairUp l).length = (l.length + 1) / 2
  | [] => by simp [pairUp]
  | [_] => by simp [pairUp]
  | a :: b :: rest => by
    simp only [pairUp, List.length_cons, pairUp_length rest]
    omega

theorem fold_leaves (k : ℕ) (l : List (Shape n)) :
    (pairUp^[k] l).flatMap Shape.leaves = l.flatMap Shape.leaves := by
  induction k generalizing l with
  | zero => rfl
  | succ k ih => rw [Function.iterate_succ_apply, ih, pairUp_leaves]

theorem fold_length_one (k : ℕ) (l : List (Shape n)) (h0 : 0 < l.length)
    (hk : l.length ≤ 2 ^ k) : (pairUp^[k] l).length = 1 := by
  induction k generalizing l with
  | zero => simp at hk; simp; omega
  | succ k ih =>
    rw [Function.iterate_succ_apply]
    apply ih
    · rw [pairUp_length]; omega
    · rw [pairUp_length]; rw [pow_succ] at hk; omega

theorem flatMap_leaf (sets : List (Finset (Fin n))) :
    (sets.map (Shape.leaf (n := n))).flatMap Shape.leaves = sets := by
  induction sets with
  | nil => rfl
  | cons a rest ih => simp [Shape.leaves, ih]

/-- **The fold the code builds.**  Starting from one leaf per set, repeated pairing ends in a
single tree whose leaves are exactly those sets, in order — each set once. -/
theorem fold_shape (sets : List (Finset (Fin n))) (h : sets ≠ []) :
    ∃ s : Shape n, pairUp^[sets.length] (sets.map Shape.leaf) = [s] ∧ s.leaves = sets := by
  have hlen : (pairUp^[sets.length] (sets.map Shape.leaf)).length = 1 :=
    fold_length_one _ _ (by simpa using List.length_pos_of_ne_nil h)
      (by simpa using Nat.lt_two_pow_self.le)
  obtain ⟨s, hs⟩ := List.length_eq_one_iff.mp hlen
  refine ⟨s, hs, ?_⟩
  have h1 := fold_leaves sets.length (sets.map (Shape.leaf (n := n)))
  rw [hs] at h1
  rw [flatMap_leaf] at h1
  simpa using h1

/-- It spends one double sharing fewer than there are sets: `doubles_per_dabit`. -/
theorem fold_mults (sets : List (Finset (Fin n))) (s : Shape n) (hs : s.leaves = sets) :
    s.mults + 1 = sets.length := by
  rw [← hs, Shape.mults_add_one]

end DaBit
