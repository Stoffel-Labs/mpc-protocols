/-
The protocol as a mathematical object, and its correctness when nobody deviates.

An execution is a bit assignment `β` (one bit per unqualified set, after the echo) together
with a fold tree whose internal nodes carry the double sharing `(rt, r2t)` that the
degree-reduction multiplication at that node spends.
-/
import DaBit.Basic

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-- The public shape of an XOR fold: which sets are combined in which order. -/
inductive Shape (n : ℕ) where
  | leaf : Finset (Fin n) → Shape n
  | node : Shape n → Shape n → Shape n

/-- A fold tree with the randomness it consumes.  `node l r rt r2t` multiplies the two
sub-results with the double sharing `(rt, r2t)`. -/
inductive DTree (F : Type*) [Field F] (n : ℕ) where
  | leaf : Finset (Fin n) → DTree F n
  | node : DTree F n → DTree F n → F[X] → F[X] → DTree F n

namespace DTree

def shape : DTree F n → Shape n
  | .leaf T => .leaf T
  | .node l r _ _ => .node l.shape r.shape

/-- The sets at the leaves, left to right. -/
def leaves : DTree F n → List (Finset (Fin n))
  | .leaf T => [T]
  | .node l r _ _ => l.leaves ++ r.leaves

/-- Well-formedness: leaves are sets of at most `t` parties, and every double sharing is a
degree-`t` and a degree-`2t` sharing of one value.  This is what `RanDouSha` delivers. -/
def Valid (t : ℕ) : DTree F n → Prop
  | .leaf T => T.card ≤ t
  | .node l r rt r2t =>
      l.Valid t ∧ r.Valid t ∧ rt.natDegree ≤ t ∧ r2t.natDegree ≤ 2 * t ∧ rt.eval 0 = r2t.eval 0

end DTree

/-- The bit a subtree computes: the XOR of its leaves' bits. -/
def val (β : Finset (Fin n) → ZMod 2) : DTree F n → ZMod 2
  | .leaf T => β T
  | .node l r _ _ => val β l + val β r

/-- The sharing polynomial on the output wire of a subtree.  Party `i`'s share is its value at
`x i`, and each line is what `ReplicatedDaBitNode::run` computes locally:

* leaf: `β_T · f_T(x_i)` (`arith_leaves`);
* node: open `d = (x·y + r2t)(0)`, set `xy = d - rt`, output `x + y - 2·xy`. -/
noncomputable def poly (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) : DTree F n → F[X]
  | .leaf T => C (bitF (β T)) * vanish x T
  | .node l r rt r2t =>
      poly x β l + poly x β r
        - C 2 * (C ((poly x β l * poly x β r + r2t).eval 0) - rt)

/-- The degree-`2t` polynomials whose shares are sent to the opening, in order. -/
noncomputable def opened (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) : DTree F n → List F[X]
  | .leaf _ => []
  | .node l r _ r2t => opened x β l ++ opened x β r ++ [poly x β l * poly x β r + r2t]

/-! ### Correctness of the `F` side -/

theorem val_eq_sum_leaves (β : Finset (Fin n) → ZMod 2) (tr : DTree F n) :
    val β tr = (tr.leaves.map β).sum := by
  induction tr with
  | leaf T => simp [val, DTree.leaves]
  | node l r rt r2t ihl ihr => simp [val, DTree.leaves, ihl, ihr]

theorem poly_natDegree_le (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) {t : ℕ}
    {tr : DTree F n} (h : tr.Valid t) : (poly x β tr).natDegree ≤ t := by
  induction tr with
  | leaf T =>
    exact (natDegree_C_mul_le _ _).trans ((vanish_natDegree_le x T).trans h)
  | node l r rt r2t ihl ihr =>
    obtain ⟨hl, hr, hrt, -, -⟩ := h
    have h1 : (C ((poly x β l * poly x β r + r2t).eval 0) - rt).natDegree ≤ t :=
      (natDegree_sub_le _ _).trans (max_le ((natDegree_C _).le.trans (Nat.zero_le t)) hrt)
    have h2 : (C (2 : F) * (C ((poly x β l * poly x β r + r2t).eval 0) - rt)).natDegree ≤ t :=
      (natDegree_C_mul_le _ _).trans h1
    exact (natDegree_sub_le _ _).trans
      (max_le ((natDegree_add_le _ _).trans (max_le (ihl hl) (ihr hr))) h2)

/-- The output wire shares the XOR of the leaves' bits. -/
theorem poly_eval_zero {x : Fin n → F} (hx0 : ∀ j, x j ≠ 0) (β : Finset (Fin n) → ZMod 2)
    {t : ℕ} {tr : DTree F n} (h : tr.Valid t) : (poly x β tr).eval 0 = bitF (val β tr) := by
  induction tr with
  | leaf T => simp [poly, val, vanish_eval_zero hx0]
  | node l r rt r2t ihl ihr =>
    obtain ⟨hl, hr, -, -, h0⟩ := h
    simp only [poly, val, eval_sub, eval_add, eval_mul, eval_C, ihl hl, ihr hr, bitF_xor, h0]
    ring

/-- Every polynomial handed to the opening has degree at most `2t`, so an honest run passes the
opening's degree check. -/
theorem opened_natDegree_le (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) {t : ℕ}
    {tr : DTree F n} (h : tr.Valid t) : ∀ D ∈ opened x β tr, D.natDegree ≤ 2 * t := by
  induction tr with
  | leaf T => intro D hD; simp [opened] at hD
  | node l r rt r2t ihl ihr =>
    obtain ⟨hl, hr, -, hr2t, -⟩ := h
    intro D hD
    simp only [opened, List.mem_append, List.mem_singleton] at hD
    rcases hD with (hD | hD) | rfl
    · exact ihl hl D hD
    · exact ihr hr D hD
    · refine (natDegree_add_le _ _).trans (max_le ?_ hr2t)
      refine natDegree_mul_le.trans ?_
      have := poly_natDegree_le x β hl
      have := poly_natDegree_le x β hr
      omega

/-- The share party `i` sends to the opening is computed from its own shares only. -/
theorem opened_share (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) (l r : DTree F n)
    (r2t : F[X]) (i : Fin n) :
    (poly x β l * poly x β r + r2t).eval (x i)
      = (poly x β l).eval (x i) * (poly x β r).eval (x i) + r2t.eval (x i) := by
  simp

/-- The share party `i` outputs at a node is computed from its own shares and the opened value. -/
theorem node_share (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) (l r : DTree F n)
    (rt r2t : F[X]) (i : Fin n) :
    (poly x β (.node l r rt r2t)).eval (x i)
      = (poly x β l).eval (x i) + (poly x β r).eval (x i)
        - 2 * ((poly x β l * poly x β r + r2t).eval 0 - rt.eval (x i)) := by
  simp [poly]

/-- A party inside `T` contributes the share zero at leaf `T`: it needs no knowledge of `β_T`. -/
theorem leaf_share_of_mem (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) {T : Finset (Fin n)}
    {i : Fin n} (hi : i ∈ T) : (poly x β (.leaf T : DTree F n)).eval (x i) = 0 := by
  simp [poly, vanish_eval_mem x hi]

/-! ### The `K` side -/

section KSide

variable {K : Type*} [Field K] [CharP K 2]

/-- A bit as an element of the binary field. It is a ring homomorphism, so XOR becomes `+`. -/
noncomputable def bitK : ZMod 2 →+* K := ZMod.castHom (dvd_refl 2) K

/-- The `K`-side sharing polynomial: `Σ_T β_T · f^K_T`.  No interaction. -/
noncomputable def polyK (xK : Fin n → K) (𝒯 : Finset (Finset (Fin n)))
    (β : Finset (Fin n) → ZMod 2) : K[X] :=
  ∑ T ∈ 𝒯, C (bitK (β T)) * vanish xK T

theorem polyK_natDegree_le (xK : Fin n → K) {𝒯 : Finset (Finset (Fin n))} {t : ℕ}
    (h𝒯 : ∀ T ∈ 𝒯, T.card ≤ t) (β : Finset (Fin n) → ZMod 2) :
    (polyK xK 𝒯 β).natDegree ≤ t := by
  unfold polyK
  refine natDegree_sum_le_of_forall_le 𝒯 _ fun T hT => ?_
  exact (natDegree_C_mul_le _ _).trans ((vanish_natDegree_le xK T).trans (h𝒯 T hT))

/-- The `K` side shares the XOR of all the bits. -/
theorem polyK_eval_zero {xK : Fin n → K} (hx0 : ∀ j, xK j ≠ 0) (𝒯 : Finset (Finset (Fin n)))
    (β : Finset (Fin n) → ZMod 2) :
    (polyK xK 𝒯 β).eval 0 = bitK (∑ T ∈ 𝒯, β T) := by
  simp [polyK, eval_finsetSum, vanish_eval_zero hx0, map_sum]

/-- Party `i`'s `K` share only involves the bits of the sets it is outside of (`bin_share`). -/
theorem polyK_share (xK : Fin n → K) (𝒯 : Finset (Finset (Fin n)))
    (β : Finset (Fin n) → ZMod 2) (i : Fin n) :
    (polyK xK 𝒯 β).eval (xK i)
      = ∑ T ∈ 𝒯 with i ∉ T, bitK (β T) * (vanish xK T).eval (xK i) := by
  simp only [polyK, eval_finsetSum, eval_mul, eval_C]
  rw [Finset.sum_filter]
  refine Finset.sum_congr rfl fun T _ => ?_
  by_cases hi : i ∈ T
  · simp [hi, vanish_eval_mem xK hi]
  · simp [hi]

end KSide

/-! ### Both halves share the same bit -/

/-- If the fold visits every set exactly once, it computes the XOR of all the bits. -/
theorem val_eq_sum_of_perm (β : Finset (Fin n) → ZMod 2) {tr : DTree F n}
    {𝒯 : Finset (Finset (Fin n))} (hperm : tr.leaves.Perm 𝒯.toList) :
    val β tr = ∑ T ∈ 𝒯, β T := by
  rw [val_eq_sum_leaves, (hperm.map β).sum_eq, Finset.sum_map_toList]

/-- **Correctness.** In an execution where nobody deviates, the two halves of a daBit are
degree-`t` sharings, over `F` and over `K`, of one and the same bit `⊕_T β_T`. -/
theorem dabit_correct {K : Type*} [Field K] [CharP K 2]
    {x : Fin n → F} {xK : Fin n → K} (hx0 : ∀ j, x j ≠ 0) (hxK0 : ∀ j, xK j ≠ 0)
    {t : ℕ} {𝒯 : Finset (Finset (Fin n))} (h𝒯 : ∀ T ∈ 𝒯, T.card ≤ t)
    (β : Finset (Fin n) → ZMod 2) {tr : DTree F n} (hv : tr.Valid t)
    (hperm : tr.leaves.Perm 𝒯.toList) :
    (poly x β tr).natDegree ≤ t ∧ (polyK xK 𝒯 β).natDegree ≤ t ∧
      (poly x β tr).eval 0 = bitF (∑ T ∈ 𝒯, β T) ∧
      (polyK xK 𝒯 β).eval 0 = bitK (∑ T ∈ 𝒯, β T) :=
  ⟨poly_natDegree_le x β hv, polyK_natDegree_le xK h𝒯 β,
    by rw [poly_eval_zero hx0 β hv, val_eq_sum_of_perm β hperm], polyK_eval_zero hxK0 𝒯 β⟩

end DaBit
