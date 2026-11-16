/-
The security statement, assembled.

An execution is the honest parties' randomness — the dealt bits and the double sharings — and
the view is everything a coalition inside `Ts` sees.  The theorems say: the paired execution is
valid, looks identical, and shares the opposite bit; hence, for every view, the executions that
produce it split evenly between the two values of the daBit.
-/
import DaBit.Privacy
import DaBit.Soundness
import DaBit.Fold

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {K : Type*} [Field K] [CharP K 2] {n : ℕ}

/-- The randomness of one daBit: the bit of every set and the double sharing of every
multiplication. -/
structure Exec (F : Type*) [Field F] (n : ℕ) where
  bits : Finset (Fin n) → ZMod 2
  tree : DTree F n

/-- Everything a coalition contained in `Ts` sees — and more than it sees. -/
structure View (F K : Type*) [Field F] [Field K] (n : ℕ) where
  /-- Every dealt bit except the one of `Ts` (the echoes repeat these). -/
  bits : Finset (Fin n) → ZMod 2
  /-- The public shape of the fold. -/
  shape : Shape n
  /-- Every polynomial opened at degree `2t`, entire: all `n` shares, not just the value. -/
  opened : List F[X]
  /-- The coalition's shares of every double sharing. -/
  masks : List ((Fin n → F) × (Fin n → F))
  /-- The coalition's shares of the `F` half of the daBit. -/
  fShares : Fin n → F
  /-- The coalition's shares of the `K` half of the daBit. -/
  kShares : Fin n → K

section Defs

variable (x : Fin n → F) (xK : Fin n → K) (𝒯 : Finset (Finset (Fin n)))
  (Ts : Finset (Fin n)) (t : ℕ)

noncomputable def view (e : Exec F n) : View F K n where
  bits := fun T => if T = Ts then 0 else e.bits T
  shape := e.tree.shape
  opened := opened x e.bits e.tree
  masks := maskShares x Ts e.tree
  fShares := fun i => if i ∈ Ts then (poly x e.bits e.tree).eval (x i) else 0
  kShares := fun i => if i ∈ Ts then (polyK xK 𝒯 e.bits).eval (xK i) else 0

/-- The daBit. -/
def out (e : Exec F n) : ZMod 2 := ∑ T ∈ 𝒯, e.bits T

/-- A well-formed execution: valid double sharings, and a fold that visits each set once. -/
def Good (e : Exec F n) : Prop := e.tree.Valid t ∧ e.tree.leaves.Perm 𝒯.toList

/-- The paired execution. -/
noncomputable def swap (e : Exec F n) : Exec F n :=
  ⟨flip Ts e.bits, adjust x Ts e.bits e.tree⟩

/-- The executions that produce view `v` and daBit `b`. -/
def Fibre (v : View F K n) (b : ZMod 2) : Type _ :=
  {e : Exec F n // Good 𝒯 t e ∧ view x xK 𝒯 Ts e = v ∧ out 𝒯 e = b}

end Defs

section Theorems

variable {x : Fin n → F} {xK : Fin n → K} {𝒯 : Finset (Finset (Fin n))}
  {Ts : Finset (Fin n)} {t : ℕ}

/-- `out` really is the bit both halves share. -/
theorem out_is_shared (hx0 : ∀ j, x j ≠ 0) (hxK0 : ∀ j, xK j ≠ 0)
    (h𝒯 : ∀ T ∈ 𝒯, T.card ≤ t) {e : Exec F n} (hg : Good 𝒯 t e) :
    (poly x e.bits e.tree).natDegree ≤ t ∧ (polyK xK 𝒯 e.bits).natDegree ≤ t ∧
      (poly x e.bits e.tree).eval 0 = bitF (out 𝒯 e) ∧
      (polyK xK 𝒯 e.bits).eval 0 = bitK (out 𝒯 e) :=
  dabit_correct hx0 hxK0 h𝒯 e.bits hg.1 hg.2

theorem swap_good (hx0 : ∀ j, x j ≠ 0) (hTs : Ts.card ≤ t) {e : Exec F n}
    (hg : Good 𝒯 t e) : Good 𝒯 t (swap x Ts e) :=
  ⟨adjust_valid hx0 hTs e.bits hg.1, by
    show (adjust x Ts e.bits e.tree).leaves.Perm 𝒯.toList
    rw [leaves_adjust]; exact hg.2⟩

/-- The paired execution looks the same. -/
theorem swap_view (e : Exec F n) :
    view x xK 𝒯 Ts (swap x Ts e) = view x xK 𝒯 Ts e := by
  simp only [view, swap, View.mk.injEq]
  refine ⟨?_, shape_adjust _ _ _ _, opened_adjust _ _ _ _, maskShares_adjust _ _ _ _, ?_, ?_⟩
  · funext T
    by_cases h : T = Ts
    · simp [h]
    · simp [h, flip_of_ne e.bits h]
  · funext i
    by_cases hi : i ∈ Ts
    · simp [hi, poly_adjust_eval x Ts e.bits e.tree hi]
    · simp [hi]
  · funext i
    by_cases hi : i ∈ Ts
    · simp [hi, polyK_flip_eval xK 𝒯 Ts e.bits hi]
    · simp [hi]

/-- The paired execution shares the opposite bit. -/
theorem swap_out (hmem : Ts ∈ 𝒯) (e : Exec F n) : out 𝒯 (swap x Ts e) = out 𝒯 e + 1 :=
  sum_flip hmem e.bits

theorem swap_swap (e : Exec F n) : swap x Ts (swap x Ts e) = e := by
  cases e with
  | mk bits tree =>
    simp only [swap, flip_flip, adjust_adjust]

/-- **Perfect privacy, as a bijection.**  For every view, pairing is a one-to-one
correspondence between the executions that give that view with daBit `b` and those that give
it with daBit `b + 1`. -/
noncomputable def fibreEquiv (hx0 : ∀ j, x j ≠ 0) (hTs : Ts.card ≤ t) (hmem : Ts ∈ 𝒯)
    (v : View F K n) (b : ZMod 2) :
    Fibre x xK 𝒯 Ts t v b ≃ Fibre x xK 𝒯 Ts t v (b + 1) where
  toFun e := ⟨swap x Ts e.1, swap_good hx0 hTs e.2.1, (swap_view e.1).trans e.2.2.1, by
    rw [swap_out hmem, e.2.2.2]⟩
  invFun e := ⟨swap x Ts e.1, swap_good hx0 hTs e.2.1, (swap_view e.1).trans e.2.2.1, by
    rw [swap_out hmem, e.2.2.2, add_assoc, zmod2_add_self, add_zero]⟩
  left_inv e := Subtype.ext (swap_swap e.1)
  right_inv e := Subtype.ext (swap_swap e.1)

/-! ### Finiteness, so that the counts below are honest counts -/

theorem finite_natDegree_le [Finite F] (d : ℕ) : {p : F[X] | p.natDegree ≤ d}.Finite := by
  have : Finite (Fin (d + 1) → F) := inferInstance
  refine Set.Finite.of_injOn (f := fun p : F[X] => fun i : Fin (d + 1) => p.coeff i)
    (t := Set.univ) (fun _ _ => Set.mem_univ _) ?_ Set.finite_univ
  intro p hp q hq hpq
  ext k
  by_cases hk : k ≤ d
  · exact congrFun hpq ⟨k, by omega⟩
  · rw [coeff_eq_zero_of_natDegree_lt (lt_of_le_of_lt hp (by omega)),
      coeff_eq_zero_of_natDegree_lt (lt_of_le_of_lt hq (by omega))]

theorem finite_trees [Finite F] (t : ℕ) (s : Shape n) :
    {tr : DTree F n | tr.shape = s ∧ tr.Valid t}.Finite := by
  induction s with
  | leaf T =>
    refine (Set.finite_singleton (DTree.leaf T)).subset ?_
    rintro tr ⟨hs, -⟩
    cases tr with
    | leaf T' =>
      simp only [DTree.shape, Shape.leaf.injEq] at hs
      simp [hs]
    | node l r rt r2t => simp [DTree.shape] at hs
  | node sl sr ihl ihr =>
    refine ((((ihl.prod ihr).prod (finite_natDegree_le t)).prod
      (finite_natDegree_le (2 * t))).image
        (fun p : ((DTree F n × DTree F n) × F[X]) × F[X] =>
          DTree.node p.1.1.1 p.1.1.2 p.1.2 p.2)).subset ?_
    rintro tr ⟨hs, hv⟩
    cases tr with
    | leaf T => simp [DTree.shape] at hs
    | node l r rt r2t =>
      simp only [DTree.shape, Shape.node.injEq] at hs
      obtain ⟨hl, hr, hrt, hr2t, -⟩ := hv
      exact ⟨(((l, r), rt), r2t), ⟨⟨⟨⟨hs.1, hl⟩, ⟨hs.2, hr⟩⟩, hrt⟩, hr2t⟩, rfl⟩

/-- Over a finite field only finitely many executions give a view. -/
theorem fibre_finite [Finite F] (v : View F K n) (b : ZMod 2) :
    Finite (Fibre x xK 𝒯 Ts t v b) := by
  have hfin : {e : Exec F n | e.tree.shape = v.shape ∧ e.tree.Valid t}.Finite := by
    refine (((Set.finite_univ (α := Finset (Fin n) → ZMod 2)).prod
      (finite_trees (F := F) t v.shape)).image
        (fun p : (Finset (Fin n) → ZMod 2) × DTree F n => (⟨p.1, p.2⟩ : Exec F n))).subset ?_
    rintro ⟨bits, tree⟩ h
    exact ⟨(bits, tree), ⟨Set.mem_univ _, h⟩, rfl⟩
  have hsub : {e : Exec F n | Good 𝒯 t e ∧ view x xK 𝒯 Ts e = v ∧ out 𝒯 e = b}
      ⊆ {e : Exec F n | e.tree.shape = v.shape ∧ e.tree.Valid t} := by
    rintro e ⟨hg, hv, -⟩
    exact ⟨by rw [← hv]; rfl, hg.1⟩
  exact (hfin.subset hsub).to_subtype

/-- **Perfect privacy, as a count.**  Every view arises from exactly as many executions with
the daBit equal to `b` as with it equal to `b + 1`.  The honest parties' randomness is uniform,
so the daBit is uniform conditioned on the view: the coalition learns nothing about it. -/
theorem perfect_privacy (hx0 : ∀ j, x j ≠ 0) (hTs : Ts.card ≤ t) (hmem : Ts ∈ 𝒯)
    (v : View F K n) (b : ZMod 2) :
    Nat.card (Fibre x xK 𝒯 Ts t v b) = Nat.card (Fibre x xK 𝒯 Ts t v (b + 1)) :=
  Nat.card_congr (fibreEquiv hx0 hTs hmem v b)

/-- **Nothing else is hidden in the output.**  Against a coalition of full size `t`, the two
output sharings are a function of the view and the daBit alone: two executions with the same
view and the same daBit give every honest party the same shares.  So the protocol produces
exactly what the ideal daBit functionality produces — a uniform bit, shared by the unique
degree-`t` polynomials through the coalition's shares. -/
theorem output_determined (hx : Function.Injective x) (hxK : Function.Injective xK)
    (hx0 : ∀ j, x j ≠ 0) (hxK0 : ∀ j, xK j ≠ 0) (h𝒯 : ∀ T ∈ 𝒯, T.card ≤ t)
    (hTs : t ≤ Ts.card) {e e' : Exec F n} (hg : Good 𝒯 t e) (hg' : Good 𝒯 t e')
    (hv : view x xK 𝒯 Ts e = view x xK 𝒯 Ts e') (ho : out 𝒯 e = out 𝒯 e') :
    poly x e.bits e.tree = poly x e'.bits e'.tree ∧ polyK xK 𝒯 e.bits = polyK xK 𝒯 e'.bits := by
  obtain ⟨d1, d2, s1, s2⟩ := out_is_shared (xK := xK) hx0 hxK0 h𝒯 hg
  obtain ⟨d1', d2', s1', s2'⟩ := out_is_shared (xK := xK) hx0 hxK0 h𝒯 hg'
  refine ⟨eq_of_secret_and_shares hx hx0 d1 d1' Ts hTs (by rw [s1, s1', ho]) fun i hi => ?_,
    eq_of_secret_and_shares hxK hxK0 d2 d2' Ts hTs (by rw [s2, s2', ho]) fun i hi => ?_⟩
  · have h := congrFun (congrArg View.fShares hv) i
    simpa [view, hi] using h
  · have h := congrFun (congrArg View.kShares hv) i
    simpa [view, hi] using h

/-! ### The statements are not vacuous -/

/-- The fold of a given shape with all-zero double sharings. -/
noncomputable def zeroTree : Shape n → DTree F n
  | .leaf T => .leaf T
  | .node l r => .node (zeroTree l) (zeroTree r) 0 0

/-- Well-formed executions exist for every fold shape over sets of at most `t` parties. -/
theorem zeroTree_valid (s : Shape n) (h : ∀ T ∈ s.leaves, T.card ≤ t) :
    (zeroTree (F := F) s).Valid t ∧ (zeroTree (F := F) s).leaves = s.leaves := by
  induction s with
  | leaf T => exact ⟨h T (by simp [Shape.leaves]), rfl⟩
  | node l r ihl ihr =>
    have hl := ihl fun T hT => h T (by simp [Shape.leaves, hT])
    have hr := ihr fun T hT => h T (by simp [Shape.leaves, hT])
    refine ⟨?_, by simp only [zeroTree, DTree.leaves, Shape.leaves, hl.2, hr.2]⟩
    simp only [zeroTree, DTree.Valid]
    simp [hl.1, hr.1]

/-! ### The set of the theorem exists -/

/-- At most `t` corrupt parties are always contained in one of the `C(n,t)` sets the code
enumerates; every party outside that set — its dealer and all its holders — is honest. -/
theorem exists_all_honest_set {t : ℕ} (C : Finset (Fin n)) (hC : C.card ≤ t) (ht : t ≤ n) :
    ∃ Ts ∈ Finset.powersetCard t (Finset.univ : Finset (Fin n)),
      C ⊆ Ts ∧ ∀ i, i ∉ Ts → i ∉ C := by
  obtain ⟨Ts, hsub, hcard⟩ := Finset.exists_superset_card_eq hC (by simpa using ht)
  exact ⟨Ts, by simp [Finset.mem_powersetCard, hcard], hsub, fun i hi hiC => hi (hsub hiC)⟩

/-- **The security theorem.**  `n` parties, threshold `t`, any coalition `C` of at most `t`
parties, the `C(n,t)` sets of the implementation, any fold shape.  There is a set `Ts ⊇ C`
such that, for every view `v` of a coalition inside `Ts` and every bit `b`:

* only finitely many executions produce `v`;
* exactly as many of them have daBit `b` as have daBit `b + 1`;
* in each of them both halves are degree-`t` sharings of the daBit. -/
theorem dabit_secure [Finite F] {x : Fin n → F} {xK : Fin n → K}
    (hx0 : ∀ j, x j ≠ 0) (hxK0 : ∀ j, xK j ≠ 0) {t : ℕ}
    (C : Finset (Fin n)) (hC : C.card ≤ t) (ht : t ≤ n) :
    ∃ Ts ∈ Finset.powersetCard t (Finset.univ : Finset (Fin n)), C ⊆ Ts ∧
      ∀ (v : View F K n) (b : ZMod 2),
        Finite (Fibre x xK (Finset.powersetCard t Finset.univ) Ts t v b) ∧
        Nat.card (Fibre x xK (Finset.powersetCard t Finset.univ) Ts t v b)
          = Nat.card (Fibre x xK (Finset.powersetCard t Finset.univ) Ts t v (b + 1)) ∧
        ∀ e : Fibre x xK (Finset.powersetCard t Finset.univ) Ts t v b,
          (poly x e.1.bits e.1.tree).natDegree ≤ t ∧
          (polyK xK (Finset.powersetCard t Finset.univ) e.1.bits).natDegree ≤ t ∧
          (poly x e.1.bits e.1.tree).eval 0 = bitF b ∧
          (polyK xK (Finset.powersetCard t Finset.univ) e.1.bits).eval 0 = bitK b := by
  obtain ⟨Ts, hmem, hsub, -⟩ := exists_all_honest_set C hC ht
  have hcard : ∀ T ∈ Finset.powersetCard t (Finset.univ : Finset (Fin n)), T.card ≤ t :=
    fun T hT => (Finset.mem_powersetCard.mp hT).2.le
  refine ⟨Ts, hmem, hsub, fun v b => ⟨fibre_finite v b, ?_, fun e => ?_⟩⟩
  · exact perfect_privacy hx0 (hcard Ts hmem) hmem v b
  · have h := out_is_shared (xK := xK) hx0 hxK0 hcard e.2.1
    rw [e.2.2.2] at h
    exact h

end Theorems

end DaBit
