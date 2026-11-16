/-
Perfect privacy.

`Ts` is an unqualified set that contains every corrupt party, so that nobody outside it is
corrupt: its dealer and all its holders are honest and no corrupt party ever receives `β_Ts`.

We build an explicit involution on executions that flips `β_Ts` — and therefore the daBit —
while leaving everything a coalition inside `Ts` can see unchanged.  Because the involution
maps the honest parties' randomness bijectively onto itself, every view is exactly as likely
with the daBit equal to 0 as with it equal to 1.
-/
import DaBit.Protocol

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-! ### Flipping the hidden bit -/

/-- Flip the bit of the all-honest set and leave every other bit alone. -/
def flip (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2) : Finset (Fin n) → ZMod 2 :=
  fun T => if T = Ts then β T + 1 else β T

theorem flip_of_ne {Ts T : Finset (Fin n)} (β : Finset (Fin n) → ZMod 2) (h : T ≠ Ts) :
    flip Ts β T = β T := by
  simp [flip, h]

@[simp] theorem flip_self (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2) :
    flip Ts β Ts = β Ts + 1 := by
  simp [flip]

@[simp] theorem flip_flip (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2) :
    flip Ts (flip Ts β) = β := by
  funext T
  by_cases h : T = Ts
  · subst h
    rw [flip_self, flip_self, add_assoc, zmod2_add_self, add_zero]
  · rw [flip_of_ne _ h, flip_of_ne _ h]

/-! ### Compensating the masks -/

/-- How much the product at a node changes when the hidden bit flips. -/
noncomputable def delta (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (l r l' r' : DTree F n) : F[X] :=
  poly x β l * poly x β r - poly x (flip Ts β) l' * poly x (flip Ts β) r'

/-- The execution paired with `(β, tr)`: same shape, but each double sharing is shifted by
exactly the change in the product it masks, so that every opening stays the same.  The shift of
the degree-`t` half is a multiple of `f_Ts`, which vanishes on `Ts`. -/
noncomputable def adjust (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2) :
    DTree F n → DTree F n
  | .leaf T => .leaf T
  | .node l r rt r2t =>
      .node (adjust x Ts β l) (adjust x Ts β r)
        (rt + C ((delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r)).eval 0) * vanish x Ts)
        (r2t + delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r))

theorem adjust_product (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (l r : DTree F n) (r2t : F[X]) :
    poly x (flip Ts β) (adjust x Ts β l) * poly x (flip Ts β) (adjust x Ts β r)
        + (r2t + delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r))
      = poly x β l * poly x β r + r2t := by
  unfold delta
  ring

theorem poly_adjust_node (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (l r : DTree F n) (rt r2t : F[X]) :
    poly x (flip Ts β) (adjust x Ts β (.node l r rt r2t))
      = poly x (flip Ts β) (adjust x Ts β l) + poly x (flip Ts β) (adjust x Ts β r)
        - C 2 * (C ((poly x β l * poly x β r + r2t).eval 0)
          - (rt + C ((delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r)).eval 0)
              * vanish x Ts)) := by
  simp only [adjust, poly, adjust_product]

/-- The shape of the fold is unchanged. -/
theorem shape_adjust (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (tr : DTree F n) : (adjust x Ts β tr).shape = tr.shape := by
  induction tr with
  | leaf T => rfl
  | node l r rt r2t ihl ihr => simp only [adjust, DTree.shape, ihl, ihr]

theorem leaves_adjust (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (tr : DTree F n) : (adjust x Ts β tr).leaves = tr.leaves := by
  induction tr with
  | leaf T => rfl
  | node l r rt r2t ihl ihr => simp only [adjust, DTree.leaves, ihl, ihr]

/-- **Shares inside `Ts` do not move**, on any wire. -/
theorem poly_adjust_eval (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (tr : DTree F n) {i : Fin n} (hi : i ∈ Ts) :
    (poly x (flip Ts β) (adjust x Ts β tr)).eval (x i) = (poly x β tr).eval (x i) := by
  induction tr with
  | leaf T =>
    by_cases h : T = Ts
    · subst h
      simp [adjust, poly, vanish_eval_mem x hi]
    · simp [adjust, poly, flip_of_ne β h]
  | node l r rt r2t ihl ihr =>
    rw [poly_adjust_node]
    simp only [poly, eval_sub, eval_add, eval_mul, eval_C, ihl, ihr, vanish_eval_mem x hi,
      mul_zero, add_zero]

theorem delta_eval (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (l r : DTree F n) {i : Fin n} (hi : i ∈ Ts) :
    (delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r)).eval (x i) = 0 := by
  simp [delta, poly_adjust_eval x Ts β _ hi]

/-- **Every opened polynomial is unchanged** — not just the opened value, the whole polynomial,
i.e. every share any party sends to the opening. -/
theorem opened_adjust (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (tr : DTree F n) : opened x (flip Ts β) (adjust x Ts β tr) = opened x β tr := by
  induction tr with
  | leaf T => rfl
  | node l r rt r2t ihl ihr => simp only [adjust, opened, ihl, ihr, adjust_product]

/-- The shares of the double sharings held by the parties in `S`, in order. -/
noncomputable def maskShares (x : Fin n → F) (S : Finset (Fin n)) :
    DTree F n → List ((Fin n → F) × (Fin n → F))
  | .leaf _ => []
  | .node l r rt r2t =>
      maskShares x S l ++ maskShares x S r ++
        [(fun i => if i ∈ S then rt.eval (x i) else 0,
          fun i => if i ∈ S then r2t.eval (x i) else 0)]

/-- **The double-sharing shares inside `Ts` are unchanged.** -/
theorem maskShares_adjust (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (tr : DTree F n) : maskShares x Ts (adjust x Ts β tr) = maskShares x Ts tr := by
  induction tr with
  | leaf T => rfl
  | node l r rt r2t ihl ihr =>
    have h1 : (fun i => if i ∈ Ts then
          (rt + C ((delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r)).eval 0)
            * vanish x Ts).eval (x i) else 0)
        = fun i => if i ∈ Ts then rt.eval (x i) else 0 := by
      funext i
      by_cases hi : i ∈ Ts
      · simp [hi, vanish_eval_mem x hi]
      · simp [hi]
    have h2 : (fun i => if i ∈ Ts then
          (r2t + delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r)).eval (x i) else 0)
        = fun i => if i ∈ Ts then r2t.eval (x i) else 0 := by
      funext i
      by_cases hi : i ∈ Ts
      · simp [hi, delta_eval x Ts β l r hi]
      · simp [hi]
    simp only [adjust, maskShares, ihl, ihr, h1, h2]

/-- The paired execution is as well-formed as the original: its double sharings are again a
degree-`t` and a degree-`2t` sharing of one value. -/
theorem adjust_valid {x : Fin n → F} (hx0 : ∀ j, x j ≠ 0) {Ts : Finset (Fin n)} {t : ℕ}
    (hTs : Ts.card ≤ t) (β : Finset (Fin n) → ZMod 2) {tr : DTree F n} (h : tr.Valid t) :
    (adjust x Ts β tr).Valid t := by
  induction tr with
  | leaf T => exact h
  | node l r rt r2t ihl ihr =>
    obtain ⟨hl, hr, hrt, hr2t, h0⟩ := h
    have hl' := ihl hl
    have hr' := ihr hr
    have hΔ : (delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r)).natDegree ≤ 2 * t := by
      unfold delta
      refine (natDegree_sub_le _ _).trans (max_le ?_ ?_)
      · refine natDegree_mul_le.trans ?_
        have := poly_natDegree_le x β hl
        have := poly_natDegree_le x β hr
        omega
      · refine natDegree_mul_le.trans ?_
        have := poly_natDegree_le x (flip Ts β) hl'
        have := poly_natDegree_le x (flip Ts β) hr'
        omega
    simp only [adjust, DTree.Valid]
    refine ⟨hl', hr', ?_, ?_, ?_⟩
    · exact (natDegree_add_le _ _).trans
        (max_le hrt ((natDegree_C_mul_le _ _).trans ((vanish_natDegree_le x Ts).trans hTs)))
    · exact (natDegree_add_le _ _).trans (max_le hr2t hΔ)
    · simp [vanish_eval_zero hx0, h0]

/-- Flipping the hidden bit flips the result once per occurrence of `Ts` among the leaves. -/
theorem val_flip (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2) (tr : DTree F n) :
    val (flip Ts β) tr = val β tr + ((tr.leaves.count Ts : ℕ) : ZMod 2) := by
  induction tr with
  | leaf T =>
    by_cases h : T = Ts
    · subst h
      simp [val, DTree.leaves]
    · simp [val, DTree.leaves, flip_of_ne β h, h]
  | node l r rt r2t ihl ihr =>
    simp only [val, DTree.leaves, List.count_append, Nat.cast_add, ihl, ihr]
    ring

/-- Pairing twice returns the original execution: the pairing is a bijection. -/
theorem adjust_adjust (x : Fin n → F) (Ts : Finset (Fin n)) (β : Finset (Fin n) → ZMod 2)
    (tr : DTree F n) : adjust x Ts (flip Ts β) (adjust x Ts β tr) = tr := by
  induction tr with
  | leaf T => rfl
  | node l r rt r2t ihl ihr =>
    have hδ : delta x Ts (flip Ts β) (adjust x Ts β l) (adjust x Ts β r) l r
        = - delta x Ts β l r (adjust x Ts β l) (adjust x Ts β r) := by
      unfold delta
      rw [flip_flip]
      ring
    simp only [adjust, ihl, ihr, hδ]
    congr 1
    · rw [eval_neg, C_neg]; ring
    · ring

/-! ### The `K` side -/

section KSide

variable {K : Type*} [Field K] [CharP K 2]

/-- The `K` shares inside `Ts` do not depend on the hidden bit. -/
theorem polyK_flip_eval (xK : Fin n → K) (𝒯 : Finset (Finset (Fin n))) (Ts : Finset (Fin n))
    (β : Finset (Fin n) → ZMod 2) {i : Fin n} (hi : i ∈ Ts) :
    (polyK xK 𝒯 (flip Ts β)).eval (xK i) = (polyK xK 𝒯 β).eval (xK i) := by
  simp only [polyK, eval_finsetSum, eval_mul, eval_C]
  refine Finset.sum_congr rfl fun T _ => ?_
  by_cases h : T = Ts
  · subst h
    simp [vanish_eval_mem xK hi]
  · rw [flip_of_ne β h]

end KSide

/-- Flipping the hidden bit flips the XOR of all bits. -/
theorem sum_flip {𝒯 : Finset (Finset (Fin n))} {Ts : Finset (Fin n)} (hmem : Ts ∈ 𝒯)
    (β : Finset (Fin n) → ZMod 2) : ∑ T ∈ 𝒯, flip Ts β T = ∑ T ∈ 𝒯, β T + 1 := by
  have h : ∀ T, flip Ts β T = β T + if T = Ts then 1 else 0 := by
    intro T
    by_cases hT : T = Ts
    · subst hT; simp
    · simp [flip_of_ne β hT, hT]
  simp only [h, Finset.sum_add_distrib, Finset.sum_ite_eq', hmem, ite_true]

/-! ### An adaptive, rushing dealer -/

/-- The bits after the dealing round.  Sets with an honest dealer get the honest bits `h`; sets
with a corrupt dealer (`cd`) get whatever the adversary's strategy `σ` outputs. -/
def dealt (cd : Finset (Fin n) → Prop) [DecidablePred cd]
    (σ : (Finset (Fin n) → ZMod 2) → Finset (Fin n) → ZMod 2)
    (h : Finset (Fin n) → ZMod 2) : Finset (Fin n) → ZMod 2 :=
  fun T => if cd T then σ h T else h T

/-- The adversary may choose its dealt bits after seeing every honest bit except `β_Ts` — far
more than it actually sees.  Flipping the hidden honest bit still flips exactly `β_Ts` in the
resulting assignment, so the pairing above applies to executions with a corrupt, rushing,
adaptive dealer unchanged. -/
theorem dealt_flip {cd : Finset (Fin n) → Prop} [DecidablePred cd] {Ts : Finset (Fin n)}
    (hTs : ¬ cd Ts) {σ : (Finset (Fin n) → ZMod 2) → Finset (Fin n) → ZMod 2}
    (hσ : ∀ h h', (∀ T, T ≠ Ts → h T = h' T) → σ h = σ h')
    (h : Finset (Fin n) → ZMod 2) : dealt cd σ (flip Ts h) = flip Ts (dealt cd σ h) := by
  have hs : σ (flip Ts h) = σ h := hσ _ _ fun T hT => flip_of_ne h hT
  funext T
  by_cases hT : T = Ts
  · subst hT
    simp [dealt, hTs]
  · rw [flip_of_ne _ hT]
    by_cases hc : cd T
    · simp [dealt, hc, hs]
    · simp [dealt, hc, flip_of_ne h hT]

end DaBit
