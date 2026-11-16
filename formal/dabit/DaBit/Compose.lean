/-
How the pieces fit together.

* A2B followed by full-width B2A returns the value it started from.
* The outputs of A2B are valid inputs for the privacy theorem of B2A: paired A2B executions give
  the coalition the same shares of every output bit.
* Online openings always complete: the honest parties alone form a quorum.
-/
import DaBit.EdaBit
import DaBit.Soundness

open Polynomial

namespace DaBit

variable {p : ℕ} [Fact p.Prime] {K : Type*} [Field K] [CharP K 2] {n : ℕ}

/-! ### The round trip -/

/-- A number below `2^w` is the integer its low `w` bits encode. -/
theorem bitsValue_bitOf {w m : ℕ} (hm : m < 2 ^ w) :
    bitsValue (fun k : Fin w => bitOf m k) = m := by
  apply Nat.eq_of_testBit_eq
  intro i
  have hbit : ∀ a : ℕ, bitOf a i = (if a.testBit i then 1 else 0) := fun _ => rfl
  have hinj : ∀ a b : ℕ, bitOf a i = bitOf b i → a.testBit i = b.testBit i := by
    intro a b h
    rw [hbit, hbit] at h
    cases ha : a.testBit i <;> cases hb : b.testBit i <;> simp [ha, hb] at h ⊢
  apply hinj
  by_cases hi : i < w
  · exact bitOf_bitsValue (fun k : Fin w => bitOf m k) ⟨i, hi⟩
  · have hi' : w ≤ i := not_lt.mp hi
    rw [bitOf_bitsValue_ge _ hi']
    have : m.testBit i = false :=
      Nat.testBit_lt_two_pow (hm.trans_le (Nat.pow_le_pow_right (by norm_num) hi'))
    simp [bitOf, this]

/-- **A2B then full-width B2A is the identity.**  If the arithmetic sharings handed to the
recomposition share the bits of the canonical representative of `x` — which is what B2A produces
from A2B's output, bit by bit — then the result is a degree-`t` sharing of `x` itself, for every
`x` in the field.  This is the contract of `b2a_full_width_unchecked`. -/
theorem a2b_b2a_roundtrip {t w : ℕ} (hw : p ≤ 2 ^ w) (x : ZMod p) {q : Fin w → (ZMod p)[X]}
    (hdeg : ∀ k, (q k).natDegree ≤ t) (hq : ∀ k, (q k).eval 0 = bitF (bitOf x.val k)) :
    (recompose q).natDegree ≤ t ∧ (recompose q).eval 0 = x := by
  refine ⟨recompose_natDegree_le hdeg, ?_⟩
  rw [recompose_eval (fun k : Fin w => bitOf x.val k) hq,
    bitsValue_bitOf ((ZMod.val_lt x).trans_le hw)]
  exact ZMod.natCast_zmod_val x

/-- The whole pipeline on shares: A2B's output wires, converted bit by bit with valid daBits
and recomposed, share `x` again. -/
theorem a2b_then_b2a {t w : ℕ} (hw : p ≤ 2 ^ w) {net : ZMod p → List (Skel (ZMod 2))}
    {outW : ℕ → ℕ} (hspec : NetSpec w net outW) {X : (ZMod p)[X]} {e : EdaBitSh p K}
    (he : e.Valid t) {gs : List (Gate K)} (hv : ∀ g ∈ gs, g.Valid t)
    (hplan : gs.map Gate.skel
      = (net ((X - e.arith).eval 0)).map (Skel.map (bitK : ZMod 2 →+* K)))
    (d : Fin w → DaBitSh (ZMod p) K) (hd : ∀ k, (d k).Valid t) :
    let c : Fin w → ZMod 2 := fun k => bitOf (X.eval 0).val k + (d k).bit
    -- what B2A opens for bit `k` really is `c k` …
    (∀ k : Fin w, (run w e.bits gs (outW k) + (d k).bin).eval 0 = bitK (c k)) ∧
    -- … and the recomposed output shares `x`.
    (recompose fun k => b2aBit (c k) (d k).arith).natDegree ≤ t ∧
    (recompose fun k => b2aBit (c k) (d k).arith).eval 0 = X.eval 0 := by
  intro c
  have hA := a2b_correct hspec he hv hplan
  refine ⟨fun k => b2a_opened (hA k k.2).2 (hd k).2.2.2, ?_⟩
  exact a2b_b2a_roundtrip hw (X.eval 0)
    (fun k => b2aBit_natDegree_le _ (hd k).1)
    (fun k => b2aBit_eval _ _ (hd k).2.2.1)

/-! ### Composing the privacy theorems -/

/-- **A2B's outputs can be fed to B2A without losing privacy.**  In the execution paired with
`(e, gs)` by `a2bSwap`, the coalition holds the same shares of every output bit.  That is the
hypothesis `hagree` of `b2aFibreEquiv` (and of `cfibreEquiv` for any Boolean circuit run on the
bits in between), so the privacy theorems chain: change the arithmetic input, re-pair the edaBit
and triples, then re-pair each daBit used downstream. -/
theorem a2bSwap_outputs_agree {xK : Fin n → K} {Ts : Finset (Fin n)} (w : ℕ)
    (X X' : (ZMod p)[X]) (eg : EdaBitSh p K × List (Gate K)) :
    Agree xK Ts (run w eg.1.bits eg.2)
      (run w (a2bSwap (xK := xK) (Ts := Ts) w X X' eg).1.bits
        (a2bSwap (xK := xK) (Ts := Ts) w X X' eg).2) :=
  adj_agree w (a2bSwapE_agree _ _ eg.1) eg.2

end DaBit

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-! ### Beaver triples from double sharings -/

/-- **Triple generation is an instance of the same machinery.**  A triple is two random sharings
`A`, `B` and their product computed by one degree-reduction multiplication; the result is a valid
Beaver triple.  Its privacy is `cfibreEquiv` for the one-gate program, and the randomness of
`A`, `B` and of the double sharing is `HimPoints.fibreEquiv`. -/
theorem triple_from_double {t : ℕ} {A B rt r2t : F[X]} (hA : A.natDegree ≤ t)
    (hB : B.natDegree ≤ t) (hd : (Gate.mulDN 0 1 rt r2t : Gate F).Valid t) :
    (Gate.mul 0 1 A B
      ((Gate.mulDN 0 1 rt r2t).step fun k => if k = 0 then A else if k = 1 then B else 0)).Valid
        t := by
  have hw : ∀ k, (if k = 0 then A else if k = 1 then B else (0 : F[X])).natDegree ≤ t := by
    intro k
    split
    · exact hA
    · split
      · exact hB
      · simp
  refine ⟨hA, hB, Gate.step_natDegree_le hw hd, ?_⟩
  rw [Gate.step_eval_zero _ hd]
  simp [Gate.skel, Skel.step]

/-! ### Online openings always complete -/

/-- With `n ≥ 3t + 1` and at most `t` corrupt parties, the honest parties alone are enough to
pass the acceptance rule of a degree-`t` opening. -/
theorem honest_quorum {t : ℕ} (H : Finset (Fin n)) (hcorrupt : Hᶜ.card ≤ t)
    (hn : 3 * t + 1 ≤ n) : t + t + 1 ≤ H.card := by
  have h : H.card + Hᶜ.card = n := by simp
  omega

/-- **Guaranteed output of an online opening.**  Whatever the corrupt parties send or withhold,
once the honest shares have arrived the true polynomial meets the acceptance rule, and
(`opening_sound`) nothing else can.  So a degree-`t` opening cannot be aborted and cannot be
forged — the property that makes A2B and B2A robust. -/
theorem online_opening_completes {t : ℕ} {x : Fin n → F} (hx : Function.Injective x)
    {D : F[X]} (hD : D.natDegree ≤ t) (H : Finset (Fin n)) (hcorrupt : Hᶜ.card ≤ t)
    (hn : 3 * t + 1 ≤ n) (recv : Fin n → F) (hH : ∀ i ∈ H, recv i = D.eval (x i)) :
    (∃ M : Finset (Fin n), t + t + 1 ≤ M.card ∧ ∀ i ∈ M, D.eval (x i) = recv i) ∧
    ∀ (q : F[X]) (M : Finset (Fin n)), q.natDegree ≤ t → t + t + 1 ≤ M.card →
      (∀ i ∈ M, q.eval (x i) = recv i) → q = D :=
  ⟨⟨H, honest_quorum H hcorrupt hn, fun i hi => (hH i hi).symm⟩,
    fun _ M hq hM hmatch => opening_sound hx hD hq H M recv hcorrupt hH hM hmatch⟩

end DaBit
