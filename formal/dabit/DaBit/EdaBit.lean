/-
edaBit composition and the `r < p` filter (`mpc/src/honeybadger/dabit/edabit.rs`).

`w` daBits are composed into `[r]_F = Σ 2^i [b_i]_F`.  That shares the integer `r = Σ 2^i b_i`
only while `r < p`, so a comparison netlist computes `bad = [r ≥ p]` on the binary halves, with
degree-reduction multiplications, and opens it.  Candidates with `bad = 1` are dropped.
-/
import DaBit.A2B

open Polynomial

namespace DaBit

variable {p : ℕ} [Fact p.Prime] {K : Type*} [Field K] [CharP K 2] {n : ℕ}

/-! ### The bits of a composed value -/

/-- Bit `k` of the integer a bit vector encodes is entry `k` of the vector. -/
theorem bitOf_bitsValue {ℓ : ℕ} (b : Fin ℓ → ZMod 2) (k : Fin ℓ) :
    bitOf (bitsValue b) k = b k := by
  induction ℓ with
  | zero => exact k.elim0
  | succ ℓ ih =>
    have hsplit : bitsValue b
        = 2 ^ ℓ * (b (Fin.last ℓ)).val + bitsValue (fun i : Fin ℓ => b i.castSucc) := by
      simp only [bitsValue, Fin.sum_univ_castSucc, Fin.val_castSucc, Fin.val_last]
      ring
    have hlt := bitsValue_lt fun i : Fin ℓ => b i.castSucc
    unfold bitOf
    rw [hsplit, Nat.testBit_two_pow_mul_add _ hlt]
    induction k using Fin.lastCases with
    | last =>
      simp only [Fin.val_last, lt_self_iff_false, if_false, Nat.sub_self, Nat.testBit_zero]
      rcases zmod2_cases (b (Fin.last ℓ)) with h | h <;> simp [h, ZMod.val_one]
    | cast j =>
      have hj : (j.castSucc : ℕ) < ℓ := by simp
      simp only [hj, if_true]
      exact ih (fun i : Fin ℓ => b i.castSucc) j

/-- Above the width every bit is zero. -/
theorem bitOf_bitsValue_ge {ℓ : ℕ} (b : Fin ℓ → ZMod 2) {k : ℕ} (hk : ℓ ≤ k) :
    bitOf (bitsValue b) k = 0 := by
  have h : (bitsValue b).testBit k = false :=
    Nat.testBit_lt_two_pow ((bitsValue_lt b).trans_le (Nat.pow_le_pow_right (by norm_num) hk))
  simp [bitOf, h]

/-! ### Composition -/

/-- The edaBit composed from `w` daBits. -/
noncomputable def composeEdaBit {w : ℕ} (d : Fin w → DaBitSh (ZMod p) K) : EdaBitSh p K where
  r := ((bitsValue fun i => (d i).bit : ℕ) : ZMod p)
  arith := recompose fun i => (d i).arith
  bits := fun k => if h : k < w then (d ⟨k, h⟩).bin else 0

/-- **A composed candidate that passes the filter is a valid edaBit.**  If the `w` daBits are
valid and the integer their bits encode is below `p`, then the arithmetic half shares that
integer and binary wire `k` shares its `k`-th bit — exactly the precondition of A2B. -/
theorem composeEdaBit_valid {t w : ℕ} {d : Fin w → DaBitSh (ZMod p) K}
    (hd : ∀ i, (d i).Valid t) (hlt : (bitsValue fun i => (d i).bit) < p) :
    (composeEdaBit d).Valid t := by
  have hval : ((bitsValue fun i => (d i).bit : ℕ) : ZMod p).val = bitsValue fun i => (d i).bit :=
    ZMod.val_natCast_of_lt hlt
  refine ⟨recompose_natDegree_le fun i => (hd i).1,
    recompose_eval (fun i => (d i).bit) fun i => (hd i).2.2.1, fun k => ?_⟩
  simp only [composeEdaBit, hval]
  by_cases hk : k < w
  · simp only [hk, dif_pos]
    refine ⟨(hd ⟨k, hk⟩).2.1, ?_⟩
    rw [(hd ⟨k, hk⟩).2.2.2]
    exact congrArg _ (bitOf_bitsValue (fun i => (d i).bit) ⟨k, hk⟩).symm
  · simp only [hk, dif_neg, not_false_eq_true]
    refine ⟨by simp, ?_⟩
    rw [bitOf_bitsValue_ge _ (not_lt.mp hk)]
    simp

/-! ### The filter -/

/-- **What the comparison netlist must compute**: on the bits of any `m < 2^w`, wire `bad`
carries `1` exactly when `m ≥ p`.  Discharged for the real netlist in `formal/netlists`. -/
def CmpSpec (p w : ℕ) (cmp : List (Skel (ZMod 2))) (bad : ℕ) : Prop :=
  ∀ m < 2 ^ w, prun w (fun i => bitOf m i) cmp bad = if p ≤ m then 1 else 0

/-- **The filter is sound.**  If the opened verdict is zero, the candidate is below `p`. -/
theorem filter_sound {t w : ℕ} {cmp : List (Skel (ZMod 2))} {bad : ℕ}
    (hspec : CmpSpec p w cmp bad) {m : ℕ} (hm : m < 2 ^ w) {bits : ℕ → K[X]}
    (hbits : ∀ k, (bits k).eval 0 = bitK (bitOf m k)) {gs : List (Gate K)}
    (hv : ∀ g ∈ gs, g.Valid t)
    (hplan : gs.map Gate.skel = cmp.map (Skel.map (bitK : ZMod 2 →+* K)))
    (hverdict : (run w bits gs bad).eval 0 = 0) : m < p := by
  by_contra hge
  have hin : (fun j => (bits j).eval 0) = fun j => (bitK : ZMod 2 →+* K) (bitOf m j) :=
    funext hbits
  rw [run_eval_zero w bits hv, hplan, hin, prun_map, hspec m hm, if_pos (not_lt.mp hge)] at hverdict
  simp at hverdict

omit [Fact (Nat.Prime p)] in
/-- **The filter is complete**: a candidate below `p` opens the verdict zero, so it is kept. -/
theorem filter_complete {t w : ℕ} {cmp : List (Skel (ZMod 2))} {bad : ℕ}
    (hspec : CmpSpec p w cmp bad) {m : ℕ} (hm : m < 2 ^ w) (hlt : m < p) {bits : ℕ → K[X]}
    (hbits : ∀ k, (bits k).eval 0 = bitK (bitOf m k)) {gs : List (Gate K)}
    (hv : ∀ g ∈ gs, g.Valid t)
    (hplan : gs.map Gate.skel = cmp.map (Skel.map (bitK : ZMod 2 →+* K))) :
    (run w bits gs bad).eval 0 = 0 := by
  have hin : (fun j => (bits j).eval 0) = fun j => (bitK : ZMod 2 →+* K) (bitOf m j) :=
    funext hbits
  rw [run_eval_zero w bits hv, hplan, hin, prun_map, hspec m hm, if_neg (not_le.mpr hlt)]
  simp

/-- **The filter reveals only its verdict.**  Two accepted candidates `m`, `m'` whose bit
sharings give the coalition the same shares produce the same view from equally much randomness:
the degree-`2t` openings of the comparison and the opened verdict say nothing about which
value below `p` was kept. -/
noncomputable def filterEquiv (xK : Fin n → K) (hxK : Function.Injective xK)
    (hxK0 : ∀ j, xK j ≠ 0) {t w : ℕ} {Ts : Finset (Fin n)} (hTs : Ts.card = t)
    {cmp : List (Skel (ZMod 2))} {bad : ℕ} (hspec : CmpSpec p w cmp bad)
    {m m' : ℕ} (hm : m < 2 ^ w) (hm' : m' < 2 ^ w) (hlt : m < p) (hlt' : m' < p)
    {bits bits' : ℕ → K[X]} (hdeg : ∀ k, (bits k).natDegree ≤ t)
    (hdeg' : ∀ k, (bits' k).natDegree ≤ t)
    (hbits : ∀ k, (bits k).eval 0 = bitK (bitOf m k))
    (hbits' : ∀ k, (bits' k).eval 0 = bitK (bitOf m' k))
    (hagree : Agree xK Ts bits bits') (v : CView K n)
    (hv : v.skel = cmp.map (Skel.map (bitK : ZMod 2 →+* K))) :
    CFibre xK Ts t w [bad] bits v ≃ CFibre xK Ts t w [bad] bits' v :=
  cfibreEquiv hxK hxK0 hTs w [bad] hdeg hdeg' hagree v (by
    intro k hk
    simp only [List.mem_singleton] at hk
    subst hk
    have hin : (fun j => (bits j).eval 0) = fun j => (bitK : ZMod 2 →+* K) (bitOf m j) :=
      funext hbits
    have hin' : (fun j => (bits' j).eval 0) = fun j => (bitK : ZMod 2 →+* K) (bitOf m' j) :=
      funext hbits'
    rw [hv, hin, hin', prun_map, prun_map, hspec m hm, hspec m' hm', if_neg (not_le.mpr hlt),
      if_neg (not_le.mpr hlt')])

end DaBit
