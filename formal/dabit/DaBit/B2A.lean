/-
Binary-to-arithmetic conversion (`mpc/src/honeybadger/b2a/b2a.rs`).

Per bit: open `c = x ⊕ r` on the binary side, then locally take `[r]_F` if `c = 0` and
`1 - [r]_F` if `c = 1`.  The value is the weighted sum of the bits.

The daBit consumed here is the ideal object the daBit proofs establish: a uniform bit shared by
degree-`t` polynomials in both fields (`dabit_secure`, `output_determined`).
-/
import DaBit.Circuit

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {K : Type*} [Field K] [CharP K 2] {n : ℕ}

/-- A daBit: one bit, its arithmetic sharing and its binary sharing. -/
structure DaBitSh (F K : Type*) [Field F] [Field K] where
  bit : ZMod 2
  arith : F[X]
  bin : K[X]

/-- Both halves are degree-`t` sharings of the bit. -/
def DaBitSh.Valid (t : ℕ) (d : DaBitSh F K) : Prop :=
  d.arith.natDegree ≤ t ∧ d.bin.natDegree ≤ t ∧
    d.arith.eval 0 = bitF d.bit ∧ d.bin.eval 0 = bitK d.bit

/-! ### Correctness of one bit -/

theorem bitK_injective : Function.Injective (bitK : ZMod 2 → K) := by
  intro a b h
  have h1 : (bitK : ZMod 2 →+* K) 1 = 1 := map_one _
  have h0 : (bitK : ZMod 2 →+* K) 0 = 0 := map_zero _
  rcases zmod2_cases a with rfl | rfl <;> rcases zmod2_cases b with rfl | rfl
  · rfl
  · rw [h0, h1] at h; exact absurd h.symm one_ne_zero
  · rw [h0, h1] at h; exact absurd h one_ne_zero
  · rfl

/-- Step 3 of the protocol: the arithmetic sharing of `x`, from the opened `c` and `[r]_F`. -/
noncomputable def b2aBit (c : ZMod 2) (RF : F[X]) : F[X] := if c = 0 then RF else C 1 - RF

/-- The opened value is `x ⊕ r`, and `gf_to_bit` reads it back unambiguously. -/
theorem b2a_opened {X RK : K[X]} {x r : ZMod 2} (hX : X.eval 0 = bitK x)
    (hR : RK.eval 0 = bitK r) : (X + RK).eval 0 = bitK (x + r) := by
  rw [eval_add, hX, hR, map_add]

/-- **One bit is converted correctly.** -/
theorem b2aBit_eval {RF : F[X]} (x r : ZMod 2) (hR : RF.eval 0 = bitF r) :
    (b2aBit (x + r) RF).eval 0 = bitF x := by
  have h11 : (1 : ZMod 2) + 1 = 0 := by decide
  have h10 : (1 : ZMod 2) ≠ 0 := by decide
  rcases zmod2_cases x with rfl | rfl <;> rcases zmod2_cases r with rfl | rfl
  · simpa [b2aBit] using hR
  · simp [b2aBit, h10, hR]
  · simp [b2aBit, h10, hR]
  · simpa [b2aBit, h11] using hR

theorem b2aBit_natDegree_le {t : ℕ} (c : ZMod 2) {RF : F[X]} (hR : RF.natDegree ≤ t) :
    (b2aBit c RF).natDegree ≤ t := by
  unfold b2aBit
  split
  · exact hR
  · exact (natDegree_sub_le _ _).trans (max_le ((natDegree_C _).le.trans (Nat.zero_le t)) hR)

/-! ### Recomposition and the width bound -/

/-- Step 4: `Σ 2^i · [x_i]_F`.  The same formula composes an edaBit from daBits. -/
noncomputable def recompose {ℓ : ℕ} (p : Fin ℓ → F[X]) : F[X] :=
  ∑ i : Fin ℓ, C ((2 : F) ^ (i : ℕ)) * p i

/-- The integer a bit vector encodes. -/
def bitsValue {ℓ : ℕ} (b : Fin ℓ → ZMod 2) : ℕ := ∑ i : Fin ℓ, 2 ^ (i : ℕ) * (b i).val

theorem bitF_eq_cast (b : ZMod 2) : (bitF b : F) = ((b.val : ℕ) : F) := by
  rcases zmod2_cases b with rfl | rfl
  · simp
  · simp [ZMod.val_one]

theorem recompose_natDegree_le {ℓ t : ℕ} {p : Fin ℓ → F[X]} (hp : ∀ i, (p i).natDegree ≤ t) :
    (recompose p).natDegree ≤ t :=
  natDegree_sum_le_of_forall_le _ _ fun i _ => (natDegree_C_mul_le _ _).trans (hp i)

/-- **The output shares the integer the bits encode**, as an element of `F`. -/
theorem recompose_eval {ℓ : ℕ} {p : Fin ℓ → F[X]} (b : Fin ℓ → ZMod 2)
    (hp : ∀ i, (p i).eval 0 = bitF (b i)) : (recompose p).eval 0 = ((bitsValue b : ℕ) : F) := by
  simp only [recompose, bitsValue, eval_finsetSum, eval_mul, eval_C, hp, bitF_eq_cast]
  push_cast
  rfl

theorem bitsValue_lt {ℓ : ℕ} (b : Fin ℓ → ZMod 2) : bitsValue b < 2 ^ ℓ := by
  induction ℓ with
  | zero => simp [bitsValue]
  | succ ℓ ih =>
    have h := ih fun i => b i.castSucc
    have hv : (b (Fin.last ℓ)).val ≤ 1 := Nat.lt_succ_iff.mp (ZMod.val_lt _)
    have hm : 2 ^ ℓ * (b (Fin.last ℓ)).val ≤ 2 ^ ℓ := by
      calc 2 ^ ℓ * (b (Fin.last ℓ)).val ≤ 2 ^ ℓ * 1 := Nat.mul_le_mul_left _ hv
        _ = 2 ^ ℓ := Nat.mul_one _
    simp only [bitsValue, Fin.sum_univ_castSucc, Fin.val_castSucc, Fin.val_last] at h ⊢
    rw [pow_succ]
    omega

/-- **The width bound.**  If `2^ℓ ≤ p`, no two `ℓ`-bit values are confused by the conversion:
the integer is below the characteristic, so its image in `F` determines it.  This is
`B2AError::WidthTooLarge` — `ℓ ≤ 254` on the scalar field of BLS12-381. -/
theorem recompose_faithful {p : ℕ} [CharP F p] {ℓ : ℕ} (hℓ : 2 ^ ℓ ≤ p) (b b' : Fin ℓ → ZMod 2)
    (h : ((bitsValue b : ℕ) : F) = ((bitsValue b' : ℕ) : F)) : bitsValue b = bitsValue b' :=
  CharP.natCast_injOn_Iio F p ((bitsValue_lt b).trans_le hℓ) ((bitsValue_lt b').trans_le hℓ) h

/-- At full width the same holds for values the caller knows to be below `p` — which is the
precondition of `b2a_full_width_unchecked`, and what A2B's output satisfies. -/
theorem recompose_faithful_of_lt {p : ℕ} [CharP F p] {ℓ : ℕ} (b b' : Fin ℓ → ZMod 2)
    (hb : bitsValue b < p) (hb' : bitsValue b' < p)
    (h : ((bitsValue b : ℕ) : F) = ((bitsValue b' : ℕ) : F)) : bitsValue b = bitsValue b' :=
  CharP.natCast_injOn_Iio F p hb hb' h

/-! ### Privacy of one bit -/

section Privacy

variable (x : Fin n → F) (xK : Fin n → K) (Ts : Finset (Fin n))

/-- What a coalition inside `Ts` sees when the bit shared by `X` is converted with daBit `d`:
the whole opened polynomial, and its own shares of the input and of both halves of the daBit. -/
structure B2AView (F K : Type*) [Field F] [Field K] (n : ℕ) where
  opened : K[X]
  inShares : Fin n → K
  arithShares : Fin n → F
  binShares : Fin n → K

noncomputable def b2aView (X : K[X]) (d : DaBitSh F K) : B2AView F K n where
  opened := X + d.bin
  inShares := fun i => if i ∈ Ts then X.eval (xK i) else 0
  arithShares := fun i => if i ∈ Ts then d.arith.eval (x i) else 0
  binShares := fun i => if i ∈ Ts then d.bin.eval (xK i) else 0

/-- The daBit paired with `d` when the input changes from `X` to `X'`. -/
noncomputable def b2aSwap (X X' : K[X]) (δ : ZMod 2) (d : DaBitSh F K) : DaBitSh F K where
  bit := d.bit + δ
  arith := d.arith + C (bitF (d.bit + δ) - bitF d.bit) * vanish x Ts
  bin := d.bin + (X - X')

variable {x} {xK} {Ts}

theorem b2aSwap_valid (hx0 : ∀ j, x j ≠ 0) {t : ℕ} (hTs : Ts.card ≤ t) {X X' : K[X]}
    {b b' : ZMod 2} (hX : X.natDegree ≤ t) (hX' : X'.natDegree ≤ t) (hb : X.eval 0 = bitK b)
    (hb' : X'.eval 0 = bitK b') {d : DaBitSh F K} (hd : d.Valid t) :
    (b2aSwap x Ts X X' (b + b') d).Valid t := by
  obtain ⟨h1, h2, h3, h4⟩ := hd
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact (natDegree_add_le _ _).trans
      (max_le h1 ((natDegree_C_mul_le _ _).trans ((vanish_natDegree_le x Ts).trans hTs)))
  · exact (natDegree_add_le _ _).trans (max_le h2 ((natDegree_sub_le _ _).trans (max_le hX hX')))
  · simp [b2aSwap, vanish_eval_zero hx0, h3]
  · simp only [b2aSwap, eval_add, eval_sub, h4, hb, hb', map_add]
    have h2' : ∀ a : K, -a = a := fun a => by
      have : a + a = 0 := CharTwo.add_self_eq_zero a
      exact neg_eq_of_add_eq_zero_left this
    rw [sub_eq_add_neg, h2']

omit [CharP K 2] in
theorem b2aSwap_view {X X' : K[X]} (hagree : ∀ i ∈ Ts, X.eval (xK i) = X'.eval (xK i))
    (δ : ZMod 2) (d : DaBitSh F K) :
    b2aView x xK Ts X' (b2aSwap x Ts X X' δ d) = b2aView x xK Ts X d := by
  simp only [b2aView, b2aSwap, B2AView.mk.injEq]
  refine ⟨by ring, ?_, ?_, ?_⟩
  · funext i; by_cases hi : i ∈ Ts
    · simp [hi, hagree i hi]
    · simp [hi]
  · funext i; by_cases hi : i ∈ Ts
    · simp [hi, vanish_eval_mem x hi]
    · simp [hi]
  · funext i; by_cases hi : i ∈ Ts
    · simp [hi, hagree i hi]
    · simp [hi]

omit [CharP K 2] in
theorem b2aSwap_swap (X X' : K[X]) (δ : ZMod 2) (d : DaBitSh F K) :
    b2aSwap x Ts X' X δ (b2aSwap x Ts X X' δ d) = d := by
  have hbit : d.bit + δ + δ = d.bit := by rw [add_assoc, zmod2_add_self, add_zero]
  cases d with
  | mk bit arith bin =>
    simp only [b2aSwap] at hbit ⊢
    congr 1
    · rw [hbit, add_assoc, ← add_mul, ← C_add]
      simp
    · ring

/-- The daBits that produce view `v` when the input sharing is `X`. -/
def B2AFibre (t : ℕ) (X : K[X]) (v : B2AView F K n) : Type _ :=
  {d : DaBitSh F K // d.Valid t ∧ b2aView x xK Ts X d = v}

/-- **Perfect privacy of B2A.**  Whatever bit is being converted, the same views arise from
equally many daBits: for inputs `X`, `X'` sharing bits `b`, `b'` and giving the coalition the
same shares, pairing is a one-to-one correspondence between the daBits behind any view.  The
daBit is uniform, so the opened `c` — and everything else the coalition sees — is independent
of the input. -/
noncomputable def b2aFibreEquiv (hx0 : ∀ j, x j ≠ 0) {t : ℕ} (hTs : Ts.card ≤ t)
    {X X' : K[X]} {b b' : ZMod 2} (hX : X.natDegree ≤ t) (hX' : X'.natDegree ≤ t)
    (hb : X.eval 0 = bitK b) (hb' : X'.eval 0 = bitK b')
    (hagree : ∀ i ∈ Ts, X.eval (xK i) = X'.eval (xK i)) (v : B2AView F K n) :
    B2AFibre (x := x) (xK := xK) (Ts := Ts) t X v ≃ B2AFibre (x := x) (xK := xK) (Ts := Ts) t X' v where
  toFun d := ⟨b2aSwap x Ts X X' (b + b') d.1, b2aSwap_valid hx0 hTs hX hX' hb hb' d.2.1,
    (b2aSwap_view hagree _ d.1).trans d.2.2⟩
  invFun d := ⟨b2aSwap x Ts X' X (b + b') d.1, by
      have := b2aSwap_valid hx0 hTs hX' hX hb' hb d.2.1
      rwa [add_comm b' b] at this,
    (b2aSwap_view (fun i hi => (hagree i hi).symm) _ d.1).trans d.2.2⟩
  left_inv d := Subtype.ext (b2aSwap_swap X X' _ d.1)
  right_inv d := Subtype.ext (b2aSwap_swap X' X _ d.1)

/-- In the paired execution the output is the conversion of the other bit: the swap is a real
execution of the protocol on the other input, not just a relabelling. -/
theorem b2aSwap_output {X X' : K[X]} {b b' : ZMod 2} {d : DaBitSh F K} {t : ℕ}
    (hx0 : ∀ j, x j ≠ 0) (hTs : Ts.card ≤ t) (hX : X.natDegree ≤ t) (hX' : X'.natDegree ≤ t)
    (hb : X.eval 0 = bitK b) (hb' : X'.eval 0 = bitK b') (hd : d.Valid t) :
    (b2aBit (b' + (b2aSwap x Ts X X' (b + b') d).bit)
      (b2aSwap x Ts X X' (b + b') d).arith).eval 0 = bitF b' :=
  b2aBit_eval b' _ (b2aSwap_valid hx0 hTs hX hX' hb hb' hd).2.2.1

end Privacy

/-! ### The checked variant -/

/-- `b2a_checked` opens `x·(x+1)`, computed with one Beaver multiplication.  It is zero exactly
for bits, so a passing check opens the same value whatever the bit is. -/
theorem bit_mul_succ (b : ZMod 2) : (bitK b : K) * (bitK b + 1) = 0 := by
  rcases zmod2_cases b with rfl | rfl
  · simp
  · have : (1 : K) + 1 = 0 := CharTwo.add_self_eq_zero 1
    simp [this]

/-- Soundness of the check: in a field, `x·(x+1) = 0` forces `x ∈ {0, 1}`. -/
theorem bit_of_mul_succ_eq_zero {a : K} (h : a * (a + 1) = 0) : a = 0 ∨ a = 1 := by
  rcases mul_eq_zero.mp h with h | h
  · exact Or.inl h
  · right
    have h1 : (1 : K) + 1 = 0 := CharTwo.add_self_eq_zero 1
    calc a = a + (1 + 1) := by rw [h1, add_zero]
      _ = (a + 1) + 1 := by ring
      _ = 1 := by rw [h, zero_add]

/-- **Privacy of the certification layer.**  The program is the single gate `x · (x + 1)` with
its product opened.  For two bit inputs it opens the same value, so `cfibreEquiv` applies: the
check reveals nothing about which bit was certified. -/
noncomputable def b2aCheckEquiv (hxK : Function.Injective xK) (hxK0 : ∀ j, xK j ≠ 0) {t : ℕ}
    {Ts : Finset (Fin n)} (hTs : Ts.card = t) {w w' : ℕ → K[X]}
    (hw : ∀ k, (w k).natDegree ≤ t) (hw' : ∀ k, (w' k).natDegree ≤ t)
    (hagree : Agree xK Ts w w') {b b' : ZMod 2}
    (h0 : (w 0).eval 0 = bitK b) (h1 : (w 1).eval 0 = bitK b + 1)
    (h0' : (w' 0).eval 0 = bitK b') (h1' : (w' 1).eval 0 = bitK b' + 1)
    (v : CView K n) (hv : v.skel = [Skel.mul false 0 1]) :
    CFibre xK Ts t 2 [2] w v ≃ CFibre xK Ts t 2 [2] w' v :=
  cfibreEquiv hxK hxK0 hTs 2 [2] hw hw' hagree v (by
    intro k hk
    simp only [List.mem_singleton] at hk
    subst hk
    simp [hv, prun, Skel.step, h0, h1, h0', h1', bit_mul_succ])

end DaBit
