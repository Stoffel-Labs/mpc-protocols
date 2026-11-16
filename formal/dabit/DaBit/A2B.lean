/-
Arithmetic-to-binary conversion (`mpc/src/honeybadger/a2b/a2b.rs`).

  1. `[y] = [x] - [r]`, opened at degree `t`;
  2. the adder netlist for the public `y` is evaluated on the shared bits of `r`, one Beaver
     multiplication per AND;
  3. its outputs are sharings of the bits of `x`.

The field is `ZMod p`, so that "the bits of the canonical representative" has a meaning.

What the netlist computes is a property of the Rust circuit generator.  It enters here as the
hypothesis `NetSpec`, and is discharged for the real netlists by the SMT checks in
`formal/netlists`.
-/
import DaBit.B2A

open Polynomial

namespace DaBit

variable {p : ℕ} [Fact p.Prime] {K : Type*} [Field K] [CharP K 2] {n : ℕ}

/-- Bit `k` of the natural number `m`. -/
def bitOf (m k : ℕ) : ZMod 2 := if m.testBit k then 1 else 0

/-- An edaBit: a field element, its arithmetic sharing, and binary sharings of its bits. -/
structure EdaBitSh (p : ℕ) (K : Type*) [Field K] where
  r : ZMod p
  arith : (ZMod p)[X]
  bits : ℕ → K[X]

/-- The arithmetic half shares `r`; binary wire `k` shares bit `k` of the canonical
representative of `r` — which is below `p`, the guarantee of the `r < p` filter. -/
def EdaBitSh.Valid (t : ℕ) (e : EdaBitSh p K) : Prop :=
  e.arith.natDegree ≤ t ∧ e.arith.eval 0 = e.r ∧
    ∀ k, (e.bits k).natDegree ≤ t ∧ (e.bits k).eval 0 = bitK (bitOf e.r.val k)

/-- **What the adder netlist must compute.**  For every public mask `y` and every `r`, running
the netlist for `y` on the bits of `r` puts bit `k` of `(y + r) mod p` on output wire `k`. -/
def NetSpec (w : ℕ) (net : ZMod p → List (Skel (ZMod 2))) (outW : ℕ → ℕ) : Prop :=
  ∀ y r : ZMod p, ∀ k < w,
    prun w (fun i => bitOf r.val i) (net y) (outW k) = bitOf (y + r).val k

/-! ### Correctness -/

/-- **A2B is correct.**  Given a valid edaBit, valid triples and a netlist meeting its
specification, every output wire is a degree-`t` binary sharing of the corresponding bit of the
canonical representative of `x`. -/
theorem a2b_correct {t w : ℕ} {net : ZMod p → List (Skel (ZMod 2))} {outW : ℕ → ℕ}
    (hspec : NetSpec w net outW) {X : (ZMod p)[X]} {e : EdaBitSh p K} (he : e.Valid t)
    {gs : List (Gate K)} (hv : ∀ g ∈ gs, g.Valid t)
    (hplan : gs.map Gate.skel
      = (net ((X - e.arith).eval 0)).map (Skel.map (bitK : ZMod 2 →+* K))) :
    ∀ k < w, (run w e.bits gs (outW k)).natDegree ≤ t ∧
      (run w e.bits gs (outW k)).eval 0 = bitK (bitOf (X.eval 0).val k) := by
  intro k hk
  refine ⟨run_natDegree_le w (fun j => (he.2.2 j).1) hv _, ?_⟩
  have hin : (fun j => (e.bits j).eval 0) = fun j => (bitK : ZMod 2 →+* K) (bitOf e.r.val j) :=
    funext fun j => (he.2.2 j).2
  rw [run_eval_zero w e.bits hv, hplan, hin, prun_map, hspec _ _ k hk]
  congr 2
  rw [eval_sub, he.2.1]
  ring_nf

/-! ### Privacy -/

section Privacy

variable (x : Fin n → ZMod p) (xK : Fin n → K) (Ts : Finset (Fin n))

/-- What a coalition inside `Ts` sees of one conversion: the whole opened mask polynomial, its
shares of the edaBit's arithmetic half, and the complete view of the circuit evaluation
(every Beaver opening, its shares of every triple and of every wire, input bits included). -/
structure A2BView (p : ℕ) (K : Type*) [Field K] (n : ℕ) where
  opened : (ZMod p)[X]
  arithShares : Fin n → ZMod p
  circ : CView K n

noncomputable def a2bView (w : ℕ) (X : (ZMod p)[X]) (e : EdaBitSh p K) (gs : List (Gate K)) :
    A2BView p K n where
  opened := X - e.arith
  arithShares := fun i => if i ∈ Ts then e.arith.eval (x i) else 0
  circ := cview xK Ts w [] e.bits gs

/-- The edaBit paired with `e` when the input changes by `Δ` (whose value at 0 is `δ`): the mask
moves by the same amount, so the opened polynomial does not. -/
noncomputable def a2bSwapE (δ : ZMod p) (Δ : (ZMod p)[X]) (e : EdaBitSh p K) : EdaBitSh p K where
  r := e.r + δ
  arith := e.arith + Δ
  bits := fun k =>
    e.bits k + C (bitK (bitOf (e.r + δ).val k) - bitK (bitOf e.r.val k)) * vanish xK Ts

variable {x} {xK} {Ts}

theorem a2bSwapE_valid (hxK0 : ∀ j, xK j ≠ 0) {t : ℕ} (hTs : Ts.card ≤ t) {δ : ZMod p}
    {Δ : (ZMod p)[X]} (hΔ : Δ.natDegree ≤ t) (hδ : Δ.eval 0 = δ) {e : EdaBitSh p K}
    (he : e.Valid t) : (a2bSwapE xK Ts δ Δ e).Valid t := by
  obtain ⟨h1, h2, h3⟩ := he
  refine ⟨(natDegree_add_le _ _).trans (max_le h1 hΔ), by simp [a2bSwapE, h2, hδ], fun k => ?_⟩
  refine ⟨?_, ?_⟩
  · exact (natDegree_add_le _ _).trans
      (max_le (h3 k).1 ((natDegree_C_mul_le _ _).trans ((vanish_natDegree_le xK Ts).trans hTs)))
  · simp [a2bSwapE, vanish_eval_zero hxK0, (h3 k).2]

theorem a2bSwapE_agree (δ : ZMod p) (Δ : (ZMod p)[X]) (e : EdaBitSh p K) :
    Agree xK Ts e.bits (a2bSwapE xK Ts δ Δ e).bits := by
  intro k i hi
  simp [a2bSwapE, vanish_eval_mem xK hi]

theorem a2bSwapE_swap {δ δ' : ZMod p} {Δ Δ' : (ZMod p)[X]} (hδ : δ + δ' = 0) (hΔ : Δ + Δ' = 0)
    (e : EdaBitSh p K) : a2bSwapE xK Ts δ' Δ' (a2bSwapE xK Ts δ Δ e) = e := by
  cases e with
  | mk r arith bits =>
    have hr : r + δ + δ' = r := by rw [add_assoc, hδ, add_zero]
    simp only [a2bSwapE, EdaBitSh.mk.injEq, hr]
    refine ⟨trivial, by rw [add_assoc, hΔ, add_zero], ?_⟩
    funext k
    rw [add_assoc, ← add_mul, ← C_add]
    simp

omit [CharP K 2] in
/-- With nothing opened at the end, the paired circuit run has the same view. -/
theorem cview_adj_nil (len : ℕ) {w w' : ℕ → K[X]} (hw : Agree xK Ts w w') (gs : List (Gate K)) :
    cview xK Ts len [] w' (adj xK Ts len w w' gs) = cview xK Ts len [] w gs := by
  have hrun := adj_agree len hw gs
  simp only [cview, CView.mk.injEq, List.map_nil, and_true]
  refine ⟨adj_skel len w w' gs, adj_allOpens len hw gs, adj_maskShares len hw gs, ?_⟩
  funext k i
  by_cases hi : i ∈ Ts
  · simp [hi, hrun k i hi]
  · simp [hi]

/-- The pairing on whole executions: the edaBit and the triples together. -/
noncomputable def a2bSwap (w : ℕ) (X X' : (ZMod p)[X])
    (eg : EdaBitSh p K × List (Gate K)) : EdaBitSh p K × List (Gate K) :=
  (a2bSwapE xK Ts ((X' - X).eval 0) (X' - X) eg.1,
    adj xK Ts w eg.1.bits (a2bSwapE xK Ts ((X' - X).eval 0) (X' - X) eg.1).bits eg.2)

theorem a2bSwap_swap (w : ℕ) (X X' : (ZMod p)[X]) (eg : EdaBitSh p K × List (Gate K)) :
    a2bSwap (xK := xK) (Ts := Ts) w X' X (a2bSwap (xK := xK) (Ts := Ts) w X X' eg) = eg := by
  have hE : a2bSwapE xK Ts ((X - X').eval 0) (X - X')
      (a2bSwapE xK Ts ((X' - X).eval 0) (X' - X) eg.1) = eg.1 :=
    a2bSwapE_swap (by simp) (by ring) eg.1
  refine Prod.ext hE ?_
  simp only [a2bSwap, hE]
  exact adj_adj w _ _ eg.2

/-- The edaBits and triples that produce view `v` when the input sharing is `X`. -/
def A2BFibre (t w : ℕ) (X : (ZMod p)[X]) (v : A2BView p K n) : Type _ :=
  {eg : EdaBitSh p K × List (Gate K) //
    eg.1.Valid t ∧ (∀ g ∈ eg.2, g.Valid t) ∧ a2bView x xK Ts w X eg.1 eg.2 = v}

/-- **Perfect privacy of A2B.**  For two input sharings `X`, `X'` — of any two field elements —
that give the coalition the same shares, pairing is a one-to-one correspondence between the
preprocessing (edaBit and triples) behind any view.  The preprocessing is uniform, so the
opened mask, every Beaver opening and every share the coalition holds are jointly independent of
the value being converted.  Nothing is opened at the end: the outputs stay shared. -/
noncomputable def a2bFibreEquiv (hxK0 : ∀ j, xK j ≠ 0) {t : ℕ} (hTs : Ts.card ≤ t) (w : ℕ)
    {X X' : (ZMod p)[X]} (hX : X.natDegree ≤ t) (hX' : X'.natDegree ≤ t)
    (hagree : ∀ i ∈ Ts, X.eval (x i) = X'.eval (x i)) (v : A2BView p K n) :
    A2BFibre (x := x) (xK := xK) (Ts := Ts) t w X v
      ≃ A2BFibre (x := x) (xK := xK) (Ts := Ts) t w X' v := by
  have key : ∀ {Y Y' : (ZMod p)[X]}, Y.natDegree ≤ t → Y'.natDegree ≤ t →
      (∀ i ∈ Ts, Y.eval (x i) = Y'.eval (x i)) →
      ∀ eg : EdaBitSh p K × List (Gate K), eg.1.Valid t → (∀ g ∈ eg.2, g.Valid t) →
        a2bView x xK Ts w Y eg.1 eg.2 = v →
        (a2bSwap (xK := xK) (Ts := Ts) w Y Y' eg).1.Valid t ∧
        (∀ g ∈ (a2bSwap (xK := xK) (Ts := Ts) w Y Y' eg).2, g.Valid t) ∧
        a2bView x xK Ts w Y' (a2bSwap (xK := xK) (Ts := Ts) w Y Y' eg).1
          (a2bSwap (xK := xK) (Ts := Ts) w Y Y' eg).2 = v := by
    intro Y Y' hY hY' hag eg he hg hview
    have hΔ : (Y' - Y).natDegree ≤ t := (natDegree_sub_le _ _).trans (max_le hY' hY)
    have he' := a2bSwapE_valid (xK := xK) hxK0 hTs hΔ rfl he
    have hbits := a2bSwapE_agree (xK := xK) (Ts := Ts) ((Y' - Y).eval 0) (Y' - Y) eg.1
    refine ⟨he', ?_, ?_⟩
    · exact adj_valid hxK0 hTs w (fun k => (he.2.2 k).1) (fun k => (he'.2.2 k).1) hg
    · rw [← hview]
      simp only [a2bView, a2bSwap, A2BView.mk.injEq]
      refine ⟨by simp only [a2bSwapE]; ring, ?_, cview_adj_nil w hbits eg.2⟩
      funext i
      by_cases hi : i ∈ Ts
      · simp [a2bSwapE, hi, hag i hi]
      · simp [hi]
  exact
    { toFun := fun e =>
        ⟨a2bSwap (xK := xK) (Ts := Ts) w X X' e.1, key hX hX' hagree e.1 e.2.1 e.2.2.1 e.2.2.2⟩
      invFun := fun e =>
        ⟨a2bSwap (xK := xK) (Ts := Ts) w X' X e.1,
          key hX' hX (fun i hi => (hagree i hi).symm) e.1 e.2.1 e.2.2.1 e.2.2.2⟩
      left_inv := fun e => Subtype.ext (a2bSwap_swap w X X' e.1)
      right_inv := fun e => Subtype.ext (a2bSwap_swap w X' X e.1) }

end Privacy

/-! ### Why one conditional subtraction is enough -/

/-- The arithmetic behind the parallel offset adder.  With `y, r < p ≤ 2^w`, put
`Y = y + (2^w - p)`.  If `Y + r` carries out of `w` bits then `(y + r) mod p` is the low `w` bits
of `Y + r`; otherwise it is `y + r` itself.  This is the case analysis the netlist's final MUX
implements; the netlists themselves are checked against `(y + r) mod p` directly. -/
theorem offset_adder {p w y r : ℕ} (hp : p ≤ 2 ^ w) (hy : y < p) (hr : r < p) :
    (y + r) % p = if 2 ^ w ≤ y + (2 ^ w - p) + r then (y + (2 ^ w - p) + r) % 2 ^ w else y + r := by
  split
  · next h =>
    have h1 : p ≤ y + r := by omega
    have h2 : (y + r) % p = y + r - p := by
      rw [Nat.mod_eq_sub_mod h1, Nat.mod_eq_of_lt (by omega)]
    have h3 : y + (2 ^ w - p) + r = 2 ^ w + (y + r - p) := by omega
    rw [h2, h3, Nat.add_mod_left, Nat.mod_eq_of_lt (by omega)]
  · next h =>
    exact Nat.mod_eq_of_lt (by omega)

end DaBit
