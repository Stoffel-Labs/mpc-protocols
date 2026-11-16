/-
Randomness extraction with a hyper-invertible matrix
(`common::share::make_hyper_invertible`, used by `RanSha`, `RanDouSha`, the zero-share generator
and their `GF(2^k)` twins).

Every party deals a sharing; an `n × n` matrix `M` is applied to the `n` dealings; some outputs
are kept and the others are opened, one to each checking party.  Two properties of `M` carry the
whole protocol:

* soundness — bad dealings from the corrupt parties cannot cancel in every honest check;
* privacy   — the kept outputs are uniform given the outputs opened to corrupt checkers.

Both hold for *every* choice of corrupt parties exactly when `M` is hyper-invertible.  The matrix
is the one of Beerliová-Trubíniová and Hirt: for `2n` distinct points `α_j`, `β_i` it sends the
values of a polynomial of degree below `n` at the `α`s to its values at the `β`s.
-/
import DaBit.Basic

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-- The `2n` distinct points of the matrix. -/
structure HimPoints (F : Type*) [Field F] (n : ℕ) where
  α : Fin n → F
  β : Fin n → F
  hα : Function.Injective α
  hβ : Function.Injective β
  hαβ : ∀ j i, α j ≠ β i

namespace HimPoints

variable (P : HimPoints F n)

/-- The polynomial of degree below `n` taking the values `v` at the `α`s. -/
noncomputable def interp (v : Fin n → F) : F[X] := Lagrange.interpolate Finset.univ P.α v

/-- The matrix applied to a vector: row `i` is the value of the interpolant at `β_i`. -/
noncomputable def apply (v : Fin n → F) (i : Fin n) : F := (P.interp v).eval (P.β i)

theorem interp_eval (v : Fin n → F) (j : Fin n) : (P.interp v).eval (P.α j) = v j :=
  Lagrange.eval_interpolate_at_node v P.hα.injOn (Finset.mem_univ j)

theorem interp_degree_lt (v : Fin n → F) : (P.interp v).degree < n := by
  have h := Lagrange.degree_interpolate_lt (s := Finset.univ) v P.hα.injOn
  rw [Finset.card_univ, Fintype.card_fin] at h
  exact h

/-- The entries are the ones `make_hyper_invertible` computes:
`M[i][j] = ∏_{k ≠ j} (β_i - α_k) / (α_j - α_k)`. -/
theorem apply_eq_sum (v : Fin n → F) (i : Fin n) :
    P.apply v i
      = ∑ j, v j * ∏ k ∈ Finset.univ.erase j, (P.α j - P.α k)⁻¹ * (P.β i - P.α k) := by
  simp [apply, interp, Lagrange.interpolate_apply, eval_finsetSum, Lagrange.basis,
    Lagrange.basisDivisor, eval_prod]

theorem apply_add (v w : Fin n → F) (i : Fin n) :
    P.apply (v + w) i = P.apply v i + P.apply w i := by
  simp [apply, interp, map_add]

/-- All `2n` points as one injective family. -/
def pts : Fin n ⊕ Fin n → F := Sum.elim P.α P.β

theorem pts_injective : Function.Injective P.pts := by
  rintro (a | a) (b | b) h
  · exact congrArg Sum.inl (P.hα h)
  · exact absurd h (P.hαβ a b)
  · exact absurd h.symm (P.hαβ b a)
  · exact congrArg Sum.inr (P.hβ h)

/-- **Hyper-invertibility, as injectivity.**  Take any set `R` of rows and any set `C` of columns
with `|C| ≤ |R|`.  A vector supported on `C` that the rows of `R` all send to zero is zero.

Proof: its interpolant has degree below `n`, vanishes at the `n - |C|` points `α_j`, `j ∉ C`,
and at the `|R|` points `β_i`, `i ∈ R` — at least `n` distinct points. -/
theorem injective_on (R C : Finset (Fin n)) (hcard : C.card ≤ R.card) (v : Fin n → F)
    (hsupp : ∀ j ∉ C, v j = 0) (hzero : ∀ i ∈ R, P.apply v i = 0) : v = 0 := by
  classical
  have hf : P.interp v = 0 := by
    refine Polynomial.eq_of_degrees_lt_of_eval_index_eq (Cᶜ.disjSum R) P.pts_injective.injOn
      ?_ ?_ ?_
    · refine (P.interp_degree_lt v).trans_le ?_
      have h1 : (Cᶜ.disjSum R).card = Cᶜ.card + R.card := Finset.card_disjSum _ _
      have h2 : C.card + Cᶜ.card = n := by simp
      exact_mod_cast (by omega : n ≤ (Cᶜ.disjSum R).card)
    · simp only [degree_zero]
      exact WithBot.bot_lt_coe _
    · rintro (j | i) h
      · have hj : j ∉ C := by simpa [Finset.mem_disjSum] using h
        simp [pts, P.interp_eval v j, hsupp j hj]
      · have hi : i ∈ R := by simpa [Finset.mem_disjSum] using h
        simpa [pts, apply] using hzero i hi
  funext j
  rw [← P.interp_eval v j, hf]
  simp

/-- **Soundness of the check.**  `E k x` is coordinate `x` of the error in party `k`'s dealing —
of anything linear that vanishes on valid dealings: the part of a sharing above degree `t`, or
the difference between the two secrets of a double sharing.  Honest dealings have no error.  If
the outputs checked by at least as many honest parties as there are corrupt dealers show no
error, then no dealing has one, and so no output has one either. -/
theorem extraction_sound {ι : Type*} (C R : Finset (Fin n)) (hcard : C.card ≤ R.card)
    (E : Fin n → ι → F) (hhonest : ∀ k ∉ C, E k = 0)
    (hcheck : ∀ i ∈ R, ∀ x, P.apply (fun k => E k x) i = 0) : ∀ k, E k = 0 := by
  intro k
  funext x
  have h := P.injective_on R C hcard (fun k => E k x)
    (fun j hj => by simp [hhonest j hj]) (fun i hi => hcheck i hi x)
  exact congrFun h k

/-- **Hyper-invertibility, as surjectivity.**  Take any set `J` of rows and any set `H` of
columns with `|J| ≤ |H|`.  Every assignment of values to the rows of `J` is produced by some
vector supported on `H`. -/
theorem surjective_on (J H : Finset (Fin n)) (hcard : J.card ≤ H.card) (y : Fin n → F) :
    ∃ s : Fin n → F, (∀ k ∉ H, s k = 0) ∧ ∀ j ∈ J, P.apply s j = y j := by
  classical
  -- Interpolate: zero at the `α_k` outside `H`, the wanted values at the `β_j` in `J`.
  let S : Finset (Fin n ⊕ Fin n) := Hᶜ.disjSum J
  let g : Fin n ⊕ Fin n → F := Sum.elim (fun _ => 0) y
  let f : F[X] := Lagrange.interpolate S P.pts g
  have hS : S.card ≤ n := by
    have h1 : S.card = Hᶜ.card + J.card := Finset.card_disjSum _ _
    have h2 : H.card + Hᶜ.card = n := by simp
    omega
  have hfdeg : f.degree < n :=
    (Lagrange.degree_interpolate_lt g P.pts_injective.injOn).trans_le (by exact_mod_cast hS)
  have hfS : ∀ p ∈ S, f.eval (P.pts p) = g p := fun p hp =>
    Lagrange.eval_interpolate_at_node g P.pts_injective.injOn hp
  refine ⟨fun k => f.eval (P.α k), fun k hk => ?_, fun j hj => ?_⟩
  · have hmem : (Sum.inl k : Fin n ⊕ Fin n) ∈ S := by simp [S, Finset.mem_disjSum, hk]
    simpa [pts, g] using hfS _ hmem
  · have hinterp : P.interp (fun k => f.eval (P.α k)) = f := by
      refine Polynomial.eq_of_degrees_lt_of_eval_index_eq Finset.univ P.hα.injOn ?_ ?_ ?_
      · simpa using P.interp_degree_lt _
      · simpa using hfdeg
      · intro k _
        exact P.interp_eval _ k
    have hmem : (Sum.inr j : Fin n ⊕ Fin n) ∈ S := by simp [S, Finset.mem_disjSum, hj]
    simpa [apply, hinterp, pts, g] using hfS _ hmem

/-- The honest dealers' secrets (zero outside `H`) that produce the values `y` on the rows `J`. -/
def Fibre (J H : Finset (Fin n)) (y : Fin n → F) : Type _ :=
  {s : Fin n → F // (∀ k ∉ H, s k = 0) ∧ ∀ j ∈ J, P.apply s j = y j}

/-- **Privacy of the extraction.**  `H` is the set of honest dealers and `J` the kept outputs
together with the outputs opened to corrupt checkers, `|J| ≤ |H|`.  Any two assignments of values
to the rows of `J` are produced by equally many honest secrets.  The honest secrets are uniform,
so the outputs on `J` are uniform and independent: in particular the kept outputs are uniform
given everything the corrupt checkers were shown. -/
noncomputable def fibreEquiv (J H : Finset (Fin n)) (hcard : J.card ≤ H.card)
    (y y' : Fin n → F) : P.Fibre J H y ≃ P.Fibre J H y' := by
  classical
  let s0 := (P.surjective_on J H hcard (y' - y)).choose
  have h0 := (P.surjective_on J H hcard (y' - y)).choose_spec
  have hz : ∀ k ∉ H, s0 k = 0 := h0.1
  have hv : ∀ j ∈ J, P.apply s0 j = (y' - y) j := h0.2
  exact
    { toFun := fun s => ⟨s.1 + s0, fun k hk => by simp [s.2.1 k hk, hz k hk], fun j hj => by
        rw [P.apply_add, s.2.2 j hj, hv j hj]; simp⟩
      invFun := fun s => ⟨s.1 - s0, fun k hk => by simp [s.2.1 k hk, hz k hk], fun j hj => by
        have h := P.apply_add (s.1 - s0) s0 j
        rw [sub_add_cancel, s.2.2 j hj, hv j hj] at h
        have h' : P.apply (s.1 - s0) j = y' j - (y' - y) j := eq_sub_of_add_eq h.symm
        simpa using h'⟩
      left_inv := fun s => Subtype.ext (by simp)
      right_inv := fun s => Subtype.ext (by simp) }

end HimPoints

/-! ### The counting behind the two uses -/

/-- `RanDouSha` keeps outputs `0..t` and opens the other `n - t - 1`.  With `n ≥ 3t + 1` and at
most `t` corrupt parties there are enough honest checkers for soundness and enough honest
dealers for privacy, whichever parties are corrupt. -/
theorem double_split_counts {n t c cc : ℕ} (hn : 3 * t + 1 ≤ n) (hc : c ≤ t) (hcc : cc ≤ c) :
    c ≤ (n - (t + 1)) - cc ∧ (t + 1) + cc ≤ n - c := by
  omega

/-- `RanSha` and the zero-share generator open outputs `0..2t-1` and keep the other `n - 2t`. -/
theorem single_split_counts {n t c cc : ℕ} (hn : 3 * t + 1 ≤ n) (hc : c ≤ t) (hcc : cc ≤ c) :
    c ≤ 2 * t - cc ∧ (n - 2 * t) + cc ≤ n - c := by
  omega

end DaBit
