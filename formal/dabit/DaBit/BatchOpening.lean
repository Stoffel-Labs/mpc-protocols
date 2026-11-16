/-
The opening as `BatchReconNode` actually runs it: two rounds.

Round 1.  For each party `j`, every party sends `j` its share of `Y_j = Σ_k x_j^k · D_k`
(`apply_vandermonde`); `j` decodes `Y_j` and keeps `y_j = Y_j(0)`.
Round 2.  Every party broadcasts its `y_j`; a receiver decodes the polynomial
`Z = Σ_k D_k(0) · X^k` from them and reads the opened values off its coefficients.

Both rounds use the same acceptance rule, so `opening_sound` applies to each.
-/
import DaBit.Soundness

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-- **Soundness of the two-round batched opening.**  `D k` are the `d + 1` polynomials of one
batch, each of degree at most `d`; `H` is the set of honest parties, with at most `t` parties
outside it.

* `q1 j` is what honest party `j` accepted in round 1, among contributions in which the honest
  parties sent their true shares of `Y_j`;
* `q2` is what some honest receiver accepted in round 2, among broadcasts in which each honest
  party `j` sent `(q1 j)(0)`.

Then the coefficients of `q2` are exactly the true opened values `D_k(0)`. -/
theorem batch_opening_sound {d t : ℕ} {x : Fin n → F} (hx : Function.Injective x)
    (D : Fin (d + 1) → F[X]) (hD : ∀ k, (D k).natDegree ≤ d)
    (H : Finset (Fin n)) (hcorrupt : Hᶜ.card ≤ t)
    (q1 : Fin n → F[X])
    (hq1 : ∀ j ∈ H, (q1 j).natDegree ≤ d ∧
      ∃ (M : Finset (Fin n)) (recv : Fin n → F), d + t + 1 ≤ M.card ∧
        (∀ i ∈ M, (q1 j).eval (x i) = recv i) ∧
        ∀ i ∈ H, recv i = ∑ k : Fin (d + 1), x j ^ (k : ℕ) * (D k).eval (x i))
    (q2 : F[X]) (hq2 : q2.natDegree ≤ d) (M : Finset (Fin n)) (recv : Fin n → F)
    (hM : d + t + 1 ≤ M.card) (hmatch : ∀ j ∈ M, q2.eval (x j) = recv j)
    (hH : ∀ j ∈ H, recv j = (q1 j).eval 0) :
    ∀ k : Fin (d + 1), q2.coeff k = (D k).eval 0 := by
  -- Round 1: every honest party decodes the true `Y_j`.
  have hY : ∀ j ∈ H, q1 j = ∑ k : Fin (d + 1), C (x j ^ (k : ℕ)) * D k := by
    intro j hj
    obtain ⟨hdeg, M1, recv1, hM1, hmatch1, hH1⟩ := hq1 j hj
    refine opening_sound hx ?_ hdeg H M1 recv1 hcorrupt (fun i hi => ?_) hM1 hmatch1
    · exact natDegree_sum_le_of_forall_le _ _ fun k _ =>
        (natDegree_C_mul_le _ _).trans (hD k)
    · rw [hH1 i hi]
      simp [eval_finsetSum]
  -- Round 2: the broadcast values of the honest parties lie on `Z`.
  have hZdeg : (∑ k : Fin (d + 1), C ((D k).eval 0) * X ^ (k : ℕ) : F[X]).natDegree ≤ d :=
    natDegree_sum_le_of_forall_le _ _ fun k _ =>
      (natDegree_C_mul_X_pow_le _ _).trans (by omega)
  have hq2Z : q2 = ∑ k : Fin (d + 1), C ((D k).eval 0) * X ^ (k : ℕ) := by
    refine opening_sound hx hZdeg hq2 H M recv hcorrupt (fun j hj => ?_) hM hmatch
    rw [hH j hj, hY j hj]
    simp only [eval_finsetSum, eval_mul, eval_C, eval_pow, eval_X]
    exact Finset.sum_congr rfl fun k _ => mul_comm _ _
  intro k
  rw [hq2Z, finsetSum_coeff]
  simp only [coeff_C_mul_X_pow]
  rw [Finset.sum_eq_single k]
  · simp
  · intro k' _ hne
    have : (k : ℕ) ≠ (k' : ℕ) := fun h => hne (Fin.ext h.symm)
    simp [this]
  · simp

end DaBit
