/-
Algebraic building blocks of the replicated one-time-bit daBit
(`mpc/src/honeybadger/dabit/replicated.rs`).

Everything here is information-theoretic: there is no adversary bound, no
negligible function and no computational assumption anywhere in this development.
-/
import Mathlib

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-! ### The conversion polynomial `f_T` -/

/-- `f_T(X) = ∏_{j ∈ T} (X - x_j) / (0 - x_j)`: one at zero, zero on `T`, degree `|T|`.

`SetTable::new` computes exactly `(f_T).eval (x id)` as `coeff_f` / `coeff_k`. -/
noncomputable def vanish (x : Fin n → F) (T : Finset (Fin n)) : F[X] :=
  ∏ j ∈ T, C (-(x j))⁻¹ * (X - C (x j))

/-- The closed form the Rust loop evaluates. -/
theorem vanish_eval (x : Fin n → F) (T : Finset (Fin n)) (a : F) :
    (vanish x T).eval a = ∏ j ∈ T, (-(x j))⁻¹ * (a - x j) := by
  simp [vanish, eval_prod]

theorem vanish_eval_zero {x : Fin n → F} (hx0 : ∀ j, x j ≠ 0) (T : Finset (Fin n)) :
    (vanish x T).eval 0 = 1 := by
  rw [vanish_eval]
  refine Finset.prod_eq_one fun j _ => ?_
  have h : -(x j) ≠ 0 := neg_ne_zero.mpr (hx0 j)
  rw [zero_sub]
  exact inv_mul_cancel₀ h

/-- A party inside `T` holds the share zero, which it can compute without knowing the bit. -/
theorem vanish_eval_mem (x : Fin n → F) {T : Finset (Fin n)} {i : Fin n} (hi : i ∈ T) :
    (vanish x T).eval (x i) = 0 := by
  rw [vanish_eval]
  exact Finset.prod_eq_zero hi (by simp)

theorem vanish_natDegree_le (x : Fin n → F) (T : Finset (Fin n)) :
    (vanish x T).natDegree ≤ T.card := by
  unfold vanish
  refine (natDegree_prod_le T (fun j => C (-(x j))⁻¹ * (X - C (x j)))).trans ?_
  have h : ∀ j ∈ T, (C (-(x j))⁻¹ * (X - C (x j))).natDegree ≤ 1 := fun j _ =>
    (natDegree_C_mul_le _ _).trans (natDegree_X_sub_C_le (x j))
  exact (Finset.sum_le_sum h).trans (by simp)

/-! ### Bits in the two fields -/

theorem zmod2_cases (a : ZMod 2) : a = 0 ∨ a = 1 := by
  revert a; decide

theorem zmod2_add_self (a : ZMod 2) : a + a = 0 := by
  revert a; decide

/-- A bit as an element of the arithmetic field. -/
def bitF (b : ZMod 2) : F := if b = 0 then 0 else 1

@[simp] theorem bitF_zero : (bitF 0 : F) = 0 := by simp [bitF]
@[simp] theorem bitF_one : (bitF 1 : F) = 1 := by simp [bitF]

/-- The XOR gate of the fold: `x ⊕ y = x + y - 2xy`, valid in every field. -/
theorem bitF_xor (a b : ZMod 2) :
    (bitF (a + b) : F) = bitF a + bitF b - 2 * (bitF a * bitF b) := by
  have h11 : (1 : ZMod 2) + 1 = 0 := by decide
  rcases zmod2_cases a with rfl | rfl <;> rcases zmod2_cases b with rfl | rfl
  · simp
  · simp
  · simp
  · rw [h11]; simp; ring

/-- Bit-ness: the embedded value is 0 or 1. -/
theorem bitF_bit (b : ZMod 2) : (bitF b : F) = 0 ∨ (bitF b : F) = 1 := by
  rcases zmod2_cases b with rfl | rfl <;> simp

/-! ### Uniqueness of bounded-degree polynomials -/

/-- Two polynomials of degree at most `d` that agree on more than `d` party points are equal. -/
theorem eq_of_eval_eq_on {d : ℕ} {x : Fin n → F} (hx : Function.Injective x) {p q : F[X]}
    (hp : p.natDegree ≤ d) (hq : q.natDegree ≤ d) (S : Finset (Fin n)) (hS : d < S.card)
    (h : ∀ i ∈ S, p.eval (x i) = q.eval (x i)) : p = q := by
  have hlt : ∀ r : F[X], r.natDegree ≤ d → r.degree < (S.card : WithBot ℕ) := fun r hr =>
    (degree_le_of_natDegree_le hr).trans_lt (by exact_mod_cast hS)
  exact Polynomial.eq_of_degrees_lt_of_eval_index_eq S hx.injOn (hlt p hp) (hlt q hq) h

/-- A degree-`t` sharing is determined by its secret and `t` of its shares.  This is what makes
the output of the protocol, against a full-strength adversary, a deterministic function of the
shared bit and the adversary's own shares. -/
theorem eq_of_secret_and_shares {t : ℕ} {x : Fin n → F} (hx : Function.Injective x)
    (hx0 : ∀ j, x j ≠ 0) {p q : F[X]} (hp : p.natDegree ≤ t) (hq : q.natDegree ≤ t)
    (S : Finset (Fin n)) (hS : t ≤ S.card) (h0 : p.eval 0 = q.eval 0)
    (h : ∀ i ∈ S, p.eval (x i) = q.eval (x i)) : p = q := by
  classical
  -- Add the point 0 to the party points.
  let y : Option (Fin n) → F := fun o => o.elim 0 x
  have hy : Function.Injective y := by
    intro a b hab
    cases a with
    | none =>
      cases b with
      | none => rfl
      | some j => exact absurd hab.symm (hx0 j)
    | some i =>
      cases b with
      | none => exact absurd hab (hx0 i)
      | some j => exact congrArg some (hx hab)
  let S' : Finset (Option (Fin n)) := insert none (S.map Function.Embedding.some)
  have hcard : t < S'.card := by
    have : S'.card = S.card + 1 := by
      simp [S']
    omega
  have hlt : ∀ r : F[X], r.natDegree ≤ t → r.degree < (S'.card : WithBot ℕ) := fun r hr =>
    (degree_le_of_natDegree_le hr).trans_lt (by exact_mod_cast hcard)
  refine Polynomial.eq_of_degrees_lt_of_eval_index_eq S' hy.injOn (hlt p hp) (hlt q hq) ?_
  intro o ho
  cases o with
  | none => simpa [y] using h0
  | some i =>
    have hi : i ∈ S := by simpa [S'] using ho
    simpa [y] using h i hi

end DaBit
