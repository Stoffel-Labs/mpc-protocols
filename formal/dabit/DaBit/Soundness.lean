/-
Active security of the output: a run that no honest party aborts produces exactly the shares
of the honest execution.  The adversary's only other option is to make somebody abort.
-/
import DaBit.Protocol

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-! ### The opening -/

/-- **Soundness of one opening.**  `H` is the set of honest parties, at most `t` parties are
outside it, and the honest parties contribute shares of `D`, of degree at most `d`.  Whatever
the other parties contribute, a polynomial `q` of degree at most `d` that matches at least
`d + t + 1` of the contributions is `D` itself.

This is the acceptance rule of `robust_interpolate` (`valid_count >= degree + t + 1`,
`matched >= degree + t + 1`, and the `needed` verification points of `batch_recover_secret`),
used by `BatchReconNode` in both of its rounds. -/
theorem opening_sound {d t : ℕ} {x : Fin n → F} (hx : Function.Injective x) {D q : F[X]}
    (hD : D.natDegree ≤ d) (hq : q.natDegree ≤ d) (H M : Finset (Fin n)) (recv : Fin n → F)
    (hcorrupt : Hᶜ.card ≤ t) (hH : ∀ i ∈ H, recv i = D.eval (x i))
    (hM : d + t + 1 ≤ M.card) (hmatch : ∀ i ∈ M, q.eval (x i) = recv i) : q = D := by
  classical
  refine eq_of_eval_eq_on hx hq hD (M ∩ H) ?_ ?_
  · have h1 := Finset.card_inter_add_card_sdiff M H
    have h2 : (M \ H).card ≤ Hᶜ.card :=
      Finset.card_le_card fun i hi => by
        simp only [Finset.mem_sdiff] at hi
        simpa using hi.2
    omega
  · intro i hi
    rw [Finset.mem_inter] at hi
    rw [hmatch i hi.1, hH i hi.2]

/-! ### The dealing and the echo -/

/-- Every unqualified set has an honest party outside it, so every bit has an honest holder. -/
theorem exists_honest_holder {t : ℕ} (H T : Finset (Fin n)) (hcorrupt : Hᶜ.card ≤ t)
    (hT : T.card ≤ t) (hn : 2 * t + 1 ≤ n) : ∃ i ∈ H, i ∉ T := by
  by_contra hne
  push Not at hne
  have h1 : H.card + Hᶜ.card = n := by simp
  have h2 : H.card ≤ T.card := Finset.card_le_card fun i hi => hne i hi
  omega

/-- **Soundness of the echo.**  `held i` is the bit party `i` accepted for set `T`.  If the
honest holders' pairwise echoes all compared equal, then the honest parties' locally computed
leaf shares — zero inside `T`, `held i · f_T(x_i)` outside — are the shares of one polynomial
`b · f_T`: a consistent degree-`|T|` sharing of a bit, whoever dealt it. -/
theorem echo_consistent (x : Fin n → F) (H T : Finset (Fin n)) (held : Fin n → ZMod 2)
    (hecho : ∀ i ∈ H, ∀ j ∈ H, i ∉ T → j ∉ T → held i = held j) :
    ∃ b : ZMod 2, ∀ i ∈ H,
      (if i ∈ T then (0 : F) else bitF (held i) * (vanish x T).eval (x i))
        = (C (bitF b) * vanish x T).eval (x i) := by
  by_cases h : ∃ j ∈ H, j ∉ T
  · obtain ⟨j, hj, hjT⟩ := h
    refine ⟨held j, fun i hi => ?_⟩
    by_cases hiT : i ∈ T
    · simp [hiT, vanish_eval_mem x hiT]
    · simp [hiT, hecho i hi j hj hiT hjT]
  · push Not at h
    refine ⟨0, fun i hi => ?_⟩
    simp [h i hi]

/-! ### The whole fold under an active adversary -/

/-- A run in which the opened polynomials are whatever the opening accepted: `node l r rt r2t q`
records the accepted polynomial `q` at that multiplication. -/
inductive Run (F : Type*) [Field F] (n : ℕ) where
  | leaf : Finset (Fin n) → Run F n
  | node : Run F n → Run F n → F[X] → F[X] → F[X] → Run F n

namespace Run

/-- The honest execution with the same bits and the same double sharings. -/
def honest : Run F n → DTree F n
  | .leaf T => .leaf T
  | .node l r rt r2t _ => .node l.honest r.honest rt r2t

/-- The honest parties' shares in the run: they use the accepted opening `q`, not the true one. -/
noncomputable def poly (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) : Run F n → F[X]
  | .leaf T => C (bitF (β T)) * vanish x T
  | .node l r rt _ q => poly x β l + poly x β r - C 2 * (C (q.eval 0) - rt)

/-- No honest party aborted: at every multiplication the accepted `q` has degree at most `2t`
and matches at least `2t + t + 1` contributions, where the honest parties (`H`) contributed
the shares they computed from their own state in this run. -/
def Accepted (x : Fin n → F) (β : Finset (Fin n) → ZMod 2) (H : Finset (Fin n)) (t : ℕ) :
    Run F n → Prop
  | .leaf _ => True
  | .node l r _ r2t q =>
      Accepted x β H t l ∧ Accepted x β H t r ∧ q.natDegree ≤ 2 * t ∧
        ∃ (M : Finset (Fin n)) (recv : Fin n → F),
          2 * t + t + 1 ≤ M.card ∧ (∀ i ∈ M, q.eval (x i) = recv i) ∧
            ∀ i ∈ H, recv i
              = (poly x β l).eval (x i) * (poly x β r).eval (x i) + r2t.eval (x i)

end Run

/-- **Abort or correct.**  With at most `t` corrupt parties and valid double sharings, a run
that no honest party aborts gives the honest parties exactly the output sharing of the honest
execution.  Lying at an opening cannot change a daBit; it can only abort the batch. -/
theorem run_sound {x : Fin n → F} (hx : Function.Injective x) (β : Finset (Fin n) → ZMod 2)
    {H : Finset (Fin n)} {t : ℕ} (hcorrupt : Hᶜ.card ≤ t) {run : Run F n}
    (hv : run.honest.Valid t) (hacc : run.Accepted x β H t) :
    run.poly x β = poly x β run.honest := by
  induction run with
  | leaf T => rfl
  | node l r rt r2t q ihl ihr =>
    obtain ⟨hl, hr, -, -, -⟩ := id hv
    obtain ⟨al, ar, hq, M, recv, hM, hmatch, hH⟩ := hacc
    have el := ihl hl al
    have er := ihr hr ar
    have hD : (DaBit.poly x β l.honest * DaBit.poly x β r.honest + r2t).natDegree ≤ 2 * t :=
      opened_natDegree_le x β hv _ (by simp [Run.honest, opened])
    have hqD : q = DaBit.poly x β l.honest * DaBit.poly x β r.honest + r2t := by
      refine opening_sound hx hD hq H M recv hcorrupt (fun i hi => ?_) hM hmatch
      rw [hH i hi, el, er]
      simp
    simp only [Run.poly, Run.honest, DaBit.poly, el, er, hqD]

end DaBit
