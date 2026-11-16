/-
Secure evaluation of straight-line programs over shared values.

This is the engine shared by every conversion: the adder of A2B, the `r < p` comparison of the
edaBit filter, and the bit-certification of checked B2A are all straight-line programs of
additions, public constants and multiplications, evaluated gate by gate on Shamir sharings.

Two kinds of multiplication appear in the code and both are modelled:

* `mul`   — Beaver, from a triple `(A, B, Cc)`; opens `U - A` and `V - B` at degree `t`.
            Online (`GfMultiply`, and the certification layer of `b2a_checked`).
* `mulDN` — degree reduction, from a double sharing `(rt, r2t)`; opens `U·V + r2t` at degree
            `2t`.  Preprocessing only (`GfDn07MulNode`, the edaBit filter).

Wires are numbered from zero; the first `len` wires are the inputs.  A wire is the sharing
polynomial, so party `i`'s share is its value at `x i` and the shared value is its value at 0.
-/
import DaBit.Protocol

open Polynomial

namespace DaBit

variable {F : Type*} [Field F] {n : ℕ}

/-- A gate together with the randomness it consumes. -/
inductive Gate (F : Type*) [Field F] where
  | const (c : F)
  | add (i j : ℕ)
  | smul (c : F) (i : ℕ)
  | mul (i j : ℕ) (A B Cc : F[X])
  | mulDN (i j : ℕ) (rt r2t : F[X])

/-- The public part of a gate: what the netlist says. -/
inductive Skel (R : Type*) where
  | const (c : R)
  | add (i j : ℕ)
  | smul (c : R) (i : ℕ)
  | mul (dn : Bool) (i j : ℕ)

namespace Gate

def skel : Gate F → Skel F
  | .const c => .const c
  | .add i j => .add i j
  | .smul c i => .smul c i
  | .mul i j _ _ _ => .mul false i j
  | .mulDN i j _ _ => .mul true i j

/-- Well-formed randomness: a Beaver triple is three degree-`t` sharings with `c = a·b`; a double
sharing is a degree-`t` and a degree-`2t` sharing of one value. -/
def Valid (t : ℕ) : Gate F → Prop
  | .mul _ _ A B Cc =>
      A.natDegree ≤ t ∧ B.natDegree ≤ t ∧ Cc.natDegree ≤ t ∧ Cc.eval 0 = A.eval 0 * B.eval 0
  | .mulDN _ _ rt r2t => rt.natDegree ≤ t ∧ r2t.natDegree ≤ 2 * t ∧ rt.eval 0 = r2t.eval 0
  | _ => True

/-- The sharing a gate puts on its output wire.

Beaver (`GfMultiply`, `b2a.rs` step 6): with `d = u - a`, `e = v - b` opened,
`[uv] = [c] + e·[a] + d·[b] + d·e`. -/
noncomputable def step (w : ℕ → F[X]) : Gate F → F[X]
  | .const c => C c
  | .add i j => w i + w j
  | .smul c i => C c * w i
  | .mul i j A B Cc =>
      Cc + C ((w j - B).eval 0) * A + C ((w i - A).eval 0) * B
        + C ((w i - A).eval 0 * (w j - B).eval 0)
  | .mulDN i j rt r2t => C ((w i * w j + r2t).eval 0) - rt

/-- What a gate opens: the complete polynomials, i.e. every party's contribution. -/
noncomputable def opens (w : ℕ → F[X]) : Gate F → List F[X]
  | .mul i j A B _ => [w i - A, w j - B]
  | .mulDN i j _ r2t => [w i * w j + r2t]
  | _ => []

/-- The shares of a gate's randomness held by the parties in `S`. -/
noncomputable def maskShares (x : Fin n → F) (S : Finset (Fin n)) : Gate F → List (Fin n → F)
  | .mul _ _ A B Cc =>
      [fun i => if i ∈ S then A.eval (x i) else 0, fun i => if i ∈ S then B.eval (x i) else 0,
        fun i => if i ∈ S then Cc.eval (x i) else 0]
  | .mulDN _ _ rt r2t =>
      [fun i => if i ∈ S then rt.eval (x i) else 0, fun i => if i ∈ S then r2t.eval (x i) else 0]
  | _ => []

end Gate

/-- Plain evaluation of one gate on values. -/
def Skel.step {R : Type*} [CommRing R] (v : ℕ → R) : Skel R → R
  | .const c => c
  | .add i j => v i + v j
  | .smul c i => c * v i
  | .mul _ i j => v i * v j

/-- Plain evaluation of a program: `len` wires are already defined by `v`. -/
def prun {R : Type*} [CommRing R] : ℕ → (ℕ → R) → List (Skel R) → ℕ → R
  | _, v, [] => v
  | len, v, g :: gs => prun (len + 1) (Function.update v len (g.step v)) gs

/-- Shared evaluation of a program. -/
noncomputable def run : ℕ → (ℕ → F[X]) → List (Gate F) → ℕ → F[X]
  | _, w, [] => w
  | len, w, g :: gs => run (len + 1) (Function.update w len (g.step w)) gs

/-- Everything opened during a run, in order. -/
noncomputable def allOpens : ℕ → (ℕ → F[X]) → List (Gate F) → List F[X]
  | _, _, [] => []
  | len, w, g :: gs => g.opens w ++ allOpens (len + 1) (Function.update w len (g.step w)) gs

/-! ### Correctness -/

theorem Gate.step_eval_zero {t : ℕ} (w : ℕ → F[X]) {g : Gate F} (hg : g.Valid t) :
    (g.step w).eval 0 = g.skel.step (fun k => (w k).eval 0) := by
  cases g with
  | const c => simp [Gate.step, Gate.skel, Skel.step]
  | add i j => simp [Gate.step, Gate.skel, Skel.step]
  | smul c i => simp [Gate.step, Gate.skel, Skel.step]
  | mul i j A B Cc =>
    obtain ⟨-, -, -, hc⟩ := hg
    simp only [Gate.step, Gate.skel, Skel.step, eval_add, eval_mul, eval_C, eval_sub, hc]
    ring
  | mulDN i j rt r2t =>
    obtain ⟨-, -, h0⟩ := hg
    simp only [Gate.step, Gate.skel, Skel.step, eval_add, eval_mul, eval_C, eval_sub, h0]
    ring

theorem Gate.step_natDegree_le {t : ℕ} {w : ℕ → F[X]} (hw : ∀ k, (w k).natDegree ≤ t)
    {g : Gate F} (hg : g.Valid t) : (g.step w).natDegree ≤ t := by
  have hC : ∀ c : F, (C c).natDegree ≤ t := fun c => (natDegree_C c).le.trans (Nat.zero_le t)
  cases g with
  | const c => exact hC c
  | add i j => exact (natDegree_add_le _ _).trans (max_le (hw i) (hw j))
  | smul c i => exact (natDegree_C_mul_le _ _).trans (hw i)
  | mul i j A B Cc =>
    obtain ⟨hA, hB, hCc, -⟩ := hg
    refine (natDegree_add_le _ _).trans (max_le ?_ (hC _))
    refine (natDegree_add_le _ _).trans (max_le ?_ ((natDegree_C_mul_le _ _).trans hB))
    exact (natDegree_add_le _ _).trans (max_le hCc ((natDegree_C_mul_le _ _).trans hA))
  | mulDN i j rt r2t =>
    obtain ⟨hrt, -, -⟩ := hg
    exact (natDegree_sub_le _ _).trans (max_le (hC _) hrt)

/-- Every wire of a run is a degree-`t` sharing. -/
theorem run_natDegree_le {t : ℕ} (len : ℕ) {w : ℕ → F[X]} (hw : ∀ k, (w k).natDegree ≤ t)
    {gs : List (Gate F)} (hv : ∀ g ∈ gs, g.Valid t) : ∀ k, (run len w gs k).natDegree ≤ t := by
  induction gs generalizing len w with
  | nil => exact hw
  | cons g gs ih =>
    refine ih (len + 1) (fun k => ?_) fun g' hg' => hv g' (List.mem_cons_of_mem _ hg')
    by_cases hk : k = len
    · subst hk
      simpa using Gate.step_natDegree_le hw (hv g List.mem_cons_self)
    · simpa [Function.update_of_ne hk] using hw k

/-- **Correctness of shared evaluation.**  Every wire shares exactly the value the plain program
computes on the shared inputs. -/
theorem run_eval_zero {t : ℕ} (len : ℕ) (w : ℕ → F[X]) {gs : List (Gate F)}
    (hv : ∀ g ∈ gs, g.Valid t) :
    ∀ k, (run len w gs k).eval 0 = prun len (fun k => (w k).eval 0) (gs.map Gate.skel) k := by
  induction gs generalizing len w with
  | nil => intro k; rfl
  | cons g gs ih =>
    intro k
    have h := ih (len + 1) (Function.update w len (g.step w))
      (fun g' hg' => hv g' (List.mem_cons_of_mem _ hg')) k
    have hupd : (fun k => (Function.update w len (g.step w) k).eval 0)
        = Function.update (fun k => (w k).eval 0) len (g.skel.step fun k => (w k).eval 0) := by
      funext k'
      by_cases hk : k' = len
      · subst hk
        simp [Gate.step_eval_zero w (hv g List.mem_cons_self)]
      · simp [Function.update_of_ne hk]
    simpa [run, prun, hupd] using h

/-! ### Changing the inputs without changing the view -/

section Privacy

variable (x : Fin n → F) (Ts : Finset (Fin n))

/-- Two assignments of sharings to wires give the parties in `Ts` the same shares. -/
def Agree (w w' : ℕ → F[X]) : Prop := ∀ k, ∀ i ∈ Ts, (w k).eval (x i) = (w' k).eval (x i)

/-- The gate paired with `g` when the wires change from `w` to `w'`: its randomness is shifted so
that it opens exactly the same polynomials. -/
noncomputable def adjGate (w w' : ℕ → F[X]) : Gate F → Gate F
  | .mul i j A B Cc =>
      .mul i j (A + (w' i - w i)) (B + (w' j - w j))
        (Cc + C ((A + (w' i - w i)).eval 0 * (B + (w' j - w j)).eval 0 - A.eval 0 * B.eval 0)
          * vanish x Ts)
  | .mulDN i j rt r2t =>
      .mulDN i j (rt + C ((w i * w j - w' i * w' j).eval 0) * vanish x Ts)
        (r2t + (w i * w j - w' i * w' j))
  | g => g

/-- The run paired with `gs` when the inputs change from `w` to `w'`. -/
noncomputable def adj : ℕ → (ℕ → F[X]) → (ℕ → F[X]) → List (Gate F) → List (Gate F)
  | _, _, _, [] => []
  | len, w, w', g :: gs =>
      adjGate x Ts w w' g ::
        adj (len + 1) (Function.update w len (g.step w))
          (Function.update w' len ((adjGate x Ts w w' g).step w')) gs

variable {x} {Ts}

theorem adjGate_skel (w w' : ℕ → F[X]) (g : Gate F) : (adjGate x Ts w w' g).skel = g.skel := by
  cases g <;> rfl

theorem adjGate_opens (w w' : ℕ → F[X]) (g : Gate F) :
    (adjGate x Ts w w' g).opens w' = g.opens w := by
  cases g with
  | const c => rfl
  | add i j => rfl
  | smul c i => rfl
  | mul i j A B Cc =>
    simp only [adjGate, Gate.opens]
    congr 1
    · ring
    · congr 1; ring
  | mulDN i j rt r2t =>
    simp only [adjGate, Gate.opens]
    congr 1; ring

theorem adjGate_step_eval {w w' : ℕ → F[X]} (hw : Agree x Ts w w') (g : Gate F) {i : Fin n}
    (hi : i ∈ Ts) : ((adjGate x Ts w w' g).step w').eval (x i) = (g.step w).eval (x i) := by
  cases g with
  | const c => rfl
  | add a b => simp [adjGate, Gate.step, hw a i hi, hw b i hi]
  | smul c a => simp [adjGate, Gate.step, hw a i hi]
  | mul a b A B Cc =>
    have hd : w' a - (A + (w' a - w a)) = w a - A := by ring
    have he : w' b - (B + (w' b - w b)) = w b - B := by ring
    simp only [adjGate, Gate.step, hd, he, eval_add, eval_mul, eval_C, eval_sub,
      vanish_eval_mem x hi, hw a i hi, hw b i hi]
    ring
  | mulDN a b rt r2t =>
    have hD : w' a * w' b + (r2t + (w a * w b - w' a * w' b)) = w a * w b + r2t := by ring
    simp only [adjGate, Gate.step, hD, eval_add, eval_mul, eval_C, eval_sub,
      vanish_eval_mem x hi]
    ring

theorem adjGate_maskShares {w w' : ℕ → F[X]} (hw : Agree x Ts w w') (g : Gate F) :
    (adjGate x Ts w w' g).maskShares x Ts = g.maskShares x Ts := by
  cases g with
  | const c => rfl
  | add i j => rfl
  | smul c i => rfl
  | mul a b A B Cc =>
    simp only [adjGate, Gate.maskShares]
    have h1 : (fun i => if i ∈ Ts then (A + (w' a - w a)).eval (x i) else 0)
        = fun i => if i ∈ Ts then A.eval (x i) else 0 := by
      funext i; by_cases hi : i ∈ Ts
      · simp [hi, hw a i hi]
      · simp [hi]
    have h2 : (fun i => if i ∈ Ts then (B + (w' b - w b)).eval (x i) else 0)
        = fun i => if i ∈ Ts then B.eval (x i) else 0 := by
      funext i; by_cases hi : i ∈ Ts
      · simp [hi, hw b i hi]
      · simp [hi]
    have h3 : ∀ c : F, (fun i => if i ∈ Ts then (Cc + C c * vanish x Ts).eval (x i) else 0)
        = fun i => if i ∈ Ts then Cc.eval (x i) else 0 := by
      intro c; funext i; by_cases hi : i ∈ Ts
      · simp [hi, vanish_eval_mem x hi]
      · simp [hi]
    rw [h1, h2, h3]
  | mulDN a b rt r2t =>
    simp only [adjGate, Gate.maskShares]
    have h1 : ∀ c : F, (fun i => if i ∈ Ts then (rt + C c * vanish x Ts).eval (x i) else 0)
        = fun i => if i ∈ Ts then rt.eval (x i) else 0 := by
      intro c; funext i; by_cases hi : i ∈ Ts
      · simp [hi, vanish_eval_mem x hi]
      · simp [hi]
    have h2 : (fun i => if i ∈ Ts then (r2t + (w a * w b - w' a * w' b)).eval (x i) else 0)
        = fun i => if i ∈ Ts then r2t.eval (x i) else 0 := by
      funext i; by_cases hi : i ∈ Ts
      · simp [hi, hw a i hi, hw b i hi]
      · simp [hi]
    rw [h1, h2]

theorem adjGate_valid (hx0 : ∀ j, x j ≠ 0) {t : ℕ} (hTs : Ts.card ≤ t) {w w' : ℕ → F[X]}
    (hw : ∀ k, (w k).natDegree ≤ t) (hw' : ∀ k, (w' k).natDegree ≤ t) {g : Gate F}
    (hg : g.Valid t) : (adjGate x Ts w w' g).Valid t := by
  have hv : ∀ c : F, (C c * vanish x Ts).natDegree ≤ t := fun c =>
    (natDegree_C_mul_le _ _).trans ((vanish_natDegree_le x Ts).trans hTs)
  cases g with
  | const c => trivial
  | add i j => trivial
  | smul c i => trivial
  | mul a b A B Cc =>
    obtain ⟨hA, hB, hCc, hc⟩ := hg
    refine ⟨?_, ?_, ?_, ?_⟩
    · exact (natDegree_add_le _ _).trans
        (max_le hA ((natDegree_sub_le _ _).trans (max_le (hw' a) (hw a))))
    · exact (natDegree_add_le _ _).trans
        (max_le hB ((natDegree_sub_le _ _).trans (max_le (hw' b) (hw b))))
    · exact (natDegree_add_le _ _).trans (max_le hCc (hv _))
    · simp only [eval_add, eval_mul, eval_C, vanish_eval_zero hx0, hc]
      ring
  | mulDN a b rt r2t =>
    obtain ⟨hrt, hr2t, h0⟩ := hg
    refine ⟨?_, ?_, ?_⟩
    · exact (natDegree_add_le _ _).trans (max_le hrt (hv _))
    · refine (natDegree_add_le _ _).trans (max_le hr2t ?_)
      refine (natDegree_sub_le _ _).trans (max_le ?_ ?_)
      · refine natDegree_mul_le.trans ?_
        have := hw a; have := hw b; omega
      · refine natDegree_mul_le.trans ?_
        have := hw' a; have := hw' b; omega
    · simp only [eval_add, eval_mul, eval_C, vanish_eval_zero hx0, h0]
      ring

theorem adjGate_adjGate (w w' : ℕ → F[X]) (g : Gate F) :
    adjGate x Ts w' w (adjGate x Ts w w' g) = g := by
  cases g with
  | const c => rfl
  | add i j => rfl
  | smul c i => rfl
  | mul a b A B Cc =>
    have hA : A + (w' a - w a) + (w a - w' a) = A := by ring
    have hB : B + (w' b - w b) + (w b - w' b) = B := by ring
    simp only [adjGate, hA, hB]
    congr 1
    rw [add_assoc, ← add_mul, ← C_add]
    simp
  | mulDN a b rt r2t =>
    simp only [adjGate]
    congr 1
    · rw [add_assoc, ← add_mul, ← C_add]
      simp
    · ring

theorem agree_update {w w' : ℕ → F[X]} (hw : Agree x Ts w w') (len : ℕ) {p p' : F[X]}
    (hp : ∀ i ∈ Ts, p.eval (x i) = p'.eval (x i)) :
    Agree x Ts (Function.update w len p) (Function.update w' len p') := by
  intro k i hi
  by_cases hk : k = len
  · subst hk; simpa using hp i hi
  · simpa [Function.update_of_ne hk] using hw k i hi

/-- The paired run has the same netlist. -/
theorem adj_skel (len : ℕ) (w w' : ℕ → F[X]) (gs : List (Gate F)) :
    (adj x Ts len w w' gs).map Gate.skel = gs.map Gate.skel := by
  induction gs generalizing len w w' with
  | nil => rfl
  | cons g gs ih => simp only [adj, List.map_cons, adjGate_skel, ih]

/-- **The paired run opens exactly the same polynomials.** -/
theorem adj_allOpens (len : ℕ) {w w' : ℕ → F[X]} (hw : Agree x Ts w w') (gs : List (Gate F)) :
    allOpens len w' (adj x Ts len w w' gs) = allOpens len w gs := by
  induction gs generalizing len w w' with
  | nil => rfl
  | cons g gs ih =>
    simp only [adj, allOpens, adjGate_opens]
    rw [ih (len + 1) (agree_update hw len fun i hi => (adjGate_step_eval hw g hi).symm)]

/-- **The parties in `Ts` hold the same shares of all the randomness.** -/
theorem adj_maskShares (len : ℕ) {w w' : ℕ → F[X]} (hw : Agree x Ts w w')
    (gs : List (Gate F)) :
    (adj x Ts len w w' gs).flatMap (Gate.maskShares x Ts) = gs.flatMap (Gate.maskShares x Ts) := by
  induction gs generalizing len w w' with
  | nil => rfl
  | cons g gs ih =>
    simp only [adj, List.flatMap_cons, adjGate_maskShares hw]
    rw [ih (len + 1) (agree_update hw len fun i hi => (adjGate_step_eval hw g hi).symm)]

/-- **The parties in `Ts` hold the same shares of every wire.** -/
theorem adj_agree (len : ℕ) {w w' : ℕ → F[X]} (hw : Agree x Ts w w') (gs : List (Gate F)) :
    Agree x Ts (run len w gs) (run len w' (adj x Ts len w w' gs)) := by
  induction gs generalizing len w w' with
  | nil => exact hw
  | cons g gs ih =>
    exact ih (len + 1) (agree_update hw len fun i hi => (adjGate_step_eval hw g hi).symm)

/-- The paired run uses well-formed randomness. -/
theorem adj_valid (hx0 : ∀ j, x j ≠ 0) {t : ℕ} (hTs : Ts.card ≤ t) (len : ℕ) {w w' : ℕ → F[X]}
    (hw : ∀ k, (w k).natDegree ≤ t) (hw' : ∀ k, (w' k).natDegree ≤ t) {gs : List (Gate F)}
    (hv : ∀ g ∈ gs, g.Valid t) : ∀ g ∈ adj x Ts len w w' gs, g.Valid t := by
  induction gs generalizing len w w' with
  | nil => intro g hg; simp [adj] at hg
  | cons g gs ih =>
    have hg := hv g List.mem_cons_self
    have hg' := adjGate_valid hx0 hTs hw hw' hg
    have hupd : ∀ (u : ℕ → F[X]) (p : F[X]), (∀ k, (u k).natDegree ≤ t) → p.natDegree ≤ t →
        ∀ k, (Function.update u len p k).natDegree ≤ t := by
      intro u p hu hp k
      by_cases hk : k = len
      · subst hk; simpa using hp
      · simpa [Function.update_of_ne hk] using hu k
    intro g'' hmem
    simp only [adj, List.mem_cons] at hmem
    rcases hmem with rfl | hmem
    · exact hg'
    · exact ih (len + 1) (hupd w _ hw (Gate.step_natDegree_le hw hg))
        (hupd w' _ hw' (Gate.step_natDegree_le hw' hg'))
        (fun g₀ h₀ => hv g₀ (List.mem_cons_of_mem _ h₀)) g'' hmem

/-- Pairing back returns the original run: the pairing is a bijection. -/
theorem adj_adj (len : ℕ) (w w' : ℕ → F[X]) (gs : List (Gate F)) :
    adj x Ts len w' w (adj x Ts len w w' gs) = gs := by
  induction gs generalizing len w w' with
  | nil => rfl
  | cons g gs ih =>
    simp only [adj, adjGate_adjGate]
    rw [ih]

/-- **An opened output is the same polynomial in both runs** as soon as it has the same value:
with `t` shares and the secret fixed, a degree-`t` sharing has no freedom left. -/
theorem opened_output_eq (hx : Function.Injective x) (hx0 : ∀ j, x j ≠ 0) {t : ℕ}
    (hTs : t ≤ Ts.card) {p p' : F[X]} (hp : p.natDegree ≤ t) (hp' : p'.natDegree ≤ t)
    (h0 : p.eval 0 = p'.eval 0) (hagree : ∀ i ∈ Ts, p.eval (x i) = p'.eval (x i)) : p = p' :=
  eq_of_secret_and_shares hx hx0 hp hp' Ts hTs h0 hagree

end Privacy

/-! ### The view, and the counting statement -/

section View

variable (x : Fin n → F) (Ts : Finset (Fin n))

/-- What a coalition inside `Ts` sees of a run on inputs `w` (the first `len` wires):
the netlist, every opened polynomial, its shares of all the randomness, its shares of every
wire, and the complete sharing of each wire in `outs`, which the protocol opens at the end. -/
structure CView (F : Type*) [Field F] (n : ℕ) where
  skel : List (Skel F)
  opened : List F[X]
  masks : List (Fin n → F)
  wireShares : ℕ → Fin n → F
  outputs : List F[X]

noncomputable def cview (len : ℕ) (outs : List ℕ) (w : ℕ → F[X]) (gs : List (Gate F)) :
    CView F n where
  skel := gs.map Gate.skel
  opened := allOpens len w gs
  masks := gs.flatMap (Gate.maskShares x Ts)
  wireShares := fun k i => if i ∈ Ts then (run len w gs k).eval (x i) else 0
  outputs := outs.map (run len w gs)

/-- The well-formed randomness that produces view `v` on inputs `w`. -/
def CFibre (t len : ℕ) (outs : List ℕ) (w : ℕ → F[X]) (v : CView F n) : Type _ :=
  {gs : List (Gate F) // (∀ g ∈ gs, g.Valid t) ∧ cview x Ts len outs w gs = v}

variable {x} {Ts}

/-- **Perfect privacy of shared evaluation.**

Take two input assignments `w`, `w'` that give the coalition the same shares, and suppose the
program being run (`v.skel`) computes the same value on every wire that is opened at the end.  Then pairing is
a one-to-one correspondence between the randomness producing a view on `w` and the randomness
producing the same view on `w'`.  The randomness is uniform, so the view has the same
distribution whatever the inputs are: it carries no information beyond the opened outputs. -/
noncomputable def cfibreEquiv (hx : Function.Injective x) (hx0 : ∀ j, x j ≠ 0) {t : ℕ}
    (hTs : Ts.card = t) (len : ℕ) (outs : List ℕ) {w w' : ℕ → F[X]}
    (hw : ∀ k, (w k).natDegree ≤ t) (hw' : ∀ k, (w' k).natDegree ≤ t)
    (hagree : Agree x Ts w w')
    (v : CView F n)
    (hout : ∀ k ∈ outs,
      prun len (fun k => (w k).eval 0) v.skel k = prun len (fun k => (w' k).eval 0) v.skel k) :
    CFibre x Ts t len outs w v ≃ CFibre x Ts t len outs w' v := by
  have key : ∀ {u u' : ℕ → F[X]}, (∀ k, (u k).natDegree ≤ t) → (∀ k, (u' k).natDegree ≤ t) →
      Agree x Ts u u' →
      (∀ k ∈ outs,
        prun len (fun k => (u k).eval 0) v.skel k = prun len (fun k => (u' k).eval 0) v.skel k) →
      ∀ gs : List (Gate F), (∀ g ∈ gs, g.Valid t) → cview x Ts len outs u gs = v →
        (∀ g ∈ adj x Ts len u u' gs, g.Valid t) ∧
          cview x Ts len outs u' (adj x Ts len u u' gs) = v := by
    intro u u' hu hu' hag ho gs hv hview
    have hv' := adj_valid hx0 hTs.le len hu hu' hv
    refine ⟨hv', ?_⟩
    have hsk : gs.map Gate.skel = v.skel := congrArg CView.skel hview
    have hrun := adj_agree len hag gs
    rw [← hview]
    simp only [cview, CView.mk.injEq]
    refine ⟨adj_skel len u u' gs, adj_allOpens len hag gs, adj_maskShares len hag gs, ?_, ?_⟩
    · funext k i
      by_cases hi : i ∈ Ts
      · simp [hi, hrun k i hi]
      · simp [hi]
    · refine List.map_congr_left fun k hk => ?_
      refine (opened_output_eq hx hx0 hTs.ge (run_natDegree_le len hu hv k)
        (run_natDegree_le len hu' hv' k) ?_ (hrun k)).symm
      rw [run_eval_zero len u hv, run_eval_zero len u' hv', adj_skel, hsk]
      exact ho k hk
  have hag' : Agree x Ts w' w := fun k i hi => (hagree k i hi).symm
  have hout' : ∀ k ∈ outs,
      prun len (fun k => (w' k).eval 0) v.skel k = prun len (fun k => (w k).eval 0) v.skel k :=
    fun k hk => (hout k hk).symm
  exact
    { toFun := fun e =>
        ⟨adj x Ts len w w' e.1, key hw hw' hagree hout e.1 e.2.1 e.2.2⟩
      invFun := fun e =>
        ⟨adj x Ts len w' w e.1, key hw' hw hag' hout' e.1 e.2.1 e.2.2⟩
      left_inv := fun e => Subtype.ext (adj_adj len w w' e.1)
      right_inv := fun e => Subtype.ext (adj_adj len w' w e.1) }

end View

/-! ### Boolean programs inside a field -/

/-- A program over one ring, read in another through a ring homomorphism. -/
def Skel.map {R S : Type*} (φ : R → S) : Skel R → Skel S
  | .const c => .const (φ c)
  | .add i j => .add i j
  | .smul c i => .smul (φ c) i
  | .mul dn i j => .mul dn i j

/-- Evaluating a mapped program on mapped inputs gives the mapped result.  With
`φ = bitK : ZMod 2 →+* K` this says that running a Boolean netlist on bits embedded in `K`
computes the embedded Boolean result: XOR is `+`, AND is `·`. -/
theorem prun_map {R S : Type*} [CommRing R] [CommRing S] (φ : R →+* S) (len : ℕ) (v : ℕ → R)
    (gs : List (Skel R)) :
    ∀ k, prun len (fun k => φ (v k)) (gs.map (Skel.map φ)) k = φ (prun len v gs k) := by
  induction gs generalizing len v with
  | nil => intro k; rfl
  | cons g gs ih =>
    intro k
    have hstep : (Skel.map φ g).step (fun k => φ (v k)) = φ (g.step v) := by
      cases g <;> simp [Skel.map, Skel.step]
    have hupd : Function.update (fun k => φ (v k)) len (φ (g.step v))
        = fun k => φ (Function.update v len (g.step v) k) := by
      funext k'
      by_cases hk : k' = len
      · subst hk; simp
      · simp [Function.update_of_ne hk]
    simp only [List.map_cons, prun, hstep, hupd]
    exact ih (len + 1) _ k

end DaBit
