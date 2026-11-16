# Machine-checked security proofs: daBit, edaBit, A2B and B2A

A Lean 4 + Mathlib development proving the daBit generator
(`mpc/src/honeybadger/dabit/replicated.rs`), edaBit composition and its filter
(`dabit/edabit.rs`), and the two conversions (`a2b/a2b.rs`, `b2a/b2a.rs`). Every theorem below is checked by the Lean kernel:
there is no `sorry`, and the only axioms used are Lean's three standard ones (`propext`,
`Classical.choice`, `Quot.sound`).

The proof is **about a mathematical model of the protocol, not about the Rust source**. The
table in [Model and code](#model-and-code) says which line of the model corresponds to which
piece of code; that correspondence is checked by reading, not by a tool.

## Check it

```bash
cd formal/dabit && lake exe cache get && lake build
```

The build prints the axioms behind each headline theorem. Toolchain: Lean `v4.35.0`, Mathlib
`v4.35.0` (pinned in `lake-manifest.json`).

## What is proved

Setting: `n` parties, threshold `t`, any field `F`, any field `K` of characteristic 2, party
points `x_i ∈ F` and `x^K_i ∈ K` that are non-zero (and, for soundness, distinct). The
statements hold for **every** `n`, `t` and fold shape, not for sampled parameters.

| # | Statement | Theorem | File |
|---|-----------|---------|------|
| 1 | **Correctness.** Both halves are degree-`t` sharings of the same bit `⊕_T β_T`. | `dabit_correct` | `Protocol.lean` |
| 2 | **Bit-ness.** The shared `F` value is 0 or 1. | `bitF_bit`, with 1 | `Basic.lean` |
| 3 | **Echo.** If the honest holders' echoes agree, their local leaf shares are a consistent sharing of one bit, whoever dealt it. | `echo_consistent`, `exists_honest_holder` | `Soundness.lean` |
| 4 | **Opening.** With at most `t` corrupt parties, a degree-`≤ d` polynomial that matches `d + t + 1` contributions is the true one. | `opening_sound` | `Soundness.lean` |
| 4b | **Two-round opening.** The same holds for the batched opening as `BatchReconNode` runs it: each party decodes its combination, then everyone decodes the broadcast values. | `batch_opening_sound` | `BatchOpening.lean` |
| 5 | **Abort or correct.** A run that no honest party aborts gives the honest parties exactly the shares of the honest execution. | `run_sound` | `Soundness.lean` |
| 6 | **Perfect privacy.** For every view of a coalition of at most `t` parties, exactly as many executions produce it with daBit 0 as with daBit 1. | `fibreEquiv`, `perfect_privacy`, `fibre_finite` | `Security.lean` |
| 7 | **Rushing dealer.** 6 still holds when corrupt dealers choose their bits after seeing every honest bit except the hidden one. | `dealt_flip` | `Privacy.lean` |
| 8 | **Nothing else leaks through the output.** At full corruption the output sharings are a function of the view and the daBit only. | `output_determined` | `Security.lean` |
| 9 | **The code's fold.** Level-by-level pairing visits each set once and spends `C(n,t) − 1` multiplications. | `fold_shape`, `fold_mults` | `Fold.lean` |

`dabit_secure` bundles 1, 6 and the existence of the all-honest set for the `C(n,t)` sets the
implementation enumerates.

### The privacy argument

Let `T*` be a set of `t` parties containing every corrupt party (`exists_all_honest_set`).
Nobody outside `T*` is corrupt, so its dealer is honest and no corrupt party receives `β_{T*}`.

The proof builds an explicit map on executions (`swap`): flip `β_{T*}`, and at every
multiplication shift the double sharing by exactly the amount the masked product changed —
`r2t += Δ`, `rt += Δ(0) · f_{T*}`. Lean checks that this map

- keeps every double sharing valid (`adjust_valid`),
- leaves the view unchanged (`swap_view`),
- flips the daBit (`swap_out`),
- is its own inverse (`swap_swap`).

It is therefore a bijection between "this view, daBit 0" and "this view, daBit 1". The honest
randomness is uniform, so the two are equally likely. No bound on the adversary's computing
power appears anywhere: the result is unconditional.

The **view** is deliberately larger than what a coalition really sees:

- every dealt bit except `β_{T*}` (so also every echo);
- the *entire* polynomial behind every degree-`2t` opening, i.e. all `n` shares of it, not only
  the batch-reconstruction messages derived from them;
- the shares, at every party of `T*`, of every double sharing and of both output sharings.

## A2B, B2A and edaBits

The same development proves the two conversions and the edaBit generator, again for every `n`
and `t`. All three are built on one engine, `Circuit.lean`: secure evaluation of a straight-line
program of additions, public constants and multiplications on shared values, with both kinds of
multiplication the code uses (Beaver, opened at degree `t`; degree reduction, opened at degree
`2t`).

| # | Statement | Theorem | File |
|---|-----------|---------|------|
| 10 | **Shared evaluation is correct.** Every wire is a degree-`t` sharing of what the plain program computes. | `run_eval_zero`, `run_natDegree_le` | `Circuit.lean` |
| 11 | **Shared evaluation is private.** For inputs giving the coalition the same shares, and the same values on the wires opened at the end, any view arises from equally much randomness. | `cfibreEquiv` | `Circuit.lean` |
| 12 | **B2A converts each bit correctly**, and the output shares the integer the bits encode. | `b2aBit_eval`, `recompose_eval` | `B2A.lean` |
| 13 | **The width bound.** If `2^ℓ ≤ p` no two `ℓ`-bit values collide; at full width the same holds for values below `p`. | `recompose_faithful`, `recompose_faithful_of_lt` | `B2A.lean` |
| 14 | **B2A is private.** Whatever bit is converted, any view arises from equally many daBits. | `b2aFibreEquiv` | `B2A.lean` |
| 15 | **Checked B2A.** `x(x+1) = 0` exactly for bits, and opening it reveals nothing about which bit. | `bit_of_mul_succ_eq_zero`, `b2aCheckEquiv` | `B2A.lean` |
| 16 | **A2B is correct.** Given a valid edaBit, valid triples and a netlist meeting its specification, output wire `k` shares bit `k` of the canonical representative of `x`. | `a2b_correct` | `A2B.lean` |
| 17 | **A2B is private.** For any two inputs giving the coalition the same shares, any view — the opened mask, every Beaver opening, every share held — arises from equally much preprocessing. | `a2bFibreEquiv` | `A2B.lean` |
| 18 | **A composed candidate that passes the filter is a valid edaBit.** | `composeEdaBit_valid`, `bitOf_bitsValue` | `EdaBit.lean` |
| 19 | **The filter is sound and complete**: the verdict is zero exactly when the candidate is below `p`. | `filter_sound`, `filter_complete` | `EdaBit.lean` |
| 20 | **The filter reveals only its verdict.** | `filterEquiv` | `EdaBit.lean` |

| 21 | **A2B then full-width B2A is the identity** on every field element. | `a2b_b2a_roundtrip`, `a2b_then_b2a` | `Compose.lean` |
| 22 | **The privacy theorems chain.** Paired A2B executions give the coalition the same shares of every output bit, which is the hypothesis of B2A's theorem. | `a2bSwap_outputs_agree` | `Compose.lean` |
| 23 | **Online openings always complete** and cannot be forged: the honest parties alone are a quorum. | `online_opening_completes` | `Compose.lean` |
| 24 | **A triple made from a double sharing is a valid Beaver triple.** | `triple_from_double` | `Compose.lean` |
| 25 | **The extraction matrix is hyper-invertible**, hence random sharing is sound and private against every corrupt set. | `HimPoints.injective_on`, `surjective_on`, `extraction_sound`, `fibreEquiv` | `Extraction.lean` |

Privacy is always the same argument as for the daBit: an explicit, self-inverse map on the
preprocessing that turns an execution on one input into an execution on another while leaving
the view untouched. For A2B it shifts the edaBit by the difference of the inputs, so the opened
mask does not move, and then shifts every Beaver triple by the change in the wire it masks.

### What the netlists compute is checked separately

`a2b_correct` and the filter theorems take the behaviour of the Boolean netlist as a hypothesis
(`NetSpec`, `CmpSpec`): *the adder for mask `y` maps the bits of `r` to the bits of
`(y + r) mod p`*; *the comparison maps the bits of `m` to `[m ≥ p]`*. Those are statements about
the Rust circuit generator, and `../netlists` discharges them on the real circuits with an SMT
solver. Lean proves that a correct netlist is evaluated correctly and privately; the solver
proves the netlists are correct.

### What these theorems assume

- A **daBit** is the ideal object: a uniform bit shared in both fields, the two sharings fixed
  by the bit and the coalition's shares. That is what statements 1, 6 and 8 establish for the
  generator.
- **Beaver triples and double sharings are ideal**: valid, and uniform given the coalition's
  shares. Statements 24 and 25 are the two facts that justify this — the extraction that makes
  random (double) sharings, and the multiplication that turns them into triples — but the
  dealing and checking rounds of `RanSha`/`RanDouSha` are not modelled message by message.
- For A2B the field is `ZMod p`.

## Assumptions

1. **Double sharings are ideal.** Each multiplication consumes a fresh pair of a degree-`t` and
   a degree-`2t` sharing of one value, uniform given the corrupt parties' shares. This is what
   `RanDouSha` is assumed to deliver; its own security is not proved here.
2. **Private, authenticated pairwise channels**, and a network that binds each message to its
   sender. In deployment this is TLS, which is computational.
3. **Fresh uniform bits** from the operating system at every honest dealer.
4. **At most `t` corrupt parties**, `n ≥ 3t + 1`.
5. **Synchronous, abort-permitted preprocessing.** Nothing here is about liveness.

## Model and code

| Model | Code |
|-------|------|
| `vanish x T`, `vanish_eval` | `SetTable::new` — `coeff_f`, `coeff_k` |
| `poly … (.leaf T)`, `leaf_share_of_mem` | `arith_leaves` |
| `polyK`, `polyK_share` | `bin_share` |
| `poly … (.node …)`, `node_share`, `opened_share` | the XOR-fold loop in `run`, `Dn07MulNode::init_mul` |
| `pairUp`, `fold_shape` | the `while width > 1` loop in `run` |
| `echo_consistent` | `advance` — `echo_ok.len() == n − 1`, `DealingMismatch` |
| `batch_opening_sound` | `BatchReconNode` — `apply_vandermonde` then the two decode rounds |
| `opening_sound` with `d = 2t` | `robust_interpolate` — `valid_count >= degree + t + 1`, `matched >= degree + t + 1`; `batch_recover_secret` — `needed = degree + t + 1` |
| `𝒯 = powersetCard t univ` | `all_tsets` — `(0..n).combinations(t)` |
| `hx0`, `Function.Injective x` | the evaluation domains' elements are non-zero and distinct |

## Not covered

- **The Rust implementation.** Message parsing, session and store handling, timeouts, batching,
  and the correspondence above are outside the proof. The existing tests cover them.
- **Abort decisions are a function of the view.** An honest party aborts on an echo mismatch or
  a failed opening; both depend only on values in the view. This is why there is no
  selective-abort leak. It is not mechanised here for general `n`; the EasyCrypt proof in
  `../easycrypt` does mechanise it for `n = 4, t = 1`.
- **Batches.** The theorems are per daBit. A batch is independent copies sharing no randomness.
- **Composition is by hand.** Each protocol is proved against ideal versions of what it
  consumes (A2B against an ideal edaBit and ideal triples, and so on). The theorems fit
  together — statement 8 is exactly the daBit the others assume — but there is no single
  end-to-end theorem and no composition framework.
- **Online robustness.** That the degree-`t` openings of A2B and B2A cannot be blocked or forged
  is `opening_sound` with `d = t`; liveness under asynchrony is not modelled.
- **Agreement on abort.** One honest party may abort while another finishes. The proof shows
  that whoever finishes holds correct shares; it says nothing about pool alignment afterwards.
- **Side channels**, including timing of the local share computation.
