# Real/ideal proofs in EasyCrypt (`n = 4`, `t = 1`)

`DaBitSim.ec` proves, for the smallest deployment, that the daBit protocol of
`mpc/src/honeybadger/dabit/replicated.rs` is **perfectly indistinguishable** from an ideal daBit
functionality run with a simulator:

```
lemma real_ideal &m :
  Pr[Protocol(A).main() @ &m : res] = Pr[IdealWorld(A).main() @ &m : res].
```

for every adversary `A`. It is an equality, not a bound: there is no error term and no
assumption on what `A` can compute. The file contains no `admit`.

It complements the Lean development in `../dabit`, which covers every `n` and `t` but states
privacy as a count over executions rather than as a simulation.

`B2ASim.ec` does the same for B2A, one bit at a time, against the ideal daBit that the first
file shows the generator realises:

```
lemma b2a_real_ideal &m :
  Pr[B2AReal(A).main() @ &m : res] = Pr[B2AIdeal(A).main() @ &m : res].
```

There the adversary chooses the bit, the corrupt party's share of it and the corrupt party's
shares of the daBit, sees the whole opened polynomial `c = x ⊕ r`, and finally the honest
parties' arithmetic output shares. The simulator is given the corrupt party's input share and
never the bit; it opens a fair coin. A value of several bits is this protocol run once per bit
on independent daBits, followed by a public linear combination.

A2B has no EasyCrypt proof: its circuit makes the game large. Its privacy for every `n` is
`a2bFibreEquiv` in the Lean development.

## Check it

```bash
easycrypt DaBitSim.ec && easycrypt B2ASim.ec
```

Exit status 0 means every lemma checked. Built with EasyCrypt `r2026.10`, Alt-Ergo and Z3.

## The two worlds

**The adversary** is the corrupt party and the environment at once. It

- chooses the bit of every set the corrupt party holds (so also every set it could deal);
- chooses its own shares of every double sharing, after seeing everything so far;
- at each of the three multiplications sees the whole opened degree-2 polynomial — every
  honest share — and only then says which share the corrupt party contributes;
- finally sees whether the honest parties accepted, and all their output shares in both fields.

**The real protocol** (`Protocol`) samples the hidden set's bit and the honest part of each
double sharing, runs the XOR fold `({c} ⊕ {p}) ⊕ ({q} ⊕ {s})`, and accepts an opening only if
the corrupt party's share lies on the polynomial.

**The ideal world** (`IdealWorld`) samples a uniform bit `b`, runs the simulator `Sim`, and
gives the honest parties the unique degree-1 sharings of `b` through the corrupt party's
shares. `Sim` is a separate module that is never passed `b`: it samples each opening uniformly
among the polynomials consistent with the corrupt party's own share, and decides acceptance
itself.

## Assumptions

Stated as axioms in the file; each is a parameter of the setting, not a cryptographic assumption.

- `F` and `K` are fields; `K` has characteristic 2 (`char2`).
- `dF` is the uniform distribution on `F` (`dF_ll`, `dF_funi`).
- Every party's evaluation point is non-zero.
- Double sharings are ideal: the adversary picks its two shares, the rest is uniform.

## Limits

- **One size.** `n = 4`, `t = 1` only; the general case is the Lean development.
- **One position.** The corrupt party's set is the first leaf of the fold. The fold is
  symmetric under swapping the children of any node and multiplication is commutative, so the
  other three positions are the same game with the leaves relabelled; that step is not
  mechanised.
- **The dealing is abstracted.** The adversary simply chooses every bit it holds. That gives it
  strictly more power than the deal-and-echo round does, and it leaves the echo's own
  soundness to `echo_consistent` in Lean.
- **Stronger than the code in two places.** The distinguisher receives the would-be outputs
  even after an abort, and the run continues after a rejected opening. Both give the adversary
  more than the implementation does.
- It is a proof about this model, not about the Rust source.
