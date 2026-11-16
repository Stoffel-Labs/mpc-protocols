# Formal verification of share conversion

Five checks, each checking a different layer of daBit generation, edaBit composition, A2B and
B2A.

| Directory | Tool | What it establishes | Scope |
|-----------|------|---------------------|-------|
| [`dabit/`](dabit/README.md) | Lean 4 + Mathlib | daBit, edaBit, A2B and B2A: correctness, and perfect privacy as an exact count over executions | every `n`, `t` |
| [`netlists/`](netlists/README.md) | Z3 | The adder and comparison circuits the Rust code builds compute the right function | the adder design for every mask and input, and about 900 folded plans per field, each for every input; BLS12-381 and BN254 scalar fields |
| [`extraction/`](extraction/README.md) | exact linear algebra | The randomness-extraction matrix is sound and private against every corrupt set | `n = 4..16`; BLS12-381, BN254 and `GF(2^8)` |
| [`easycrypt/`](easycrypt/README.md) | EasyCrypt | daBit and B2A: perfect real/ideal indistinguishability with a simulator, against an active rushing adversary | `n = 4`, `t = 1` |

All of them are unconditional: nothing here assumes a bound on the adversary's computation.

## What the verification found

- **Randomness extraction was unsound and not private at 13–16 parties.** A coalition of `t`
  parties could get invalid double sharings accepted and learn a relation between kept outputs.
  Reproduced against the real code, fixed with a hyper-invertible matrix, proved in Lean. See
  [`extraction/`](extraction/README.md).
- **The opening's acceptance threshold matters.** Soundness of the degree-`2t` opening needs a
  polynomial matching `degree + t + 1` contributions; a decoder accepting within the unique
  decoding radius would be unsound for some sizes. The code has the right rule.
- **edaBit generation failed on a general field.** It treated a batch in which every candidate
  was rejected as an error, assuming rejection had probability `2^-32`. On BLS12-381's scalar
  field a candidate is rejected about 9% of the time, so generating a single edaBit failed that
  often. It now retries.
- **A conversion could start preprocessing.** `a2b`/`b2a` topped their pools up on demand, which
  made a robust call abortable. A short pool is now an error.

## What is still assumed or unverified

- Channels are private and authenticated, and dealers use fresh randomness.
- The Lean and EasyCrypt proofs are about models. The bit packing, the `Gf256` field axioms, the
  circuit plans and the extraction matrix are checked on the code itself; the rest of the link
  from model to Rust is by inspection, and each README lists the correspondence.
- The protocols are proved one at a time against ideal versions of what they consume, and the
  theorems that connect them are stated (`Compose.lean`), but there is no single end-to-end
  simulation theorem.
- The adder is proved for every mask in its unfolded form. The per-mask plans the protocol runs
  are that circuit with constants folded in; the folding is checked on about 900 masks per
  curve field and exhaustively on small fields, not proved for every mask.
- A2B has no EasyCrypt simulation proof.
- Prime-field arithmetic is `ark-ff`'s and is trusted.
- Liveness under asynchrony, beyond the fact that an online opening always has an honest quorum.
