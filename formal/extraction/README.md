# The randomness-extraction matrix

`RanSha`, `RanDouSha`, the zero-share generator and their `GF(2^8)` twins all work the same way:
every party deals a sharing, an `n × n` matrix is applied to the `n` dealings, some outputs are
kept and the rest are opened — one to each checking party — to be checked. Everything downstream
(Beaver triples, daBits, edaBits, both conversions) is built from the kept outputs.

Two properties of the matrix carry the protocol, for every set `C` of at most `t` corrupt parties:

- **soundness** — bad dealings from `C` cannot cancel in every honest check;
- **privacy** — the kept outputs are uniform given the outputs opened to checkers in `C`.

Both ask for particular sub-matrices, chosen by the adversary, to have full rank. That is what a
*hyper-invertible* matrix guarantees, and what a Vandermonde matrix does not.

## The weakness that was here

The code used `M[j][k] = α_j^k` with `α_j = g^j`, the evaluation domain. `check.py` tests both
conditions exactly, for every corrupt set:

| Field | Sizes at which some corrupt set breaks a condition |
|-------|----------------------------------------------------|
| BLS12-381 and BN254 scalar fields (any field with a radix-2 domain of size 16) | `n = 13, 14, 15, 16` |
| `GF(2^8)` | `n = 16` |

Everything from `n = 4` to `n = 12` was fine in all three fields.

The smallest case is `n = 13`, `t = 4`, corrupt set `{0, 4, 8, 12}`. The domain has size 16, so
those four columns only depend on the row index modulo 4, and `Σ_m i^(j·m) = 0` unless `4 | j`.
If the four dealers add the same error to their dealings it cancels at every checker except 8 and
12 — which are in the coalition. `mpc/tests/randousha_extraction_test.rs` ran this against the
real `RanDouShaNode`: all nine honest parties finished, and kept outputs 0 and 4 were not double
sharings (their degree-`2t` and degree-`t` secrets differed). The same set breaks privacy: it
learns the sum of two kept outputs.

An invalid double sharing makes a degree-reduction multiplication return a wrong product, so this
reached triples, daBits and everything built on them.

## The fix

`make_hyper_invertible` (`mpc/src/common/share/mod.rs`, `mpc/src/common/gf2k/vandermonde.rs`)
builds the matrix of Beerliová-Trubíniová and Hirt,
`M[i][j] = ∏_{k≠j} (β_i − α_k) / (α_j − α_k)`, and the five extraction protocols use it. It
sends the values of a polynomial of degree below `n` at the `α`s to its values at the `β`s.

- **Proved** for every `n`, `t` and field in `../dabit/DaBit/Extraction.lean`: any rows `R` and
  columns `C` with `|C| ≤ |R|` are injective (`HimPoints.injective_on`), any with `|J| ≤ |H|`
  are surjective (`surjective_on`), hence soundness (`extraction_sound`) and privacy
  (`fibreEquiv`). `apply_eq_sum` ties the model to the entry formula the code computes.
- **Checked exactly** by `check.py` on the matrices as built, for every corrupt set at every
  `n` from 4 to 16 in all three fields, under both output splits.
- **Regression-tested**: the coalition above is now caught.

```bash
python3 formal/extraction/check.py            # both matrices; exit status is the new one's
python3 formal/extraction/check.py him 31,10  # one size
```

## Consequences worth knowing

- **It is a protocol change.** Every party must use the same matrix, so old and new nodes cannot
  preprocess together.
- **`GF(2^8)` now supports at most 127 parties** for random sharing, not 255: the matrix needs
  `2n` distinct points.
- **The AVSS share generator was left on the Vandermonde matrix.** It opens nothing to checkers
  and keeps a run of consecutive outputs, for which the Vandermonde matrix *is* sufficient;
  `check.py` confirms that (the `avss` split).
- The F-side `RanDouSha` check still requires the opened degrees to be *exactly* `t` and `2t`,
  so an honest run aborts with probability about `2^-64` per check. The `GF(2^8)` twins had the
  same check fixed upstream because there the probability was `1/256`.
