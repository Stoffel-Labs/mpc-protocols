# SMT proofs of the real circuit plans

`../dabit` proves that A2B and the edaBit filter are correct and private *given* that their
Boolean netlists compute the right function. This directory proves that part, on the netlists
the Rust code actually builds for the scalar fields of BLS12-381 (255 bits) and BN254 (254 bits).

```bash
NETLIST_DIR=/tmp/nets NETLIST_RANDOM=500 \
  cargo test -p stoffelcrypto --test netlist_formal export_curve_field_plans -- --ignored
python3 formal/netlists/check.py /tmp/nets/bls12_381
python3 formal/netlists/check.py /tmp/nets/bn254
```

`export_curve_field_plans` writes each plan with `Netlist::to_text`, and the modulus beside
them; `check.py` (Z3) asks, for each plan, for an input on which the plan and the arithmetic
specification differ, and must be told there is none. The script reads the modulus from the
directory, so it is not tied to any field.

| Plan | Proved for | Specification |
|------|------------|---------------|
| `generic.net` — the adder with the mask as inputs | every `y < p` and every `r < p` | outputs `=` the `w` bits of `(y + r) mod p` |
| `overflow.net` — the `r ≥ p` filter | every `r < 2^w` | output `= [r ≥ p]` |
| `a2b_<y>.net` — the adder for mask `y` | every `r < p` | outputs `=` the `w` bits of `(y + r) mod p` |

The filter netlist does not depend on any data, so one proof covers it completely.

The adder is proved in two layers. `generic.net` is the construction with the mask as *inputs*
(`FieldA2BCircuit::generic_plan_on`): the prefix network, the offset trick and the final MUX,
built by the same functions the protocol's plans are built by. One query proves it for every mask
and every input — 4,307 ANDs at 255 bits, under a minute. The plan the protocol actually runs for
a mask `y` is that circuit with `y` folded in as constants and dead gates dropped, so there is one
per mask and they cannot all be enumerated; the export covers the arithmetic boundaries of the
reduction, every single-bit mask and its complement, regular patterns, and a seeded random
spread.

**Last run:** BLS12-381 — 901 plans, all proved; BN254 — 867 plans, all proved. Two to four
minutes per field on 10 cores.

## Is the checker itself any good?

Eighteen single-line mutations were applied to three BLS12-381 plans — the generic adder, one
folded plan and the filter — dropping a fused XOR, ANDing or XORing a wire with itself, or
flipping a constant. The checker rejected all eighteen.

## The generator, for every mask

SMT cannot quantify over masks, because the plan's structure changes with them. The generator
is instead tested exhaustively where that is possible, in `mpc/tests/netlist_formal.rs`:

| Field | Coverage |
|-------|----------|
| `p = 241 = 2^8 − 2^4 + 1` (a Solinas prime, taking the specialised filter) | every mask × every input, folded and generic; every 8-bit filter candidate |
| `p = 251` (a general prime, taking the same filter path as the curve fields) | every mask × every input, folded and generic; every 8-bit filter candidate |
| `p = 61441 = 2^16 − 2^12 + 1` | every mask × 33 inputs; every 16-bit filter candidate |

These are tests, not proofs about the curve fields: they show the generator is right for every
mask on small fields, and the SMT runs show it is right for every input on hundreds of masks of
each curve field.

## Not covered

- The constant folding for a mask outside the exported set. The adder itself is
  proved for every mask; what is sampled is that folding a particular mask in preserves it.
- The step from a plan to the straight-line programs of the Lean development. A plan writes
  each arena slot once and an AND layer reads only earlier slots, so it is a straight-line
  program up to renumbering, with a fused `and`+`xor` as two gates; that translation is by
  inspection.
- The driver that walks a plan on shares (`BinaryCircuit`). The interpreter here and the solver
  read the exported text; that the driver applies it the same way is covered by the ordinary
  A2B tests.
