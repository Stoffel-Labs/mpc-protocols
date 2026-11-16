# Model checking production code with Kani

Bounded model checking of `mpc/src/honeybadger/dabit/packing.rs` — the **production source
file itself**, pulled in by path, not a copy.

```bash
cd formal/kani && cargo kani
```

Expected: `Complete - 11 successfully verified harnesses, 0 failures, 11 total.`
Built with Kani 0.68 / CBMC 6.11.

For every batch size from 1 to 16 and every possible byte content:

| Harness | Property |
|---------|----------|
| `clear_padding_yields_a_canonical_packing` | What `sample_bits` produces always passes `is_canonical`. |
| `clear_padding_keeps_every_bit` | Clearing the padding changes no bit of the batch. |
| `canonical_packings_are_equal_iff_their_bits_are` | The echo's byte comparison is exactly a comparison of the bits. |
| `nothing_is_readable_past_the_batch` | A canonical packing reads as zero past `count`: nothing rides in the padding. |

Together these are the code-level half of "bit-ness is structural" and of the echo's
soundness, which the Lean development (`../dabit`) proves at the level of bits.

The bound of 16 covers both shapes of a batch — one that ends on a byte boundary and one that
does not — and both one- and two-byte packings. Larger batches are not checked.

## `Gf256` is a field of characteristic 2

Every proof about the binary side assumes `K` is a field of characteristic 2. These harnesses
prove it of `mpc/src/common/gf2k/field.rs`, for all 256 elements:

| Harness | Property |
|---------|----------|
| `addition_is_xor_and_has_characteristic_two` | `a + b = a ⊕ b`, `a + a = 0`, subtraction is addition |
| `multiplication_is_commutative_with_identity_one` | `ab = ba`, `a·1 = a`, `a·0 = 0` |
| `multiplication_distributes_over_addition` | `a(b + c) = ab + ac`, all `2^24` triples |
| `multiplication_is_associative_on_the_basis` | `(ab)c = a(bc)` on `1, x, .., x^7` |
| `every_nonzero_element_has_an_inverse` | `a · a⁻¹ = 1` for `a ≠ 0`; zero has none |
| `is_bit_holds_exactly_for_zero_and_one` | the check behind `gf_to_bit` |
| `the_generator_has_full_order` | the evaluation domain is 255 distinct non-zero points |

Associativity over all `2^24` triples is beyond the SAT solver in reasonable time (it ran for
ten minutes without an answer). It follows from the basis case because the product is
commutative and distributive, hence bilinear; and `cargo test --release` in this directory
checks every triple directly by enumeration, in a fraction of a second.

This crate is outside the workspace because Kani cannot build the main crate's dependency
tree; `packing.rs` depends on nothing but `core` for that reason, and `field.rs` is compiled
against a three-line stand-in for its parent module's error type.
