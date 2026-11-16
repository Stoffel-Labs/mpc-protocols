#!/usr/bin/env python3
"""Exact check of the matrix conditions random (double) sharing rests on.

The random-sharing protocols extract randomness by applying an `n x n` matrix `M` to the `n`
dealt sharings: output `j` is `sum_k M[j][k] * dealing_k`.  Some outputs are kept and the others
are opened to one party each, who checks them:

    RanDouSha, GfRanDouSha   keep 0..t,       open t+1..n-1 to parties t+1..n-1
    RanSha, GfRanSha, zero   keep 2t..n-1,    open 0..2t-1  to parties 0..2t-1
    AVSS RanSha              keep 2t..n-1,    open nothing (privacy only)

For a corrupt set C (|C| <= t), with H the honest parties, the protocol needs:

  soundness  the rows of the honest checkers, restricted to the corrupt dealers' columns, have
             full column rank: bad dealings cannot cancel in every honest check.
  privacy    the rows of the kept outputs and of the corrupt checkers, restricted to the honest
             dealers' columns, have full row rank: the kept outputs are uniform given everything
             the corrupt parties see.

Both are properties of `M`.  This script checks them exactly, for every corrupt set, in the two
fields the crate runs on — the BLS12-381 and BN254 scalar fields and GF(2^8) — for two matrices:

  vandermonde  M[j][k] = alpha_j^k with alpha_j = g^j, the evaluation domain.  What the code
               used.  It is *not* hyper-invertible and fails for some committee sizes.
  him          M[i][j] = prod_{k != j} (beta_i - alpha_k) / (alpha_j - alpha_k), the
               hyper-invertible matrix of Beerliova-Trubiniova and Hirt.  What the code uses now.

    python3 check.py [vandermonde|him] [n,t ...]
"""
import itertools
import sys

# ---- The curve scalar fields ---------------------------------------------------------------
def prime_field(label, modulus, generator):
    """A prime field with arkworks' radix-2 evaluation domain."""

    class Field:
        name = label
        zero, one = 0, 1

        @staticmethod
        def add(a, b):
            return (a + b) % modulus

        @staticmethod
        def sub(a, b):
            return (a - b) % modulus

        @staticmethod
        def mul(a, b):
            return a * b % modulus

        @staticmethod
        def inv(a):
            return pow(a, modulus - 2, modulus)

        @staticmethod
        def domain(n):
            # arkworks radix-2 domain: size N = next power of two >= n, element(i) = w^i with
            # w = GENERATOR^((p-1)/N).
            size = 1
            while size < n:
                size *= 2
            w = pow(generator, (modulus - 1) // size, modulus)
            return [pow(w, i, modulus) for i in range(n)]

        @staticmethod
        def him_points(n):
            # make_hyper_invertible: alpha_k = k + 1, beta_i = n + i + 1.
            return [k + 1 for k in range(2 * n)]

    return Field


# BLS12-381 scalar field, generator 7; BN254 scalar field, generator 5 (ark-bls12-381, ark-bn254).
Bls = prime_field(
    "BLS12-381",
    0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001,
    7,
)
Bn = prime_field(
    "BN254",
    0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001,
    5,
)


# ---- GF(2^8), modulus 0x11B ---------------------------------------------------------------
def _gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


class Gf256:
    name = "GF(2^8)"
    zero, one = 0, 1
    GENERATOR = None  # filled in from the Rust source by main()

    add = staticmethod(lambda a, b: a ^ b)
    sub = staticmethod(lambda a, b: a ^ b)
    mul = staticmethod(_gf_mul)

    @staticmethod
    def inv(a):
        r = 1
        for _ in range(254):
            r = _gf_mul(r, a)
        return r

    @classmethod
    def domain(cls, n):
        out, x = [], 1
        for _ in range(n):
            out.append(x)
            x = _gf_mul(x, cls.GENERATOR)
        return out

    @classmethod
    def him_points(cls, n):
        # make_hyper_invertible: the first 2n powers of the generator.
        return cls.domain(2 * n)


def power(field, base, exp):
    r = field.one
    for _ in range(exp):
        r = field.mul(r, base)
    return r


def rank(field, rows):
    """Rank by Gaussian elimination, exact."""
    m = [list(r) for r in rows]
    rk = 0
    cols = len(m[0]) if m else 0
    for c in range(cols):
        pivot = next((i for i in range(rk, len(m)) if m[i][c] != field.zero), None)
        if pivot is None:
            continue
        m[rk], m[pivot] = m[pivot], m[rk]
        inv = field.inv(m[rk][c])
        m[rk] = [field.mul(v, inv) for v in m[rk]]
        for i in range(len(m)):
            if i != rk and m[i][c] != field.zero:
                f = m[i][c]
                m[i] = [field.sub(a, field.mul(f, b)) for a, b in zip(m[i], m[rk])]
        rk += 1
    return rk


def vandermonde(field, n):
    alpha = field.domain(n)
    assert len(set(alpha)) == n and field.zero not in alpha
    return [[power(field, alpha[j], k) for k in range(n)] for j in range(n)]


def him(field, n):
    points = field.him_points(n)
    assert len(set(points)) == 2 * n
    alpha, beta = points[:n], points[n:]
    rows = []
    for i in range(n):
        row = []
        for j in range(n):
            num, den = field.one, field.one
            for k in range(n):
                if k != j:
                    num = field.mul(num, field.sub(beta[i], alpha[k]))
                    den = field.mul(den, field.sub(alpha[j], alpha[k]))
            row.append(field.mul(num, field.inv(den)))
        rows.append(row)
    return rows


SPLITS = {
    # name: (kept outputs, checked outputs)
    "double": lambda n, t: (list(range(t + 1)), list(range(t + 1, n))),
    "single": lambda n, t: (list(range(2 * t, n)), list(range(2 * t))),
    # The AVSS share generator keeps 2t..n-1 and opens nothing: its dealings are verified by
    # the AVSS itself.  It still uses the Vandermonde matrix, which is enough for this split.
    "avss": lambda n, t: (list(range(2 * t, n)), []),
}


def check(field, M, n, t, split):
    kept, checkers = SPLITS[split](n, t)
    bad, sets = [], 0
    for size in range(0, t + 1):
        for C in itertools.combinations(range(n), size):
            sets += 1
            corrupt = set(C)
            honest = [k for k in range(n) if k not in corrupt]
            if C and checkers:
                rows = [[M[j][k] for k in C] for j in checkers if j not in corrupt]
                if rank(field, rows) != len(C):
                    bad.append(("soundness", C))
            seen = kept + [j for j in checkers if j in corrupt]
            rows = [[M[j][k] for k in honest] for j in seen]
            if rank(field, rows) != len(seen):
                bad.append(("privacy", C))
    return sets, bad


def main():
    import os
    import re
    src = os.path.join(os.path.dirname(__file__), "..", "..", "mpc", "src", "common", "gf2k",
                       "field.rs")
    text = open(src).read()
    Gf256.GENERATOR = int(re.search(r"GENERATOR: Gf256 = Gf256\((0x[0-9A-Fa-f]+|\d+)\)", text)
                          .group(1), 0)
    args = sys.argv[1:]
    kinds = [a for a in args if a in ("vandermonde", "him")] or ["vandermonde", "him"]
    params = [tuple(map(int, a.split(","))) for a in args if "," in a] or \
        [(n, (n - 1) // 3) for n in range(4, 17)]
    failed = set()
    for kind in kinds:
        build = vandermonde if kind == "vandermonde" else him
        for field in (Bls, Bn, Gf256):
            for n, t in params:
                M = build(field, n)
                for split in SPLITS:
                    sets, bad = check(field, M, n, t, split)
                    status = "ok" if not bad else f"FAILED ({len(bad)})"
                    print(f"{kind:11} {field.name:10} n={n:2} t={t} {split:6} "
                          f"{sets:5} corrupt sets  {status}")
                    for what, C in bad[:2]:
                        print(f"      {what}: corrupt = {list(C)}")
                    if bad:
                        failed.add(kind)
    # The matrix in use must pass; the old one is reported for the record.
    sys.exit(1 if "him" in failed else 0)


if __name__ == "__main__":
    main()
