#!/usr/bin/env python3
"""SMT proofs that the exported circuit plans compute what they should.

For each plan exported by `cargo test --test netlist_formal export_curve_field_plans`:

  generic.net   for ALL y, r < p:   plan(r, y, y + 2^w - p) == bits of ((y + r) mod p)
  a2b_<y>.net   for ALL r < p:      plan(bits of r) == bits of ((y + r) mod p)
  overflow.net  for ALL r < 2^w:    plan(bits of r) == [r >= p]

The modulus `p` is read from `modulus.txt` in the same directory, and `w` is its bit length, so
the same script checks any field the exporter writes.

`generic.net` is the adder with the mask as inputs: one query covers every mask. The per-mask
plans are what the protocol runs, with the mask folded in as constants.

Each is one unsatisfiability query: Z3 is asked for an input on which the plan and the
arithmetic specification differ, and must answer that none exists.

    python3 check.py <dir>/bls12_381 [jobs]
"""
import glob
import multiprocessing
import os
import sys
import time

import z3

# Set per directory from `modulus.txt`, which the exporter writes beside the plans.
P = None
W = None


def load_field(directory):
    global P, W
    with open(os.path.join(directory, "modulus.txt")) as handle:
        P = int(handle.read().strip(), 16)
    W = P.bit_length()


def run_plan(path, r):
    """Symbolically executes a `Netlist::to_text` plan on the bits of the bit-vector `r`."""
    wires, outputs, pending = [], [], None
    with open(path) as handle:
        for line in handle:
            f = line.split()
            if not f:
                continue
            op = f[0]
            if op == "arena":
                wires = [z3.BoolVal(False)] * int(f[1])
            elif op == "inputs":
                for i, w in enumerate(f[1:]):
                    wires[int(w)] = z3.Extract(i, i, r) == 1
            elif op == "outputs":
                outputs = [int(w) for w in f[1:]]
            elif op == "const":
                wires[int(f[1])] = z3.BoolVal(f[2] == "1")
            elif op == "xor":
                wires[int(f[1])] = z3.Xor(wires[int(f[2])], wires[int(f[3])])
            elif op == "xorc":
                src = wires[int(f[2])]
                wires[int(f[1])] = z3.Not(src) if f[3] == "1" else src
            elif op == "layer":
                pending = []
            elif op == "and":
                # Every AND of a layer reads the wires as they stood when the layer began.
                value = z3.And(wires[int(f[2])], wires[int(f[3])])
                if f[4] != "-":
                    value = z3.Xor(value, wires[int(f[4])])
                pending.append((int(f[1]), value))
            elif op == "end":
                for dst, value in pending:
                    wires[dst] = value
                pending = None
            else:
                raise ValueError(f"unknown netlist line: {line!r}")
    return [wires[w] for w in outputs]


def check(path):
    start = time.time()
    load_field(os.path.dirname(path))
    name = os.path.basename(path)
    r = z3.BitVec("r", W)
    solver = z3.Solver()
    if name == "generic.net":
        y = z3.BitVec("y", W)
        # Inputs in order: r, y, Y = y + (2^w - p); input i is bit i of the concatenation.
        offset = y + z3.BitVecVal((1 << W) - P, W)
        out = run_plan(path, z3.Concat(offset, y, r))
        assert len(out) == W
        total = z3.ZeroExt(1, r) + z3.ZeroExt(1, y)
        reduced = z3.If(z3.UGE(total, z3.BitVecVal(P, W + 1)), total - P, total)
        differs = z3.Or([out[i] != (z3.Extract(i, i, reduced) == 1) for i in range(W)])
        modulus = z3.BitVecVal(P, W)
        solver.add(z3.ULT(r, modulus), z3.ULT(y, modulus), differs)
        verdict = solver.check()
        return name, str(verdict), time.time() - start
    out = run_plan(path, r)
    if name == "overflow.net":
        assert len(out) == 1
        spec = z3.UGE(r, z3.BitVecVal(P, W))
        solver.add(out[0] != spec)
    else:
        y = int(name[len("a2b_"):-len(".net")], 16)
        assert y < P and len(out) == W
        # (y + r) mod p, computed in w + 1 bits so that nothing wraps.
        total = z3.ZeroExt(1, r) + z3.BitVecVal(y, W + 1)
        reduced = z3.If(z3.UGE(total, z3.BitVecVal(P, W + 1)), total - P, total)
        differs = z3.Or([out[i] != (z3.Extract(i, i, reduced) == 1) for i in range(W)])
        solver.add(z3.ULT(r, z3.BitVecVal(P, W)), differs)
    verdict = solver.check()
    return name, str(verdict), time.time() - start


def main():
    directory = sys.argv[1]
    jobs = int(sys.argv[2]) if len(sys.argv) > 2 else max(1, multiprocessing.cpu_count() - 2)
    paths = sorted(glob.glob(os.path.join(directory, "*.net")))
    if not paths:
        sys.exit(f"no .net files in {directory}")
    failures, slowest, done = [], 0.0, 0
    with multiprocessing.Pool(jobs) as pool:
        for name, verdict, seconds in pool.imap_unordered(check, paths):
            done += 1
            slowest = max(slowest, seconds)
            if verdict != "unsat":
                failures.append((name, verdict))
                print(f"FAIL {name}: {verdict}")
            if done % 50 == 0:
                print(f"  {done}/{len(paths)} checked", flush=True)
    print(f"{len(paths) - len(failures)} of {len(paths)} plans proved; slowest {slowest:.1f}s")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
