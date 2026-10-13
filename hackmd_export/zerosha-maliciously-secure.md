# ZeroSha, Maliciously Secure


*A line-by-line proof that the ZeroSha sub-protocol produces fresh random degree-$2t$ zero-sharings safely — the degree-$2t$, secret-$0$ extension of RanDouSha, argued from hyperinvertibility.*

> **Theorem.** The ZeroSha protocol UC-realizes $\mathcal{F}_{\mathsf{ZeroSha}}$ against a static adversary corrupting $a \le t$ of $n = 3t+1$ parties, with **perfect security-with-abort**.

**Configuration** — $n = 3t + 1$ · static, active, $\le t$ corruptions · guarantee: perfect, information-theoretic, with abort.

## 1. Notation and setup

- $n$ parties $P_0, \dots, P_{n-1}$, Byzantine threshold $t$, with $n = 3t+1$ (`recover_secret` enforces $n \ge 3t+1$).
- $\mathbb{F}$ a finite field; $\omega$ a primitive root giving the evaluation domain $\{\omega^0, \dots, \omega^{n-1}\}$. Note $0$ is **not** a domain point (roots of unity are nonzero), so "share of $P_j$" means evaluation at $\omega^j$, and the secret lives at the separate point $0$.
- A **sharing** is the length-$n$ vector of its parties' shares, identified with its degree-$\le 2t$ polynomial.
- $D \subseteq \mathbb{F}^n$ is the set of **degree-$\le 2t$ zero-sharings**: evaluations of some $g$ with $\deg g \le 2t$ and $g(0) = 0$. $D$ is an $\mathbb{F}$-subspace; a degree-$\le 2t$ polynomial is fixed by its value at $0$ plus any $2t$ domain points, so $\dim D = 2t$.
- $A \subseteq [n]$ the corrupt set, $a := |A| \le t$; $H := [n] \setminus A$ the honest set, $|H| = n - a \ge 2t+1$.

### Hyperinvertible matrices

$M \in \mathbb{F}^{n\times n}$ is **hyperinvertible** iff for every $R, C \subseteq [n]$ with $|R| = |C|$, the submatrix $M_{R,C}$ is invertible. Two consequences are used throughout:

- **Wide ⇒ surjective.** If $|R| \le |C|$, then $M_{R,C}$ has full row rank $|R|$ (any $|R|$ of its columns form an invertible square block), so $M_{R,C} : \mathbb{F}^C \to \mathbb{F}^R$ is onto.
- **Tall ⇒ injective.** If $|R| \ge |C|$, then $M_{R,C}$ has full column rank $|C|$.

`make_hyperinvertible_matrix` builds $M[j][d] =$ the Lagrange coefficient sending evaluations on the party domain $\{\delta_d\}$ to the evaluation at $\gamma_j$, where $\{\gamma_j\}$ is a *disjoint* coset (the domain shifted by `F::GENERATOR`). This is Construction 1 of Beerliová-Trubiníová–Hirt (TCC 2008), hyperinvertible for *any* $2n$ pairwise-distinct points — the proof uses only $\gamma_j \ne \delta_d$. Disjointness holds because `GENERATOR` has order $|\mathbb{F}|-1$, which never divides the domain subgroup's order.

> **Why hyperinvertibility, not just "some" mixing matrix.** The regression test `test_old_vandermonde_exploit_n16_t5_zero_share` runs the real ZeroSha shape through the old plain power-basis Vandermonde $M[j][d] = \alpha_j^d$ over a single order-16 FFT domain. There, columns 0 and 8 satisfy $\alpha_j^0 + \alpha_j^8 = 1 + (-1)^j$, which is $0$ on all 8 odd rows. Two colluding dealers inject a bias that cancels on the checked odd rows but **survives in the unchecked, released rows** — exactly the failure Lemma 1 rules out, and only hyperinvertibility rules it out (a 2-column corruption then zeroes at most $k-1 = 1$ row). The correctness lemma's single hypothesis is one the codebase already has a live exploit for when it fails.

## 2. The protocol, as implemented

Batch size $b \ge 1$; take $b = 1$ for readability (the batch loops over independent slots).

**Round 1 — deal.** Each $P_i$ acts as a dealer: samples a uniform degree-$2t$ polynomial $f_i$ with $f_i(0) = 0$ and sends share $f_i(\omega^j)$ to each $P_j$. Honest ⇒ $f_i \in D$.

**Local combine.** On receiving all $n$ dealt shares, $P_j$ applies the hyperinvertible matrix to its vector of received shares, producing its share of each of $n$ **combined rows** $r_0, \dots, r_{n-1}$, where $r_k = \sum_i M[k][i]\, f_i$. Linearity ⇒ each $r_k$ is a degree-$2t$ sharing with $r_k(0) = \sum_i M[k][i]\, f_i(0)$.

**Round 2 — open to verifier.** The first $2t$ rows are opened for checking, each to a *single* designated verifier: $P_j$ sends its share of $r_i$ to $P_i$, for $i \in [0, 2t)$. **Rows are sent point-to-point, never broadcast.**

**Verify.** Verifier $P_i$ ($i < 2t$) waits for all $n$ shares of $r_i$, reconstructs, and **accepts iff** the decoded polynomial $g$ has $\deg g = 2t$, $g(0) = 0$, *and* agrees with every received share:

```rust
let consistent = domain.as_ref().is_some_and(|domain| {
    shares.iter().all(|s| poly.evaluate(&domain.element(s.id)) == s.share[0])
});
if !(poly.degree() == 2 * self.threshold && r.1.is_zero()) || !consistent { ok = false; … }
```

The verifier then RBC-broadcasts only the **boolean** `ok`.

**Release.** A party finalizes once it has $2t$ verifier OKs; a single `ok = false` aborts the receiver, and only verifier ids $< 2t$ are accepted. On finalize it outputs the **remaining $n - 2t = t+1$ rows** $r_{2t}, \dots, r_{n-1}$. So from $n$ dealers, ZeroSha **checks $2t$ rows and releases $t+1$**.

### Why the outputs must be good — the consumer's requirement

The released $[0]_{2t}$ sharings re-randomize a degree-$2t$ sharing immediately before it is opened — in RandBit via MulPub ("one degree-$2t$ zero-sharing re-randomising the MulPub opening per output bit") and in PreMulC's `u_zero_shares`. Adding $[0]_{2t}$ to $[a]_{2t}$ and opening the sum must reveal **only $a$**. That needs two properties, both proved below:

- **Correctness (Lemma 1)** — the released sharing really is a degree-$\le 2t$ sharing of $0$; else the opened value is $a + \delta$ for a bias $\delta$ the colluding dealers know and subtract back out.
- **Privacy (Lemma 2)** — the adversary does not know the *honest shares* of the released sharing; else it subtracts the whole mask and recovers the un-randomized $[a]_{2t}$.

## 3. Adversary model and ideal functionality

**Adversary.** Static, actively (Byzantine) corrupting a fixed set $A$, $a \le t$, of the $n = 3t+1$ parties; rushing; fully controls the asynchronous schedule. Authenticity between honest parties holds: the node dispatch checks network-sender $==$ `msg.sender_id` before handing a message to ZeroSha, and the RBC drain re-checks the embedded sender against the RBC-authenticated slot.

**Ideal functionality $\mathcal{F}_{\mathsf{ZeroSha}}$** (batch $b$, with abort):

1. Sample $b \cdot (t+1)$ independent uniform sharings in $D$ (degree-$\le 2t$, secret $0$).
2. Hand the adversary its own shares (the $A$-coordinates) of all sampled sharings.
3. Receive deliver or abort. On deliver, give each honest $P_j$ its $j$-coordinate of every sharing; on abort, give honest parties $\bot$.

This is the natural "produce fresh random degree-$2t$ zero-sharings" preprocessing oracle. Abort is permitted (security-with-abort; see §9). The theorem (§6) is that ZeroSha UC-realizes $\mathcal{F}_{\mathsf{ZeroSha}}$ with perfect security.

## 4. Lemma 1 — correctness / robust soundness

> **Lemma 1 (Correctness).** Fix any adversary strategy. If an honest party finalizes and releases output, then for every released row $k \in \{2t, \dots, n-1\}$ the honest parties' shares $(r_k[j])_{j\in H}$ lie on a single polynomial $g_k$ with $\deg g_k \le 2t$ and $g_k(0) = 0$. I.e. every released sharing is a genuine degree-$\le 2t$ zero-sharing on the honest coordinates, and so robustly opens to secret $0$.

**Why honest coordinates.** A corrupt dealer may send *inconsistent* shares, and a corrupt party may send a *fake* share when a row is opened. Neither is locally detectable. What downstream robust reconstruction needs, and all that is recoverable, is that the $\ge 2t+1$ honest shares are consistent; the corrupt shares are error-corrected away.

**Proof.** Let $x_i \in \mathbb{F}^n$ be the vector of shares dealer $i$ actually sent (honest $i$: $x_i \in D$). Write $x_i^H := (x_i[j])_{j\in H}$ for its honest coordinates, and let

$$
D_H := \{\, (g[j])_{j \in H} : g \in D \,\} \subseteq \mathbb{F}^H
$$

Because $|H| \ge 2t+1$ and a degree-$\le 2t$ polynomial is determined by any $2t+1$ values, the restriction $D \to \mathbb{F}^H$ is injective, so $\dim D_H = 2t$; and as $|H| \ge 2t+1 > 2t$, $D_H$ is a *proper* subspace. Let $\pi : \mathbb{F}^H \to \mathbb{F}^H / D_H$ be the quotient, $W := \mathbb{F}^H / D_H$.

Define the **deviation** $w_i := \pi(x_i^H) \in W$. Honest dealers satisfy $x_i^H \in D_H$, so $w_i = 0$; hence $\operatorname{supp}(w) \subseteq A$ and $|\operatorname{supp}(w)| \le a \le t$. Combined rows are $\mathbb{F}$-linear coordinate-wise, so $r_k^H = \sum_i M[k][i]\, x_i^H$, and applying $\pi$:

$$
\pi(r_k^H) = \sum_i M[k][i]\, w_i = (Mw)_k \qquad (\text{over } W,\ M \text{ on the dealer index})
$$

Consider the **honest verifiers** $C_h := [0,2t) \cap H$. Since release needs $2t$ OKs and a single false aborts the receiver, release implies *every* honest verifier accepted.

*Acceptance of row $k$ by an honest verifier ⇒ $r_k^H \in D_H$.* The verifier's decoded $g \in D$ (it enforced $\deg = 2t$, $g(0)=0$) matches every received share. Among them, the $\ge 2t+1$ sent by honest parties are the *true* $r_k[j]$. A degree-$\le 2t$ polynomial is fixed by any $2t+1$ points, so $g$ is exactly the interpolant of the honest shares; thus $(r_k[j])_{j\in H} \in D_H$, i.e. $\pi(r_k^H) = 0$.

> **Where the `consistent` check earns its place.** Without it the verifier would accept whatever `RobustShare::recover_secret` returns — a *correcting* decoder that, for $n > 3t+1$, repairs up to $t$ bad shares and hands back a clean $g \in D$ even when the honest coordinates do **not** lie on it (silent repair). The acceptance ⇒ $r_k^H \in D_H$ step would then be false and Lemma 1 would collapse. The `.all()` re-evaluation against *every* received share — not a `valid_count >= threshold` slack — restores it. (Checklist item 12.)

So $(Mw)_k = 0$ for all $k \in C_h$, i.e. $M_{C_h,S}\, w_S = 0$ where $S := \operatorname{supp}(w)$. Count: $|C_h| = 2t - |A \cap [0,2t)| \ge 2t - a$, and since $a \le t$, we have $2t - a \ge a \ge |S|$. Pick any $|S|$ rows $C' \subseteq C_h$. Then $M_{C',S}$ is a square submatrix of a hyperinvertible matrix, hence invertible, and $M_{C',S}\, w_S = 0 \Rightarrow w_S = 0 \Rightarrow w = 0$.

Therefore $\pi(r_k^H) = (Mw)_k = 0$ for *every* $k$, in particular every released $k \in [2t, n)$: $r_k^H \in D_H$. ∎

**Tightness.** The bound $2t - a \ge a$ is exactly $a \le t$; at $a = t$ there are exactly $t$ honest verifiers and $t$ possibly-corrupt dealers — zero slack. This matches the exploit test, where $t = 5$ of the $2t = 10$ checked rows fail "with no slack to spare": hyperinvertibility is what stops the corruption hiding entirely in the $t+1$ unchecked released rows.

## 5. Lemma 2 — privacy

> **Lemma 2 (Privacy of honest shares).** Fix any static adversary with corrupt set $A$, $a \le t$. Condition on the adversary's entire view $V$ of an honest execution. Then the released rows $(r_k)_{k\in K}$, $K = [2t, n)$, are distributed as $t+1$ **independent** samples, each **uniform** in $\{\, g \in D : g[j] = r_k[j]\ \forall j \in A \,\}$ — uniform in $D$ subject only to the adversary's own shares. The honest coordinates carry full residual entropy.

**The adversary's view** $V$ consists of: (1) $x_A$ — its own dealt sharings; (2) $\{\, x_i[j] : i \in H,\, j \in A \,\}$ — its $a$ shares of each honest dealer's sharing; (3) $\{\, r_k \text{ in full} : k \in O \,\}$, where $O := A \cap [0,2t)$ is the set of opened rows whose designated verifier is **corrupt** — only there does the adversary obtain a full row, because opening is point-to-point and honest verifiers broadcast only a boolean. Hence $|O| \le a \le t$; (4) the OK bits (all true; by Lemma 1 a deterministic function carrying no entropy). Its own shares of every row are computable from (1)+(2), so add nothing.

**Proof.** All maps are $\mathbb{F}$-linear, so argue inside $D$ ($\dim 2t$). Let

$$
U := \{\, g \in D : g[j] = 0 \ \ \forall j \in A \,\}
$$

$U$ is $D$ cut by the $a$ evaluation functionals at $\{\omega^j : j \in A\}$. With the defining $g(0)=0$, these are $a+1 \le t+1 \le 2t+1$ functionals at *distinct* points, hence independent on degree-$\le 2t$ polynomials. So $\dim U = (2t+1) - (a+1) = 2t - a$.

Conditioned on (2), each honest sharing is $x_i = x_i^0 + u_i$ with $x_i^0$ fixed (matching observed shares) and $u_i$ **uniform in $U$, independent across $i \in H$**. For any row $m$, split $r_m = r_m^0 + e_m$ with $e_m := \sum_{i\in H} M[m][i]\, u_i$. Each $e_m \in U$: for $j \in A$, $e_m[j] = \sum_i M[m][i] \cdot 0 = 0$. Consider

$$
\Psi : U^H \to U^{O \cup K}, \qquad (u_i)_{i \in H} \mapsto (e_m)_{m \in O \cup K} = M_{O \cup K,\, H}\ \text{over}\ U
$$

Dimensions: $|O \cup K| \le a + (t+1) \le 2t+1$, while $|H| = 3t+1 - a \ge 2t+1$. So $|O \cup K| \le |H|$, and by **wide ⇒ surjective**, $M_{O\cup K,\, H}$ is onto $\mathbb{F}^{O\cup K}$; tensoring with $\mathrm{id}_U$, $\Psi$ is onto $U^{O\cup K}$.

$u_H$ is uniform on $U^H$. A surjective linear map pushes uniform to uniform on its image, jointly: $(e_m)_{m\in O\cup K}$ is uniform on $U^{O\cup K}$. Conditioning on $(e_m)_{m\in O}$ — exactly what $V$-item (3) reveals — the remaining $(e_k)_{k\in K}$ stays uniform on $U^K$. Translating back, $(r_k)_{k\in K}$ is uniform on $\prod_{k\in K}(r_k^0 + U)$. ∎

> **Proof-critical: point-to-point opening is the hypothesis.** Surjectivity needs $|O \cup K| \le |H|$. Point-to-point opening gives $|O| \le a \le t$, so $|O \cup K| \le 2t+1 \le |H|$. If opened rows were instead **broadcast**, the adversary would see all $2t$, $O = [0,2t)$, and at $a = t$: $|O \cup K| = 2t + (t+1) = 3t+1 = n > |H| = 2t+1$. Then $M_{O\cup K,\, H}$ becomes **tall** — injective but not surjective — so $e_K$ is a deterministic function of $e_O$. The adversary, seeing the $2t$ opened rows, computes every released row in full: **total loss of privacy.** "Open each checked row only to its one designated verifier" is not an optimization; it is the hypothesis Lemma 2 runs on.

## 6. Theorem and simulator

> **Theorem.** The ZeroSha protocol UC-realizes $\mathcal{F}_{\mathsf{ZeroSha}}$ against a static adversary corrupting $a \le t$ of $n = 3t+1$ parties, with perfect security-with-abort.

**Simulator S.** $S$ runs the real adversary and plays the honest parties:

1. **Deal.** For each honest dealer $i \in H$, $S$ samples $f_i \in D$ uniformly (the real distribution) and sends $f_i(\omega^j)$ to each corrupt $j$ — producing $V$-items (1),(2). It records corrupt dealers' sent shares, learning $x_A$.
2. **Open / verify.** $S$ computes every combined row, delivers the opened rows for corrupt verifiers (item 3), and simulates honest OK bits with the real acceptance predicate. If the adversary makes any honest verifier reject, $S$ sends abort; else deliver.
3. **Consistency.** $S$ has fully determined the released rows (a deterministic function of all dealt vectors, which it knows), and sets the corrupt parties' ideal shares to their $A$-coordinates. By Lemma 2 the real released rows are uniform in $D$ given exactly those coordinates — precisely how $\mathcal{F}_{\mathsf{ZeroSha}}$ samples.

**Indistinguishability.** The adversary's view is produced from the same distribution as the real protocol (honest $f_i$ uniform in $D$ in both). By Lemma 1, whenever $S$ delivers, the released rows are legal outputs of $\mathcal{F}_{\mathsf{ZeroSha}}$; whenever the real execution would abort, $S$ aborts. By Lemma 2 the honest outputs are distributed identically to ideal given the view. Hence the real and ideal (view, output) pairs are *identically* distributed: perfect security. ∎

## 7. The same result as an extension of RanDouSha

RanDouSha and ZeroSha share one skeleton: *every party deals a sharing; combine through a hyperinvertible matrix; open $2t$ combined rows to $2t$ designated verifiers; release the remaining $t+1$.* Compare the verifier cores:

|  | RanDouSha | ZeroSha |
| --- | --- | --- |
| **dealt object** | random value at degrees $t$ **and** $2t$ | degree-$2t$ sharing of $0$ |
| **combine** | hyperinvertible $M$ | same |
| **open to** | one verifier per row, point-to-point | one verifier per row, point-to-point |
| **verifier check** | $\deg = t$, $\deg = 2t$, **same secret** | $\deg = 2t$, **secret $= 0$**, per-share consistent |
| **reconstructor** | `NonRobustShare` — Lagrange, non-correcting | `RobustShare` — correcting + `consistent` gate |
| **release** | $t+1$ double-sharings | $t+1$ zero-sharings |

ZeroSha is RanDouSha under two syntactic specializations:

- **Drop the degree-$t$ component.** Removing a checked component removes checks and released material but changes no surviving message, so it cannot weaken either lemma: Lemma 1 runs per released object, and Lemma 2's bound $|O \cup K| \le |H|$ only improves when fewer objects are released.
- **Fix the secret to $0$.** RanDouSha's released secret is uniform and must be hidden (secret-privacy). ZeroSha's secret is the public constant $0$, so secret-privacy is *vacuous*. What ZeroSha instead needs — privacy of the honest **shares** of a public-secret sharing — is exactly RanDouSha's degree-$2t$ **polynomial**-privacy argument, reproduced verbatim as Lemma 2 (which never used that the secret was unknown — only hyperinvertibility and point-to-point opening).

RanDouSha's degree-$2t$ reconstructor is the non-correcting `NonRobustShare::recover_secret`, a detector by construction, so its Lemma-1 analogue needs no extra per-share check. ZeroSha uses the correcting `RobustShare::recover_secret` and must — and does — re-add the per-share `consistent` gate to recover the same "accept ⇒ in $D$" soundness. **That single clause is the whole delta between the two verifiers' security arguments.** With it in place, ZeroSha inherits RanDouSha's cleared guarantee.

## 8. Proof-critical invariants

Each is cited where the proof uses it. Breaking one breaks the named lemma.

1. **$M$ is hyperinvertible** (`make_hyperinvertible_matrix`, BH08 Construction 1). — *Lemmas 1 & 2.* Guarded by `test_hyperinvertible_matrix_random_submatrices_invertible`; the failure mode is the exploit test.
2. **The verifier re-checks the decoded polynomial against every received share** (`consistent` with `.all()`), fail-closed when the domain is None. — *Lemma 1.* A correcting decoder without this silently repairs dealer corruption.
3. **Opened rows are sent point-to-point to the single designated verifier, never broadcast**; verifiers broadcast only the boolean OK. — *Lemma 2.* Broadcasting opened rows is a total privacy break (§5).
4. **Release requires all $2t$ verifier OKs, and any single false aborts.** — *Lemma 1.* Lowering the OK threshold loses the $|C_h| \ge 2t - a \ge a$ count the inversion step needs.
5. **Dealt and opened shares are authenticated to their sender and their embedded index.** — *Both lemmas.* Ensures the "honest parties' shares are the true $r_k[j]$" statement; a mis-attributed share would corrupt the interpolation.

## 9. Scope and caveats

- **Security-with-abort, not guaranteed output.** The proof shows safety: any output produced is a correct, private batch of degree-$2t$ zero-sharings, and the simulator reproduces the adversary's view. It does not claim robustness. As implemented, a verifier waits for all $n$ opening shares and release needs all $2t$ OKs; at $n = 3t+1$, degree $2t$, a single bad opening share is uncorrectable (OEC needs $3t+2$ points), so a Byzantine party can force abort — a legitimate exercise of the abort capability $\mathcal{F}_{\mathsf{ZeroSha}}$ already grants, not a safety violation.
- **Static corruption.** The simulator assumes a fixed corrupt set chosen before execution, matching the rest of this codebase's model.
- **Perfect, not statistical.** Everything above is information-theoretic; no statistical slack is used, because the secret is the public constant $0$ and no masking-width argument enters — ZeroSha hides shares, not a value that must out-range a secret.
