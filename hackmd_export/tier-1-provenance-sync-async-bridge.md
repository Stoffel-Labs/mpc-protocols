# Tier-1 Provenance & Sync-Async Bridge

2026-11-02 · Garry

List item 4 executed: all three source papers (DN07, BTH08, Asharov–Lindell 2017) read against the sharp question — do they prove perfect security with straight-line black-box simulators for the constructions our code implements — plus the sync→async bridging argument. Companion to the Perfect-Open Lemma (whose §6 conditions this discharges) and the HBMPC Security Assumption Audit.

## Asharov–Lindell 2017 — CONFIRMED, and better than hoped

Verdict: perfect ✓, straight-line black-box ✓ (stated by the paper itself), UC corollary already published ✓.

**What we get, in one line:** AL17 already proves the BGW-style foundations our code relies on are perfectly secure *and* universally composable — so we cite it instead of proving it ourselves.

**1. Main result (Theorem 1 / Corollary 7.3)**

- Every functionality is computable with **perfect security**.
- Adversary: **static, malicious**, at **t < n/3**.
- Model: synchronous network, private channels, broadcast.

**2. Why it matters for us (§8, "Security under composition")**

- The paper states *all its simulators are straight-line black-box*.
- It applies Kushilevitz–Lindell–Rabin [ref. 23] — the same theorem our concurrency program rests on.
- Result, **Corollary 2**: perfect UC security, static malicious t < n/3, plain private channels, no setup.
- So the KLR lift for our BGW foundations is published literature, not an obligation on us.

**3. What our code inherits from it**

1. **Shamir share algebra** (Claims 3.1–3.5): uniformity of $\le t$ shares, joint independence across polynomials, leading-coefficient hiding — the facts our Perfect-Open and Masked-Open simulators cite.
2. **Robust Reed–Solomon reconstruction** (Theorem 5.1): corrects up to t errors at t < n/3.
3. **VSS**.
4. **Proof framework**: corruption-aware functionalities and modular composition, used by all our lemma write-ups.

**4. Caveats — all benign**

| Point | AL17 | Our code | Effect |
| --- | --- | --- | --- |
| Network | Synchronous | Asynchronous | Handled by the sync→async bridge below |
| Broadcast | Assumed primitive | RBC | Same agreement property |
| Adversary | Efficient simulation static only (adaptive Cor. 8.3 is inefficient) | Static-only claims | Exact match |
| Output | Guaranteed delivery | With-abort | Strict weakening — safe |

**5. Scope limit — what it does not cover**

- Their multiplication protocol ($\mathcal{F}_{\mathsf{mult}}^{\mathsf{VSS}}$ over bivariate VSS) is **not** the one we run.
- Our triples come via the DN07/Beaver route, so AL17 covers foundations and framework, **not** our triple generation.

## BTH08 — perfect confirmed; simulator not supplied (as expected)

Verdict: perfect ✓ (claimed and argued), straight-line simulator ✗ (none exists in the paper — ours to write, as planned).

**What we get, in one line:** BTH08 proves our share-generation protocols (`RanSha` / `RanDouSha` / `zero_share`) are perfectly secure — but gives no simulator, so the straight-line simulators are still ours to write.

**1. Main result (Abstract, §2.1)**

- **Perfect security**: "information-theoretic without any error probability."
- Adversary: active, **adaptive**, at **t < n/3** (optimal).
- Model: synchronous secure channels plus broadcast (realized by BGP92/CW92).

**2. What our code inherits from it**

1. **DoubleShareRandom = our `RanSha` / `RanDouSha` / `zero_share`**: each party deals a random (double-)sharing; the hyperinvertible matrix combines them; 2t check rows are privately reconstructed to verifiers; $n - 2t$ outputs are kept.
2. **Hyperinvertible matrix** (Construction 1): already confirmed byte-level in our code.
3. **Lemma 5 + Lemma 2 (bijective mapping)**: proves correctness and privacy; this is the full-rank residual-uniformity fact used by Perfect-Open §4 step 2 and the zero-share analysis — now literature-anchored.

**3. The gap — what it does not give us**

- Proofs are property-style: correctness + privacy lemmas only.
- No ideal functionality and no simulator, so **no straight-line claim to inherit**.
- Our Perfect-Open Lemma and the planned RanDouSha companion fill this gap; BTH08 supplies the algebra they cite.

**4. Difference from our code — benign**

| Point | BTH08 | Our code (HBMPC) | Effect |
| --- | --- | --- | --- |
| Robustness | Player elimination over t segments, repeat failed segments | Abort | Strict weakening — safe; origin of our with-abort stack |

## DN07 — statistical, not perfect: the citation chain must be corrected

Verdict: perfect ✗ — DN07 must stop being cited as a perfect-security source; what we inherit from it is structural and happens to be deterministic.

**What we get, in one line:** DN07 is only statistically secure, but the two pieces we take from it are deterministic — so no statistical cost reaches our code. We must stop citing it for perfect security.

**1. Main result — statistical, not perfect**

- Security is **unconditional/statistical**: insecurity bounded by $\operatorname{poly}(\kappa)\cdot 2^{-\kappa}$.
- Consistency checks are probabilistic: random challenge from an extension field G (Fig. 7), soundness error $\ell/|G|$.
- BTH08 classifies DN07 as "unconditional" (vs. its own "perfect") and calls it the protocol "with error probability."
- **No full simulation proofs** (§3.4: "we will however not prove this with full simulation proofs").

**2. What our code inherits from it**

1. **King-based public reconstruction** (Open/OpenRobust, Figs. 8–9 = our `batch_recon`): expand $n - (2t+1)$ sharings to $n$ via Vandermonde; each party reconstructs one privately and redistributes; Berlekamp–Welch corrects errors.
2. **Triple-generation shape** (Fig. 4): open $\langle D \rangle = [a][b] + \langle R \rangle$ at degree 2t, set $[c] = D - [r]$.

**3. Why no statistical cost flows in**

- Both inherited pieces are deterministic coding and algebra: no coin, no challenge, no $\kappa$.
- DN07's error lives only in its consistency checks (Fig. 7) and dispute control.
- HBMPC replaced those with **BTH08's perfect hyperinvertible verification**.

**4. Corrected citation chain — binding from now on**

| What | Cite |
| --- | --- |
| Structure (reconstruction, triple shape) | DN07 |
| Perfect verification | BTH08 |
| Simulation proofs | AL17 + our own lemma documents |

Writing "perfectly secure (DN07)" anywhere is wrong.

**5. Side finding — corroborates the Perfect-Open degree dichotomy**

- DN07 §5: at t < n/3, Berlekamp–Welch cannot correct degree-2t openings; an honest king may fail to reconstruct.
- DN07's fix: dispute control. HBMPC's fix: wait-for-all / abort.
- Same wall, two mitigations; ours is the with-abort one.

## The exact-degree finding generalizes: three sites, not one

This extends list item 16 from one code site to three.

BTH08's check predicate is **degree-≤**: a d-sharing is defined by the existence of a polynomial of degree *at most* d, and an exact-degree reading would abort honest executions with probability ~$1/q$ per check — contradicting the paper's own "without any error probability." The ≤ reading is therefore forced by the paper's perfect-security claim itself.

Our code uses **exact-degree** tests in three verifiers:

| Site | Predicate |
| --- | --- |
| `zero_share.rs:514` | `poly.degree() == 2*threshold` (the original item 16) |
| `ran_dou_sha/mod.rs:661-662` | `threshold != poly1.degree() \|\| 2*threshold != poly2.degree()` |
| `share_gen/share_gen.rs:644` | `poly.degree() != threshold` |

Each makes the RBC'd OK/abort bit a non constant function of honest residuals — the $\Theta(t/q)$ simulation-error mechanism the Perfect-Open verification found for zero_share — and additionally aborts honest executions with probability ~$t/q$. **Fix: change all three to degree-≤, which is also what the source paper prescribes.** Soundness of the relaxation: a lower-degree sharing is still a valid ≤-threshold sharing — reconstruction thresholds are unchanged, and output privacy rests on honest dealers' full-field randomness, never on a corrupted dealing attaining full degree.

Not affected: the share-metadata equality checks at `ran_dou_sha/mod.rs:576-577` compare a received share's *declared degree label*, not a reconstructed polynomial — exact equality on a type tag is correct and stays.

## The sync→async bridging argument

All three papers are synchronous: rounds, a broadcast channel, a missing message replaced by a default — and AL17/BTH08 already assume *rushing* adversaries, so "the adversary sees honest messages before sending its own" is inside their model, not an async novelty. The HBMPC adaptation our code implements changes four things. The claim: **safety transfers; liveness does not and is not claimed.**

1. **Rounds → message-driven quorums.** Every acceptance predicate in our code is quorum-based: degree-t opens accept at ≥ degree+t+1 consistent shares (satisfiable by honest shares alone), degree-2t opens effectively at n (a wrong value is unacceptable under any schedule — Perfect-Open §2's code audit). The papers' correctness and privacy arguments are algebraic statements about share vectors — polynomial identities, threshold counting, hyperinvertible rank — quantified over arbitrary corrupted values and nowhere dependent on *when* a share arrives, only on *which* honest shares exist. Under adversarial scheduling the honest share set is identical; what the adversary gains is delivery ordering, which the async $\mathcal{F}_{\mathsf{Open}}$ interface (Masked-Open §6B) models explicitly: integrity unconditional, delivery adversarially scheduled. The simulators stay straight-line: they are message-driven and respond to deliveries in whatever order the adversary chooses.
2. **Broadcast channel → RBC.** The papers assume a broadcast primitive (realized synchronously by Byzantine Generals). Our code uses asynchronous RBC (Bracha/AVID, t < n/3), consumed only for low-rate control data: the verifiers' OK/abort bits (RanDouSha, RanSha, zero_share) and RISS commitment vectors. RBC's agreement + totality deliver exactly the property the proofs use from broadcast — all honest parties adopt the same value — so an abort is unanimous.
3. **Player elimination / dispute control → abort.** BTH08 and DN07 achieve guaranteed output delivery by identifying a dispute pair and repeating the segment; attributing silence to a party requires synchrony. HBMPC drops this entirely: a detected fault, or a withheld share at a degree-2t open, stalls or aborts the session. This is a strict weakening to security-with-abort — precisely the setting of every KLR theorem we invoke — so the composition story is untouched; what is lost is only the papers' output-delivery and termination claims, which we never make (HBMPC's own Table-1 offline-phase caveat).
4. **Adaptive → static.** BTH08 claims adaptive security; AL17's efficient simulation is static. All our claims are static — the weaker target — so nothing is over-inherited.

Residual items, already tracked on the list: the all-n fold on degree-2t material is the liveness price of (3) (exercised by the planned Byzantine fault-injection tests), and the degree-≤ fix above must land before the "perfect" label on the generation protocols is technically earned (it gates KLR Thm 1.2, which consumes *perfect*, not perfect-minus-$\Theta(t/q)$).
