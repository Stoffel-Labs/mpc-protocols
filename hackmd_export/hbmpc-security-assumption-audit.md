# HBMPC Security Assumption Audit

2026-10-19 · Garry

## Methodology:

Catrina & de Hoogh 2010 states on its own (p.7-8) that any protocol in the paper becomes actively secure ($t < n/3$) once plain Shamir sharing is swapped for verifiable secret sharing plus "an associated multiplication proof," citing [16,1,8] (or a PRSS-compatible variant via [7,13]). That is the paper's own claim — not something verified independently — and the paper says so itself: "the evaluation of these approaches... is the subject of on-going work."

That claim only transfers to a given protocol when both hold:

- the implementation is a faithful instance of what the paper specifies, not an ad hoc shortcut
- we've independently confirmed no honest-execution leak exists (the paper's claim is about surviving active cheating, not about whether the specified reveal pattern is already safe to disclose — a separate property

One more point specific to this codebase: the paper's active-security prescription has two separate parts — "extend Shamir's secret sharing to VSS" (stop a malicious *dealer* from distributing inconsistent shares undetected) and "an associated multiplication proof" (stop a malicious party from injecting a wrong local product contribution undetected). This codebase closes both, via different mechanisms than the paper's own cited references: VSS's job is done by the dealer-consistency check already confirmed in `ran_dou_sha`/`zero_share` (`NonRobustShare::recover_secret` + degree check, plus a per-share consistency check); the multiplication proof's job is done by robust (Reed-Solomon error-correcting) reconstruction at every Beaver-multiply/reveal site — confirmed at `Mod2`, `TruncPr`, `MulPub`, `PreMulC`, and `KOrCS` specifically (see Core sub-protocols below). Both halves of what the paper asks for are present; neither is the literal mechanism it cites, but both reach the same guarantee.

## Tier 1 — provably malicious-secure

The cited paper's own contribution *is* active/Byzantine security — not a semi-honest paper we're trusting to go further. (See the provenance note right after the table: the paper itself assembles these from several earlier, separately-proven results rather than proving them from scratch.)

| Sub-protocol | Source | Why it's Tier 1 |
| --- | --- | --- |
| `robust_interpolate` | HBMPC paper, Fig. 1 | RS interpolation, the paper's own correcting/detecting decoder |
| `batch_recon` | HBMPC paper, Fig. 2 | Batch reconstruction built on the same decoder |
| `ran_dou_sha` / `double_share` | HBMPC paper, Fig. 3 | Verifier uses `NonRobustShare::recover_secret` + degree check — the correct detecting decoder (confirmed in code, not just cited) |
| `share_gen` (RanSha) | HBMPC paper | User-granted; part of the same construction family as RanDouSha |
| `triple_gen` | HBMPC paper | Degree-reduction via RanDouSha's mask + robust (correcting) reconstruction — correction is right here since this is an online open, not a verifier |
| `mul` (Beaver), add, sub | HBMPC paper | add/sub are local, no reveal, secure under any model |
| `input` | HBMPC paper §4.1 | Cited directly in the module's own doc comment |
| `output` | HBMPC paper (standard functionality) | Adds no cryptographic step beyond already-proven robust reconstruction; shares go only to the designated recipient |

**What Tier 1 actually rests on.** The HBMPC paper does not itself carry a simulation-based security proof for Robust-Interpolate, BatchRecPub, RanDouSha, or Beaver-triple generation — it presents each as a standard construction and cites earlier papers for the actual proofs: Robust-Interpolate to Ben-Or–Kelmer–Rabin (1994), Bracha (1987), and Choudhury–Hirt–Patra (2013)/Choudhury–Patra (2015, 2017); BatchRecPub to Damgård & Nielsen, "Scalable and Unconditionally Secure Multiparty Computation," CRYPTO 2007; RanDouSha and the Beaver-triple degree-reduction step to the same Damgård–Nielsen 2007 paper and to Beerliová-Trubíniová & Hirt, "Perfectly-Secure MPC with Linear Communication Complexity," TCC 2008. So the real proof obligation behind "Tier 1" sits one citation hop further back than this review had been treating it. Tier 1's status rests on these being among the most established, heavily-cited constructions in the MPC literature, not on independent verification performed here.

## Tier 2 — conditionally malicious-secure

All trace to Catrina & de Hoogh 2010 / Catrina & Saxena FC2010 / Catrina COMM 2018, whose own stated model is semi-honest ("a passive threshold adversary"). Each qualifies for the paper's own active-security upgrade claim because each is a faithful instance of what the paper specifies, and each has an independently-confirmed clean reveal (no honest-execution leak).

| Sub-protocol | Paper source | Faithful? | Honest-leak check |
| --- | --- | --- | --- |
| `rand_bit` | Protocol ran_2 | Yes — matches line for line | Reveals r² for fresh random r, not an app secret — clean |
| `mul_pub` | MulPub, p.4 | Yes | Reveal is the primitive's own explicit public output |
| `pre_mulc` | Protocol 4.2 (Bar-Ilan & Beaver method) | Yes | Safe only when callers feed inputs non-zero for every value the secret can take — now documented at the function itself and true for every current caller |
| `kor_cs` | Table 4 (cites [11]) | Yes | `a = 1+Σb_i` guaranteed non-zero by construction |
| `kor_cl` | Protocol 4.3 | Yes | Reduces to KOrCS safely; sum-≤-k argument re-derived directly |
| `mod2` | Protocol 3.4 | Yes | Additive mask, standard safe reveal |
| `pre_bitlt` | Protocol 11 (Catrina 2018) | Yes | Uses the `d_i+1` shift correctly |
| `pre_mod2m` / `bit_dec` | Built on PreBitLT | Yes | No reveal beyond PreBitLT's own |
| `truncpr` | Protocol 3.1 (FC2010) | Yes | Mask width now derived from the value's own width (item 11 fix) |
| `ltz` | Protocol 3.6 | Yes | Sign via Trunc, no new reveal |
| `eqz` | Protocol 3.7 | Yes | $c = a + 2^k r'' + r'$ then KOr, matches paper |
| `suf_mul_inv` | Same PreMulC machinery as PreBitLT | Yes | `d_i+1` shift, verified distributionally indistinguishable regardless of the bit |
| `suf_or` | Protocol 4.4 PreOrC | Yes, as of this fix | Was the one confirmed leak (fed raw bits); now matches PreOrC |
| `app_rec` | Protocol 8 (Catrina 2018) | Yes, with one independent re-derivation (step 5's `v` formula — the paper's own printed line doesn't reduce to its own stated target) | No further reveal beyond its sub-calls |
| `fpdiv` / `fpdiv_const`, `fpmul` | Same paper family | Yes | Composition of already-checked pieces |

A separate, real caveat on this whole tier: the paper's compositional claim is for Shamir sharing swapped to VSS specifically. This codebase's reveals mostly run through the already-Tier-1 robust reconstruction instead — plausibly satisfies the same role, but that equivalence hasn't been checked reveal-by-reveal (see Open questions).

## Tier 3 — genuinely open

| Sub-protocol | Why it doesn't inherit the Tier-2 argument |
| --- | --- |
| `rand_inv_pair` | Same MulPub-based reveal-random-with-retry shape as RandBit, but not a protocol the paper names explicitly — the paper's own compositional claim covers "the protocols presented in the following," and this isn't literally one of them. Likely fine by analogy, not yet entitled to the claim. |
| `prandint` / `prss` | A different security model entirely: PRSS mask derivation is HMAC-SHA256/PRF-based (computational), not information-theoretic. The paper's Shamir-to-VSS swap doesn't speak to this at all — needs its own argument, not inherited from anything above. Contained to PRandInt's own optional PRSS path; a non-PRSS RISS fallback exists. |
| `zero_share` | Provenance is ambiguous: its verifier is structurally identical to RanDouSha's already-Tier-1 pattern (same consistency check, same fix history), so a proof would likely just mirror RanSha's — open by strict provenance, but low-priority. |

## Core sub-protocols to prioritize

Refined by checking what each one's *interactive* steps actually are, not just what they're inspired by.

**Cleared — reduce directly to Tier 1, essentially no residual proof work:**

- **Mod2** — one reveal (`c = 2^{k-1}+a+2r''+r'`) via `RobustShare::recover_secret` directly, no multiplication anywhere. A cheater's only move is a wrong share of an honest sum — already tolerated by Tier-1 robust reconstruction.
- **TruncPr** — identical shape, same argument.
- **MulPub** — its reveal is a degree-2t locally-computed product via robust reconstruction, the same mechanism `triple_gen` (Tier 1) already uses. Abort-on-zero only ever fires on fresh randomness (`r·s`, independent of any secret), so the abort event itself carries no information. Every current caller (`RandBit`'s `r²`, `PreMulC`-offline's `r·s`, `RandInvPair`'s `r·r⁻¹`) feeds it only randomness, never an application secret — safe regardless of which specific masking argument applies to the caller's own use, since nothing sensitive is ever the input here.
- **RandBit** (Protocol 2.1, Catrina & de Hoogh 2010): `[r]←PRandFld(Zq); u←MulPub([r],[r])` (repeat if u=0), `v←u^{-(q+1)/4}`, `[b]←(v[r]+1)(2^{-1})`. One `MulPub` call on fresh randomness plus local arithmetic (square root, inverse, combine) — zero further interaction. Malicious security comes from where the protocol originates: it is the random-bit protocol of Damgård–Fitzi–Kiltz–Nielsen–Toft (TCC 2006), stated secure against active adversaries for any linear secret sharing scheme with a secure multiplication protocol — so it holds here as long as the MulPub product and its robust reveal are actively secure. The bit-hiding argument itself is a quadratic-residue one: squaring is exactly 2-to-1 on `F\{0}`, so revealing `u=r²` leaves exactly one bit of ambiguity — which of the two square roots `±r` was the truth — and since `r` was uniform before `u` was computed, that bit is perfectly hidden and uniformly distributed, which is precisely the bit the protocol extracts. Inherits `MulPub`'s clearance for the reveal step itself; the bit-extraction argument is independent of it and specific to this construction.

**Mostly cleared — a short, mechanical composition check remains, not a fresh proof:**

- **PreMulC** and **KOrCS** — every interactive step in each is a standard Tier-1 `Multiply` (Beaver) followed by a Tier-1 robust reveal at degree t (matching Beaver's own output degree) — no raw, non-Beaver multiplication anywhere in either. What's left is confirming a short (1–3 call), purely-local-linear-arithmetic glue between already-proven Tier-1 calls doesn't introduce a new cross-step issue — checkable mechanically since there's no secret-dependent branching beyond the already-bounded zero-abort case.

**Not cleared — a genuinely separate proof obligation:**

- **PRandInt / PRSS** — doesn't touch Reed-Solomon reconstruction at all when the PRSS path is active. Security rests on an HMAC-SHA256 PRF assumption plus soundness of replicated-key distribution across maximal unqualified sets — a different argument entirely from the one that clears the other six. The one real, from-scratch proof obligation left in the core 7.

Everything else in Tier 2 (`SufMulInv`, `PreBitLT`, `PreMod2m`/`BitDec`, `LTZ`, `EQZ`, `KOrCL`, `SufOr`, `AppRec`, `FXDiv`, `FpMul`) is a composition built on these seven — once a proof covers `PRSS` and the two composition checks, the rest reduces mostly to the faithfulness check already done (the Tier 2 table's "Faithful?" column), not re-deriving masking security from scratch.

## When UC composability actually matters

Sequential composition (cheap: check the glue, invoke an existing theorem) only works if sessions never run concurrently on the same committee — no later session starts before an earlier one fully completes and cleans up. This codebase doesn't enforce that: session stores are explicitly built for many simultaneous sessions (per-peer admission caps exist precisely for this), and a driver task awaiting a top-level operation and the node's message-processing loop are necessarily separate, concurrently-running tasks even for a single operation. Nothing found in this crate prevents a second top-level operation's driver from starting while a first is still mid-flight.

**The statement:** UC security is needed exactly when two or more sessions — same operation or different, same client or different — can be concurrently live on the same committee with no mechanism enforcing that one fully completes before the next starts. If that's possible, sequential composition's precondition is false and only UC's composition theorem justifies the stitching.

Two ways to close this, not one:

- **Enforce single-flight execution** — a per-node lock gating top-level operation entry, so only one operation is ever in flight. Small engineering lift; makes sequential composition's precondition true by construction.
- **Target UC instead** — if concurrent throughput is a real requirement, the core-7 proofs need to be built UC-style (environment-driven adversary, concurrent sessions) from the start, not upgraded later.

## To be done — Review

- [ ] PRandInt/RISS proof — reviewed, sound. (Item 20 caveat gone.)
- [ ] Concurrency architectural decision
- [ ] Perfect-core active-security write-ups — degree-≤ satisfied
- [ ] Tier-1 provenance verification
- [ ] Generation Lemma — degree-≤ satisfied
- [ ] **Masked-Open Lemma — ready for your review.** One doc, covers what used to be three line items: the lemma proper (§1–§5 + §6 Canetti composition + §6C collision-freeness), **stacked-layer functionality statements (§6A)**, and **the two framework obligations (§6B, degree-≤ satisfied via `1de29e8`)**.

## Engineering

- [x] zero_share batch_size fix — `04b679e`
- [x] Mask-index agreement — `d0092b4`
- [ ] Interim scoped lock — cancelled
- [x] RISS bootstrap gating — `944b22e`
- [ ] [→] SID uniqueness — **DELEGATED to VM** (like QUIC); registry parked in `stash@{1}`, not committed
- [x] $\kappa \ge 44$ — `53ead0e`
- [ ] FFI raw-pointer guard — deprioritized
- [x] Exact-degree verifier tests — `1de29e8`
- [ ] Minor: PRandMPrep comment done (`c91e301`) / QUIC → item 18
- [ ] Byzantine fault-injection testing — open

## Done/closed

- [x] zero_share provenance — closed by Generation Lemma
- [x] zero_share degree test (single-site) — merged above

## New

- [ ] [→] 18. QUIC peer auth — delegated, blocks item 3
- [x] 19. §5(d) single-session UC claim rigorous — done (incl. 19a/19b in §6C)
- [x] 20. RBC agreement/totality — FULLY CLOSED (proof doc + 20-eng `6f1a2ad`)
- [x] 21. PRSS/RISS security proof — done
- [x] 22. `*_fixed` ops added to Masked-Open scope — done
- [x] Cross-layer RBC quota gap — `a701fb4`

## In progress :

1. `PRandInt`**/RISS** :In review
2. **Concurrency architectural decision :**
    1. **What we're trying to do (one line):** every security proof we have is stand-alone — one operation at a time — but the node allows operations to run concurrently, which sits outside every proof's model; we're establishing which operations are provably safe to run concurrently and fixing the rest.

        **1. Papers we're following and what we got from them**

        - **Canetti, "Universally Composable Security" (J.ACM 2020):** stand-alone security does *not* imply concurrent security — two coordinated sessions suffice to break a stand-alone-secure protocol. Straight-line simulation is *necessary* for UC, never shown sufficient. Its non-concurrent model (§7.4, Prop. 29) formally anchors the lock option: a per-node lock = deploying in exactly the model our existing proofs already cover.
        - **Kushilevitz–Lindell–Rabin (STOC 2006 / SICOMP 2010) — the decisive one:**
            - Thm 1.1: *statistical* security + straight-line simulator $\nRightarrow$ concurrent security (explicit counterexample via delayed inputs).
            - Thm 1.2: *perfect* security + straight-line black-box simulator $\Longrightarrow$ secure under concurrent general composition $\Longleftrightarrow$ UC — no protocol changes.
            - Thm 1.5: *any* security level + straight-line + start synchronization (all-n "begin" barrier) $\Longrightarrow$ same.
            - Limits: all results are security-with-abort (liveness argued separately); plain model with independent sessions only — shared random oracle / shared PRSS keys not covered.

        **2. Classification — why and result**

        Why: KLR makes perfect-vs-statistical the *exact* boundary between "concurrency is free" and "concurrency is provably unsafe." So every primitive was classified by code-verified analysis of each reveal site and its mask's sampling domain (file:line evidence).

        | Class | Primitives | Mask | Consequence |
        | --- | --- | --- | --- |
        | **Perfect** | `robust_interpolate`, `batch_recon`, `mul` (Beaver), `triple_gen`, `ran_dou_sha`/`share_gen`, `input`, `output`, `MulPub`, `RandBit`, `RandInvPair`, `PreMulC`\*, `KOrCS` | full-field uniform (`F::rand`) | concurrency/UC free via KLR Thm 1.2, once stand-alone proofs are written down |
        | **Statistical** | `Mod2`, `TruncPr`, `KOrCL` + everything built on them (`PreMod2m`, `BitDec`, `LTZ`, `EQZ`, `AppRec`, `FXDiv`, `FpMul`, all comparisons) | bounded-width PRandM mask, slack $\kappa \ge 40$ | provably does **not** compose concurrently as-is (KLR Thm 1.1 shape) |
        | **Computational** | `PRandInt`/PRSS — and the entire statistical layer whenever PRSS keys are installed (the default), since the high mask `r″` is then PRF-derived | HMAC-SHA keystream / SHA256 commit-open | own proof (Lemma G); in deployment the "statistical" layer is actually computational |

        \* `PreMulC` conditional on its documented nonzero-input precondition.

        **3. How we intend to solve the concurrency issue**

        1. **Global single-flight lock** — sound, but serializes everything, including the perfect core that's provably concurrency-safe.
        2. **Start-sync preamble on statistical ops** (KLR Thm 1.5) — restores their concurrency but waits on all n parties per invocation, importing an all-n liveness coupling the system rejects everywhere else. Rejected.
        3. **Scoped reader/writer lock** — perfect ops acquire shared (run concurrently, justified by Thm 1.2); statistical ops acquire exclusive (isolation gives input availability by construction, so existing proofs apply). No liveness change, ~20 lines. **Interim/fallback.**
        4. **Prove the statistical ("red") ops UC directly** — proof strategy identified: inputs are handles to already-fixed values read atomically at invocation, and the transcript contains zero information about a session's mask until t+1 honest parties broadcast — each of which required its input already fixed — so input availability falls out of the Shamir threshold structure itself. Our own derivation; needs adversarial verification.

        **Decision: pursue 4**
