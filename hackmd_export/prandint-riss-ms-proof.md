# Proof for Maliciously secure PRandInt/RISS

**Setting :** $n$ parties, threshold $t < n/3$, sync, assuming SHA256 is modeled as a random oracle and the key-derivation PRF $\psi$ is secure, the protocol realizes $\mathcal{F}_{\mathsf{RandSum}}$ — correctness, privacy, and termination — against a static, active adversary corrupting at most $t$ parties.

## The algorithm

$n$ parties jointly produce a replicated (RISS) sharing of a random field element with no trusted dealer, then convert it locally to a Shamir sharing.

**Setting.** Parties $P_1 \dots P_n$, a static active adversary corrupting at most $t < n/3$ of them, a field $F$, a hash $H$ (modeled as a random oracle) and a reliable broadcast channel (RBC). Let $\mathcal{T}$ be the set of all maximal unqualified sets $T \subset \{1 \dots n\}$ with $|T| = t$. Party $P_j$ is entitled to the component $r_T$ exactly when $j \notin T$.

**Stage 1 — Generation (commit, then open).**

1. **Sample.** Each $P_i$, for every $T \in \mathcal{T}$, picks a uniform contribution $r_T^i \in F$ and a fresh nonce $\rho_T^i \in \{0,1\}^\lambda$.
2. **Commit.** $P_i$ computes $c_T^i = H(T, r_T^i, \rho_T^i)$ for every $T$ and sends the whole vector $(c_T^i)_T$ through RBC, so every party sees the same commitments.
3. **Barrier.** No party sends any opening until RBC has delivered commitment vectors from all $n$ parties. This fixes every contribution before any value is revealed (anti-rushing).
4. **Open.** For every $T$ and every $j \notin T$, $P_i$ sends $(r_T^i, \rho_T^i)$ privately to $P_j$.
5. **Verify.** $P_j$ checks $H(T, r_T^i, \rho_T^i) = c_T^i$ for each opening it receives. Any mismatch → $P_j$ aborts, naming $P_i$.
6. **Aggregate.** $P_j$ sets $r_T = \sum_i r_T^i$ for every $T \not\ni j$ and outputs its RISS share $\{r_T : j \notin T\}$. The shared secret is $r = \sum_T r_T$, which no single $T$-coalition can learn because it is missing $r_T$.

**Stage 2 — Local conversion to Shamir (no messages).** For each $T$, let $f_T$ be the unique polynomial of degree $\le t$ with $f_T(0) = 1$ and $f_T(k) = 0$ for every $k \in T$. Party $P_j$ outputs:

$$
s_j = \sum_{T \in \mathcal{T},\; j \notin T} r_T \cdot f_T(j)
$$

The points $(j, s_j)$ lie on the degree-$t$ polynomial $\sum_T r_T \cdot f_T$, whose value at $0$ is $r$ — a Shamir sharing of the same secret.

**Stage 3 — Optional PRSS bootstrap (no messages).** Treat each $r_T$ (or a key derived from it) as a PRF key $K_T$. For any public counter $a$, $P_j$ outputs a fresh Shamir share of a pseudorandom value without interaction:

$$
s_j(a) = \sum_{T \in \mathcal{T},\; j \notin T} \psi_{K_T}(a) \cdot f_T(j)
$$

Only Stage 1 involves interaction, which is why the security argument below concentrates on it.

## Goal

For each maximal unqualified set $T$ ($|T| = t$, in the $n$-party, $t < n/3$ threshold structure), the generation step must deliver a single agreed value $r_T = \sum_i r_T^i$ to every party outside $T$, such that:

- every honest contribution $r_T^i$ is uniform and independent
- a corrupt party's contribution is fixed before it can see any honest value
- any two honest parties who both terminate agree on $r_T$

Everything downstream — the RISS→Shamir conversion, the optional PRSS key bootstrap — only consumes this $r_T$. So proving the whole PRandInt/RISS pipeline malicious-secure reduces to three steps: prove the generation step realizes this target; confirm the downstream stages are safe given a correctly-generated $r_T$ (they are, by direct citation); compose.

## Already covered by the source papers

Two of the four pipeline stages need no new proof — they follow directly from cited results, conditional on a correctly-generated $r_T$.

| Stage | Result | What it gives |
| --- | --- | --- |
| RISS → Shamir conversion (`try_advance_from_riss`) | Cramer–Damgård–Ishai, *Share Conversion, Pseudorandom Secret-Sharing and Applications to Secure Computation*, TCC 2005, Theorem 1; Damgård–Thorbek, *Efficient Conversion of Secret-shared Values Between Different Fields*, Proposition 1 | A purely local, deterministic, non-interactive transform — no messages, so no new attack surface for an active adversary. Holds unconditionally given a valid input sharing. |
| RISS correctness/privacy | Damgård–Thorbek, Lemma 1 | Qualified sets reconstruct, unqualified sets learn nothing — given the share was honestly dealt. |
| PRF-based fast mask derivation (`generate_prss_at`) | Cramer–Damgård–Ishai, Theorem 3 ($(d+2)t < n$) and Theorem 5 ($t < n/4$) | Genuine *active*, static-adversary security proofs — real simulators reducing to PRF indistinguishability, not just passive results. |

Neither of the first two rows is an "MS theorem" in the usual sense — they're adversary-agnostic structural facts (no interaction, nothing for an active adversary to attack). The third row is a genuine active-adversary result. All three share one precondition: a correctly, non-equivocally generated $r_T$ feeding in.

## The genuinely open gap

Neither paper proves — or even fully specifies — active-secure generation of the initial $r_T$ when no single party is a trusted dealer.

Cramer–Damgård–Ishai's active-adversary theorems (Theorem 3, Theorem 5) take "sets of keys... have been distributed" as a blanket setup assumption. Their one proof of generating a shared value under adversarial behavior, NIVSS (Lemma 3), explicitly assumes an *honest* dealer: "Adv that corrupts up to t of the players, but not D."

Damgård–Thorbek's bit-conversion protocol assumes "the players have shared a RISS share $\{r_A\}$" as a precondition throughout. The one place addressing dealer-less generation — §3.4, "The Initial RISS Share" — is two informal sentences, with no protocol specification, no stated adversary model, and no proof: "letting each player share a random value in RISS and using the sum of those."

This codebase's `generate_riss`/`verify_and_insert` is exactly that gap, filled with machinery neither paper describes: a SHA256 commit-then-open scheme, an RBC-broadcast commitment, and an anti-rushing barrier before any opening. That's the one piece needing an original proof.

## Lemma G: generation security

Simulator Sim, for one execution of `generate_riss`/`verify_and_insert`, against a static active adversary Adv corrupting $C$, $|C| \le t$. Models $H$ (SHA256) as a random oracle — a real modeling assumption, flagged explicitly rather than folded into "collision-resistant."

**Phase 1 — simulate commitments.** For each honest party $i$ and each tset $T$ not containing $i$, Sim broadcasts a uniformly random string as $c_T^i$ instead of a real commitment — indistinguishable, since a real $H(\text{tset}, r, \text{nonce})$ on a fresh high-entropy nonce is itself statistically close to uniform. For Adv's commitment broadcasts on behalf of corrupted parties, Sim records every oracle query Adv makes to $H$; when Adv later broadcasts $c_T^i$ for corrupted $i$, Sim scans for a recorded query producing that exact hash and extracts $(\text{tset}, r_T^i, \text{nonce})$. No match → Sim assumes $r_T^i := 0$ (Adv cannot open it to anything else except with negligible probability).

**Phase 2 — query the ideal functionality.** Once all $n$ commitment-vectors are RBC-delivered (RBC's totality is already established elsewhere), Sim submits the extracted corrupted contributions to $\mathcal{F}_{\mathsf{RandSum}}$ for every applicable $T$ and receives the true $r_T$ for every $T$ with at least one corrupted party outside it — the only sets a corrupted party is entitled to learn anything about.

**Phase 3 — program the openings.** Sim must open the honest parties' dummy commitments to values that sum, with the already-fixed corrupted contributions, to the real $r_T$. It samples all but one honest contribution uniformly and sets the last to whatever makes the total equal $r_T$ — reproducing the exact real joint distribution, since conditioning $n$ independent uniforms on their sum is the same as sampling $n-1$ freely and fixing the last. Sim then programs the random oracle so $H(\text{tset}, \text{assigned\_value}, \text{nonce}) = c_T^i$ (the string already broadcast) and sends the resulting opening to Adv, matching the real message schedule exactly.

**Phase 4 — abort behavior.** If Adv's corrupted parties send a simulated honest party an opening that doesn't match their own broadcast commitment, Sim runs the real verification check — bit-for-bit, no approximation — and reports the same equivocation abort a real honest party would, per recipient. This correctly reproduces the protocol's real asymmetric-abort behavior: Adv can make some honest parties abort and others complete, since that's a genuine property of the protocol, not a simulation artifact.

**Indistinguishability.** Adv distinguishes Sim's world from reality only by catching the oracle-programming step in Phase 3 — having already queried $H$ on the exact $(\text{tset}, \text{assigned\_value}, \text{nonce})$ point before Sim programs it. Since each nonce is fresh, high-entropy, and chosen after Adv's commit-phase messages are fixed, that probability is negligible. Everything else — abort logic, the final numeric distribution of $r_T$ — is exact.

**What this establishes.** Generation is proven secure in the random-oracle model for SHA256, computationally (not information-theoretically), for $t < n/3$, with correctness/privacy guaranteed on termination and the asymmetric-abort behavior carried forward explicitly as a liveness property rather than smoothed over.

## Composition theorem: PRandInt/RISS is MS

**Theorem.** Fix $n$ parties, $t < n/3$, a static active adversary. Assume SHA256 is modeled as a random oracle (for the commitment scheme) and the key-derivation PRF $\psi$ is secure. Then the composed protocol — generation (`generate_riss`/`verify_and_insert`) → local conversion (`try_advance_from_riss`) → optional PRSS bootstrap (`take_riss_keys`/`generate_prss_at`) — correctly and privately produces Shamir-shared (pseudo)random values on termination, against this adversary.

**Why composition is easy here.** Stage 2 (conversion) is a deterministic, non-interactive function of Stage 1's output — `build_all_f_polys`/evaluate sends no messages at all. Theorem 1 (Cramer–Damgård–Ishai) plus Proposition 1 (Damgård–Thorbek) say this local function preserves exactly the correctness/privacy Stage 1 already established, introducing no new protocol view for Adv to exploit. The same holds for Stage 3's bootstrap (`derive_key_from_riss`) and the fast derivation itself (`generate_prss_at`) — both purely local, no network calls. So the combined simulator for generation + conversion + bootstrap is just $\mathrm{Sim}_G$ (Lemma G's simulator): stages 2 and 3 add no interaction, so there's nothing further to simulate — the environment can recompute those deterministic steps itself from $\mathrm{Sim}_G$'s output exactly as it would in the real world.

The one place genuine active-adversary proof machinery re-enters is downstream consumption of PRSS-derived shares (for example, feeding them into `TruncPr`'s masking) — that's where the Theorem 3/5-style PRF-indistinguishability reduction actually does work, at the point of use, not inside key derivation itself. That is a separate, per-caller obligation, not part of this theorem.

## Scope and residual caveats

**Computational, not information-theoretic.** The result rests on SHA256-as-random-oracle plus PRF security — consistent with where PRandInt/RISS sat before this proof (the one construction in the core protocol set that doesn't reduce to a Shamir-to-VSS or Reed-Solomon argument).

**Liveness is not guaranteed.** Correctness and privacy hold on termination. Abort-steering lets a corrupt contributor commit, watch every honest opening arrive, then withhold its own — a clean stall, since RBC totality means every honest party reaches the same conclusion about who's missing. Separately, asymmetric equivocation can make some honest recipients abort on a bad opening while others — who never received it — complete normally. Neither breaks correctness or privacy for any party that does terminate; both are carried forward as liveness properties, not smoothed into the security claim.

**Scope: generation only.** This theorem covers PRandInt/RISS as a self-contained mechanism for producing Shamir-shared (pseudo)random values. It does not clear any specific caller's *use* of those values — each consumer (`TruncPr` and others) still needs its own masking/independence check, the same obligation every other Tier-1 primitive's callers already carry.

**Target functionality.** For each maximal unqualified set $T$, deliver a single agreed value $r_T = \sum_i r_T^i$ to every party outside $T$, where each honest contribution is uniform and independent, and a corrupt contribution is fixed before any honest value is revealed. That's the property the generation step (`generate_riss`/`verify_and_insert`) has to realize against active, $t < n/3$ corruption — everything downstream just consumes $r_T$.

**Lemma G (Generation).** The commit-then-open construction realizes this, via three properties:

- **Binding** — each $r_T^i$ is locked in by a SHA256 commitment before anything opens. Under collision resistance, a corrupt party cannot later produce a different opening that still verifies — whatever it committed to is what gets used.
- **Hiding / anti-rushing** — no party opens anything until all $n$ commitment-vectors are RBC-delivered. RBC's totality (already Tier 1) means every honest party sees the identical set of commitments before any value is revealed, so a corrupt contribution is fixed independently of every honest $r_T^i$ for the same $T$ — it can't be chosen in reaction to them.
- **Consistency** — a recipient accepts an opening only if it matches the RBC-delivered commitment (`commit_contribution(...) == expected`); a mismatch is rejected outright (`EquivocationDetected`), not silently accepted. Since RBC gives every honest party the same commitment vector, any two honest parties who both finish collecting $r_T$ agree on its value.

The one acknowledged gap is abort-steering — a corrupt party can commit, watch, then simply never open — but that only stalls termination (and does so cleanly, since RBC totality means every honest party reaches the same conclusion about who's missing). It doesn't produce disagreement or leak anything once a party *does* terminate. So Lemma G proves correctness + privacy conditional on termination, with liveness carved out as a separate, already-understood caveat.

**Composition.** Lemma G's output — an agreed, correctly-distributed $r_T$ sum — is exactly the precondition every other piece assumes: Damgård–Thorbek's Lemma 1 (RISS correctness/privacy), Cramer–Damgård–Ishai's Theorem 1 / Damgård–Thorbek's Proposition 1 (RISS→Shamir conversion), and the Theorem 3/5-style PRF argument (PRSS bootstrap) all start from "given a correctly-dealt share." Sequential composition — Lemma G's simulator feeding into theirs — glues these into one end-to-end claim.

**Resulting theorem (draft statement):** Against a static, active adversary corrupting $t < n/3$ parties, assuming SHA256 is collision-resistant and the PRF used for mask derivation is secure, the PRandInt/RISS protocol realizes correct, private generation of Shamir-shared (pseudo)random values — with liveness (not correctness or privacy) conditioned on every committed party eventually opening.
