# HoneyBadgerMPC Malicious-Security Proof Stack — Overview

This note is the map for the proof collection. Each linked document is self-contained; together they establish one end-to-end claim about the `mpc-protocols` (HoneyBadgerMPC) implementation.

## The headline claim

> **Theorem (composed).** Against a **static active adversary** corrupting $t < n/3$ of $n = 3t+1$ parties, in the **asynchronous** network model, the construction **UC-realizes its ideal functionalities with abort**: the perfect core exactly, and the statistical ("red") operations as *leaky* functionalities with total distinguishing advantage at most
> $$
> \mathrm{Adv}^{(N)}_{\mathrm{PRF}} + N \cdot 2^{-\kappa_{\mathrm{eff}}}, \qquad \kappa_{\mathrm{eff}} \ge 44
> $$
> where $N$ is the number of masked opens (per-operation counts tabulated in the Masked-Open Lemma §6). On the RISS path the PRF term vanishes.

What it deliberately is **not**: no guaranteed output delivery (abort is always adversary-reachable — with-abort is the claim, permanently); not leak-free (red ops publish masked values by design, with the budget above); not information-theoretic on the PRSS path (one global PRF term); not unconditionally deployable (standing conditions below).

## How the stack fits together

Trust flows bottom-up; each layer's proof consumes the layer below as its hybrid-model assumption:

1. **Transport** — mutually authenticated point-to-point channels (the "secure channels" every model paragraph assumes). Discharged by QUIC key-pinning, deny-by-default (engineering item 18, delegated).
2. **Broadcast** — Bracha RBC and AVID give agreement/totality/validity (the papers' own theorems; implementation faithfulness is taken as given). The one property the papers don't cover — many concurrent sessions multiplexed through one node store — is proved in *RBC session isolation*.
3. **Generation (preprocessing suppliers)** — *Generation Lemma* (RanSha / RanDouSha / ZeroSha realize their pool functionalities with zero-error straight-line simulators), *ZeroSha, Maliciously Secure* (the standalone line-by-line proof and code-witness for ZeroSha's invariants), and *PRandInt/RISS* (dealer-less mask-key generation, commit-then-open, random-oracle model).
4. **Consumption** —
   - *Perfect-Open Lemma*: the perfect core (`mul`, triple sacrifice, MulPub, RandBit, RandInvPair, PreMulC, KOrCS, input/output) opens with **zero** simulation error, straight-line ⇒ UC by KLR Thm 1.2.
   - *Masked-Open Lemma*: the statistical layer ($\mathcal{F}_{\mathsf{TruncPr}}$, $\mathcal{F}_{\mathsf{Mod2}}$, $\mathcal{F}_{\mathsf{KOrCL}}$) as leaky functionalities — single-instance UC theorem (§5), Canetti-composition budget (§6), stacked-op functionality statements (§6A), framework obligations (§6B), and mask-index collision-freeness (§6C).
5. **Provenance** — *Tier-1 Provenance & Sync-Async Bridge* audits every literature citation the stack leans on and states why synchronous-paper *safety* transfers to the async deployment (liveness is not claimed). *HBMPC Security Assumption Audit* is the original inventory that scoped the whole effort.

## The documents

| Doc | What it establishes | Guarantee |
| --- | --- | --- |
| **HBMPC Security Assumption Audit** (`hbmpc-security-assumption-audit.md`) | The assumption inventory that drove the review: what each protocol silently relied on, and its status | audit, not a proof |
| **Tier-1 Provenance & Sync-Async Bridge** (`tier-1-provenance-sync-async-bridge.md`) | Citation audit (incl. corrected DN07 attribution) + why sync-paper safety carries to the async model via schedule-independent algebra + RBC | literature audit + bridge argument |
| **RBC session isolation** (`rbc-session-isolation.md`) | Concurrent RBC instances through one `SessionStore` stay independent (state partition, no shared quorum counters, label agreement, liveness isolation); Bracha/AVID single-instance properties by citation | structural proof; dealer-quota DoS recorded as fault-model residual (since fixed) |
| **ZeroSha, Maliciously Secure** (`zerosha-maliciously-secure.md`) | ZeroSha UC-realizes $\mathcal{F}_{\mathsf{ZeroSha}}$; the hyperinvertibility and point-to-point-opening invariants with their exploit-backed counterexamples | perfect, with abort |
| **Generation Lemma** (`generation-lemma.md`) | RanSha / RanDouSha / ZeroSha realize corruption-aware pool functionalities with **zero-error straight-line simulators** (the dimension-ledger argument); closes the last trusted-by-citation hole in the perfect core | perfect, with abort; KLR lift to UC |
| **PRandInt/RISS MS proof** (`prandint-riss-ms-proof.md`) | Dealer-less generation of RISS mask keys: Lemma G (commit-then-open, SHA256 as random oracle) + composition with the cited CDI05/DT conversion results | computational (ROM + PRF), with abort; liveness carved out |
| **Perfect-Open Lemma** (`perfect-open-lemma.md`) | Every perfect-core reveal is simulatable with zero error, straight-line ⇒ UC via KLR Thm 1.2, conditional on secure channels (KLR Cor. 4 — item 18) and the pool functionalities (Generation Lemma) | perfect, with abort |
| **Masked-Open Lemma & F_TruncPr** (`masked-open-lemma.md`) | The red layer: leaky functionalities, single-instance UC theorem (§5), composition budget $\mathrm{Adv}^{(N)}_{\mathrm{PRF}} + N\cdot 2^{-\kappa_{\mathrm{eff}}}$ (§6), per-op leak counts (§6 table, §6A), async $\mathcal{F}_{\mathsf{Open}}$ / $\mathcal{F}_{\mathsf{PRandM}}$ obligations (§6B), mask-index collision-freeness MI-1–MI-4 (§6C) | statistical + one global PRF term, with abort |

Reading order for a first pass: Audit → Tier-1 → RBC isolation → ZeroSha → Generation → PRandInt/RISS → Perfect-Open → Masked-Open. Dependency order for checking the theorem: bottom-up as in the previous section.

## Standing deployment conditions

These are the theorem's assumptions, enforced operationally — they never "close" as work items:

- **A — Same program order and configuration.** All honest nodes execute the identical global sequence of top-level operations, one at a time, with identical `precision` / `statistical_security` (hence `mask_bits`). Needed by Masked-Open §6C (session/mask agreement) and by the shared FIFO preprocessing pools (triples, RandBits, zero-shares), which bind entries to operations by drain order.
- **B — All-or-nothing advancement.** An operation that fails on any honest node terminates the execution for all; no partial retry. A violated B is a *silent, persistent privacy leak*, not a loud abort (Masked-Open §6C failure analysis).
- **C — instance_id uniqueness.** No two executions sharing PRSS keys may reuse an `instance_id` (else keystreams repeat and $c_1 - c_2 = x_1 - x_2$ is public). Discharged by the VM allocating fresh ids per run, or re-keying per run — delegated to the VM owner.
- **Secure channels (item 18).** Every node↔node connection mutually authenticated against the party registry, deny-by-default (QUIC key pinning). This is the hybrid-model channel assumption of every proof above and the explicit KLR Cor. 4 condition of the Perfect-Open lift — delegated to the networking owner. Client-link pinning/TOFU is a separate, lower-priority follow-up (client I/O privacy only).

## Status

All proof documents are written and adversarially verified (independent refutation passes; outcomes folded into each doc's status section). Supporting engineering is committed on `security`: session-derived PRandInt masks (`d0092b4`), sender-attributed RBC quotas + byte ledger (`6f1a2ad`), retire-after-drain (`a701fb4`), degree-$\le$ verifiers (`1de29e8`), $\kappa \ge 44$ (`53ead0e`), zero_share batch-size hardening (`04b679e`), RISS bootstrap gating (`944b22e`). Outstanding: the two delegated items above (18, C) and the review sign-off of this document set. Byzantine fault-injection / fuzzing remains as assurance work, not a proof dependency.
