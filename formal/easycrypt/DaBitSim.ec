(* ==================================================================== *)
(* Real/ideal security of the replicated one-time-bit daBit, n = 4, t = 1 *)
(*                                                                        *)
(* Model of mpc/src/honeybadger/dabit/replicated.rs for the smallest      *)
(* deployment.  One party is corrupt.  The statement is perfect: no bound *)
(* on the adversary, no computational assumption, no error term.          *)
(* ==================================================================== *)
require import AllCore Bool Distr DBool.
require (*--*) Ring.

(* -------------------------------------------------------------------- *)
(* The arithmetic field F and the binary field K                          *)
(* -------------------------------------------------------------------- *)
type F.
clone import Ring.Field as FF with type t <- F.

instance field with F
  op rzero = FF.zeror
  op rone  = FF.oner
  op add   = FF.( + )
  op mul   = FF.( * )
  op opp   = FF.([-])
  op inv   = FF.invr
  op expr  = FF.exp

  proof oner_neq0 by apply/FF.oner_neq0
  proof addr0     by apply/FF.addr0
  proof addrA     by apply/FF.addrA
  proof addrC     by apply/FF.addrC
  proof addrN     by apply/FF.addrN
  proof mulr1     by apply/FF.mulr1
  proof mulrA     by apply/FF.mulrA
  proof mulrC     by apply/FF.mulrC
  proof mulrDl    by apply/FF.mulrDl
  proof mulrV     by apply/FF.mulrV
  proof expr0     by apply/FF.expr0
  proof exprS     by apply/FF.exprS
  proof exprN     by (move=> ?? _; apply/FF.exprN).

type K.
clone import Ring.Field as KF with type t <- K.

instance field with K
  op rzero = KF.zeror
  op rone  = KF.oner
  op add   = KF.( + )
  op mul   = KF.( * )
  op opp   = KF.([-])
  op inv   = KF.invr
  op expr  = KF.exp

  proof oner_neq0 by apply/KF.oner_neq0
  proof addr0     by apply/KF.addr0
  proof addrA     by apply/KF.addrA
  proof addrC     by apply/KF.addrC
  proof addrN     by apply/KF.addrN
  proof mulr1     by apply/KF.mulr1
  proof mulrA     by apply/KF.mulrA
  proof mulrC     by apply/KF.mulrC
  proof mulrDl    by apply/KF.mulrDl
  proof mulrV     by apply/KF.mulrV
  proof expr0     by apply/KF.expr0
  proof exprS     by apply/KF.exprS
  proof exprN     by (move=> ?? _; apply/KF.exprN).

(* K has characteristic 2. *)
axiom char2 : KF.oner + KF.oner = KF.zeror.

(* The uniform distribution on F. *)
op dF : F distr.
axiom dF_ll   : is_lossless dF.
axiom dF_funi : is_funiform dF.

lemma dF_fu : is_full dF by apply/funi_ll_full/dF_ll/dF_funi.

(* -------------------------------------------------------------------- *)
(* Parties.  c is corrupt; p, q, s are honest.  The unqualified sets are  *)
(* {c}, {p}, {q}, {s}; nobody outside {c} is corrupt.                     *)
(* x_i is party i's evaluation point in F, k_i its point in K.            *)
(* -------------------------------------------------------------------- *)
op xc, xp, xq, xs : F.
axiom xc_nz : xc <> FF.zeror.
axiom xp_nz : xp <> FF.zeror.
axiom xq_nz : xq <> FF.zeror.
axiom xs_nz : xs <> FF.zeror.

op kc, kp, kq, ks : K.
axiom kc_nz : kc <> KF.zeror.
axiom kp_nz : kp <> KF.zeror.
axiom kq_nz : kq <> KF.zeror.
axiom ks_nz : ks <> KF.zeror.

op two : F = FF.oner + FF.oner.

(* A bit in each field. *)
op bF (b : bool) : F = if b then FF.oner else FF.zeror.
op bK (b : bool) : K = if b then KF.oner else KF.zeror.

(* -------------------------------------------------------------------- *)
(* The adversary: the corrupt party, the dealer of every set it can deal, *)
(* the chooser of its own shares of every double sharing, and the         *)
(* environment that finally sees the honest parties' outputs.             *)
(* -------------------------------------------------------------------- *)
module type Adv = {
  (* the bits of {p}, {q}, {s}: every bit the corrupt party holds *)
  proc bits() : bool * bool * bool
  (* its shares (degree t, degree 2t) of the double sharing of each multiplication *)
  proc mask1() : F * F
  (* It is rushing: it sees the complete opened degree-2 polynomial (every honest share), *)
  (* and only then says which share of it the corrupt party contributes.                *)
  proc open1(d0 d1 d2 : F) : F
  proc mask2() : F * F
  proc open2(d0 d1 d2 : F) : F
  proc mask3() : F * F
  proc open3(d0 d1 d2 : F) : F
  (* whether the honest parties accepted every opening, and their output shares *)
  proc distinguish(ok : bool, fp fq fs : F, gp gq gs : K) : bool
}.

(* -------------------------------------------------------------------- *)
(* The real protocol.  A degree-1 sharing is a pair (secret, slope).      *)
(* -------------------------------------------------------------------- *)
module Protocol (A : Adv) = {
  proc main() : bool = {
    var bc, bp, bq, bs, st, s2t, r, u, r1, d, sh, ok, b';
    var c0, c1, p0, p1, q0, q1, s0, s1;
    var m0, m1, v0, v1, w0, w1, z0, z1, g0, g1;

    (* Deal.  {c}'s dealer is honest: a fresh uniform bit nobody corrupt receives. *)
    bc <$ {0,1};
    (bp, bq, bs) <@ A.bits();

    (* Leaves: beta_T * f_T, with f_T(X) = 1 - X / x_T. *)
    c0 <- bF bc; c1 <- - bF bc * invr xc;
    p0 <- bF bp; p1 <- - bF bp * invr xp;
    q0 <- bF bq; q1 <- - bF bq * invr xq;
    s0 <- bF bs; s1 <- - bF bs * invr xs;
    ok <- true;

    (* Multiplication 1: {c} with {p}. *)
    (st, s2t) <@ A.mask1();
    r <$ dF; u <$ dF;
    r1 <- (s2t - r - u * xc * xc) * invr xc;
    d  <- c0 * p0 + r;
    sh <@ A.open1(d, c0 * p1 + c1 * p0 + r1, c1 * p1 + u);
    (* n = 3t + 1: the opening needs every share to lie on one degree-2 polynomial *)
    ok <- ok /\ sh = d + (c0 * p1 + c1 * p0 + r1) * xc + (c1 * p1 + u) * xc * xc;
    m0 <- d - r; m1 <- - (st - r) * invr xc;
    v0 <- c0 + p0 - two * m0; v1 <- c1 + p1 - two * m1;

    (* Multiplication 2: {q} with {s}. *)
    (st, s2t) <@ A.mask2();
    r <$ dF; u <$ dF;
    r1 <- (s2t - r - u * xc * xc) * invr xc;
    d  <- q0 * s0 + r;
    sh <@ A.open2(d, q0 * s1 + q1 * s0 + r1, q1 * s1 + u);
    (* n = 3t + 1: the opening needs every share to lie on one degree-2 polynomial *)
    ok <- ok /\ sh = d + (q0 * s1 + q1 * s0 + r1) * xc + (q1 * s1 + u) * xc * xc;
    m0 <- d - r; m1 <- - (st - r) * invr xc;
    w0 <- q0 + s0 - two * m0; w1 <- q1 + s1 - two * m1;

    (* Multiplication 3: the two results. *)
    (st, s2t) <@ A.mask3();
    r <$ dF; u <$ dF;
    r1 <- (s2t - r - u * xc * xc) * invr xc;
    d  <- v0 * w0 + r;
    sh <@ A.open3(d, v0 * w1 + v1 * w0 + r1, v1 * w1 + u);
    (* n = 3t + 1: the opening needs every share to lie on one degree-2 polynomial *)
    ok <- ok /\ sh = d + (v0 * w1 + v1 * w0 + r1) * xc + (v1 * w1 + u) * xc * xc;
    m0 <- d - r; m1 <- - (st - r) * invr xc;
    z0 <- v0 + w0 - two * m0; z1 <- v1 + w1 - two * m1;

    (* K side: sum over the sets of beta_T * f^K_T. *)
    g0 <- bK bc + bK bp + bK bq + bK bs;
    g1 <- - (bK bc * invr kc + bK bp * invr kp + bK bq * invr kq + bK bs * invr ks);

    b' <@ A.distinguish(ok, z0 + z1 * xp, z0 + z1 * xq, z0 + z1 * xs,
                        g0 + g1 * kp, g0 + g1 * kq, g0 + g1 * ks);
    return b';
  }
}.

(* -------------------------------------------------------------------- *)
(* The ideal world.                                                       *)
(* -------------------------------------------------------------------- *)

(* The simulator runs the adversary.  It is never given the daBit. *)
module Sim (A : Adv) = {
  proc run() : bool * F * K = {
    var bp, bq, bs, st, s2t, d0, d1, d2, sh, ok;
    var ec, ep, eq, es, ev, ew, ez, gc;

    (bp, bq, bs) <@ A.bits();

    (* The corrupt party's shares of the leaves: zero for its own set. *)
    ec <- FF.zeror;
    ep <- bF bp * (FF.oner - xc * invr xp);
    eq <- bF bq * (FF.oner - xc * invr xq);
    es <- bF bs * (FF.oner - xc * invr xs);
    ok <- true;

    (* Each opening is uniform among the degree-2 polynomials that agree with the *)
    (* corrupt party's own share.                                                 *)
    (st, s2t) <@ A.mask1();
    d0 <$ dF; d2 <$ dF;
    d1 <- (ec * ep + s2t - d0 - d2 * xc * xc) * invr xc;
    sh <@ A.open1(d0, d1, d2);
    ok <- ok /\ sh = d0 + d1 * xc + d2 * xc * xc;
    ev <- ec + ep - two * (d0 - st);

    (st, s2t) <@ A.mask2();
    d0 <$ dF; d2 <$ dF;
    d1 <- (eq * es + s2t - d0 - d2 * xc * xc) * invr xc;
    sh <@ A.open2(d0, d1, d2);
    ok <- ok /\ sh = d0 + d1 * xc + d2 * xc * xc;
    ew <- eq + es - two * (d0 - st);

    (st, s2t) <@ A.mask3();
    d0 <$ dF; d2 <$ dF;
    d1 <- (ev * ew + s2t - d0 - d2 * xc * xc) * invr xc;
    sh <@ A.open3(d0, d1, d2);
    ok <- ok /\ sh = d0 + d1 * xc + d2 * xc * xc;
    ez <- ev + ew - two * (d0 - st);

    gc <- bK bp * (KF.oner - kc * invr kp) + bK bq * (KF.oner - kc * invr kq)
        + bK bs * (KF.oner - kc * invr ks);
    return (ok, ez, gc);
  }
}.

(* The daBit functionality: a uniform bit, shared in both fields by the unique *)
(* degree-1 polynomials through the corrupt party's shares.                    *)
module IdealWorld (A : Adv) = {
  proc main() : bool = {
    var b, acc, sf, sk, b';

    b <$ {0,1};
    (acc, sf, sk) <@ Sim(A).run();
    b' <@ A.distinguish(acc,
      bF b + (sf - bF b) * invr xc * xp,
      bF b + (sf - bF b) * invr xc * xq,
      bF b + (sf - bF b) * invr xc * xs,
      bK b + (sk - bK b) * invr kc * kp,
      bK b + (sk - bK b) * invr kc * kq,
      bK b + (sk - bK b) * invr kc * ks);
    return b';
  }
}.

(* -------------------------------------------------------------------- *)
(* Algebra                                                                *)
(* -------------------------------------------------------------------- *)
lemma bF_xor (x y : bool) :
  bF (x ^^ y) = bF x + bF y - two * (bF x * bF y).
proof.
by case: x => _; case: y => _; rewrite /bF /two /(^^) /=; ring.
qed.

(* What the fold computes at one gate, as the code writes it: m0 = d - r. *)
lemma xor_gate (x y : bool) (r : F) :
  bF x + bF y - two * (bF x * bF y + r - r) = bF (x ^^ y).
proof. by rewrite bF_xor; ring. qed.

lemma bK_xor (x y : bool) : bK (x ^^ y) = bK x + bK y.
proof.
case: x => _; case: y => _; rewrite /bK /(^^) /=; first by rewrite char2.
+ by ring.
+ by ring.
by ring.
qed.

(* -------------------------------------------------------------------- *)
(* Security                                                               *)
(* -------------------------------------------------------------------- *)
section.

declare module A <: Adv.

lemma real_ideal &m :
  Pr[Protocol(A).main() @ &m : res] = Pr[IdealWorld(A).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> ={res}) => //.
proc; inline *.
swap{1} 1 1. swap{2} 1 1.
(* the dealing: the functionality's bit is the hidden bit XOR the known ones *)
seq 2 2 : (={glob A, bp, bq, bs} /\ b{2} = (bc{1} ^^ bp{1}) ^^ (bq{1} ^^ bs{1})).
+ rnd (fun x => (x ^^ bp{1}) ^^ (bq{1} ^^ bs{1})).
  call (_ : true).
  auto => />.
  smt().
(* the leaves: the simulator holds the corrupt party's share of every wire *)
seq 9 5 : (={glob A, bp, bq, bs, ok} /\ b{2} = (bc{1} ^^ bp{1}) ^^ (bq{1} ^^ bs{1}) /\
           c0{1} = bF bc{1} /\ p0{1} = bF bp{1} /\ q0{1} = bF bq{1} /\ s0{1} = bF bs{1} /\
           ec{2} = c0{1} + c1{1} * xc /\ ep{2} = p0{1} + p1{1} * xc /\
           eq{2} = q0{1} + q1{1} * xc /\ es{2} = s0{1} + s1{1} * xc).
+ auto => /> &1 &2; do! split.
  + by field; apply xc_nz.
  + by field; apply xp_nz.
  + by field; apply xq_nz.
  by field; apply xs_nz.
(* multiplication 1 *)
seq 11 7 : (={glob A, bp, bq, bs, ok} /\ b{2} = (bc{1} ^^ bp{1}) ^^ (bq{1} ^^ bs{1}) /\
            q0{1} = bF bq{1} /\ s0{1} = bF bs{1} /\
            eq{2} = q0{1} + q1{1} * xc /\ es{2} = s0{1} + s1{1} * xc /\
            v0{1} = bF (bc{1} ^^ bp{1}) /\ ev{2} = v0{1} + v1{1} * xc).
+ wp; call (_ : true); wp.
  rnd (fun u => u + c1{1} * p1{1}) (fun e => e - c1{1} * p1{1}).
  rnd (fun r => r + c0{1} * p0{1}) (fun e => e - c0{1} * p0{1}).
  call (_ : true).
  auto => /> &1 &2 mk; progress;
    (try by ring); (try by apply/rnd_funi/dF_funi); (try by apply/is_fullP/dF_fu);
    (try by field; apply xc_nz); (try by apply xor_gate); by smt().
(* multiplication 2 *)
seq 11 7 : (={glob A, bp, bq, bs, ok} /\ b{2} = (bc{1} ^^ bp{1}) ^^ (bq{1} ^^ bs{1}) /\
            v0{1} = bF (bc{1} ^^ bp{1}) /\ ev{2} = v0{1} + v1{1} * xc /\
            w0{1} = bF (bq{1} ^^ bs{1}) /\ ew{2} = w0{1} + w1{1} * xc).
+ wp; call (_ : true); wp.
  rnd (fun u => u + q1{1} * s1{1}) (fun e => e - q1{1} * s1{1}).
  rnd (fun r => r + q0{1} * s0{1}) (fun e => e - q0{1} * s0{1}).
  call (_ : true).
  auto => /> &1 &2 mk; progress;
    (try by ring); (try by apply/rnd_funi/dF_funi); (try by apply/is_fullP/dF_fu);
    (try by field; apply xc_nz); (try by apply xor_gate); by smt().
(* multiplication 3 *)
seq 11 7 : (={glob A, bp, bq, bs, ok} /\ b{2} = (bc{1} ^^ bp{1}) ^^ (bq{1} ^^ bs{1}) /\
            z0{1} = bF b{2} /\ ez{2} = z0{1} + z1{1} * xc).
+ wp; call (_ : true); wp.
  rnd (fun u => u + v1{1} * w1{1}) (fun e => e - v1{1} * w1{1}).
  rnd (fun r => r + v0{1} * w0{1}) (fun e => e - v0{1} * w0{1}).
  call (_ : true).
  auto => /> &1 &2 mk; progress;
    (try by ring); (try by apply/rnd_funi/dF_funi); (try by apply/is_fullP/dF_fu);
    (try by field; apply xc_nz); (try by apply xor_gate); by smt().
(* the outputs *)
call (_ : true).
auto => /> &1 &2; do! split.
+ by field; apply xc_nz.
+ by field; apply xc_nz.
+ by field; apply xc_nz.
+ by rewrite !bK_xor; field; smt(kc_nz kp_nz kq_nz ks_nz).
+ by rewrite !bK_xor; field; smt(kc_nz kp_nz kq_nz ks_nz).
by rewrite !bK_xor; field; smt(kc_nz kp_nz kq_nz ks_nz).
qed.

end section.
