(* ==================================================================== *)
(* Real/ideal security of B2A for one bit, n = 4, t = 1                   *)
(*                                                                        *)
(* Model of mpc/src/honeybadger/b2a/b2a.rs.  The daBit comes from the     *)
(* ideal daBit functionality that DaBitSim.ec shows the generator         *)
(* realises: the adversary fixes the corrupt party's two shares, the bit  *)
(* is uniform.  A value of several bits is this protocol run once per bit *)
(* on independent daBits, followed by a public linear combination.        *)
(* ==================================================================== *)
require import AllCore Bool Distr DBool.
require import DaBitSim.
import FF KF.

(* The adversary is the corrupt party and the environment. *)
module type B2AAdv = {
  (* the bit to convert, and the corrupt party's share of its binary sharing *)
  proc input() : bool * K
  (* the corrupt party's shares of the daBit: arithmetic half, binary half *)
  proc dabit() : F * K
  (* the complete opened degree-1 polynomial c = x + r, as (value, slope) *)
  proc opened(c0 c1 : K) : unit
  (* the honest parties' output shares *)
  proc distinguish(fp fq fs : F) : bool
}.

(* -------------------------------------------------------------------- *)
(* The real protocol.  A degree-1 sharing is a pair (secret, slope).      *)
(* -------------------------------------------------------------------- *)
module B2AReal (A : B2AAdv) = {
  proc main() : bool = {
    var x, sx, af, ak, r, b';
    var x0, x1, rk0, rk1, rf0, rf1, c0, c1, o0, o1;

    (x, sx) <@ A.input();
    x0 <- bK x; x1 <- (sx - bK x) * invr kc;

    (* the daBit: a uniform bit, shared through the corrupt party's shares *)
    (af, ak) <@ A.dabit();
    r <$ {0,1};
    rk0 <- bK r; rk1 <- (ak - bK r) * invr kc;
    rf0 <- bF r; rf1 <- (af - bF r) * invr xc;

    (* 1-2. mask and open; the opening is degree t and robust, so it cannot be aborted *)
    c0 <- x0 + rk0; c1 <- x1 + rk1;
    A.opened(c0, c1);

    (* 3. [x]_F = [r]_F if c = 0, and 1 - [r]_F if c = 1 *)
    if (c0 <> KF.zeror) {
      o0 <- FF.oner - rf0; o1 <- - rf1;
    } else {
      o0 <- rf0; o1 <- rf1;
    }

    b' <@ A.distinguish(o0 + o1 * xp, o0 + o1 * xq, o0 + o1 * xs);
    return b';
  }
}.

(* -------------------------------------------------------------------- *)
(* The ideal world.                                                       *)
(* -------------------------------------------------------------------- *)

(* The simulator is given the corrupt party's input share, never the bit. *)
module B2ASim (A : B2AAdv) = {
  proc run(sx : K) : F = {
    var af, ak, c;

    (af, ak) <@ A.dabit();
    (* the opened value is a fair coin *)
    c <$ {0,1};
    A.opened(bK c, (sx + ak - bK c) * invr kc);
    return (if c then FF.oner - af else af);
  }
}.

(* The functionality hands the honest parties the unique degree-1 arithmetic *)
(* sharing of the bit through the corrupt party's share.                      *)
module B2AIdeal (A : B2AAdv) = {
  proc main() : bool = {
    var x, sx, sf, b';

    (x, sx) <@ A.input();
    sf <@ B2ASim(A).run(sx);
    b' <@ A.distinguish(
      bF x + (sf - bF x) * invr xc * xp,
      bF x + (sf - bF x) * invr xc * xq,
      bF x + (sf - bF x) * invr xc * xs);
    return b';
  }
}.

(* -------------------------------------------------------------------- *)
lemma bK_nz (b : bool) : (bK b <> KF.zeror) = b.
proof. by case: b => _; rewrite /bK /= ?KF.oner_neq0. qed.

lemma bF_not (b : bool) : bF (!b) = FF.oner - bF b.
proof. by case: b => _; rewrite /bF /=; try ring. qed.

section.

declare module A <: B2AAdv.

lemma b2a_real_ideal &m :
  Pr[B2AReal(A).main() @ &m : res] = Pr[B2AIdeal(A).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> ={res}) => //.
proc; inline *.
call (_ : true).
seq 12 5 : (={glob A, x, af} /\ c{2} = x{1} ^^ r{1} /\ rf0{1} = bF r{1} /\
            rf1{1} = (af{1} - bF r{1}) * invr xc /\ c0{1} = bK (x{1} ^^ r{1})).
+ call (_ : true); wp.
  rnd (fun r => x{1} ^^ r).
  call (_ : true); wp.
  call (_ : true).
  auto => /> xs_ ds_; split; first by smt().
  move=> _ r _; split; first by smt().
  move=> _; rewrite bK_xor /=.
  by field; apply kc_nz.
auto => /> &1 &2.
case: (x{2}) => _; case: (r{1}) => _;
  rewrite /bK /bF /(^^) /= ?KF.oner_neq0 /=; (do! split); by field; apply xc_nz.
qed.

end section.
