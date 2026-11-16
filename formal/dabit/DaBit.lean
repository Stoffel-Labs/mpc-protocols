import DaBit.Basic
import DaBit.Protocol
import DaBit.Soundness
import DaBit.BatchOpening
import DaBit.Privacy
import DaBit.Fold
import DaBit.Security
import DaBit.Circuit
import DaBit.B2A
import DaBit.A2B
import DaBit.EdaBit
import DaBit.Compose
import DaBit.Extraction

/-!
The axioms each headline theorem depends on.  `sorryAx` must not appear; the three listed are
Lean's standard classical axioms.
-/
#print axioms DaBit.dabit_correct
#print axioms DaBit.opening_sound
#print axioms DaBit.batch_opening_sound
#print axioms DaBit.echo_consistent
#print axioms DaBit.run_sound
#print axioms DaBit.dealt_flip
#print axioms DaBit.fibreEquiv
#print axioms DaBit.perfect_privacy
#print axioms DaBit.eq_of_secret_and_shares
#print axioms DaBit.output_determined
#print axioms DaBit.zeroTree_valid
#print axioms DaBit.fold_shape
#print axioms DaBit.dabit_secure
-- shared circuits
#print axioms DaBit.run_eval_zero
#print axioms DaBit.cfibreEquiv
-- B2A
#print axioms DaBit.b2aBit_eval
#print axioms DaBit.recompose_eval
#print axioms DaBit.recompose_faithful
#print axioms DaBit.b2aFibreEquiv
#print axioms DaBit.b2aCheckEquiv
#print axioms DaBit.bit_of_mul_succ_eq_zero
-- A2B
#print axioms DaBit.a2b_correct
#print axioms DaBit.a2bFibreEquiv
#print axioms DaBit.offset_adder
-- edaBit
#print axioms DaBit.composeEdaBit_valid
#print axioms DaBit.filter_sound
#print axioms DaBit.filter_complete
#print axioms DaBit.filterEquiv
-- composition
#print axioms DaBit.a2b_b2a_roundtrip
#print axioms DaBit.a2b_then_b2a
#print axioms DaBit.a2bSwap_outputs_agree
#print axioms DaBit.online_opening_completes
#print axioms DaBit.triple_from_double
-- randomness extraction
#print axioms DaBit.HimPoints.apply_eq_sum
#print axioms DaBit.HimPoints.injective_on
#print axioms DaBit.HimPoints.extraction_sound
#print axioms DaBit.HimPoints.surjective_on
#print axioms DaBit.HimPoints.fibreEquiv
