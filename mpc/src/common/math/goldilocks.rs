use ark_ff::{Fp64, MontBackend, MontConfig};

/// Configuration for the Goldilocks field.
#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct GoldilocksMontConfig;

/// Number of limbs of 64 bits used by the Goldilocks field.
const NUM_LIMBS: usize = 1;

/// Goldilocks field.
pub type GoldilocksField = Fp64<MontBackend<GoldilocksMontConfig, NUM_LIMBS>>;
