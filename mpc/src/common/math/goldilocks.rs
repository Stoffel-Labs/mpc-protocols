use ark_ff::{Fp64, MontConfig};

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct GoldilocksMontConfig;

pub type GoldilocksField = Fp64<GoldilocksMontConfig>;
