use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_std::rand::Rng;

/// Public parameters for Pedersen commitment to polynomials.
pub struct PedersenPolyCommParams<F, G>
where
    G: CurveGroup<ScalarField = F>,
    F: FftField,
{
    /// Base point g.
    pub g: G,
    /// Base point h.
    ///
    /// # Security requirement
    ///
    /// This point should be such that nobody knows `log_g(h)`.
    pub h: G,
}

impl<F, G> PedersenPolyCommParams<F, G>
where
    G: CurveGroup<ScalarField = F>,
    F: FftField,
{
    /// Creates a new parameter set for Pedersen commitments.
    pub fn new(g: G, h: G) -> Self {
        Self { g, h }
    }
}

/// Pedersen commitments for a polynomial.
///
/// The commitment is a collection of individual Pedersen commitments to each coefficient of the
/// polynomial.
pub struct PedersenPolyCommitment<F, G>
where
    G: CurveGroup<ScalarField = F>,
    F: FftField,
{
    /// Public parameters used for this commitment.
    pub public_params: PedersenPolyCommParams<F, G>,
    /// Commitments to the polynomial coefficients.
    pub coeff_commitments: Vec<G>,
}

impl<F, G> PedersenPolyCommitment<F, G>
where
    G: CurveGroup<ScalarField = F>,
    F: FftField,
{
    /// Computes the commitment to a polynomial.
    pub fn commit(
        public_params: PedersenPolyCommParams<F, G>,
        poly_coeffs: &[F],
        rng: &mut impl Rng,
    ) -> (Self, Vec<F>) {
        let random_t: Vec<F> = (0..poly_coeffs.len()).map(|_| F::rand(rng)).collect();
        let coeff_commitments = poly_coeffs
            .iter()
            .zip(random_t.clone())
            .map(|(coeff, t)| public_params.g.mul(*coeff).add(public_params.h.mul(t)))
            .collect();
        (
            PedersenPolyCommitment {
                public_params,
                coeff_commitments,
            },
            random_t,
        )
    }

    /// Verifies the polynomial commitment.
    pub fn verify(&self, poly_coeffs: &[F], random_t: &[F]) -> bool {
        self.coeff_commitments
            .iter()
            .zip(poly_coeffs.iter())
            .zip(random_t.iter())
            .all(|((&commitment, &coeff), &random_t)| {
                commitment == self.public_params.g.mul(coeff) + self.public_params.h.mul(random_t)
            })
    }
}

mod tests {
    use crate::common::acss::pedersen::{PedersenPolyCommParams, PedersenPolyCommitment};
    use ark_bls12_381::Fr;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::DenseUVPolynomial;
    use ark_std::UniformRand;
    use std::ops::Add;

    #[test]
    fn commitment_verifies_with_correct_coeffs() {
        let mut rng = ark_std::test_rng();
        let g = ark_bls12_381::G1Projective::rand(&mut rng);
        let h = ark_bls12_381::G1Projective::rand(&mut rng);
        let public_params = PedersenPolyCommParams::new(g, h);
        let polynomial = DensePolynomial::rand(100, &mut rng);
        let (commitment, random_t) =
            PedersenPolyCommitment::commit(public_params, &polynomial.coeffs, &mut rng);
        assert!(commitment.verify(&polynomial.coeffs, &random_t))
    }

    #[test]
    fn commitment_does_not_verify_with_wrong_coeffs() {
        let mut rng = ark_std::test_rng();
        let g = ark_bls12_381::G1Projective::rand(&mut rng);
        let h = ark_bls12_381::G1Projective::rand(&mut rng);
        let public_params = PedersenPolyCommParams::new(g, h);
        let polynomial = DensePolynomial::rand(100, &mut rng);
        let (commitment, random_t) =
            PedersenPolyCommitment::commit(public_params, &polynomial.coeffs, &mut rng);
        let modified_coeffs: Vec<Fr> = polynomial
            .coeffs
            .iter()
            .map(|coeff| coeff.add(&ark_bls12_381::Fr::from(1)))
            .collect();
        assert!(!commitment.verify(&modified_coeffs, &random_t))
    }
}
