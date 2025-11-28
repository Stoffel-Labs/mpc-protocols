use crate::common::types::TypeError;
use crate::common::SecretSharingScheme;
use ark_ff::{FftField, PrimeField};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Sub};
use std::sync::OnceLock;

static GLOBAL_FIXED_PRECISION: OnceLock<FixedPointPrecision> = OnceLock::new();

/// Returns the global precision, initializing with the default (32,16) if unset.
pub fn global_precision() -> &'static FixedPointPrecision {
    GLOBAL_FIXED_PRECISION.get_or_init(|| FixedPointPrecision::new(32, 16))
}

/// Allows the user to set a custom global precision **before** use.
/// Fails if already set or if `global_precision()` was already called.
pub fn try_init_global_precision(p: FixedPointPrecision) -> Result<(), &'static str> {
    GLOBAL_FIXED_PRECISION
        .set(p)
        .map_err(|_| "already initialized")
}

/// Parameters that decribe the precision of the fixed point representation.
#[derive(Copy, Debug, Clone, PartialEq)]
pub struct FixedPointPrecision {
    /// Total number of bits in the fixed point representation.
    k: usize,
    /// Number of bits spent in the fractional fragment.
    f: usize,
}

impl FixedPointPrecision {
    pub fn new(k: usize, f: usize) -> Self {
        assert!(f < k, "the number of bits in the fractional fragment must be less than the total number of bits for the representation");
        Self { k, f }
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn f(&self) -> usize {
        self.f
    }
}

/// Represents a fixed-point number shared among the parties.
///
/// The fields of this struct are private to prevent erroneous mutation of the precision and the
/// share. The share and the bit size must be consistent in that the integer representation must
/// fit into the field to guarantee correctness.
#[derive(Copy, Debug, Clone, PartialEq)]
pub struct SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    /// The secret share used to represent the fixed point number.
    value: S,
    /// Precision of this fixed point number.
    precision: FixedPointPrecision,
    _field_type: PhantomData<F>,
}

impl<F, S> SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    /// Creates a new secret fixed point number.
    ///
    /// When we crate a new fixed point value, we must check that the created element fits into the
    /// field.
    pub fn new(value: S) -> Self {
        Self {
            value,
            precision: *global_precision(),
            _field_type: PhantomData,
        }
    }
    pub fn new_with_precision(value: S, precision: FixedPointPrecision) -> Self {
        assert!(
            (precision.k as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the precision does not fit into the field"
        );

        match GLOBAL_FIXED_PRECISION.get() {
            Some(global) => {
                assert_eq!(
                    *global, precision,
                    "provided precision does not match global precision"
                );
            }
            None => {
                let _ = try_init_global_precision(precision);
            }
        }

        Self {
            value,
            precision: *global_precision(),
            _field_type: PhantomData,
        }
    }

    pub fn value(&self) -> &S {
        &self.value
    }

    pub fn precision(&self) -> &FixedPointPrecision {
        &self.precision
    }
}

impl<F, S> Mul<ClearFixedPoint<F>> for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn mul(self, rhs: ClearFixedPoint<F>) -> Self::Output {
        // All fixed-point values must adhere to global precision
        let global = *global_precision();

        // Defensive check — if a rogue value has different precision, catch early
        if rhs.precision != global {
            return Err(TypeError::IncompatibleFixedPointPrecision {
                current: global,
                other: rhs.precision,
            });
        }

        // Multiplying two fixed-point values of k bits can produce up to 2k bits
        assert!(
            ((global.k * 2) as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the resulting precision of the operation does not fit into the field"
        );
        Ok(Self {
            value: (self.value * rhs.value)?,
            precision: global,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Add<ClearFixedPoint<F>> for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn add(self, rhs: ClearFixedPoint<F>) -> Self::Output {
        let global = *global_precision();

        if rhs.precision != global {
            return Err(TypeError::IncompatibleFixedPointPrecision {
                current: global,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value + rhs.value)?,
            precision: global,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Sub<ClearFixedPoint<F>> for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn sub(self, rhs: ClearFixedPoint<F>) -> Self::Output {
        let global = *global_precision();

        if rhs.precision != global {
            return Err(TypeError::IncompatibleFixedPointPrecision {
                current: global,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value - rhs.value)?,
            precision: global,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Add for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn add(self, rhs: Self) -> Self::Output {
        let global = *global_precision();

        // Defensive check — should never fail if all values respect global precision
        if self.precision != global || rhs.precision != global {
            return Err(TypeError::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }

        Ok(Self {
            value: (self.value + rhs.value)?,
            precision: global,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Sub for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn sub(self, rhs: Self) -> Self::Output {
        let global = *global_precision();

        if self.precision != global || rhs.precision != global {
            return Err(TypeError::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value - rhs.value)?,
            precision: global,
            _field_type: PhantomData,
        })
    }
}

/// Represents a public fixed-point number.
///
/// The fields of this struct are private to prevent erroneous mutation of the precision and the
/// share. The share and the bit size must be consistent in that the integer representation must
/// fit into the field to guarantee correctness.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ClearFixedPoint<F: FftField> {
    value: F,
    precision: FixedPointPrecision,
}

impl<F> ClearFixedPoint<F>
where
    F: FftField,
{
    /// Create using the current global precision.
    pub fn new(value: F) -> Self {
        let precision = *global_precision();
        assert!(
            (precision.k as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the precision does not fit into the field"
        );
        Self { value, precision }
    }

    /// Create with explicit precision, consistent with or initializing global precision.
    pub fn new_with_precision(value: F, precision: FixedPointPrecision) -> Self {
        assert!(
            (precision.k as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the precision does not fit into the field"
        );

        match GLOBAL_FIXED_PRECISION.get() {
            Some(global) => {
                assert_eq!(
                    *global, precision,
                    "provided precision does not match global precision"
                );
            }
            None => {
                let _ = try_init_global_precision(precision);
            }
        }

        Self { value, precision }
    }

    pub fn from_float(clear_value: f64) -> Self {
        let precision = *global_precision();
        let f = precision.f();

        let scaled_val = (clear_value * (1u128 << f) as f64).round();
        let scaled_field = F::from(scaled_val as u128);

        Self {
            value: scaled_field,
            precision,
        }
    }

    pub fn value(&self) -> &F {
        &self.value
    }

    pub fn precision(&self) -> &FixedPointPrecision {
        &self.precision
    }
}

impl<F> Add for ClearFixedPoint<F>
where
    F: FftField,
{
    type Output = Result<Self, TypeError>;
    fn add(self, rhs: Self) -> Self::Output {
        let global = *global_precision();
        if self.precision != global || rhs.precision != global {
            return Err(TypeError::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }

        Ok(Self {
            value: self.value + rhs.value,
            precision: global,
        })
    }
}

impl<F> Sub for ClearFixedPoint<F>
where
    F: FftField,
{
    type Output = Result<Self, TypeError>;
    fn sub(self, rhs: Self) -> Self::Output {
        let global = *global_precision();
        if self.precision != global || rhs.precision != global {
            return Err(TypeError::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }

        Ok(Self {
            value: self.value - rhs.value,
            precision: global,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use ark_bn254::Fr;
    use ark_std::test_rng;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup_precision() {
        INIT.call_once(|| {
            let _ = try_init_global_precision(FixedPointPrecision::new(16, 8));
        });
    }

    #[test]
    fn test_secret_fixed_point_new_from_share() {
        setup_precision();
        let mut rng = test_rng();
        let n_parties = 5;
        let t = 1;

        // 5.5 * 2^8 = 1408
        let shares =
            RobustShare::compute_shares(Fr::from(1408u64), n_parties, t, None, &mut rng).unwrap();
        let sfix = SecretFixedPoint::<Fr, RobustShare<Fr>>::new(shares[0].clone());
        assert_eq!(sfix.precision(), global_precision());
        assert_eq!(*sfix.value(), shares[0]);
    }

    #[test]
    fn test_secret_fixed_point_addition_across_parties() {
        setup_precision();
        let mut rng = test_rng();
        let n_parties = 5;
        let t = 1;

        // Represent x = 2.0 * 2^8 = 512, y = 3.25 * 2^8 = 832
        let x_shares =
            RobustShare::compute_shares(Fr::from(512u64), n_parties, t, None, &mut rng).unwrap();
        let y_shares =
            RobustShare::compute_shares(Fr::from(832u64), n_parties, t, None, &mut rng).unwrap();

        let sfix_x = SecretFixedPoint::new(x_shares[0].clone());
        let sfix_y = SecretFixedPoint::new(y_shares[0].clone());

        let sum = (sfix_x + sfix_y).unwrap();
        assert_eq!(sum.precision(), global_precision());

        // verify local addition result equals share addition
        let expected_share = (x_shares[0].clone() + y_shares[0].clone()).unwrap();
        assert_eq!(sum.value().clone(), expected_share);
    }

    #[test]
    fn test_secret_fixed_point_subtraction_across_parties() {
        setup_precision();
        let mut rng = test_rng();
        let n_parties = 5;
        let t = 1;

        // Represent x = 4.0 * 2^8 = 1024, y = 1.5 * 2^8 = 384
        let x_shares =
            RobustShare::compute_shares(Fr::from(1024u64), n_parties, t, None, &mut rng).unwrap();
        let y_shares =
            RobustShare::compute_shares(Fr::from(384u64), n_parties, t, None, &mut rng).unwrap();

        let sfix_x = SecretFixedPoint::new(x_shares[0].clone());
        let sfix_y = SecretFixedPoint::new(y_shares[0].clone());

        let diff = (sfix_x - sfix_y).unwrap();
        let expected_share = (x_shares[0].clone() - y_shares[0].clone()).unwrap();
        assert_eq!(diff.value(), &expected_share);
    }

    #[test]
    fn test_secret_fixed_point_with_clear_fixed_point() {
        setup_precision();
        let mut rng = test_rng();
        let n_parties = 5;
        let t = 1;

        // secret = 10.0 * 2^8 = 2560
        let shares =
            RobustShare::compute_shares(Fr::from(2560u64), n_parties, t, None, &mut rng).unwrap();
        let sfix = SecretFixedPoint::<Fr, RobustShare<Fr>>::new(shares[0].clone());
        let cfix = ClearFixedPoint::<Fr>::from_float(1.25); // 1.25 * 2^8 = 320

        // a + b
        let add_res = (sfix.clone() + cfix).unwrap();
        assert_eq!(add_res.precision(), global_precision());
        // a - b
        let sub_res = (sfix.clone() - cfix).unwrap();
        assert_eq!(sub_res.precision(), global_precision());
        // a * b
        let mul_res = (sfix * cfix).unwrap();
        assert_eq!(mul_res.precision(), global_precision());
    }

    #[test]
    fn test_clear_fixed_point_precision_mismatch_error() {
        setup_precision();
        let global = *global_precision();
        let other = FixedPointPrecision::new(global.k() + 2, global.f());

        // Construct both using global precision
        let a = ClearFixedPoint::<Fr>::new(Fr::from(10u64));
        let mut b = ClearFixedPoint::<Fr>::new(Fr::from(10u64));

        // Manually override precision to simulate mismatch
        b = ClearFixedPoint::<Fr> {
            value: *b.value(),
            precision: other,
        };

        let res = a + b;
        assert!(
            res.is_err(),
            "expected precision mismatch error, got success: {:?}",
            res
        );
    }

    #[test]
    fn test_clear_fixed_point_from_float_and_add_sub() {
        setup_precision();
        let a = ClearFixedPoint::<Fr>::from_float(1.5);
        let b = ClearFixedPoint::<Fr>::from_float(2.0);
        let sum = a + b;
        assert!(sum.is_ok());
        let sub = b - a;
        assert!(sub.is_ok());
    }

    #[test]
    fn test_precision_mismatch_error() {
        let mut rng = test_rng();
        let n_parties = 5;
        let t = 1;

        let precision = FixedPointPrecision::new(16, 8);
        let other_precision = FixedPointPrecision::new(24, 12);
        let _ = try_init_global_precision(precision);

        // secret = 2.5 * 2^8 = 640
        let shares =
            RobustShare::compute_shares(Fr::from(640u64), n_parties, t, None, &mut rng).unwrap();
        let sfix = SecretFixedPoint::<Fr, RobustShare<Fr>>::new_with_precision(
            shares[0].clone(),
            precision,
        );

        // mismatched clear value — construct using global precision, then manually set precision to other
        let mut cfix = ClearFixedPoint::<Fr>::new(Fr::from(100u64));
        cfix = ClearFixedPoint::<Fr> {
            value: *cfix.value(),
            precision: other_precision, // force mismatch
        };

        let res = sfix + cfix;
        assert!(
            res.is_err(),
            "expected precision mismatch error, got success: {:?}",
            res
        );
    }
}
