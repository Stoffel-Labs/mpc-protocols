//! `gf2k/field.rs` names its parent module's error type; this is that module, reduced to the one
//! item the file needs: the two variants it constructs.

#[derive(Debug)]
pub enum Gf2kError {
    PolynomialOperationError(String),
    NoSuitableDomain(usize),
}

#[path = "../../../../mpc/src/common/gf2k/field.rs"]
pub mod field;
