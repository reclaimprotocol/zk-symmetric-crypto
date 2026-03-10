//! TOPRF (Threshold Oblivious PRF) verification component.
//!
//! Implements the verification logic for TOPRF proofs, including:
//! - DLEQ (Discrete Log Equality) verification
//! - Hash-to-point computation
//! - Response combination with Lagrange coefficients
//! - Final output hash computation

pub mod air;
pub mod constraints;
pub mod gen;

#[cfg(test)]
mod integration_test;

#[cfg(test)]
mod gnark_compat_test;

use crate::babyjub::field256::gen::BigInt256;
pub use crate::babyjub::point::AffinePointBigInt;

/// Threshold for TOPRF (number of required shares).
pub const THRESHOLD: usize = 1;

/// Bytes per field element for secret data (31 bytes = 248 bits).
pub const BYTES_PER_ELEMENT: usize = 31;

/// TOPRF public inputs.
#[derive(Clone, Debug)]
pub struct TOPRFPublicInputs {
    /// Domain separator for hash-to-point.
    pub domain_separator: BigInt256,

    /// Server responses (one per threshold share).
    pub responses: [AffinePointBigInt; THRESHOLD],

    /// Lagrange coefficients for combining responses.
    pub coefficients: [BigInt256; THRESHOLD],

    /// Public keys for each share.
    pub share_public_keys: [AffinePointBigInt; THRESHOLD],

    /// DLEQ challenge values.
    pub c: [BigInt256; THRESHOLD],

    /// DLEQ response values.
    pub r: [BigInt256; THRESHOLD],

    /// Expected output hash (MiMC hash output, gnark-compatible).
    pub output: BigInt256,
}

/// TOPRF private inputs.
#[derive(Clone, Debug)]
pub struct TOPRFPrivateInputs {
    /// Blinding mask for the data point.
    pub mask: BigInt256,

    /// Secret data extracted from plaintext (two 248-bit field elements).
    pub secret_data: [BigInt256; 2],
}

/// Full TOPRF verification inputs.
#[derive(Clone, Debug)]
pub struct TOPRFInputs {
    pub public: TOPRFPublicInputs,
    pub private: TOPRFPrivateInputs,
}

impl Default for TOPRFPublicInputs {
    fn default() -> Self {
        Self {
            domain_separator: BigInt256::zero(),
            responses: [AffinePointBigInt::default(); THRESHOLD],
            coefficients: [BigInt256::zero(); THRESHOLD],
            share_public_keys: [AffinePointBigInt::default(); THRESHOLD],
            c: [BigInt256::zero(); THRESHOLD],
            r: [BigInt256::zero(); THRESHOLD],
            output: BigInt256::zero(),
        }
    }
}

impl Default for TOPRFPrivateInputs {
    fn default() -> Self {
        Self {
            mask: BigInt256::one(),
            secret_data: [BigInt256::zero(); 2],
        }
    }
}

impl Default for TOPRFInputs {
    fn default() -> Self {
        Self {
            public: TOPRFPublicInputs::default(),
            private: TOPRFPrivateInputs::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_inputs() {
        let inputs = TOPRFInputs::default();
        assert!(!inputs.private.mask.is_zero());
    }
}
