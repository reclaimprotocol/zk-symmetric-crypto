//! TOPRF Server-side implementation.
//!
//! Provides threshold OPRF operations for servers:
//! - DKG: Distributed Key Generation using Shamir's Secret Sharing
//! - Eval: OPRF evaluation on masked client points
//! - DLEQ: Discrete Log Equality proofs
//!
//! This complements the stwo circuit that verifies TOPRF proofs client-side.

pub mod dkg;
pub mod dleq;
pub mod eval;

#[cfg(test)]
mod e2e_test;

use crate::babyjub::field256::gen::BigInt256;
use crate::babyjub::point::ExtendedPointBigInt;

/// A threshold share of the TOPRF secret key.
#[derive(Clone, Debug)]
pub struct Share {
    /// Share index (1-indexed, used in Lagrange interpolation).
    pub index: usize,

    /// Private key share (scalar on BN254).
    pub private_key: BigInt256,

    /// Public key for this share (G * private_key).
    pub public_key: ExtendedPointBigInt,
}

/// Shared key structure for threshold TOPRF.
#[derive(Clone, Debug)]
pub struct SharedKey {
    /// Number of total nodes.
    pub nodes: usize,

    /// Threshold required for reconstruction.
    pub threshold: usize,

    /// Server public key (G * master_secret).
    pub server_public_key: ExtendedPointBigInt,

    /// Individual shares.
    pub shares: Vec<Share>,
}

/// OPRF response from a server.
#[derive(Clone, Debug)]
pub struct OPRFResponse {
    /// Evaluated point (request * private_key).
    pub evaluated_point: ExtendedPointBigInt,

    /// DLEQ challenge.
    pub c: BigInt256,

    /// DLEQ response.
    pub r: BigInt256,
}

/// TOPRF verification result (M31 output).
#[derive(Clone, Debug)]
pub struct TOPRFResult {
    /// Unmasked point (after deblinding).
    pub unmasked_point: ExtendedPointBigInt,

    /// Final hash output (as u32, M31 field element).
    pub output: u32,
}

/// TOPRF verification result with MiMC hash (gnark-compatible).
#[derive(Clone, Debug)]
pub struct TOPRFResultMiMC {
    /// Unmasked point (after deblinding).
    pub unmasked_point: ExtendedPointBigInt,

    /// Final MiMC hash output (256-bit, gnark-compatible).
    pub output: BigInt256,
}

// Re-export commonly used items
pub use dkg::{create_shares, generate_shared_key, lagrange_coefficient};
pub use dleq::{prove_dleq, prove_dleq_mimc, verify_dleq, verify_dleq_mimc};
pub use eval::{evaluate_oprf, evaluate_oprf_mimc, finalize_toprf, finalize_toprf_mimc, hash_to_point_mimc, threshold_mul};
