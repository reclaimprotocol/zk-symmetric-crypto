//! Baby Jubjub elliptic curve operations for TOPRF verification.
//!
//! This module implements 256-bit field emulation over M31 to enable
//! Baby Jubjub curve operations for Threshold Oblivious PRF (TOPRF).
//!
//! Baby Jubjub is a twisted Edwards curve over the BN254 scalar field:
//!   a*x² + y² = 1 + d*x²y²
//! where a = -1 (equivalently 168700) and d = 168696.

pub mod field256;
pub mod mimc_compat;
pub mod point;
pub mod toprf;

// Re-export commonly used types
pub use field256::{Field256, LIMB_BITS, MODULUS, N_LIMBS};
pub use point::{AffinePoint, ExtendedPoint};
