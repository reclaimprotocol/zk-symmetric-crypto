//! AIR for ChaCha20 stream cipher.
//! See https://datatracker.ietf.org/doc/html/rfc7539
//!
//! ChaCha20 quarter-round:
//!   a += b; d ^= a; d <<<= 16;
//!   c += d; b ^= c; b <<<= 12;
//!   a += b; d ^= a; d <<<= 8;
//!   c += d; b ^= c; b <<<= 7;

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Sub};
use std::simd::u32x16;

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::FieldExpOps;
use stwo::prover::backend::simd::m31::PackedBaseField;

pub mod bitwise;
pub mod block;
pub mod quarter_round;

/// ChaCha state is 16 x 32-bit words
pub const STATE_SIZE: usize = 16;

/// Number of field elements per u32 (we split into two 16-bit halves)
pub const N_FELTS_IN_U32: usize = 2;

/// ChaCha20 uses 20 rounds (10 double-rounds)
pub const N_ROUNDS: usize = 20;

/// Number of double-rounds
pub const N_DOUBLE_ROUNDS: usize = 10;

/// Number of field elements for round lookup (input state + output state)
pub const N_ROUND_INPUT_FELTS: usize = STATE_SIZE * N_FELTS_IN_U32 * 2;

/// Split a SIMD u32x16 into two PackedBaseField (low 16 bits, high 16 bits)
pub fn to_felts(x: &u32x16) -> [PackedBaseField; 2] {
    [
        unsafe { PackedBaseField::from_simd_unchecked(*x & u32x16::splat(0xffff)) },
        unsafe { PackedBaseField::from_simd_unchecked(*x >> 16) },
    ]
}

/// Utility for representing a u32 as two field elements (low 16 bits, high 16 bits).
/// This fits nicely in M31 field (2^31 - 1) since 16 bits << 31 bits.
#[derive(Clone, Debug)]
pub struct Fu32<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    /// Lower 16 bits
    pub l: F,
    /// Upper 16 bits
    pub h: F,
}

impl<F> Fu32<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    pub fn new(l: F, h: F) -> Self {
        Self { l, h }
    }

    pub fn into_felts(self) -> [F; 2] {
        [self.l, self.h]
    }
}

/// Split a native u32 into two 16-bit field elements
pub fn u32_to_felts(x: u32) -> [BaseField; 2] {
    [
        BaseField::from_u32_unchecked(x & 0xffff),
        BaseField::from_u32_unchecked(x >> 16),
    ]
}

/// ChaCha20 constants: "expand 32-byte k"
pub const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify the constants spell "expand 32-byte k" in little-endian
        let bytes: Vec<u8> = CONSTANTS
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        assert_eq!(&bytes, b"expand 32-byte k");
    }

    #[test]
    fn test_u32_to_felts() {
        let x = 0xAABBCCDDu32;
        let [l, h] = u32_to_felts(x);
        assert_eq!(l.0, 0xCCDD);
        assert_eq!(h.0, 0xAABB);
    }
}
