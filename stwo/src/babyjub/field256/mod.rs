//! 256-bit field arithmetic emulated over M31.
//!
//! Uses 9 limbs of 29 bits each (261 bits total, covering 254-bit BN254 scalar field).
//! Each limb fits comfortably in M31 (2^31 - 1), and product of two 29-bit values
//! is < 2^62, safe for intermediate computations.

pub mod constraints;
pub mod gen;

#[cfg(test)]
mod underconstraint_test;

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Sub};

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::FieldExpOps;

/// Number of bits per limb.
pub const LIMB_BITS: u32 = 29;

/// Number of limbs for 256-bit representation.
pub const N_LIMBS: usize = 9;

/// Mask for extracting LIMB_BITS bits.
pub const LIMB_MASK: u32 = (1 << LIMB_BITS) - 1;

/// 2^LIMB_BITS as a field constant for carry extraction.
pub const TWO_POW_LIMB: u32 = 1 << LIMB_BITS;

/// BN254 scalar field modulus (used as Baby Jubjub base field).
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
///
/// In 29-bit limbs (little-endian):
/// Computed as: r = sum(MODULUS[i] * 2^(29*i) for i in 0..9)
pub const MODULUS: [u32; N_LIMBS] = [
    0x10000001, // limb 0
    0x1f0fac9f, // limb 1
    0x0e5c2450, // limb 2
    0x07d090f3, // limb 3
    0x1585d283, // limb 4
    0x02db40c0, // limb 5
    0x00a6e141, // limb 6
    0x0e5c2634, // limb 7
    0x0030644e, // limb 8
];

/// Baby Jubjub prime subgroup order (used for scalar multiplication).
/// ℓ = 2736030358979909402780800718157159386076813972158567259200215660948447373041
///
/// This is the order of the generator point G in the prime-order subgroup.
/// The full curve has order 8 * ℓ (cofactor 8).
///
/// In 29-bit limbs (little-endian):
pub const SCALAR_ORDER: [u32; N_LIMBS] = [
    0x192126f1, // limb 0
    0x1b94bee1, // limb 1
    0x083b8299, // limb 2
    0x1ddb7072, // limb 3
    0x02b0bab3, // limb 4
    0x045b6818, // limb 5
    0x1014dc28, // limb 6
    0x19cb84c6, // limb 7
    0x00060c89, // limb 8
];


/// 256-bit field element represented as 9 x 29-bit limbs.
/// Little-endian: limbs[0] contains the least significant bits.
#[derive(Clone, Debug)]
pub struct Field256<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    /// Limbs in little-endian order (limbs[0] is LSB).
    pub limbs: [F; N_LIMBS],
}

impl<F> Field256<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    /// Create a new Field256 from limbs.
    pub fn new(limbs: [F; N_LIMBS]) -> Self {
        Self { limbs }
    }

    /// Create a zero field element.
    pub fn zero() -> Self
    where
        F: From<BaseField>,
    {
        Self {
            limbs: std::array::from_fn(|_| F::from(BaseField::from_u32_unchecked(0))),
        }
    }

    /// Create a field element representing 1.
    pub fn one() -> Self
    where
        F: From<BaseField>,
    {
        let mut limbs: [F; N_LIMBS] =
            std::array::from_fn(|_| F::from(BaseField::from_u32_unchecked(0)));
        limbs[0] = F::from(BaseField::from_u32_unchecked(1));
        Self { limbs }
    }
}

/// Convert a u32 array (representing a 256-bit number in 32-bit limbs, little-endian)
/// to 29-bit limbs for Field256.
pub fn u256_to_limbs29(value: &[u32; 8]) -> [u32; N_LIMBS] {
    // Combine all bits into a single computation
    // value[i] contains bits [32*i, 32*(i+1))
    // We need to extract 29-bit chunks

    let mut result = [0u32; N_LIMBS];

    // Use u64 for intermediate calculations to avoid overflow
    let mut bit_buffer: u64 = 0;
    let mut buffer_bits: u32 = 0;
    let mut input_idx = 0;
    let mut output_idx = 0;

    while output_idx < N_LIMBS {
        // Fill buffer if we need more bits
        while buffer_bits < LIMB_BITS && input_idx < 8 {
            bit_buffer |= (value[input_idx] as u64) << buffer_bits;
            buffer_bits += 32;
            input_idx += 1;
        }

        // Extract 29-bit limb
        result[output_idx] = (bit_buffer as u32) & LIMB_MASK;
        bit_buffer >>= LIMB_BITS;
        buffer_bits = buffer_bits.saturating_sub(LIMB_BITS);
        output_idx += 1;
    }

    result
}

/// Convert 29-bit limbs back to 32-bit limbs (little-endian).
pub fn limbs29_to_u256(limbs: &[u32; N_LIMBS]) -> [u32; 8] {
    let mut result = [0u32; 8];

    let mut bit_buffer: u64 = 0;
    let mut buffer_bits: u32 = 0;
    let mut input_idx = 0;
    let mut output_idx = 0;

    while output_idx < 8 {
        // Fill buffer if we need more bits
        while buffer_bits < 32 && input_idx < N_LIMBS {
            bit_buffer |= (limbs[input_idx] as u64) << buffer_bits;
            buffer_bits += LIMB_BITS;
            input_idx += 1;
        }

        // Extract 32-bit word
        result[output_idx] = bit_buffer as u32;
        bit_buffer >>= 32;
        buffer_bits = buffer_bits.saturating_sub(32);
        output_idx += 1;
    }

    result
}

/// Create Field256 constant from 29-bit limb array.
pub fn field256_from_limbs29<F>(limbs: &[u32; N_LIMBS]) -> Field256<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>
        + From<BaseField>,
{
    Field256 {
        limbs: std::array::from_fn(|i| F::from(BaseField::from_u32_unchecked(limbs[i]))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_limb_conversion_roundtrip() {
        let original: [u32; 8] = [
            0x12345678, 0x9abcdef0, 0x11223344, 0x55667788, 0xaabbccdd, 0xeeff0011, 0x22334455,
            0x00667788,
        ];

        let limbs29 = u256_to_limbs29(&original);
        let recovered = limbs29_to_u256(&limbs29);

        assert_eq!(original, recovered, "Round-trip conversion failed");
    }

    #[test]
    fn test_modulus_size() {
        // Verify each limb fits in 29 bits
        for (i, &limb) in MODULUS.iter().enumerate() {
            assert!(
                limb < (1 << LIMB_BITS),
                "Limb {} = {} exceeds {} bits",
                i,
                limb,
                LIMB_BITS
            );
        }
    }

    #[test]
    fn test_zero_conversion() {
        let zero: [u32; 8] = [0; 8];
        let limbs29 = u256_to_limbs29(&zero);
        assert_eq!(limbs29, [0u32; N_LIMBS]);
    }

    #[test]
    fn test_one_conversion() {
        let one: [u32; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
        let limbs29 = u256_to_limbs29(&one);
        assert_eq!(limbs29[0], 1);
        for i in 1..N_LIMBS {
            assert_eq!(limbs29[i], 0);
        }
    }

    #[test]
    fn test_max_limb_value() {
        // Test a value that fills all 29 bits of the first limb
        let val: [u32; 8] = [0x1FFFFFFF, 0, 0, 0, 0, 0, 0, 0];
        let limbs29 = u256_to_limbs29(&val);
        assert_eq!(limbs29[0], 0x1FFFFFFF);
        assert_eq!(limbs29[1], 0);
    }
}
