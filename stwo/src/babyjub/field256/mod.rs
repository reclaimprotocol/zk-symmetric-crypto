//! 256-bit field arithmetic emulated over M31.
//!
//! Uses 17 limbs of 16 bits each (272 bits total, covering 256-bit fields).
//! Each limb fits in u16 (max 65535), and product of two 16-bit values
//! is < 2^32, which fits safely in M31 (2^31 - 1) when accumulated carefully.
//!
//! This design enables verified multiplication: we can constrain a*b = q*p + r
//! because sub-products (16-bit * 16-bit = 32-bit) stay within M31 bounds.

pub mod constraints;
pub mod gen;

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Sub};

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::FieldExpOps;

/// Number of bits per limb.
/// Using 16 bits ensures sub-products fit in M31 for verified multiplication.
pub const LIMB_BITS: u32 = 16;

/// Number of limbs for 256-bit representation.
/// 17 * 16 = 272 bits, covering 256-bit field elements.
pub const N_LIMBS: usize = 17;

/// Mask for extracting LIMB_BITS bits.
pub const LIMB_MASK: u32 = (1 << LIMB_BITS) - 1;

/// 2^LIMB_BITS as a field constant for carry extraction.
pub const TWO_POW_LIMB: u32 = 1 << LIMB_BITS;

/// BN254 scalar field modulus (used as Baby Jubjub base field).
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
///
/// In 16-bit limbs (little-endian):
/// Computed as: r = sum(MODULUS[i] * 2^(16*i) for i in 0..17)
pub const MODULUS: [u32; N_LIMBS] = [
    0x0001, // limb 0:  bits 0-15
    0xf000, // limb 1:  bits 16-31
    0xf593, // limb 2:  bits 32-47
    0x43e1, // limb 3:  bits 48-63
    0x7091, // limb 4:  bits 64-79
    0x79b9, // limb 5:  bits 80-95
    0xe848, // limb 6:  bits 96-111
    0x2833, // limb 7:  bits 112-127
    0x585d, // limb 8:  bits 128-143
    0x8181, // limb 9:  bits 144-159
    0x45b6, // limb 10: bits 160-175
    0xb850, // limb 11: bits 176-191
    0xa029, // limb 12: bits 192-207
    0xe131, // limb 13: bits 208-223
    0x4e72, // limb 14: bits 224-239
    0x3064, // limb 15: bits 240-255
    0x0000, // limb 16: bits 256-271 (overflow)
];

/// Baby Jubjub prime subgroup order (used for scalar multiplication).
/// ℓ = 2736030358979909402780800718157159386076813972158567259200215660948447373041
///
/// This is the order of the generator point G in the prime-order subgroup.
/// The full curve has order 8 * ℓ (cofactor 8).
///
/// In 16-bit limbs (little-endian):
pub const SCALAR_ORDER: [u32; N_LIMBS] = [
    0x26f1, // limb 0
    0x3921, // limb 1
    0x97dc, // limb 2
    0x6772, // limb 3
    0xee0a, // limb 4
    0x3920, // limb 5
    0xedb8, // limb 6
    0xab3e, // limb 7
    0x2b0b, // limb 8
    0xd030, // limb 9
    0x08b6, // limb 10
    0x370a, // limb 11
    0x3405, // limb 12
    0x5c26, // limb 13
    0x89ce, // limb 14
    0x060c, // limb 15
    0x0000, // limb 16
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
/// to 16-bit limbs for Field256.
pub fn u256_to_limbs16(value: &[u32; 8]) -> [u32; N_LIMBS] {
    let mut result = [0u32; N_LIMBS];

    // Each 32-bit word gives us 2 x 16-bit limbs
    for i in 0..8 {
        result[2 * i] = value[i] & LIMB_MASK;
        result[2 * i + 1] = (value[i] >> 16) & LIMB_MASK;
    }
    // Limb 16 is always 0 for 256-bit values
    result[16] = 0;

    result
}

/// Convert 16-bit limbs back to 32-bit limbs (little-endian).
pub fn limbs16_to_u256(limbs: &[u32; N_LIMBS]) -> [u32; 8] {
    let mut result = [0u32; 8];

    // Combine pairs of 16-bit limbs into 32-bit words
    for i in 0..8 {
        result[i] = limbs[2 * i] | (limbs[2 * i + 1] << 16);
    }

    result
}

// Legacy aliases for compatibility during transition
#[inline]
pub fn u256_to_limbs29(value: &[u32; 8]) -> [u32; N_LIMBS] {
    u256_to_limbs16(value)
}

#[inline]
pub fn limbs29_to_u256(limbs: &[u32; N_LIMBS]) -> [u32; 8] {
    limbs16_to_u256(limbs)
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

        let limbs16 = u256_to_limbs16(&original);
        let recovered = limbs16_to_u256(&limbs16);

        assert_eq!(original, recovered, "Round-trip conversion failed");
    }

    #[test]
    fn test_modulus_size() {
        // Verify each limb fits in 16 bits
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
        let limbs16 = u256_to_limbs16(&zero);
        assert_eq!(limbs16, [0u32; N_LIMBS]);
    }

    #[test]
    fn test_one_conversion() {
        let one: [u32; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
        let limbs16 = u256_to_limbs16(&one);
        assert_eq!(limbs16[0], 1);
        for i in 1..N_LIMBS {
            assert_eq!(limbs16[i], 0);
        }
    }

    #[test]
    fn test_max_limb_value() {
        // Test a value that fills all 16 bits of the first limb
        let val: [u32; 8] = [0xFFFF, 0, 0, 0, 0, 0, 0, 0];
        let limbs16 = u256_to_limbs16(&val);
        assert_eq!(limbs16[0], 0xFFFF);
        assert_eq!(limbs16[1], 0);
    }

    #[test]
    fn test_limb16_structure() {
        // Test that 32-bit words are split correctly into 16-bit limbs
        let val: [u32; 8] = [0xABCD1234, 0, 0, 0, 0, 0, 0, 0];
        let limbs16 = u256_to_limbs16(&val);
        assert_eq!(limbs16[0], 0x1234, "Low 16 bits");
        assert_eq!(limbs16[1], 0xABCD, "High 16 bits");
    }

    #[test]
    fn test_modulus_value() {
        // Reconstruct modulus from 16-bit limbs and verify
        let p = limbs16_to_u256(&MODULUS);
        // First word of BN254 modulus is 0xf0000001
        assert_eq!(p[0], 0xf0000001);
    }
}
