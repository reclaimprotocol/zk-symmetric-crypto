//! 256-bit field arithmetic emulated over M31.
//!
//! Uses 20 limbs of 13 bits each (260 bits total, covering 256-bit fields).
//! Column sum max = 20 × 2^26 = 1.34B < M31 (2.15B)

pub mod constraints;
pub mod gen;

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Sub};

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::FieldExpOps;

/// Number of bits per limb (13 bits).
pub const LIMB_BITS: u32 = 13;

/// Number of limbs (20 limbs × 13 bits = 260 bits).
pub const N_LIMBS: usize = 20;

/// Mask for extracting LIMB_BITS bits.
pub const LIMB_MASK: u32 = (1 << LIMB_BITS) - 1;

/// 2^LIMB_BITS
pub const TWO_POW_LIMB: u32 = 1 << LIMB_BITS;

/// BN254 scalar field modulus in 13-bit limbs (little-endian).
pub const MODULUS: [u32; N_LIMBS] = [
    0x0001, 0x0000, 0x04FC, 0x03EB, 0x143E, 0x1848, 0x06E5, 0x090F, 0x13E8, 0x0941,
    0x1617, 0x0302, 0x1B68, 0x0822, 0x06E1, 0x1405, 0x0131, 0x1397, 0x1913, 0x0060,
];

/// Baby Jubjub scalar order in 13-bit limbs (little-endian).
pub const SCALAR_ORDER: [u32; N_LIMBS] = [
    0x06F1, 0x0909, 0x170E, 0x052F, 0x0677, 0x1705, 0x0483, 0x1707, 0x1EED, 0x1D59,
    0x0AC2, 0x0060, 0x0B6D, 0x0504, 0x14DC, 0x0680, 0x1C26, 0x0E72, 0x0322, 0x000C,
];

/// 256-bit field element as 20 × 13-bit limbs.
#[derive(Clone, Debug)]
pub struct Field256<F>
where
    F: FieldExpOps + Clone + Debug + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    pub limbs: [F; N_LIMBS],
}

impl<F> Field256<F>
where
    F: FieldExpOps + Clone + Debug + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    pub fn new(limbs: [F; N_LIMBS]) -> Self {
        Self { limbs }
    }

    pub fn zero() -> Self
    where
        F: From<BaseField>,
    {
        Self {
            limbs: std::array::from_fn(|_| F::from(BaseField::from_u32_unchecked(0))),
        }
    }

    pub fn one() -> Self
    where
        F: From<BaseField>,
    {
        let mut limbs: [F; N_LIMBS] = std::array::from_fn(|_| F::from(BaseField::from_u32_unchecked(0)));
        limbs[0] = F::from(BaseField::from_u32_unchecked(1));
        Self { limbs }
    }
}

/// Convert u256 (8 × 32-bit) to 20 × 13-bit limbs.
pub fn u256_to_limbs(value: &[u32; 8]) -> [u32; N_LIMBS] {
    let mut result = [0u32; N_LIMBS];
    let mut bit_pos = 0usize;
    let mut out_idx = 0usize;

    for i in 0..256 {
        if out_idx >= N_LIMBS { break; }
        let in_word = i / 32;
        let in_bit = i % 32;
        let bit = (value[in_word] >> in_bit) & 1;
        let out_bit = bit_pos % LIMB_BITS as usize;
        result[out_idx] |= bit << out_bit;
        bit_pos += 1;
        if bit_pos % LIMB_BITS as usize == 0 {
            out_idx += 1;
        }
    }
    result
}

/// Convert 20 × 13-bit limbs to u256 (8 × 32-bit).
pub fn limbs_to_u256(limbs: &[u32; N_LIMBS]) -> [u32; 8] {
    let mut result = [0u32; 8];
    let mut bit_pos = 0usize;

    for out_idx in 0..N_LIMBS {
        for bit in 0..LIMB_BITS as usize {
            let i = bit_pos + bit;
            if i >= 256 { break; }
            let b = (limbs[out_idx] >> bit) & 1;
            result[i / 32] |= b << (i % 32);
        }
        bit_pos += LIMB_BITS as usize;
    }
    result
}

/// Create a Field256 from 13-bit limbs array.
pub fn field256_from_limbs<F>(limbs: &[u32; N_LIMBS]) -> Field256<F>
where
    F: FieldExpOps + Clone + Debug + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F> + From<BaseField>,
{
    Field256::new(std::array::from_fn(|i| {
        F::from(BaseField::from_u32_unchecked(limbs[i]))
    }))
}
