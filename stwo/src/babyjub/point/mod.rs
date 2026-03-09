//! Baby Jubjub elliptic curve point operations.
//!
//! Baby Jubjub is a twisted Edwards curve over the BN254 scalar field:
//!   a*x² + y² = 1 + d*x²y²
//!
//! Parameters:
//!   a = -1 (= 21888242871839275222246405745257275088548364400416034343698204186575808495616 in the field)
//!   d = 168696
//!
//! This module uses Extended Coordinates (X, Y, T, Z) where:
//!   x = X/Z, y = Y/Z, t = T/Z = x*y
//!
//! Extended coordinates avoid inversions in add/double operations.

pub mod constraints;
pub mod gen;

use super::field256::{gen::BigInt256, Field256, N_LIMBS};

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Sub};

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::FieldExpOps;

/// Baby Jubjub curve parameter a = -1 (as p - 1 in the field).
/// Stored as 29-bit limbs.
pub const CURVE_A: [u32; N_LIMBS] = [
    0x10000000, // limb 0
    0x1f0fac9f, // limb 1
    0x0e5c2450, // limb 2
    0x07d090f3, // limb 3
    0x1585d283, // limb 4
    0x02db40c0, // limb 5
    0x00a6e141, // limb 6
    0x0e5c2634, // limb 7
    0x0030644e, // limb 8
];

/// Baby Jubjub curve parameter d.
/// d = 12181644023421730124874158521699555681764249180949974110617291017600649128846
pub const CURVE_D: [u32; N_LIMBS] = [
    0x14d7eb8e, // limb 0
    0x03ae5467, // limb 1
    0x0df219f4, // limb 2
    0x1652b3d7, // limb 3
    0x111fc039, // limb 4
    0x196bccfe, // limb 5
    0x05a4f7c1, // limb 6
    0x1e2be431, // limb 7
    0x001aee90, // limb 8
];

/// Baby Jubjub base point X coordinate.
/// From gnark-crypto BN254 twisted edwards curve parameters.
/// G_x = 9671717474070082183213120605117400219616337014328744928644933853176787189663
pub const BASE_X: [u32; N_LIMBS] = [
    0x1e553f9f, // limb 0
    0x0fc8cad7, // limb 1
    0x1ca89dfc, // limb 2
    0x18e935cd, // limb 3
    0x1e94c377, // limb 4
    0x1bd260cc, // limb 5
    0x14d6293a, // limb 6
    0x106d9c33, // limb 7
    0x001561ff, // limb 8
];

/// Baby Jubjub base point Y coordinate.
/// G_y = 16950150798460657717958625567821834550301663161624707787222815936182638968203
pub const BASE_Y: [u32; N_LIMBS] = [
    0x072d7d8b, // limb 0
    0x19e12bd4, // limb 1
    0x184cddd2, // limb 2
    0x000a3f73, // limb 3
    0x1f9edfce, // limb 4
    0x170e68b5, // limb 5
    0x0924955c, // limb 6
    0x007ef416, // limb 7
    0x00257972, // limb 8
];

/// Identity point in extended coordinates: (0, 1, 0, 1).
pub const IDENTITY_X: [u32; N_LIMBS] = [0; N_LIMBS];
pub const IDENTITY_Y: [u32; N_LIMBS] = [1, 0, 0, 0, 0, 0, 0, 0, 0];
pub const IDENTITY_T: [u32; N_LIMBS] = [0; N_LIMBS];
pub const IDENTITY_Z: [u32; N_LIMBS] = [1, 0, 0, 0, 0, 0, 0, 0, 0];

/// A point in affine coordinates (x, y).
#[derive(Clone, Debug)]
pub struct AffinePoint<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    pub x: Field256<F>,
    pub y: Field256<F>,
}

/// A point in extended coordinates (X, Y, T, Z) where x = X/Z, y = Y/Z, T = X*Y/Z.
#[derive(Clone, Debug)]
pub struct ExtendedPoint<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    pub x: Field256<F>,
    pub y: Field256<F>,
    pub t: Field256<F>,
    pub z: Field256<F>,
}

impl<F> AffinePoint<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    /// Create a new affine point.
    pub fn new(x: Field256<F>, y: Field256<F>) -> Self {
        Self { x, y }
    }
}

impl<F> ExtendedPoint<F>
where
    F: FieldExpOps
        + Clone
        + Debug
        + AddAssign<F>
        + Add<F, Output = F>
        + Sub<F, Output = F>
        + Mul<BaseField, Output = F>,
{
    /// Create a new extended point.
    pub fn new(x: Field256<F>, y: Field256<F>, t: Field256<F>, z: Field256<F>) -> Self {
        Self { x, y, t, z }
    }
}

/// Native BigInt representation of an extended point for trace generation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExtendedPointBigInt {
    pub x: BigInt256,
    pub y: BigInt256,
    pub t: BigInt256,
    pub z: BigInt256,
}

impl ExtendedPointBigInt {
    /// Create a new extended point.
    pub fn new(x: BigInt256, y: BigInt256, t: BigInt256, z: BigInt256) -> Self {
        Self { x, y, t, z }
    }

    /// Create the identity point (0, 1, 0, 1).
    pub fn identity() -> Self {
        Self {
            x: BigInt256::zero(),
            y: BigInt256::one(),
            t: BigInt256::zero(),
            z: BigInt256::one(),
        }
    }

    /// Create from affine coordinates.
    pub fn from_affine(x: BigInt256, y: BigInt256, modulus: &BigInt256) -> Self {
        let t = x.mul_mod(&y, modulus);
        Self {
            x,
            y,
            t,
            z: BigInt256::one(),
        }
    }

    /// Convert to affine coordinates.
    /// Requires computing z^(-1).
    pub fn to_affine(&self, modulus: &BigInt256) -> (BigInt256, BigInt256) {
        if self.z.is_zero() || self.z == BigInt256::one() {
            return (self.x, self.y);
        }

        let z_inv = self.z.inv_mod(modulus).expect("Z should not be zero");
        let x = self.x.mul_mod(&z_inv, modulus);
        let y = self.y.mul_mod(&z_inv, modulus);
        (x, y)
    }

    // =========================================================================
    // Gnark-compatible serialization
    // =========================================================================

    /// Serialize to 64-byte gnark-compatible format.
    /// Format: X (32 bytes BE) || Y (32 bytes BE)
    /// This matches gnark-crypto's `twistededwards.PointAffine.Marshal()`.
    pub fn to_bytes_gnark(&self, modulus: &BigInt256) -> [u8; 64] {
        let (x, y) = self.to_affine(modulus);
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&x.to_bytes_be());
        bytes[32..].copy_from_slice(&y.to_bytes_be());
        bytes
    }

    /// Deserialize from 64-byte gnark-compatible format.
    /// Format: X (32 bytes BE) || Y (32 bytes BE)
    pub fn from_bytes_gnark(bytes: &[u8], modulus: &BigInt256) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        let x = BigInt256::from_bytes_be(&bytes[..32]);
        let y = BigInt256::from_bytes_be(&bytes[32..]);
        Some(Self::from_affine(x, y, modulus))
    }
}

/// Native BigInt representation of affine point.
#[derive(Clone, Copy, Debug, Default)]
pub struct AffinePointBigInt {
    pub x: BigInt256,
    pub y: BigInt256,
}

impl AffinePointBigInt {
    pub fn new(x: BigInt256, y: BigInt256) -> Self {
        Self { x, y }
    }
}

/// Get the curve parameter a as BigInt256.
pub fn curve_a() -> BigInt256 {
    BigInt256::from_limbs(CURVE_A)
}

/// Get the curve parameter d as BigInt256.
pub fn curve_d() -> BigInt256 {
    BigInt256::from_limbs(CURVE_D)
}

/// Get the base point in extended coordinates.
pub fn base_point() -> ExtendedPointBigInt {
    let x = BigInt256::from_limbs(BASE_X);
    let y = BigInt256::from_limbs(BASE_Y);
    let modulus = super::field256::gen::modulus();
    ExtendedPointBigInt::from_affine(x, y, &modulus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::field256::gen::modulus;

    #[test]
    fn test_identity_point() {
        let id = ExtendedPointBigInt::identity();
        assert_eq!(id.x, BigInt256::zero());
        assert_eq!(id.y, BigInt256::one());
        assert_eq!(id.t, BigInt256::zero());
        assert_eq!(id.z, BigInt256::one());
    }

    #[test]
    fn test_base_point() {
        let base = base_point();
        let modulus = modulus();

        // Verify base point is not identity
        assert!(!base.x.is_zero());

        // Convert to affine and back
        let (x, y) = base.to_affine(&modulus);
        let base2 = ExtendedPointBigInt::from_affine(x, y, &modulus);

        // Should have same affine coordinates
        let (x2, y2) = base2.to_affine(&modulus);
        assert_eq!(x, x2);
        assert_eq!(y, y2);
    }

    #[test]
    fn test_curve_params() {
        let a = curve_a();
        let d = curve_d();

        // d is a large number, just verify limb 0
        // d = 12181644023421730124874158521699555681764249180949974110617291017600649128846
        assert_eq!(d.limbs[0], 0x14d7eb8e);

        // a = p - 1 (a = -1 mod p)
        // So a + 1 should equal p
        let one = BigInt256::one();
        let p = modulus();
        let a_plus_1 = a.add_no_reduce(&one).0;
        assert_eq!(a_plus_1, p);
    }
}
