//! Trace generation for Baby Jubjub point operations.

use super::{curve_d, ExtendedPointBigInt};
use crate::babyjub::field256::gen::{modulus, BigInt256, Field256TraceGen};

/// Trace generator for point operations.
pub struct PointTraceGen {
    pub field_gen: Field256TraceGen,
}

impl PointTraceGen {
    /// Create new trace generator.
    pub fn new() -> Self {
        Self {
            field_gen: Field256TraceGen::new(),
        }
    }

    /// Append an extended point to trace.
    pub fn append_extended_point(&mut self, p: &ExtendedPointBigInt) {
        self.field_gen.append_field256(&p.x);
        self.field_gen.append_field256(&p.y);
        self.field_gen.append_field256(&p.t);
        self.field_gen.append_field256(&p.z);
    }

    /// Point addition in extended coordinates.
    pub fn add_points(
        &mut self,
        p1: &ExtendedPointBigInt,
        p2: &ExtendedPointBigInt,
    ) -> ExtendedPointBigInt {
        let d = curve_d();

        // A = X1 * X2
        let a = self.field_gen.gen_mul(&p1.x, &p2.x);

        // B = Y1 * Y2
        let b = self.field_gen.gen_mul(&p1.y, &p2.y);

        // C = T1 * d * T2
        let t1_t2 = self.field_gen.gen_mul(&p1.t, &p2.t);
        let c = self.field_gen.gen_mul(&t1_t2, &d);

        // D = Z1 * Z2
        let d_val = self.field_gen.gen_mul(&p1.z, &p2.z);

        // E = (X1 + Y1) * (X2 + Y2) - A - B
        let x1_plus_y1 = self.field_gen.gen_add(&p1.x, &p1.y);
        let x2_plus_y2 = self.field_gen.gen_add(&p2.x, &p2.y);
        let sum_prod = self.field_gen.gen_mul(&x1_plus_y1, &x2_plus_y2);
        let e_tmp = self.field_gen.gen_sub(&sum_prod, &a);
        let e = self.field_gen.gen_sub(&e_tmp, &b);

        // F = D - C
        let f = self.field_gen.gen_sub(&d_val, &c);

        // G = D + C
        let g = self.field_gen.gen_add(&d_val, &c);

        // H = B + A (since a = -1)
        let h = self.field_gen.gen_add(&b, &a);

        // X3 = E * F
        let x3 = self.field_gen.gen_mul(&e, &f);

        // Y3 = G * H
        let y3 = self.field_gen.gen_mul(&g, &h);

        // T3 = E * H
        let t3 = self.field_gen.gen_mul(&e, &h);

        // Z3 = F * G
        let z3 = self.field_gen.gen_mul(&f, &g);

        ExtendedPointBigInt::new(x3, y3, t3, z3)
    }

    /// Point doubling in extended coordinates.
    pub fn double_point(&mut self, p: &ExtendedPointBigInt) -> ExtendedPointBigInt {
        let modulus = modulus();

        // A = X1²
        let a = self.field_gen.gen_mul(&p.x, &p.x);

        // B = Y1²
        let b = self.field_gen.gen_mul(&p.y, &p.y);

        // C = 2 * Z1²
        let z_sq = self.field_gen.gen_mul(&p.z, &p.z);
        let c = self.field_gen.gen_add(&z_sq, &z_sq);

        // D = -A (since a = -1)
        let d = BigInt256::zero().sub_mod(&a, &modulus);
        // Generate trace for the subtraction
        self.field_gen.gen_sub(&BigInt256::zero(), &a);

        // E = (X1 + Y1)² - A - B
        let x_plus_y = self.field_gen.gen_add(&p.x, &p.y);
        let sum_sq = self.field_gen.gen_mul(&x_plus_y, &x_plus_y);
        let e_tmp = self.field_gen.gen_sub(&sum_sq, &a);
        let e = self.field_gen.gen_sub(&e_tmp, &b);

        // G = D + B
        let g = self.field_gen.gen_add(&d, &b);

        // F = G - C
        let f = self.field_gen.gen_sub(&g, &c);

        // H = D - B
        let h = self.field_gen.gen_sub(&d, &b);

        // X3 = E * F
        let x3 = self.field_gen.gen_mul(&e, &f);

        // Y3 = G * H
        let y3 = self.field_gen.gen_mul(&g, &h);

        // T3 = E * H
        let t3 = self.field_gen.gen_mul(&e, &h);

        // Z3 = F * G
        let z3 = self.field_gen.gen_mul(&f, &g);

        ExtendedPointBigInt::new(x3, y3, t3, z3)
    }

    /// Scalar multiplication using double-and-add.
    pub fn scalar_mul(
        &mut self,
        p: &ExtendedPointBigInt,
        scalar: &BigInt256,
    ) -> ExtendedPointBigInt {
        // Extract 254 bits from scalar
        let bits = scalar_to_bits(scalar);

        // Start with identity
        let identity = ExtendedPointBigInt::identity();
        self.append_extended_point(&identity);

        let mut result = identity;

        // Process bits from MSB to LSB
        for i in (0..254).rev() {
            // Double
            result = self.double_point(&result);

            // Conditional add
            let sum = self.add_points(&result, p);

            // Select based on bit
            if bits[i] {
                result = sum;
            }
            // Generate select trace
            self.gen_select_point(bits[i] as u32, &result, &sum);
        }

        result
    }

    /// Generate trace for point selection.
    pub fn gen_select_point(
        &mut self,
        cond: u32,
        p0: &ExtendedPointBigInt,
        p1: &ExtendedPointBigInt,
    ) -> ExtendedPointBigInt {
        let result = if cond == 0 { *p0 } else { *p1 };

        self.field_gen.gen_select(cond, &p0.x, &p1.x);
        self.field_gen.gen_select(cond, &p0.y, &p1.y);
        self.field_gen.gen_select(cond, &p0.t, &p1.t);
        self.field_gen.gen_select(cond, &p0.z, &p1.z);

        result
    }

    /// Clear cofactor (multiply by 8).
    pub fn clear_cofactor(&mut self, p: &ExtendedPointBigInt) -> ExtendedPointBigInt {
        let p2 = self.double_point(p);
        let p4 = self.double_point(&p2);
        let p8 = self.double_point(&p4);
        p8
    }

    /// Generate trace for inverse check (assert nonzero).
    pub fn gen_assert_nonzero(&mut self, val: &BigInt256) {
        let _inv = self.field_gen.gen_inv(val);
    }

    /// Convert to affine coordinates.
    pub fn to_affine(&mut self, p: &ExtendedPointBigInt) -> (BigInt256, BigInt256) {
        // z_inv = z^(-1)
        let z_inv = self.field_gen.gen_inv(&p.z);

        // x = X * z_inv
        let x = self.field_gen.gen_mul(&p.x, &z_inv);

        // y = Y * z_inv
        let y = self.field_gen.gen_mul(&p.y, &z_inv);

        (x, y)
    }
}

impl Default for PointTraceGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract 254 bits from a scalar (little-endian).
pub fn scalar_to_bits(scalar: &BigInt256) -> [bool; 254] {
    let u256 = scalar.to_u256();
    let mut bits = [false; 254];

    for i in 0..254 {
        let word_idx = i / 32;
        let bit_idx = i % 32;
        bits[i] = ((u256[word_idx] >> bit_idx) & 1) == 1;
    }

    bits
}

/// Convert bits to scalar.
pub fn bits_to_scalar(bits: &[bool; 254]) -> BigInt256 {
    let mut u256 = [0u32; 8];

    for i in 0..254 {
        if bits[i] {
            let word_idx = i / 32;
            let bit_idx = i % 32;
            u256[word_idx] |= 1 << bit_idx;
        }
    }

    BigInt256::from_u256(&u256)
}

/// Native point operations without trace generation (for testing).
pub mod native {
    use super::*;

    /// Add two points (no trace).
    pub fn add_points(
        p1: &ExtendedPointBigInt,
        p2: &ExtendedPointBigInt,
    ) -> ExtendedPointBigInt {
        let modulus = modulus();
        let d = curve_d();

        // A = X1 * X2
        let a = p1.x.mul_mod(&p2.x, &modulus);

        // B = Y1 * Y2
        let b = p1.y.mul_mod(&p2.y, &modulus);

        // C = T1 * d * T2
        let t1_t2 = p1.t.mul_mod(&p2.t, &modulus);
        let c = t1_t2.mul_mod(&d, &modulus);

        // D = Z1 * Z2
        let d_val = p1.z.mul_mod(&p2.z, &modulus);

        // E = (X1 + Y1) * (X2 + Y2) - A - B
        let x1_plus_y1 = p1.x.add_mod(&p1.y, &modulus);
        let x2_plus_y2 = p2.x.add_mod(&p2.y, &modulus);
        let sum_prod = x1_plus_y1.mul_mod(&x2_plus_y2, &modulus);
        let e = sum_prod.sub_mod(&a, &modulus).sub_mod(&b, &modulus);

        // F = D - C
        let f = d_val.sub_mod(&c, &modulus);

        // G = D + C
        let g = d_val.add_mod(&c, &modulus);

        // H = B + A (since a = -1)
        let h = b.add_mod(&a, &modulus);

        // X3 = E * F
        let x3 = e.mul_mod(&f, &modulus);

        // Y3 = G * H
        let y3 = g.mul_mod(&h, &modulus);

        // T3 = E * H
        let t3 = e.mul_mod(&h, &modulus);

        // Z3 = F * G
        let z3 = f.mul_mod(&g, &modulus);

        ExtendedPointBigInt::new(x3, y3, t3, z3)
    }

    /// Double a point (no trace).
    pub fn double_point(p: &ExtendedPointBigInt) -> ExtendedPointBigInt {
        let modulus = modulus();

        // A = X1²
        let a = p.x.mul_mod(&p.x, &modulus);

        // B = Y1²
        let b = p.y.mul_mod(&p.y, &modulus);

        // C = 2 * Z1²
        let z_sq = p.z.mul_mod(&p.z, &modulus);
        let c = z_sq.add_mod(&z_sq, &modulus);

        // D = -A
        let d = BigInt256::zero().sub_mod(&a, &modulus);

        // E = (X1 + Y1)² - A - B
        let x_plus_y = p.x.add_mod(&p.y, &modulus);
        let sum_sq = x_plus_y.mul_mod(&x_plus_y, &modulus);
        let e = sum_sq.sub_mod(&a, &modulus).sub_mod(&b, &modulus);

        // G = D + B
        let g = d.add_mod(&b, &modulus);

        // F = G - C
        let f = g.sub_mod(&c, &modulus);

        // H = D - B
        let h = d.sub_mod(&b, &modulus);

        // X3 = E * F
        let x3 = e.mul_mod(&f, &modulus);

        // Y3 = G * H
        let y3 = g.mul_mod(&h, &modulus);

        // T3 = E * H
        let t3 = e.mul_mod(&h, &modulus);

        // Z3 = F * G
        let z3 = f.mul_mod(&g, &modulus);

        ExtendedPointBigInt::new(x3, y3, t3, z3)
    }

    /// Scalar multiplication (no trace).
    pub fn scalar_mul(p: &ExtendedPointBigInt, scalar: &BigInt256) -> ExtendedPointBigInt {
        let bits = scalar_to_bits(scalar);
        let mut result = ExtendedPointBigInt::identity();

        for i in (0..254).rev() {
            result = double_point(&result);
            if bits[i] {
                result = add_points(&result, p);
            }
        }

        result
    }

    /// Clear cofactor (multiply by 8).
    pub fn clear_cofactor(p: &ExtendedPointBigInt) -> ExtendedPointBigInt {
        let p2 = double_point(p);
        let p4 = double_point(&p2);
        double_point(&p4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::point::base_point;

    #[test]
    fn test_scalar_bits_roundtrip() {
        let scalar = BigInt256::from_u64(0x0001_0932_3039);
        let bits = scalar_to_bits(&scalar);
        let recovered = bits_to_scalar(&bits);

        // Only compare the parts that fit in 254 bits
        assert_eq!(scalar.limbs, recovered.limbs);
    }

    #[test]
    fn test_identity_add() {
        let base = base_point();
        let identity = ExtendedPointBigInt::identity();
        let modulus = modulus();

        // P + Identity = P
        let sum = native::add_points(&base, &identity);
        let (x1, y1) = base.to_affine(&modulus);
        let (x2, y2) = sum.to_affine(&modulus);

        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_double_equals_add() {
        let base = base_point();
        let modulus = modulus();

        // 2P via double
        let doubled = native::double_point(&base);

        // 2P via add
        let added = native::add_points(&base, &base);

        // Should be equal (same affine coordinates)
        let (x1, y1) = doubled.to_affine(&modulus);
        let (x2, y2) = added.to_affine(&modulus);

        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_scalar_mul_one() {
        let base = base_point();
        let one = BigInt256::one();
        let modulus = modulus();

        // 1 * P = P
        let result = native::scalar_mul(&base, &one);
        let (x1, y1) = base.to_affine(&modulus);
        let (x2, y2) = result.to_affine(&modulus);

        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_scalar_mul_two() {
        let base = base_point();
        let two = BigInt256::from_u32(2);
        let modulus = modulus();

        // 2 * P via scalar_mul
        let result = native::scalar_mul(&base, &two);

        // 2 * P via double
        let doubled = native::double_point(&base);

        let (x1, y1) = result.to_affine(&modulus);
        let (x2, y2) = doubled.to_affine(&modulus);

        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_cofactor_clearing() {
        let base = base_point();
        let modulus = modulus();

        // Clear cofactor (multiply by 8)
        let cleared = native::clear_cofactor(&base);

        // Should not be identity
        let (x, _y) = cleared.to_affine(&modulus);
        assert!(!x.is_zero());
    }
}
