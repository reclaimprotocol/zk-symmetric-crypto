//! Constraint evaluation for Baby Jubjub point operations.
//!
//! Uses extended coordinates for efficient add/double without inversions.
//! Twisted Edwards curve formula: a*x² + y² = 1 + d*x²y²

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::{ExtendedPoint, CURVE_A, CURVE_D};
use crate::babyjub::field256::constraints::Field256EvalAtRow;
use crate::babyjub::field256::{field256_from_limbs29, Field256, N_LIMBS};

/// Evaluator for point operations.
pub struct PointEvalAtRow<'a, E: EvalAtRow> {
    pub field_eval: Field256EvalAtRow<'a, E>,
}

impl<E: EvalAtRow> PointEvalAtRow<'_, E> {
    /// Read an extended point from trace.
    pub fn next_extended_point(&mut self) -> ExtendedPoint<E::F> {
        let x = self.field_eval.next_field256();
        let y = self.field_eval.next_field256();
        let t = self.field_eval.next_field256();
        let z = self.field_eval.next_field256();
        ExtendedPoint::new(x, y, t, z)
    }

    /// Get curve parameter a as Field256.
    fn curve_a(&self) -> Field256<E::F> {
        field256_from_limbs29(&CURVE_A)
    }

    /// Get curve parameter d as Field256.
    fn curve_d(&self) -> Field256<E::F> {
        field256_from_limbs29(&CURVE_D)
    }

    /// Point addition in extended coordinates.
    ///
    /// Formula for a=-1 (twisted Edwards):
    /// A = X1 * X2
    /// B = Y1 * Y2
    /// C = T1 * d * T2
    /// D = Z1 * Z2
    /// E = (X1 + Y1) * (X2 + Y2) - A - B
    /// F = D - C
    /// G = D + C
    /// H = B - a * A = B + A (since a = -1)
    /// X3 = E * F
    /// Y3 = G * H
    /// T3 = E * H
    /// Z3 = F * G
    ///
    /// Cost: 12 field muls, 8 field adds
    pub fn add_points(
        &mut self,
        p1: &ExtendedPoint<E::F>,
        p2: &ExtendedPoint<E::F>,
    ) -> ExtendedPoint<E::F> {
        let d = self.curve_d();

        // A = X1 * X2
        let a_term = self.field_eval.mul_field256(&p1.x, &p2.x);

        // B = Y1 * Y2
        let b_term = self.field_eval.mul_field256(&p1.y, &p2.y);

        // C = T1 * d * T2
        let t1_t2 = self.field_eval.mul_field256(&p1.t, &p2.t);
        let c_term = self.field_eval.mul_field256(&t1_t2, &d);

        // D = Z1 * Z2
        let d_term = self.field_eval.mul_field256(&p1.z, &p2.z);

        // E = (X1 + Y1) * (X2 + Y2) - A - B
        let x1_plus_y1 = self.field_eval.add_field256(&p1.x, &p1.y);
        let x2_plus_y2 = self.field_eval.add_field256(&p2.x, &p2.y);
        let sum_prod = self.field_eval.mul_field256(&x1_plus_y1, &x2_plus_y2);
        let e_tmp = self.field_eval.sub_field256(&sum_prod, &a_term);
        let e_term = self.field_eval.sub_field256(&e_tmp, &b_term);

        // F = D - C
        let f_term = self.field_eval.sub_field256(&d_term, &c_term);

        // G = D + C
        let g_term = self.field_eval.add_field256(&d_term, &c_term);

        // H = B - a * A = B + A (since a = -1)
        let h_term = self.field_eval.add_field256(&b_term, &a_term);

        // X3 = E * F
        let x3 = self.field_eval.mul_field256(&e_term, &f_term);

        // Y3 = G * H
        let y3 = self.field_eval.mul_field256(&g_term, &h_term);

        // T3 = E * H
        let t3 = self.field_eval.mul_field256(&e_term, &h_term);

        // Z3 = F * G
        let z3 = self.field_eval.mul_field256(&f_term, &g_term);

        ExtendedPoint::new(x3, y3, t3, z3)
    }

    /// Point doubling in extended coordinates.
    ///
    /// Formula for a=-1 (twisted Edwards):
    /// A = X1²
    /// B = Y1²
    /// C = 2 * Z1²
    /// D = a * A = -A
    /// E = (X1 + Y1)² - A - B
    /// G = D + B
    /// F = G - C
    /// H = D - B
    /// X3 = E * F
    /// Y3 = G * H
    /// T3 = E * H
    /// Z3 = F * G
    ///
    /// Cost: 10 field muls (including squarings), 6 field adds
    pub fn double_point(&mut self, p: &ExtendedPoint<E::F>) -> ExtendedPoint<E::F> {
        // A = X1²
        let a_term = self.field_eval.mul_field256(&p.x, &p.x);

        // B = Y1²
        let b_term = self.field_eval.mul_field256(&p.y, &p.y);

        // C = 2 * Z1²
        let z_sq = self.field_eval.mul_field256(&p.z, &p.z);
        let c_term = self.field_eval.add_field256(&z_sq, &z_sq);

        // D = a * A = -A (since a = -1, we compute p - A)
        // This is equivalent to subtracting A from 0, but we need to handle it carefully
        // Instead, we'll use the formula directly with subtraction from p
        let zero = Field256::<E::F>::zero();
        let d_term = self.field_eval.sub_field256(&zero, &a_term);

        // E = (X1 + Y1)² - A - B
        let x_plus_y = self.field_eval.add_field256(&p.x, &p.y);
        let sum_sq = self.field_eval.mul_field256(&x_plus_y, &x_plus_y);
        let e_tmp = self.field_eval.sub_field256(&sum_sq, &a_term);
        let e_term = self.field_eval.sub_field256(&e_tmp, &b_term);

        // G = D + B
        let g_term = self.field_eval.add_field256(&d_term, &b_term);

        // F = G - C
        let f_term = self.field_eval.sub_field256(&g_term, &c_term);

        // H = D - B
        let h_term = self.field_eval.sub_field256(&d_term, &b_term);

        // X3 = E * F
        let x3 = self.field_eval.mul_field256(&e_term, &f_term);

        // Y3 = G * H
        let y3 = self.field_eval.mul_field256(&g_term, &h_term);

        // T3 = E * H
        let t3 = self.field_eval.mul_field256(&e_term, &h_term);

        // Z3 = F * G
        let z3 = self.field_eval.mul_field256(&f_term, &g_term);

        ExtendedPoint::new(x3, y3, t3, z3)
    }

    /// Scalar multiplication using double-and-add.
    ///
    /// The scalar is provided as bits (254 bits for BN254 scalar field).
    /// bits[0] is LSB, bits[253] is MSB.
    ///
    /// Cost: 254 * (double + conditional_add) ≈ 254 * (2000 + 2400) = ~1.1M constraints
    ///
    /// Note: For efficiency, the prover provides intermediate values and
    /// the circuit verifies the computation step by step.
    pub fn scalar_mul(
        &mut self,
        p: &ExtendedPoint<E::F>,
        scalar_bits: &[E::F; 254],
    ) -> ExtendedPoint<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // Start with identity point
        let identity = self.next_extended_point();

        // Verify identity point is correct: (0, 1, 0, 1)
        let zero = Field256::<E::F>::zero();
        let field_one = Field256::<E::F>::one();
        self.field_eval.assert_eq(&identity.x, &zero);
        self.field_eval.assert_eq(&identity.y, &field_one);
        self.field_eval.assert_eq(&identity.t, &zero);
        self.field_eval.assert_eq(&identity.z, &field_one);

        let mut result = identity;

        // Process bits from MSB to LSB
        for i in (0..254).rev() {
            // Double
            result = self.double_point(&result);

            // Conditional add: if bit[i] == 1, add p
            // result = bit[i] == 0 ? result : result + p
            let sum = self.add_points(&result, p);

            // Select based on bit
            result = self.select_point(&scalar_bits[i], &result, &sum);
        }

        result
    }

    /// Select between two points based on condition.
    /// Returns p0 if cond = 0, p1 if cond = 1.
    pub fn select_point(
        &mut self,
        cond: &E::F,
        p0: &ExtendedPoint<E::F>,
        p1: &ExtendedPoint<E::F>,
    ) -> ExtendedPoint<E::F> {
        let x = self.field_eval.select_field256(cond, &p0.x, &p1.x);
        let y = self.field_eval.select_field256(cond, &p0.y, &p1.y);
        let t = self.field_eval.select_field256(cond, &p0.t, &p1.t);
        let z = self.field_eval.select_field256(cond, &p0.z, &p1.z);
        ExtendedPoint::new(x, y, t, z)
    }

    /// Clear cofactor by multiplying by 8 (3 doublings).
    /// Baby Jubjub has cofactor 8.
    pub fn clear_cofactor(&mut self, p: &ExtendedPoint<E::F>) -> ExtendedPoint<E::F> {
        let p2 = self.double_point(p);
        let p4 = self.double_point(&p2);
        let p8 = self.double_point(&p4);
        p8
    }

    /// Assert a point is not the identity (0, 1, 0, 1).
    /// Used after cofactor clearing to ensure valid point.
    pub fn assert_not_identity(&mut self, p: &ExtendedPoint<E::F>) {
        // After cofactor clearing with Z != 0, checking X != 0 suffices
        // (identity has X = 0)
        self.field_eval.assert_nonzero(&p.x);
    }

    /// Convert extended point to affine by computing Z^(-1).
    pub fn to_affine(
        &mut self,
        p: &ExtendedPoint<E::F>,
    ) -> (Field256<E::F>, Field256<E::F>) {
        let z_inv = self.field_eval.inv_field256(&p.z);
        let x = self.field_eval.mul_field256(&p.x, &z_inv);
        let y = self.field_eval.mul_field256(&p.y, &z_inv);
        (x, y)
    }

    /// Assert two points are equal in projective coordinates.
    /// For extended coordinates (X, Y, T, Z), two points P1 and P2 are equal iff:
    ///   X1 * Z2 = X2 * Z1 and Y1 * Z2 = Y2 * Z1
    pub fn assert_points_equal(
        &mut self,
        p1: &ExtendedPoint<E::F>,
        p2: &ExtendedPoint<E::F>,
    ) {
        // X1 * Z2 = X2 * Z1
        let x1_z2 = self.field_eval.mul_field256(&p1.x, &p2.z);
        let x2_z1 = self.field_eval.mul_field256(&p2.x, &p1.z);
        self.field_eval.assert_eq(&x1_z2, &x2_z1);

        // Y1 * Z2 = Y2 * Z1
        let y1_z2 = self.field_eval.mul_field256(&p1.y, &p2.z);
        let y2_z1 = self.field_eval.mul_field256(&p2.y, &p1.z);
        self.field_eval.assert_eq(&y1_z2, &y2_z1);
    }
}

/// Estimate constraint count for point addition.
pub fn point_add_constraint_count() -> usize {
    // 12 field muls + 8 field adds
    use crate::babyjub::field256::constraints::{add_constraint_count, mul_constraint_count};
    12 * mul_constraint_count() + 8 * add_constraint_count()
}

/// Estimate constraint count for point doubling.
pub fn point_double_constraint_count() -> usize {
    // 10 field muls + 6 field adds
    use crate::babyjub::field256::constraints::{add_constraint_count, mul_constraint_count};
    10 * mul_constraint_count() + 6 * add_constraint_count()
}

/// Estimate constraint count for scalar multiplication.
pub fn scalar_mul_constraint_count() -> usize {
    // 254 * (double + add + select)
    let double = point_double_constraint_count();
    let add = point_add_constraint_count();
    let select = 4 * N_LIMBS; // 4 field256 selects (x, y, t, z)
    254 * (double + add + select)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_counts() {
        println!("Point add constraints: {}", point_add_constraint_count());
        println!("Point double constraints: {}", point_double_constraint_count());
        println!("Scalar mul constraints: {}", scalar_mul_constraint_count());

        // Verify reasonable estimates
        assert!(point_add_constraint_count() > 200);
        assert!(point_double_constraint_count() > 150);
        assert!(scalar_mul_constraint_count() > 100_000);
    }
}
