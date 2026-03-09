//! Constraint evaluation for 256-bit field arithmetic.
//!
//! All operations use non-deterministic verification:
//! - Prover provides the result
//! - Circuit verifies the result is correct
//!
//! For multiplication: verifies a * b = q * p + r (mod 2^261)
//! For inversion: verifies a * a_inv = 1 (mod p)

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::{Field256, LIMB_BITS, N_LIMBS};

/// Evaluator context for Field256 arithmetic constraints.
pub struct Field256EvalAtRow<'a, E: EvalAtRow> {
    pub eval: &'a mut E,
}

impl<E: EvalAtRow> Field256EvalAtRow<'_, E> {
    /// Read next Field256 from trace.
    /// Does NOT constrain limbs to be in range - caller must handle range checks.
    pub fn next_field256(&mut self) -> Field256<E::F> {
        Field256::new(std::array::from_fn(|_| self.eval.next_trace_mask()))
    }

    /// Read next Field256 from trace with range checks on each limb.
    /// Each limb is constrained to be < 2^LIMB_BITS.
    ///
    /// Note: Full range checking requires decomposing each limb into bits,
    /// which is expensive. For now, we rely on the prover providing valid values
    /// and check relations hold modulo the field.
    pub fn next_field256_checked(&mut self) -> Field256<E::F> {
        // For a full implementation, we would:
        // 1. Read the limb
        // 2. Decompose into bits and constrain each bit to be boolean
        // 3. Verify the limb equals the sum of bits
        //
        // This adds ~29 constraints per limb, ~261 constraints total.
        // For now, we read without explicit range checks.
        self.next_field256()
    }

    /// Constrain two Field256 values to be equal.
    pub fn assert_eq(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) {
        for i in 0..N_LIMBS {
            self.eval
                .add_constraint(a.limbs[i].clone() - b.limbs[i].clone());
        }
    }

    /// Constrain Field256 addition: result = a + b (mod p).
    ///
    /// Non-deterministic: prover provides result and borrow flag.
    /// Verifier checks: a + b = result + borrow * p
    ///
    /// This is a simplified version that assumes no reduction needed
    /// (result < p). For full correctness, need to handle reduction.
    pub fn add_field256(
        &mut self,
        a: &Field256<E::F>,
        b: &Field256<E::F>,
    ) -> Field256<E::F> {
        // Read result from trace (prover-provided)
        let result = self.next_field256();

        // Read carries from trace (one per limb)
        // carry[i] = floor((a[i] + b[i] + carry[i-1] - result[i]) / 2^29)
        let carries: [E::F; N_LIMBS] = std::array::from_fn(|_| self.eval.next_trace_mask());

        // Read reduction flag: 0 if result < p, 1 if we subtracted p
        let reduced = self.eval.next_trace_mask();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        // Constrain reduction flag is boolean
        self.eval
            .add_constraint(reduced.clone() * (one.clone() - reduced.clone()));

        // Constrain carries are boolean (in practice they can be 0, 1, or 2 for addition)
        // More precisely: carry[i] in {0, 1, 2} for unreduced, then after reduction carry <= 1
        // For simplicity, we constrain: carry * (carry - 1) * (carry - 2) = 0
        // But this is degree 3. Instead we'll verify the relation holds.

        // Verify limb-wise: a[i] + b[i] + carry[i-1] = result[i] + reduced * p[i] + carry[i] * 2^29
        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(super::MODULUS[i]))
        });

        for i in 0..N_LIMBS {
            let carry_in = if i == 0 {
                E::F::from(BaseField::from_u32_unchecked(0))
            } else {
                carries[i - 1].clone()
            };

            // a[i] + b[i] + carry_in = result[i] + reduced * p[i] + carry[i] * 2^29
            let lhs = a.limbs[i].clone() + b.limbs[i].clone() + carry_in;
            let rhs = result.limbs[i].clone()
                + reduced.clone() * modulus_limbs[i].clone()
                + carries[i].clone() * two_pow_limb.clone();

            self.eval.add_constraint(lhs - rhs);
        }

        result
    }

    /// Constrain Field256 subtraction: result = a - b (mod p).
    ///
    /// Non-deterministic: prover provides result and borrow flag.
    /// Verifier checks: a = result + b - borrow * p
    pub fn sub_field256(
        &mut self,
        a: &Field256<E::F>,
        b: &Field256<E::F>,
    ) -> Field256<E::F> {
        // Read result from trace
        let result = self.next_field256();

        // Read borrows from trace
        let borrows: [E::F; N_LIMBS] = std::array::from_fn(|_| self.eval.next_trace_mask());

        // Read borrow flag: 1 if we added p to avoid underflow
        let borrowed = self.eval.next_trace_mask();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        // Constrain borrow flag is boolean
        self.eval
            .add_constraint(borrowed.clone() * (one.clone() - borrowed.clone()));

        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(super::MODULUS[i]))
        });

        // Verify: a[i] + borrowed * p[i] = result[i] + b[i] + borrow[i] * 2^29 - borrow[i-1]
        // Rearranged: a[i] + borrowed * p[i] + borrow[i-1] = result[i] + b[i] + borrow[i] * 2^29
        for i in 0..N_LIMBS {
            let borrow_in = if i == 0 {
                E::F::from(BaseField::from_u32_unchecked(0))
            } else {
                borrows[i - 1].clone()
            };

            let lhs =
                a.limbs[i].clone() + borrowed.clone() * modulus_limbs[i].clone() + borrow_in;
            let rhs = result.limbs[i].clone()
                + b.limbs[i].clone()
                + borrows[i].clone() * two_pow_limb.clone();

            self.eval.add_constraint(lhs - rhs);
        }

        result
    }

    /// Constrain Field256 multiplication: result = a * b (mod p).
    ///
    /// Non-deterministic verification:
    /// - Prover provides result r and quotient q
    /// - Verifier checks: a * b = q * p + r (as integers, verified mod 2^(29*N_LIMBS))
    ///
    /// This requires computing the full product and comparing limb-by-limb.
    pub fn mul_field256(
        &mut self,
        a: &Field256<E::F>,
        b: &Field256<E::F>,
    ) -> Field256<E::F> {
        // Read result r and quotient q from trace
        let result = self.next_field256();
        let quotient = self.next_field256();

        // Read intermediate carries for the product computation
        // Product a*b has up to 2*N_LIMBS-1 = 17 limbs before reduction
        // We need carries for the verification equation
        let n_product_limbs = 2 * N_LIMBS - 1;
        let carries: Vec<E::F> = (0..n_product_limbs)
            .map(|_| self.eval.next_trace_mask())
            .collect();

        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(super::MODULUS[i]))
        });

        // Verify: a * b = q * p + r (limb by limb with carries)
        //
        // For each limb position k (0..2*N_LIMBS-1):
        //   sum_{i+j=k} a[i]*b[j] = sum_{i+j=k} q[i]*p[j] + r[k] + carry[k]*2^29 - carry[k-1]
        //
        // Where r[k] = 0 for k >= N_LIMBS (result fits in N_LIMBS)

        for k in 0..n_product_limbs {
            let carry_in = if k == 0 {
                E::F::from(BaseField::from_u32_unchecked(0))
            } else {
                carries[k - 1].clone()
            };

            // Compute sum of a[i] * b[j] for i + j = k
            let mut ab_sum = E::F::from(BaseField::from_u32_unchecked(0));
            for i in 0..N_LIMBS {
                let j = k as i32 - i as i32;
                if j >= 0 && (j as usize) < N_LIMBS {
                    ab_sum = ab_sum + a.limbs[i].clone() * b.limbs[j as usize].clone();
                }
            }

            // Compute sum of q[i] * p[j] for i + j = k
            let mut qp_sum = E::F::from(BaseField::from_u32_unchecked(0));
            for i in 0..N_LIMBS {
                let j = k as i32 - i as i32;
                if j >= 0 && (j as usize) < N_LIMBS {
                    qp_sum = qp_sum + quotient.limbs[i].clone() * modulus_limbs[j as usize].clone();
                }
            }

            // r[k] (result at position k, zero for k >= N_LIMBS)
            let r_k = if k < N_LIMBS {
                result.limbs[k].clone()
            } else {
                E::F::from(BaseField::from_u32_unchecked(0))
            };

            // Constraint: ab_sum + carry_in = qp_sum + r_k + carry[k] * 2^29
            let lhs = ab_sum + carry_in;
            let rhs = qp_sum + r_k + carries[k].clone() * two_pow_limb.clone();

            self.eval.add_constraint(lhs - rhs);
        }

        result
    }

    /// Constrain Field256 inversion: result = a^(-1) (mod p).
    ///
    /// Non-deterministic: prover provides result.
    /// Verifier checks: a * result = 1 (mod p).
    ///
    /// Uses mul_field256 internally and asserts result is 1.
    pub fn inv_field256(&mut self, a: &Field256<E::F>) -> Field256<E::F> {
        // Read inverse from trace
        let inv = self.next_field256();

        // Compute a * inv using mul_field256 constraints
        let product = self.mul_field256(a, &inv);

        // Assert product = 1
        let one = Field256::<E::F>::one();
        self.assert_eq(&product, &one);

        inv
    }

    /// Constrain Field256 is non-zero.
    ///
    /// Non-deterministic: prover provides inverse as witness.
    /// Verifier checks: a * inv = 1 (mod p), which fails if a = 0.
    pub fn assert_nonzero(&mut self, a: &Field256<E::F>) {
        // By computing the inverse, we implicitly check a != 0
        // (since 0 has no inverse)
        let _inv = self.inv_field256(a);
    }

    /// Select between two Field256 values based on condition.
    /// Returns a if cond = 0, b if cond = 1.
    ///
    /// Constraint: result = a + cond * (b - a)
    pub fn select_field256(
        &mut self,
        cond: &E::F,
        a: &Field256<E::F>,
        b: &Field256<E::F>,
    ) -> Field256<E::F> {
        // Read result from trace
        let result = self.next_field256();

        // Constrain: result[i] = a[i] + cond * (b[i] - a[i])
        for i in 0..N_LIMBS {
            let expected =
                a.limbs[i].clone() + cond.clone() * (b.limbs[i].clone() - a.limbs[i].clone());
            self.eval
                .add_constraint(result.limbs[i].clone() - expected);
        }

        result
    }
}

/// Count constraints for a Field256 multiplication.
/// This is useful for estimating total constraint count.
pub fn mul_constraint_count() -> usize {
    // Result: N_LIMBS reads (no constraints for reads)
    // Quotient: N_LIMBS reads
    // Carries: 2*N_LIMBS - 1 reads
    // Constraints: 2*N_LIMBS - 1 (one per limb position in the product)
    2 * N_LIMBS - 1
}

/// Count constraints for a Field256 addition.
pub fn add_constraint_count() -> usize {
    // Reduction flag: 1 boolean constraint
    // Limb verification: N_LIMBS constraints
    N_LIMBS + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_counts() {
        assert_eq!(mul_constraint_count(), 17);
        assert_eq!(add_constraint_count(), 10);
    }
}
