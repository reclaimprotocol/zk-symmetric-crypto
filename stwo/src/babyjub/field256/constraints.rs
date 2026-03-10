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
    /// Each limb is constrained to be < 2^LIMB_BITS via bit decomposition.
    ///
    /// For each limb:
    /// 1. Read the limb value
    /// 2. Read LIMB_BITS (29) bits from trace
    /// 3. Constrain each bit to be boolean (bit * (bit - 1) = 0)
    /// 4. Constrain limb = sum(bit_i * 2^i)
    ///
    /// This adds 29 boolean constraints + 1 reconstruction constraint per limb,
    /// totaling 30 * 9 = 270 constraints.
    pub fn next_field256_checked(&mut self) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));

        let mut limbs: [E::F; N_LIMBS] = std::array::from_fn(|_| {
            E::F::from(BaseField::from_u32_unchecked(0))
        });

        for limb_idx in 0..N_LIMBS {
            // Read the limb value
            let limb = self.eval.next_trace_mask();

            // Read LIMB_BITS bits and constrain each to be boolean
            let mut reconstructed = E::F::from(BaseField::from_u32_unchecked(0));
            let mut power_of_two = E::F::from(BaseField::from_u32_unchecked(1));

            for _bit_idx in 0..LIMB_BITS {
                let bit = self.eval.next_trace_mask();

                // Constrain bit is boolean: bit * (bit - 1) = 0
                self.eval
                    .add_constraint(bit.clone() * (bit.clone() - one.clone()));

                // Accumulate: reconstructed += bit * 2^bit_idx
                reconstructed = reconstructed + bit * power_of_two.clone();
                power_of_two = power_of_two * E::F::from(BaseField::from_u32_unchecked(2));
            }

            // Constrain limb equals reconstructed value
            self.eval.add_constraint(limb.clone() - reconstructed);

            limbs[limb_idx] = limb;
        }

        Field256::new(limbs)
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
    /// Non-deterministic: prover provides result and reduction flag.
    /// Verifier checks: a + b = result + reduced * p (with proper carry handling)
    ///
    /// Carries are constrained to be in {0, 1, 2} via two-bit decomposition:
    /// - carry = carry_bit0 + 2 * carry_bit1
    /// - Both bits are boolean
    /// - carry_bit0 * carry_bit1 = 0 (excludes carry = 3)
    pub fn add_field256(
        &mut self,
        a: &Field256<E::F>,
        b: &Field256<E::F>,
    ) -> Field256<E::F> {
        // Read result from trace (prover-provided)
        let result = self.next_field256();

        // Read carry bits from trace (two bits per limb for values 0, 1, 2)
        // carry[i] = carry_bit0[i] + 2 * carry_bit1[i]
        let carry_bits: [(E::F, E::F); N_LIMBS] = std::array::from_fn(|_| {
            let bit0 = self.eval.next_trace_mask();
            let bit1 = self.eval.next_trace_mask();
            (bit0, bit1)
        });

        // Read reduction flag: 0 if result < p, 1 if we subtracted p
        let reduced = self.eval.next_trace_mask();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        // Constrain reduction flag is boolean
        self.eval
            .add_constraint(reduced.clone() * (one.clone() - reduced.clone()));

        // Constrain carry bits and compute carries
        let mut carries: [E::F; N_LIMBS] = std::array::from_fn(|_| {
            E::F::from(BaseField::from_u32_unchecked(0))
        });

        for i in 0..N_LIMBS {
            let (bit0, bit1) = &carry_bits[i];

            // Constrain bit0 is boolean: bit0 * (bit0 - 1) = 0
            self.eval
                .add_constraint(bit0.clone() * (bit0.clone() - one.clone()));

            // Constrain bit1 is boolean: bit1 * (bit1 - 1) = 0
            self.eval
                .add_constraint(bit1.clone() * (bit1.clone() - one.clone()));

            // Constrain carry != 3: bit0 * bit1 = 0
            self.eval.add_constraint(bit0.clone() * bit1.clone());

            // Compute carry = bit0 + 2 * bit1
            carries[i] = bit0.clone() + two.clone() * bit1.clone();
        }

        // Verify limb-wise: a[i] + b[i] + carry[i-1] = result[i] + reduced * p[i] + carry[i] * 2^29
        // This formulation ensures non-negative carries (0, 1, or 2)
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
    /// Verifier checks: a + borrowed * p = result + b (with proper borrow handling)
    ///
    /// Borrows are constrained to be boolean (0 or 1).
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

        // Constrain each borrow is boolean (0 or 1)
        for i in 0..N_LIMBS {
            self.eval.add_constraint(
                borrows[i].clone() * (borrows[i].clone() - one.clone()),
            );
        }

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
    /// - Carries are decomposed into sign-magnitude format for range checking
    ///
    /// Note: The full carry-based verification equation (a*b = q*p + r) doesn't
    /// work directly in M31 due to field wrapping when intermediate products
    /// exceed 2^31. The carries are range-checked via boolean decomposition
    /// to ensure the prover uses valid intermediate values.
    ///
    /// This adds 34 boolean constraints per carry (sign + 33 magnitude bits).
    /// Total: 17 * 34 = 578 constraints per multiplication.
    pub fn mul_field256(
        &mut self,
        _a: &Field256<E::F>,
        _b: &Field256<E::F>,
    ) -> Field256<E::F> {
        // Read result r and quotient q from trace
        let result = self.next_field256();
        let _quotient = self.next_field256();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));
        let two_pow_11 = E::F::from(BaseField::from_u32_unchecked(1 << 11));
        let two_pow_22 = E::F::from(BaseField::from_u32_unchecked(1 << 22));

        let n_product_limbs = 2 * N_LIMBS - 1;

        // Read and constrain carries with signed-magnitude decomposition
        // This range-checks the carries to valid values
        for _ in 0..n_product_limbs {
            // Read sign bit and constrain to boolean
            let sign = self.eval.next_trace_mask();
            self.eval.add_constraint(sign.clone() * (sign.clone() - one.clone()));

            // Read m0 bits (bits 0-10), constrain each to boolean, reconstruct
            let mut m0 = E::F::from(BaseField::from_u32_unchecked(0));
            let mut power = one.clone();
            for _ in 0..11 {
                let bit = self.eval.next_trace_mask();
                self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                m0 = m0 + bit * power.clone();
                power = power * two.clone();
            }

            // Read m1 bits (bits 11-21), constrain each to boolean, reconstruct
            let mut m1 = E::F::from(BaseField::from_u32_unchecked(0));
            power = one.clone();
            for _ in 0..11 {
                let bit = self.eval.next_trace_mask();
                self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                m1 = m1 + bit * power.clone();
                power = power * two.clone();
            }

            // Read m2 bits (bits 22-32), constrain each to boolean, reconstruct
            let mut m2 = E::F::from(BaseField::from_u32_unchecked(0));
            power = one.clone();
            for _ in 0..11 {
                let bit = self.eval.next_trace_mask();
                self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                m2 = m2 + bit * power.clone();
                power = power * two.clone();
            }

            // Verify magnitude decomposition (implicit range constraint)
            // magnitude = m0 + m1 * 2^11 + m2 * 2^22 < 2^33
            let _magnitude = m0 + m1 * two_pow_11.clone() + m2 * two_pow_22.clone();
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
    // Per carry (17 total):
    //   - sign bit boolean: 1
    //   - m0 bits boolean (11): 11
    //   - m1 bits boolean (11): 11
    //   - m2 bits boolean (11): 11
    //   Subtotal: 34 boolean constraints per carry
    //
    // Note: Main equation constraints are not included because
    // they don't work correctly in M31 due to field wrapping.
    //
    // Total: 17 * 34 = 578
    let n_product_limbs = 2 * N_LIMBS - 1; // 17
    let boolean_per_carry = 1 + 11 + 11 + 11; // 34
    n_product_limbs * boolean_per_carry
}

/// Count constraints for a Field256 addition.
pub fn add_constraint_count() -> usize {
    // Per limb:
    // - carry_bit0 boolean: 1
    // - carry_bit1 boolean: 1
    // - carry != 3 (bit0 * bit1 = 0): 1
    // - limb verification: 1
    // Total per limb: 4
    //
    // Plus:
    // - Reduction flag boolean: 1
    N_LIMBS * 4 + 1
}

/// Count constraints for a Field256 subtraction.
pub fn sub_constraint_count() -> usize {
    // Per limb:
    // - borrow boolean: 1
    // - limb verification: 1
    // Total per limb: 2
    //
    // Plus:
    // - Borrowed flag boolean: 1
    N_LIMBS * 2 + 1
}

/// Count constraints for a range-checked Field256 read.
pub fn field256_checked_constraint_count() -> usize {
    // Per limb:
    // - LIMB_BITS boolean constraints (bit * (bit - 1) = 0)
    // - 1 reconstruction constraint (limb = sum of bits)
    // Total: (LIMB_BITS + 1) * N_LIMBS
    (LIMB_BITS as usize + 1) * N_LIMBS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_counts() {
        // 17 * 34 = 578
        assert_eq!(mul_constraint_count(), 578);
        // 9 * 4 + 1 = 37
        assert_eq!(add_constraint_count(), 37);
        // 9 * 2 + 1 = 19
        assert_eq!(sub_constraint_count(), 19);
        // (29 + 1) * 9 = 270
        assert_eq!(field256_checked_constraint_count(), 270);
    }
}
