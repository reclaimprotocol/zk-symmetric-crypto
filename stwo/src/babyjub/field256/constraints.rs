//! Constraint evaluation for 256-bit field arithmetic with 20 × 13-bit limbs.

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;
use super::{Field256, LIMB_BITS, N_LIMBS};

/// Evaluator for Field256 constraints.
pub struct Field256EvalAtRow<'a, E: EvalAtRow> {
    pub eval: &'a mut E,
}

impl<E: EvalAtRow> Field256EvalAtRow<'_, E> {
    /// Read Field256 (20 limbs, no range check).
    pub fn next_field256(&mut self) -> Field256<E::F> {
        Field256::new(std::array::from_fn(|_| self.eval.next_trace_mask()))
    }

    /// Read Field256 with bit decomposition for range checking.
    pub fn next_field256_checked(&mut self) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let mut limbs: [E::F; N_LIMBS] = std::array::from_fn(|_| E::F::from(BaseField::from_u32_unchecked(0)));

        for limb_idx in 0..N_LIMBS {
            let limb = self.eval.next_trace_mask();
            let mut reconstructed = E::F::from(BaseField::from_u32_unchecked(0));
            let mut power = E::F::from(BaseField::from_u32_unchecked(1));

            for _ in 0..LIMB_BITS {
                let bit = self.eval.next_trace_mask();
                self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                reconstructed = reconstructed + bit * power.clone();
                power = power * E::F::from(BaseField::from_u32_unchecked(2));
            }
            self.eval.add_constraint(limb.clone() - reconstructed);
            limbs[limb_idx] = limb;
        }
        Field256::new(limbs)
    }

    /// Constrain two Field256 values to be equal.
    pub fn assert_eq(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) {
        for i in 0..N_LIMBS {
            self.eval.add_constraint(a.limbs[i].clone() - b.limbs[i].clone());
        }
    }

    /// Constrain addition: result = a + b (mod p).
    pub fn add_field256(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) -> Field256<E::F> {
        let result = self.next_field256_checked();

        let carry_bits: [(E::F, E::F); N_LIMBS] = std::array::from_fn(|_| {
            (self.eval.next_trace_mask(), self.eval.next_trace_mask())
        });
        let reduced = self.eval.next_trace_mask();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        // Reduced is boolean
        self.eval.add_constraint(reduced.clone() * (one.clone() - reduced.clone()));

        // Constrain carries
        let mut carries: [E::F; N_LIMBS] = std::array::from_fn(|_| E::F::from(BaseField::from_u32_unchecked(0)));
        for i in 0..N_LIMBS {
            let (bit0, bit1) = &carry_bits[i];
            self.eval.add_constraint(bit0.clone() * (bit0.clone() - one.clone()));
            self.eval.add_constraint(bit1.clone() * (bit1.clone() - one.clone()));
            self.eval.add_constraint(bit0.clone() * bit1.clone()); // carry != 3
            carries[i] = bit0.clone() + two.clone() * bit1.clone();
        }

        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(super::MODULUS[i]))
        });

        // Verify: a[i] + b[i] + carry[i-1] = result[i] + reduced*p[i] + carry[i] * 2^LIMB_BITS
        for i in 0..N_LIMBS {
            let carry_in = if i == 0 { E::F::from(BaseField::from_u32_unchecked(0)) } else { carries[i - 1].clone() };
            let lhs = a.limbs[i].clone() + b.limbs[i].clone() + carry_in;
            let rhs = result.limbs[i].clone() + reduced.clone() * modulus_limbs[i].clone() + carries[i].clone() * two_pow_limb.clone();
            self.eval.add_constraint(lhs - rhs);
        }
        result
    }

    /// Constrain subtraction: result = a - b (mod p).
    pub fn sub_field256(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) -> Field256<E::F> {
        let result = self.next_field256_checked();
        let borrows: [E::F; N_LIMBS] = std::array::from_fn(|_| self.eval.next_trace_mask());
        let borrowed = self.eval.next_trace_mask();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        self.eval.add_constraint(borrowed.clone() * (one.clone() - borrowed.clone()));
        for i in 0..N_LIMBS {
            self.eval.add_constraint(borrows[i].clone() * (borrows[i].clone() - one.clone()));
        }

        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(super::MODULUS[i]))
        });

        for i in 0..N_LIMBS {
            let borrow_in = if i == 0 { E::F::from(BaseField::from_u32_unchecked(0)) } else { borrows[i - 1].clone() };
            let lhs = a.limbs[i].clone() + borrowed.clone() * modulus_limbs[i].clone() + borrows[i].clone() * two_pow_limb.clone();
            let rhs = result.limbs[i].clone() + b.limbs[i].clone() + borrow_in;
            self.eval.add_constraint(lhs - rhs);
        }
        result
    }

    /// Constrain multiplication: result = a * b (mod p).
    pub fn mul_field256(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) -> Field256<E::F> {
        let result = self.next_field256_checked();
        let quotient = self.next_field256();

        // Read and constrain sub-products
        let mut ab_subs: [[E::F; N_LIMBS]; N_LIMBS] = std::array::from_fn(|_| std::array::from_fn(|_| E::F::from(BaseField::from_u32_unchecked(0))));
        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                let sub = self.eval.next_trace_mask();
                self.eval.add_constraint(sub.clone() - a.limbs[i].clone() * b.limbs[j].clone());
                ab_subs[i][j] = sub;
            }
        }

        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| E::F::from(BaseField::from_u32_unchecked(super::MODULUS[i])));
        let mut qp_subs: [[E::F; N_LIMBS]; N_LIMBS] = std::array::from_fn(|_| std::array::from_fn(|_| E::F::from(BaseField::from_u32_unchecked(0))));
        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                let sub = self.eval.next_trace_mask();
                self.eval.add_constraint(sub.clone() - quotient.limbs[i].clone() * modulus_limbs[j].clone());
                qp_subs[i][j] = sub;
            }
        }

        // Read carries and verify column equations
        let n_cols = 2 * N_LIMBS - 1;
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));
        let mut prev_carry = E::F::from(BaseField::from_u32_unchecked(0));

        for k in 0..n_cols {
            let sign = self.eval.next_trace_mask();
            let lo = self.eval.next_trace_mask();
            let hi = self.eval.next_trace_mask();
            self.eval.add_constraint(sign.clone() * (sign.clone() - one.clone()));

            let sign_factor = one.clone() - two.clone() * sign.clone();
            let carry_mag = lo + hi * two_pow_limb.clone();
            let carry_out = sign_factor * carry_mag;

            let mut ab_sum = prev_carry.clone();
            for i in 0..=k.min(N_LIMBS - 1) {
                let j = k - i;
                if j < N_LIMBS { ab_sum = ab_sum + ab_subs[i][j].clone(); }
            }

            let mut qp_sum = E::F::from(BaseField::from_u32_unchecked(0));
            for i in 0..=k.min(N_LIMBS - 1) {
                let j = k - i;
                if j < N_LIMBS { qp_sum = qp_sum + qp_subs[i][j].clone(); }
            }

            let r_k = if k < N_LIMBS { result.limbs[k].clone() } else { E::F::from(BaseField::from_u32_unchecked(0)) };
            self.eval.add_constraint(ab_sum - qp_sum - r_k - carry_out.clone() * two_pow_limb.clone());
            prev_carry = carry_out;
        }
        result
    }

    /// Constrain inversion: result = a^-1 (mod p).
    pub fn inv_field256(&mut self, a: &Field256<E::F>) -> Field256<E::F> {
        let inv = self.next_field256();
        let product = self.mul_field256(a, &inv);
        self.assert_eq(&product, &Field256::one());
        inv
    }

    /// Select between two Field256 values based on a condition bit.
    /// Returns a if cond = 0, b if cond = 1.
    /// Formula: result = a + cond * (b - a)
    pub fn select_field256(&mut self, cond: &E::F, a: &Field256<E::F>, b: &Field256<E::F>) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // Constrain cond is boolean
        self.eval.add_constraint(cond.clone() * (cond.clone() - one.clone()));

        // result = a + cond * (b - a) = (1 - cond) * a + cond * b
        let result_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            // result[i] = a[i] + cond * (b[i] - a[i])
            a.limbs[i].clone() + cond.clone() * (b.limbs[i].clone() - a.limbs[i].clone())
        });
        Field256::new(result_limbs)
    }

    /// Assert a Field256 value is non-zero by verifying it has an inverse.
    pub fn assert_nonzero(&mut self, a: &Field256<E::F>) {
        // If a has an inverse, then a * inv = 1, which implies a != 0
        let _inv = self.inv_field256(a);
    }
}

pub fn add_constraint_count() -> usize { N_LIMBS * 4 + 1 }
pub fn sub_constraint_count() -> usize { N_LIMBS * 2 + 1 }
pub fn mul_constraint_count() -> usize { N_LIMBS * N_LIMBS * 2 + (2 * N_LIMBS - 1) * 2 + (LIMB_BITS as usize + 1) * N_LIMBS }
pub fn field256_checked_constraint_count() -> usize { (LIMB_BITS as usize + 1) * N_LIMBS }
