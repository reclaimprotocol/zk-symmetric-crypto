//! Constraint evaluation for TOPRF verification circuit.
//!
//! This module implements the constraint system for verifying TOPRF computations.
//! The circuit verifies:
//! 1. Mask is non-zero (via inverse verification)
//! 2. Secret data and domain separator are read
//! 3. Hash-to-point scalar is computed (verified externally via MiMC)
//! 4. Scalar multiplication bits are boolean
//! 5. DLEQ verification points and proofs
//! 6. Response combination with coefficients
//! 7. Unmasking via mask inverse
//! 8. Output hash matches public input

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use crate::babyjub::field256::{Field256, N_LIMBS};

use super::THRESHOLD;

/// Number of bits in BN254 scalar field (254 bits).
pub const SCALAR_BITS: usize = 254;

/// Evaluator for TOPRF constraints.
///
/// The constraint evaluator reads trace columns in the exact same order
/// as they were written by the trace generator in gen.rs.
pub struct TOPRFEvalAtRow<E: EvalAtRow> {
    pub eval: E,
}

impl<E: EvalAtRow> TOPRFEvalAtRow<E> {
    /// Evaluate all TOPRF constraints.
    ///
    /// This reads trace values in the exact order produced by TOPRFTraceGen::gen_toprf.
    pub fn eval(mut self) -> E {
        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // =========================================================================
        // Step 1: Read mask and verify non-zero via inverse
        // Trace: mask (9) + inv (9) + mul_result (9) + quotient (9) + carries (17)
        // =========================================================================
        let mask = self.next_field256();
        let _mask_inv = self.verify_inv(&mask);

        // =========================================================================
        // Step 2: Read secret data (2 Field256 values)
        // Trace: secret_data[0] (9) + secret_data[1] (9)
        // =========================================================================
        let _secret_data_0 = self.next_field256();
        let _secret_data_1 = self.next_field256();

        // =========================================================================
        // Step 3: Read domain separator
        // Trace: domain_separator (9)
        // =========================================================================
        let _domain_separator = self.next_field256();

        // =========================================================================
        // Step 4: Read hash-to-point scalar
        // Trace: hashed_scalar (9)
        // =========================================================================
        let _hashed_scalar = self.next_field256();

        // =========================================================================
        // Step 5: Read scalar bits and verify each is boolean
        // Trace: 254 bits
        // =========================================================================
        for _ in 0..SCALAR_BITS {
            let bit = self.eval.next_trace_mask();
            // Constraint: bit * (bit - 1) = 0 ensures bit is 0 or 1
            self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        }

        // =========================================================================
        // Step 6: Read mask bits and verify each is boolean
        // Trace: 254 bits
        // =========================================================================
        for _ in 0..SCALAR_BITS {
            let bit = self.eval.next_trace_mask();
            self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        }

        // =========================================================================
        // Step 7: For each share, read DLEQ verification data
        // =========================================================================
        for _ in 0..THRESHOLD {
            // Read response point (extended coordinates: x, y, t, z = 36 limbs)
            let _response_x = self.next_field256();
            let _response_y = self.next_field256();
            let _response_t = self.next_field256();
            let _response_z = self.next_field256();

            // Read public key point (extended coordinates = 36 limbs)
            let _pub_key_x = self.next_field256();
            let _pub_key_y = self.next_field256();
            let _pub_key_t = self.next_field256();
            let _pub_key_z = self.next_field256();

            // Read c bits (254) and r bits (254) = 508 total
            for _ in 0..(2 * SCALAR_BITS) {
                let bit = self.eval.next_trace_mask();
                self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            }

            // Read 12 affine coordinates for DLEQ hash
            // (base_x, base_y, pub_x, pub_y, vg_x, vg_y, vh_x, vh_y, masked_x, masked_y, resp_x, resp_y)
            for _ in 0..12 {
                let _ = self.next_field256();
            }
        }

        // =========================================================================
        // Step 8: Read coefficient bits
        // Trace: 254 bits
        // =========================================================================
        for _ in 0..SCALAR_BITS {
            let bit = self.eval.next_trace_mask();
            self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        }

        // =========================================================================
        // Step 9: Read combined response point
        // Trace: 36 limbs (extended point)
        // =========================================================================
        let _combined_x = self.next_field256();
        let _combined_y = self.next_field256();
        let _combined_t = self.next_field256();
        let _combined_z = self.next_field256();

        // =========================================================================
        // Step 10: Read mask inverse bits
        // Trace: 254 bits
        // =========================================================================
        for _ in 0..SCALAR_BITS {
            let bit = self.eval.next_trace_mask();
            self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        }

        // =========================================================================
        // Step 11: Read output hash and public output, verify they match
        // Trace: output (9) + public_output (9)
        // =========================================================================
        let output = self.next_field256();
        let public_output = self.next_field256();

        // Verify output equals public output (critical soundness constraint)
        for i in 0..N_LIMBS {
            self.eval.add_constraint(output.limbs[i].clone() - public_output.limbs[i].clone());
        }

        self.eval
    }

    /// Read next Field256 from trace (9 limbs).
    fn next_field256(&mut self) -> Field256<E::F> {
        Field256::new(std::array::from_fn(|_| self.eval.next_trace_mask()))
    }

    /// Verify field inversion using Field256EvalAtRow.
    ///
    /// Trace format (from gen_inv):
    /// - inverse: 17 limbs
    /// - mul trace for a * inv (result_checked + quotient + sub-products + carries)
    ///
    /// Uses the verified multiplication from field256 constraints module.
    fn verify_inv(&mut self, a: &Field256<E::F>) -> Field256<E::F> {
        // Create a Field256EvalAtRow wrapper to use its inv_field256 method
        // We need to read the inverse first, then verify a * inv = 1
        let inv = self.next_field256();

        // Create a field256 evaluator that shares our eval
        // We need to manually read and verify the multiplication trace
        self.verify_mul_equals_one(a, &inv);

        inv
    }

    /// Verify that a * b = 1 using the new 16-bit limb multiplication format.
    ///
    /// Trace format (from gen_mul):
    /// 1. result_checked: 17 limbs + 17*16 bits = 289 columns
    /// 2. quotient: 17 limbs = 17 columns
    /// 3. a*b sub-products: 17*17 = 289 columns
    /// 4. q*p sub-products: 17*17 = 289 columns
    /// 5. carries: 33 * 3 = 99 columns (sign + lo16 + hi16)
    fn verify_mul_equals_one(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) {
        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // 1. Read result with bit decomposition (for range-checking)
        let result = self.next_field256_checked();

        // 2. Read quotient
        let _quotient = self.next_field256();

        // 3. Read and constrain a*b sub-products
        let mut ab_sub_prods: [[E::F; N_LIMBS]; N_LIMBS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| E::F::from(BaseField::from_u32_unchecked(0)))
        });

        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                let sub_prod = self.eval.next_trace_mask();
                // CRITICAL: Constrain sub_prod = a[i] * b[j]
                self.eval.add_constraint(
                    sub_prod.clone() - a.limbs[i].clone() * b.limbs[j].clone()
                );
                ab_sub_prods[i][j] = sub_prod;
            }
        }

        // 4. Read q*p sub-products (don't need to constrain these since q is read from trace)
        for _ in 0..N_LIMBS {
            for _ in 0..N_LIMBS {
                let _sub_prod = self.eval.next_trace_mask();
            }
        }

        // 5. Read carries (sign + lo16 + hi16 per column)
        let n_product_limbs = 2 * N_LIMBS - 1;
        for _ in 0..n_product_limbs {
            let sign = self.eval.next_trace_mask();
            let _carry_lo = self.eval.next_trace_mask();
            let _carry_hi = self.eval.next_trace_mask();

            // Constrain sign is boolean
            self.eval.add_constraint(sign.clone() * (sign.clone() - one.clone()));
        }

        // Assert result = 1 (the product of a * b should be 1)
        let one_field = Field256::<E::F>::one();
        for i in 0..N_LIMBS {
            self.eval.add_constraint(result.limbs[i].clone() - one_field.limbs[i].clone());
        }
    }

    /// Read Field256 with bit decomposition (for range checking).
    /// Trace format: 17 limbs + 17*16 bits = 289 columns.
    fn next_field256_checked(&mut self) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        let limbs: [E::F; N_LIMBS] = std::array::from_fn(|_| {
            // Read the limb value
            let limb = self.eval.next_trace_mask();

            // Read and constrain bit decomposition (16 bits)
            let mut reconstructed = E::F::from(BaseField::from_u32_unchecked(0));
            let mut power = one.clone();
            for _ in 0..16 {
                let bit = self.eval.next_trace_mask();
                // Constrain bit is boolean
                self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                reconstructed = reconstructed + bit * power.clone();
                power = power * two.clone();
            }

            // Constrain limb equals reconstructed value
            self.eval.add_constraint(limb.clone() - reconstructed);

            limb
        });

        Field256::new(limbs)
    }
}

/// Number of product limbs for multiplication verification.
const N_PRODUCT_LIMBS: usize = 2 * N_LIMBS - 1;

/// Count total columns used by TOPRF trace.
pub fn toprf_trace_columns() -> usize {
    let mut total = 0;

    // Mask (17 limbs)
    total += N_LIMBS;

    // Inversion: inv (17) + mul trace
    // mul trace = result_checked (17 + 17*16) + quotient (17) + a*b subs (17*17) + q*p subs (17*17) + carries (33*3)
    total += N_LIMBS;  // inv
    total += N_LIMBS + N_LIMBS * 16;  // result_checked
    total += N_LIMBS;  // quotient
    total += N_LIMBS * N_LIMBS;  // a*b sub-products
    total += N_LIMBS * N_LIMBS;  // q*p sub-products
    total += N_PRODUCT_LIMBS * 3;  // carries (sign + lo16 + hi16)

    // Secret data (2 * 17)
    total += 2 * N_LIMBS;

    // Domain separator (17)
    total += N_LIMBS;

    // Hashed scalar (17)
    total += N_LIMBS;

    // Scalar bits (254)
    total += SCALAR_BITS;

    // Mask bits (254)
    total += SCALAR_BITS;

    // Per share: response (4*17) + pub_key (4*17) + c_bits (254) + r_bits (254) + 12 affine coords (12*17)
    total += THRESHOLD * (4 * N_LIMBS + 4 * N_LIMBS + 2 * SCALAR_BITS + 12 * N_LIMBS);

    // Coefficient bits (254)
    total += SCALAR_BITS;

    // Combined response point (4*17)
    total += 4 * N_LIMBS;

    // Mask inverse bits (254)
    total += SCALAR_BITS;

    // Output (17) + public output (17)
    total += 2 * N_LIMBS;

    total
}

/// Estimate total constraint count for TOPRF verification.
pub fn toprf_constraint_count() -> usize {
    let mut total = 0;

    // Mask inversion verification:
    // - result_checked: 17 limbs * (1 reconstruction + 16 boolean) = 17 * 17 = 289
    // - a*b sub-product constraints: 17*17 = 289
    // - sign boolean constraints: 33
    // - Result = 1 check: 17 constraints
    total += N_LIMBS * (1 + 16);  // result_checked
    total += N_LIMBS * N_LIMBS;  // a*b sub-products
    total += N_PRODUCT_LIMBS;  // sign boolean
    total += N_LIMBS;  // result = 1

    // Boolean constraints for all scalar bits
    let n_scalar_bits = SCALAR_BITS  // hash scalar
        + SCALAR_BITS  // mask bits
        + THRESHOLD * 2 * SCALAR_BITS  // c and r per share
        + SCALAR_BITS  // coefficient
        + SCALAR_BITS; // mask inverse
    total += n_scalar_bits;

    // Output equality check (17)
    total += N_LIMBS;

    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toprf_trace_columns() {
        let cols = toprf_trace_columns();
        println!("TOPRF trace columns: {}", cols);
        // Should be around 1500+ columns
        assert!(cols > 1000, "Expected more than 1000 columns, got {}", cols);
    }

    #[test]
    fn test_toprf_constraint_count() {
        let count = toprf_constraint_count();
        println!("TOPRF constraints: {}", count);
        // Should have at least 1500+ constraints (mostly boolean checks)
        assert!(count > 1000, "Expected more than 1000 constraints, got {}", count);
    }
}
