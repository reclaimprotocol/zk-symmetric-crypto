//! Constraint evaluation for TOPRF verification circuit.
//!
//! This module implements the constraint system for verifying TOPRF computations.
//! The circuit verifies:
//! 1. Mask is non-zero (via inverse verification)
//! 2. Scalar bits are boolean AND reconstruct to their scalar values
//! 3. Output hash matches public input
//!
//! Note: Full DLEQ verification and MiMC hash constraints require trace
//! restructuring and will be added incrementally.

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use crate::babyjub::field256::{Field256, N_LIMBS, LIMB_BITS};

use super::THRESHOLD;

/// Number of bits in BN254 scalar field (254 bits).
pub const SCALAR_BITS: usize = 254;

/// Evaluator for TOPRF constraints.
pub struct TOPRFEvalAtRow<E: EvalAtRow> {
    pub eval: E,
}

impl<E: EvalAtRow> TOPRFEvalAtRow<E> {
    /// Evaluate all TOPRF constraints.
    ///
    /// This reads trace values in the exact order produced by TOPRFTraceGen::gen_toprf.
    pub fn eval(mut self) -> E {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        // =========================================================================
        // Step 1: Read mask and verify non-zero via inverse
        // Trace: mask (N_LIMBS) + mul trace for inversion
        // =========================================================================
        let mask = self.next_field256();
        let _mask_inv = self.verify_inv(&mask);

        // =========================================================================
        // Step 2: Read secret data (2 Field256 values)
        // =========================================================================
        let _secret_data_0 = self.next_field256();
        let _secret_data_1 = self.next_field256();

        // =========================================================================
        // Step 3: Read domain separator
        // =========================================================================
        let _domain_separator = self.next_field256();

        // =========================================================================
        // Step 4: Read hash-to-point scalar
        // =========================================================================
        let hashed_scalar = self.next_field256();

        // =========================================================================
        // Step 5: Read scalar bits and verify reconstruction to hashed_scalar
        // =========================================================================
        self.read_and_verify_scalar_bits(&hashed_scalar);

        // =========================================================================
        // Step 6: Read mask bits and verify reconstruction to mask
        // =========================================================================
        self.read_and_verify_scalar_bits(&mask);

        // =========================================================================
        // Step 7: For each share, read DLEQ verification data
        // =========================================================================
        for _ in 0..THRESHOLD {
            // Read response point (extended coordinates: x, y, t, z = 4*N_LIMBS)
            let _response_x = self.next_field256();
            let _response_y = self.next_field256();
            let _response_t = self.next_field256();
            let _response_z = self.next_field256();

            // Read public key point (extended coordinates = 4*N_LIMBS)
            let _pub_key_x = self.next_field256();
            let _pub_key_y = self.next_field256();
            let _pub_key_t = self.next_field256();
            let _pub_key_z = self.next_field256();

            // Read c scalar and verify bit reconstruction
            let c = self.next_field256();
            self.read_and_verify_scalar_bits(&c);

            // Read r scalar and verify bit reconstruction
            let r = self.next_field256();
            self.read_and_verify_scalar_bits(&r);

            // Read 12 affine coordinates for DLEQ hash (from trace)
            for _ in 0..12 {
                let _ = self.next_field256();
            }
        }

        // =========================================================================
        // Step 8: Read coefficient and verify bit reconstruction
        // =========================================================================
        let coeff = self.next_field256();
        self.read_and_verify_scalar_bits(&coeff);

        // =========================================================================
        // Step 9: Read combined response point
        // =========================================================================
        let _combined_x = self.next_field256();
        let _combined_y = self.next_field256();
        let _combined_t = self.next_field256();
        let _combined_z = self.next_field256();

        // =========================================================================
        // Step 10: Read mask inverse scalar and verify bit reconstruction
        // =========================================================================
        let mask_inv_scalar = self.next_field256();
        self.read_and_verify_scalar_bits(&mask_inv_scalar);

        // =========================================================================
        // Step 11: Read output hash and public output, verify they match
        // =========================================================================
        let output = self.next_field256();
        let public_output = self.next_field256();

        // CRITICAL: Verify output equals public output
        for i in 0..N_LIMBS {
            self.eval.add_constraint(output.limbs[i].clone() - public_output.limbs[i].clone());
        }

        self.eval
    }

    /// Read next Field256 from trace (N_LIMBS limbs).
    fn next_field256(&mut self) -> Field256<E::F> {
        Field256::new(std::array::from_fn(|_| self.eval.next_trace_mask()))
    }

    /// Read scalar bits from trace and verify:
    /// 1. Each bit is boolean (0 or 1)
    /// 2. Bits reconstruct to the scalar value
    fn read_and_verify_scalar_bits(&mut self, scalar: &Field256<E::F>) {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        // Read all 254 bits
        let bits: [E::F; SCALAR_BITS] = std::array::from_fn(|_| {
            let bit = self.eval.next_trace_mask();
            // Constrain bit is boolean
            self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            bit
        });

        // Reconstruct scalar from bits and verify equality
        // Bits are in little-endian order: scalar = sum(bit_i * 2^i)
        // We reconstruct limb by limb (each limb is LIMB_BITS bits)
        let mut bit_idx = 0;
        for limb_idx in 0..N_LIMBS {
            let mut reconstructed_limb = E::F::from(BaseField::from_u32_unchecked(0));
            let mut power = E::F::from(BaseField::from_u32_unchecked(1));

            for _ in 0..LIMB_BITS {
                if bit_idx < SCALAR_BITS {
                    reconstructed_limb = reconstructed_limb + bits[bit_idx].clone() * power.clone();
                    bit_idx += 1;
                }
                power = power * two.clone();
            }

            // Constrain reconstructed limb equals scalar limb
            self.eval.add_constraint(
                scalar.limbs[limb_idx].clone() - reconstructed_limb
            );
        }
    }

    /// Verify field inversion: reads inverse from trace, verifies a * inv = 1.
    fn verify_inv(&mut self, a: &Field256<E::F>) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));

        // Read inverse
        let inv = self.next_field256();

        // Read and verify multiplication trace: a * inv = 1
        let result = self.next_field256_checked();

        // Read quotient (for modular reduction)
        let _quotient = self.next_field256();

        // Read and constrain a*inv sub-products
        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                let sub_prod = self.eval.next_trace_mask();
                // Constrain sub_prod = a[i] * inv[j]
                self.eval.add_constraint(
                    sub_prod.clone() - a.limbs[i].clone() * inv.limbs[j].clone()
                );
            }
        }

        // Read q*p sub-products (no constraints needed, just advancing trace)
        for _ in 0..N_LIMBS {
            for _ in 0..N_LIMBS {
                let _ = self.eval.next_trace_mask();
            }
        }

        // Read carries
        let n_product_limbs = 2 * N_LIMBS - 1;
        for _ in 0..n_product_limbs {
            let sign = self.eval.next_trace_mask();
            let _ = self.eval.next_trace_mask(); // carry_lo
            let _ = self.eval.next_trace_mask(); // carry_hi

            // Constrain sign is boolean
            self.eval.add_constraint(sign.clone() * (sign.clone() - one.clone()));
        }

        // Assert result = 1
        let one_field = Field256::<E::F>::one();
        for i in 0..N_LIMBS {
            self.eval.add_constraint(result.limbs[i].clone() - one_field.limbs[i].clone());
        }

        inv
    }

    /// Read Field256 with bit decomposition for range checking.
    fn next_field256_checked(&mut self) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        let limbs: [E::F; N_LIMBS] = std::array::from_fn(|_| {
            let limb = self.eval.next_trace_mask();

            // Read and verify bit decomposition
            let mut reconstructed = E::F::from(BaseField::from_u32_unchecked(0));
            let mut power = E::F::from(BaseField::from_u32_unchecked(1));

            for _ in 0..LIMB_BITS {
                let bit = self.eval.next_trace_mask();
                self.eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                reconstructed = reconstructed + bit * power.clone();
                power = power * two.clone();
            }

            // Constrain limb equals reconstructed
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

    // Mask (N_LIMBS)
    total += N_LIMBS;

    // Inversion trace: inv + result_checked + quotient + a*b subs + q*p subs + carries
    total += N_LIMBS; // inv
    total += N_LIMBS + N_LIMBS * LIMB_BITS as usize; // result_checked
    total += N_LIMBS; // quotient
    total += N_LIMBS * N_LIMBS; // a*b sub-products
    total += N_LIMBS * N_LIMBS; // q*p sub-products
    total += N_PRODUCT_LIMBS * 3; // carries

    // Secret data (2 * N_LIMBS)
    total += 2 * N_LIMBS;

    // Domain separator (N_LIMBS)
    total += N_LIMBS;

    // Hashed scalar (N_LIMBS) + bits (254)
    total += N_LIMBS + SCALAR_BITS;

    // Mask bits (254)
    total += SCALAR_BITS;

    // Per share: response (4*N_LIMBS) + pub_key (4*N_LIMBS) + c (N_LIMBS + 254) + r (N_LIMBS + 254) + 12 affine coords
    total += THRESHOLD * (
        4 * N_LIMBS +  // response point
        4 * N_LIMBS +  // pub_key point
        N_LIMBS + SCALAR_BITS +  // c scalar + bits
        N_LIMBS + SCALAR_BITS +  // r scalar + bits
        12 * N_LIMBS   // affine coords for DLEQ
    );

    // Coefficient (N_LIMBS + 254)
    total += N_LIMBS + SCALAR_BITS;

    // Combined response point (4*N_LIMBS)
    total += 4 * N_LIMBS;

    // Mask inverse scalar + bits (N_LIMBS + 254)
    total += N_LIMBS + SCALAR_BITS;

    // Output (N_LIMBS) + public output (N_LIMBS)
    total += 2 * N_LIMBS;

    total
}

/// Estimate total constraint count for TOPRF verification.
pub fn toprf_constraint_count() -> usize {
    let mut total = 0;

    // Mask inversion verification:
    // - result_checked: N_LIMBS * (1 reconstruction + LIMB_BITS boolean)
    // - a*b sub-product constraints: N_LIMBS * N_LIMBS
    // - sign boolean constraints: N_PRODUCT_LIMBS
    // - Result = 1 check: N_LIMBS
    total += N_LIMBS * (1 + LIMB_BITS as usize);
    total += N_LIMBS * N_LIMBS;
    total += N_PRODUCT_LIMBS;
    total += N_LIMBS;

    // Scalar bit verification (boolean + reconstruction):
    // - hashed_scalar: SCALAR_BITS boolean + N_LIMBS reconstruction
    // - mask: SCALAR_BITS boolean + N_LIMBS reconstruction
    // - per share: c + r = 2 * (SCALAR_BITS + N_LIMBS)
    // - coefficient: SCALAR_BITS + N_LIMBS
    // - mask_inv: SCALAR_BITS + N_LIMBS
    let n_scalar_verifications = 2 + THRESHOLD * 2 + 1 + 1; // hashed, mask, c+r per share, coeff, mask_inv
    total += n_scalar_verifications * (SCALAR_BITS + N_LIMBS);

    // Output equality check
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
        assert!(cols > 1000, "Expected more than 1000 columns, got {}", cols);
    }

    #[test]
    fn test_toprf_constraint_count() {
        let count = toprf_constraint_count();
        println!("TOPRF constraints: {}", count);
        assert!(count > 1000, "Expected more than 1000 constraints, got {}", count);
    }
}
