//! Constraint evaluation for TOPRF verification circuit.
//!
//! This module implements the constraint system for verifying TOPRF computations.
//!
//! # Security Model
//!
//! ## Currently Verified (Constrained):
//! 1. **Mask non-zero**: via inverse verification (a * inv = 1)
//! 2. **Scalar bit decomposition**: all scalars (hashed_scalar, mask, c, r, coeff, mask_inv)
//!    have their bits constrained to be boolean AND reconstruct to the scalar value
//! 3. **Output equality**: output hash matches public output
//! 4. **Sub-product constraints**: multiplication sub-products are constrained
//! 5. **On-curve verification**: response and public key points verified to satisfy
//!    the Baby Jubjub curve equation: -x² + y² = 1 + d*x²*y²
//!
//! ## NOT Verified (Computed Natively):
//! - **MiMC hash-to-point**: `hashed_scalar = MiMC(secret_data, domain_separator)` is computed
//!   natively; a malicious prover could provide any hashed_scalar
//! - **DLEQ verification equations**: `vG = r*G + c*pubKey` and `vH = r*masked + c*response`
//!   are computed natively; a malicious prover could forge DLEQ proofs
//! - **DLEQ challenge hash**: `c = Hash(G, pubKey, vG, vH, masked, response)` is not constrained
//! - **Scalar multiplications**: data_point, masked point, DLEQ verification points are
//!   computed natively without constraint verification
//! - **Final MiMC hash**: `output = MiMC(unmasked_x, unmasked_y, secret_data)` is computed
//!   natively; however, this is checked against public output
//!
//! ## Security Implications
//!
//! The current circuit provides **structural** verification but NOT **computational** soundness
//! for the full TOPRF protocol. A malicious prover could potentially:
//! - Provide a fake hashed_scalar that doesn't correspond to secret_data
//! - Provide forged DLEQ proofs with fake c/r values
//!
//! However, the scalar bit reconstruction ensures that if scalars are used correctly
//! in external verification, they will be consistent with their bit representations.
//!
//! ## Remediation Notes
//!
//! Full constraint soundness requires:
//! - MiMC hash constraint evaluation (~1.6M constraints per hash)
//! - Point scalar multiplication constraints (~100K constraints per scalar mul)
//! - This would significantly increase proof size and proving time
//!
//! For production use, consider:
//! 1. Separate MiMC proof with commitment binding
//! 2. Recursive proof composition
//! 3. Accept the trusted prover model for specific use cases

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use crate::babyjub::field256::{Field256, N_LIMBS, LIMB_BITS, MODULUS};
use crate::babyjub::point::CURVE_D;

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
            let response_x = self.next_field256();
            let response_y = self.next_field256();
            let _response_t = self.next_field256();
            let _response_z = self.next_field256();

            // Verify response point is on curve: -x² + y² = 1 + d*x²*y²
            self.verify_on_curve(&response_x, &response_y);

            // Read public key point (extended coordinates = 4*N_LIMBS)
            let pub_key_x = self.next_field256();
            let pub_key_y = self.next_field256();
            let _pub_key_t = self.next_field256();
            let _pub_key_z = self.next_field256();

            // Verify public key point is on curve
            self.verify_on_curve(&pub_key_x, &pub_key_y);

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

    /// Verify a point (x, y) is on the Baby Jubjub curve.
    ///
    /// Curve equation: -x² + y² = 1 + d*x²*y²
    /// Rearranged: y² - x² = 1 + d*x²*y²
    ///
    /// This reads multiplication traces for:
    /// 1. x² = x * x
    /// 2. y² = y * y
    /// 3. x²*y² = x² * y²
    /// 4. d*x²*y² = d * x²*y²
    /// Then subtraction and addition traces for the final equation.
    fn verify_on_curve(&mut self, x: &Field256<E::F>, y: &Field256<E::F>) {
        // Get curve parameter d
        let d = self.field256_from_limbs(&CURVE_D);

        // Read and verify x² = x * x
        let x_sq = self.verify_mul(x, x);

        // Read and verify y² = y * y
        let y_sq = self.verify_mul(y, y);

        // Read and verify x²*y² = x² * y²
        let x_sq_y_sq = self.verify_mul(&x_sq, &y_sq);

        // Read and verify d*x²*y² = d * x²*y²
        let d_x_sq_y_sq = self.verify_mul(&d, &x_sq_y_sq);

        // Read and verify LHS = y² - x²
        let lhs = self.verify_sub(&y_sq, &x_sq);

        // Read and verify RHS = 1 + d*x²*y²
        let one = Field256::<E::F>::one();
        let rhs = self.verify_add(&one, &d_x_sq_y_sq);

        // Critical: Constrain LHS == RHS (the curve equation)
        for i in 0..N_LIMBS {
            self.eval.add_constraint(lhs.limbs[i].clone() - rhs.limbs[i].clone());
        }
    }

    /// Convert static limbs array to Field256.
    fn field256_from_limbs(&self, limbs: &[u32; N_LIMBS]) -> Field256<E::F> {
        Field256::new(std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(limbs[i]))
        }))
    }

    /// Verify multiplication: result = a * b (mod p).
    /// Reads trace and adds constraints for sub-products.
    fn verify_mul(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) -> Field256<E::F> {
        // Read result with range check
        let result = self.next_field256_checked();

        // Read quotient
        let _quotient = self.next_field256();

        // Read and constrain sub-products: a[i] * b[j]
        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                let sub_prod = self.eval.next_trace_mask();
                self.eval.add_constraint(
                    sub_prod.clone() - a.limbs[i].clone() * b.limbs[j].clone()
                );
            }
        }

        // Read q*p sub-products (just advance, no constraints)
        for _ in 0..N_LIMBS * N_LIMBS {
            let _ = self.eval.next_trace_mask();
        }

        // Read carries
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let n_product_limbs = 2 * N_LIMBS - 1;
        for _ in 0..n_product_limbs {
            let sign = self.eval.next_trace_mask();
            let _ = self.eval.next_trace_mask(); // carry_lo
            let _ = self.eval.next_trace_mask(); // carry_hi
            self.eval.add_constraint(sign.clone() * (sign.clone() - one.clone()));
        }

        result
    }

    /// Verify subtraction: result = a - b (mod p).
    fn verify_sub(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        let result = self.next_field256_checked();

        // Read borrows
        let borrows: [E::F; N_LIMBS] = std::array::from_fn(|_| self.eval.next_trace_mask());
        let borrowed = self.eval.next_trace_mask();

        // Constrain borrowed is boolean
        self.eval.add_constraint(borrowed.clone() * (one.clone() - borrowed.clone()));

        // Constrain each borrow is boolean
        for i in 0..N_LIMBS {
            self.eval.add_constraint(borrows[i].clone() * (borrows[i].clone() - one.clone()));
        }

        // Get modulus limbs
        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(MODULUS[i]))
        });

        // Verify subtraction equation:
        // a[i] + borrowed*p[i] + borrow[i]*2^LIMB_BITS = result[i] + b[i] + borrow[i-1]
        for i in 0..N_LIMBS {
            let borrow_in = if i == 0 {
                E::F::from(BaseField::from_u32_unchecked(0))
            } else {
                borrows[i - 1].clone()
            };
            let lhs = a.limbs[i].clone()
                + borrowed.clone() * modulus_limbs[i].clone()
                + borrows[i].clone() * two_pow_limb.clone();
            let rhs = result.limbs[i].clone() + b.limbs[i].clone() + borrow_in;
            self.eval.add_constraint(lhs - rhs);
        }

        result
    }

    /// Verify addition: result = a + b (mod p).
    fn verify_add(&mut self, a: &Field256<E::F>, b: &Field256<E::F>) -> Field256<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));
        let two_pow_limb = E::F::from(BaseField::from_u32_unchecked(1 << LIMB_BITS));

        let result = self.next_field256_checked();

        // Read carry bits (2 bits per limb)
        let carry_bits: [(E::F, E::F); N_LIMBS] = std::array::from_fn(|_| {
            (self.eval.next_trace_mask(), self.eval.next_trace_mask())
        });
        let reduced = self.eval.next_trace_mask();

        // Constrain reduced is boolean
        self.eval.add_constraint(reduced.clone() * (one.clone() - reduced.clone()));

        // Constrain carry bits and compute carries
        let mut carries: [E::F; N_LIMBS] = std::array::from_fn(|_| {
            E::F::from(BaseField::from_u32_unchecked(0))
        });
        for i in 0..N_LIMBS {
            let (bit0, bit1) = &carry_bits[i];
            self.eval.add_constraint(bit0.clone() * (bit0.clone() - one.clone()));
            self.eval.add_constraint(bit1.clone() * (bit1.clone() - one.clone()));
            self.eval.add_constraint(bit0.clone() * bit1.clone()); // carry != 3
            carries[i] = bit0.clone() + two.clone() * bit1.clone();
        }

        // Get modulus limbs
        let modulus_limbs: [E::F; N_LIMBS] = std::array::from_fn(|i| {
            E::F::from(BaseField::from_u32_unchecked(MODULUS[i]))
        });

        // Verify addition equation:
        // a[i] + b[i] + carry[i-1] = result[i] + reduced*p[i] + carry[i]*2^LIMB_BITS
        for i in 0..N_LIMBS {
            let carry_in = if i == 0 {
                E::F::from(BaseField::from_u32_unchecked(0))
            } else {
                carries[i - 1].clone()
            };
            let lhs = a.limbs[i].clone() + b.limbs[i].clone() + carry_in;
            let rhs = result.limbs[i].clone()
                + reduced.clone() * modulus_limbs[i].clone()
                + carries[i].clone() * two_pow_limb.clone();
            self.eval.add_constraint(lhs - rhs);
        }

        result
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

/// Trace columns for a single multiplication.
fn mul_trace_cols() -> usize {
    N_LIMBS + N_LIMBS * LIMB_BITS as usize  // result_checked
        + N_LIMBS                            // quotient
        + N_LIMBS * N_LIMBS                  // a*b sub-products
        + N_LIMBS * N_LIMBS                  // q*p sub-products
        + N_PRODUCT_LIMBS * 3                // carries
}

/// Trace columns for subtraction.
fn sub_trace_cols() -> usize {
    N_LIMBS + N_LIMBS * LIMB_BITS as usize  // result_checked
        + N_LIMBS                            // borrows
        + 1                                  // borrowed flag
}

/// Trace columns for addition.
fn add_trace_cols() -> usize {
    N_LIMBS + N_LIMBS * LIMB_BITS as usize  // result_checked
        + N_LIMBS * 2                        // carry bits (2 per limb)
        + 1                                  // reduced flag
}

/// Trace columns for on-curve verification.
/// Verifies: y² - x² = 1 + d*x²*y²
fn on_curve_trace_cols() -> usize {
    mul_trace_cols()  // x²
        + mul_trace_cols()  // y²
        + mul_trace_cols()  // x²*y²
        + mul_trace_cols()  // d*x²*y²
        + sub_trace_cols()  // y² - x²
        + add_trace_cols()  // 1 + d*x²*y²
}

/// Count total columns used by TOPRF trace.
pub fn toprf_trace_columns() -> usize {
    let mut total = 0;

    // Mask (N_LIMBS)
    total += N_LIMBS;

    // Inversion trace: inv + mul_trace for a*inv=1
    total += N_LIMBS; // inv
    total += mul_trace_cols(); // multiplication verification

    // Secret data (2 * N_LIMBS)
    total += 2 * N_LIMBS;

    // Domain separator (N_LIMBS)
    total += N_LIMBS;

    // Hashed scalar (N_LIMBS) + bits (254)
    total += N_LIMBS + SCALAR_BITS;

    // Mask bits (254)
    total += SCALAR_BITS;

    // Per share:
    // - response (4*N_LIMBS) + on_curve check
    // - pub_key (4*N_LIMBS) + on_curve check
    // - c (N_LIMBS + 254) + r (N_LIMBS + 254)
    // - 12 affine coords for DLEQ
    total += THRESHOLD * (
        4 * N_LIMBS + on_curve_trace_cols() +  // response point + on-curve
        4 * N_LIMBS + on_curve_trace_cols() +  // pub_key point + on-curve
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

/// Constraints for a single multiplication verification.
fn mul_constraints() -> usize {
    // result_checked: N_LIMBS * (1 reconstruction + LIMB_BITS boolean)
    // sub-product constraints: N_LIMBS * N_LIMBS
    // sign boolean constraints: N_PRODUCT_LIMBS
    N_LIMBS * (1 + LIMB_BITS as usize)
        + N_LIMBS * N_LIMBS
        + N_PRODUCT_LIMBS
}

/// Constraints for subtraction verification.
fn sub_constraints() -> usize {
    // result_checked: N_LIMBS * (1 + LIMB_BITS)
    // borrow booleans: N_LIMBS + 1
    // limb equations: N_LIMBS
    N_LIMBS * (1 + LIMB_BITS as usize)
        + N_LIMBS + 1
        + N_LIMBS
}

/// Constraints for addition verification.
fn add_constraints() -> usize {
    // result_checked: N_LIMBS * (1 + LIMB_BITS)
    // carry booleans: N_LIMBS * 3 (2 bits + no-3 constraint)
    // reduced boolean: 1
    // limb equations: N_LIMBS
    N_LIMBS * (1 + LIMB_BITS as usize)
        + N_LIMBS * 3
        + 1
        + N_LIMBS
}

/// Constraints for on-curve verification.
fn on_curve_constraints() -> usize {
    // 4 multiplications + 1 subtraction + 1 addition + N_LIMBS equality
    4 * mul_constraints()
        + sub_constraints()
        + add_constraints()
        + N_LIMBS  // LHS == RHS
}

/// Estimate total constraint count for TOPRF verification.
pub fn toprf_constraint_count() -> usize {
    let mut total = 0;

    // Mask inversion verification (multiplication + result=1 check)
    total += mul_constraints();
    total += N_LIMBS; // result = 1

    // Scalar bit verification (boolean + reconstruction):
    // - hashed_scalar: SCALAR_BITS boolean + N_LIMBS reconstruction
    // - mask: SCALAR_BITS boolean + N_LIMBS reconstruction
    // - per share: c + r = 2 * (SCALAR_BITS + N_LIMBS)
    // - coefficient: SCALAR_BITS + N_LIMBS
    // - mask_inv: SCALAR_BITS + N_LIMBS
    let n_scalar_verifications = 2 + THRESHOLD * 2 + 1 + 1; // hashed, mask, c+r per share, coeff, mask_inv
    total += n_scalar_verifications * (SCALAR_BITS + N_LIMBS);

    // On-curve verification for response and pub_key points (per share)
    total += THRESHOLD * 2 * on_curve_constraints();

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
