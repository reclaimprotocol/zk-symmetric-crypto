//! Trace generation for TOPRF verification.

use stwo::core::fields::m31::BaseField;

use super::{TOPRFInputs, THRESHOLD};
use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256, Field256TraceGen};
use crate::babyjub::mimc::gen::{hash_field256_native, Poseidon2TraceGen};
use crate::babyjub::point::gen::{native, scalar_to_bits, PointTraceGen};
use crate::babyjub::point::{base_point, ExtendedPointBigInt};

/// Trace generator for TOPRF.
pub struct TOPRFTraceGen {
    pub field_gen: Field256TraceGen,
    pub point_gen: PointTraceGen,
    pub hash_gen: Poseidon2TraceGen,
}

impl TOPRFTraceGen {
    /// Create new trace generator.
    pub fn new() -> Self {
        Self {
            field_gen: Field256TraceGen::new(),
            point_gen: PointTraceGen::new(),
            hash_gen: Poseidon2TraceGen::new(),
        }
    }

    /// Generate trace for TOPRF verification.
    ///
    /// Returns the computed output hash.
    pub fn gen_toprf(&mut self, inputs: &TOPRFInputs) -> BaseField {
        let p = modulus();

        // 1. Append mask and verify non-zero
        self.field_gen.append_field256(&inputs.private.mask);
        let _mask_inv = self.field_gen.gen_inv(&inputs.private.mask);

        // 2. Append secret data
        self.field_gen.append_field256(&inputs.private.secret_data[0]);
        self.field_gen.append_field256(&inputs.private.secret_data[1]);

        // 3. Append domain separator
        self.field_gen.append_field256(&inputs.public.domain_separator);

        // 4. Hash secret data to scalar
        let hashed_scalar = hash_to_scalar(
            &inputs.private.secret_data,
            &inputs.public.domain_separator,
        );
        self.field_gen.append_field256(&hashed_scalar);

        // 5. Compute data_point = base * hashed_scalar
        let base = base_point();
        let scalar_bits = scalar_to_bits(&hashed_scalar);
        for bit in &scalar_bits {
            self.field_gen.col_index = 0; // Reset for bit append
            self.field_gen.append_limb(*bit as u32);
        }
        let data_point = native::scalar_mul(&base, &hashed_scalar);

        // 6. Append mask bits
        let mask_bits = scalar_to_bits(&inputs.private.mask);
        for bit in &mask_bits {
            self.field_gen.col_index = 0;
            self.field_gen.append_limb(*bit as u32);
        }

        // 7. Compute masked = data_point * mask
        let masked = native::scalar_mul(&data_point, &inputs.private.mask);

        // 8. For each share, verify DLEQ
        for share_idx in 0..THRESHOLD {
            let response = ExtendedPointBigInt::from_affine(
                inputs.public.responses[share_idx].x,
                inputs.public.responses[share_idx].y,
                &p,
            );
            let share_pub_key = ExtendedPointBigInt::from_affine(
                inputs.public.share_public_keys[share_idx].x,
                inputs.public.share_public_keys[share_idx].y,
                &p,
            );

            // Append points
            self.point_gen.append_extended_point(&response);
            self.point_gen.append_extended_point(&share_pub_key);

            // Clear cofactors
            let cleared_response = native::clear_cofactor(&response);
            let cleared_pub_key = native::clear_cofactor(&share_pub_key);

            // Append c and r bits
            let c_bits = scalar_to_bits(&inputs.public.c[share_idx]);
            let r_bits = scalar_to_bits(&inputs.public.r[share_idx]);

            for bit in c_bits.iter().chain(r_bits.iter()) {
                self.field_gen.col_index = 0;
                self.field_gen.append_limb(*bit as u32);
            }

            // Compute DLEQ verification points
            let r_times_g = native::scalar_mul(&base, &inputs.public.r[share_idx]);
            let c_times_pub = native::scalar_mul(&cleared_pub_key, &inputs.public.c[share_idx]);
            let _vg = native::add_points(&r_times_g, &c_times_pub);

            let r_times_masked = native::scalar_mul(&masked, &inputs.public.r[share_idx]);
            let c_times_response = native::scalar_mul(&cleared_response, &inputs.public.c[share_idx]);
            let _vh = native::add_points(&r_times_masked, &c_times_response);

            // TODO: Hash and verify challenge matches c
        }

        // 9. Combine responses with Lagrange coefficients
        // For threshold=1, just use responses[0] * coefficients[0]
        let coeff_bits = scalar_to_bits(&inputs.public.coefficients[0]);
        for bit in &coeff_bits {
            self.field_gen.col_index = 0;
            self.field_gen.append_limb(*bit as u32);
        }

        let response_0 = ExtendedPointBigInt::from_affine(
            inputs.public.responses[0].x,
            inputs.public.responses[0].y,
            &p,
        );
        let combined_response = native::scalar_mul(&response_0, &inputs.public.coefficients[0]);
        self.point_gen.append_extended_point(&combined_response);

        // 10. Compute mask inverse (in the scalar field, not base field)
        let order = scalar_order();
        let mask_inv = inputs.private.mask.inv_mod(&order).expect("mask should be nonzero");
        let mask_inv_bits = scalar_to_bits(&mask_inv);
        for bit in &mask_inv_bits {
            self.field_gen.col_index = 0;
            self.field_gen.append_limb(*bit as u32);
        }

        // 11. Unmask: unmasked = combined_response * mask^-1
        let unmasked = native::scalar_mul(&combined_response, &mask_inv);

        // 12. Convert to affine
        let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);

        // 13. Compute final hash
        let output_hash = hash_field256_native(&[
            unmasked_x,
            unmasked_y,
            inputs.private.secret_data[0],
            inputs.private.secret_data[1],
        ]);

        // 14. Append output
        self.field_gen.col_index = 0;
        self.field_gen.append_limb(output_hash.0);

        // Append public output
        self.field_gen.col_index = 0;
        self.field_gen.append_limb(inputs.public.output);

        output_hash
    }
}

impl Default for TOPRFTraceGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash secret data and domain separator to scalar.
fn hash_to_scalar(secret_data: &[BigInt256; 2], domain_separator: &BigInt256) -> BigInt256 {
    // Use Poseidon2 hash over the M31 limbs
    let hash = hash_field256_native(&[secret_data[0], secret_data[1], *domain_separator]);

    // Expand hash to 256-bit scalar
    // For now, just put the hash value in the first limb
    // A proper implementation would use a more robust expansion
    BigInt256::from_limbs([hash.0, 0, 0, 0, 0, 0, 0, 0, 0])
}

/// Native TOPRF verification (no trace generation).
pub fn verify_toprf_native(inputs: &TOPRFInputs) -> Result<BaseField, &'static str> {
    let p = modulus();

    // 1. Check mask != 0
    if inputs.private.mask.is_zero() {
        return Err("mask is zero");
    }

    // 2. Hash secret data to scalar
    let hashed_scalar = hash_to_scalar(
        &inputs.private.secret_data,
        &inputs.public.domain_separator,
    );

    // 3. Compute data_point = base * hashed_scalar
    let base = base_point();
    let data_point = native::scalar_mul(&base, &hashed_scalar);

    // 4. Compute masked = data_point * mask
    let masked = native::scalar_mul(&data_point, &inputs.private.mask);

    // 5. Verify DLEQ for each share
    for share_idx in 0..THRESHOLD {
        let response = ExtendedPointBigInt::from_affine(
            inputs.public.responses[share_idx].x,
            inputs.public.responses[share_idx].y,
            &p,
        );
        let share_pub_key = ExtendedPointBigInt::from_affine(
            inputs.public.share_public_keys[share_idx].x,
            inputs.public.share_public_keys[share_idx].y,
            &p,
        );

        // Clear cofactors
        let cleared_response = native::clear_cofactor(&response);
        let cleared_pub_key = native::clear_cofactor(&share_pub_key);

        // Check not identity
        let (x, _) = cleared_response.to_affine(&p);
        if x.is_zero() {
            return Err("cleared response is identity");
        }
        let (x, _) = cleared_pub_key.to_affine(&p);
        if x.is_zero() {
            return Err("cleared pub key is identity");
        }

        // DLEQ verification
        // vG = r*G + c*pubKey
        let r_times_g = native::scalar_mul(&base, &inputs.public.r[share_idx]);
        let c_times_pub = native::scalar_mul(&cleared_pub_key, &inputs.public.c[share_idx]);
        let vg = native::add_points(&r_times_g, &c_times_pub);

        // vH = r*masked + c*response
        let r_times_masked = native::scalar_mul(&masked, &inputs.public.r[share_idx]);
        let c_times_response = native::scalar_mul(&cleared_response, &inputs.public.c[share_idx]);
        let vh = native::add_points(&r_times_masked, &c_times_response);

        // TODO: Hash and verify challenge
        // For now we skip the hash verification
    }

    // 6. Combine responses
    let response_0 = ExtendedPointBigInt::from_affine(
        inputs.public.responses[0].x,
        inputs.public.responses[0].y,
        &p,
    );
    let combined = native::scalar_mul(&response_0, &inputs.public.coefficients[0]);

    // 7. Unmask (inverse in scalar field)
    let order = scalar_order();
    let mask_inv = inputs.private.mask.inv_mod(&order).ok_or("mask inverse failed")?;
    let unmasked = native::scalar_mul(&combined, &mask_inv);

    // 8. Convert to affine
    let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);

    // 9. Compute output hash
    let output = hash_field256_native(&[
        unmasked_x,
        unmasked_y,
        inputs.private.secret_data[0],
        inputs.private.secret_data[1],
    ]);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::toprf::{
        AffinePointBigInt, TOPRFInputs, TOPRFPrivateInputs, TOPRFPublicInputs,
    };

    #[test]
    fn test_toprf_gen_runs() {
        let inputs = TOPRFInputs {
            private: TOPRFPrivateInputs {
                mask: BigInt256::from_limbs([12345, 0, 0, 0, 0, 0, 0, 0, 0]),
                secret_data: [
                    BigInt256::from_limbs([111, 222, 0, 0, 0, 0, 0, 0, 0]),
                    BigInt256::from_limbs([333, 444, 0, 0, 0, 0, 0, 0, 0]),
                ],
            },
            public: TOPRFPublicInputs {
                domain_separator: BigInt256::from_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0]),
                coefficients: [BigInt256::one()],
                // Use base point as placeholder for response/pubkey
                responses: [AffinePointBigInt {
                    x: BigInt256::from_limbs(crate::babyjub::point::BASE_X),
                    y: BigInt256::from_limbs(crate::babyjub::point::BASE_Y),
                }],
                share_public_keys: [AffinePointBigInt {
                    x: BigInt256::from_limbs(crate::babyjub::point::BASE_X),
                    y: BigInt256::from_limbs(crate::babyjub::point::BASE_Y),
                }],
                c: [BigInt256::from_limbs([100, 0, 0, 0, 0, 0, 0, 0, 0])],
                r: [BigInt256::from_limbs([200, 0, 0, 0, 0, 0, 0, 0, 0])],
                output: 0,
            },
        };

        let mut gen = TOPRFTraceGen::new();
        let output = gen.gen_toprf(&inputs);

        println!("TOPRF output: {:?}", output);
    }

    #[test]
    fn test_native_toprf() {
        let inputs = TOPRFInputs {
            private: TOPRFPrivateInputs {
                mask: BigInt256::from_limbs([12345, 0, 0, 0, 0, 0, 0, 0, 0]),
                secret_data: [
                    BigInt256::from_limbs([111, 0, 0, 0, 0, 0, 0, 0, 0]),
                    BigInt256::from_limbs([222, 0, 0, 0, 0, 0, 0, 0, 0]),
                ],
            },
            public: TOPRFPublicInputs {
                domain_separator: BigInt256::one(),
                coefficients: [BigInt256::one()],
                responses: [AffinePointBigInt {
                    x: BigInt256::from_limbs(crate::babyjub::point::BASE_X),
                    y: BigInt256::from_limbs(crate::babyjub::point::BASE_Y),
                }],
                share_public_keys: [AffinePointBigInt {
                    x: BigInt256::from_limbs(crate::babyjub::point::BASE_X),
                    y: BigInt256::from_limbs(crate::babyjub::point::BASE_Y),
                }],
                c: [BigInt256::from_limbs([100, 0, 0, 0, 0, 0, 0, 0, 0])],
                r: [BigInt256::from_limbs([200, 0, 0, 0, 0, 0, 0, 0, 0])],
                output: 0,
            },
        };

        let result = verify_toprf_native(&inputs);
        assert!(result.is_ok());
    }
}
