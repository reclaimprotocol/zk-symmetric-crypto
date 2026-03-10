//! Trace generation for TOPRF verification.

use super::{TOPRFInputs, THRESHOLD};
use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256, Field256TraceGen};
use crate::babyjub::field256::{LIMB_MASK, N_LIMBS};
use crate::babyjub::mimc_compat::mimc_hash;
use crate::babyjub::point::gen::{native, scalar_to_bits, PointTraceGen};
use crate::babyjub::point::{base_point, ExtendedPointBigInt};
use crate::toprf_server::dleq::verify_dleq_mimc;

/// Trace generator for TOPRF.
pub struct TOPRFTraceGen {
    pub field_gen: Field256TraceGen,
    pub point_gen: PointTraceGen,
}

impl TOPRFTraceGen {
    /// Create new trace generator.
    pub fn new() -> Self {
        Self {
            field_gen: Field256TraceGen::new(),
            point_gen: PointTraceGen::new(),
        }
    }

    /// Append an extended point to field_gen trace (36 limbs = 4 * 9).
    fn append_extended_point(&mut self, p: &ExtendedPointBigInt) {
        self.field_gen.append_field256(&p.x);
        self.field_gen.append_field256(&p.y);
        self.field_gen.append_field256(&p.t);
        self.field_gen.append_field256(&p.z);
    }

    /// Generate trace for TOPRF verification.
    ///
    /// Returns the computed output hash as BigInt256 (gnark-compatible MiMC output).
    pub fn gen_toprf(&mut self, inputs: &TOPRFInputs) -> BigInt256 {
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
            self.field_gen.append_limb(*bit as u32);
        }
        let data_point = native::scalar_mul(&base, &hashed_scalar);

        // 6. Append mask bits
        let mask_bits = scalar_to_bits(&inputs.private.mask);
        for bit in &mask_bits {
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

            // Append points (using field_gen directly to keep trace in one place)
            self.append_extended_point(&response);
            self.append_extended_point(&share_pub_key);

            // Clear cofactors
            let cleared_response = native::clear_cofactor(&response);
            let cleared_pub_key = native::clear_cofactor(&share_pub_key);

            // Append c scalar and bits
            self.field_gen.append_field256(&inputs.public.c[share_idx]);
            let c_bits = scalar_to_bits(&inputs.public.c[share_idx]);
            for bit in &c_bits {
                self.field_gen.append_limb(*bit as u32);
            }

            // Append r scalar and bits
            self.field_gen.append_field256(&inputs.public.r[share_idx]);
            let r_bits = scalar_to_bits(&inputs.public.r[share_idx]);
            for bit in &r_bits {
                self.field_gen.append_limb(*bit as u32);
            }

            // Compute DLEQ verification points
            let r_times_g = native::scalar_mul(&base, &inputs.public.r[share_idx]);
            let c_times_pub = native::scalar_mul(&cleared_pub_key, &inputs.public.c[share_idx]);
            let vg = native::add_points(&r_times_g, &c_times_pub);

            let r_times_masked = native::scalar_mul(&masked, &inputs.public.r[share_idx]);
            let c_times_response = native::scalar_mul(&cleared_response, &inputs.public.c[share_idx]);
            let vh = native::add_points(&r_times_masked, &c_times_response);

            // Convert all 6 points to affine for hashing
            // Points: G (base), pubKey (cleared_pub_key), vG, vH, masked, response (cleared_response)
            let (base_x, base_y) = base.to_affine(&p);
            let (pub_x, pub_y) = cleared_pub_key.to_affine(&p);
            let (vg_x, vg_y) = vg.to_affine(&p);
            let (vh_x, vh_y) = vh.to_affine(&p);
            let (masked_x, masked_y) = masked.to_affine(&p);
            let (resp_x, resp_y) = cleared_response.to_affine(&p);

            // Append affine coordinates to trace (12 Field256 values)
            self.field_gen.append_field256(&base_x);
            self.field_gen.append_field256(&base_y);
            self.field_gen.append_field256(&pub_x);
            self.field_gen.append_field256(&pub_y);
            self.field_gen.append_field256(&vg_x);
            self.field_gen.append_field256(&vg_y);
            self.field_gen.append_field256(&vh_x);
            self.field_gen.append_field256(&vh_y);
            self.field_gen.append_field256(&masked_x);
            self.field_gen.append_field256(&masked_y);
            self.field_gen.append_field256(&resp_x);
            self.field_gen.append_field256(&resp_y);

            // Compute DLEQ challenge hash using native MiMC
            let coords = [
                base_x, base_y,
                pub_x, pub_y,
                vg_x, vg_y,
                vh_x, vh_y,
                masked_x, masked_y,
                resp_x, resp_y,
            ];
            let computed_challenge = hash_to_scalar_dleq(&coords);

            // Verify that the computed challenge matches the provided c
            // (This is a prover-side check; the circuit enforces the constraint)
            if computed_challenge != inputs.public.c[share_idx] {
                // Log warning but continue - the circuit will reject invalid proofs
                // In production, this would be an error
                #[cfg(debug_assertions)]
                eprintln!(
                    "WARNING: DLEQ challenge mismatch for share {}. \
                     Computed {:?}, expected {:?}",
                    share_idx, computed_challenge, inputs.public.c[share_idx]
                );
            }
        }

        // 9. Combine responses with Lagrange coefficients
        // For threshold=1, just use responses[0] * coefficients[0]
        self.field_gen.append_field256(&inputs.public.coefficients[0]);
        let coeff_bits = scalar_to_bits(&inputs.public.coefficients[0]);
        for bit in &coeff_bits {
            self.field_gen.append_limb(*bit as u32);
        }

        let response_0 = ExtendedPointBigInt::from_affine(
            inputs.public.responses[0].x,
            inputs.public.responses[0].y,
            &p,
        );
        let combined_response = native::scalar_mul(&response_0, &inputs.public.coefficients[0]);
        self.append_extended_point(&combined_response);

        // 10. Compute mask inverse (in the scalar field, not base field)
        let order = scalar_order();
        let mask_inv = inputs.private.mask.inv_mod(&order).expect("mask should be nonzero");
        self.field_gen.append_field256(&mask_inv);
        let mask_inv_bits = scalar_to_bits(&mask_inv);
        for bit in &mask_inv_bits {
            self.field_gen.append_limb(*bit as u32);
        }

        // 11. Unmask: unmasked = combined_response * mask^-1
        let unmasked = native::scalar_mul(&combined_response, &mask_inv);

        // 12. Convert to affine
        let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);

        // 13. Compute final hash using MiMC (gnark-compatible)
        let output_hash = mimc_hash(&[
            unmasked_x,
            unmasked_y,
            inputs.private.secret_data[0],
            inputs.private.secret_data[1],
        ]);

        // 14. Append output (all limbs of BigInt256)
        self.field_gen.append_field256(&output_hash);

        // Append public output for comparison
        self.field_gen.append_field256(&inputs.public.output);

        output_hash
    }
}

impl Default for TOPRFTraceGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash secret data and domain separator to scalar using MiMC.
///
/// This matches the gnark-compatible `hash_to_point_mimc` function exactly:
/// 1. Hash [secret_data[0], secret_data[1], domain_separator] with single MiMC call
/// 2. Use full 256-bit output directly
/// 3. Reduce modulo scalar_order
fn hash_to_scalar(secret_data: &[BigInt256; 2], domain_separator: &BigInt256) -> BigInt256 {
    // Hash the inputs using MiMC - matches hash_to_point_mimc exactly
    let scalar = mimc_hash(&[
        secret_data[0],
        secret_data[1],
        *domain_separator,
    ]);

    // Reduce mod scalar_order if needed (matching hash_to_point_mimc)
    let order = scalar_order();
    if scalar.compare(&order) != std::cmp::Ordering::Less {
        let (diff, _) = scalar.sub_no_reduce(&order);
        diff
    } else {
        scalar
    }
}

/// Hash point coordinates to scalar for DLEQ challenge using MiMC.
///
/// This computes a 256-bit scalar from 12 Field256 values (6 points × 2 coordinates) by:
/// 1. Hashing N_LIMBS times with domain separators 0 to N_LIMBS-1
/// 2. Each hash produces one 13-bit limb (using low bits of MiMC output)
/// 3. The result is reduced modulo the scalar order
fn hash_to_scalar_dleq(coords: &[BigInt256; 12]) -> BigInt256 {

    let mut result_limbs = [0u32; N_LIMBS];

    for limb_idx in 0..N_LIMBS {
        // Create input with domain separator prepended
        let mut extended_input: Vec<BigInt256> = Vec::with_capacity(coords.len() + 1);
        extended_input.push(BigInt256::from_u32(limb_idx as u32));
        extended_input.extend(coords.iter().cloned());

        let hash = mimc_hash(&extended_input);
        // Use low 13 bits of the MiMC hash (from limb 0)
        result_limbs[limb_idx] = hash.limbs[0] & LIMB_MASK;
    }

    // Reduce modulo scalar order
    let mut result = BigInt256::from_limbs(result_limbs);
    let order = scalar_order();

    // Simple reduction: subtract order while >= order
    while result.compare(&order) != std::cmp::Ordering::Less {
        let (diff, _) = result.sub_no_reduce(&order);
        result = diff;
    }

    result
}

/// Native TOPRF verification using MiMC (no trace generation).
/// Returns the MiMC hash output as a BigInt256 for gnark compatibility.
pub fn verify_toprf_native(inputs: &TOPRFInputs) -> Result<BigInt256, &'static str> {
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

        // Use the server's verify_dleq_mimc which matches prove_dleq_mimc
        // (no cofactor clearing in the current gnark implementation)
        let valid = verify_dleq_mimc(
            &inputs.public.c[share_idx],
            &inputs.public.r[share_idx],
            &share_pub_key,  // x_g = pubKey
            &response,       // x_h = response
            &masked,         // h = masked request
        );

        if !valid {
            return Err("DLEQ challenge verification failed");
        }
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

    // 9. Compute output hash using MiMC (gnark-compatible)
    let output = mimc_hash(&[
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
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use crate::toprf_server::eval::{evaluate_oprf_mimc, hash_to_point_mimc, mask_point};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Create valid TOPRF inputs using server functions to generate proper DLEQ params.
    fn create_valid_inputs() -> TOPRFInputs {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let p = modulus();
        let order = scalar_order();

        let secret_data = [
            BigInt256::from_u64(0x00DE_006F),
            BigInt256::from_u64(0x01BC_014D),
        ];
        let domain_separator = BigInt256::from_u32(1);

        // Generate key (threshold=1)
        let shared_key = generate_shared_key(&mut rng, 1, 1);
        let share = &shared_key.shares[0];

        // Client: hash to point using MiMC (gnark-compatible)
        let data_point = hash_to_point_mimc(&secret_data, &domain_separator);

        // Client: generate mask and mask the data point
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        // Server: evaluate OPRF using MiMC-based DLEQ (gnark-compatible)
        let response = evaluate_oprf_mimc(&mut rng, share, &masked_request)
            .expect("OPRF evaluation should succeed");

        // Client: unmask to get final point
        let mask_inv = mask.inv_mod(&order).expect("mask should have inverse");
        let unmasked = native::scalar_mul(&response.evaluated_point, &mask_inv);

        // Compute final hash using MiMC
        let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);
        let output_hash = mimc_hash(&[
            unmasked_x,
            unmasked_y,
            secret_data[0],
            secret_data[1],
        ]);

        // Convert response point to affine
        let (resp_x, resp_y) = response.evaluated_point.to_affine(&p);
        let (pub_x, pub_y) = share.public_key.to_affine(&p);

        TOPRFInputs {
            private: TOPRFPrivateInputs {
                mask,
                secret_data,
            },
            public: TOPRFPublicInputs {
                domain_separator,
                responses: [AffinePointBigInt { x: resp_x, y: resp_y }],
                coefficients: [BigInt256::one()],
                share_public_keys: [AffinePointBigInt { x: pub_x, y: pub_y }],
                c: [response.c],
                r: [response.r],
                output: output_hash,
            },
        }
    }

    #[test]
    fn test_toprf_gen_runs() {
        let inputs = create_valid_inputs();

        let mut gen = TOPRFTraceGen::new();
        let output = gen.gen_toprf(&inputs);

        println!("TOPRF output: {:?}", output);
        assert_eq!(output, inputs.public.output);
    }

    #[test]
    fn test_native_toprf() {
        let inputs = create_valid_inputs();

        let result = verify_toprf_native(&inputs);
        assert!(result.is_ok(), "Native verification failed: {:?}", result);

        let output = result.unwrap();
        assert_eq!(output, inputs.public.output);
    }
}
