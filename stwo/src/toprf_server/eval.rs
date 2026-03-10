//! OPRF evaluation for TOPRF server.
//!
//! Implements the server-side OPRF evaluation:
//! - evaluate_oprf: Evaluate masked point with server's private key
//! - threshold_mul: Combine multiple server responses
//! - finalize_toprf: Client-side finalization and verification
//!
//! For gnark compatibility, use the *_mimc variants which use MiMC hash
//! instead of Poseidon2.

use rand::Rng;

use super::dkg::lagrange_coefficient;
use super::dleq::{clear_cofactor, prove_dleq, prove_dleq_mimc, verify_dleq, verify_dleq_mimc, verify_dleq_mimc_with_cofactor};
use super::{OPRFResponse, Share, TOPRFResult, TOPRFResultMiMC};
use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
use crate::babyjub::mimc::gen::hash_field256_native;
use crate::babyjub::mimc_compat::mimc_hash;
use crate::babyjub::point::gen::native as point_native;
use crate::babyjub::point::{base_point, ExtendedPointBigInt};

/// Evaluate OPRF on a masked request point.
///
/// # Arguments
/// * `share` - Server's share of the TOPRF key
/// * `request` - Masked client request point (H * mask)
///
/// # Returns
/// * OPRFResponse containing evaluated point and DLEQ proof
/// * Returns None if point is invalid (in small subgroup)
pub fn evaluate_oprf<R: Rng>(
    rng: &mut R,
    share: &Share,
    request: &ExtendedPointBigInt,
) -> Option<OPRFResponse> {
    // Validate request is on curve and not in small subgroup
    let _cleared = clear_cofactor(request)?;

    // Evaluate: response = request * private_key
    let evaluated_point = point_native::scalar_mul(request, &share.private_key);

    // Generate DLEQ proof
    let (c, r) = prove_dleq(rng, &share.private_key, request)?;

    Some(OPRFResponse {
        evaluated_point,
        c,
        r,
    })
}

/// Evaluate OPRF using MiMC-based DLEQ (gnark-compatible).
///
/// This is identical to `evaluate_oprf` but uses MiMC hash for the DLEQ
/// challenge, making the proof verifiable by gnark's VerifyDLEQ.
pub fn evaluate_oprf_mimc<R: Rng>(
    rng: &mut R,
    share: &Share,
    request: &ExtendedPointBigInt,
) -> Option<OPRFResponse> {
    // Validate request is on curve and not in small subgroup
    let _cleared = clear_cofactor(request)?;

    // Evaluate: response = request * private_key
    let evaluated_point = point_native::scalar_mul(request, &share.private_key);

    // Generate DLEQ proof using MiMC (gnark-compatible)
    let (c, r) = prove_dleq_mimc(rng, &share.private_key, request)?;

    Some(OPRFResponse {
        evaluated_point,
        c,
        r,
    })
}

/// Combine threshold server responses using Lagrange interpolation.
///
/// # Arguments
/// * `indices` - Indices of the shares that responded
/// * `responses` - Evaluated points from each server
///
/// # Returns
/// * Combined point (can be unmasked by client)
pub fn threshold_mul(
    indices: &[usize],
    responses: &[ExtendedPointBigInt],
) -> ExtendedPointBigInt {
    assert_eq!(
        indices.len(),
        responses.len(),
        "Indices and responses must have same length"
    );
    assert!(!indices.is_empty(), "Need at least one response");

    // Start with identity point
    let mut result = ExtendedPointBigInt::identity();

    for (i, response) in responses.iter().enumerate() {
        // Compute Lagrange coefficient for this share
        let coeff = lagrange_coefficient(indices[i], indices);

        // Multiply response by coefficient
        let weighted = point_native::scalar_mul(response, &coeff);

        // Add to accumulator
        result = point_native::add_points(&result, &weighted);
    }

    result
}

/// Finalize TOPRF computation (client-side).
///
/// # Arguments
/// * `indices` - Indices of shares that responded
/// * `responses` - OPRF responses from servers
/// * `share_public_keys` - Public keys for each responding share
/// * `masked_request` - Original masked request point
/// * `secret_elements` - Secret data being processed
/// * `mask` - Client's blinding mask
///
/// # Returns
/// * TOPRFResult with unmasked point and final hash
/// * Returns None if any verification fails
pub fn finalize_toprf(
    indices: &[usize],
    responses: &[OPRFResponse],
    share_public_keys: &[ExtendedPointBigInt],
    masked_request: &ExtendedPointBigInt,
    secret_elements: &[BigInt256; 2],
    mask: &BigInt256,
) -> Option<TOPRFResult> {
    let modulus = modulus();

    // Verify all DLEQ proofs
    for (i, response) in responses.iter().enumerate() {
        let valid = verify_dleq(
            &response.c,
            &response.r,
            &share_public_keys[i],
            &response.evaluated_point,
            masked_request,
        );
        if !valid {
            return None;
        }
    }

    // Combine responses
    let evaluated_points: Vec<_> = responses
        .iter()
        .map(|r| r.evaluated_point.clone())
        .collect();
    let combined = threshold_mul(indices, &evaluated_points);

    // Unmask: compute mask^(-1) in the scalar field and multiply
    // Note: mask is a scalar reduced mod scalar_order, so its inverse must also be mod scalar_order
    let order = scalar_order();
    let mask_inv = mask.inv_mod(&order)?;
    let unmasked = point_native::scalar_mul(&combined, &mask_inv);

    // Convert unmasked to affine for hashing
    let (unmasked_x, unmasked_y) = unmasked.to_affine(&modulus);

    // Compute final hash: H(unmasked.x, unmasked.y, secret_elements[0], secret_elements[1])
    let hash_inputs = vec![
        unmasked_x.clone(),
        unmasked_y.clone(),
        secret_elements[0].clone(),
        secret_elements[1].clone(),
    ];

    let hash_output = hash_field256_native(&hash_inputs);

    Some(TOPRFResult {
        unmasked_point: unmasked,
        output: hash_output.0,
    })
}

/// Hash secret data to a curve point (for client-side use).
///
/// # Arguments
/// * `secret_data` - Two Field256 values to hash
/// * `domain_separator` - Domain separator for the hash
///
/// # Returns
/// * Point on the curve
pub fn hash_to_point(
    secret_data: &[BigInt256; 2],
    domain_separator: &BigInt256,
) -> ExtendedPointBigInt {
    // Hash the inputs to get a scalar
    let hash_inputs = vec![
        secret_data[0].clone(),
        secret_data[1].clone(),
        domain_separator.clone(),
    ];

    // Use multiple hash calls to generate a full scalar
    let modulus = modulus();
    let mut scalar_limbs = [0u32; 9];
    for (i, limb) in scalar_limbs.iter_mut().enumerate() {
        let mut input = hash_inputs.clone();
        input.push(BigInt256::from_limbs([i as u32, 0, 0, 0, 0, 0, 0, 0, 0]));
        let hash = hash_field256_native(&input);
        *limb = hash.0 & 0x1FFFFFFF;
    }

    // Reduce and multiply base point
    let mut scalar = BigInt256::from_limbs(scalar_limbs);
    while scalar.cmp(&modulus) >= 0 {
        let (diff, _) = scalar.sub_no_reduce(&modulus);
        scalar = diff;
    }

    let base = base_point();
    point_native::scalar_mul(&base, &scalar)
}

/// Mask a data point with a random mask (client-side).
///
/// # Arguments
/// * `data_point` - Point to mask
/// * `mask` - Random mask scalar
///
/// # Returns
/// * Masked point
pub fn mask_point(data_point: &ExtendedPointBigInt, mask: &BigInt256) -> ExtendedPointBigInt {
    point_native::scalar_mul(data_point, mask)
}

// =============================================================================
// gnark-compatible MiMC-based functions
// =============================================================================

/// Hash secret data to a curve point using MiMC (gnark-compatible).
///
/// This matches gnark's hash-to-point behavior for cross-system compatibility.
///
/// # Arguments
/// * `secret_data` - Two Field256 values to hash
/// * `domain_separator` - Domain separator for the hash
///
/// # Returns
/// * Point on the curve
pub fn hash_to_point_mimc(
    secret_data: &[BigInt256; 2],
    domain_separator: &BigInt256,
) -> ExtendedPointBigInt {
    // Hash the inputs using MiMC to get a scalar
    let hash_inputs = vec![
        secret_data[0].clone(),
        secret_data[1].clone(),
        domain_separator.clone(),
    ];

    // MiMC hash produces a full 256-bit output directly
    let scalar = mimc_hash(&hash_inputs);

    // Reduce mod scalar_order if needed
    let order = scalar_order();
    let scalar = if scalar.cmp(&order) >= 0 {
        let (diff, _) = scalar.sub_no_reduce(&order);
        diff
    } else {
        scalar
    };

    let base = base_point();
    point_native::scalar_mul(&base, &scalar)
}

/// Finalize TOPRF computation using MiMC hash (gnark-compatible).
///
/// This matches gnark's TOPRF finalization for cross-system compatibility.
/// Uses MiMC-based DLEQ verification to verify proofs from gnark.
///
/// # Arguments
/// * `indices` - Indices of shares that responded
/// * `responses` - OPRF responses from servers
/// * `share_public_keys` - Public keys for each responding share
/// * `masked_request` - Original masked request point
/// * `secret_elements` - Secret data being processed
/// * `mask` - Client's blinding mask
///
/// # Returns
/// * TOPRFResultMiMC with unmasked point and MiMC hash (gnark-compatible)
/// * Returns None if any verification fails
pub fn finalize_toprf_mimc(
    indices: &[usize],
    responses: &[OPRFResponse],
    share_public_keys: &[ExtendedPointBigInt],
    masked_request: &ExtendedPointBigInt,
    secret_elements: &[BigInt256; 2],
    mask: &BigInt256,
) -> Option<TOPRFResultMiMC> {
    let modulus = modulus();

    // Verify all DLEQ proofs using MiMC (gnark-compatible)
    // Try without cofactor clearing first (old gnark binary), then with cofactor clearing (new gnark)
    for (i, response) in responses.iter().enumerate() {
        let valid_no_cofactor = verify_dleq_mimc(
            &response.c,
            &response.r,
            &share_public_keys[i],
            &response.evaluated_point,
            masked_request,
        );
        let valid_with_cofactor = verify_dleq_mimc_with_cofactor(
            &response.c,
            &response.r,
            &share_public_keys[i],
            &response.evaluated_point,
            masked_request,
        );
        if !valid_no_cofactor && !valid_with_cofactor {
            return None;
        }
    }

    // Combine responses
    let evaluated_points: Vec<_> = responses
        .iter()
        .map(|r| r.evaluated_point.clone())
        .collect();
    let combined = threshold_mul(indices, &evaluated_points);

    // Unmask: compute mask^(-1) in the scalar field and multiply
    let order = scalar_order();
    let mask_inv = mask.inv_mod(&order)?;
    let unmasked = point_native::scalar_mul(&combined, &mask_inv);

    // Convert unmasked to affine for hashing
    let (unmasked_x, unmasked_y) = unmasked.to_affine(&modulus);

    // Compute final hash using MiMC: H(unmasked.x, unmasked.y, secret_elements[0], secret_elements[1])
    let hash_inputs = vec![
        unmasked_x.clone(),
        unmasked_y.clone(),
        secret_elements[0].clone(),
        secret_elements[1].clone(),
    ];

    let hash_output = mimc_hash(&hash_inputs);

    Some(TOPRFResultMiMC {
        unmasked_point: unmasked,
        output: hash_output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_evaluate_oprf() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        // Generate a shared key
        let shared_key = generate_shared_key(&mut rng, 3, 2);

        // Create a mock request (would be masked data point in practice)
        let request_scalar = random_scalar(&mut rng);
        let base = base_point();
        let request = point_native::scalar_mul(&base, &request_scalar);

        // Evaluate with first share
        let response = evaluate_oprf(&mut rng, &shared_key.shares[0], &request);
        assert!(response.is_some());

        let response = response.unwrap();
        // Verify the DLEQ proof
        let valid = verify_dleq(
            &response.c,
            &response.r,
            &shared_key.shares[0].public_key,
            &response.evaluated_point,
            &request,
        );
        assert!(valid);
    }

    #[test]
    fn test_threshold_mul() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        // Generate shared key with threshold 2
        let shared_key = generate_shared_key(&mut rng, 3, 2);

        // Create a request point
        let request_scalar = random_scalar(&mut rng);
        let base = base_point();
        let request = point_native::scalar_mul(&base, &request_scalar);

        // Evaluate with shares 1 and 2
        let resp1 = evaluate_oprf(&mut rng, &shared_key.shares[0], &request).unwrap();
        let resp2 = evaluate_oprf(&mut rng, &shared_key.shares[1], &request).unwrap();

        // Combine responses
        let indices = vec![1, 2];
        let responses = vec![
            resp1.evaluated_point.clone(),
            resp2.evaluated_point.clone(),
        ];
        let combined = threshold_mul(&indices, &responses);

        // The combined result should equal request * master_secret
        // We verify by checking the DLEQ proofs were valid (done in finalize)
        assert!(
            !combined.x.is_zero() || combined.y != BigInt256::one(),
            "Combined result should not be identity"
        );
    }

    #[test]
    fn test_full_toprf_flow() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        // === Server setup ===
        let shared_key = generate_shared_key(&mut rng, 3, 2);

        // === Client side: prepare request ===
        let secret_data = [
            BigInt256::from_limbs([111, 222, 0, 0, 0, 0, 0, 0, 0]),
            BigInt256::from_limbs([333, 444, 0, 0, 0, 0, 0, 0, 0]),
        ];
        let domain_separator = BigInt256::from_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Hash to point
        let data_point = hash_to_point(&secret_data, &domain_separator);

        // Generate mask
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        // === Server side: evaluate ===
        let resp1 = evaluate_oprf(&mut rng, &shared_key.shares[0], &masked_request).unwrap();
        let resp2 = evaluate_oprf(&mut rng, &shared_key.shares[1], &masked_request).unwrap();

        // === Client side: finalize ===
        let indices = vec![1, 2];
        let responses = vec![resp1, resp2];
        let pub_keys = vec![
            shared_key.shares[0].public_key.clone(),
            shared_key.shares[1].public_key.clone(),
        ];

        let result = finalize_toprf(
            &indices,
            &responses,
            &pub_keys,
            &masked_request,
            &secret_data,
            &mask,
        );

        assert!(result.is_some());
        let result = result.unwrap();
        println!("TOPRF output: {}", result.output);
    }
}
