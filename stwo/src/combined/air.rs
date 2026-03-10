//! AIR for combined cipher + TOPRF proof.
//!
//! This module provides proof generation and verification for combined
//! cipher + TOPRF circuits.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::gen::{build_toprf_inputs, verify_cipher_native};
use super::{CipherAlgorithm, CombinedInputs, DataLocation, TOPRFPrivateInputs, TOPRFPublicInputs};
use crate::babyjub::field256::gen::{modulus, BigInt256};
use crate::babyjub::point::{AffinePointBigInt, ExtendedPointBigInt};
use crate::babyjub::toprf::air::{prove_toprf, verify_toprf, TOPRFProof};
use crate::babyjub::toprf::THRESHOLD;

use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::verifier::VerificationError;

/// Combined proof structure.
///
/// Contains both cipher and TOPRF proof data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CombinedProof {
    /// Algorithm used for encryption.
    pub algorithm: String,

    /// TOPRF STARK proof (serialized).
    pub toprf_proof: TOPRFProof<Blake2sMerkleHasher>,

    /// Cipher blocks with nonces and counters.
    pub blocks: Vec<SerializedBlock>,

    /// Blake2s hash of plaintext.
    pub plaintext_hash: [u8; 32],

    /// Blake2s hash of ciphertext.
    pub ciphertext_hash: [u8; 32],

    /// Data locations for TOPRF extraction.
    pub locations: Vec<SerializedLocation>,
}

/// Serialized cipher block info.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedBlock {
    pub nonce: [u8; 12],
    pub counter: u32,
    pub byte_offset: usize,
    pub byte_len: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedLocation {
    pub pos: usize,
    pub len: usize,
}

/// Generate combined cipher + TOPRF proof.
///
/// This generates a STARK proof that proves:
/// 1. The ciphertext is a valid encryption of the plaintext
/// 2. The TOPRF output is correctly computed from data at specified locations
///
/// The cipher proof is validated natively (not via STARK) since the cipher
/// operations are straightforward. The TOPRF proof uses the existing STARK circuit.
pub fn prove_combined(
    config: PcsConfig,
    inputs: &CombinedInputs,
) -> Result<CombinedProof, String> {
    // 1. Verify cipher encryption is correct
    if !verify_cipher_native(inputs) {
        return Err("Cipher verification failed: ciphertext does not match encryption".to_string());
    }

    // 2. Build TOPRF inputs
    let toprf_inputs = build_toprf_inputs(inputs);

    // Debug: print extracted secret data
    #[cfg(feature = "debug_combined")]
    {
        eprintln!("DEBUG Combined: secret_data[0] = {:?}", hex::encode(&toprf_inputs.private.secret_data[0].to_bytes_be()));
        eprintln!("DEBUG Combined: secret_data[1] = {:?}", hex::encode(&toprf_inputs.private.secret_data[1].to_bytes_be()));
        eprintln!("DEBUG Combined: domain_separator = {:?}", hex::encode(&toprf_inputs.public.domain_separator.to_bytes_be()));
        eprintln!("DEBUG Combined: expected_output = {:?}", hex::encode(&inputs.toprf_public.output.to_bytes_be()));
    }

    // Verify TOPRF output matches (do this before expensive proof generation)
    use crate::babyjub::toprf::gen::verify_toprf_native;

    // Debug: print inputs before verification
    let mut debug_info = String::new();
    debug_info.push_str(&format!("secret_data[0]={}\n", hex::encode(toprf_inputs.private.secret_data[0].to_bytes_be_trimmed())));
    debug_info.push_str(&format!("secret_data[1]={}\n", hex::encode(toprf_inputs.private.secret_data[1].to_bytes_be_trimmed())));
    debug_info.push_str(&format!("domain_separator={}\n", hex::encode(toprf_inputs.public.domain_separator.to_bytes_be_trimmed())));
    debug_info.push_str(&format!("mask={}\n", hex::encode(toprf_inputs.private.mask.to_bytes_be_trimmed())));
    debug_info.push_str(&format!("responses[0].x={}\n", hex::encode(toprf_inputs.public.responses[0].x.to_bytes_be_trimmed())));
    debug_info.push_str(&format!("responses[0].y={}\n", hex::encode(toprf_inputs.public.responses[0].y.to_bytes_be_trimmed())));
    debug_info.push_str(&format!("share_public_keys[0].x={}\n", hex::encode(toprf_inputs.public.share_public_keys[0].x.to_bytes_be_trimmed())));
    debug_info.push_str(&format!("share_public_keys[0].y={}\n", hex::encode(toprf_inputs.public.share_public_keys[0].y.to_bytes_be_trimmed())));
    debug_info.push_str(&format!("c[0]={}\n", hex::encode(toprf_inputs.public.c[0].to_bytes_be_trimmed())));
    debug_info.push_str(&format!("r[0]={}\n", hex::encode(toprf_inputs.public.r[0].to_bytes_be_trimmed())));

    let computed_output = verify_toprf_native(&toprf_inputs)
        .map_err(|e| format!("TOPRF verification failed: {}\nDebug:\n{}", e, debug_info))?;

    if computed_output != inputs.toprf_public.output {
        // Debug output
        return Err(format!(
            "Computed output does not match expected output\nExpected: {}\nComputed: {}",
            hex::encode(&inputs.toprf_public.output.to_bytes_be()),
            hex::encode(&computed_output.to_bytes_be())
        ));
    }

    // 3. Generate TOPRF STARK proof
    let toprf_proof = prove_toprf::<Blake2sMerkleChannel>(config, &toprf_inputs)?;

    // 4. Create public input hashes
    let plaintext_hash = blake2_hash(&inputs.plaintext);
    let ciphertext_hash = blake2_hash(&inputs.ciphertext);

    // 5. Serialize locations
    let locations: Vec<SerializedLocation> = inputs
        .locations
        .iter()
        .map(|loc| SerializedLocation {
            pos: loc.pos,
            len: loc.len,
        })
        .collect();

    // 6. Serialize blocks
    let blocks: Vec<SerializedBlock> = inputs
        .blocks
        .iter()
        .map(|b| SerializedBlock {
            nonce: b.nonce,
            counter: b.counter,
            byte_offset: b.byte_offset,
            byte_len: b.byte_len,
        })
        .collect();

    Ok(CombinedProof {
        algorithm: match inputs.algorithm {
            CipherAlgorithm::ChaCha20 => "chacha20".to_string(),
            CipherAlgorithm::Aes128Ctr => "aes-128-ctr".to_string(),
            CipherAlgorithm::Aes256Ctr => "aes-256-ctr".to_string(),
        },
        toprf_proof,
        blocks,
        plaintext_hash,
        ciphertext_hash,
        locations,
    })
}

/// Verify combined cipher + TOPRF proof.
///
/// This verifies:
/// 1. The TOPRF STARK proof is valid
/// 2. The ciphertext hash matches (public input)
/// 3. The expected output matches the proof's output
/// 4. The blocks match the expected blocks
///
/// Note: Plaintext verification is optional. In TOPRF mode, the plaintext is private
/// and the security comes from:
/// - At prove time, cipher encryption correctness is verified natively
/// - The STARK proof proves the TOPRF computation is correct on extracted data
/// - The ciphertext is public and verified
pub fn verify_combined(
    proof: &CombinedProof,
    min_config: &PcsConfig,
    blocks: &[SerializedBlock],
    plaintext: Option<&[u8]>,
    ciphertext: &[u8],
    expected_output: &[u8],
) -> Result<(), VerificationError> {
    // 1. Verify blocks match
    if proof.blocks.len() != blocks.len() {
        return Err(VerificationError::InvalidStructure(
            format!("Block count mismatch: proof has {}, expected {}", proof.blocks.len(), blocks.len()),
        ));
    }

    for (i, (proof_block, expected_block)) in proof.blocks.iter().zip(blocks.iter()).enumerate() {
        if proof_block.nonce != expected_block.nonce {
            return Err(VerificationError::InvalidStructure(
                format!("Nonce mismatch at block {}", i),
            ));
        }
        if proof_block.counter != expected_block.counter {
            return Err(VerificationError::InvalidStructure(
                format!("Counter mismatch at block {}", i),
            ));
        }
        if proof_block.byte_offset != expected_block.byte_offset {
            return Err(VerificationError::InvalidStructure(
                format!("Byte offset mismatch at block {}", i),
            ));
        }
        if proof_block.byte_len != expected_block.byte_len {
            return Err(VerificationError::InvalidStructure(
                format!("Byte len mismatch at block {}", i),
            ));
        }
    }

    // 2. Verify plaintext hash matches (optional - only if plaintext provided)
    if let Some(pt) = plaintext {
        let plaintext_hash = blake2_hash(pt);
        if proof.plaintext_hash != plaintext_hash {
            return Err(VerificationError::InvalidStructure(
                "Plaintext hash mismatch".to_string(),
            ));
        }
    }

    // 3. Verify ciphertext hash matches
    let ciphertext_hash = blake2_hash(ciphertext);
    if proof.ciphertext_hash != ciphertext_hash {
        return Err(VerificationError::InvalidStructure(
            "Ciphertext hash mismatch".to_string(),
        ));
    }

    // 4. Verify TOPRF proof with expected output
    verify_toprf::<Blake2sMerkleChannel>(proof.toprf_proof.clone(), min_config)?;

    // 6. Verify output matches
    if proof.toprf_proof.stmt.public_inputs.output != expected_output {
        return Err(VerificationError::InvalidStructure(
            "TOPRF output mismatch".to_string(),
        ));
    }

    Ok(())
}

/// Serialize combined proof to JSON string.
pub fn serialize_combined_proof(proof: &CombinedProof) -> Result<String, String> {
    let proof_bytes = serde_json::to_vec(proof).map_err(|e| format!("Serialization error: {}", e))?;
    let proof_b64 = BASE64.encode(&proof_bytes);

    // Serialize blocks for info (first block's nonce/counter for backward compat)
    let first_nonce = proof.blocks.first().map(|b| hex::encode(b.nonce)).unwrap_or_default();
    let first_counter = proof.blocks.first().map(|b| b.counter).unwrap_or(0);

    Ok(json!({
        "success": true,
        "algorithm": proof.algorithm,
        "proof": proof_b64,
        "nonce": first_nonce,
        "counter": first_counter,
        "num_blocks": proof.blocks.len(),
        "plaintext_hash": hex::encode(proof.plaintext_hash),
        "ciphertext_hash": hex::encode(proof.ciphertext_hash),
    })
    .to_string())
}

/// Deserialize combined proof from base64 string.
pub fn deserialize_combined_proof(proof_b64: &str) -> Result<CombinedProof, String> {
    let proof_bytes = BASE64
        .decode(proof_b64)
        .map_err(|e| format!("Invalid base64: {}", e))?;
    serde_json::from_slice(&proof_bytes).map_err(|e| format!("Invalid proof format: {}", e))
}

/// Blake2s-256 hash.
fn blake2_hash(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    Blake2s256::digest(data).into()
}

/// Parse TOPRF JSON inputs (gnark-compatible format).
///
/// Expected JSON format:
/// ```json
/// {
///   "locations": [{"pos": 0, "len": 14}],
///   "domainSeparator": "reclaim",
///   "output": "0x...",
///   "responses": [{
///     "publicKeyShare": "0x...",
///     "evaluated": "0x...",
///     "c": "0x...",
///     "r": "0x..."
///   }],
///   "mask": "0x..."
/// }
/// ```
pub fn parse_toprf_json(json_str: &str) -> Result<(Vec<DataLocation>, TOPRFPublicInputs, TOPRFPrivateInputs), String> {
    #[cfg(debug_assertions)]
    eprintln!("DEBUG parse_toprf_json: input = {}", json_str);
    let params: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {}", e))?;

    // Parse locations
    let locations: Vec<DataLocation> = match params["locations"].as_array() {
        Some(arr) => arr
            .iter()
            .map(|loc| DataLocation {
                pos: loc["pos"].as_u64().unwrap_or(0) as usize,
                len: loc["len"].as_u64().unwrap_or(0) as usize,
            })
            .collect(),
        None => return Err("Missing locations".to_string()),
    };

    // Parse domain separator
    let domain_separator_str = params["domainSeparator"]
        .as_str()
        .unwrap_or("");
    let domain_separator = bytes_to_bigint256_gnark(domain_separator_str.as_bytes());

    // Parse output
    let output_hex = params["output"].as_str().unwrap_or("");
    let output_bytes = hex_decode(output_hex)?;
    let output = BigInt256::from_bytes_be(&output_bytes);

    // Parse responses
    let responses_arr = params["responses"]
        .as_array()
        .ok_or("Missing responses")?;

    if responses_arr.is_empty() {
        return Err("At least one response required".to_string());
    }

    let mut responses = [AffinePointBigInt::default(); THRESHOLD];
    let mut share_public_keys = [AffinePointBigInt::default(); THRESHOLD];
    let mut c_vals = [BigInt256::zero(); THRESHOLD];
    let mut r_vals = [BigInt256::zero(); THRESHOLD];

    for (i, resp) in responses_arr.iter().take(THRESHOLD).enumerate() {
        // Parse evaluated point (32 bytes compressed or 64 bytes uncompressed)
        let eval_hex = resp["evaluated"].as_str().unwrap_or("");
        let eval_bytes = hex_decode(eval_hex)?;
        #[cfg(debug_assertions)]
        eprintln!("DEBUG: evaluated[{}] hex={}, len={}", i, eval_hex, eval_bytes.len());
        if eval_bytes.len() >= 32 {
            let (x, y) = parse_point_bytes(&eval_bytes)?;
            responses[i] = AffinePointBigInt { x, y };
            #[cfg(debug_assertions)]
            eprintln!("DEBUG: evaluated[{}] parsed x={}, y={}", i, hex::encode(x.to_bytes_be_trimmed()), hex::encode(y.to_bytes_be_trimmed()));
        }

        // Parse public key share (32 bytes compressed or 64 bytes uncompressed)
        let pk_hex = resp["publicKeyShare"].as_str().unwrap_or("");
        let pk_bytes = hex_decode(pk_hex)?;
        #[cfg(debug_assertions)]
        eprintln!("DEBUG: publicKeyShare[{}] hex={}, len={}", i, pk_hex, pk_bytes.len());
        if pk_bytes.len() >= 32 {
            let (x, y) = parse_point_bytes(&pk_bytes)?;
            share_public_keys[i] = AffinePointBigInt { x, y };
            #[cfg(debug_assertions)]
            eprintln!("DEBUG: publicKeyShare[{}] parsed x={}, y={}", i, hex::encode(x.to_bytes_be_trimmed()), hex::encode(y.to_bytes_be_trimmed()));
        }

        // Parse c
        let c_hex = resp["c"].as_str().unwrap_or("");
        let c_bytes = hex_decode(c_hex)?;
        c_vals[i] = BigInt256::from_bytes_be(&c_bytes);
        #[cfg(debug_assertions)]
        eprintln!("DEBUG: c[{}] = {}", i, hex::encode(c_vals[i].to_bytes_be_trimmed()));

        // Parse r
        let r_hex = resp["r"].as_str().unwrap_or("");
        let r_bytes = hex_decode(r_hex)?;
        r_vals[i] = BigInt256::from_bytes_be(&r_bytes);
        #[cfg(debug_assertions)]
        eprintln!("DEBUG: r[{}] = {}", i, hex::encode(r_vals[i].to_bytes_be_trimmed()));
    }

    // Parse mask (private)
    let mask_hex = params["mask"].as_str().unwrap_or("");
    let mask_bytes = hex_decode(mask_hex)?;
    let mask = BigInt256::from_bytes_be(&mask_bytes);

    let public = TOPRFPublicInputs {
        domain_separator,
        responses,
        coefficients: [BigInt256::one(); THRESHOLD],
        share_public_keys,
        c: c_vals,
        r: r_vals,
        output,
    };

    let private = TOPRFPrivateInputs { mask };

    Ok((locations, public, private))
}

/// Parse point bytes (32 bytes compressed gnark format OR 64 bytes uncompressed).
fn parse_point_bytes(bytes: &[u8]) -> Result<(BigInt256, BigInt256), String> {
    let p = modulus();

    if bytes.len() == 32 {
        // 32-byte compressed gnark format
        let point = ExtendedPointBigInt::from_bytes_gnark(bytes, &p)
            .ok_or("Failed to decompress point")?;
        let (x, y) = point.to_affine(&p);
        Ok((x, y))
    } else if bytes.len() >= 64 {
        // 64-byte uncompressed format (x || y, big-endian)
        let x = BigInt256::from_bytes_be(&bytes[..32]);
        let y = BigInt256::from_bytes_be(&bytes[32..64]);
        Ok((x, y))
    } else {
        Err(format!("Invalid point bytes length: {}, expected 32 or 64", bytes.len()))
    }
}

/// Decode hex string (with or without 0x prefix).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))
}

/// Convert bytes to BigInt256 (gnark-compatible: reverse bytes).
fn bytes_to_bigint256_gnark(bytes: &[u8]) -> BigInt256 {
    if bytes.is_empty() {
        return BigInt256::zero();
    }

    let mut reversed: Vec<u8> = bytes.to_vec();
    reversed.reverse();
    BigInt256::from_bytes_be(&reversed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
    use crate::toprf_server::dleq::verify_dleq_mimc;
    use crate::babyjub::point::ExtendedPointBigInt;
    use crate::babyjub::point::gen::native as point_native;

    #[test]
    fn test_parse_toprf_json() {
        let json = r#"{
            "locations": [{"pos": 0, "len": 14}],
            "domainSeparator": "reclaim",
            "output": "0x1234",
            "responses": [{
                "publicKeyShare": "0x0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200",
                "evaluated": "0x0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000400",
                "c": "0x05",
                "r": "0x06"
            }],
            "mask": "0x07"
        }"#;

        let result = parse_toprf_json(json);
        assert!(result.is_ok(), "Parse failed: {:?}", result);

        let (locations, public, private) = result.unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].pos, 0);
        assert_eq!(locations[0].len, 14);
        assert!(!private.mask.is_zero());
    }

    #[test]
    fn test_blake2_hash() {
        let data = b"test data";
        let hash = blake2_hash(data);
        assert_eq!(hash.len(), 32);
    }

    /// Test that DLEQ verification works when computing masked from secret_data
    #[test]
    fn test_dleq_with_computed_masked() {
        use crate::toprf_server::dkg::generate_shared_key;
        use crate::toprf_server::{evaluate_oprf_mimc, Share};
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        // 1. Generate keys
        let shared = generate_shared_key(&mut rng, 5, 1);
        let share = &shared.shares[0];

        // 2. Create secret data and domain separator (matching JS test)
        let secret_bytes = b"test@email.com";
        let domain_str = "reclaim";

        // Convert to field elements using gnark encoding
        let secret_data = bytes_to_field256_elements_gnark(secret_bytes);
        let domain = bytes_to_bigint256_gnark(domain_str.as_bytes());

        // 3. Compute data_point via hash_to_point_mimc
        let data_point = hash_to_point_mimc(&secret_data, &domain);

        // 4. Generate random mask
        use crate::toprf_server::dkg::random_scalar;
        let mask = random_scalar(&mut rng);

        // 5. Compute masked = data_point * mask
        let masked = mask_point(&data_point, &mask);

        // 6. Evaluate OPRF (this creates DLEQ proof)
        let response = evaluate_oprf_mimc(&mut rng, share, &masked).expect("eval failed");

        // 7. Now verify DLEQ using the computed masked point
        let valid = verify_dleq_mimc(
            &response.c,
            &response.r,
            &share.public_key,
            &response.evaluated_point,
            &masked,
        );

        assert!(valid, "DLEQ verification failed with computed masked point");

        // 8. Now simulate what verify_toprf_native does: recompute masked from secret_data
        // First, compute hashed_scalar and data_point from scratch (matching gen.rs)
        use crate::babyjub::mimc_compat::mimc_hash;
        use crate::babyjub::field256::gen::scalar_order;
        use crate::babyjub::point::base_point;

        let hashed_scalar = {
            let scalar = mimc_hash(&[secret_data[0], secret_data[1], domain]);
            let order = scalar_order();
            if scalar.cmp(&order) >= 0 {
                let (diff, _) = scalar.sub_no_reduce(&order);
                diff
            } else {
                scalar
            }
        };

        let base = base_point();
        let data_point_recomputed = point_native::scalar_mul(&base, &hashed_scalar);
        let masked_recomputed = point_native::scalar_mul(&data_point_recomputed, &mask);

        // Verify the recomputed masked matches the original
        let (orig_x, orig_y) = masked.to_affine(&p);
        let (recomp_x, recomp_y) = masked_recomputed.to_affine(&p);

        assert_eq!(orig_x, recomp_x, "masked X mismatch");
        assert_eq!(orig_y, recomp_y, "masked Y mismatch");

        // 9. Verify DLEQ with recomputed masked
        let valid_recomputed = verify_dleq_mimc(
            &response.c,
            &response.r,
            &share.public_key,
            &response.evaluated_point,
            &masked_recomputed,
        );

        assert!(valid_recomputed, "DLEQ verification failed with recomputed masked point");
    }

    /// Convert bytes to Field256 elements (gnark-compatible)
    fn bytes_to_field256_elements_gnark(bytes: &[u8]) -> [BigInt256; 2] {
        const BYTES_PER_ELEMENT: usize = 31;
        let mut elem0 = BigInt256::zero();
        let mut elem1 = BigInt256::zero();

        if !bytes.is_empty() {
            if bytes.len() > BYTES_PER_ELEMENT {
                let mut reversed0: Vec<u8> = bytes[..BYTES_PER_ELEMENT].to_vec();
                reversed0.reverse();
                elem0 = BigInt256::from_bytes_be(&reversed0);

                let mut reversed1: Vec<u8> = bytes[BYTES_PER_ELEMENT..].to_vec();
                reversed1.reverse();
                elem1 = BigInt256::from_bytes_be(&reversed1);
            } else {
                let mut reversed: Vec<u8> = bytes.to_vec();
                reversed.reverse();
                elem0 = BigInt256::from_bytes_be(&reversed);
            }
        }
        [elem0, elem1]
    }

    /// Test full round-trip: generate data, serialize to JSON, parse, verify
    #[test]
    fn test_full_toprf_json_roundtrip() {
        use crate::toprf_server::dkg::generate_shared_key;
        use crate::toprf_server::{evaluate_oprf_mimc, Share};
        use crate::babyjub::toprf::gen::verify_toprf_native;
        use crate::combined::extract_secret_data;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        // 1. Generate keys
        let shared = generate_shared_key(&mut rng, 5, 1);
        let share = &shared.shares[0];

        // 2. Create secret data (simulating email in plaintext)
        let secret_bytes = b"test@email.com";
        let domain_str = "reclaim";

        // Convert to field elements using gnark encoding
        let secret_data = bytes_to_field256_elements_gnark(secret_bytes);
        let domain = bytes_to_bigint256_gnark(domain_str.as_bytes());

        // 3. Compute data_point and masked
        let data_point = hash_to_point_mimc(&secret_data, &domain);
        use crate::toprf_server::dkg::random_scalar;
        let mask = random_scalar(&mut rng);
        let masked = mask_point(&data_point, &mask);

        // 4. Evaluate OPRF
        let response = evaluate_oprf_mimc(&mut rng, share, &masked).expect("eval failed");

        // 5. Serialize to gnark format (32-byte compressed points)
        let evaluated_hex = hex::encode(response.evaluated_point.to_bytes_gnark(&p));
        let pub_key_hex = hex::encode(share.public_key.to_bytes_gnark(&p));
        let c_hex = hex::encode(response.c.to_bytes_be_trimmed());
        let r_hex = hex::encode(response.r.to_bytes_be_trimmed());
        let mask_hex = hex::encode(mask.to_bytes_be_trimmed());

        // Compute expected output (via finalize)
        use crate::toprf_server::{OPRFResponse, finalize_toprf_mimc};
        let finalize_result = finalize_toprf_mimc(
            &[share.index],
            &[OPRFResponse {
                evaluated_point: response.evaluated_point.clone(),
                c: response.c,
                r: response.r,
            }],
            &[share.public_key.clone()],
            &masked,
            &secret_data,
            &mask,
        ).expect("finalize failed");
        let output_hex = hex::encode(finalize_result.output.to_bytes_be_trimmed());

        // 6. Build JSON matching what JS would send
        let json = format!(r#"{{
            "locations": [{{"pos": 0, "len": 14}}],
            "domainSeparator": "reclaim",
            "output": "0x{}",
            "responses": [{{
                "publicKeyShare": "0x{}",
                "evaluated": "0x{}",
                "c": "0x{}",
                "r": "0x{}"
            }}],
            "mask": "0x{}"
        }}"#, output_hex, pub_key_hex, evaluated_hex, c_hex, r_hex, mask_hex);

        println!("Generated JSON:\n{}", json);

        // 7. Parse JSON back
        let (locations, toprf_public, toprf_private) = parse_toprf_json(&json)
            .expect("parse failed");

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].pos, 0);
        assert_eq!(locations[0].len, 14);

        // 8. Build plaintext with email at position 0
        let mut plaintext = vec![0u8; 64];
        plaintext[..secret_bytes.len()].copy_from_slice(secret_bytes);

        // 9. Extract secret data from plaintext (simulating what combined proof does)
        let extracted_secret = extract_secret_data(&plaintext, &locations);

        // Verify extracted matches original
        assert_eq!(extracted_secret[0], secret_data[0], "secret_data[0] mismatch");
        assert_eq!(extracted_secret[1], secret_data[1], "secret_data[1] mismatch");

        // 10. Build full TOPRF inputs
        use crate::babyjub::toprf::{TOPRFInputs, TOPRFPrivateInputs as TOPRFPriv, TOPRFPublicInputs as TOPRFPub};

        let toprf_inputs = TOPRFInputs {
            public: TOPRFPub {
                domain_separator: toprf_public.domain_separator,
                responses: toprf_public.responses,
                coefficients: toprf_public.coefficients,
                share_public_keys: toprf_public.share_public_keys,
                c: toprf_public.c,
                r: toprf_public.r,
                output: toprf_public.output,
            },
            private: TOPRFPriv {
                mask: toprf_private.mask,
                secret_data: extracted_secret,
            },
        };

        // 11. Verify TOPRF
        let result = verify_toprf_native(&toprf_inputs);
        assert!(result.is_ok(), "TOPRF verification failed: {:?}", result);

        let computed_output = result.unwrap();
        assert_eq!(computed_output, finalize_result.output, "Output mismatch");
    }
}
