//! Trace generation for combined cipher + TOPRF proofs.
//!
//! This module generates traces that prove:
//! 1. Correct cipher encryption/decryption
//! 2. TOPRF verification on data extracted from the plaintext

use super::{extract_secret_data, CipherAlgorithm, CombinedInputs};
use crate::babyjub::field256::gen::BigInt256;
use crate::babyjub::toprf::gen::TOPRFTraceGen;
use crate::babyjub::toprf::{TOPRFInputs, TOPRFPrivateInputs as TOPRFPrivInputs, TOPRFPublicInputs as TOPRFPubInputs};

/// Combined trace generation result.
pub struct CombinedTraceResult {
    /// Computed TOPRF output hash.
    pub output: BigInt256,

    /// Extracted secret data from plaintext.
    pub secret_data: [BigInt256; 2],
}

/// Generate TOPRF inputs from combined inputs.
///
/// This extracts the secret data from plaintext at specified locations
/// and constructs proper TOPRF inputs.
pub fn build_toprf_inputs(inputs: &CombinedInputs) -> TOPRFInputs {
    // Extract secret data from plaintext at locations
    let secret_data = extract_secret_data(&inputs.plaintext, &inputs.locations);

    TOPRFInputs {
        public: TOPRFPubInputs {
            domain_separator: inputs.toprf_public.domain_separator,
            responses: inputs.toprf_public.responses,
            coefficients: inputs.toprf_public.coefficients,
            share_public_keys: inputs.toprf_public.share_public_keys,
            c: inputs.toprf_public.c,
            r: inputs.toprf_public.r,
            output: inputs.toprf_public.output,
        },
        private: TOPRFPrivInputs {
            mask: inputs.toprf_private.mask,
            secret_data,
        },
    }
}

/// Generate TOPRF trace and compute output.
///
/// This generates the TOPRF trace and returns the computed output hash.
pub fn generate_toprf_trace_and_output(inputs: &CombinedInputs) -> CombinedTraceResult {
    let toprf_inputs = build_toprf_inputs(inputs);
    let secret_data = toprf_inputs.private.secret_data;

    // Generate TOPRF trace
    let mut gen = TOPRFTraceGen::new();
    let output = gen.gen_toprf(&toprf_inputs);

    CombinedTraceResult {
        output,
        secret_data,
    }
}

/// Verify that cipher encryption is correct (native, no ZK).
///
/// Returns true if ciphertext = encrypt(key, nonce, counter, plaintext).
pub fn verify_cipher_native(inputs: &CombinedInputs) -> bool {
    match inputs.algorithm {
        CipherAlgorithm::ChaCha20 => verify_chacha20_native(inputs),
        CipherAlgorithm::Aes128Ctr => verify_aes128_ctr_native(inputs),
        CipherAlgorithm::Aes256Ctr => verify_aes256_ctr_native(inputs),
    }
}

fn verify_chacha20_native(inputs: &CombinedInputs) -> bool {
    use crate::chacha::block::chacha20_block_from_key;

    if inputs.key.len() != 32 {
        return false;
    }
    if inputs.plaintext.len() != inputs.ciphertext.len() {
        return false;
    }

    // Parse key as 8 u32s (little-endian)
    let key_u32: [u32; 8] = std::array::from_fn(|i| {
        u32::from_le_bytes([
            inputs.key[i * 4],
            inputs.key[i * 4 + 1],
            inputs.key[i * 4 + 2],
            inputs.key[i * 4 + 3],
        ])
    });

    // Parse nonce as 3 u32s (little-endian)
    let nonce_u32: [u32; 3] = std::array::from_fn(|i| {
        u32::from_le_bytes([
            inputs.nonce[i * 4],
            inputs.nonce[i * 4 + 1],
            inputs.nonce[i * 4 + 2],
            inputs.nonce[i * 4 + 3],
        ])
    });

    // Verify each block
    let block_size = 64;
    let num_blocks = (inputs.plaintext.len() + block_size - 1) / block_size;

    for block_idx in 0..num_blocks {
        let counter = inputs.counter + block_idx as u32;
        let keystream_u32 = chacha20_block_from_key(&key_u32, counter, &nonce_u32);

        // Convert keystream to bytes
        let mut keystream_bytes = [0u8; 64];
        for (i, &word) in keystream_u32.iter().enumerate() {
            keystream_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        // Check each byte in this block
        let start = block_idx * block_size;
        let end = (start + block_size).min(inputs.plaintext.len());

        for i in start..end {
            let expected = inputs.plaintext[i] ^ keystream_bytes[i - start];
            if inputs.ciphertext[i] != expected {
                return false;
            }
        }
    }

    true
}

fn verify_aes128_ctr_native(inputs: &CombinedInputs) -> bool {
    use crate::aes::aes128_ctr_block;

    if inputs.key.len() != 16 {
        return false;
    }
    if inputs.plaintext.len() != inputs.ciphertext.len() {
        return false;
    }

    let key: [u8; 16] = inputs.key[..16].try_into().unwrap();

    // Verify each block
    let block_size = 16;
    let num_blocks = (inputs.plaintext.len() + block_size - 1) / block_size;

    for block_idx in 0..num_blocks {
        let counter = inputs.counter + block_idx as u32;
        let start = block_idx * block_size;
        let end = (start + block_size).min(inputs.plaintext.len());

        // Get plaintext block (pad with zeros if partial)
        let mut pt_block = [0u8; 16];
        pt_block[..end - start].copy_from_slice(&inputs.plaintext[start..end]);

        // Encrypt
        let ct_block = aes128_ctr_block(&key, &inputs.nonce, counter, &pt_block);

        // Verify
        for i in 0..(end - start) {
            if inputs.ciphertext[start + i] != ct_block[i] {
                return false;
            }
        }
    }

    true
}

fn verify_aes256_ctr_native(inputs: &CombinedInputs) -> bool {
    use crate::aes::aes256_ctr_block;

    if inputs.key.len() != 32 {
        return false;
    }
    if inputs.plaintext.len() != inputs.ciphertext.len() {
        return false;
    }

    let key: [u8; 32] = inputs.key[..32].try_into().unwrap();

    // Verify each block
    let block_size = 16;
    let num_blocks = (inputs.plaintext.len() + block_size - 1) / block_size;

    for block_idx in 0..num_blocks {
        let counter = inputs.counter + block_idx as u32;
        let start = block_idx * block_size;
        let end = (start + block_size).min(inputs.plaintext.len());

        // Get plaintext block (pad with zeros if partial)
        let mut pt_block = [0u8; 16];
        pt_block[..end - start].copy_from_slice(&inputs.plaintext[start..end]);

        // Encrypt
        let ct_block = aes256_ctr_block(&key, &inputs.nonce, counter, &pt_block);

        // Verify
        for i in 0..(end - start) {
            if inputs.ciphertext[start + i] != ct_block[i] {
                return false;
            }
        }
    }

    true
}

/// Verify combined cipher + TOPRF natively (no ZK proof).
///
/// Returns Ok(output) if verification succeeds, Err(msg) otherwise.
pub fn verify_combined_native(inputs: &CombinedInputs) -> Result<BigInt256, &'static str> {
    // 1. Verify cipher encryption
    if !verify_cipher_native(inputs) {
        return Err("Cipher verification failed: ciphertext does not match encryption");
    }

    // 2. Build TOPRF inputs and verify
    let toprf_inputs = build_toprf_inputs(inputs);

    // Verify TOPRF using native verification
    use crate::babyjub::toprf::gen::verify_toprf_native;
    let output = verify_toprf_native(&toprf_inputs)?;

    // 3. Verify output matches
    if output != inputs.toprf_public.output {
        return Err("TOPRF output mismatch");
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::field256::gen::{modulus, scalar_order};
    use crate::babyjub::mimc_compat::mimc_hash;
    use crate::babyjub::point::gen::native;
    use crate::babyjub::point::AffinePointBigInt;
    use crate::babyjub::toprf::THRESHOLD;
    use crate::combined::DataLocation;
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use crate::toprf_server::eval::{evaluate_oprf_mimc, hash_to_point_mimc, mask_point};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn create_test_inputs(algorithm: CipherAlgorithm) -> CombinedInputs {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let p = modulus();
        let order = scalar_order();

        // Create plaintext with test data
        let email = b"test@email.com";
        let plaintext_len = match algorithm {
            CipherAlgorithm::ChaCha20 => 64,
            CipherAlgorithm::Aes128Ctr | CipherAlgorithm::Aes256Ctr => 64, // Use 64 for easier testing
        };
        let mut plaintext = vec![0u8; plaintext_len];
        plaintext[..email.len()].copy_from_slice(email);

        // Create key
        let key = match algorithm {
            CipherAlgorithm::ChaCha20 | CipherAlgorithm::Aes256Ctr => {
                (0..32).collect::<Vec<u8>>()
            }
            CipherAlgorithm::Aes128Ctr => (0..16).collect::<Vec<u8>>(),
        };

        let nonce: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let counter = 1u32;

        // Encrypt plaintext
        let ciphertext = encrypt_native(algorithm, &key, &nonce, counter, &plaintext);

        // Create TOPRF inputs
        let locations = vec![DataLocation {
            pos: 0,
            len: email.len(),
        }];
        let secret_data = extract_secret_data(&plaintext, &locations);

        // Generate TOPRF keys and response
        let domain_separator_str = "reclaim";
        let domain_separator = bytes_to_bigint256_gnark(domain_separator_str.as_bytes());

        let shared_key = generate_shared_key(&mut rng, 1, 1);
        let share = &shared_key.shares[0];

        let data_point = hash_to_point_mimc(&secret_data, &domain_separator);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        let response = evaluate_oprf_mimc(&mut rng, share, &masked_request)
            .expect("OPRF evaluation should succeed");

        // Unmask
        let mask_inv = mask.inv_mod(&order).expect("mask should have inverse");
        let unmasked = native::scalar_mul(&response.evaluated_point, &mask_inv);

        // Compute output
        let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);
        let output_hash = mimc_hash(&[unmasked_x, unmasked_y, secret_data[0], secret_data[1]]);

        let (resp_x, resp_y) = response.evaluated_point.to_affine(&p);
        let (pub_x, pub_y) = share.public_key.to_affine(&p);

        CombinedInputs {
            algorithm,
            key,
            nonce,
            counter,
            plaintext,
            ciphertext,
            locations,
            toprf_public: super::super::TOPRFPublicInputs {
                domain_separator,
                responses: [AffinePointBigInt { x: resp_x, y: resp_y }],
                coefficients: [BigInt256::one(); THRESHOLD],
                share_public_keys: [AffinePointBigInt { x: pub_x, y: pub_y }],
                c: [response.c; THRESHOLD],
                r: [response.r; THRESHOLD],
                output: output_hash,
            },
            toprf_private: super::super::TOPRFPrivateInputs { mask },
        }
    }

    fn encrypt_native(
        algorithm: CipherAlgorithm,
        key: &[u8],
        nonce: &[u8; 12],
        counter: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        match algorithm {
            CipherAlgorithm::ChaCha20 => {
                use crate::chacha::block::chacha20_block_from_key;

                let key_u32: [u32; 8] = std::array::from_fn(|i| {
                    u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
                });
                let nonce_u32: [u32; 3] = std::array::from_fn(|i| {
                    u32::from_le_bytes([
                        nonce[i * 4],
                        nonce[i * 4 + 1],
                        nonce[i * 4 + 2],
                        nonce[i * 4 + 3],
                    ])
                });

                let block_size = 64;
                let num_blocks = (plaintext.len() + block_size - 1) / block_size;
                let mut ciphertext = vec![0u8; plaintext.len()];

                for block_idx in 0..num_blocks {
                    let c = counter + block_idx as u32;
                    let keystream_u32 = chacha20_block_from_key(&key_u32, c, &nonce_u32);

                    let mut keystream_bytes = [0u8; 64];
                    for (i, &word) in keystream_u32.iter().enumerate() {
                        keystream_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
                    }

                    let start = block_idx * block_size;
                    let end = (start + block_size).min(plaintext.len());
                    for i in start..end {
                        ciphertext[i] = plaintext[i] ^ keystream_bytes[i - start];
                    }
                }

                ciphertext
            }
            CipherAlgorithm::Aes128Ctr => {
                use crate::aes::aes128_ctr_block;
                let key_arr: [u8; 16] = key[..16].try_into().unwrap();

                let block_size = 16;
                let num_blocks = (plaintext.len() + block_size - 1) / block_size;
                let mut ciphertext = vec![0u8; plaintext.len()];

                for block_idx in 0..num_blocks {
                    let c = counter + block_idx as u32;
                    let start = block_idx * block_size;
                    let end = (start + block_size).min(plaintext.len());

                    let mut pt_block = [0u8; 16];
                    pt_block[..end - start].copy_from_slice(&plaintext[start..end]);

                    let ct_block = aes128_ctr_block(&key_arr, nonce, c, &pt_block);

                    ciphertext[start..end].copy_from_slice(&ct_block[..end - start]);
                }

                ciphertext
            }
            CipherAlgorithm::Aes256Ctr => {
                use crate::aes::aes256_ctr_block;
                let key_arr: [u8; 32] = key[..32].try_into().unwrap();

                let block_size = 16;
                let num_blocks = (plaintext.len() + block_size - 1) / block_size;
                let mut ciphertext = vec![0u8; plaintext.len()];

                for block_idx in 0..num_blocks {
                    let c = counter + block_idx as u32;
                    let start = block_idx * block_size;
                    let end = (start + block_size).min(plaintext.len());

                    let mut pt_block = [0u8; 16];
                    pt_block[..end - start].copy_from_slice(&plaintext[start..end]);

                    let ct_block = aes256_ctr_block(&key_arr, nonce, c, &pt_block);

                    ciphertext[start..end].copy_from_slice(&ct_block[..end - start]);
                }

                ciphertext
            }
        }
    }

    fn bytes_to_bigint256_gnark(bytes: &[u8]) -> BigInt256 {
        if bytes.is_empty() {
            return BigInt256::zero();
        }

        let mut reversed: Vec<u8> = bytes.to_vec();
        reversed.reverse();
        BigInt256::from_bytes_be(&reversed)
    }

    #[test]
    fn test_verify_combined_chacha20() {
        let inputs = create_test_inputs(CipherAlgorithm::ChaCha20);
        let result = verify_combined_native(&inputs);
        assert!(result.is_ok(), "Combined verification failed: {:?}", result);
    }

    #[test]
    fn test_verify_combined_aes128() {
        let inputs = create_test_inputs(CipherAlgorithm::Aes128Ctr);
        let result = verify_combined_native(&inputs);
        assert!(result.is_ok(), "Combined verification failed: {:?}", result);
    }

    #[test]
    fn test_verify_combined_aes256() {
        let inputs = create_test_inputs(CipherAlgorithm::Aes256Ctr);
        let result = verify_combined_native(&inputs);
        assert!(result.is_ok(), "Combined verification failed: {:?}", result);
    }

    #[test]
    fn test_cipher_verification_fails_on_bad_ciphertext() {
        let mut inputs = create_test_inputs(CipherAlgorithm::ChaCha20);
        // Corrupt the ciphertext
        inputs.ciphertext[0] ^= 0xFF;

        let result = verify_combined_native(&inputs);
        assert!(result.is_err());
    }
}
