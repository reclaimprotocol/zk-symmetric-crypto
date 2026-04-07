//! Production WASM API for symmetric cipher proofs.
//!
//! Accepts actual key/nonce/plaintext/ciphertext data for proving.
//! Supports separate prove/verify workflow with serialized proofs.

use std::simd::u32x16;

use wasm_bindgen::prelude::*;

use std::simd::Simd;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::json;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;

use crate::chacha::bitwise::air_stream::{prove_stream_with_inputs, verify_stream_with_public_inputs, StreamProof};
use crate::chacha::bitwise::gen_stream::ChaChaStreamInput;
use crate::chacha::block::chacha20_block_from_key;
use crate::aes::lookup::air_ctr::{prove_aes128_ctr_with_inputs, prove_aes256_ctr_with_inputs, verify_aes_ctr_with_public_inputs, AESCtrProof};
use crate::aes::lookup::gen_ctr::AESCtrInput;
use crate::aes::{AesKeySize, aes128_ctr_block, aes256_ctr_block};

type Blake2sMerkleHasher = stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;

/// Maximum proof size in base64 (8 MB) to prevent memory DoS.
const MAX_PROOF_B64_LEN: usize = 8 * 1024 * 1024;

/// Minimum acceptable PCS config for verification.
/// This prevents malicious provers from using weak STARK settings.
/// Uses default values which provide ~100 bits of security.
fn min_pcs_config() -> PcsConfig {
    PcsConfig::default()
}

/// Build a JSON error response with proper escaping.
fn json_error(msg: impl std::fmt::Display) -> String {
    json!({ "error": msg.to_string() }).to_string()
}

// ============================================================================
// ChaCha20 API
// ============================================================================

/// Prove ChaCha20 encryption.
///
/// # Arguments
/// * `key` - 32-byte key (Uint8Array) - PRIVATE
/// * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
/// * `counter` - Starting counter value - PUBLIC
/// * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 64) - PUBLIC
/// * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
///
/// # Returns
/// JSON string: {"success": true, "blocks": N} or {"error": "..."}
///
/// # What the proof demonstrates
/// "I know a secret key K such that ChaCha20(K, nonce, counter, plaintext) = ciphertext"
/// The key remains private - the verifier learns nothing about it.
#[wasm_bindgen]
pub fn prove_chacha20_encrypt(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    // Validate inputs
    if key.len() != 32 {
        return json_error(format!("Key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }
    if plaintext.is_empty() || plaintext.len() % 64 != 0 {
        return json_error(format!("Plaintext must be non-empty multiple of 64 bytes, got {}", plaintext.len()));
    }
    if ciphertext.len() != plaintext.len() {
        return json_error(format!("Ciphertext must be same length as plaintext, got {} vs {}", ciphertext.len(), plaintext.len()));
    }

    let num_blocks = plaintext.len() / 64;

    // Validate counter won't overflow (max counter used is counter + num_blocks - 1)
    if num_blocks > 1 && counter.checked_add(num_blocks as u32 - 1).is_none() {
        return json_error(format!("Counter overflow: counter {} + {} blocks would exceed u32::MAX", counter, num_blocks));
    }

    let log_size = ((num_blocks as f64).log2().ceil() as u32).max(4);

    // Parse key as 8 little-endian u32s
    let key_u32: [u32; 8] = std::array::from_fn(|i| {
        u32::from_le_bytes([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]])
    });

    // Parse nonce as 3 little-endian u32s
    let nonce_u32: [u32; 3] = std::array::from_fn(|i| {
        u32::from_le_bytes([nonce[i*4], nonce[i*4+1], nonce[i*4+2], nonce[i*4+3]])
    });

    // Build inputs - each row processes 16 blocks in parallel
    let rows_needed = (num_blocks + 15) / 16;
    let mut inputs = Vec::with_capacity(rows_needed);

    for row in 0..rows_needed {
        let base_block = row * 16;
        let counters = u32x16::from_array(std::array::from_fn(|lane| {
            counter + (base_block + lane) as u32
        }));

        // Parse plaintext for this row
        let plaintext_u32: [u32x16; 16] = std::array::from_fn(|word_idx| {
            u32x16::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    let byte_offset = block_idx * 64 + word_idx * 4;
                    u32::from_le_bytes([
                        plaintext[byte_offset],
                        plaintext[byte_offset + 1],
                        plaintext[byte_offset + 2],
                        plaintext[byte_offset + 3],
                    ])
                } else {
                    0
                }
            }))
        });

        // For padding lanes (block_idx >= num_blocks), we need ciphertext = keystream
        // since plaintext is 0 and validation checks: keystream XOR plaintext == ciphertext
        // Pre-compute keystreams for padding lanes in this row
        let padding_keystreams: Vec<[u32; 16]> = (0..16)
            .filter_map(|lane| {
                let block_idx = base_block + lane;
                if block_idx >= num_blocks {
                    let padding_counter = counter + block_idx as u32;
                    Some(chacha20_block_from_key(&key_u32, padding_counter, &nonce_u32))
                } else {
                    None
                }
            })
            .collect();

        // Parse ciphertext for this row
        let ciphertext_u32: [u32x16; 16] = std::array::from_fn(|word_idx| {
            u32x16::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    let byte_offset = block_idx * 64 + word_idx * 4;
                    u32::from_le_bytes([
                        ciphertext[byte_offset],
                        ciphertext[byte_offset + 1],
                        ciphertext[byte_offset + 2],
                        ciphertext[byte_offset + 3],
                    ])
                } else {
                    // Use keystream as ciphertext for padding (since plaintext is 0)
                    let padding_idx = block_idx - num_blocks;
                    padding_keystreams[padding_idx][word_idx]
                }
            }))
        });

        inputs.push(ChaChaStreamInput {
            key: key_u32,
            nonce: nonce_u32,
            counters,
            plaintext: plaintext_u32,
            ciphertext: ciphertext_u32,
        });
    }

    let config = PcsConfig::default();
    let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
    let proof = match prove_stream_with_inputs::<Blake2sMerkleChannel>(
        log_size, config, &nonce_arr, counter, plaintext, ciphertext, &inputs
    ) {
        Ok(p) => p,
        Err(e) => return json_error(e),
    };

    match verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
        proof, &min_pcs_config(), &nonce_arr, counter, plaintext, ciphertext
    ) {
        Ok(_) => json!({"success": true, "blocks": num_blocks, "algorithm": "chacha20"}).to_string(),
        Err(e) => json_error(format!("Verification failed: {:?}", e)),
    }
}

// ============================================================================
// AES-128-CTR API
// ============================================================================

/// Prove AES-128-CTR encryption.
///
/// # Arguments
/// * `key` - 16-byte key (Uint8Array) - PRIVATE
/// * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
/// * `counter` - Starting counter value - PUBLIC
/// * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 16) - PUBLIC
/// * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
///
/// # Returns
/// JSON string: {"success": true, "blocks": N} or {"error": "..."}
///
/// # What the proof demonstrates
/// "I know a secret key K such that AES-128-CTR(K, nonce, counter, plaintext) = ciphertext"
/// The key remains private - the verifier learns nothing about it.
#[wasm_bindgen]
pub fn prove_aes128_ctr_encrypt(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    if key.len() != 16 {
        return json_error(format!("Key must be 16 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return json_error(format!("Plaintext must be non-empty multiple of 16 bytes, got {}", plaintext.len()));
    }
    if ciphertext.len() != plaintext.len() {
        return json_error(format!("Ciphertext must be same length as plaintext, got {} vs {}", ciphertext.len(), plaintext.len()));
    }

    let num_blocks = plaintext.len() / 16;

    // Validate counter won't overflow (max counter used is counter + num_blocks - 1)
    if num_blocks > 1 && counter.checked_add(num_blocks as u32 - 1).is_none() {
        return json_error(format!("Counter overflow: counter {} + {} blocks would exceed u32::MAX", counter, num_blocks));
    }

    let log_size = ((num_blocks as f64).log2().ceil() as u32).max(8);

    // Parse key
    let key_arr: [u8; 16] = match key.try_into() {
        Ok(k) => k,
        Err(_) => return json_error("Invalid key length"),
    };

    // Parse nonce
    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(n) => n,
        Err(_) => return json_error("Invalid nonce length"),
    };

    // Build inputs - each row processes 16 blocks in parallel
    let rows_needed = (num_blocks + 15) / 16;
    let mut inputs = Vec::with_capacity(rows_needed);

    for row in 0..rows_needed {
        let base_block = row * 16;
        let counters = Simd::from_array(std::array::from_fn(|lane| {
            counter + (base_block + lane) as u32
        }));

        // For padding lanes (block_idx >= num_blocks), we need ciphertext = keystream
        // since plaintext is 0 and validation checks: keystream XOR plaintext == ciphertext
        // Pre-compute keystreams for padding lanes in this row
        let padding_keystreams: Vec<[u8; 16]> = (0..16)
            .filter_map(|lane| {
                let block_idx = base_block + lane;
                if block_idx >= num_blocks {
                    let padding_counter = counter + block_idx as u32;
                    // plaintext = 0, so ciphertext = keystream
                    Some(aes128_ctr_block(&key_arr, &nonce_arr, padding_counter, &[0u8; 16]))
                } else {
                    None
                }
            })
            .collect();

        // Parse plaintext for this row (16 bytes per block, 16 parallel blocks)
        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    plaintext[block_idx * 16 + byte_idx]
                } else {
                    0
                }
            }))
        });

        // Parse ciphertext for this row
        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    ciphertext[block_idx * 16 + byte_idx]
                } else {
                    // Use keystream as ciphertext for padding (since plaintext is 0)
                    let padding_idx = block_idx - num_blocks;
                    padding_keystreams[padding_idx][byte_idx]
                }
            }))
        });

        inputs.push(AESCtrInput {
            nonce: nonce_arr,
            counters,
            plaintext: plaintext_simd,
            ciphertext: ciphertext_simd,
        });
    }

    let config = PcsConfig::default();
    let proof = match prove_aes128_ctr_with_inputs::<Blake2sMerkleChannel>(
        log_size, config, &key_arr, &nonce_arr, counter, plaintext, ciphertext, &inputs
    ) {
        Ok(p) => p,
        Err(e) => return json_error(e),
    };

    match verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
        proof, &min_pcs_config(), &nonce_arr, counter, plaintext, ciphertext
    ) {
        Ok(_) => json!({"success": true, "blocks": num_blocks, "algorithm": "aes128-ctr"}).to_string(),
        Err(e) => json_error(format!("Verification failed: {:?}", e)),
    }
}

/// Prove AES-256-CTR encryption.
///
/// # Arguments
/// * `key` - 32-byte key (Uint8Array) - PRIVATE
/// * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
/// * `counter` - Starting counter value - PUBLIC
/// * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 16) - PUBLIC
/// * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
///
/// # Returns
/// JSON string: {"success": true, "blocks": N} or {"error": "..."}
///
/// # What the proof demonstrates
/// "I know a secret key K such that AES-256-CTR(K, nonce, counter, plaintext) = ciphertext"
/// The key remains private - the verifier learns nothing about it.
#[wasm_bindgen]
pub fn prove_aes256_ctr_encrypt(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    if key.len() != 32 {
        return json_error(format!("Key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return json_error(format!("Plaintext must be non-empty multiple of 16 bytes, got {}", plaintext.len()));
    }
    if ciphertext.len() != plaintext.len() {
        return json_error(format!("Ciphertext must be same length as plaintext, got {} vs {}", ciphertext.len(), plaintext.len()));
    }

    let num_blocks = plaintext.len() / 16;

    // Validate counter won't overflow (max counter used is counter + num_blocks - 1)
    if num_blocks > 1 && counter.checked_add(num_blocks as u32 - 1).is_none() {
        return json_error(format!("Counter overflow: counter {} + {} blocks would exceed u32::MAX", counter, num_blocks));
    }

    let log_size = ((num_blocks as f64).log2().ceil() as u32).max(8);

    // Parse key
    let key_arr: [u8; 32] = match key.try_into() {
        Ok(k) => k,
        Err(_) => return json_error("Invalid key length"),
    };

    // Parse nonce
    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(n) => n,
        Err(_) => return json_error("Invalid nonce length"),
    };

    // Build inputs - each row processes 16 blocks in parallel
    let rows_needed = (num_blocks + 15) / 16;
    let mut inputs = Vec::with_capacity(rows_needed);

    for row in 0..rows_needed {
        let base_block = row * 16;
        let counters = Simd::from_array(std::array::from_fn(|lane| {
            counter + (base_block + lane) as u32
        }));

        // For padding lanes (block_idx >= num_blocks), we need ciphertext = keystream
        // since plaintext is 0 and validation checks: keystream XOR plaintext == ciphertext
        // Pre-compute keystreams for padding lanes in this row
        let padding_keystreams: Vec<[u8; 16]> = (0..16)
            .filter_map(|lane| {
                let block_idx = base_block + lane;
                if block_idx >= num_blocks {
                    let padding_counter = counter + block_idx as u32;
                    // plaintext = 0, so ciphertext = keystream
                    Some(aes256_ctr_block(&key_arr, &nonce_arr, padding_counter, &[0u8; 16]))
                } else {
                    None
                }
            })
            .collect();

        // Parse plaintext for this row (16 bytes per block, 16 parallel blocks)
        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    plaintext[block_idx * 16 + byte_idx]
                } else {
                    0
                }
            }))
        });

        // Parse ciphertext for this row
        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    ciphertext[block_idx * 16 + byte_idx]
                } else {
                    // Use keystream as ciphertext for padding (since plaintext is 0)
                    let padding_idx = block_idx - num_blocks;
                    padding_keystreams[padding_idx][byte_idx]
                }
            }))
        });

        inputs.push(AESCtrInput {
            nonce: nonce_arr,
            counters,
            plaintext: plaintext_simd,
            ciphertext: ciphertext_simd,
        });
    }

    let config = PcsConfig::default();
    let proof = match prove_aes256_ctr_with_inputs::<Blake2sMerkleChannel>(
        log_size, config, &key_arr, &nonce_arr, counter, plaintext, ciphertext, &inputs
    ) {
        Ok(p) => p,
        Err(e) => return json_error(e),
    };

    match verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
        proof, &min_pcs_config(), &nonce_arr, counter, plaintext, ciphertext
    ) {
        Ok(_) => json!({"success": true, "blocks": num_blocks, "algorithm": "aes256-ctr"}).to_string(),
        Err(e) => json_error(format!("Verification failed: {:?}", e)),
    }
}

// ============================================================================
// Proof Generation (returns serialized proof for separate verification)
// ============================================================================

/// Generate ChaCha20 proof and return it serialized (base64).
/// Use verify_chacha20_proof() to verify the proof separately.
#[wasm_bindgen]
pub fn generate_chacha20_proof(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    // Validate inputs
    if key.len() != 32 {
        return json_error(format!("Key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }
    if plaintext.is_empty() || plaintext.len() % 64 != 0 {
        return json_error(format!("Plaintext must be non-empty multiple of 64 bytes, got {}", plaintext.len()));
    }
    if ciphertext.len() != plaintext.len() {
        return json_error(format!("Ciphertext must be same length as plaintext, got {} vs {}", ciphertext.len(), plaintext.len()));
    }

    let num_blocks = plaintext.len() / 64;

    // Validate counter won't overflow (max counter used is counter + num_blocks - 1)
    if num_blocks > 1 && counter.checked_add(num_blocks as u32 - 1).is_none() {
        return json_error(format!("Counter overflow: counter {} + {} blocks would exceed u32::MAX", counter, num_blocks));
    }

    let log_size = ((num_blocks as f64).log2().ceil() as u32).max(4);

    // Parse key as 8 little-endian u32s
    let key_u32: [u32; 8] = std::array::from_fn(|i| {
        u32::from_le_bytes([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]])
    });

    // Parse nonce as 3 little-endian u32s
    let nonce_u32: [u32; 3] = std::array::from_fn(|i| {
        u32::from_le_bytes([nonce[i*4], nonce[i*4+1], nonce[i*4+2], nonce[i*4+3]])
    });

    // Build inputs
    let rows_needed = (num_blocks + 15) / 16;
    let mut inputs = Vec::with_capacity(rows_needed);

    for row in 0..rows_needed {
        let base_block = row * 16;
        let counters = u32x16::from_array(std::array::from_fn(|lane| {
            counter + (base_block + lane) as u32
        }));

        let plaintext_u32: [u32x16; 16] = std::array::from_fn(|word_idx| {
            u32x16::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    let byte_offset = block_idx * 64 + word_idx * 4;
                    u32::from_le_bytes([
                        plaintext[byte_offset],
                        plaintext[byte_offset + 1],
                        plaintext[byte_offset + 2],
                        plaintext[byte_offset + 3],
                    ])
                } else {
                    0
                }
            }))
        });

        // For padding lanes (block_idx >= num_blocks), we need ciphertext = keystream
        // since plaintext is 0 and validation checks: keystream XOR plaintext == ciphertext
        // Pre-compute keystreams for padding lanes in this row
        let padding_keystreams: Vec<[u32; 16]> = (0..16)
            .filter_map(|lane| {
                let block_idx = base_block + lane;
                if block_idx >= num_blocks {
                    let padding_counter = counter + block_idx as u32;
                    Some(chacha20_block_from_key(&key_u32, padding_counter, &nonce_u32))
                } else {
                    None
                }
            })
            .collect();

        let ciphertext_u32: [u32x16; 16] = std::array::from_fn(|word_idx| {
            u32x16::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    let byte_offset = block_idx * 64 + word_idx * 4;
                    u32::from_le_bytes([
                        ciphertext[byte_offset],
                        ciphertext[byte_offset + 1],
                        ciphertext[byte_offset + 2],
                        ciphertext[byte_offset + 3],
                    ])
                } else {
                    // Use keystream as ciphertext for padding (since plaintext is 0)
                    let padding_idx = block_idx - num_blocks;
                    padding_keystreams[padding_idx][word_idx]
                }
            }))
        });

        inputs.push(ChaChaStreamInput {
            key: key_u32,
            nonce: nonce_u32,
            counters,
            plaintext: plaintext_u32,
            ciphertext: ciphertext_u32,
        });
    }

    let config = PcsConfig::default();
    let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
    let proof = match prove_stream_with_inputs::<Blake2sMerkleChannel>(
        log_size, config, &nonce_arr, counter, plaintext, ciphertext, &inputs
    ) {
        Ok(p) => p,
        Err(e) => return json_error(e),
    };

    // Serialize proof - public inputs are cryptographically bound via Fiat-Shamir hashes
    // inside stmt.public_inputs, so we don't need to send raw data separately
    let proof_bytes = match bincode::serialize(&proof) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Failed to serialize proof: {}", e)),
    };
    let proof_b64 = BASE64.encode(&proof_bytes);
    let proof_size = proof.stark_proof.size_estimate();

    json!({
        "success": true,
        "blocks": num_blocks,
        "algorithm": "chacha20",
        "proof": proof_b64,
        "proof_size_bytes": proof_size
    }).to_string()
}

/// Verify a ChaCha20 proof (base64-encoded) against verifier-supplied public inputs.
///
/// The verifier must provide the expected nonce, counter, plaintext, and ciphertext.
/// Verification fails if the proof was generated for different data.
#[wasm_bindgen]
pub fn verify_chacha20_proof(
    proof_b64: &str,
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    // Check proof size to prevent memory DoS
    if proof_b64.len() > MAX_PROOF_B64_LEN {
        return json_error("Proof payload too large");
    }

    // Validate inputs
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }

    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(n) => n,
        Err(_) => return json_error("Invalid nonce length"),
    };

    let proof_bytes = match BASE64.decode(proof_b64) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid base64: {}", e)),
    };

    let proof: StreamProof<Blake2sMerkleHasher> = match bincode::deserialize(&proof_bytes) {
        Ok(p) => p,
        Err(e) => return json_error(format!("Invalid proof format: {}", e)),
    };

    // Verify with verifier-supplied public inputs and minimum config validation
    match verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
        proof, &min_pcs_config(), &nonce_arr, counter, plaintext, ciphertext
    ) {
        Ok(_) => json!({"valid": true, "algorithm": "chacha20"}).to_string(),
        Err(e) => json!({"valid": false, "error": format!("{:?}", e)}).to_string(),
    }
}

/// Generate AES-128-CTR proof and return it serialized (base64).
#[wasm_bindgen]
pub fn generate_aes128_ctr_proof(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    if key.len() != 16 {
        return json_error(format!("Key must be 16 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return json_error(format!("Plaintext must be non-empty multiple of 16 bytes, got {}", plaintext.len()));
    }
    if ciphertext.len() != plaintext.len() {
        return json_error(format!("Ciphertext must be same length as plaintext, got {} vs {}", ciphertext.len(), plaintext.len()));
    }

    let num_blocks = plaintext.len() / 16;

    // Validate counter won't overflow (max counter used is counter + num_blocks - 1)
    if num_blocks > 1 && counter.checked_add(num_blocks as u32 - 1).is_none() {
        return json_error(format!("Counter overflow: counter {} + {} blocks would exceed u32::MAX", counter, num_blocks));
    }

    let log_size = ((num_blocks as f64).log2().ceil() as u32).max(8);

    let key_arr: [u8; 16] = match key.try_into() {
        Ok(k) => k,
        Err(_) => return json_error("Invalid key length"),
    };

    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(n) => n,
        Err(_) => return json_error("Invalid nonce length"),
    };

    let rows_needed = (num_blocks + 15) / 16;
    let mut inputs = Vec::with_capacity(rows_needed);

    for row in 0..rows_needed {
        let base_block = row * 16;
        let counters = Simd::from_array(std::array::from_fn(|lane| {
            counter + (base_block + lane) as u32
        }));

        // For padding lanes (block_idx >= num_blocks), we need ciphertext = keystream
        // since plaintext is 0 and validation checks: keystream XOR plaintext == ciphertext
        // Pre-compute keystreams for padding lanes in this row
        let padding_keystreams: Vec<[u8; 16]> = (0..16)
            .filter_map(|lane| {
                let block_idx = base_block + lane;
                if block_idx >= num_blocks {
                    let padding_counter = counter + block_idx as u32;
                    // plaintext = 0, so ciphertext = keystream
                    Some(aes128_ctr_block(&key_arr, &nonce_arr, padding_counter, &[0u8; 16]))
                } else {
                    None
                }
            })
            .collect();

        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    plaintext[block_idx * 16 + byte_idx]
                } else {
                    0
                }
            }))
        });

        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    ciphertext[block_idx * 16 + byte_idx]
                } else {
                    // Use keystream as ciphertext for padding (since plaintext is 0)
                    let padding_idx = block_idx - num_blocks;
                    padding_keystreams[padding_idx][byte_idx]
                }
            }))
        });

        inputs.push(AESCtrInput {
            nonce: nonce_arr,
            counters,
            plaintext: plaintext_simd,
            ciphertext: ciphertext_simd,
        });
    }

    let config = PcsConfig::default();
    let proof = match prove_aes128_ctr_with_inputs::<Blake2sMerkleChannel>(
        log_size, config, &key_arr, &nonce_arr, counter, plaintext, ciphertext, &inputs
    ) {
        Ok(p) => p,
        Err(e) => return json_error(e),
    };

    // Serialize proof - public inputs are cryptographically bound via Fiat-Shamir hashes
    // inside stmt0.public_inputs, so we don't need to send raw data separately
    let proof_bytes = match bincode::serialize(&proof) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Failed to serialize proof: {}", e)),
    };
    let proof_b64 = BASE64.encode(&proof_bytes);
    let proof_size = proof.stark_proof.size_estimate();

    json!({
        "success": true,
        "blocks": num_blocks,
        "algorithm": "aes128-ctr",
        "proof": proof_b64,
        "proof_size_bytes": proof_size
    }).to_string()
}

/// Generate AES-256-CTR proof and return it serialized (base64).
#[wasm_bindgen]
pub fn generate_aes256_ctr_proof(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    if key.len() != 32 {
        return json_error(format!("Key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return json_error(format!("Plaintext must be non-empty multiple of 16 bytes, got {}", plaintext.len()));
    }
    if ciphertext.len() != plaintext.len() {
        return json_error(format!("Ciphertext must be same length as plaintext, got {} vs {}", ciphertext.len(), plaintext.len()));
    }

    let num_blocks = plaintext.len() / 16;

    // Validate counter won't overflow (max counter used is counter + num_blocks - 1)
    if num_blocks > 1 && counter.checked_add(num_blocks as u32 - 1).is_none() {
        return json_error(format!("Counter overflow: counter {} + {} blocks would exceed u32::MAX", counter, num_blocks));
    }

    let log_size = ((num_blocks as f64).log2().ceil() as u32).max(8);

    let key_arr: [u8; 32] = match key.try_into() {
        Ok(k) => k,
        Err(_) => return json_error("Invalid key length"),
    };

    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(n) => n,
        Err(_) => return json_error("Invalid nonce length"),
    };

    let rows_needed = (num_blocks + 15) / 16;
    let mut inputs = Vec::with_capacity(rows_needed);

    for row in 0..rows_needed {
        let base_block = row * 16;
        let counters = Simd::from_array(std::array::from_fn(|lane| {
            counter + (base_block + lane) as u32
        }));

        // For padding lanes (block_idx >= num_blocks), we need ciphertext = keystream
        // since plaintext is 0 and validation checks: keystream XOR plaintext == ciphertext
        // Pre-compute keystreams for padding lanes in this row
        let padding_keystreams: Vec<[u8; 16]> = (0..16)
            .filter_map(|lane| {
                let block_idx = base_block + lane;
                if block_idx >= num_blocks {
                    let padding_counter = counter + block_idx as u32;
                    // plaintext = 0, so ciphertext = keystream
                    Some(aes256_ctr_block(&key_arr, &nonce_arr, padding_counter, &[0u8; 16]))
                } else {
                    None
                }
            })
            .collect();

        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    plaintext[block_idx * 16 + byte_idx]
                } else {
                    0
                }
            }))
        });

        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                let block_idx = base_block + lane;
                if block_idx < num_blocks {
                    ciphertext[block_idx * 16 + byte_idx]
                } else {
                    // Use keystream as ciphertext for padding (since plaintext is 0)
                    let padding_idx = block_idx - num_blocks;
                    padding_keystreams[padding_idx][byte_idx]
                }
            }))
        });

        inputs.push(AESCtrInput {
            nonce: nonce_arr,
            counters,
            plaintext: plaintext_simd,
            ciphertext: ciphertext_simd,
        });
    }

    let config = PcsConfig::default();
    let proof = match prove_aes256_ctr_with_inputs::<Blake2sMerkleChannel>(
        log_size, config, &key_arr, &nonce_arr, counter, plaintext, ciphertext, &inputs
    ) {
        Ok(p) => p,
        Err(e) => return json_error(e),
    };

    // Serialize proof - public inputs are cryptographically bound via Fiat-Shamir hashes
    // inside stmt0.public_inputs, so we don't need to send raw data separately
    let proof_bytes = match bincode::serialize(&proof) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Failed to serialize proof: {}", e)),
    };
    let proof_b64 = BASE64.encode(&proof_bytes);
    let proof_size = proof.stark_proof.size_estimate();

    json!({
        "success": true,
        "blocks": num_blocks,
        "algorithm": "aes256-ctr",
        "proof": proof_b64,
        "proof_size_bytes": proof_size
    }).to_string()
}

/// Verify an AES-CTR proof (base64-encoded) against verifier-supplied public inputs.
/// Works for both AES-128 and AES-256.
///
/// The verifier must provide the expected nonce, counter, plaintext, and ciphertext.
/// Verification fails if the proof was generated for different data.
#[wasm_bindgen]
pub fn verify_aes_ctr_proof(
    proof_b64: &str,
    nonce: &[u8],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> String {
    // Check proof size to prevent memory DoS
    if proof_b64.len() > MAX_PROOF_B64_LEN {
        return json_error("Proof payload too large");
    }

    // Validate inputs
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }

    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(n) => n,
        Err(_) => return json_error("Invalid nonce length"),
    };

    let proof_bytes = match BASE64.decode(proof_b64) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid base64: {}", e)),
    };

    let proof: AESCtrProof<Blake2sMerkleHasher> = match bincode::deserialize(&proof_bytes) {
        Ok(p) => p,
        Err(e) => return json_error(format!("Invalid proof format: {}", e)),
    };

    let algorithm = if proof.stmt0.key_size == AesKeySize::Aes128 { "aes128-ctr" } else { "aes256-ctr" };

    // Verify with verifier-supplied public inputs and minimum config validation
    match verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
        proof, &min_pcs_config(), &nonce_arr, counter, plaintext, ciphertext
    ) {
        Ok(_) => json!({"valid": true, "algorithm": algorithm}).to_string(),
        Err(e) => json!({"valid": false, "error": format!("{:?}", e)}).to_string(),
    }
}

// ============================================================================
// Utility
// ============================================================================

/// Debug: compute ChaCha20 keystream and return it (for debugging WASM issues).
#[wasm_bindgen]
pub fn debug_chacha20_keystream(
    key: &[u8],
    nonce: &[u8],
    counter: u32,
) -> String {
    use crate::chacha::block::{chacha20_block_from_key, state_to_bytes};

    if key.len() != 32 {
        return json_error(format!("Key must be 32 bytes, got {}", key.len()));
    }
    if nonce.len() != 12 {
        return json_error(format!("Nonce must be 12 bytes, got {}", nonce.len()));
    }

    // Parse key as 8 little-endian u32s
    let key_u32: [u32; 8] = std::array::from_fn(|i| {
        u32::from_le_bytes([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]])
    });

    // Parse nonce as 3 little-endian u32s
    let nonce_u32: [u32; 3] = std::array::from_fn(|i| {
        u32::from_le_bytes([nonce[i*4], nonce[i*4+1], nonce[i*4+2], nonce[i*4+3]])
    });

    // Compute keystream
    let keystream_u32 = chacha20_block_from_key(&key_u32, counter, &nonce_u32);
    let keystream_bytes = state_to_bytes(&keystream_u32);

    // Return as hex (do not include key material in response for security)
    let hex: String = keystream_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    json!({
        "keystream_hex": hex,
        "counter": counter,
        "nonce_len": nonce.len(),
        "key_len": key.len()
    }).to_string()
}

/// Get circuit information as JSON.
#[wasm_bindgen]
pub fn get_circuits_info() -> String {
    use crate::aes::lookup::{aes128_ctr_info, aes256_ctr_info};
    use crate::chacha::bitwise::chacha_stream_info;

    let aes128 = aes128_ctr_info();
    let aes256 = aes256_ctr_info();
    let chacha = chacha_stream_info();

    format!(
        r#"{{"aes128_ctr":{{"cols":{},"constraints":{},"block_bytes":16,"key_bytes":16}},"aes256_ctr":{{"cols":{},"constraints":{},"block_bytes":16,"key_bytes":32}},"chacha20":{{"cols":{},"constraints":{},"block_bytes":64,"key_bytes":32}}}}"#,
        aes128.mask_offsets[1].len(), aes128.n_constraints,
        aes256.mask_offsets[1].len(), aes256.n_constraints,
        chacha.mask_offsets[1].len(), chacha.n_constraints,
    )
}
