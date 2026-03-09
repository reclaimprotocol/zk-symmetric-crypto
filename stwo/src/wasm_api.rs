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
    let proof_bytes = match serde_json::to_vec(&proof) {
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

    let proof: StreamProof<Blake2sMerkleHasher> = match serde_json::from_slice(&proof_bytes) {
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
    let proof_bytes = match serde_json::to_vec(&proof) {
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
    let proof_bytes = match serde_json::to_vec(&proof) {
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

    let proof: AESCtrProof<Blake2sMerkleHasher> = match serde_json::from_slice(&proof_bytes) {
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
    use crate::babyjub::toprf::air::toprf_info;

    let aes128 = aes128_ctr_info();
    let aes256 = aes256_ctr_info();
    let chacha = chacha_stream_info();
    let toprf = toprf_info();

    format!(
        r#"{{"aes128_ctr":{{"cols":{},"constraints":{},"block_bytes":16,"key_bytes":16}},"aes256_ctr":{{"cols":{},"constraints":{},"block_bytes":16,"key_bytes":32}},"chacha20":{{"cols":{},"constraints":{},"block_bytes":64,"key_bytes":32}},"toprf":{{"cols":{},"constraints":{}}}}}"#,
        aes128.mask_offsets[1].len(), aes128.n_constraints,
        aes256.mask_offsets[1].len(), aes256.n_constraints,
        chacha.mask_offsets[1].len(), chacha.n_constraints,
        toprf.mask_offsets[1].len(), toprf.n_constraints,
    )
}

// ============================================================================
// TOPRF API
// ============================================================================

/// Benchmark native TOPRF verification (no ZK proof, just the crypto operations).
///
/// This measures the time for scalar multiplications, hashing, etc.
/// Returns JSON with timing info.
#[wasm_bindgen]
pub fn bench_toprf_native(secret_bytes: &[u8], domain_separator: u32) -> String {
    use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
    use crate::babyjub::mimc::gen::hash_field256_native;
    use crate::babyjub::point::gen::native as point_native;
    use crate::babyjub::toprf::{AffinePointBigInt, TOPRFInputs, TOPRFPrivateInputs, TOPRFPublicInputs};
    use crate::babyjub::toprf::gen::verify_toprf_native;
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use crate::toprf_server::eval::{evaluate_oprf, hash_to_point, mask_point};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Setup
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let p = modulus();
    let order = scalar_order();

    // Convert secret to field elements
    let secret_data = bytes_to_field256_elements(secret_bytes);
    let domain = BigInt256::from_limbs([domain_separator, 0, 0, 0, 0, 0, 0, 0, 0]);

    // Generate key (threshold=1)
    let shared_key = generate_shared_key(&mut rng, 1, 1);
    let share = &shared_key.shares[0];

    // Client: hash to point
    let data_point = hash_to_point(&secret_data, &domain);

    // Client: generate mask
    let mask = random_scalar(&mut rng);
    let masked_request = mask_point(&data_point, &mask);

    // Server: evaluate OPRF
    let response = match evaluate_oprf(&mut rng, share, &masked_request) {
        Some(r) => r,
        None => return json_error("OPRF eval failed: invalid point"),
    };

    // Client: unmask
    let mask_inv = match mask.inv_mod(&order) {
        Some(inv) => inv,
        None => return json_error("mask inverse failed"),
    };
    let unmasked = point_native::scalar_mul(&response.evaluated_point, &mask_inv);

    // Compute output
    let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);
    let output_hash = hash_field256_native(&[
        unmasked_x.clone(),
        unmasked_y.clone(),
        secret_data[0].clone(),
        secret_data[1].clone(),
    ]);

    // Create TOPRF inputs
    let (resp_x, resp_y) = response.evaluated_point.to_affine(&p);
    let (pub_x, pub_y) = share.public_key.to_affine(&p);

    let inputs = TOPRFInputs {
        private: TOPRFPrivateInputs {
            mask: mask.clone(),
            secret_data,
        },
        public: TOPRFPublicInputs {
            domain_separator: domain,
            responses: [AffinePointBigInt { x: resp_x, y: resp_y }],
            coefficients: [BigInt256::one()],
            share_public_keys: [AffinePointBigInt { x: pub_x, y: pub_y }],
            c: [response.c],
            r: [response.r],
            output: output_hash.0,
        },
    };

    // Benchmark native verification
    let start = web_sys_time();
    let result = verify_toprf_native(&inputs);
    let elapsed = web_sys_time() - start;

    match result {
        Ok(output) => json!({
            "success": true,
            "output": output.0,
            "time_ms": elapsed,
            "secret_len": secret_bytes.len(),
        }).to_string(),
        Err(e) => json_error(format!("Verification failed: {}", e)),
    }
}

/// Helper to get time in ms (for WASM).
fn web_sys_time() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now())
            .unwrap_or(0.0)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0.0
    }
}

/// Convert bytes to Field256 elements (helper).
fn bytes_to_field256_elements(bytes: &[u8]) -> [crate::babyjub::field256::gen::BigInt256; 2] {
    use crate::babyjub::field256::gen::BigInt256;

    let mut elem0 = BigInt256::zero();
    let mut elem1 = BigInt256::zero();

    if !bytes.is_empty() {
        let end = bytes.len().min(31);
        elem0 = bytes_to_bigint256_le(&bytes[..end]);
    }

    if bytes.len() > 31 {
        elem1 = bytes_to_bigint256_le(&bytes[31..]);
    }

    [elem0, elem1]
}

fn bytes_to_bigint256_le(bytes: &[u8]) -> crate::babyjub::field256::gen::BigInt256 {
    use crate::babyjub::field256::gen::BigInt256;

    let mut limbs = [0u32; 9];
    let mut bit_pos = 0;

    for &byte in bytes {
        let limb_idx = bit_pos / 29;
        let bit_offset = bit_pos % 29;

        if limb_idx < 9 {
            limbs[limb_idx] |= (byte as u32) << bit_offset;
            if bit_offset > 21 && limb_idx + 1 < 9 {
                limbs[limb_idx + 1] |= (byte as u32) >> (29 - bit_offset);
            }
        }
        bit_pos += 8;
    }

    for limb in &mut limbs {
        *limb &= 0x1FFFFFFF;
    }

    BigInt256::from_limbs(limbs)
}

/// Get TOPRF circuit info.
#[wasm_bindgen]
pub fn get_toprf_info() -> String {
    use crate::babyjub::toprf::air::toprf_info;
    use crate::babyjub::toprf::constraints::toprf_constraint_count;

    let info = toprf_info();

    json!({
        "cols": info.mask_offsets[1].len(),
        "constraints": info.n_constraints,
        "estimated_constraints": toprf_constraint_count(),
        "algorithm": "poseidon2_m31",
        "curve": "babyjub",
        "threshold": 1,
    }).to_string()
}

// ============================================================================
// TOPRF Full API (gnark-compatible JSON format)
// ============================================================================

/// Generate TOPRF shared keys for threshold scheme.
///
/// # Arguments
/// * `nodes` - Total number of nodes
/// * `threshold` - Minimum nodes required to reconstruct
/// * `seed` - Random seed for deterministic key generation (for testing)
///
/// # Returns
/// JSON string with:
/// - serverPublicKey: 64-byte hex-encoded point
/// - shares: Array of share objects with index, privateKey, publicKey
#[wasm_bindgen]
pub fn toprf_generate_keys(nodes: u32, threshold: u32, seed: u64) -> String {
    use crate::babyjub::field256::gen::modulus;
    use crate::toprf_server::dkg::generate_shared_key;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    if threshold > nodes || threshold == 0 {
        return json_error("threshold must be > 0 and <= nodes");
    }

    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let p = modulus();

    let shared_key = generate_shared_key(&mut rng, nodes as usize, threshold as usize);

    // Serialize server public key
    let server_pub_bytes = shared_key.server_public_key.to_bytes_gnark(&p);
    let server_pub_hex = hex::encode(server_pub_bytes);

    // Serialize shares
    let shares: Vec<_> = shared_key.shares.iter().map(|share| {
        let pub_bytes = share.public_key.to_bytes_gnark(&p);
        json!({
            "index": share.index,
            "privateKey": hex::encode(share.private_key.to_bytes_be_trimmed()),
            "publicKey": hex::encode(pub_bytes),
        })
    }).collect();

    json!({
        "serverPublicKey": server_pub_hex,
        "nodes": nodes,
        "threshold": threshold,
        "shares": shares,
    }).to_string()
}

/// Create OPRF request (client-side).
///
/// # Arguments
/// * `secret_bytes` - Secret data to hash (max 62 bytes)
/// * `domain_separator` - Domain separator string
///
/// # Returns
/// JSON string matching gnark's OPRFRequest format:
/// - mask: hex-encoded scalar
/// - maskedData: hex-encoded 64-byte point
/// - secretElements: [hex, hex] two field elements
#[wasm_bindgen]
pub fn toprf_create_request(secret_bytes: &[u8], domain_separator: &str) -> String {
    use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
    use crate::toprf_server::dkg::random_scalar;
    use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    if secret_bytes.len() > 62 {
        return json_error(format!("secret data too big: {}, max 62 bytes", secret_bytes.len()));
    }

    let p = modulus();

    // Convert secret bytes to field elements (gnark-compatible: BEtoLE)
    let secret_data = bytes_to_field256_elements_gnark(secret_bytes);

    // Domain separator as field element
    let domain_bytes = domain_separator.as_bytes();
    let domain = bytes_to_bigint256_gnark(domain_bytes);

    // Hash to curve point using MiMC (gnark-compatible)
    let data_point = hash_to_point_mimc(&secret_data, &domain);

    // Generate random mask
    let mut rng = ChaCha20Rng::from_entropy();
    let mask = random_scalar(&mut rng);

    // Mask the data point
    let masked_request = mask_point(&data_point, &mask);

    // Serialize in gnark format
    let mask_hex = hex::encode(mask.to_bytes_be_trimmed());
    let masked_data_hex = hex::encode(masked_request.to_bytes_gnark(&p));
    let secret_elem_0_hex = hex::encode(secret_data[0].to_bytes_be_trimmed());
    let secret_elem_1_hex = hex::encode(secret_data[1].to_bytes_be_trimmed());

    json!({
        "mask": mask_hex,
        "maskedData": masked_data_hex,
        "secretElements": [secret_elem_0_hex, secret_elem_1_hex],
    }).to_string()
}

/// Evaluate OPRF (server-side).
///
/// # Arguments
/// * `share_json` - JSON with share: { index, privateKey, publicKey }
/// * `masked_request_hex` - Hex-encoded 64-byte masked point
///
/// # Returns
/// JSON string matching gnark's OPRFResponse format:
/// - index: share index
/// - publicKeyShare: hex-encoded 64-byte point
/// - evaluated: hex-encoded 64-byte point
/// - c: hex-encoded DLEQ challenge
/// - r: hex-encoded DLEQ response
#[wasm_bindgen]
pub fn toprf_evaluate(share_json: &str, masked_request_hex: &str) -> String {
    use crate::babyjub::field256::gen::{modulus, BigInt256};
    use crate::babyjub::point::ExtendedPointBigInt;
    use crate::toprf_server::{Share, evaluate_oprf};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let p = modulus();

    // Parse share
    let share_value: serde_json::Value = match serde_json::from_str(share_json) {
        Ok(v) => v,
        Err(e) => return json_error(format!("Invalid share JSON: {}", e)),
    };

    let index = match share_value["index"].as_u64() {
        Some(i) => i as usize,
        None => return json_error("Missing or invalid share index"),
    };

    let private_key_hex = match share_value["privateKey"].as_str() {
        Some(s) => s,
        None => return json_error("Missing privateKey"),
    };

    let private_key_bytes = match hex::decode(private_key_hex) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid privateKey hex: {}", e)),
    };

    let public_key_hex = match share_value["publicKey"].as_str() {
        Some(s) => s,
        None => return json_error("Missing publicKey"),
    };

    let public_key_bytes = match hex::decode(public_key_hex) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid publicKey hex: {}", e)),
    };

    // Parse masked request
    let masked_bytes = match hex::decode(masked_request_hex) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid maskedRequest hex: {}", e)),
    };

    let private_key = BigInt256::from_bytes_be(&private_key_bytes);
    let public_key = match ExtendedPointBigInt::from_bytes_gnark(&public_key_bytes, &p) {
        Some(pt) => pt,
        None => return json_error("Invalid public key point"),
    };
    let masked_request = match ExtendedPointBigInt::from_bytes_gnark(&masked_bytes, &p) {
        Some(pt) => pt,
        None => return json_error("Invalid masked request point"),
    };

    let share = Share {
        index,
        private_key,
        public_key,
    };

    // Evaluate OPRF
    let mut rng = ChaCha20Rng::from_entropy();
    let response = match evaluate_oprf(&mut rng, &share, &masked_request) {
        Some(r) => r,
        None => return json_error("OPRF evaluation failed: invalid point"),
    };

    // Serialize response
    json!({
        "index": index,
        "publicKeyShare": hex::encode(public_key_bytes),
        "evaluated": hex::encode(response.evaluated_point.to_bytes_gnark(&p)),
        "c": hex::encode(response.c.to_bytes_be_trimmed()),
        "r": hex::encode(response.r.to_bytes_be_trimmed()),
    }).to_string()
}

/// Finalize TOPRF (client-side).
///
/// # Arguments
/// * `params_json` - JSON matching gnark's InputTOPRFFinalizeParams:
///   - serverPublicKey: hex-encoded 64-byte point
///   - request: { mask, maskedData, secretElements }
///   - responses: [{ index, publicKeyShare, evaluated, c, r }, ...]
///
/// # Returns
/// JSON string with:
/// - output: hex-encoded hash output
/// - outputDecimal: decimal string of output (for comparison)
#[wasm_bindgen]
pub fn toprf_finalize(params_json: &str) -> String {
    use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
    use crate::babyjub::point::ExtendedPointBigInt;
    use crate::toprf_server::{OPRFResponse, finalize_toprf_mimc};

    let p = modulus();

    // Parse params
    let params: serde_json::Value = match serde_json::from_str(params_json) {
        Ok(v) => v,
        Err(e) => return json_error(format!("Invalid params JSON: {}", e)),
    };

    // Parse server public key
    let server_pub_hex = match params["serverPublicKey"].as_str() {
        Some(s) => s,
        None => return json_error("Missing serverPublicKey"),
    };
    let server_pub_bytes = match hex::decode(server_pub_hex) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid serverPublicKey hex: {}", e)),
    };
    let _server_public_key = match ExtendedPointBigInt::from_bytes_gnark(&server_pub_bytes, &p) {
        Some(pt) => pt,
        None => return json_error("Invalid server public key point"),
    };

    // Parse request
    let request = &params["request"];
    let mask_hex = match request["mask"].as_str() {
        Some(s) => s,
        None => return json_error("Missing request.mask"),
    };
    let mask_bytes = match hex::decode(mask_hex) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid mask hex: {}", e)),
    };
    let mask = BigInt256::from_bytes_be(&mask_bytes);

    let masked_data_hex = match request["maskedData"].as_str() {
        Some(s) => s,
        None => return json_error("Missing request.maskedData"),
    };
    let masked_data_bytes = match hex::decode(masked_data_hex) {
        Ok(b) => b,
        Err(e) => return json_error(format!("Invalid maskedData hex: {}", e)),
    };
    let masked_request = match ExtendedPointBigInt::from_bytes_gnark(&masked_data_bytes, &p) {
        Some(pt) => pt,
        None => return json_error("Invalid masked data point"),
    };

    let secret_elements = match request["secretElements"].as_array() {
        Some(arr) if arr.len() == 2 => {
            let elem0_hex = arr[0].as_str().unwrap_or("");
            let elem1_hex = arr[1].as_str().unwrap_or("");
            let elem0_bytes = hex::decode(elem0_hex).unwrap_or_default();
            let elem1_bytes = hex::decode(elem1_hex).unwrap_or_default();
            [
                BigInt256::from_bytes_be(&elem0_bytes),
                BigInt256::from_bytes_be(&elem1_bytes),
            ]
        }
        _ => return json_error("Invalid secretElements"),
    };

    // Parse responses
    let responses_arr = match params["responses"].as_array() {
        Some(arr) => arr,
        None => return json_error("Missing responses array"),
    };

    let mut indices = Vec::new();
    let mut responses = Vec::new();
    let mut share_public_keys = Vec::new();

    for resp in responses_arr {
        let index = match resp["index"].as_u64() {
            Some(i) => i as usize,
            None => return json_error("Missing response index"),
        };
        indices.push(index);

        let pub_key_hex = match resp["publicKeyShare"].as_str() {
            Some(s) => s,
            None => return json_error("Missing publicKeyShare"),
        };
        let pub_key_bytes = match hex::decode(pub_key_hex) {
            Ok(b) => b,
            Err(e) => return json_error(format!("Invalid publicKeyShare hex: {}", e)),
        };
        let pub_key = match ExtendedPointBigInt::from_bytes_gnark(&pub_key_bytes, &p) {
            Some(pt) => pt,
            None => return json_error("Invalid public key share point"),
        };
        share_public_keys.push(pub_key);

        let evaluated_hex = match resp["evaluated"].as_str() {
            Some(s) => s,
            None => return json_error("Missing evaluated"),
        };
        let evaluated_bytes = match hex::decode(evaluated_hex) {
            Ok(b) => b,
            Err(e) => return json_error(format!("Invalid evaluated hex: {}", e)),
        };
        let evaluated_point = match ExtendedPointBigInt::from_bytes_gnark(&evaluated_bytes, &p) {
            Some(pt) => pt,
            None => return json_error("Invalid evaluated point"),
        };

        let c_hex = match resp["c"].as_str() {
            Some(s) => s,
            None => return json_error("Missing c"),
        };
        let c_bytes = match hex::decode(c_hex) {
            Ok(b) => b,
            Err(e) => return json_error(format!("Invalid c hex: {}", e)),
        };

        let r_hex = match resp["r"].as_str() {
            Some(s) => s,
            None => return json_error("Missing r"),
        };
        let r_bytes = match hex::decode(r_hex) {
            Ok(b) => b,
            Err(e) => return json_error(format!("Invalid r hex: {}", e)),
        };

        responses.push(OPRFResponse {
            evaluated_point,
            c: BigInt256::from_bytes_be(&c_bytes),
            r: BigInt256::from_bytes_be(&r_bytes),
        });
    }

    // Finalize TOPRF using MiMC hash (gnark-compatible)
    let result = match finalize_toprf_mimc(
        &indices,
        &responses,
        &share_public_keys,
        &masked_request,
        &secret_elements,
        &mask,
    ) {
        Some(r) => r,
        None => return json_error("TOPRF finalization failed: verification error"),
    };

    // Output is a 256-bit MiMC hash (gnark-compatible)
    let output_bytes = result.output.to_bytes_be();
    let output_hex = hex::encode(&output_bytes);

    // For decimal representation, convert limbs directly
    // The output is primarily used as hex for gnark compatibility
    json!({
        "output": output_hex,
        "outputDecimal": output_hex,  // Use hex as placeholder - gnark uses hex format
    }).to_string()
}

/// Convert bytes to Field256 elements (gnark-compatible: big-endian to little-endian).
fn bytes_to_field256_elements_gnark(bytes: &[u8]) -> [crate::babyjub::field256::gen::BigInt256; 2] {
    use crate::babyjub::field256::gen::BigInt256;

    const BYTES_PER_ELEMENT: usize = 31;

    let mut elem0 = BigInt256::zero();
    let mut elem1 = BigInt256::zero();

    if !bytes.is_empty() {
        if bytes.len() > BYTES_PER_ELEMENT {
            // First element: first 31 bytes (reversed to LE)
            let mut reversed0: Vec<u8> = bytes[..BYTES_PER_ELEMENT].to_vec();
            reversed0.reverse();
            elem0 = BigInt256::from_bytes_be(&reversed0);

            // Second element: remaining bytes (reversed to LE)
            let mut reversed1: Vec<u8> = bytes[BYTES_PER_ELEMENT..].to_vec();
            reversed1.reverse();
            elem1 = BigInt256::from_bytes_be(&reversed1);
        } else {
            // All bytes fit in first element (reversed to LE)
            let mut reversed: Vec<u8> = bytes.to_vec();
            reversed.reverse();
            elem0 = BigInt256::from_bytes_be(&reversed);
        }
    }

    [elem0, elem1]
}

/// Convert bytes to BigInt256 (gnark-compatible).
fn bytes_to_bigint256_gnark(bytes: &[u8]) -> crate::babyjub::field256::gen::BigInt256 {
    use crate::babyjub::field256::gen::BigInt256;

    if bytes.is_empty() {
        return BigInt256::zero();
    }

    // Reverse bytes (BE to LE) then parse
    let mut reversed: Vec<u8> = bytes.to_vec();
    reversed.reverse();
    BigInt256::from_bytes_be(&reversed)
}

// Note: WASM API tests are in babyjub/toprf/gnark_compat_test.rs
// since wasm_bindgen functions can't be tested in native context.
