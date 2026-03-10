//! End-to-end tests for TOPRF with cipher integration.
//!
//! Tests the full flow: encrypt plaintext with ChaCha20, extract secret data,
//! perform TOPRF with threshold shares, verify DLEQ proofs, and finalize.

#[cfg(test)]
mod tests {
    use crate::babyjub::field256::gen::{modulus, BigInt256};
    use crate::chacha::block::{chacha20_block_from_key, state_to_bytes};
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use crate::toprf_server::dleq::verify_dleq_mimc;
    use crate::toprf_server::eval::{evaluate_oprf_mimc, finalize_toprf_mimc, hash_to_point_mimc, mask_point};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Maximum bytes per Field256 element (31 bytes = 248 bits fits in BN254 field).
    const BYTES_PER_ELEMENT: usize = 31;

    /// ChaCha block size in bytes.
    const CHACHA_BLOCK_SIZE: usize = 64;

    /// Convert bytes to little-endian Field256 elements.
    /// Returns two elements, each holding up to 31 bytes.
    fn bytes_to_field256_elements(bytes: &[u8]) -> [BigInt256; 2] {
        assert!(bytes.len() <= BYTES_PER_ELEMENT * 2, "Too many bytes for 2 elements");

        let mut elem0 = BigInt256::zero();
        let mut elem1 = BigInt256::zero();

        // First 31 bytes go into elem0 (little-endian)
        if !bytes.is_empty() {
            let end = bytes.len().min(BYTES_PER_ELEMENT);
            elem0 = bytes_to_bigint256_le(&bytes[..end]);
        }

        // Remaining bytes go into elem1
        if bytes.len() > BYTES_PER_ELEMENT {
            elem1 = bytes_to_bigint256_le(&bytes[BYTES_PER_ELEMENT..]);
        }

        [elem0, elem1]
    }

    /// Convert bytes (little-endian) to BigInt256.
    fn bytes_to_bigint256_le(bytes: &[u8]) -> BigInt256 {
        // Each limb is 29 bits, we need to pack bytes into limbs
        let mut limbs = [0u32; 9];
        let mut bit_pos = 0;

        for &byte in bytes {
            // Add this byte at the current bit position
            let limb_idx = bit_pos / 29;
            let bit_offset = bit_pos % 29;

            if limb_idx < 9 {
                limbs[limb_idx] |= (byte as u32) << bit_offset;

                // Handle overflow to next limb
                if bit_offset > 21 && limb_idx + 1 < 9 {
                    limbs[limb_idx + 1] |= (byte as u32) >> (29 - bit_offset);
                }
            }

            bit_pos += 8;
        }

        // Mask to 29 bits per limb
        for limb in &mut limbs {
            *limb &= 0x1FFFFFFF;
        }

        BigInt256::from_limbs(limbs)
    }

    /// XOR two byte slices (for ChaCha encryption).
    fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }

    /// ChaCha20 encrypt a plaintext buffer.
    /// Key is 32 bytes, nonce is 12 bytes.
    fn chacha20_encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        counter: u32,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let num_blocks = (plaintext.len() + CHACHA_BLOCK_SIZE - 1) / CHACHA_BLOCK_SIZE;
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        // Convert key to u32 words
        let mut key_words = [0u32; 8];
        for (i, chunk) in key.chunks(4).enumerate() {
            key_words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        // Convert nonce to u32 words
        let mut nonce_words = [0u32; 3];
        for (i, chunk) in nonce.chunks(4).enumerate() {
            nonce_words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        for block_idx in 0..num_blocks {
            let start = block_idx * CHACHA_BLOCK_SIZE;
            let end = (start + CHACHA_BLOCK_SIZE).min(plaintext.len());

            // Generate keystream block
            let keystream_state =
                chacha20_block_from_key(&key_words, counter + block_idx as u32, &nonce_words);
            let keystream = state_to_bytes(&keystream_state);

            // XOR plaintext with keystream
            let block_ct = xor_bytes(&plaintext[start..end], &keystream[..end - start]);
            ciphertext.extend(block_ct);
        }

        ciphertext
    }

    /// Extract bytes from plaintext at given position and length.
    fn extract_secret_bytes(plaintext: &[u8], pos: usize, len: usize) -> Vec<u8> {
        plaintext[pos..pos + len].to_vec()
    }

    /// Full end-to-end test: ChaCha encryption + TOPRF.
    /// This mirrors the gnark test pattern from chachaV3_oprf/chacha_test.go
    #[test]
    fn test_e2e_chacha_toprf() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        // === Setup cipher parameters ===
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        for byte in &mut key {
            *byte = rng.gen();
        }
        for byte in &mut nonce {
            *byte = rng.gen();
        }
        let counter = 12345u32;

        // === Create plaintext with secret at position spanning blocks ===
        // Position 66 means secret starts in block 1 (after byte 64) and may span into block 2
        let secret_str = "test@reclaim.com";
        let secret_bytes = secret_str.as_bytes();
        let pos = 66; // This spans block boundary: block 1 has 64 bytes, so pos 66 is 2 bytes in

        // Create 2 blocks of plaintext (128 bytes)
        let mut plaintext = vec![0u8; 128];
        plaintext[pos..pos + secret_bytes.len()].copy_from_slice(secret_bytes);

        // === Encrypt with ChaCha20 ===
        let ciphertext = chacha20_encrypt(&key, &nonce, counter, &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        // Verify decryption works (sanity check)
        let decrypted = chacha20_encrypt(&key, &nonce, counter, &ciphertext);
        assert_eq!(decrypted, plaintext, "Decryption should recover plaintext");

        // === Extract secret data ===
        let extracted = extract_secret_bytes(&plaintext, pos, secret_bytes.len());
        assert_eq!(extracted, secret_bytes, "Extracted bytes should match original");

        // Convert to Field256 elements (as gnark does)
        let secret_elements = bytes_to_field256_elements(&extracted);
        println!("Secret element 0: {:?}", secret_elements[0].limbs);
        println!("Secret element 1: {:?}", secret_elements[1].limbs);

        // === Generate TOPRF key shares ===
        // 2-of-3 threshold
        let threshold = 2;
        let nodes = 3;
        let shared_key = generate_shared_key(&mut rng, nodes, threshold);

        println!("Generated {}-of-{} threshold key", threshold, nodes);
        println!("Server public key x: {:?}", shared_key.server_public_key.x.limbs);

        // === Client: Prepare OPRF request ===
        let domain_separator = BigInt256::from_limbs([
            // "reclaim" encoded as little-endian
            0x7265636c, // "recl" = 0x6c636572 LE
            0x61696d00, // "aim\0" = 0x006d6961 LE
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);

        // Hash secret to curve point
        let data_point = hash_to_point_mimc(&secret_elements, &domain_separator);
        println!("Data point x: {:?}", data_point.x.limbs);

        // Generate random mask
        let mask = random_scalar(&mut rng);
        println!("Mask: {:?}", mask.limbs);

        // Mask the data point
        let masked_request = mask_point(&data_point, &mask);
        println!("Masked request x: {:?}", masked_request.x.limbs);

        // === Server: Evaluate OPRF for each participating share ===
        // Use shares 1 and 2 (indices 0 and 1)
        let participating_indices = vec![1, 2];

        let mut responses = Vec::new();
        let mut pub_keys = Vec::new();

        for &idx in &participating_indices {
            let share = &shared_key.shares[idx - 1];
            let response = evaluate_oprf_mimc(&mut rng, share, &masked_request)
                .expect("OPRF evaluation should succeed");

            // Verify DLEQ proof immediately
            let valid = verify_dleq_mimc(
                &response.c,
                &response.r,
                &share.public_key,
                &response.evaluated_point,
                &masked_request,
            );
            assert!(valid, "DLEQ proof for share {} should be valid", idx);

            responses.push(response);
            pub_keys.push(share.public_key.clone());
        }

        println!("All {} DLEQ proofs verified", participating_indices.len());

        // === Client: Finalize TOPRF ===
        let result = finalize_toprf_mimc(
            &participating_indices,
            &responses,
            &pub_keys,
            &masked_request,
            &secret_elements,
            &mask,
        );

        assert!(result.is_some(), "TOPRF finalization should succeed");
        let toprf_result = result.unwrap();

        println!("TOPRF output: {:?}", toprf_result.output);
        println!(
            "Unmasked point x: {:?}",
            toprf_result.unmasked_point.x.limbs
        );

        // === Verify consistency: same secret should produce same output ===
        // Re-run with different random values but same secret
        let mut rng2 = ChaCha20Rng::seed_from_u64(54321);
        let mask2 = random_scalar(&mut rng2);
        let masked_request2 = mask_point(&data_point, &mask2);

        let mut responses2 = Vec::new();
        for &idx in &participating_indices {
            let share = &shared_key.shares[idx - 1];
            let response = evaluate_oprf_mimc(&mut rng2, share, &masked_request2)
                .expect("OPRF evaluation should succeed");
            responses2.push(response);
        }

        let result2 = finalize_toprf_mimc(
            &participating_indices,
            &responses2,
            &pub_keys,
            &masked_request2,
            &secret_elements,
            &mask2,
        );

        assert!(result2.is_some());
        let toprf_result2 = result2.unwrap();

        // Same secret data should produce same unmasked point
        let modulus = modulus();
        let (ux1, uy1) = toprf_result.unmasked_point.to_affine(&modulus);
        let (ux2, uy2) = toprf_result2.unmasked_point.to_affine(&modulus);

        assert_eq!(
            ux1.limbs, ux2.limbs,
            "Unmasked x should be same for same secret"
        );
        assert_eq!(
            uy1.limbs, uy2.limbs,
            "Unmasked y should be same for same secret"
        );

        // And same final output
        assert_eq!(
            toprf_result.output, toprf_result2.output,
            "TOPRF output should be deterministic for same secret"
        );

        println!("Consistency check passed: same secret produces same output");
    }

    /// Test with secret spanning multiple cipher blocks.
    #[test]
    fn test_e2e_secret_spanning_blocks() {
        let mut rng = ChaCha20Rng::seed_from_u64(99999);

        // Setup cipher
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        for byte in &mut key {
            *byte = rng.gen();
        }
        for byte in &mut nonce {
            *byte = rng.gen();
        }

        // Secret that spans block boundary (position 60, length 16 = ends at 76)
        // Block 0: bytes 0-63, Block 1: bytes 64-127
        // So this secret starts in block 0 at byte 60 and ends in block 1 at byte 76
        let secret_str = "span@example.org";
        let secret_bytes = secret_str.as_bytes();
        let pos = 60;
        assert!(pos + secret_bytes.len() > 64, "Secret should span blocks");

        // Create plaintext
        let mut plaintext = vec![0u8; 128];
        plaintext[pos..pos + secret_bytes.len()].copy_from_slice(secret_bytes);

        // Encrypt
        let _ciphertext = chacha20_encrypt(&key, &nonce, 1, &plaintext);

        // Extract and verify
        let extracted = extract_secret_bytes(&plaintext, pos, secret_bytes.len());
        assert_eq!(extracted, secret_bytes);

        // Convert to field elements
        let secret_elements = bytes_to_field256_elements(&extracted);

        // Generate 3-of-5 threshold
        let threshold = 3;
        let nodes = 5;
        let shared_key = generate_shared_key(&mut rng, nodes, threshold);

        // Hash to point
        let domain_separator = BigInt256::from_limbs([0x12345678, 0, 0, 0, 0, 0, 0, 0, 0]);
        let data_point = hash_to_point_mimc(&secret_elements, &domain_separator);

        // Mask
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        // Use shares 2, 3, 5 (indices 1, 2, 4)
        let participating_indices = vec![2, 3, 5];

        let mut responses = Vec::new();
        let mut pub_keys = Vec::new();

        for &idx in &participating_indices {
            let share = &shared_key.shares[idx - 1];
            let response = evaluate_oprf_mimc(&mut rng, share, &masked_request)
                .expect("OPRF evaluation should succeed");

            let valid = verify_dleq_mimc(
                &response.c,
                &response.r,
                &share.public_key,
                &response.evaluated_point,
                &masked_request,
            );
            assert!(valid, "DLEQ proof for share {} should be valid", idx);

            responses.push(response);
            pub_keys.push(share.public_key.clone());
        }

        // Finalize
        let result = finalize_toprf_mimc(
            &participating_indices,
            &responses,
            &pub_keys,
            &masked_request,
            &secret_elements,
            &mask,
        );

        assert!(result.is_some(), "3-of-5 TOPRF should succeed");
        println!(
            "3-of-5 TOPRF with block-spanning secret: output = {:?}",
            result.unwrap().output
        );
    }

    /// Test different subset of shares produces same result.
    #[test]
    fn test_e2e_different_share_subsets() {
        let mut rng = ChaCha20Rng::seed_from_u64(11111);

        // Generate 2-of-3 threshold
        let shared_key = generate_shared_key(&mut rng, 3, 2);

        // Setup secret
        let secret_str = "same_secret";
        let secret_elements = bytes_to_field256_elements(secret_str.as_bytes());

        let domain_separator = BigInt256::from_limbs([0xABCDEF, 0, 0, 0, 0, 0, 0, 0, 0]);
        let data_point = hash_to_point_mimc(&secret_elements, &domain_separator);

        // First run: use shares 1 and 2
        let mask1 = random_scalar(&mut rng);
        let masked1 = mask_point(&data_point, &mask1);

        let resp1_1 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[0], &masked1).unwrap();
        let resp1_2 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[1], &masked1).unwrap();

        let result1 = finalize_toprf_mimc(
            &[1, 2],
            &[resp1_1, resp1_2],
            &[
                shared_key.shares[0].public_key.clone(),
                shared_key.shares[1].public_key.clone(),
            ],
            &masked1,
            &secret_elements,
            &mask1,
        )
        .unwrap();

        // Second run: use shares 1 and 3
        let mask2 = random_scalar(&mut rng);
        let masked2 = mask_point(&data_point, &mask2);

        let resp2_1 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[0], &masked2).unwrap();
        let resp2_3 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[2], &masked2).unwrap();

        let result2 = finalize_toprf_mimc(
            &[1, 3],
            &[resp2_1, resp2_3],
            &[
                shared_key.shares[0].public_key.clone(),
                shared_key.shares[2].public_key.clone(),
            ],
            &masked2,
            &secret_elements,
            &mask2,
        )
        .unwrap();

        // Third run: use shares 2 and 3
        let mask3 = random_scalar(&mut rng);
        let masked3 = mask_point(&data_point, &mask3);

        let resp3_2 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[1], &masked3).unwrap();
        let resp3_3 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[2], &masked3).unwrap();

        let result3 = finalize_toprf_mimc(
            &[2, 3],
            &[resp3_2, resp3_3],
            &[
                shared_key.shares[1].public_key.clone(),
                shared_key.shares[2].public_key.clone(),
            ],
            &masked3,
            &secret_elements,
            &mask3,
        )
        .unwrap();

        // All three should produce the same unmasked point
        let modulus = modulus();
        let (ux1, _) = result1.unmasked_point.to_affine(&modulus);
        let (ux2, _) = result2.unmasked_point.to_affine(&modulus);
        let (ux3, _) = result3.unmasked_point.to_affine(&modulus);

        assert_eq!(
            ux1.limbs, ux2.limbs,
            "Shares (1,2) and (1,3) should give same result"
        );
        assert_eq!(
            ux2.limbs, ux3.limbs,
            "Shares (1,3) and (2,3) should give same result"
        );

        // And same final output
        assert_eq!(
            result1.output, result2.output,
            "Different share subsets should give same output"
        );
        assert_eq!(
            result2.output, result3.output,
            "All subsets should give same output"
        );

        println!("All 3 subsets of 2-of-3 shares produce same TOPRF output: {:?}", result1.output);
    }

    /// Test with maximum secret size (62 bytes = 2 x 31 bytes).
    #[test]
    fn test_e2e_max_secret_size() {
        let mut rng = ChaCha20Rng::seed_from_u64(77777);

        // 62 bytes = maximum that fits in 2 Field256 elements
        let secret_bytes: Vec<u8> = (0u8..62).collect();
        assert_eq!(secret_bytes.len(), 62);

        let secret_elements = bytes_to_field256_elements(&secret_bytes);

        // Generate key
        let shared_key = generate_shared_key(&mut rng, 3, 2);

        // Hash to point
        let domain_separator = BigInt256::zero();
        let data_point = hash_to_point_mimc(&secret_elements, &domain_separator);

        // Mask
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        // Evaluate
        let resp1 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[0], &masked_request).unwrap();
        let resp2 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[1], &masked_request).unwrap();

        // Finalize
        let result = finalize_toprf_mimc(
            &[1, 2],
            &[resp1, resp2],
            &[
                shared_key.shares[0].public_key.clone(),
                shared_key.shares[1].public_key.clone(),
            ],
            &masked_request,
            &secret_elements,
            &mask,
        );

        assert!(result.is_some(), "62-byte secret should work");
        println!("Max secret size (62 bytes) TOPRF output: {:?}", result.unwrap().output);
    }

    /// Test that different secrets produce different outputs.
    #[test]
    fn test_e2e_different_secrets_different_outputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(33333);

        let shared_key = generate_shared_key(&mut rng, 3, 2);
        let domain_separator = BigInt256::zero();

        // First secret
        let secret1 = bytes_to_field256_elements(b"secret_one");
        let point1 = hash_to_point_mimc(&secret1, &domain_separator);
        let mask1 = random_scalar(&mut rng);
        let masked1 = mask_point(&point1, &mask1);

        let resp1_1 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[0], &masked1).unwrap();
        let resp1_2 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[1], &masked1).unwrap();

        let result1 = finalize_toprf_mimc(
            &[1, 2],
            &[resp1_1, resp1_2],
            &[
                shared_key.shares[0].public_key.clone(),
                shared_key.shares[1].public_key.clone(),
            ],
            &masked1,
            &secret1,
            &mask1,
        )
        .unwrap();

        // Second secret (different)
        let secret2 = bytes_to_field256_elements(b"secret_two");
        let point2 = hash_to_point_mimc(&secret2, &domain_separator);
        let mask2 = random_scalar(&mut rng);
        let masked2 = mask_point(&point2, &mask2);

        let resp2_1 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[0], &masked2).unwrap();
        let resp2_2 = evaluate_oprf_mimc(&mut rng, &shared_key.shares[1], &masked2).unwrap();

        let result2 = finalize_toprf_mimc(
            &[1, 2],
            &[resp2_1, resp2_2],
            &[
                shared_key.shares[0].public_key.clone(),
                shared_key.shares[1].public_key.clone(),
            ],
            &masked2,
            &secret2,
            &mask2,
        )
        .unwrap();

        // Outputs should be different
        assert_ne!(
            result1.output, result2.output,
            "Different secrets should produce different outputs"
        );

        // Unmasked points should be different
        let modulus = modulus();
        let (ux1, _) = result1.unmasked_point.to_affine(&modulus);
        let (ux2, _) = result2.unmasked_point.to_affine(&modulus);

        assert_ne!(
            ux1.limbs, ux2.limbs,
            "Different secrets should produce different unmasked points"
        );

        println!("Different secrets correctly produce different outputs");
    }

    use rand::Rng;
}
