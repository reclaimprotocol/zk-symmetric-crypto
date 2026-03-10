//! Tests for gnark-compatible serialization and TOPRF API.

#[cfg(test)]
mod tests {
    use crate::babyjub::field256::gen::{modulus, BigInt256};
    use crate::babyjub::point::{base_point, ExtendedPointBigInt};
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use crate::toprf_server::eval::{
        evaluate_oprf_mimc, finalize_toprf_mimc, hash_to_point_mimc, mask_point,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_bigint256_bytes_roundtrip() {
        // Test various values
        let values = [
            BigInt256::zero(),
            BigInt256::one(),
            BigInt256::from_limbs([
                0x12345678, 0x09ABCDEF, 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555,
                0x66666666, 0x00777777,
            ]),
        ];

        for original in values {
            let bytes = original.to_bytes_be();
            assert_eq!(bytes.len(), 32, "BE bytes should always be 32 bytes");

            let recovered = BigInt256::from_bytes_be(&bytes);

            // Compare via u256 representation
            let original_u256 = original.to_u256();
            let recovered_u256 = recovered.to_u256();
            assert_eq!(
                original_u256, recovered_u256,
                "BigInt256 serialization roundtrip failed"
            );
        }
    }

    #[test]
    fn test_bigint256_trimmed_bytes() {
        // Small value should have few bytes
        let small = BigInt256::from_limbs([0x42, 0, 0, 0, 0, 0, 0, 0, 0]);
        let trimmed = small.to_bytes_be_trimmed();
        assert!(trimmed.len() < 32, "Trimmed bytes should be shorter than 32");
        assert!(!trimmed.is_empty(), "Non-zero value should have bytes");

        // Zero should produce empty or single zero
        let zero = BigInt256::zero();
        let zero_trimmed = zero.to_bytes_be_trimmed();
        assert!(
            zero_trimmed.is_empty() || zero_trimmed == vec![0],
            "Zero should produce empty or single zero byte"
        );
    }

    #[test]
    fn test_point_gnark_serialization() {
        let p = modulus();
        let base = base_point();

        // Serialize to gnark compressed format (32 bytes)
        let bytes = base.to_bytes_gnark(&p);
        assert_eq!(bytes.len(), 32, "Gnark point should be 32 bytes (compressed)");

        // Bytes should be non-zero for base point (contains Y coordinate)
        assert!(!bytes.iter().all(|&b| b == 0), "Compressed point should be non-zero");

        // Deserialize and verify roundtrip
        let recovered = ExtendedPointBigInt::from_bytes_gnark(&bytes, &p).unwrap();

        let (orig_x, orig_y) = base.to_affine(&p);
        let (rec_x, rec_y) = recovered.to_affine(&p);

        assert_eq!(orig_x, rec_x, "X coordinate mismatch after roundtrip");
        assert_eq!(orig_y, rec_y, "Y coordinate mismatch after roundtrip");
    }

    #[test]
    fn test_gnark_api_flow() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let p = modulus();

        // 1. Generate keys (simulates toprf_generate_keys)
        let shared_key = generate_shared_key(&mut rng, 3, 2);

        // Verify serialization (compressed format: 32 bytes)
        let server_pub_bytes = shared_key.server_public_key.to_bytes_gnark(&p);
        assert_eq!(server_pub_bytes.len(), 32);

        for share in &shared_key.shares {
            let priv_bytes = share.private_key.to_bytes_be_trimmed();
            let pub_bytes = share.public_key.to_bytes_gnark(&p);
            assert!(!priv_bytes.is_empty(), "Private key should serialize");
            assert_eq!(pub_bytes.len(), 32, "Public key should be 32 bytes (compressed)");
        }

        println!("Key generation: OK");

        // 2. Create request (simulates toprf_create_request)
        let secret_bytes = b"test@example.com";
        let secret_data = bytes_to_field_elements(secret_bytes);
        let domain = BigInt256::from_limbs([12345, 0, 0, 0, 0, 0, 0, 0, 0]);

        let data_point = hash_to_point_mimc(&secret_data, &domain);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        // Verify serialization (compressed format: 32 bytes)
        let mask_bytes = mask.to_bytes_be_trimmed();
        let masked_bytes = masked_request.to_bytes_gnark(&p);
        assert!(!mask_bytes.is_empty());
        assert_eq!(masked_bytes.len(), 32);

        println!("Request creation: OK");

        // 3. Evaluate (simulates toprf_evaluate for each share)
        let mut responses = Vec::new();
        for i in 0..2 {
            let response = evaluate_oprf_mimc(&mut rng, &shared_key.shares[i], &masked_request)
                .expect("Evaluation should succeed");

            // Verify serialization (compressed format: 32 bytes)
            let eval_bytes = response.evaluated_point.to_bytes_gnark(&p);
            let c_bytes = response.c.to_bytes_be_trimmed();
            let r_bytes = response.r.to_bytes_be_trimmed();

            assert_eq!(eval_bytes.len(), 32);
            assert!(!c_bytes.is_empty());
            assert!(!r_bytes.is_empty());

            responses.push(response);
            println!("Share {} evaluation: OK", i);
        }

        // 4. Finalize (simulates toprf_finalize)
        let indices: Vec<usize> = (1..=2).collect();
        let pub_keys: Vec<_> = shared_key.shares[0..2]
            .iter()
            .map(|s| s.public_key.clone())
            .collect();

        let result = finalize_toprf_mimc(
            &indices,
            &responses,
            &pub_keys,
            &masked_request,
            &secret_data,
            &mask,
        )
        .expect("Finalization should succeed");

        println!("Finalization: OK");
        println!("  Output: {:?}", result.output);

        // Verify output is deterministic
        let result2 = finalize_toprf_mimc(
            &indices,
            &responses,
            &pub_keys,
            &masked_request,
            &secret_data,
            &mask,
        )
        .expect("Second finalization should succeed");

        assert_eq!(
            result.output, result2.output,
            "Same inputs should produce same output"
        );
        println!("  Determinism check: OK");
    }

    #[test]
    fn test_gnark_hex_format_compatibility() {
        let p = modulus();

        // Test that hex encoding produces expected format (compressed: 32 bytes = 64 hex chars)
        let base = base_point();
        let bytes = base.to_bytes_gnark(&p);
        let hex_str = hex::encode(&bytes);

        assert_eq!(hex_str.len(), 64, "Hex string should be 64 chars for 32 bytes (compressed)");
        assert!(
            hex_str.chars().all(|c| c.is_ascii_hexdigit()),
            "Should be valid hex"
        );

        // Verify roundtrip through hex
        let decoded = hex::decode(&hex_str).unwrap();
        assert_eq!(decoded, bytes);

        let recovered = ExtendedPointBigInt::from_bytes_gnark(&decoded, &p).unwrap();
        let (orig_x, orig_y) = base.to_affine(&p);
        let (rec_x, rec_y) = recovered.to_affine(&p);
        assert_eq!(orig_x, rec_x);
        assert_eq!(orig_y, rec_y);

        println!("Hex encoding roundtrip: OK");
        println!("  Point hex: {}", &hex_str);
    }

    #[test]
    fn test_gnark_mimc_api_flow() {
        let mut rng = ChaCha20Rng::seed_from_u64(54321);
        let p = modulus();

        // 1. Generate keys
        let shared_key = generate_shared_key(&mut rng, 3, 2);

        // 2. Create request with MiMC hash_to_point
        let secret_bytes = b"test@example.com";
        let secret_data = bytes_to_field_elements(secret_bytes);
        let domain = BigInt256::from_limbs([12345, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Use MiMC-based hash_to_point for gnark compatibility
        let data_point = hash_to_point_mimc(&secret_data, &domain);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        // Verify point is valid
        let (x, y) = masked_request.to_affine(&p);
        assert!(!x.is_zero() || !y.is_zero(), "Masked point should be non-trivial");

        println!("MiMC hash_to_point: OK");

        // 3. Evaluate using MiMC-based DLEQ (gnark-compatible)
        let mut responses = Vec::new();
        for i in 0..2 {
            let response = evaluate_oprf_mimc(&mut rng, &shared_key.shares[i], &masked_request)
                .expect("Evaluation should succeed");
            responses.push(response);
        }

        // 4. Finalize with MiMC
        let indices: Vec<usize> = (1..=2).collect();
        let pub_keys: Vec<_> = shared_key.shares[0..2]
            .iter()
            .map(|s| s.public_key.clone())
            .collect();

        let result = finalize_toprf_mimc(
            &indices,
            &responses,
            &pub_keys,
            &masked_request,
            &secret_data,
            &mask,
        )
        .expect("Finalization should succeed");

        // MiMC output is 256 bits (BigInt256)
        let output_bytes = result.output.to_bytes_be();
        assert_eq!(output_bytes.len(), 32, "MiMC output should be 32 bytes");
        assert!(
            !output_bytes.iter().all(|&b| b == 0),
            "Output should be non-zero"
        );

        println!(
            "MiMC finalization: OK (output: {}...)",
            hex::encode(&output_bytes[..8])
        );

        // Verify determinism
        let result2 = finalize_toprf_mimc(
            &indices,
            &responses,
            &pub_keys,
            &masked_request,
            &secret_data,
            &mask,
        )
        .expect("Second finalization should succeed");

        let output_bytes2 = result2.output.to_bytes_be();
        assert_eq!(
            output_bytes, output_bytes2,
            "Same inputs should produce same MiMC output"
        );
        println!("  Determinism check: OK");

        // Verify different inputs produce different outputs
        let different_secret = b"different@example.com";
        let different_data = bytes_to_field_elements(different_secret);
        let different_point = hash_to_point_mimc(&different_data, &domain);

        assert_ne!(
            data_point.to_affine(&p),
            different_point.to_affine(&p),
            "Different secrets should produce different points"
        );
        println!("  Different input check: OK");
    }

    /// Helper to convert bytes to field elements (simplified version)
    fn bytes_to_field_elements(bytes: &[u8]) -> [BigInt256; 2] {
        const BYTES_PER_ELEMENT: usize = 31;

        let mut elem0 = BigInt256::zero();
        let mut elem1 = BigInt256::zero();

        if !bytes.is_empty() {
            let end = bytes.len().min(BYTES_PER_ELEMENT);
            elem0 = bytes_to_bigint_le(&bytes[..end]);
        }

        if bytes.len() > BYTES_PER_ELEMENT {
            elem1 = bytes_to_bigint_le(&bytes[BYTES_PER_ELEMENT..]);
        }

        [elem0, elem1]
    }

    fn bytes_to_bigint_le(bytes: &[u8]) -> BigInt256 {
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
}
