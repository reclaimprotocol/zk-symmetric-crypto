//! Integration tests for TOPRF proving with real server-generated params.

#[cfg(test)]
mod tests {
    use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
    use crate::babyjub::mimc_compat::mimc_hash;
    use crate::babyjub::point::gen::native as point_native;
    use crate::babyjub::point::ExtendedPointBigInt;
    use crate::babyjub::toprf::{
        AffinePointBigInt, TOPRFInputs, TOPRFPrivateInputs, TOPRFPublicInputs,
    };
    use crate::babyjub::toprf::gen::{verify_toprf_native, TOPRFTraceGen};
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use crate::toprf_server::eval::{evaluate_oprf_mimc, hash_to_point_mimc, mask_point};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Convert bytes to Field256 elements (2 x 31 bytes max).
    fn bytes_to_field256_elements(bytes: &[u8]) -> [BigInt256; 2] {
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

    fn bytes_to_bigint256_le(bytes: &[u8]) -> BigInt256 {
        // Convert little-endian bytes to BigInt256
        BigInt256::from_bytes_le(bytes)
    }

    /// Create TOPRF circuit inputs from toprf_server evaluation.
    fn create_circuit_inputs(
        secret_bytes: &[u8],
        domain_separator: &BigInt256,
    ) -> (TOPRFInputs, BigInt256) {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();

        // Convert secret to field elements
        let secret_data = bytes_to_field256_elements(secret_bytes);

        // Generate key (threshold=1 for simplicity)
        let shared_key = generate_shared_key(&mut rng, 1, 1);
        let share = &shared_key.shares[0];

        // Client: hash to point using MiMC (gnark-compatible)
        let data_point = hash_to_point_mimc(&secret_data, domain_separator);

        // Client: generate mask and mask the data point
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        // Server: evaluate OPRF using MiMC-based DLEQ (gnark-compatible)
        let response = evaluate_oprf_mimc(&mut rng, share, &masked_request)
            .expect("OPRF evaluation should succeed");

        // Client: unmask to get final point
        let mask_inv = mask.inv_mod(&order).expect("mask should have inverse");
        let unmasked = point_native::scalar_mul(&response.evaluated_point, &mask_inv);

        // Compute final hash using MiMC
        let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);
        let output_hash = mimc_hash(&[
            unmasked_x.clone(),
            unmasked_y.clone(),
            secret_data[0].clone(),
            secret_data[1].clone(),
        ]);

        // Convert response point to affine
        let (resp_x, resp_y) = response.evaluated_point.to_affine(&p);
        let (pub_x, pub_y) = share.public_key.to_affine(&p);

        let inputs = TOPRFInputs {
            private: TOPRFPrivateInputs {
                mask: mask.clone(),
                secret_data,
            },
            public: TOPRFPublicInputs {
                domain_separator: domain_separator.clone(),
                responses: [AffinePointBigInt {
                    x: resp_x,
                    y: resp_y,
                }],
                coefficients: [BigInt256::one()], // For threshold=1, coefficient is 1
                share_public_keys: [AffinePointBigInt { x: pub_x, y: pub_y }],
                c: [response.c],
                r: [response.r],
                output: output_hash.clone(),
            },
        };

        (inputs, output_hash)
    }

    #[test]
    fn test_integrated_toprf_with_server_params() {
        let secret = b"test@reclaim.com";
        let domain_separator = BigInt256::from_u64(
            0x61696d00_7265636c, // "recl" + "aim\0"
        );

        let (inputs, expected_output) = create_circuit_inputs(secret, &domain_separator);

        println!("Expected output: {:?}", expected_output);
        println!("Public output in inputs: {:?}", inputs.public.output);

        // Verify using native computation
        let result = verify_toprf_native(&inputs);
        assert!(result.is_ok(), "Native verification failed: {:?}", result);

        let computed_output = result.unwrap();
        println!("Computed output: {:?}", computed_output);

        // The computed output should match
        assert_eq!(
            computed_output, inputs.public.output,
            "Output mismatch"
        );
    }

    #[test]
    fn test_trace_gen_with_real_params() {
        let secret = b"hello@example.org";
        let domain_separator = BigInt256::from_u32(12345);

        let (inputs, _) = create_circuit_inputs(secret, &domain_separator);

        let mut gen = TOPRFTraceGen::new();
        let output = gen.gen_toprf(&inputs);

        println!("Trace gen output: {:?}", output);
        println!("Expected output: {:?}", inputs.public.output);

        // Output should match
        assert_eq!(output, inputs.public.output, "Trace gen output mismatch");
    }

    #[test]
    fn test_different_secrets_different_outputs() {
        let domain_separator = BigInt256::from_u32(999);

        let (inputs1, output1) = create_circuit_inputs(b"secret_one", &domain_separator);
        let (inputs2, output2) = create_circuit_inputs(b"secret_two", &domain_separator);

        assert_ne!(output1, output2, "Different secrets should have different outputs");

        // Both should verify
        assert!(verify_toprf_native(&inputs1).is_ok());
        assert!(verify_toprf_native(&inputs2).is_ok());
    }

    #[test]
    fn bench_native_toprf_verification() {
        let secret = b"benchmark@test.com";
        let domain_separator = BigInt256::from_u64(0x0003_0002_0001);

        let (inputs, _) = create_circuit_inputs(secret, &domain_separator);

        // Warm up
        for _ in 0..3 {
            let _ = verify_toprf_native(&inputs);
        }

        // Benchmark
        let iterations = 10;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = verify_toprf_native(&inputs);
        }
        let elapsed = start.elapsed();

        println!(
            "Native TOPRF verification: {:.2}ms avg ({} iterations, {:.2}ms total)",
            elapsed.as_secs_f64() * 1000.0 / iterations as f64,
            iterations,
            elapsed.as_secs_f64() * 1000.0
        );
    }
}
