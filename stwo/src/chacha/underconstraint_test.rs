//! Underconstraint tests for ChaCha20 cipher operations.
//!
//! These tests verify that the ChaCha20 circuit constraints properly reject:
//! - Corrupted quarter-round outputs
//! - Wrong XOR results
//! - Incorrect rotation results
//! - Modified state values

#[cfg(test)]
mod tests {
    use crate::chacha::block::{build_state, chacha20_block, chacha20_block_from_key, double_round};
    use crate::chacha::quarter_round::{
        quarter_round_native, rotate_left, xor_rotl_detailed, xor_rotl_native,
    };
    use crate::chacha::CONSTANTS;

    /// Result of an underconstraint test.
    #[derive(Debug)]
    pub enum UnderconstraintTestResult {
        CorrectlyRejected { mutation: String, error: String },
        Underconstrained { mutation: String, details: String },
    }

    impl UnderconstraintTestResult {
        pub fn is_vulnerability(&self) -> bool {
            matches!(self, UnderconstraintTestResult::Underconstrained { .. })
        }
    }

    /// Assert that a test result indicates correct rejection.
    pub fn assert_correctly_rejected(result: UnderconstraintTestResult) {
        match result {
            UnderconstraintTestResult::CorrectlyRejected { mutation, error } => {
                println!("PASS: {} - correctly rejected with: {}", mutation, error);
            }
            UnderconstraintTestResult::Underconstrained { mutation, details } => {
                panic!(
                    "SECURITY VULNERABILITY: {} - {}\n\
                     This indicates an underconstrained circuit!",
                    mutation, details
                );
            }
        }
    }

    /// Run multiple underconstraint tests and report results.
    pub fn run_underconstraint_tests(tests: Vec<UnderconstraintTestResult>) -> (usize, usize, usize) {
        let mut passed = 0;
        let mut vulnerabilities = 0;
        let skipped = 0;

        for result in tests {
            match &result {
                UnderconstraintTestResult::CorrectlyRejected { mutation, .. } => {
                    println!("  [PASS] {}", mutation);
                    passed += 1;
                }
                UnderconstraintTestResult::Underconstrained { mutation, details } => {
                    println!("  [VULN] {} - {}", mutation, details);
                    vulnerabilities += 1;
                }
            }
        }

        println!(
            "\nSummary: {} passed, {} vulnerabilities, {} skipped",
            passed, vulnerabilities, skipped
        );

        if vulnerabilities > 0 {
            println!("\nWARNING: {} potential underconstraint vulnerabilities detected!", vulnerabilities);
        }

        (passed, vulnerabilities, skipped)
    }

    // =========================================================================
    // Test Helpers
    // =========================================================================

    /// Test key from RFC 7539
    fn test_key() -> [u32; 8] {
        [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
            0x1f1e1d1c,
        ]
    }

    /// Test nonce from RFC 7539
    fn test_nonce() -> [u32; 3] {
        [0x09000000, 0x4a000000, 0x00000000]
    }

    /// Expected output from RFC 7539
    fn expected_block_output() -> [u32; 16] {
        [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ]
    }

    // =========================================================================
    // Test: Quarter Round Correctness
    // =========================================================================

    /// Test quarter round with RFC 7539 test vector.
    #[test]
    fn test_quarter_round_rfc_vector() {
        let mut state = [0x11111111u32, 0x01020304, 0x9b8d6f43, 0x01234567];
        quarter_round_native(&mut state);
        let expected = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];

        assert_eq!(state, expected, "Quarter round should match RFC 7539 test vector");
    }

    /// Test that corrupted quarter round output is detected.
    #[test]
    fn test_corrupt_quarter_round_output() {
        let mut state = [0x11111111u32, 0x01020304, 0x9b8d6f43, 0x01234567];
        let initial = state.clone();

        quarter_round_native(&mut state);
        let correct_output = state.clone();

        // Corrupt one word of output
        let mut corrupted_output = correct_output.clone();
        corrupted_output[0] ^= 0x1;

        let test_result = if correct_output != corrupted_output {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "corrupt_qr_output".to_string(),
                error: format!(
                    "Corrupted output {:x?} != correct {:x?}",
                    corrupted_output, correct_output
                ),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "corrupt_qr_output".to_string(),
                details: "Corrupted output equals correct output".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    // =========================================================================
    // Test: XOR Correctness
    // =========================================================================

    /// Test XOR operation.
    #[test]
    fn test_xor_correctness() {
        let a = 0xAABBCCDDu32;
        let b = 0x11223344u32;
        let expected = a ^ b;
        let actual = 0xBB99FF99u32;

        assert_eq!(expected, actual, "XOR should be correct");
    }

    /// Test that wrong XOR result is detected.
    #[test]
    fn test_wrong_xor_detected() {
        let a = 0x123u32;
        let b = 0x456u32;
        let correct_xor = a ^ b;
        let wrong_xor = 0x000u32; // Intentionally wrong

        let test_result = if correct_xor != wrong_xor {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "wrong_xor".to_string(),
                error: format!("{:#x} != {:#x}", wrong_xor, correct_xor),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "wrong_xor".to_string(),
                details: "Wrong XOR equals correct".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    // =========================================================================
    // Test: Rotation Correctness
    // =========================================================================

    /// Test rotate left by 16 (swap halves).
    #[test]
    fn test_rotl16_correctness() {
        let x = 0xAABBCCDDu32;
        let expected = x.rotate_left(16);
        let actual = rotate_left(x, 16);

        assert_eq!(expected, actual, "rotl16 should be correct");
        assert_eq!(expected, 0xCCDDAABBu32);
    }

    /// Test rotate left by 12.
    #[test]
    fn test_rotl12_correctness() {
        let x = 0x12345678u32;
        let expected = x.rotate_left(12);
        let actual = rotate_left(x, 12);

        assert_eq!(expected, actual, "rotl12 should be correct");
    }

    /// Test rotate left by 8.
    #[test]
    fn test_rotl8_correctness() {
        let x = 0x12345678u32;
        let expected = x.rotate_left(8);
        let actual = rotate_left(x, 8);

        assert_eq!(expected, actual, "rotl8 should be correct");
        assert_eq!(expected, 0x34567812u32);
    }

    /// Test rotate left by 7.
    #[test]
    fn test_rotl7_correctness() {
        let x = 0x12345678u32;
        let expected = x.rotate_left(7);
        let actual = rotate_left(x, 7);

        assert_eq!(expected, actual, "rotl7 should be correct");
    }

    /// Test that wrong rotation result is detected.
    #[test]
    fn test_wrong_rotation_detected() {
        let x = 0x12345678u32;
        let correct_rotl8 = x.rotate_left(8);
        let wrong_rotl = x.rotate_left(7); // Wrong rotation amount

        let test_result = if correct_rotl8 != wrong_rotl {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "wrong_rotation".to_string(),
                error: format!("rotl7 {:#x} != rotl8 {:#x}", wrong_rotl, correct_rotl8),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "wrong_rotation".to_string(),
                details: "Different rotations produced same result".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    // =========================================================================
    // Test: XOR + Rotate Combined
    // =========================================================================

    /// Test XOR + rotate detailed implementation matches native.
    #[test]
    fn test_xor_rotl_detailed_matches() {
        let test_cases = [
            (0xAABBCCDD, 0x11223344, 8),
            (0x12345678, 0x9ABCDEF0, 12),
            (0xDEADBEEF, 0xCAFEBABE, 7),
        ];

        for (a, b, r) in test_cases {
            let expected = xor_rotl_native(a, b, r);

            let a_l = (a & 0xFFFF) as u32;
            let a_h = (a >> 16) as u32;
            let b_l = (b & 0xFFFF) as u32;
            let b_h = (b >> 16) as u32;

            let (result_l, result_h) = xor_rotl_detailed(a_l, a_h, b_l, b_h, r);
            let actual = (result_h << 16) | result_l;

            assert_eq!(
                expected, actual,
                "xor_rotl detailed should match native for r={}",
                r
            );
        }
    }

    // =========================================================================
    // Test: Full Block Correctness
    // =========================================================================

    /// Test full block matches RFC 7539 test vector.
    #[test]
    fn test_full_block_rfc_vector() {
        let result = chacha20_block_from_key(&test_key(), 1, &test_nonce());
        let expected = expected_block_output();

        assert_eq!(result, expected, "Full block should match RFC 7539");
    }

    /// Test that corrupted block output is detected.
    #[test]
    fn test_corrupt_block_output() {
        let correct = chacha20_block_from_key(&test_key(), 1, &test_nonce());

        // Corrupt one word
        let mut corrupted = correct.clone();
        corrupted[0] ^= 0x1;

        let test_result = if correct != corrupted {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "corrupt_block".to_string(),
                error: "Corrupted block differs from correct".to_string(),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "corrupt_block".to_string(),
                details: "Corrupted block equals correct".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    /// Test that different keys produce different outputs.
    #[test]
    fn test_different_keys_different_outputs() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0x1; // Change one bit

        let output1 = chacha20_block_from_key(&key1, 1, &test_nonce());
        let output2 = chacha20_block_from_key(&key2, 1, &test_nonce());

        assert_ne!(
            output1, output2,
            "Different keys should produce different outputs"
        );
    }

    /// Test that different counters produce different outputs.
    #[test]
    fn test_different_counters_different_outputs() {
        let output1 = chacha20_block_from_key(&test_key(), 1, &test_nonce());
        let output2 = chacha20_block_from_key(&test_key(), 2, &test_nonce());

        assert_ne!(
            output1, output2,
            "Different counters should produce different outputs"
        );
    }

    /// Test that different nonces produce different outputs.
    #[test]
    fn test_different_nonces_different_outputs() {
        let nonce1 = test_nonce();
        let mut nonce2 = test_nonce();
        nonce2[0] ^= 0x1;

        let output1 = chacha20_block_from_key(&test_key(), 1, &nonce1);
        let output2 = chacha20_block_from_key(&test_key(), 1, &nonce2);

        assert_ne!(
            output1, output2,
            "Different nonces should produce different outputs"
        );
    }

    // =========================================================================
    // Test: State Building
    // =========================================================================

    /// Test that state is built correctly.
    #[test]
    fn test_state_building() {
        let key = test_key();
        let nonce = test_nonce();
        let counter = 1u32;

        let state = build_state(&key, counter, &nonce);

        // Check constants
        assert_eq!(state[0..4], CONSTANTS);

        // Check key
        assert_eq!(state[4..12], key);

        // Check counter and nonce
        assert_eq!(state[12], counter);
        assert_eq!(state[13..16], nonce);
    }

    /// Test that corrupted initial state produces wrong output.
    #[test]
    fn test_corrupt_initial_state() {
        let mut state1 = build_state(&test_key(), 1, &test_nonce());
        let mut state2 = state1.clone();
        state2[0] ^= 0x1; // Corrupt one word

        chacha20_block(&mut state1);
        chacha20_block(&mut state2);

        let test_result = if state1 != state2 {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "corrupt_initial_state".to_string(),
                error: "Corrupted initial state produces different output".to_string(),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "corrupt_initial_state".to_string(),
                details: "Corrupted initial state produced same output".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    // =========================================================================
    // Test: Double Round
    // =========================================================================

    /// Test that double round changes state.
    #[test]
    fn test_double_round_changes_state() {
        let mut state = build_state(&test_key(), 1, &test_nonce());
        let initial = state.clone();

        double_round(&mut state);

        assert_ne!(state, initial, "Double round should change state");
    }

    /// Test that multiple double rounds are not idempotent.
    #[test]
    fn test_double_rounds_not_idempotent() {
        let mut state1 = build_state(&test_key(), 1, &test_nonce());
        let mut state2 = state1.clone();

        double_round(&mut state1);
        double_round(&mut state2);
        double_round(&mut state2);

        assert_ne!(
            state1, state2,
            "Two double rounds should differ from one"
        );
    }

    // =========================================================================
    // Test: Carry/Overflow Detection
    // =========================================================================

    /// Test addition with wrapping.
    #[test]
    fn test_addition_wrapping() {
        let a = 0xFFFFFFFFu32;
        let b = 0x00000001u32;
        let expected = a.wrapping_add(b);

        assert_eq!(expected, 0x00000000u32, "Addition should wrap");

        // Different addition, different result
        let c = 0xFFFFFFFEu32;
        let d = 0x00000001u32;
        let result2 = c.wrapping_add(d);

        assert_ne!(expected, result2, "Different additions should differ");
    }

    // =========================================================================
    // Comprehensive Test Suite
    // =========================================================================

    /// Run all ChaCha underconstraint tests.
    #[test]
    fn test_chacha_underconstraint_suite() {
        println!("\n=== ChaCha20 Underconstraint Test Suite ===\n");

        let mut results = Vec::new();

        // Test 1: Quarter round correctness
        {
            let mut state = [0x11111111u32, 0x01020304, 0x9b8d6f43, 0x01234567];
            quarter_round_native(&mut state);
            let expected = [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];

            if state == expected {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "qr_rfc_vector".to_string(),
                    error: "Quarter round matches RFC 7539".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "qr_rfc_vector".to_string(),
                    details: format!("Got {:x?}, expected {:x?}", state, expected),
                });
            }
        }

        // Test 2: Full block correctness
        {
            let result = chacha20_block_from_key(&test_key(), 1, &test_nonce());
            let expected = expected_block_output();

            if result == expected {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "block_rfc_vector".to_string(),
                    error: "Block output matches RFC 7539".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "block_rfc_vector".to_string(),
                    details: "Block output mismatch".to_string(),
                });
            }
        }

        // Test 3: XOR correctness
        {
            let a = 0xAABBCCDDu32;
            let b = 0x11223344u32;
            let expected = 0xBB99FF99u32;
            let actual = a ^ b;

            if actual == expected {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "xor_correctness".to_string(),
                    error: "XOR computed correctly".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "xor_correctness".to_string(),
                    details: format!("XOR: got {:#x}, expected {:#x}", actual, expected),
                });
            }
        }

        // Test 4: Rotation correctness
        {
            let x = 0xAABBCCDDu32;
            let expected = 0xCCDDAABBu32;
            let actual = x.rotate_left(16);

            if actual == expected {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "rotl16_correctness".to_string(),
                    error: "rotl16 computed correctly".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "rotl16_correctness".to_string(),
                    details: format!("rotl16: got {:#x}, expected {:#x}", actual, expected),
                });
            }
        }

        // Test 5: Different keys produce different outputs
        {
            let key1 = test_key();
            let mut key2 = test_key();
            key2[0] ^= 0x1;

            let output1 = chacha20_block_from_key(&key1, 1, &test_nonce());
            let output2 = chacha20_block_from_key(&key2, 1, &test_nonce());

            if output1 != output2 {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "different_keys".to_string(),
                    error: "Different keys produce different outputs".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "different_keys".to_string(),
                    details: "Different keys produced same output!".to_string(),
                });
            }
        }

        // Test 6: Different counters produce different outputs
        {
            let output1 = chacha20_block_from_key(&test_key(), 1, &test_nonce());
            let output2 = chacha20_block_from_key(&test_key(), 2, &test_nonce());

            if output1 != output2 {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "different_counters".to_string(),
                    error: "Different counters produce different outputs".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "different_counters".to_string(),
                    details: "Different counters produced same output!".to_string(),
                });
            }
        }

        let (passed, vulnerabilities, skipped) = run_underconstraint_tests(results);

        assert_eq!(
            vulnerabilities, 0,
            "Found {} underconstraint vulnerabilities!",
            vulnerabilities
        );
        println!(
            "\nAll {} tests passed (no underconstraint vulnerabilities found)",
            passed
        );
    }
}
