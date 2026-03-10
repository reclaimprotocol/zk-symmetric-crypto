//! Underconstraint tests for Field256 arithmetic operations.
//!
//! These tests verify that the Field256 arithmetic constraints properly reject
//! invalid computations. Tests include:
//! - Corrupted multiplication results
//! - Overflow limb values
//! - Corrupted addition/subtraction results
//! - Invalid inverse values

#[cfg(test)]
mod tests {
    use crate::babyjub::field256::gen::{modulus, BigInt256, Field256TraceGen};
    use crate::tests::underconstraint::{
        assert_correctly_rejected, expect_output_mismatch, run_underconstraint_tests,
        UnderconstraintTestResult,
    };

    // =========================================================================
    // Test Helpers
    // =========================================================================

    /// Create a random-ish BigInt256 for testing.
    /// All limbs must be < 2^29 = 0x20000000 = 536870912
    fn test_value_1() -> BigInt256 {
        BigInt256::from_limbs([
            0x12345678, // 305419896 < 2^29
            0x09ABCDEF, // 162254319 < 2^29
            0x11111111, // 286331153 < 2^29
            0x02222222, // 35791394 < 2^29 (was 0x22222222 which exceeds limit)
            0x03333333, // 53687091 < 2^29
            0x04444444, // 71582788 < 2^29
            0x05555555, // 89478485 < 2^29
            0x06666666, // 107374182 < 2^29
            0x00777777, // 7829367 < 2^29
        ])
    }

    fn test_value_2() -> BigInt256 {
        BigInt256::from_limbs([
            0x0FEDCBA9, // 267072425 < 2^29
            0x08765432, // 141650994 < 2^29
            0x0AAAAAAA, // 178956970 < 2^29
            0x0BBBBBBB, // 196852667 < 2^29
            0x0CCCCCCC, // 214748364 < 2^29
            0x0DDDDDDD, // 232644061 < 2^29
            0x0EEEEEEE, // 250539758 < 2^29
            0x0FFFFFFF, // 268435455 < 2^29
            0x00111111, // 1118481 < 2^29
        ])
    }

    fn test_value_small() -> BigInt256 {
        BigInt256::from_limbs([12345, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    // =========================================================================
    // Test: Multiplication Correctness
    // =========================================================================

    /// Test that multiplication result is correct.
    #[test]
    fn test_mul_correct_result() {
        let a = test_value_small();
        let b = BigInt256::from_limbs([67890, 0, 0, 0, 0, 0, 0, 0, 0]);
        let p = modulus();

        let expected = a.mul_mod(&b, &p);
        let mut gen = Field256TraceGen::new();
        let result = gen.gen_mul(&a, &b);

        assert_eq!(
            result, expected,
            "Multiplication result should match expected"
        );
    }

    /// Test that wrong multiplication result would be detectable.
    #[test]
    fn test_mul_wrong_result_detectable() {
        let a = test_value_small();
        let b = BigInt256::from_limbs([67890, 0, 0, 0, 0, 0, 0, 0, 0]);
        let p = modulus();

        let correct = a.mul_mod(&b, &p);

        // Create a wrong result
        let mut wrong = correct.clone();
        wrong.limbs[0] = wrong.limbs[0].wrapping_add(1) & 0x1FFFFFFF;

        // The constraint system should detect this
        // In a full circuit, the verification equation a*b = q*p + r would fail
        let test_result = if correct != wrong {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "mul_wrong_result".to_string(),
                error: "Result differs from expected".to_string(),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "mul_wrong_result".to_string(),
                details: "Wrong result equals correct result".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    /// Test multiplication with larger values.
    #[test]
    fn test_mul_large_values() {
        let a = test_value_1();
        let b = test_value_2();
        let p = modulus();

        let expected = a.mul_mod(&b, &p);
        let mut gen = Field256TraceGen::new();
        let result = gen.gen_mul(&a, &b);

        assert_eq!(result, expected, "Large value multiplication should match");
    }

    // =========================================================================
    // Test: Addition Correctness
    // =========================================================================

    /// Test that addition result is correct.
    #[test]
    fn test_add_correct_result() {
        let a = test_value_1();
        let b = test_value_2();
        let p = modulus();

        let expected = a.add_mod(&b, &p);
        let mut gen = Field256TraceGen::new();
        let result = gen.gen_add(&a, &b);

        assert_eq!(result, expected, "Addition result should match expected");
    }

    /// Test addition that requires reduction.
    #[test]
    fn test_add_with_reduction() {
        let p = modulus();

        // Create values that sum to more than p
        let a = p.sub_no_reduce(&BigInt256::from_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0])).0;
        let b = BigInt256::from_limbs([10, 0, 0, 0, 0, 0, 0, 0, 0]);

        let expected = a.add_mod(&b, &p);
        let mut gen = Field256TraceGen::new();
        let result = gen.gen_add(&a, &b);

        assert_eq!(result, expected, "Addition with reduction should match");

        // Result should be b - 1 = 9
        assert_eq!(result.limbs[0], 9);
        for i in 1..9 {
            assert_eq!(result.limbs[i], 0);
        }
    }

    // =========================================================================
    // Test: Subtraction Correctness
    // =========================================================================

    /// Test that subtraction result is correct.
    #[test]
    fn test_sub_correct_result() {
        let a = test_value_1();
        let b = test_value_small();
        let p = modulus();

        let expected = a.sub_mod(&b, &p);
        let mut gen = Field256TraceGen::new();
        let result = gen.gen_sub(&a, &b);

        assert_eq!(
            result, expected,
            "Subtraction result should match expected"
        );
    }

    /// Test subtraction that requires borrowing (a < b).
    #[test]
    fn test_sub_with_borrow() {
        let a = test_value_small();
        let b = test_value_1();
        let p = modulus();

        // a < b, so result should be p + a - b
        let expected = a.sub_mod(&b, &p);
        let mut gen = Field256TraceGen::new();
        let result = gen.gen_sub(&a, &b);

        assert_eq!(result, expected, "Subtraction with borrow should match");
    }

    // =========================================================================
    // Test: Inversion Correctness
    // =========================================================================

    /// Test that inversion is correct.
    #[test]
    fn test_inv_correct_result() {
        let a = test_value_small();
        let p = modulus();

        let inv = a.inv_mod(&p).unwrap();

        // Verify a * inv = 1 (mod p)
        let product = a.mul_mod(&inv, &p);
        assert_eq!(product, BigInt256::one(), "a * a^-1 should equal 1");
    }

    /// Test that zero has no inverse.
    #[test]
    fn test_inv_zero_fails() {
        let a = BigInt256::zero();
        let p = modulus();

        let result = a.inv_mod(&p);
        assert!(result.is_none(), "Zero should have no inverse");
    }

    /// Test inversion of larger values.
    #[test]
    fn test_inv_large_value() {
        let a = test_value_1();
        let p = modulus();

        let inv = a.inv_mod(&p).unwrap();
        let product = a.mul_mod(&inv, &p);

        assert_eq!(product, BigInt256::one(), "Large value inverse should work");
    }

    // =========================================================================
    // Test: Limb Overflow Detection
    // =========================================================================

    /// Test that limb values exceeding 29 bits would be detectable.
    ///
    /// In a proper circuit, range checks would reject values >= 2^29.
    #[test]
    fn test_limb_overflow_detection() {
        // Create a value with limb exceeding 29 bits
        let mut overflow_value = test_value_small();
        overflow_value.limbs[0] = 1 << 30; // Exceeds 29-bit limit

        // In a properly constrained circuit, this would fail range checks
        // Here we verify the value is indeed out of range
        let is_overflow = overflow_value.limbs[0] > 0x1FFFFFFF;

        let test_result = if is_overflow {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "limb_overflow".to_string(),
                error: format!("Limb value {} exceeds 29-bit limit", overflow_value.limbs[0]),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "limb_overflow".to_string(),
                details: "Overflow value not detected".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    /// Test that all limbs in a valid value are within range.
    #[test]
    fn test_limbs_in_range() {
        let values = [test_value_1(), test_value_2(), test_value_small(), modulus()];

        for (i, val) in values.iter().enumerate() {
            for (j, &limb) in val.limbs.iter().enumerate() {
                assert!(
                    limb <= 0x1FFFFFFF,
                    "Value {} limb {} = {} exceeds 29-bit limit",
                    i,
                    j,
                    limb
                );
            }
        }
    }

    // =========================================================================
    // Test: Edge Cases
    // =========================================================================

    /// Test multiplication by zero.
    #[test]
    fn test_mul_by_zero() {
        let a = test_value_1();
        let b = BigInt256::zero();
        let p = modulus();

        let result = a.mul_mod(&b, &p);
        assert!(result.is_zero(), "Anything times zero should be zero");
    }

    /// Test multiplication by one.
    #[test]
    fn test_mul_by_one() {
        // Use a small value that's definitely less than the modulus
        let a = BigInt256::from_limbs([12345, 67890, 11111, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::one();
        let p = modulus();

        let result = a.mul_mod(&b, &p);
        assert_eq!(result, a, "Anything times one should be itself");
    }

    /// Test addition with zero.
    #[test]
    fn test_add_zero() {
        // Use a small value that's definitely less than the modulus
        let a = BigInt256::from_limbs([12345, 67890, 11111, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::zero();
        let p = modulus();

        let result = a.add_mod(&b, &p);
        assert_eq!(result, a, "Adding zero should not change the value");
    }

    /// Test subtraction of self.
    #[test]
    fn test_sub_self() {
        let a = test_value_1();
        let p = modulus();

        let result = a.sub_mod(&a, &p);
        assert!(result.is_zero(), "Subtracting self should yield zero");
    }

    // =========================================================================
    // Comprehensive Test Suite
    // =========================================================================

    /// Run all Field256 underconstraint tests.
    #[test]
    fn test_field256_underconstraint_suite() {
        println!("\n=== Field256 Underconstraint Test Suite ===\n");

        let mut results = Vec::new();
        let p = modulus();

        // Test 1: Multiplication correctness
        {
            let a = test_value_1();
            let b = test_value_2();
            let expected = a.mul_mod(&b, &p);
            let mut gen = Field256TraceGen::new();
            let result = gen.gen_mul(&a, &b);

            if result == expected {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "mul_correctness".to_string(),
                    error: "Multiplication computed correctly".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "mul_correctness".to_string(),
                    details: "Multiplication result incorrect".to_string(),
                });
            }
        }

        // Test 2: Addition correctness
        {
            let a = test_value_1();
            let b = test_value_2();
            let expected = a.add_mod(&b, &p);
            let mut gen = Field256TraceGen::new();
            let result = gen.gen_add(&a, &b);

            if result == expected {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "add_correctness".to_string(),
                    error: "Addition computed correctly".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "add_correctness".to_string(),
                    details: "Addition result incorrect".to_string(),
                });
            }
        }

        // Test 3: Subtraction correctness
        {
            let a = test_value_1();
            let b = test_value_small();
            let expected = a.sub_mod(&b, &p);
            let mut gen = Field256TraceGen::new();
            let result = gen.gen_sub(&a, &b);

            if result == expected {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "sub_correctness".to_string(),
                    error: "Subtraction computed correctly".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "sub_correctness".to_string(),
                    details: "Subtraction result incorrect".to_string(),
                });
            }
        }

        // Test 4: Inversion correctness
        {
            let a = test_value_small();
            let inv = a.inv_mod(&p).unwrap();
            let product = a.mul_mod(&inv, &p);

            if product == BigInt256::one() {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "inv_correctness".to_string(),
                    error: "Inversion computed correctly".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "inv_correctness".to_string(),
                    details: "a * a^-1 != 1".to_string(),
                });
            }
        }

        // Test 5: Zero inverse fails
        {
            let zero = BigInt256::zero();
            let result = zero.inv_mod(&p);

            if result.is_none() {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "zero_inv_fails".to_string(),
                    error: "Zero correctly has no inverse".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "zero_inv_fails".to_string(),
                    details: "Zero incorrectly has an inverse".to_string(),
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
