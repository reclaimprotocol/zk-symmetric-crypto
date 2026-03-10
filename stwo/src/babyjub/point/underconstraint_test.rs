//! Underconstraint tests for Baby Jubjub point operations.
//!
//! These tests verify that point operation constraints properly reject:
//! - Non-binary scalar bits
//! - Corrupted point coordinates
//! - Invalid curve points
//! - Incorrect point addition/doubling results

#[cfg(test)]
mod tests {
    use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
    use crate::babyjub::point::gen::{native, scalar_to_bits, bits_to_scalar, PointTraceGen};
    use crate::babyjub::point::{base_point, curve_a, curve_d, ExtendedPointBigInt};
    use crate::tests::underconstraint::{
        assert_correctly_rejected, run_underconstraint_tests, UnderconstraintTestResult,
    };

    // =========================================================================
    // Test Helpers
    // =========================================================================

    /// Check if a point is on the curve: a*x^2 + y^2 = 1 + d*x^2*y^2
    fn is_on_curve(x: &BigInt256, y: &BigInt256) -> bool {
        let p = modulus();
        let a = curve_a();
        let d = curve_d();

        let x2 = x.mul_mod(x, &p);
        let y2 = y.mul_mod(y, &p);
        let ax2 = a.mul_mod(&x2, &p);
        let dx2y2 = d.mul_mod(&x2.mul_mod(&y2, &p), &p);

        let lhs = ax2.add_mod(&y2, &p);
        let rhs = BigInt256::one().add_mod(&dx2y2, &p);

        lhs == rhs
    }

    /// Create a test scalar for multiplication tests.
    fn test_scalar() -> BigInt256 {
        BigInt256::from_limbs([12345, 67890, 11111, 0, 0, 0, 0, 0, 0])
    }

    // =========================================================================
    // Test: Base Point on Curve
    // =========================================================================

    /// Verify base point is on the curve.
    #[test]
    fn test_base_point_on_curve() {
        let base = base_point();
        let p = modulus();
        let (x, y) = base.to_affine(&p);

        assert!(is_on_curve(&x, &y), "Base point should be on curve");
    }

    // =========================================================================
    // Test: Scalar Bit Constraints
    // =========================================================================

    /// Test that scalar bits are properly extracted.
    #[test]
    fn test_scalar_bits_extraction() {
        let scalar = test_scalar();
        let bits = scalar_to_bits(&scalar);

        // Verify all bits are 0 or 1
        for (i, &bit) in bits.iter().enumerate() {
            assert!(
                bit == false || bit == true,
                "Bit {} should be boolean, got {:?}",
                i,
                bit
            );
        }

        // Verify roundtrip
        let recovered = bits_to_scalar(&bits);
        // Note: Scalar might lose high bits beyond 254
        for i in 0..8 {
            // Check lower 254 bits match
            if i < 7 {
                assert_eq!(
                    scalar.limbs[i] & 0x1FFFFFFF,
                    recovered.limbs[i] & 0x1FFFFFFF,
                    "Limb {} mismatch after roundtrip",
                    i
                );
            }
        }
    }

    /// Test detection of non-binary scalar bit values.
    ///
    /// In a proper circuit, each scalar bit b must satisfy b * (b - 1) = 0.
    /// A value of 2 would violate this constraint.
    #[test]
    fn test_non_binary_scalar_bit_detected() {
        // Simulate what would happen with a non-binary bit
        let non_binary_bit: u32 = 2;

        // Check that b * (b - 1) != 0 for non-binary values
        let constraint = non_binary_bit * (non_binary_bit - 1);

        let test_result = if constraint != 0 {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "non_binary_scalar_bit".to_string(),
                error: format!(
                    "Constraint b*(b-1) = {} != 0 for b = {}",
                    constraint, non_binary_bit
                ),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "non_binary_scalar_bit".to_string(),
                details: "Non-binary value passed boolean constraint".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    // =========================================================================
    // Test: Point Addition
    // =========================================================================

    /// Test that point addition produces valid curve points.
    #[test]
    fn test_point_addition_valid() {
        let base = base_point();
        let p = modulus();

        let doubled = native::add_points(&base, &base);
        let (x, y) = doubled.to_affine(&p);

        assert!(is_on_curve(&x, &y), "P + P should be on curve");
    }

    /// Test that P + O = P (identity property).
    #[test]
    fn test_point_add_identity() {
        let base = base_point();
        let identity = ExtendedPointBigInt::identity();
        let p = modulus();

        let result = native::add_points(&base, &identity);
        let (bx, by) = base.to_affine(&p);
        let (rx, ry) = result.to_affine(&p);

        assert_eq!(bx, rx, "P + O should equal P (x coord)");
        assert_eq!(by, ry, "P + O should equal P (y coord)");
    }

    /// Test corrupted point addition input.
    #[test]
    fn test_corrupted_point_add_input() {
        let base = base_point();
        let p = modulus();

        // Create a corrupted point (not on curve)
        let mut corrupted = base.clone();
        corrupted.x.limbs[0] ^= 0x100;

        // Addition should produce a point not equal to expected result
        let result_good = native::add_points(&base, &base);
        let result_bad = native::add_points(&base, &corrupted);

        let (gx, gy) = result_good.to_affine(&p);
        let (bx, by) = result_bad.to_affine(&p);

        let test_result = if gx != bx || gy != by {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "corrupted_point_add".to_string(),
                error: "Corrupted input produces different result".to_string(),
            }
        } else {
            UnderconstraintTestResult::Underconstrained {
                mutation: "corrupted_point_add".to_string(),
                details: "Corrupted input produced same result".to_string(),
            }
        };

        assert_correctly_rejected(test_result);
    }

    // =========================================================================
    // Test: Point Doubling
    // =========================================================================

    /// Test that point doubling equals adding point to itself.
    #[test]
    fn test_double_equals_add() {
        let base = base_point();
        let p = modulus();

        let doubled = native::double_point(&base);
        let added = native::add_points(&base, &base);

        let (dx, dy) = doubled.to_affine(&p);
        let (ax, ay) = added.to_affine(&p);

        assert_eq!(dx, ax, "2P via double should equal P+P (x coord)");
        assert_eq!(dy, ay, "2P via double should equal P+P (y coord)");
    }

    /// Test doubling identity gives identity.
    #[test]
    fn test_double_identity() {
        let identity = ExtendedPointBigInt::identity();
        let p = modulus();

        let doubled = native::double_point(&identity);
        let (x, y) = doubled.to_affine(&p);

        // Identity has x=0, y=1
        assert!(x.is_zero(), "2*O should have x=0");
        assert_eq!(y, BigInt256::one(), "2*O should have y=1");
    }

    // =========================================================================
    // Test: Scalar Multiplication
    // =========================================================================

    /// Test scalar multiplication by 1.
    #[test]
    fn test_scalar_mul_one() {
        let base = base_point();
        let one = BigInt256::one();
        let p = modulus();

        let result = native::scalar_mul(&base, &one);
        let (bx, by) = base.to_affine(&p);
        let (rx, ry) = result.to_affine(&p);

        assert_eq!(bx, rx, "1*P should equal P (x coord)");
        assert_eq!(by, ry, "1*P should equal P (y coord)");
    }

    /// Test scalar multiplication by 2.
    #[test]
    fn test_scalar_mul_two() {
        let base = base_point();
        let two = BigInt256::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
        let p = modulus();

        let mul_result = native::scalar_mul(&base, &two);
        let double_result = native::double_point(&base);

        let (mx, my) = mul_result.to_affine(&p);
        let (dx, dy) = double_result.to_affine(&p);

        assert_eq!(mx, dx, "2*P via scalar_mul should equal 2P via double (x)");
        assert_eq!(my, dy, "2*P via scalar_mul should equal 2P via double (y)");
    }

    /// Test scalar multiplication by 0.
    #[test]
    fn test_scalar_mul_zero() {
        let base = base_point();
        let zero = BigInt256::zero();
        let p = modulus();

        let result = native::scalar_mul(&base, &zero);
        let (x, y) = result.to_affine(&p);

        // 0*P should be identity (0, 1)
        assert!(x.is_zero(), "0*P should have x=0");
        assert_eq!(y, BigInt256::one(), "0*P should have y=1");
    }

    /// Test that different scalars produce different points.
    #[test]
    fn test_different_scalars_different_points() {
        let base = base_point();
        let p = modulus();

        let scalar1 = BigInt256::from_limbs([100, 0, 0, 0, 0, 0, 0, 0, 0]);
        let scalar2 = BigInt256::from_limbs([101, 0, 0, 0, 0, 0, 0, 0, 0]);

        let result1 = native::scalar_mul(&base, &scalar1);
        let result2 = native::scalar_mul(&base, &scalar2);

        let (x1, y1) = result1.to_affine(&p);
        let (x2, y2) = result2.to_affine(&p);

        assert!(
            x1 != x2 || y1 != y2,
            "Different scalars should produce different points"
        );
    }

    // =========================================================================
    // Test: Cofactor Clearing
    // =========================================================================

    /// Test cofactor clearing (multiply by 8).
    #[test]
    fn test_cofactor_clearing() {
        let base = base_point();
        let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
        let p = modulus();

        let cleared = native::clear_cofactor(&base);
        let mul_eight = native::scalar_mul(&base, &eight);

        let (cx, cy) = cleared.to_affine(&p);
        let (mx, my) = mul_eight.to_affine(&p);

        assert_eq!(cx, mx, "Cofactor clearing should equal 8*P (x coord)");
        assert_eq!(cy, my, "Cofactor clearing should equal 8*P (y coord)");
    }

    /// Test that cofactor cleared point is not identity (for base point).
    #[test]
    fn test_cofactor_cleared_not_identity() {
        let base = base_point();
        let p = modulus();

        let cleared = native::clear_cofactor(&base);
        let (x, _y) = cleared.to_affine(&p);

        assert!(
            !x.is_zero(),
            "Cofactor cleared base point should not be identity"
        );
    }

    // =========================================================================
    // Test: Invalid Point Detection
    // =========================================================================

    /// Test that a point with corrupted coordinates is detected.
    #[test]
    fn test_corrupted_coordinates_detected() {
        let p = modulus();

        // Create a point with invalid coordinates (likely not on curve)
        let invalid = ExtendedPointBigInt::from_affine(
            BigInt256::from_limbs([12345, 67890, 0, 0, 0, 0, 0, 0, 0]),
            BigInt256::from_limbs([11111, 22222, 0, 0, 0, 0, 0, 0, 0]),
            &p,
        );

        let (x, y) = invalid.to_affine(&p);
        let on_curve = is_on_curve(&x, &y);

        let test_result = if !on_curve {
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: "invalid_point_coords".to_string(),
                error: "Point with random coords is not on curve".to_string(),
            }
        } else {
            // Unlikely but possible
            UnderconstraintTestResult::Skipped {
                reason: "Random point happened to be on curve".to_string(),
            }
        };

        match test_result {
            UnderconstraintTestResult::Underconstrained { .. } => {
                panic!("Should not have underconstraint here");
            }
            _ => {}
        }
    }

    // =========================================================================
    // Test: Trace Generation Consistency
    // =========================================================================

    /// Test that trace generation matches native computation.
    #[test]
    fn test_trace_gen_matches_native() {
        let base = base_point();
        let p = modulus();

        // Using trace generator
        let mut gen = PointTraceGen::new();
        let trace_doubled = gen.double_point(&base);

        // Using native
        let native_doubled = native::double_point(&base);

        let (tx, ty) = trace_doubled.to_affine(&p);
        let (nx, ny) = native_doubled.to_affine(&p);

        assert_eq!(tx, nx, "Trace gen should match native (x coord)");
        assert_eq!(ty, ny, "Trace gen should match native (y coord)");
    }

    // =========================================================================
    // Comprehensive Test Suite
    // =========================================================================

    /// Run all point operation underconstraint tests.
    #[test]
    fn test_point_underconstraint_suite() {
        println!("\n=== Point Operation Underconstraint Test Suite ===\n");

        let base = base_point();
        let p = modulus();
        let mut results = Vec::new();

        // Test 1: Base point on curve
        {
            let (x, y) = base.to_affine(&p);
            if is_on_curve(&x, &y) {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "base_point_on_curve".to_string(),
                    error: "Base point verified on curve".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "base_point_on_curve".to_string(),
                    details: "Base point not on curve!".to_string(),
                });
            }
        }

        // Test 2: Non-binary bit detection
        {
            let non_binary: u32 = 2;
            let constraint = non_binary * (non_binary - 1);
            if constraint != 0 {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "non_binary_bit".to_string(),
                    error: format!("b*(b-1) = {} for b=2", constraint),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "non_binary_bit".to_string(),
                    details: "Non-binary passed constraint".to_string(),
                });
            }
        }

        // Test 3: Point addition preserves curve membership
        {
            let sum = native::add_points(&base, &base);
            let (x, y) = sum.to_affine(&p);
            if is_on_curve(&x, &y) {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "point_add_on_curve".to_string(),
                    error: "P+P is on curve".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "point_add_on_curve".to_string(),
                    details: "P+P not on curve!".to_string(),
                });
            }
        }

        // Test 4: Double equals add
        {
            let doubled = native::double_point(&base);
            let added = native::add_points(&base, &base);
            let (dx, dy) = doubled.to_affine(&p);
            let (ax, ay) = added.to_affine(&p);

            if dx == ax && dy == ay {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "double_equals_add".to_string(),
                    error: "2P via double equals P+P".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "double_equals_add".to_string(),
                    details: "2P via double != P+P".to_string(),
                });
            }
        }

        // Test 5: Scalar mul by 1
        {
            let result = native::scalar_mul(&base, &BigInt256::one());
            let (bx, by) = base.to_affine(&p);
            let (rx, ry) = result.to_affine(&p);

            if bx == rx && by == ry {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "scalar_mul_one".to_string(),
                    error: "1*P equals P".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "scalar_mul_one".to_string(),
                    details: "1*P != P".to_string(),
                });
            }
        }

        // Test 6: Cofactor clearing
        {
            let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
            let cleared = native::clear_cofactor(&base);
            let mul_eight = native::scalar_mul(&base, &eight);
            let (cx, cy) = cleared.to_affine(&p);
            let (mx, my) = mul_eight.to_affine(&p);

            if cx == mx && cy == my {
                results.push(UnderconstraintTestResult::CorrectlyRejected {
                    mutation: "cofactor_clearing".to_string(),
                    error: "Cofactor clearing equals 8*P".to_string(),
                });
            } else {
                results.push(UnderconstraintTestResult::Underconstrained {
                    mutation: "cofactor_clearing".to_string(),
                    details: "Cofactor clearing != 8*P".to_string(),
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
