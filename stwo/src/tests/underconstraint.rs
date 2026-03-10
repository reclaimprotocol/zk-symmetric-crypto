//! Common infrastructure for underconstraint testing.
//!
//! Underconstraint vulnerabilities occur when a malicious prover can generate
//! valid proofs for invalid computations. This module provides tools to detect
//! such vulnerabilities by:
//!
//! 1. Generating traces with intentional corruptions
//! 2. Attempting to verify these corrupted traces
//! 3. Asserting that verification fails
//!
//! If verification succeeds for a corrupted trace, the circuit is underconstrained.

use std::fmt::Debug;

/// Types of trace mutations for malicious prover tests.
#[derive(Clone, Debug)]
pub enum TraceMutation {
    /// Set a specific value at a given position.
    SetValue {
        row: usize,
        col: usize,
        value: u32,
    },
    /// Corrupt a boolean constraint (set value to 2 instead of 0 or 1).
    CorruptBoolean { row: usize, col: usize },
    /// Flip the lowest bit of a value.
    FlipBit { row: usize, col: usize },
    /// Set a value to zero.
    SetZero { row: usize, col: usize },
    /// Set a value to maximum (0x1FFFFFFF for 29-bit limbs).
    SetMax { row: usize, col: usize },
}

/// Result of an underconstraint test.
#[derive(Debug)]
pub enum UnderconstraintTestResult {
    /// The test passed: verification correctly failed for corrupted input.
    CorrectlyRejected {
        mutation: String,
        error: String,
    },
    /// The test revealed an underconstraint: verification passed for corrupted input.
    Underconstrained {
        mutation: String,
        details: String,
    },
    /// The test was skipped or could not be run.
    Skipped { reason: String },
}

impl UnderconstraintTestResult {
    /// Returns true if this result indicates a potential security vulnerability.
    pub fn is_vulnerability(&self) -> bool {
        matches!(self, UnderconstraintTestResult::Underconstrained { .. })
    }

    /// Returns true if verification correctly rejected the corrupted input.
    pub fn is_correctly_rejected(&self) -> bool {
        matches!(self, UnderconstraintTestResult::CorrectlyRejected { .. })
    }
}

/// Wrapper for running tests that expect verification to fail.
///
/// This macro/function pattern is used to test that corrupted inputs are
/// correctly rejected by the verification logic.
///
/// # Arguments
/// * `test_name` - Description of what's being tested
/// * `test_fn` - Function that attempts verification with corrupted input
///
/// # Returns
/// * `Ok(())` if verification correctly failed
/// * `Err(msg)` if verification incorrectly succeeded (indicating underconstraint)
pub fn expect_verification_failure<F, E>(test_name: &str, test_fn: F) -> UnderconstraintTestResult
where
    F: FnOnce() -> Result<(), E>,
    E: Debug,
{
    match test_fn() {
        Ok(()) => {
            // Verification succeeded when it should have failed!
            UnderconstraintTestResult::Underconstrained {
                mutation: test_name.to_string(),
                details: "Verification succeeded for corrupted input - circuit may be underconstrained".to_string(),
            }
        }
        Err(e) => {
            // Verification correctly failed
            UnderconstraintTestResult::CorrectlyRejected {
                mutation: test_name.to_string(),
                error: format!("{:?}", e),
            }
        }
    }
}

/// Run a test that expects native verification to fail.
///
/// This is used when we corrupt inputs and expect the native verification
/// to detect the corruption and return an error.
pub fn expect_native_failure<T, E: Debug>(
    test_name: &str,
    result: Result<T, E>,
) -> UnderconstraintTestResult {
    match result {
        Ok(_) => UnderconstraintTestResult::Underconstrained {
            mutation: test_name.to_string(),
            details: "Native verification succeeded for corrupted input".to_string(),
        },
        Err(e) => UnderconstraintTestResult::CorrectlyRejected {
            mutation: test_name.to_string(),
            error: format!("{:?}", e),
        },
    }
}

/// Run a test that expects output mismatch.
///
/// Used when we corrupt inputs but expect the computation to produce
/// a different output than the expected public output.
pub fn expect_output_mismatch(
    test_name: &str,
    expected: u32,
    actual: u32,
) -> UnderconstraintTestResult {
    if expected != actual {
        UnderconstraintTestResult::CorrectlyRejected {
            mutation: test_name.to_string(),
            error: format!("Output mismatch: expected {}, got {}", expected, actual),
        }
    } else {
        UnderconstraintTestResult::Underconstrained {
            mutation: test_name.to_string(),
            details: format!(
                "Output matched ({}) despite corrupted input - potential underconstraint",
                actual
            ),
        }
    }
}

/// Run a test that expects output mismatch for BigInt256 values.
///
/// Used when we corrupt inputs but expect the computation to produce
/// a different output than the expected public output (for MiMC hash outputs).
pub fn expect_output_mismatch_bigint<T: PartialEq + Debug>(
    test_name: &str,
    expected: &T,
    actual: &T,
) -> UnderconstraintTestResult {
    if expected != actual {
        UnderconstraintTestResult::CorrectlyRejected {
            mutation: test_name.to_string(),
            error: format!("Output mismatch: expected {:?}, got {:?}", expected, actual),
        }
    } else {
        UnderconstraintTestResult::Underconstrained {
            mutation: test_name.to_string(),
            details: format!(
                "Output matched ({:?}) despite corrupted input - potential underconstraint",
                actual
            ),
        }
    }
}

/// Assert that a test result indicates correct rejection.
///
/// Panics if the result indicates an underconstraint vulnerability.
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
        UnderconstraintTestResult::Skipped { reason } => {
            println!("SKIP: {}", reason);
        }
    }
}

/// Run multiple underconstraint tests and report results.
pub fn run_underconstraint_tests(tests: Vec<UnderconstraintTestResult>) -> (usize, usize, usize) {
    let mut passed = 0;
    let mut vulnerabilities = 0;
    let mut skipped = 0;

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
            UnderconstraintTestResult::Skipped { reason } => {
                println!("  [SKIP] {}", reason);
                skipped += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expect_verification_failure_correct() {
        let result = expect_verification_failure("test failure", || -> Result<(), &str> {
            Err("expected error")
        });
        assert!(result.is_correctly_rejected());
    }

    #[test]
    fn test_expect_verification_failure_vulnerability() {
        let result = expect_verification_failure("test success", || -> Result<(), &str> { Ok(()) });
        assert!(result.is_vulnerability());
    }

    #[test]
    fn test_output_mismatch_correct() {
        let result = expect_output_mismatch("test mismatch", 123, 456);
        assert!(result.is_correctly_rejected());
    }

    #[test]
    fn test_output_mismatch_vulnerability() {
        let result = expect_output_mismatch("test match", 123, 123);
        assert!(result.is_vulnerability());
    }
}
