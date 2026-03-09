//! MiMC hash function compatible with gnark-crypto.
//!
//! This implements MiMC over BN254 scalar field using Miyaguchi-Preneel construction,
//! exactly matching gnark-crypto's implementation for cross-system compatibility.
//!
//! Parameters:
//! - Rounds: 110
//! - Exponent: 5 (x^5 per round)
//! - Field: BN254 scalar field (same as Baby Jubjub base field)
//! - Constants: Generated from Keccak256 hash of "seed"
//!
//! The hash function is defined as:
//! ```text
//! For each input element:
//!   r = encrypt(element, state)
//!   state = state + r + element
//! Return state
//! ```
//!
//! Where encrypt is:
//! ```text
//! for i in 0..110:
//!   tmp = m + k + c[i]
//!   m = tmp^5
//! return m + k
//! ```

pub mod constants;

use crate::babyjub::field256::gen::{modulus, BigInt256};

/// Number of MiMC rounds (matches gnark-crypto).
pub const MIMC_ROUNDS: usize = 110;

/// MiMC encryption: encrypt(message, key) using 110 rounds of x^5.
///
/// This matches gnark-crypto's MiMC encryption exactly.
pub fn mimc_encrypt(message: &BigInt256, key: &BigInt256) -> BigInt256 {
    let p = modulus();
    let mut m = *message;

    for i in 0..MIMC_ROUNDS {
        // tmp = m + k + c[i]
        let c_i = BigInt256::from_u256(&constants::MIMC_CONSTANTS[i]);
        let tmp = m.add_mod(key, &p).add_mod(&c_i, &p);

        // m = tmp^5 (computed as tmp^2 * tmp^2 * tmp)
        let tmp2 = tmp.mul_mod(&tmp, &p);
        let tmp4 = tmp2.mul_mod(&tmp2, &p);
        m = tmp4.mul_mod(&tmp, &p);
    }

    // Return m + k
    m.add_mod(key, &p)
}

/// MiMC hash using Miyaguchi-Preneel construction.
///
/// This matches gnark-crypto's MiMC hash exactly:
/// ```text
/// h = 0
/// for each element in data:
///   r = encrypt(element, h)
///   h = h + r + element
/// return h
/// ```
pub fn mimc_hash(data: &[BigInt256]) -> BigInt256 {
    let p = modulus();
    let mut h = BigInt256::zero();

    for element in data {
        let r = mimc_encrypt(element, &h);
        // h = h + r + element
        h = h.add_mod(&r, &p).add_mod(element, &p);
    }

    h
}

/// MiMC hash for bytes (gnark-compatible).
///
/// Converts bytes to field elements (big-endian, 32 bytes per element)
/// and then hashes them.
pub fn mimc_hash_bytes(data: &[&[u8]]) -> BigInt256 {
    let elements: Vec<BigInt256> = data
        .iter()
        .map(|bytes| {
            // gnark uses big-endian bytes for field elements
            BigInt256::from_bytes_be(bytes)
        })
        .collect();

    mimc_hash(&elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mimc_encrypt_basic() {
        let p = modulus();
        let message = BigInt256::from_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0]);
        let key = BigInt256::zero();

        let result = mimc_encrypt(&message, &key);

        // Result should be non-zero and less than modulus
        assert!(!result.is_zero());
        assert!(result.lt(&p));
    }

    #[test]
    fn test_mimc_hash_single_element() {
        let input = BigInt256::from_limbs([42, 0, 0, 0, 0, 0, 0, 0, 0]);
        let hash = mimc_hash(&[input]);

        // Hash should be deterministic
        let hash2 = mimc_hash(&[input]);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_mimc_hash_multiple_elements() {
        let a = BigInt256::from_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
        let c = BigInt256::from_limbs([3, 0, 0, 0, 0, 0, 0, 0, 0]);

        let hash1 = mimc_hash(&[a, b, c]);
        let hash2 = mimc_hash(&[a, b, c]);
        let hash3 = mimc_hash(&[a, c, b]); // Different order

        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_ne!(hash1, hash3, "Different order should give different hash");
    }

    #[test]
    fn test_mimc_hash_empty() {
        let hash = mimc_hash(&[]);
        assert!(hash.is_zero(), "Empty hash should be zero");
    }

    #[test]
    fn test_constants_loaded() {
        // Verify first constant matches expected value
        let c0 = BigInt256::from_u256(&constants::MIMC_CONSTANTS[0]);
        assert!(!c0.is_zero(), "First constant should not be zero");

        // Verify last constant
        let c109 = BigInt256::from_u256(&constants::MIMC_CONSTANTS[109]);
        assert!(!c109.is_zero(), "Last constant should not be zero");
    }

    // ===========================================
    // gnark-crypto compatibility tests
    // Test vectors generated from gnark-crypto/ecc/bn254/fr/mimc
    // ===========================================

    #[test]
    fn test_mimc_gnark_compat_hash_1() {
        // Hash([1]) from gnark-crypto: 0x27e5458b666ef581475a9acddbc3524ca252185cae3936506e65cda9c358222b
        let input = BigInt256::from_u256(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let hash = mimc_hash(&[input]);
        let hash_bytes = hash.to_bytes_be();

        let expected: [u8; 32] = [
            0x27, 0xe5, 0x45, 0x8b, 0x66, 0x6e, 0xf5, 0x81,
            0x47, 0x5a, 0x9a, 0xcd, 0xdb, 0xc3, 0x52, 0x4c,
            0xa2, 0x52, 0x18, 0x5c, 0xae, 0x39, 0x36, 0x50,
            0x6e, 0x65, 0xcd, 0xa9, 0xc3, 0x58, 0x22, 0x2b,
        ];

        assert_eq!(hash_bytes, expected, "Hash([1]) mismatch with gnark-crypto");
    }

    #[test]
    fn test_mimc_gnark_compat_hash_42() {
        // Hash([42]) from gnark-crypto: 0x15cc289ebc18cb3ba9301f46f0619391ee79007ea289fd3d9155d574f121e953
        let input = BigInt256::from_u256(&[42, 0, 0, 0, 0, 0, 0, 0]);
        let hash = mimc_hash(&[input]);
        let hash_bytes = hash.to_bytes_be();

        let expected: [u8; 32] = [
            0x15, 0xcc, 0x28, 0x9e, 0xbc, 0x18, 0xcb, 0x3b,
            0xa9, 0x30, 0x1f, 0x46, 0xf0, 0x61, 0x93, 0x91,
            0xee, 0x79, 0x00, 0x7e, 0xa2, 0x89, 0xfd, 0x3d,
            0x91, 0x55, 0xd5, 0x74, 0xf1, 0x21, 0xe9, 0x53,
        ];

        assert_eq!(hash_bytes, expected, "Hash([42]) mismatch with gnark-crypto");
    }

    #[test]
    fn test_mimc_gnark_compat_hash_1_2() {
        // Hash([1, 2]) from gnark-crypto: 0x07f751d627280b8f73ebe288d68acd77dc2fd6962debda017df192e355065814
        let a = BigInt256::from_u256(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::from_u256(&[2, 0, 0, 0, 0, 0, 0, 0]);
        let hash = mimc_hash(&[a, b]);
        let hash_bytes = hash.to_bytes_be();

        let expected: [u8; 32] = [
            0x07, 0xf7, 0x51, 0xd6, 0x27, 0x28, 0x0b, 0x8f,
            0x73, 0xeb, 0xe2, 0x88, 0xd6, 0x8a, 0xcd, 0x77,
            0xdc, 0x2f, 0xd6, 0x96, 0x2d, 0xeb, 0xda, 0x01,
            0x7d, 0xf1, 0x92, 0xe3, 0x55, 0x06, 0x58, 0x14,
        ];

        assert_eq!(hash_bytes, expected, "Hash([1, 2]) mismatch with gnark-crypto");
    }

    #[test]
    fn test_mimc_gnark_compat_hash_1_2_3() {
        // Hash([1, 2, 3]) from gnark-crypto: 0x03868717a65a6849e28d9cf6fcc2340e9e00b8dee902ed252d8f4e986e2b8864
        let a = BigInt256::from_u256(&[1, 0, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::from_u256(&[2, 0, 0, 0, 0, 0, 0, 0]);
        let c = BigInt256::from_u256(&[3, 0, 0, 0, 0, 0, 0, 0]);
        let hash = mimc_hash(&[a, b, c]);
        let hash_bytes = hash.to_bytes_be();

        let expected: [u8; 32] = [
            0x03, 0x86, 0x87, 0x17, 0xa6, 0x5a, 0x68, 0x49,
            0xe2, 0x8d, 0x9c, 0xf6, 0xfc, 0xc2, 0x34, 0x0e,
            0x9e, 0x00, 0xb8, 0xde, 0xe9, 0x02, 0xed, 0x25,
            0x2d, 0x8f, 0x4e, 0x98, 0x6e, 0x2b, 0x88, 0x64,
        ];

        assert_eq!(hash_bytes, expected, "Hash([1, 2, 3]) mismatch with gnark-crypto");
    }

    #[test]
    fn test_mimc_first_constant() {
        // Verify first constant matches gnark-crypto: 0x00808370c37267481fb91b077899955706f209e5e0762dac2c79ba1e7a91b018
        let c0 = BigInt256::from_u256(&constants::MIMC_CONSTANTS[0]);
        let c0_bytes = c0.to_bytes_be();

        let expected: [u8; 32] = [
            0x00, 0x80, 0x83, 0x70, 0xc3, 0x72, 0x67, 0x48,
            0x1f, 0xb9, 0x1b, 0x07, 0x78, 0x99, 0x95, 0x57,
            0x06, 0xf2, 0x09, 0xe5, 0xe0, 0x76, 0x2d, 0xac,
            0x2c, 0x79, 0xba, 0x1e, 0x7a, 0x91, 0xb0, 0x18,
        ];

        assert_eq!(c0_bytes, expected, "First constant mismatch with gnark-crypto");
    }
}
