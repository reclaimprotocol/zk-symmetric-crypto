//! Combined cipher + TOPRF STARK proof module.
//!
//! This module provides a combined STARK proof that proves both:
//! 1. Correct cipher decryption (ChaCha20 or AES-CTR)
//! 2. TOPRF verification on data extracted from the plaintext
//!
//! This enables proving that a specific piece of data exists within
//! encrypted content and computing a verifiable PRF output on it,
//! without revealing the encryption key or the full plaintext.

pub mod air;
pub mod gen;

use crate::babyjub::field256::gen::BigInt256;
use crate::babyjub::point::AffinePointBigInt;
use crate::babyjub::toprf::THRESHOLD;

/// Location in plaintext to extract secret data.
#[derive(Clone, Debug)]
pub struct DataLocation {
    /// Byte position in plaintext.
    pub pos: usize,
    /// Number of bytes to extract.
    pub len: usize,
}

/// A cipher block with its own nonce and counter.
#[derive(Clone, Debug)]
pub struct CipherBlock {
    /// Nonce/IV for this block.
    pub nonce: [u8; 12],
    /// Starting counter for this block.
    pub counter: u32,
    /// Byte offset in the concatenated plaintext/ciphertext where this block starts.
    pub byte_offset: usize,
    /// Length of this block in bytes.
    pub byte_len: usize,
}

/// Cipher algorithm selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherAlgorithm {
    ChaCha20,
    Aes128Ctr,
    Aes256Ctr,
}

impl CipherAlgorithm {
    /// Parse from string (e.g., "chacha20", "aes-128-ctr").
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "chacha20" => Some(Self::ChaCha20),
            "aes-128-ctr" | "aes128-ctr" | "aes128ctr" => Some(Self::Aes128Ctr),
            "aes-256-ctr" | "aes256-ctr" | "aes256ctr" => Some(Self::Aes256Ctr),
            _ => None,
        }
    }

    /// Get block size in bytes.
    pub fn block_size(&self) -> usize {
        match self {
            Self::ChaCha20 => 64,
            Self::Aes128Ctr | Self::Aes256Ctr => 16,
        }
    }

    /// Get key size in bytes.
    pub fn key_size(&self) -> usize {
        match self {
            Self::ChaCha20 => 32,
            Self::Aes128Ctr => 16,
            Self::Aes256Ctr => 32,
        }
    }
}

/// TOPRF public inputs for combined proof.
#[derive(Clone, Debug)]
pub struct TOPRFPublicInputs {
    /// Domain separator for hash-to-point.
    pub domain_separator: BigInt256,

    /// Server responses (one per threshold share).
    pub responses: [AffinePointBigInt; THRESHOLD],

    /// Lagrange coefficients for combining responses.
    pub coefficients: [BigInt256; THRESHOLD],

    /// Public keys for each share.
    pub share_public_keys: [AffinePointBigInt; THRESHOLD],

    /// DLEQ challenge values.
    pub c: [BigInt256; THRESHOLD],

    /// DLEQ response values.
    pub r: [BigInt256; THRESHOLD],

    /// Expected output hash (MiMC hash output, gnark-compatible).
    pub output: BigInt256,
}

/// TOPRF private inputs for combined proof.
#[derive(Clone, Debug)]
pub struct TOPRFPrivateInputs {
    /// Blinding mask for the data point.
    pub mask: BigInt256,
}

/// Combined cipher + TOPRF inputs for proving.
#[derive(Clone, Debug)]
pub struct CombinedInputs {
    /// Cipher algorithm to use.
    pub algorithm: CipherAlgorithm,

    /// Encryption key (private).
    pub key: Vec<u8>,

    /// Cipher blocks with their nonces and counters.
    /// Each block covers a portion of the plaintext/ciphertext.
    pub blocks: Vec<CipherBlock>,

    /// Plaintext (concatenated from all blocks).
    pub plaintext: Vec<u8>,

    /// Ciphertext (concatenated from all blocks).
    pub ciphertext: Vec<u8>,

    /// Locations in plaintext to extract secret data for TOPRF.
    pub locations: Vec<DataLocation>,

    /// TOPRF public inputs.
    pub toprf_public: TOPRFPublicInputs,

    /// TOPRF private inputs.
    pub toprf_private: TOPRFPrivateInputs,
}

impl CombinedInputs {
    /// Get the first nonce (for backward compatibility).
    pub fn first_nonce(&self) -> [u8; 12] {
        self.blocks.first().map(|b| b.nonce).unwrap_or([0u8; 12])
    }

    /// Get the first counter (for backward compatibility).
    pub fn first_counter(&self) -> u32 {
        self.blocks.first().map(|b| b.counter).unwrap_or(0)
    }
}

impl Default for TOPRFPublicInputs {
    fn default() -> Self {
        Self {
            domain_separator: BigInt256::zero(),
            responses: [AffinePointBigInt::default(); THRESHOLD],
            coefficients: [BigInt256::one(); THRESHOLD],
            share_public_keys: [AffinePointBigInt::default(); THRESHOLD],
            c: [BigInt256::zero(); THRESHOLD],
            r: [BigInt256::zero(); THRESHOLD],
            output: BigInt256::zero(),
        }
    }
}

impl Default for TOPRFPrivateInputs {
    fn default() -> Self {
        Self {
            mask: BigInt256::one(),
        }
    }
}

/// Extract secret data from plaintext at specified locations.
/// Returns up to 62 bytes packed into two 31-byte field elements.
pub fn extract_secret_data(plaintext: &[u8], locations: &[DataLocation]) -> [BigInt256; 2] {
    // Collect all bytes from locations (up to 62 bytes total)
    let mut secret_bytes = Vec::with_capacity(62);

    for loc in locations {
        let end = (loc.pos + loc.len).min(plaintext.len());
        if loc.pos < plaintext.len() {
            secret_bytes.extend_from_slice(&plaintext[loc.pos..end]);
        }
        if secret_bytes.len() >= 62 {
            break;
        }
    }

    // Truncate to 62 bytes max
    if secret_bytes.len() > 62 {
        secret_bytes.truncate(62);
    }

    // Convert to two field elements using gnark-compatible encoding
    bytes_to_field256_elements_gnark(&secret_bytes)
}

/// Convert bytes to Field256 elements (gnark-compatible: big-endian to little-endian).
fn bytes_to_field256_elements_gnark(bytes: &[u8]) -> [BigInt256; 2] {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_secret_data_simple() {
        let plaintext = b"Hello, World! This is a test.";
        let locations = vec![DataLocation { pos: 0, len: 13 }];

        let [elem0, elem1] = extract_secret_data(plaintext, &locations);

        // elem0 should contain "Hello, World!" reversed
        assert!(!elem0.is_zero());
        // elem1 should be zero (no second element needed)
        assert!(elem1.is_zero());
    }

    #[test]
    fn test_extract_secret_data_multiple_locations() {
        let plaintext = b"AAAAAAAAAAAABBBBBBBBBBBB";
        let locations = vec![
            DataLocation { pos: 0, len: 12 },
            DataLocation { pos: 12, len: 12 },
        ];

        let [elem0, elem1] = extract_secret_data(plaintext, &locations);

        // Should have data in elem0, possibly elem1
        assert!(!elem0.is_zero());
    }

    #[test]
    fn test_cipher_algorithm_from_str() {
        assert_eq!(
            CipherAlgorithm::from_str("chacha20"),
            Some(CipherAlgorithm::ChaCha20)
        );
        assert_eq!(
            CipherAlgorithm::from_str("aes-128-ctr"),
            Some(CipherAlgorithm::Aes128Ctr)
        );
        assert_eq!(
            CipherAlgorithm::from_str("aes-256-ctr"),
            Some(CipherAlgorithm::Aes256Ctr)
        );
        assert_eq!(CipherAlgorithm::from_str("invalid"), None);
    }
}
