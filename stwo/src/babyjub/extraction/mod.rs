//! Data extraction component for TOPRF.
//!
//! Extracts selected bytes from cipher plaintext into two Field256 elements
//! for use as TOPRF secret data. Uses byte-level bitmask selection.
//!
//! The extraction works as follows:
//! - Plaintext bytes come from cipher output (128 bytes for ChaCha/AES)
//! - A public bitmask (0xFF = include, 0x00 = exclude) selects which bytes matter
//! - Selected bytes are packed into two Field256 elements (31 bytes each, max 62 total)
//! - The circuit verifies the extraction is done correctly

pub mod constraints;
pub mod gen;

use crate::babyjub::field256::gen::BigInt256;

/// Maximum bytes that can be extracted (2 × 31 = 62).
pub const MAX_EXTRACT_BYTES: usize = 62;

/// Bytes per Field256 element (31 bytes = 248 bits < 254 bits).
pub const BYTES_PER_FIELD: usize = 31;

/// Total plaintext bytes from cipher (2 ChaCha blocks or 8 AES blocks).
pub const TOTAL_PLAINTEXT_BYTES: usize = 128;

/// Public inputs for data extraction.
#[derive(Clone, Debug)]
pub struct ExtractionPublicInputs {
    /// Bitmask: 0xFF for bytes to include, 0x00 for bytes to exclude.
    pub bitmask: [u8; TOTAL_PLAINTEXT_BYTES],

    /// Expected number of selected bytes (for validation).
    pub len: u32,
}

/// Private inputs for data extraction.
#[derive(Clone, Debug)]
pub struct ExtractionPrivateInputs {
    /// Plaintext bytes from cipher decryption.
    pub plaintext: [u8; TOTAL_PLAINTEXT_BYTES],
}

/// Output of data extraction.
#[derive(Clone, Debug, Default)]
pub struct ExtractionOutput {
    /// First 31 bytes packed as Field256.
    pub secret_data_0: BigInt256,

    /// Next 31 bytes packed as Field256.
    pub secret_data_1: BigInt256,
}

impl Default for ExtractionPublicInputs {
    fn default() -> Self {
        Self {
            bitmask: [0; TOTAL_PLAINTEXT_BYTES],
            len: 0,
        }
    }
}

impl Default for ExtractionPrivateInputs {
    fn default() -> Self {
        Self {
            plaintext: [0; TOTAL_PLAINTEXT_BYTES],
        }
    }
}

/// Set bitmask for a contiguous range of bytes.
pub fn set_bitmask_range(bitmask: &mut [u8], start: usize, len: usize) {
    for i in start..(start + len) {
        if i < bitmask.len() {
            bitmask[i] = 0xFF;
        }
    }
}

/// Set bitmask for multiple non-contiguous byte ranges.
pub fn set_bitmask_ranges(bitmask: &mut [u8], ranges: &[(usize, usize)]) {
    for &(start, len) in ranges {
        set_bitmask_range(bitmask, start, len);
    }
}

/// Count selected bytes in a bitmask.
pub fn count_selected_bytes(bitmask: &[u8]) -> usize {
    bitmask.iter().filter(|&&b| b == 0xFF).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_bitmask_range() {
        let mut bitmask = [0u8; 128];
        set_bitmask_range(&mut bitmask, 10, 5);

        assert_eq!(bitmask[9], 0);
        assert_eq!(bitmask[10], 0xFF);
        assert_eq!(bitmask[14], 0xFF);
        assert_eq!(bitmask[15], 0);
    }

    #[test]
    fn test_count_selected() {
        let mut bitmask = [0u8; 128];
        set_bitmask_range(&mut bitmask, 0, 31);
        set_bitmask_range(&mut bitmask, 64, 31);

        assert_eq!(count_selected_bytes(&bitmask), 62);
    }
}
