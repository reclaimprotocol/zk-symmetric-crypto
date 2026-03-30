//! ChaCha20 full block computation.
//!
//! Implements the full ChaCha20 block function (20 rounds = 10 double-rounds).
//! Reference: RFC 7539 https://datatracker.ietf.org/doc/html/rfc7539

use super::quarter_round::quarter_round_native;
use super::{CONSTANTS, STATE_SIZE};

/// Perform a ChaCha20 double-round (column rounds + diagonal rounds).
///
/// A double-round consists of:
/// - 4 column quarter-rounds on indices (0,4,8,12), (1,5,9,13), (2,6,10,14), (3,7,11,15)
/// - 4 diagonal quarter-rounds on indices (0,5,10,15), (1,6,11,12), (2,7,8,13), (3,4,9,14)
#[inline]
pub fn double_round(state: &mut [u32; STATE_SIZE]) {
    // Column rounds
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);

    // Diagonal rounds
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

/// Quarter-round on arbitrary indices within a state array.
#[inline]
fn quarter_round(state: &mut [u32; STATE_SIZE], a: usize, b: usize, c: usize, d: usize) {
    let mut qr = [state[a], state[b], state[c], state[d]];
    quarter_round_native(&mut qr);
    state[a] = qr[0];
    state[b] = qr[1];
    state[c] = qr[2];
    state[d] = qr[3];
}

/// Build initial ChaCha state from key, counter, and nonce.
///
/// State layout (16 x 32-bit words):
/// ```text
/// cccccccc  cccccccc  cccccccc  cccccccc
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
/// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
/// ```
/// Where:
/// - c = constants ("expand 32-byte k")
/// - k = 256-bit key (8 words)
/// - b = 32-bit block counter
/// - n = 96-bit nonce (3 words)
pub fn build_state(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; STATE_SIZE] {
    [
        CONSTANTS[0],
        CONSTANTS[1],
        CONSTANTS[2],
        CONSTANTS[3],
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        counter,
        nonce[0],
        nonce[1],
        nonce[2],
    ]
}

/// Compute a full ChaCha20 block.
///
/// This performs 20 rounds (10 double-rounds) and adds the initial state.
/// The result is 64 bytes of keystream.
pub fn chacha20_block(state: &mut [u32; STATE_SIZE]) {
    let initial = *state;

    // 20 rounds = 10 double-rounds
    for _ in 0..10 {
        double_round(state);
    }

    // Add initial state (mod 2^32)
    for i in 0..STATE_SIZE {
        state[i] = state[i].wrapping_add(initial[i]);
    }
}

/// Compute ChaCha20 block from key, counter, and nonce.
/// Returns 64 bytes of keystream as 16 u32 words.
pub fn chacha20_block_from_key(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; STATE_SIZE] {
    let mut state = build_state(key, counter, nonce);
    chacha20_block(&mut state);
    state
}

/// Serialize state to bytes (little-endian).
pub fn state_to_bytes(state: &[u32; STATE_SIZE]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7539 Section 2.3.2 - Test Vector for ChaCha20 Block Function
    #[test]
    fn test_chacha20_block_rfc7539() {
        // Key: 00:01:02:...1f
        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
            0x1f1e1d1c,
        ];

        // Nonce: 00:00:00:09:00:00:00:4a:00:00:00:00
        let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];

        // Counter: 1
        let counter: u32 = 1;

        let result = chacha20_block_from_key(&key, counter, &nonce);

        // Expected output from RFC 7539
        let expected: [u32; 16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(result, expected);
    }

    /// Test that initial state is built correctly
    #[test]
    fn test_build_state() {
        let key: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let nonce: [u32; 3] = [9, 10, 11];
        let counter: u32 = 42;

        let state = build_state(&key, counter, &nonce);

        // Check constants
        assert_eq!(state[0], CONSTANTS[0]);
        assert_eq!(state[1], CONSTANTS[1]);
        assert_eq!(state[2], CONSTANTS[2]);
        assert_eq!(state[3], CONSTANTS[3]);

        // Check key
        for i in 0..8 {
            assert_eq!(state[4 + i], key[i]);
        }

        // Check counter and nonce
        assert_eq!(state[12], counter);
        assert_eq!(state[13], nonce[0]);
        assert_eq!(state[14], nonce[1]);
        assert_eq!(state[15], nonce[2]);
    }

    /// Test double-round separately
    #[test]
    fn test_double_round() {
        // Start with a known state
        let mut state: [u32; 16] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
            0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
            0x4a000000, 0x00000000,
        ];

        // After one double-round
        double_round(&mut state);

        // The state should have changed
        assert_ne!(state[0], 0x61707865);
    }

    /// Test serialization to bytes
    #[test]
    fn test_state_to_bytes() {
        let state: [u32; 16] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
            0x1f1e1d1c, 0x23222120, 0x27262524, 0x2b2a2928, 0x2f2e2d2c, 0x33323130, 0x37363534,
            0x3b3a3938, 0x3f3e3d3c,
        ];

        let bytes = state_to_bytes(&state);

        // First word: 0x03020100 -> [0x00, 0x01, 0x02, 0x03] in little-endian
        assert_eq!(bytes[0..4], [0x00, 0x01, 0x02, 0x03]);
        assert_eq!(bytes[4..8], [0x04, 0x05, 0x06, 0x07]);
    }
}
