//! AES implementation for Stwo.
//!
//! This module provides both native reference implementations and
//! STARK circuit implementations for AES-128/256.

pub mod bitwise;
pub mod lookup;
pub mod sbox_table;

/// AES S-box lookup table (for reference/testing).
pub const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Inverse S-box lookup table.
pub const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Round constants for key expansion.
pub const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// GF(2^8) multiplication by 2 (xtime).
/// Polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
#[inline]
pub fn xtime(x: u8) -> u8 {
    let shifted = x << 1;
    if x & 0x80 != 0 {
        shifted ^ 0x1b
    } else {
        shifted
    }
}

/// GF(2^8) multiplication.
#[inline]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi_bit = a & 0x80;
        a <<= 1;
        if hi_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

/// Compute multiplicative inverse in GF(2^8) using x^254.
/// Returns 0 for input 0 (by AES convention).
#[inline]
pub fn gf_inv(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }

    // Compute x^254 using addition chain:
    // x^2, x^3, x^6, x^12, x^14, x^15, x^30, x^60, x^120, x^126, x^127, x^254
    let x2 = gf_mul(x, x);
    let x3 = gf_mul(x2, x);
    let x6 = gf_mul(x3, x3);
    let x12 = gf_mul(x6, x6);
    let x14 = gf_mul(x12, x2);
    let x15 = gf_mul(x14, x);
    let x30 = gf_mul(x15, x15);
    let x60 = gf_mul(x30, x30);
    let x120 = gf_mul(x60, x60);
    let x126 = gf_mul(x120, x6);
    let x127 = gf_mul(x126, x);
    let x254 = gf_mul(x127, x127);

    x254
}

/// Compute S-box value: inverse in GF(2^8) followed by affine transform.
#[inline]
pub fn sbox_compute(x: u8) -> u8 {
    let inv = gf_inv(x);

    // Affine transformation over GF(2):
    // b'[i] = b[i] XOR b[(i+4) mod 8] XOR b[(i+5) mod 8] XOR b[(i+6) mod 8] XOR b[(i+7) mod 8] XOR c[i]
    // where c = 0x63
    let mut result = 0u8;
    for i in 0..8 {
        let bit = ((inv >> i) & 1)
            ^ ((inv >> ((i + 4) % 8)) & 1)
            ^ ((inv >> ((i + 5) % 8)) & 1)
            ^ ((inv >> ((i + 6) % 8)) & 1)
            ^ ((inv >> ((i + 7) % 8)) & 1)
            ^ ((0x63 >> i) & 1);
        result |= bit << i;
    }
    result
}

/// Native AES-128 block encryption.
pub fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let round_keys = expand_key_128(key);

    // Initial AddRoundKey
    for i in 0..16 {
        block[i] ^= round_keys[i];
    }

    // 9 main rounds
    for round in 1..10 {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &round_keys[round * 16..(round + 1) * 16]);
    }

    // Final round (no MixColumns)
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &round_keys[160..176]);
}

/// SubBytes transformation.
fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

/// ShiftRows transformation.
fn shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // Row 2: shift left by 2
    let tmp0 = state[2];
    let tmp1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = tmp0;
    state[14] = tmp1;

    // Row 3: shift left by 3 (= right by 1)
    let tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

/// MixColumns transformation.
fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let s0 = state[i];
        let s1 = state[i + 1];
        let s2 = state[i + 2];
        let s3 = state[i + 3];

        state[i] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[i + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[i + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[i + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

/// AddRoundKey transformation.
fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

/// Expand AES-128 key to round keys (11 round keys = 176 bytes).
pub fn expand_key_128(key: &[u8; 16]) -> [u8; 176] {
    let mut w = [0u8; 176];

    // First 16 bytes are the key itself
    w[..16].copy_from_slice(key);

    for i in 4..44 {
        let mut temp = [w[i * 4 - 4], w[i * 4 - 3], w[i * 4 - 2], w[i * 4 - 1]];

        if i % 4 == 0 {
            // RotWord + SubWord + Rcon
            let t = temp[0];
            temp[0] = SBOX[temp[1] as usize] ^ RCON[i / 4];
            temp[1] = SBOX[temp[2] as usize];
            temp[2] = SBOX[temp[3] as usize];
            temp[3] = SBOX[t as usize];
        }

        for j in 0..4 {
            w[i * 4 + j] = w[(i - 4) * 4 + j] ^ temp[j];
        }
    }

    w
}

/// Expand AES-256 key to round keys (15 round keys = 240 bytes).
pub fn expand_key_256(key: &[u8; 32]) -> [u8; 240] {
    let mut w = [0u8; 240];

    // First 32 bytes are the key itself
    w[..32].copy_from_slice(key);

    for i in 8..60 {
        let mut temp = [w[i * 4 - 4], w[i * 4 - 3], w[i * 4 - 2], w[i * 4 - 1]];

        if i % 8 == 0 {
            // RotWord + SubWord + Rcon
            let t = temp[0];
            temp[0] = SBOX[temp[1] as usize] ^ RCON[i / 8];
            temp[1] = SBOX[temp[2] as usize];
            temp[2] = SBOX[temp[3] as usize];
            temp[3] = SBOX[t as usize];
        } else if i % 8 == 4 {
            // SubWord only (AES-256 specific)
            temp[0] = SBOX[temp[0] as usize];
            temp[1] = SBOX[temp[1] as usize];
            temp[2] = SBOX[temp[2] as usize];
            temp[3] = SBOX[temp[3] as usize];
        }

        for j in 0..4 {
            w[i * 4 + j] = w[(i - 8) * 4 + j] ^ temp[j];
        }
    }

    w
}

/// Native AES-256 block encryption.
pub fn aes256_encrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let round_keys = expand_key_256(key);

    // Initial AddRoundKey
    for i in 0..16 {
        block[i] ^= round_keys[i];
    }

    // 13 main rounds
    for round in 1..14 {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &round_keys[round * 16..(round + 1) * 16]);
    }

    // Final round (no MixColumns)
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &round_keys[224..240]);
}

/// AES key variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AesKeySize {
    Aes128,
    Aes256,
}

impl AesKeySize {
    pub fn key_bytes(&self) -> usize {
        match self {
            AesKeySize::Aes128 => 16,
            AesKeySize::Aes256 => 32,
        }
    }

    pub fn num_rounds(&self) -> usize {
        match self {
            AesKeySize::Aes128 => 10,
            AesKeySize::Aes256 => 14,
        }
    }

    pub fn num_round_keys(&self) -> usize {
        self.num_rounds() + 1
    }
}

/// AES-CTR encryption/decryption.
/// Encrypts `plaintext` using AES-CTR mode with given key and nonce.
/// Returns ciphertext of the same length.
pub fn aes_ctr_encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let key_size = match key.len() {
        16 => AesKeySize::Aes128,
        32 => AesKeySize::Aes256,
        _ => panic!("Invalid key length: must be 16 or 32 bytes"),
    };

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter: u32 = 1; // Start at 1 per RFC 7539

    for chunk in plaintext.chunks(16) {
        // Build counter block: nonce (12 bytes) || counter (4 bytes big-endian)
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(nonce);
        counter_block[12..16].copy_from_slice(&counter.to_be_bytes());

        // Encrypt counter block
        match key_size {
            AesKeySize::Aes128 => {
                let key_arr: [u8; 16] = key.try_into().unwrap();
                aes128_encrypt_block(&key_arr, &mut counter_block);
            }
            AesKeySize::Aes256 => {
                let key_arr: [u8; 32] = key.try_into().unwrap();
                aes256_encrypt_block(&key_arr, &mut counter_block);
            }
        }

        // XOR with plaintext
        for (i, &byte) in chunk.iter().enumerate() {
            ciphertext.push(byte ^ counter_block[i]);
        }

        counter = counter.wrapping_add(1);
    }

    ciphertext
}

/// AES-CTR decryption (same as encryption due to XOR symmetry).
pub fn aes_ctr_decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    aes_ctr_encrypt(key, nonce, ciphertext)
}

/// Encrypt a single AES-128-CTR block.
/// Returns ciphertext = AES(nonce || counter) XOR plaintext.
pub fn aes128_ctr_block(key: &[u8; 16], nonce: &[u8; 12], counter: u32, plaintext: &[u8; 16]) -> [u8; 16] {
    // Build counter block: nonce (12 bytes) || counter (4 bytes big-endian)
    let mut counter_block = [0u8; 16];
    counter_block[..12].copy_from_slice(nonce);
    counter_block[12..16].copy_from_slice(&counter.to_be_bytes());

    // Encrypt counter block
    aes128_encrypt_block(key, &mut counter_block);

    // XOR with plaintext
    let mut ciphertext = [0u8; 16];
    for i in 0..16 {
        ciphertext[i] = plaintext[i] ^ counter_block[i];
    }
    ciphertext
}

/// Encrypt a single AES-256-CTR block.
/// Returns ciphertext = AES(nonce || counter) XOR plaintext.
pub fn aes256_ctr_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, plaintext: &[u8; 16]) -> [u8; 16] {
    // Build counter block: nonce (12 bytes) || counter (4 bytes big-endian)
    let mut counter_block = [0u8; 16];
    counter_block[..12].copy_from_slice(nonce);
    counter_block[12..16].copy_from_slice(&counter.to_be_bytes());

    // Encrypt counter block
    aes256_encrypt_block(key, &mut counter_block);

    // XOR with plaintext
    let mut ciphertext = [0u8; 16];
    for i in 0..16 {
        ciphertext[i] = plaintext[i] ^ counter_block[i];
    }
    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_computation() {
        // Verify computed S-box matches the table
        for i in 0..256 {
            let computed = sbox_compute(i as u8);
            assert_eq!(computed, SBOX[i], "S-box mismatch at index {}", i);
        }
    }

    #[test]
    fn test_gf_inverse() {
        // Test that x * x^(-1) = 1 for all non-zero x
        for x in 1..=255u8 {
            let inv = gf_inv(x);
            let product = gf_mul(x, inv);
            assert_eq!(product, 1, "Inverse failed for {}: inv={}, product={}", x, inv, product);
        }
    }

    #[test]
    fn test_aes128_known_answer() {
        // FIPS 197 test vector
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        aes128_encrypt_block(&key, &mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_aes256_known_answer() {
        // FIPS 197 AES-256 test vector
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

        aes256_encrypt_block(&key, &mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn test_aes128_ctr() {
        // Test AES-128-CTR
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [0x00; 12];
        let plaintext = b"Hello, World! This is a test of AES-CTR mode.";

        let ciphertext = aes_ctr_encrypt(&key, &nonce, plaintext);
        let decrypted = aes_ctr_decrypt(&key, &nonce, &ciphertext);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_ctr() {
        // Test AES-256-CTR
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [0x00; 12];
        let plaintext = b"Hello, World! This is a test of AES-256-CTR mode with multiple blocks.";

        let ciphertext = aes_ctr_encrypt(&key, &nonce, plaintext);
        let decrypted = aes_ctr_decrypt(&key, &nonce, &ciphertext);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_ctr_multiple_blocks() {
        // Test CTR mode with multiple blocks
        let key: [u8; 16] = [0x2b; 16];
        let nonce: [u8; 12] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];

        // 5 blocks = 80 bytes
        let plaintext = vec![0x42u8; 80];

        let ciphertext = aes_ctr_encrypt(&key, &nonce, &plaintext);
        assert_eq!(ciphertext.len(), 80);

        let decrypted = aes_ctr_decrypt(&key, &nonce, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }
}
