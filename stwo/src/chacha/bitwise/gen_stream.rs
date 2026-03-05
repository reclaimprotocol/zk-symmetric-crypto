//! Trace generation for ChaCha20 stream encryption.
//!
//! Public inputs: nonce, counter, plaintext, ciphertext
//! Private input: key
//! Proves: ChaCha20(key, nonce, counter) XOR plaintext == ciphertext

use std::simd::u32x16;

use itertools::Itertools;
use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{PackedBaseField, LOG_N_LANES};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::ORIGINAL_TRACE_IDX;

use super::chacha_bitwise_info;
use crate::chacha::STATE_SIZE;

/// Input to ChaCha20 stream encryption (SIMD-packed: 16 parallel blocks).
#[derive(Clone)]
pub struct ChaChaStreamInput {
    /// Key (8 u32s = 256 bits), same across all lanes - PRIVATE
    pub key: [u32; 8],
    /// Nonce (3 u32s = 96 bits), same across all lanes - PUBLIC
    pub nonce: [u32; 3],
    /// Counter values for each of 16 parallel blocks - PUBLIC
    pub counters: u32x16,
    /// Plaintext: 16 u32s per block, packed as u32x16 - PUBLIC
    pub plaintext: [u32x16; 16],
    /// Ciphertext: 16 u32s per block, packed as u32x16 - PUBLIC
    pub ciphertext: [u32x16; 16],
}

/// Trace generator for ChaCha20 stream.
struct StreamTraceGenerator {
    trace: Vec<BaseColumn>,
}

impl StreamTraceGenerator {
    fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        // Get base info and add columns for plaintext (16*32) + ciphertext (16*32)
        let info = chacha_bitwise_info();
        let base_cols = info.mask_offsets[ORIGINAL_TRACE_IDX].len();
        // Add: plaintext bits (16*32) + ciphertext bits (16*32)
        let n_cols = base_cols + 16 * 32 + 16 * 32;
        let trace = (0..n_cols)
            .map(|_| unsafe { Col::<SimdBackend, BaseField>::uninitialized(1 << log_size) })
            .collect_vec();
        Self { trace }
    }

    fn gen_row(&mut self, vec_row: usize) -> StreamTraceGeneratorRow<'_> {
        StreamTraceGeneratorRow {
            gen: self,
            col_index: 0,
            vec_row,
        }
    }
}

/// Row generator for stream trace generation.
struct StreamTraceGeneratorRow<'a> {
    gen: &'a mut StreamTraceGenerator,
    col_index: usize,
    vec_row: usize,
}

impl StreamTraceGeneratorRow<'_> {
    /// Append a single bit to the trace.
    fn append_bit(&mut self, val: u32x16) {
        self.gen.trace[self.col_index].data[self.vec_row] =
            unsafe { PackedBaseField::from_simd_unchecked(val) };
        self.col_index += 1;
    }

    /// Append a u32 as 32 bits (LSB first).
    fn append_u32_bits(&mut self, val: u32x16) {
        for i in 0..32 {
            let bit = (val >> i) & u32x16::splat(1);
            self.append_bit(bit);
        }
    }

    /// Build initial state from key, counter, nonce.
    fn build_state(key: &[u32; 8], counter: u32x16, nonce: &[u32; 3]) -> [u32x16; STATE_SIZE] {
        [
            // Constants "expand 32-byte k"
            u32x16::splat(0x61707865),
            u32x16::splat(0x3320646e),
            u32x16::splat(0x79622d32),
            u32x16::splat(0x6b206574),
            // Key
            u32x16::splat(key[0]),
            u32x16::splat(key[1]),
            u32x16::splat(key[2]),
            u32x16::splat(key[3]),
            u32x16::splat(key[4]),
            u32x16::splat(key[5]),
            u32x16::splat(key[6]),
            u32x16::splat(key[7]),
            // Counter (varies per lane)
            counter,
            // Nonce
            u32x16::splat(nonce[0]),
            u32x16::splat(nonce[1]),
            u32x16::splat(nonce[2]),
        ]
    }

    /// Generate trace for a full block with stream encryption.
    /// Returns true if ciphertext matches, false otherwise.
    fn generate(&mut self, input: &ChaChaStreamInput) -> bool {
        let initial = Self::build_state(&input.key, input.counters, &input.nonce);

        // Append initial state (16 x 32 = 512 bits)
        for s in &initial {
            self.append_u32_bits(*s);
        }

        let mut v = initial;

        // 10 double-rounds
        for _ in 0..10 {
            // Column quarter-rounds
            self.quarter_round(&mut v, 0, 4, 8, 12);
            self.quarter_round(&mut v, 1, 5, 9, 13);
            self.quarter_round(&mut v, 2, 6, 10, 14);
            self.quarter_round(&mut v, 3, 7, 11, 15);

            // Diagonal quarter-rounds
            self.quarter_round(&mut v, 0, 5, 10, 15);
            self.quarter_round(&mut v, 1, 6, 11, 12);
            self.quarter_round(&mut v, 2, 7, 8, 13);
            self.quarter_round(&mut v, 3, 4, 9, 14);
        }

        // Final addition: keystream[i] = v[i] + initial[i]
        let mut keystream = [u32x16::splat(0); 16];
        for i in 0..STATE_SIZE {
            keystream[i] = self.add_u32(v[i], initial[i]);
        }

        // Append plaintext bits (16 x 32 = 512 bits) - PUBLIC INPUT
        for pt in &input.plaintext {
            self.append_u32_bits(*pt);
        }

        // Compute expected ciphertext and verify against provided ciphertext
        let mut valid = true;
        for i in 0..16 {
            let computed_ct = keystream[i] ^ input.plaintext[i];
            // Append the PROVIDED ciphertext (not computed) - PUBLIC INPUT
            self.append_u32_bits(input.ciphertext[i]);

            // Check if computed matches provided (for all lanes)
            let mismatch = computed_ct ^ input.ciphertext[i];
            for lane in 0..16 {
                if mismatch[lane] != 0 {
                    valid = false;
                }
            }
        }

        valid
    }

    /// Quarter-round on indices a, b, c, d.
    fn quarter_round(&mut self, v: &mut [u32x16; STATE_SIZE], a: usize, b: usize, c: usize, d: usize) {
        // a += b; d ^= a; d <<<= 16
        v[a] = self.add_u32(v[a], v[b]);
        v[d] = self.xor_rotl_u32(v[a], v[d], 16);

        // c += d; b ^= c; b <<<= 12
        v[c] = self.add_u32(v[c], v[d]);
        v[b] = self.xor_rotl_u32(v[c], v[b], 12);

        // a += b; d ^= a; d <<<= 8
        v[a] = self.add_u32(v[a], v[b]);
        v[d] = self.xor_rotl_u32(v[a], v[d], 8);

        // c += d; b ^= c; b <<<= 7
        v[c] = self.add_u32(v[c], v[d]);
        v[b] = self.xor_rotl_u32(v[c], v[b], 7);
    }

    /// Add two u32s, append result bits and carry bits.
    fn add_u32(&mut self, a: u32x16, b: u32x16) -> u32x16 {
        let result = a + b; // Wrapping add for SIMD u32

        // Append result bits
        self.append_u32_bits(result);

        // Compute and append carry bits
        let mut carry = u32x16::splat(0);
        for i in 0..32 {
            let a_bit = (a >> i) & u32x16::splat(1);
            let b_bit = (b >> i) & u32x16::splat(1);
            let sum = a_bit + b_bit + carry;
            carry = sum >> 1;
            self.append_bit(carry);
        }

        result
    }

    /// XOR two u32s and left-rotate by r bits.
    fn xor_rotl_u32(&mut self, a: u32x16, b: u32x16, r: u32) -> u32x16 {
        let xor_result = a ^ b;
        let rotated = (xor_result << r) | (xor_result >> (32 - r));

        // Append result bits
        self.append_u32_bits(rotated);

        rotated
    }
}

/// Generate trace for ChaCha20 stream encryption.
/// Returns (trace, valid) where valid indicates if all ciphertexts match.
pub fn generate_stream_trace(
    log_size: u32,
    inputs: &[ChaChaStreamInput],
) -> (ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>, bool) {
    let mut generator = StreamTraceGenerator::new(log_size);
    let mut all_valid = true;

    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let mut row_gen = generator.gen_row(vec_row);
        if let Some(input) = inputs.get(vec_row) {
            let valid = row_gen.generate(input);
            if !valid {
                all_valid = false;
            }
        } else {
            // Generate with default/zero input
            let default_input = ChaChaStreamInput {
                key: [0; 8],
                nonce: [0; 3],
                counters: u32x16::splat(0),
                plaintext: [u32x16::splat(0); 16],
                ciphertext: [u32x16::splat(0); 16],
            };
            row_gen.generate(&default_input);
        }
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace = generator
        .trace
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect_vec();

    (trace, all_valid)
}

/// Compute ChaCha20 keystream for given inputs (for encryption).
pub fn chacha20_encrypt(key: &[u32; 8], nonce: &[u32; 3], counter: u32, plaintext: &[u32; 16]) -> [u32; 16] {
    // Build initial state
    let mut state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2],
    ];
    let initial = state;

    // 10 double-rounds
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // XOR with plaintext
    let mut ciphertext = [0u32; 16];
    for i in 0..16 {
        ciphertext[i] = state[i] ^ plaintext[i];
    }

    ciphertext
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_encrypt_rfc() {
        // RFC 7539 test vector
        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];
        let counter = 1u32;
        let plaintext = [0u32; 16]; // Zero plaintext = get keystream

        let keystream = chacha20_encrypt(&key, &nonce, counter, &plaintext);

        // Expected keystream from RFC 7539 section 2.3.2
        let expected: [u32; 16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(keystream, expected);
    }

    #[test]
    fn test_stream_trace_with_valid_ciphertext() {
        const LOG_SIZE: u32 = 6;

        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];

        let inputs: Vec<ChaChaStreamInput> = (0..(1 << (LOG_SIZE - LOG_N_LANES)))
            .map(|i| {
                let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane + 1) as u32));

                // Create plaintext
                let plaintext: [u32x16; 16] = std::array::from_fn(|word| {
                    u32x16::from_array(std::array::from_fn(|lane| {
                        ((i * 16 + lane) * 16 + word) as u32
                    }))
                });

                // Compute correct ciphertext for each lane
                let mut ciphertext: [u32x16; 16] = [u32x16::splat(0); 16];
                for lane in 0..16 {
                    let counter = (i * 16 + lane + 1) as u32;
                    let pt: [u32; 16] = std::array::from_fn(|w| plaintext[w][lane]);
                    let ct = chacha20_encrypt(&key, &nonce, counter, &pt);
                    for w in 0..16 {
                        ciphertext[w][lane] = ct[w];
                    }
                }

                ChaChaStreamInput {
                    key,
                    nonce,
                    counters,
                    plaintext,
                    ciphertext,
                }
            })
            .collect();

        let (trace, valid) = generate_stream_trace(LOG_SIZE, &inputs);

        assert!(valid, "Ciphertext verification should pass");
        println!("ChaCha20 stream trace columns: {}", trace.len());
    }

    #[test]
    fn test_stream_trace_with_invalid_ciphertext() {
        const LOG_SIZE: u32 = 4;

        let key = [0u32; 8];
        let nonce = [0u32; 3];

        let input = ChaChaStreamInput {
            key,
            nonce,
            counters: u32x16::splat(1),
            plaintext: [u32x16::splat(0); 16],
            ciphertext: [u32x16::splat(0xDEADBEEF); 16], // Wrong ciphertext
        };

        let (_, valid) = generate_stream_trace(LOG_SIZE, &[input]);

        assert!(!valid, "Should detect invalid ciphertext");
    }
}
