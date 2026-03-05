//! Trace generation for bitwise ChaCha20.

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

/// Input to a bitwise ChaCha block (SIMD-packed: 16 parallel blocks).
#[derive(Copy, Clone, Default)]
pub struct ChaChabitwiseInput {
    pub initial_state: [u32x16; STATE_SIZE],
}

/// Trace generator state.
struct TraceGenerator {
    #[allow(dead_code)]
    log_size: u32,
    trace: Vec<BaseColumn>,
}

impl TraceGenerator {
    fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        let info = chacha_bitwise_info();
        let n_cols = info.mask_offsets[ORIGINAL_TRACE_IDX].len();
        let trace = (0..n_cols)
            .map(|_| unsafe { Col::<SimdBackend, BaseField>::uninitialized(1 << log_size) })
            .collect_vec();
        Self { log_size, trace }
    }

    fn gen_row(&mut self, vec_row: usize) -> TraceGeneratorRow<'_> {
        TraceGeneratorRow {
            gen: self,
            col_index: 0,
            vec_row,
        }
    }
}

/// Row generator for trace generation.
struct TraceGeneratorRow<'a> {
    gen: &'a mut TraceGenerator,
    col_index: usize,
    vec_row: usize,
}

impl TraceGeneratorRow<'_> {
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

    /// Generate trace for a full block.
    fn generate(&mut self, initial: [u32x16; STATE_SIZE]) {
        // Append initial state (16 × 32 = 512 bits)
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

        // Final addition: output[i] = v[i] + initial[i]
        for i in 0..STATE_SIZE {
            v[i] = self.add_u32(v[i], initial[i]);
        }
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
        // carry[i] = 1 if sum at position i overflows
        let mut carry = u32x16::splat(0);
        for i in 0..32 {
            let a_bit = (a >> i) & u32x16::splat(1);
            let b_bit = (b >> i) & u32x16::splat(1);
            let sum = a_bit + b_bit + carry;
            carry = sum >> 1; // carry = sum / 2
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

/// Generate trace for bitwise ChaCha block component.
pub fn generate_trace(
    log_size: u32,
    inputs: &[ChaChabitwiseInput],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let mut generator = TraceGenerator::new(log_size);

    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let mut row_gen = generator.gen_row(vec_row);
        let input = inputs.get(vec_row).copied().unwrap_or_default();
        row_gen.generate(input.initial_state);
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    generator
        .trace
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::simd::Simd;
    use crate::chacha::block::{build_state, chacha20_block};

    #[test]
    fn test_generate_trace_runs() {
        const LOG_SIZE: u32 = 6;

        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];
        let counter: u32 = 1;
        let state = build_state(&key, counter, &nonce);

        let inputs: Vec<ChaChabitwiseInput> = (0..(1 << (LOG_SIZE - LOG_N_LANES)))
            .map(|_| ChaChabitwiseInput {
                initial_state: std::array::from_fn(|j| Simd::splat(state[j])),
            })
            .collect();

        let trace = generate_trace(LOG_SIZE, &inputs);

        println!("Bitwise trace columns: {}", trace.len());
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_bitwise_matches_native() {
        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];
        let counter: u32 = 1;
        let initial_state = build_state(&key, counter, &nonce);

        // Compute native result
        let mut native_state = initial_state;
        chacha20_block(&mut native_state);

        // Expected output from RFC 7539
        let expected: [u32; 16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(native_state, expected, "Native block output should match RFC");
    }
}
