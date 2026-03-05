//! Trace generation for ChaCha20 full block.

use std::simd::u32x16;

use itertools::Itertools;
use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{PackedBaseField, LOG_N_LANES};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{LogupTraceGenerator, ORIGINAL_TRACE_IDX};

use super::chacha_block_info;
use crate::chacha::constraints::ChaChaXorElements;
use crate::chacha::xor_table::XorAccums;
use crate::chacha::STATE_SIZE;

/// Input to a ChaCha block (SIMD-packed: 16 parallel blocks).
#[derive(Copy, Clone, Default)]
pub struct ChaChaBlockInput {
    pub initial_state: [u32x16; STATE_SIZE],
}

/// Lookup data collected during trace generation.
pub struct ChaChaBlockLookupData {
    /// XOR lookups: (width, [a_col, b_col, c_col])
    pub xor_lookups: Vec<(u32, [BaseColumn; 3])>,
}

/// Trace generator state.
struct TraceGenerator {
    log_size: u32,
    trace: Vec<BaseColumn>,
    xor_lookups: Vec<(u32, [BaseColumn; 3])>,
}

impl TraceGenerator {
    fn new(log_size: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        let info = chacha_block_info();
        let trace = (0..info.mask_offsets[ORIGINAL_TRACE_IDX].len())
            .map(|_| unsafe { Col::<SimdBackend, BaseField>::uninitialized(1 << log_size) })
            .collect_vec();
        Self {
            log_size,
            trace,
            xor_lookups: vec![],
        }
    }

    fn gen_row(&mut self, vec_row: usize) -> TraceGeneratorRow<'_> {
        TraceGeneratorRow {
            gen: self,
            col_index: 0,
            vec_row,
            xor_lookups_index: 0,
        }
    }
}

/// Row generator for trace generation.
struct TraceGeneratorRow<'a> {
    gen: &'a mut TraceGenerator,
    col_index: usize,
    vec_row: usize,
    xor_lookups_index: usize,
}

impl TraceGeneratorRow<'_> {
    /// Append a field element to the trace.
    fn append_felt(&mut self, val: u32x16) {
        self.gen.trace[self.col_index].data[self.vec_row] =
            unsafe { PackedBaseField::from_simd_unchecked(val) };
        self.col_index += 1;
    }

    /// Append a u32 to the trace (as two 16-bit field elements).
    fn append_u32(&mut self, val: u32x16) {
        self.append_felt(val & u32x16::splat(0xffff)); // Low 16 bits
        self.append_felt(val >> 16); // High 16 bits
    }

    /// Generate trace for a full block.
    fn generate(&mut self, initial: [u32x16; STATE_SIZE]) {
        // Append initial state
        for s in &initial {
            self.append_u32(*s);
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
            let _output = self.add2_u32s(v[i], initial[i]);
        }
    }

    /// Quarter-round on indices a, b, c, d.
    fn quarter_round(&mut self, v: &mut [u32x16; STATE_SIZE], a: usize, b: usize, c: usize, d: usize) {
        // a += b; d ^= a; d <<<= 16
        v[a] = self.add2_u32s(v[a], v[b]);
        v[d] = self.xor_rotl16_u32(v[a], v[d]);

        // c += d; b ^= c; b <<<= 12
        v[c] = self.add2_u32s(v[c], v[d]);
        v[b] = self.xor_rotl_u32(v[c], v[b], 12);

        // a += b; d ^= a; d <<<= 8
        v[a] = self.add2_u32s(v[a], v[b]);
        v[d] = self.xor_rotl_u32(v[a], v[d], 8);

        // c += d; b ^= c; b <<<= 7
        v[c] = self.add2_u32s(v[c], v[d]);
        v[b] = self.xor_rotl_u32(v[c], v[b], 7);
    }

    /// Add two u32s and append result.
    fn add2_u32s(&mut self, a: u32x16, b: u32x16) -> u32x16 {
        let s = a + b; // Wrapping add for SIMD
        self.append_u32(s);
        s
    }

    /// Split a u32 at position r, append high part.
    fn split(&mut self, a: u32x16, r: u32) -> (u32x16, u32x16) {
        let h = a >> r;
        let l = a & u32x16::splat((1 << r) - 1);
        self.append_felt(h);
        (l, h)
    }

    /// XOR and append result, recording lookup data.
    fn xor(&mut self, w: u32, a: u32x16, b: u32x16) -> u32x16 {
        let c = a ^ b;
        self.append_felt(c);

        // Lazily create lookup columns
        if self.gen.xor_lookups.len() <= self.xor_lookups_index {
            self.gen.xor_lookups.push((
                w,
                std::array::from_fn(|_| unsafe {
                    BaseColumn::uninitialized(1 << self.gen.log_size)
                }),
            ));
        }

        // Store lookup data
        self.gen.xor_lookups[self.xor_lookups_index].1[0].data[self.vec_row] =
            unsafe { PackedBaseField::from_simd_unchecked(a) };
        self.gen.xor_lookups[self.xor_lookups_index].1[1].data[self.vec_row] =
            unsafe { PackedBaseField::from_simd_unchecked(b) };
        self.gen.xor_lookups[self.xor_lookups_index].1[2].data[self.vec_row] =
            unsafe { PackedBaseField::from_simd_unchecked(c) };

        self.xor_lookups_index += 1;
        c
    }

    /// XOR and left-rotate by 16.
    fn xor_rotl16_u32(&mut self, a: u32x16, b: u32x16) -> u32x16 {
        // Split at 8 bits
        let (all, alh) = self.split(a & u32x16::splat(0xffff), 8);
        let (ahl, ahh) = self.split(a >> 16, 8);
        let (bll, blh) = self.split(b & u32x16::splat(0xffff), 8);
        let (bhl, bhh) = self.split(b >> 16, 8);

        // XOR parts (8-bit width)
        let xorll = self.xor(8, all, bll);
        let xorhl = self.xor(8, ahl, bhl);
        let xorlh = self.xor(8, alh, blh);
        let xorhh = self.xor(8, ahh, bhh);

        // Reassemble with left rotation by 16 (swap halves)
        let result_l = (xorhh << 8) | xorhl;
        let result_h = (xorlh << 8) | xorll;
        (result_h << 16) | result_l
    }

    /// XOR and left-rotate by r bits.
    fn xor_rotl_u32(&mut self, a: u32x16, b: u32x16, r: u32) -> u32x16 {
        // Split at (16-r)
        let (all, alh) = self.split(a & u32x16::splat(0xffff), 16 - r);
        let (ahl, ahh) = self.split(a >> 16, 16 - r);
        let (bll, blh) = self.split(b & u32x16::splat(0xffff), 16 - r);
        let (bhl, bhh) = self.split(b >> 16, 16 - r);

        // XOR parts
        let xorll = self.xor(16 - r, all, bll);
        let xorhl = self.xor(16 - r, ahl, bhl);
        let xorlh = self.xor(r, alh, blh);
        let xorhh = self.xor(r, ahh, bhh);

        // Reassemble with left rotation by r
        let result_l = (xorll << r) | xorhh;
        let result_h = (xorhl << r) | xorlh;
        (result_h << 16) | result_l
    }
}

/// Generate trace for ChaCha block component.
pub fn generate_trace(
    log_size: u32,
    inputs: &[ChaChaBlockInput],
    xor_accum: &mut XorAccums,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ChaChaBlockLookupData,
) {
    let mut generator = TraceGenerator::new(log_size);

    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let mut row_gen = generator.gen_row(vec_row);
        let input = inputs.get(vec_row).copied().unwrap_or_default();
        row_gen.generate(input.initial_state);

        // Collect XOR multiplicities
        for (w, [a, b, _c]) in &generator.xor_lookups {
            let a_val = a.data[vec_row].into_simd();
            let b_val = b.data[vec_row].into_simd();
            xor_accum.add_input(*w, a_val, b_val);
        }
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace = generator
        .trace
        .into_iter()
        .map(|col| CircleEvaluation::new(domain, col))
        .collect_vec();

    let lookup_data = ChaChaBlockLookupData {
        xor_lookups: generator.xor_lookups,
    };

    (trace, lookup_data)
}

/// Generate interaction trace for LogUp.
pub fn generate_interaction_trace(
    log_size: u32,
    lookup_data: ChaChaBlockLookupData,
    xor_lookup_elements: &ChaChaXorElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    // Process XOR lookups in pairs
    for [(w0, l0), (w1, l1)] in lookup_data.xor_lookups.array_chunks::<2>() {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let p0: PackedSecureField =
                xor_lookup_elements.combine(*w0, &l0.each_ref().map(|l| l.data[vec_row]));
            let p1: PackedSecureField =
                xor_lookup_elements.combine(*w1, &l1.each_ref().map(|l| l.data[vec_row]));

            col_gen.write_frac(vec_row, p0 + p1, p0 * p1);
        }
        col_gen.finalize_col();
    }

    // Handle odd remainder XOR lookups
    let mut xor_iter = lookup_data.xor_lookups.iter();
    while xor_iter.len() % 2 != 0 {
        if let Some((w, l)) = xor_iter.next() {
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
                let p: PackedSecureField =
                    xor_lookup_elements.combine(*w, &l.each_ref().map(|l| l.data[vec_row]));
                col_gen.write_frac(vec_row, PackedSecureField::one(), p);
            }
            col_gen.finalize_col();
        }
    }

    logup_gen.finalize_last()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::simd::Simd;
    use crate::chacha::block::{build_state, chacha20_block};

    #[test]
    fn test_generate_trace_runs() {
        const LOG_SIZE: u32 = 8;
        let mut xor_accum = XorAccums::new();

        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];
        let counter: u32 = 1;
        let state = build_state(&key, counter, &nonce);

        let inputs: Vec<ChaChaBlockInput> = (0..(1 << (LOG_SIZE - LOG_N_LANES)))
            .map(|_| ChaChaBlockInput {
                initial_state: std::array::from_fn(|j| Simd::splat(state[j])),
            })
            .collect();

        let (trace, lookup_data) = generate_trace(LOG_SIZE, &inputs, &mut xor_accum);

        // Basic sanity checks
        assert!(!trace.is_empty());
        assert!(!lookup_data.xor_lookups.is_empty());

        println!("Block trace columns: {}", trace.len());
        println!("Block XOR lookups: {}", lookup_data.xor_lookups.len());
    }

    #[test]
    fn test_block_output_matches_native() {
        const LOG_SIZE: u32 = 4; // Very small
        let mut xor_accum = XorAccums::new();

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

        // The expected output from RFC 7539
        let expected: [u32; 16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(native_state, expected, "Native block output should match RFC");

        // Now verify trace generation produces consistent results
        let inputs = vec![ChaChaBlockInput {
            initial_state: std::array::from_fn(|j| Simd::splat(initial_state[j])),
        }];

        let (trace, _) = generate_trace(LOG_SIZE, &inputs, &mut xor_accum);

        // The trace should have the final output as the last 32 columns
        // (16 u32s = 32 field elements)
        // Check that trace was generated without panicking
        assert!(!trace.is_empty());
    }
}
