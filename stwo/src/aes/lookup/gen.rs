//! Trace generation for lookup-based AES.

use std::simd::Simd;

use itertools::Itertools;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{PackedM31, LOG_N_LANES};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use num_traits::One;
use stwo_constraint_framework::LogupTraceGenerator;
use stwo_constraint_framework::Relation;

use crate::aes::sbox_table::{SboxAccumulator, SboxElements, SBOX_SIZE};
use crate::aes::{expand_key_128, SBOX};

/// Input for a single AES block (SIMD-packed).
pub struct AESLookupInput {
    /// Plaintext: 16 bytes, each as u8x16 (16 parallel blocks)
    pub plaintext: [Simd<u8, 16>; 16],
    /// Key: 16 bytes for AES-128
    pub key: [Simd<u8, 16>; 16],
}

/// Lookup data collected during trace generation, used for interaction trace.
pub struct AESLookupData {
    /// S-box lookups: columns of (input, output) values for each row.
    /// Each entry is [input_column, output_column].
    pub sbox_lookups: Vec<[BaseColumn; 2]>,
}

/// Trace generator for lookup-based AES.
pub struct TraceGenerator {
    log_size: u32,
    columns: Vec<Vec<PackedM31>>,
    sbox_accum: SboxAccumulator,
    /// S-box lookup data: list of [input_values, output_values] columns.
    sbox_lookups: Vec<[Vec<PackedM31>; 2]>,
}

impl TraceGenerator {
    pub fn new(log_size: u32) -> Self {
        Self {
            log_size,
            columns: Vec::new(),
            sbox_accum: SboxAccumulator::new(),
            sbox_lookups: Vec::new(),
        }
    }

    /// Append a packed value to the current row position.
    fn append(&mut self, col_idx: usize, value: PackedM31) {
        while self.columns.len() <= col_idx {
            self.columns.push(Vec::new());
        }
        self.columns[col_idx].push(value);
    }

    /// Convert SIMD byte values to PackedM31.
    fn byte_to_packed(value: Simd<u8, 16>) -> PackedM31 {
        PackedM31::from_array(std::array::from_fn(|i| {
            BaseField::from_u32_unchecked(value[i] as u32)
        }))
    }

    /// Append a byte column.
    fn append_byte(&mut self, col: &mut usize, value: Simd<u8, 16>) {
        self.append(*col, Self::byte_to_packed(value));
        *col += 1;
    }

    /// Append bit decomposition (8 bits, LSB first) for a byte.
    fn append_bits(&mut self, col: &mut usize, value: Simd<u8, 16>) {
        for bit_idx in 0..8 {
            let bit = (value >> Simd::splat(bit_idx)) & Simd::splat(1);
            self.append(*col, Self::byte_to_packed(bit));
            *col += 1;
        }
    }

    /// Process XOR of two bytes, appending trace columns.
    /// Layout: 8 a_bits, 8 b_bits, 8 c_bits (XOR result bits), result byte
    fn xor_byte_trace(&mut self, col: &mut usize, a: Simd<u8, 16>, b: Simd<u8, 16>) -> Simd<u8, 16> {
        let result = a ^ b;

        // Append bit decomposition of a (8 bits)
        self.append_bits(col, a);
        // Append bit decomposition of b (8 bits)
        self.append_bits(col, b);
        // Append bit decomposition of result (8 bits)
        self.append_bits(col, result);
        // Append result byte
        self.append_byte(col, result);

        result
    }

    /// Process xtime (multiply by 2), appending trace columns.
    /// Layout: 8 a_bits, 8 r_bits (result bits), result byte
    fn xtime_trace(&mut self, col: &mut usize, a: Simd<u8, 16>) -> Simd<u8, 16> {
        let result = Self::xtime_simd(a);

        // Append bit decomposition of a (8 bits)
        self.append_bits(col, a);
        // Append bit decomposition of result (8 bits)
        self.append_bits(col, result);
        // Append result byte
        self.append_byte(col, result);

        result
    }

    /// SIMD xtime operation.
    fn xtime_simd(a: Simd<u8, 16>) -> Simd<u8, 16> {
        let shifted = a << Simd::splat(1);
        let mask = a >> Simd::splat(7);
        let reduction = mask * Simd::splat(0x1b);
        shifted ^ reduction
    }

    /// Apply S-box and record lookup.
    fn sbox_trace(&mut self, col: &mut usize, input: Simd<u8, 16>, lookup_idx: usize) -> Simd<u8, 16> {
        let output = Simd::from_array(std::array::from_fn(|i| {
            let inp = input[i];
            self.sbox_accum.add_input(inp);
            SBOX[inp as usize]
        }));

        // Record the S-box lookup values
        let input_packed = Self::byte_to_packed(input);
        let output_packed = Self::byte_to_packed(output);

        // Ensure we have storage for this lookup index
        while self.sbox_lookups.len() <= lookup_idx {
            self.sbox_lookups.push([Vec::new(), Vec::new()]);
        }
        self.sbox_lookups[lookup_idx][0].push(input_packed);
        self.sbox_lookups[lookup_idx][1].push(output_packed);

        // Append S-box output to trace
        self.append_byte(col, output);

        output
    }

    /// GF multiply by 3: 3*a = 2*a XOR a
    fn gf_mul3_trace(&mut self, col: &mut usize, a: Simd<u8, 16>) -> Simd<u8, 16> {
        let doubled = self.xtime_trace(col, a);
        self.xor_byte_trace(col, doubled, a)
    }

    /// Process a single AES-128 block and record trace.
    pub fn process_block(&mut self, input: &AESLookupInput) {
        let mut col = 0;

        // Expand key to round keys
        let round_keys = self.expand_keys_simd(&input.key);

        // Append plaintext
        for i in 0..16 {
            self.append_byte(&mut col, input.plaintext[i]);
        }

        // Append round keys
        for rk in &round_keys {
            for i in 0..16 {
                self.append_byte(&mut col, rk[i]);
            }
        }

        // Initial AddRoundKey
        let mut state: [Simd<u8, 16>; 16] = std::array::from_fn(|i| {
            self.xor_byte_trace(&mut col, input.plaintext[i], round_keys[0][i])
        });

        // S-box lookup index counter (160 total: 10 rounds * 16 bytes)
        let mut sbox_idx = 0usize;

        // 9 main rounds
        for round in 1..10 {
            // SubBytes
            state = std::array::from_fn(|i| {
                let result = self.sbox_trace(&mut col, state[i], sbox_idx);
                sbox_idx += 1;
                result
            });

            // ShiftRows (just reorder, no trace)
            state = [
                state[0], state[5], state[10], state[15],
                state[4], state[9], state[14], state[3],
                state[8], state[13], state[2], state[7],
                state[12], state[1], state[6], state[11],
            ];

            // MixColumns
            let mut new_state = [Simd::splat(0u8); 16];
            for c in 0..4 {
                let i = c * 4;
                let s0 = state[i];
                let s1 = state[i + 1];
                let s2 = state[i + 2];
                let s3 = state[i + 3];

                // r0 = 2*s0 + 3*s1 + s2 + s3
                let t0 = self.xtime_trace(&mut col, s0);
                let t1 = self.gf_mul3_trace(&mut col, s1);
                let t2 = self.xor_byte_trace(&mut col, t0, t1);
                let t3 = self.xor_byte_trace(&mut col, t2, s2);
                new_state[i] = self.xor_byte_trace(&mut col, t3, s3);

                // r1 = s0 + 2*s1 + 3*s2 + s3
                let t0 = self.xtime_trace(&mut col, s1);
                let t1 = self.gf_mul3_trace(&mut col, s2);
                let t2 = self.xor_byte_trace(&mut col, s0, t0);
                let t3 = self.xor_byte_trace(&mut col, t2, t1);
                new_state[i + 1] = self.xor_byte_trace(&mut col, t3, s3);

                // r2 = s0 + s1 + 2*s2 + 3*s3
                let t0 = self.xtime_trace(&mut col, s2);
                let t1 = self.gf_mul3_trace(&mut col, s3);
                let t2 = self.xor_byte_trace(&mut col, s0, s1);
                let t3 = self.xor_byte_trace(&mut col, t2, t0);
                new_state[i + 2] = self.xor_byte_trace(&mut col, t3, t1);

                // r3 = 3*s0 + s1 + s2 + 2*s3
                let t0 = self.gf_mul3_trace(&mut col, s0);
                let t1 = self.xtime_trace(&mut col, s3);
                let t2 = self.xor_byte_trace(&mut col, t0, s1);
                let t3 = self.xor_byte_trace(&mut col, t2, s2);
                new_state[i + 3] = self.xor_byte_trace(&mut col, t3, t1);
            }
            state = new_state;

            // AddRoundKey
            state = std::array::from_fn(|i| {
                self.xor_byte_trace(&mut col, state[i], round_keys[round][i])
            });
        }

        // Final round (no MixColumns)
        state = std::array::from_fn(|i| {
            let result = self.sbox_trace(&mut col, state[i], sbox_idx);
            sbox_idx += 1;
            result
        });
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ];
        let _output: [Simd<u8, 16>; 16] = std::array::from_fn(|i| {
            self.xor_byte_trace(&mut col, state[i], round_keys[10][i])
        });
    }

    /// Expand key to round keys.
    fn expand_keys_simd(&self, key: &[Simd<u8, 16>; 16]) -> [[Simd<u8, 16>; 16]; 11] {
        let mut result: [[Simd<u8, 16>; 16]; 11] = std::array::from_fn(|_| {
            std::array::from_fn(|_| Simd::splat(0u8))
        });

        for lane in 0..16 {
            let key_bytes: [u8; 16] = std::array::from_fn(|i| key[i][lane]);
            let expanded = expand_key_128(&key_bytes);

            for round in 0..11 {
                for byte_idx in 0..16 {
                    let mut arr = result[round][byte_idx].to_array();
                    arr[lane] = expanded[round * 16 + byte_idx];
                    result[round][byte_idx] = Simd::from_array(arr);
                }
            }
        }

        result
    }

    /// Convert trace to CircleEvaluations.
    pub fn into_trace(
        self,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SboxAccumulator,
        AESLookupData,
    ) {
        let domain = CanonicCoset::new(self.log_size).circle_domain();

        let trace = self
            .columns
            .into_iter()
            .map(|col| {
                let mut base_col = BaseColumn::zeros(1 << self.log_size);
                for (i, val) in col.into_iter().enumerate() {
                    base_col.data[i] = val;
                }
                CircleEvaluation::new(domain, base_col)
            })
            .collect();

        // Convert S-box lookups to BaseColumns
        let sbox_lookups: Vec<[BaseColumn; 2]> = self
            .sbox_lookups
            .into_iter()
            .map(|[inputs, outputs]| {
                let mut input_col = BaseColumn::zeros(1 << self.log_size);
                let mut output_col = BaseColumn::zeros(1 << self.log_size);
                for (i, (inp, out)) in inputs.into_iter().zip(outputs.into_iter()).enumerate() {
                    input_col.data[i] = inp;
                    output_col.data[i] = out;
                }
                [input_col, output_col]
            })
            .collect();

        (trace, self.sbox_accum, AESLookupData { sbox_lookups })
    }
}

/// Generate trace for lookup-based AES.
pub fn generate_trace(
    log_size: u32,
    inputs: &[AESLookupInput],
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SboxAccumulator,
    AESLookupData,
) {
    assert!(
        log_size >= LOG_N_LANES,
        "log_size ({}) must be >= LOG_N_LANES ({})",
        log_size,
        LOG_N_LANES
    );
    let n_rows = 1usize << (log_size - LOG_N_LANES);
    assert!(
        inputs.len() <= n_rows,
        "inputs length ({}) exceeds trace row capacity ({})",
        inputs.len(),
        n_rows
    );

    let mut gen = TraceGenerator::new(log_size);

    for input in inputs {
        gen.process_block(input);
    }

    gen.into_trace()
}

/// Generate interaction trace for AES S-box lookups.
/// This creates LogUp fractions for both the table side (negative multiplicity)
/// and the main trace side (positive lookups).
pub fn generate_sbox_interaction_trace(
    log_size: u32,
    _sbox_accum: &SboxAccumulator,
    lookup_data: &AESLookupData,
    sbox_elements: &SboxElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    assert!(
        log_size >= LOG_N_LANES,
        "log_size ({}) must be >= LOG_N_LANES ({})",
        log_size,
        LOG_N_LANES
    );
    let vec_rows = 1 << (log_size - LOG_N_LANES);
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    // Process S-box lookups from main trace in pairs
    let mut lookup_iter = lookup_data.sbox_lookups.iter().enumerate().array_chunks::<2>();

    for [(_idx0, lookup0), (_idx1, lookup1)] in &mut lookup_iter {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..vec_rows {
            // Get (input, output) pairs from both lookups
            let input0 = lookup0[0].data[vec_row];
            let output0 = lookup0[1].data[vec_row];
            let input1 = lookup1[0].data[vec_row];
            let output1 = lookup1[1].data[vec_row];

            // Compute denominators: z + alpha * input + alpha^2 * output
            let p0: PackedSecureField = sbox_elements.combine(&[input0, output0]);
            let p1: PackedSecureField = sbox_elements.combine(&[input1, output1]);

            // Each lookup contributes +1 to numerator (consuming from table)
            // Batched: (1/p0 + 1/p1) = (p0 + p1) / (p0 * p1)
            col_gen.write_frac(vec_row, p0 + p1, p0 * p1);
        }
        col_gen.finalize_col();
    }

    // Handle remaining odd lookup if any
    if let Some(remainder) = lookup_iter.into_remainder() {
        if let Some((_, lookup)) = remainder.collect_vec().pop() {
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..vec_rows {
                let input = lookup[0].data[vec_row];
                let output = lookup[1].data[vec_row];
                let p: PackedSecureField = sbox_elements.combine(&[input, output]);
                col_gen.write_frac(vec_row, PackedSecureField::broadcast(SecureField::one()), p);
            }
            col_gen.finalize_col();
        }
    }

    logup_gen.finalize_last()
}

/// Generate interaction trace for the S-box table side.
/// This contributes negative multiplicities for each table entry.
pub fn generate_sbox_table_interaction_trace(
    sbox_accum: &SboxAccumulator,
    sbox_elements: &SboxElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    use crate::aes::sbox_table::SBOX_BITS;
    use crate::aes::SBOX;

    let mut logup_gen = LogupTraceGenerator::new(SBOX_BITS);
    let mut col_gen = logup_gen.new_col();

    // S-box table has 256 entries, SIMD packed into 256/16 = 16 vec_rows
    for vec_row in 0..(SBOX_SIZE >> LOG_N_LANES) {
        let base_idx = vec_row << LOG_N_LANES;

        // Build packed values for input, output, and multiplicity
        let inputs: [BaseField; 16] = std::array::from_fn(|lane| {
            BaseField::from_u32_unchecked((base_idx + lane) as u32)
        });
        let outputs: [BaseField; 16] = std::array::from_fn(|lane| {
            BaseField::from_u32_unchecked(SBOX[base_idx + lane] as u32)
        });
        let mults: [BaseField; 16] = std::array::from_fn(|lane| {
            BaseField::from_u32_unchecked(sbox_accum.mults[base_idx + lane])
        });

        let input = PackedM31::from_array(inputs);
        let output = PackedM31::from_array(outputs);
        let mult = PackedM31::from_array(mults);

        let p: PackedSecureField = sbox_elements.combine(&[input, output]);

        // Negative multiplicity (table yields entries)
        col_gen.write_frac(vec_row, -PackedSecureField::from(mult), p);
    }
    col_gen.finalize_col();

    logup_gen.finalize_last()
}
