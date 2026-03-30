//! Trace generation for AES-CTR mode (supports both AES-128 and AES-256).

use std::simd::Simd;

use itertools::Itertools;
use num_traits::One;
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
use stwo_constraint_framework::LogupTraceGenerator;
use stwo_constraint_framework::Relation;

use crate::aes::sbox_table::{SboxAccumulator, SboxElements};
use crate::aes::{expand_key_128, expand_key_256, AesKeySize, SBOX, aes128_ctr_block, aes256_ctr_block};

/// Input for AES-CTR block (SIMD-packed).
#[derive(Clone)]
pub struct AESCtrInput {
    /// Nonce (12 bytes), same across all lanes - PUBLIC
    pub nonce: [u8; 12],
    /// Counter values for each of 16 parallel blocks - PUBLIC
    pub counters: Simd<u32, 16>,
    /// Plaintext: 16 bytes, each as u8x16 (16 parallel blocks) - PUBLIC
    pub plaintext: [Simd<u8, 16>; 16],
    /// Ciphertext: 16 bytes, each as u8x16 (16 parallel blocks) - PUBLIC
    pub ciphertext: [Simd<u8, 16>; 16],
}

/// Lookup data for interaction trace.
pub struct AESCtrLookupData {
    /// S-box lookups: [input_column, output_column] for each lookup position.
    pub sbox_lookups: Vec<[BaseColumn; 2]>,
}

/// Trace generator for AES-CTR.
pub struct CtrTraceGenerator {
    log_size: u32,
    key_size: AesKeySize,
    columns: Vec<Vec<PackedM31>>,
    sbox_accum: SboxAccumulator,
    sbox_lookups: Vec<[Vec<PackedM31>; 2]>,
}

impl CtrTraceGenerator {
    pub fn new(log_size: u32, key_size: AesKeySize) -> Self {
        Self {
            log_size,
            key_size,
            columns: Vec::new(),
            sbox_accum: SboxAccumulator::new(),
            sbox_lookups: Vec::new(),
        }
    }

    fn append(&mut self, col_idx: usize, value: PackedM31) {
        while self.columns.len() <= col_idx {
            self.columns.push(Vec::new());
        }
        self.columns[col_idx].push(value);
    }

    fn byte_to_packed(value: Simd<u8, 16>) -> PackedM31 {
        PackedM31::from_array(std::array::from_fn(|i| {
            BaseField::from_u32_unchecked(value[i] as u32)
        }))
    }

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

    /// Process XOR of two bytes with bit decomposition.
    /// Layout: 8 a_bits, 8 b_bits, 8 c_bits (result bits), result byte
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

    /// Process xtime with bit decomposition.
    /// Layout: 8 a_bits, 8 r_bits (result bits), result byte
    fn xtime_trace(&mut self, col: &mut usize, a: Simd<u8, 16>) -> Simd<u8, 16> {
        let shifted = a << Simd::splat(1);
        let mask = a >> Simd::splat(7);
        let reduction = mask * Simd::splat(0x1b);
        let result = shifted ^ reduction;

        // Append bit decomposition of a (8 bits)
        self.append_bits(col, a);
        // Append bit decomposition of result (8 bits)
        self.append_bits(col, result);
        // Append result byte
        self.append_byte(col, result);

        result
    }

    fn sbox_trace(&mut self, col: &mut usize, input: Simd<u8, 16>, lookup_idx: usize) -> Simd<u8, 16> {
        let output = Simd::from_array(std::array::from_fn(|i| {
            let inp = input[i];
            self.sbox_accum.add_input(inp);
            SBOX[inp as usize]
        }));

        let input_packed = Self::byte_to_packed(input);
        let output_packed = Self::byte_to_packed(output);

        while self.sbox_lookups.len() <= lookup_idx {
            self.sbox_lookups.push([Vec::new(), Vec::new()]);
        }
        self.sbox_lookups[lookup_idx][0].push(input_packed);
        self.sbox_lookups[lookup_idx][1].push(output_packed);

        self.append_byte(col, output);

        output
    }

    fn gf_mul3_trace(&mut self, col: &mut usize, a: Simd<u8, 16>) -> Simd<u8, 16> {
        let doubled = self.xtime_trace(col, a);
        self.xor_byte_trace(col, doubled, a)
    }

    fn mix_columns_trace(
        &mut self,
        col: &mut usize,
        state: [Simd<u8, 16>; 16],
    ) -> [Simd<u8, 16>; 16] {
        let mut new_state = [Simd::splat(0u8); 16];

        for c in 0..4 {
            let i = c * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            // r0 = 2*s0 + 3*s1 + s2 + s3
            let t0 = self.xtime_trace(col, s0);
            let t1 = self.gf_mul3_trace(col, s1);
            let t2 = self.xor_byte_trace(col, t0, t1);
            let t3 = self.xor_byte_trace(col, t2, s2);
            new_state[i] = self.xor_byte_trace(col, t3, s3);

            // r1 = s0 + 2*s1 + 3*s2 + s3
            let t0 = self.xtime_trace(col, s1);
            let t1 = self.gf_mul3_trace(col, s2);
            let t2 = self.xor_byte_trace(col, s0, t0);
            let t3 = self.xor_byte_trace(col, t2, t1);
            new_state[i + 1] = self.xor_byte_trace(col, t3, s3);

            // r2 = s0 + s1 + 2*s2 + 3*s3
            let t0 = self.xtime_trace(col, s2);
            let t1 = self.gf_mul3_trace(col, s3);
            let t2 = self.xor_byte_trace(col, s0, s1);
            let t3 = self.xor_byte_trace(col, t2, t0);
            new_state[i + 2] = self.xor_byte_trace(col, t3, t1);

            // r3 = 3*s0 + s1 + s2 + 2*s3
            let t0 = self.gf_mul3_trace(col, s0);
            let t1 = self.xtime_trace(col, s3);
            let t2 = self.xor_byte_trace(col, t0, s1);
            let t3 = self.xor_byte_trace(col, t2, s2);
            new_state[i + 3] = self.xor_byte_trace(col, t3, t1);
        }

        new_state
    }

    /// Process a CTR block. Returns true if computed ciphertext matches provided ciphertext.
    pub fn process_ctr_block(&mut self, input: &AESCtrInput, round_keys: &[[Simd<u8, 16>; 16]]) -> bool {
        let mut col = 0;
        let num_rounds = self.key_size.num_rounds();

        // Append nonce (12 bytes)
        for i in 0..12 {
            self.append_byte(&mut col, Simd::splat(input.nonce[i]));
        }

        // Append counter (4 bytes, big-endian)
        let counter_bytes: [Simd<u8, 16>; 4] = std::array::from_fn(|i| {
            let shift = (3 - i) * 8;
            Simd::from_array(std::array::from_fn(|lane| {
                ((input.counters[lane] >> shift) & 0xFF) as u8
            }))
        });
        for i in 0..4 {
            self.append_byte(&mut col, counter_bytes[i]);
        }

        // Append round keys
        for rk in round_keys.iter() {
            for i in 0..16 {
                self.append_byte(&mut col, rk[i]);
            }
        }

        // Append plaintext - PUBLIC INPUT
        for i in 0..16 {
            self.append_byte(&mut col, input.plaintext[i]);
        }

        // Append ciphertext - PUBLIC INPUT (for verification)
        for i in 0..16 {
            self.append_byte(&mut col, input.ciphertext[i]);
        }

        // Build counter block: nonce (12 bytes) || counter (4 bytes)
        let counter_block: [Simd<u8, 16>; 16] = std::array::from_fn(|i| {
            if i < 12 {
                Simd::splat(input.nonce[i])
            } else {
                counter_bytes[i - 12]
            }
        });

        // Initial AddRoundKey
        let mut state: [Simd<u8, 16>; 16] = std::array::from_fn(|i| {
            self.xor_byte_trace(&mut col, counter_block[i], round_keys[0][i])
        });

        // S-box lookup index
        let mut sbox_idx = 0usize;

        // Main rounds
        for round in 1..num_rounds {
            // SubBytes
            state = std::array::from_fn(|i| {
                let result = self.sbox_trace(&mut col, state[i], sbox_idx);
                sbox_idx += 1;
                result
            });

            // ShiftRows
            state = [
                state[0], state[5], state[10], state[15],
                state[4], state[9], state[14], state[3],
                state[8], state[13], state[2], state[7],
                state[12], state[1], state[6], state[11],
            ];

            // MixColumns
            state = self.mix_columns_trace(&mut col, state);

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
        let keystream: [Simd<u8, 16>; 16] = std::array::from_fn(|i| {
            self.xor_byte_trace(&mut col, state[i], round_keys[num_rounds][i])
        });

        // XOR keystream with plaintext to get computed ciphertext
        let computed_ct: [Simd<u8, 16>; 16] = std::array::from_fn(|i| {
            self.xor_byte_trace(&mut col, keystream[i], input.plaintext[i])
        });

        // Verify computed ciphertext matches provided ciphertext
        let mut valid = true;
        for i in 0..16 {
            let mismatch = computed_ct[i] ^ input.ciphertext[i];
            for lane in 0..16 {
                if mismatch[lane] != 0 {
                    valid = false;
                }
            }
        }
        valid
    }

    /// Convert trace to CircleEvaluations.
    pub fn into_trace(
        self,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SboxAccumulator,
        AESCtrLookupData,
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

        (trace, self.sbox_accum, AESCtrLookupData { sbox_lookups })
    }
}

/// Expand key to SIMD round keys.
fn expand_keys_simd_128(key: &[u8; 16]) -> [[Simd<u8, 16>; 16]; 11] {
    let expanded = expand_key_128(key);
    let mut result: [[Simd<u8, 16>; 16]; 11] = std::array::from_fn(|_| {
        std::array::from_fn(|_| Simd::splat(0u8))
    });

    for round in 0..11 {
        for byte_idx in 0..16 {
            result[round][byte_idx] = Simd::splat(expanded[round * 16 + byte_idx]);
        }
    }

    result
}

/// Expand key to SIMD round keys for AES-256.
fn expand_keys_simd_256(key: &[u8; 32]) -> [[Simd<u8, 16>; 16]; 15] {
    let expanded = expand_key_256(key);
    let mut result: [[Simd<u8, 16>; 16]; 15] = std::array::from_fn(|_| {
        std::array::from_fn(|_| Simd::splat(0u8))
    });

    for round in 0..15 {
        for byte_idx in 0..16 {
            result[round][byte_idx] = Simd::splat(expanded[round * 16 + byte_idx]);
        }
    }

    result
}

/// Generate trace for AES-128-CTR with provided inputs.
/// Returns (trace, sbox_accum, lookup_data, valid) where valid indicates if all ciphertexts match.
pub fn generate_aes128_ctr_trace_with_inputs(
    log_size: u32,
    key: &[u8; 16],
    inputs: &[AESCtrInput],
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SboxAccumulator,
    AESCtrLookupData,
    bool,
) {
    let mut gen = CtrTraceGenerator::new(log_size, AesKeySize::Aes128);
    let round_keys = expand_keys_simd_128(key);
    let round_keys_slice: Vec<[Simd<u8, 16>; 16]> = round_keys.to_vec();
    let mut all_valid = true;

    let num_rows = 1 << (log_size - LOG_N_LANES);
    assert!(
        inputs.len() <= num_rows,
        "inputs length ({}) exceeds trace row capacity ({})",
        inputs.len(),
        num_rows
    );
    // Pre-compute keystream for default padding rows (nonce=0, plaintext=0)
    // so that ciphertext = keystream and validation passes
    let default_keystreams: [[u8; 16]; 16] = std::array::from_fn(|lane| {
        aes128_ctr_block(key, &[0; 12], lane as u32, &[0; 16])
    });

    for row in 0..num_rows {
        if let Some(input) = inputs.get(row) {
            let valid = gen.process_ctr_block(input, &round_keys_slice);
            if !valid {
                all_valid = false;
            }
        } else {
            // Use default input for padding with correct ciphertext = keystream
            let default_ciphertext: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
                Simd::from_array(std::array::from_fn(|lane| {
                    default_keystreams[lane][byte_idx]
                }))
            });
            let default_input = AESCtrInput {
                nonce: [0; 12],
                counters: Simd::from_array(std::array::from_fn(|lane| lane as u32)),
                plaintext: [Simd::splat(0); 16],
                ciphertext: default_ciphertext,
            };
            gen.process_ctr_block(&default_input, &round_keys_slice);
        }
    }

    let (trace, sbox_accum, lookup_data) = gen.into_trace();
    (trace, sbox_accum, lookup_data, all_valid)
}

/// Generate trace for AES-128-CTR with test data.
/// Note: num_blocks must be a multiple of 16 (SIMD lane count).
pub fn generate_aes128_ctr_trace(
    log_size: u32,
    key: &[u8; 16],
    nonce: &[u8; 12],
    num_blocks: usize,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SboxAccumulator,
    AESCtrLookupData,
) {
    assert!(
        num_blocks % 16 == 0,
        "num_blocks ({}) must be a multiple of 16 (SIMD lane count)",
        num_blocks
    );
    let mut gen = CtrTraceGenerator::new(log_size, AesKeySize::Aes128);
    let round_keys = expand_keys_simd_128(key);
    let round_keys_slice: Vec<[Simd<u8, 16>; 16]> = round_keys.to_vec();

    for batch in 0..(num_blocks / 16) {
        let base_counter = (batch * 16 + 1) as u32;
        let counters = Simd::from_array(std::array::from_fn(|lane| base_counter + lane as u32));

        // Create plaintext (for testing, use pattern)
        let plaintext: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                ((batch * 256 + lane * 16 + byte_idx) & 0xFF) as u8
            }))
        });

        // Compute correct ciphertext
        let ciphertext = compute_aes128_ctr_ciphertext(key, nonce, &counters, &plaintext);

        let input = AESCtrInput {
            nonce: *nonce,
            counters,
            plaintext,
            ciphertext,
        };

        gen.process_ctr_block(&input, &round_keys_slice);
    }

    gen.into_trace()
}

/// Generate trace for AES-256-CTR with provided inputs.
/// Returns (trace, sbox_accum, lookup_data, valid) where valid indicates if all ciphertexts match.
pub fn generate_aes256_ctr_trace_with_inputs(
    log_size: u32,
    key: &[u8; 32],
    inputs: &[AESCtrInput],
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SboxAccumulator,
    AESCtrLookupData,
    bool,
) {
    let mut gen = CtrTraceGenerator::new(log_size, AesKeySize::Aes256);
    let round_keys = expand_keys_simd_256(key);
    let round_keys_slice: Vec<[Simd<u8, 16>; 16]> = round_keys.to_vec();
    let mut all_valid = true;

    let num_rows = 1 << (log_size - LOG_N_LANES);
    assert!(
        inputs.len() <= num_rows,
        "inputs length ({}) exceeds trace row capacity ({})",
        inputs.len(),
        num_rows
    );
    // Pre-compute keystream for default padding rows (nonce=0, plaintext=0)
    // so that ciphertext = keystream and validation passes
    let default_keystreams: [[u8; 16]; 16] = std::array::from_fn(|lane| {
        aes256_ctr_block(key, &[0; 12], lane as u32, &[0; 16])
    });

    for row in 0..num_rows {
        if let Some(input) = inputs.get(row) {
            let valid = gen.process_ctr_block(input, &round_keys_slice);
            if !valid {
                all_valid = false;
            }
        } else {
            // Use default input for padding with correct ciphertext = keystream
            let default_ciphertext: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
                Simd::from_array(std::array::from_fn(|lane| {
                    default_keystreams[lane][byte_idx]
                }))
            });
            let default_input = AESCtrInput {
                nonce: [0; 12],
                counters: Simd::from_array(std::array::from_fn(|lane| lane as u32)),
                plaintext: [Simd::splat(0); 16],
                ciphertext: default_ciphertext,
            };
            gen.process_ctr_block(&default_input, &round_keys_slice);
        }
    }

    let (trace, sbox_accum, lookup_data) = gen.into_trace();
    (trace, sbox_accum, lookup_data, all_valid)
}

/// Generate trace for AES-256-CTR with test data.
/// Note: num_blocks must be a multiple of 16 (SIMD lane count).
pub fn generate_aes256_ctr_trace(
    log_size: u32,
    key: &[u8; 32],
    nonce: &[u8; 12],
    num_blocks: usize,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SboxAccumulator,
    AESCtrLookupData,
) {
    assert!(
        num_blocks % 16 == 0,
        "num_blocks ({}) must be a multiple of 16 (SIMD lane count)",
        num_blocks
    );
    let mut gen = CtrTraceGenerator::new(log_size, AesKeySize::Aes256);
    let round_keys = expand_keys_simd_256(key);
    let round_keys_slice: Vec<[Simd<u8, 16>; 16]> = round_keys.to_vec();

    for batch in 0..(num_blocks / 16) {
        let base_counter = (batch * 16 + 1) as u32;
        let counters = Simd::from_array(std::array::from_fn(|lane| base_counter + lane as u32));

        let plaintext: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                ((batch * 256 + lane * 16 + byte_idx) & 0xFF) as u8
            }))
        });

        // Compute correct ciphertext
        let ciphertext = compute_aes256_ctr_ciphertext(key, nonce, &counters, &plaintext);

        let input = AESCtrInput {
            nonce: *nonce,
            counters,
            plaintext,
            ciphertext,
        };

        gen.process_ctr_block(&input, &round_keys_slice);
    }

    gen.into_trace()
}

/// Compute AES-128-CTR ciphertext for a batch of 16 parallel blocks.
fn compute_aes128_ctr_ciphertext(
    key: &[u8; 16],
    nonce: &[u8; 12],
    counters: &Simd<u32, 16>,
    plaintext: &[Simd<u8, 16>; 16],
) -> [Simd<u8, 16>; 16] {
    use crate::aes::aes128_ctr_block;

    let mut ciphertext: [Simd<u8, 16>; 16] = [Simd::splat(0); 16];

    for lane in 0..16 {
        let counter = counters[lane];
        let pt: [u8; 16] = std::array::from_fn(|i| plaintext[i][lane]);
        let ct = aes128_ctr_block(key, nonce, counter, &pt);
        for i in 0..16 {
            ciphertext[i][lane] = ct[i];
        }
    }

    ciphertext
}

/// Compute AES-256-CTR ciphertext for a batch of 16 parallel blocks.
fn compute_aes256_ctr_ciphertext(
    key: &[u8; 32],
    nonce: &[u8; 12],
    counters: &Simd<u32, 16>,
    plaintext: &[Simd<u8, 16>; 16],
) -> [Simd<u8, 16>; 16] {
    use crate::aes::aes256_ctr_block;

    let mut ciphertext: [Simd<u8, 16>; 16] = [Simd::splat(0); 16];

    for lane in 0..16 {
        let counter = counters[lane];
        let pt: [u8; 16] = std::array::from_fn(|i| plaintext[i][lane]);
        let ct = aes256_ctr_block(key, nonce, counter, &pt);
        for i in 0..16 {
            ciphertext[i][lane] = ct[i];
        }
    }

    ciphertext
}

/// Generate interaction trace for CTR S-box lookups.
pub fn generate_ctr_sbox_interaction_trace(
    log_size: u32,
    lookup_data: &AESCtrLookupData,
    sbox_elements: &SboxElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let mut logup_gen = LogupTraceGenerator::new(log_size);

    let mut lookup_iter = lookup_data.sbox_lookups.iter().enumerate().array_chunks::<2>();

    for [(_idx0, lookup0), (_idx1, lookup1)] in &mut lookup_iter {
        let mut col_gen = logup_gen.new_col();

        for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
            let input0 = lookup0[0].data[vec_row];
            let output0 = lookup0[1].data[vec_row];
            let input1 = lookup1[0].data[vec_row];
            let output1 = lookup1[1].data[vec_row];

            let p0: PackedSecureField = sbox_elements.combine(&[input0, output0]);
            let p1: PackedSecureField = sbox_elements.combine(&[input1, output1]);

            col_gen.write_frac(vec_row, p0 + p1, p0 * p1);
        }
        col_gen.finalize_col();
    }

    if let Some(remainder) = lookup_iter.into_remainder() {
        if let Some((_, lookup)) = remainder.collect_vec().pop() {
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_ctr_trace_generation() {
        let key: [u8; 16] = [0x00; 16];
        let nonce: [u8; 12] = [0x00; 12];

        let log_size = 8;
        let num_blocks = 1 << log_size;

        let (trace, sbox_accum, lookup_data) = generate_aes128_ctr_trace(log_size, &key, &nonce, num_blocks);

        println!("AES-128-CTR trace columns: {}", trace.len());
        println!("S-box lookups recorded: {}", lookup_data.sbox_lookups.len());
        println!("Total S-box uses: {}", sbox_accum.mults.iter().sum::<u32>());
    }

    #[test]
    fn test_aes256_ctr_trace_generation() {
        let key: [u8; 32] = [0x00; 32];
        let nonce: [u8; 12] = [0x00; 12];

        let log_size = 8;
        let num_blocks = 1 << log_size;

        let (trace, sbox_accum, lookup_data) = generate_aes256_ctr_trace(log_size, &key, &nonce, num_blocks);

        println!("AES-256-CTR trace columns: {}", trace.len());
        println!("S-box lookups recorded: {}", lookup_data.sbox_lookups.len());
        println!("Total S-box uses: {}", sbox_accum.mults.iter().sum::<u32>());
    }

    /// Test single block with padding lanes - simulates WASM API scenario
    #[test]
    fn test_aes128_ctr_single_block_with_padding() {
        use crate::aes::aes128_ctr_block;

        let key: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let nonce: [u8; 12] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let counter: u32 = 1;
        let num_blocks = 1;
        let log_size = 8; // Needs log_size >= 4 for AES

        // Create plaintext
        let plaintext: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];

        // Compute expected ciphertext using native function
        let ciphertext = aes128_ctr_block(&key, &nonce, counter, &plaintext);

        // Build counters (16 parallel blocks starting at counter)
        let counters = Simd::from_array(std::array::from_fn(|lane| counter + lane as u32));

        // Build plaintext SIMD - only lane 0 has real data
        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 {
                    plaintext[byte_idx]
                } else {
                    0
                }
            }))
        });

        // Compute padding keystreams using native function
        let padding_keystreams: Vec<[u8; 16]> = (1..16)
            .map(|lane| {
                let padding_counter = counter + lane as u32;
                aes128_ctr_block(&key, &nonce, padding_counter, &[0u8; 16])
            })
            .collect();

        // Build ciphertext SIMD - lane 0 has real ciphertext, others have keystreams
        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 {
                    ciphertext[byte_idx]
                } else {
                    padding_keystreams[lane - 1][byte_idx]
                }
            }))
        });

        // Create input
        let input = AESCtrInput {
            nonce,
            counters,
            plaintext: plaintext_simd,
            ciphertext: ciphertext_simd,
        };

        // Generate trace
        let (trace, sbox_accum, lookup_data, valid) =
            generate_aes128_ctr_trace_with_inputs(log_size, &key, &[input]);

        println!("Single block with padding test: valid = {}", valid);
        println!("Trace columns: {}", trace.len());

        assert!(valid, "Single block with padding should validate");
    }
}
