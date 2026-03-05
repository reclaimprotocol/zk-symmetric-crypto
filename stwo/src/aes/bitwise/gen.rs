//! Trace generation for bitwise AES.

use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;

use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::PackedM31;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;

use crate::aes::{SBOX, expand_key_128};

/// Input for a single AES block (SIMD-packed).
pub struct AESBitwiseInput {
    /// Plaintext: 16 bytes, each as u8x16 (16 parallel blocks)
    pub plaintext: [Simd<u8, 16>; 16],
    /// Key: 16 bytes for AES-128
    pub key: [Simd<u8, 16>; 16],
}

/// Trace generator for bitwise AES.
struct TraceGenerator {
    log_size: u32,
    trace: Vec<Vec<PackedM31>>,
}

impl TraceGenerator {
    fn new(log_size: u32) -> Self {
        Self {
            log_size,
            trace: Vec::new(),
        }
    }

    /// Add a column of bits for a single byte across all SIMD lanes.
    fn append_byte_bits(&mut self, values: Simd<u8, 16>) {
        for bit_idx in 0..8 {
            let bit_values: [u32; 16] = std::array::from_fn(|lane| {
                ((values[lane] >> bit_idx) & 1) as u32
            });
            self.append_packed(PackedM31::from_array(
                bit_values.map(|v| BaseField::from_u32_unchecked(v))
            ));
        }
    }

    /// Add a column of packed M31 values.
    fn append_packed(&mut self, value: PackedM31) {
        let col_idx = self.trace.len();
        if col_idx >= self.trace.len() {
            self.trace.push(Vec::new());
        }
        self.trace[col_idx].push(value);
    }

    /// Extend trace column with a single packed value (for building columns row by row).
    #[allow(dead_code)]
    fn extend_column(&mut self, col_idx: usize, value: PackedM31) {
        while self.trace.len() <= col_idx {
            self.trace.push(Vec::new());
        }
        self.trace[col_idx].push(value);
    }

    /// XOR two bytes (SIMD), return result and record intermediate bits.
    #[allow(dead_code)]
    fn xor_byte(&mut self, a: Simd<u8, 16>, b: Simd<u8, 16>) -> Simd<u8, 16> {
        let result = a ^ b;
        // Record result bits
        self.append_byte_bits(result);
        result
    }

    /// GF(2^8) xtime operation.
    fn xtime_simd(&self, a: Simd<u8, 16>) -> Simd<u8, 16> {
        let shifted = a << Simd::splat(1);
        let mask = a >> Simd::splat(7); // High bit as 0 or 1
        let reduction = mask * Simd::splat(0x1b);
        shifted ^ reduction
    }

    /// GF(2^8) multiply (native, for computing values).
    fn gf_mul_simd(&self, a: Simd<u8, 16>, b: Simd<u8, 16>) -> Simd<u8, 16> {
        let mut result = Simd::splat(0u8);
        let mut a = a;
        let mut b_shifted = b;

        for _ in 0..8 {
            let mask = (b_shifted & Simd::splat(1)).simd_ne(Simd::splat(0));
            result = mask.select(result ^ a, result);
            a = self.xtime_simd(a);
            b_shifted = b_shifted >> Simd::splat(1);
        }

        result
    }

    /// Apply S-box to a byte (using lookup table).
    fn sbox_simd(&self, x: Simd<u8, 16>) -> Simd<u8, 16> {
        Simd::from_array(std::array::from_fn(|i| SBOX[x[i] as usize]))
    }

    /// Process a single AES-128 block and record trace.
    fn process_block(&mut self, input: &AESBitwiseInput) {
        // Expand key to round keys
        let round_keys = self.expand_keys_simd(&input.key);

        // Record plaintext bits (16 bytes * 8 bits = 128 columns)
        for i in 0..16 {
            self.append_byte_bits(input.plaintext[i]);
        }

        // Record round key bits (11 * 16 * 8 = 1408 columns)
        for rk in &round_keys {
            for i in 0..16 {
                self.append_byte_bits(rk[i]);
            }
        }

        // Initial AddRoundKey
        let mut state: [Simd<u8, 16>; 16] = std::array::from_fn(|i| {
            input.plaintext[i] ^ round_keys[0][i]
        });
        for i in 0..16 {
            self.append_byte_bits(state[i]);
        }

        // 9 main rounds
        for round in 1..10 {
            state = self.sub_bytes_trace(&state);
            state = self.shift_rows(&state);
            state = self.mix_columns_trace(&state);
            state = self.add_round_key_trace(&state, &round_keys[round]);
        }

        // Final round (no MixColumns)
        state = self.sub_bytes_trace(&state);
        state = self.shift_rows(&state);
        let _output = self.add_round_key_trace(&state, &round_keys[10]);
    }

    /// Expand key (native computation).
    fn expand_keys_simd(&self, key: &[Simd<u8, 16>; 16]) -> [[Simd<u8, 16>; 16]; 11] {
        // For simplicity, expand each lane's key separately and combine
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

    /// SubBytes with trace recording.
    fn sub_bytes_trace(&mut self, state: &[Simd<u8, 16>; 16]) -> [Simd<u8, 16>; 16] {
        let mut result = [Simd::splat(0u8); 16];
        for i in 0..16 {
            result[i] = self.sbox_simd(state[i]);
            // Record S-box output bits
            self.append_byte_bits(result[i]);
            // TODO: Record intermediate GF inverse computations
        }
        result
    }

    /// ShiftRows (no trace needed, just permutation).
    fn shift_rows(&self, state: &[Simd<u8, 16>; 16]) -> [Simd<u8, 16>; 16] {
        [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]
    }

    /// MixColumns with trace recording.
    fn mix_columns_trace(&mut self, state: &[Simd<u8, 16>; 16]) -> [Simd<u8, 16>; 16] {
        let mut result = [Simd::splat(0u8); 16];
        let two = Simd::splat(0x02u8);
        let three = Simd::splat(0x03u8);

        for col in 0..4 {
            let i = col * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];

            // r0 = 2*s0 + 3*s1 + s2 + s3
            let t0 = self.gf_mul_simd(two, s0);
            let t1 = self.gf_mul_simd(three, s1);
            result[i] = t0 ^ t1 ^ s2 ^ s3;

            // r1 = s0 + 2*s1 + 3*s2 + s3
            let t0 = self.gf_mul_simd(two, s1);
            let t1 = self.gf_mul_simd(three, s2);
            result[i + 1] = s0 ^ t0 ^ t1 ^ s3;

            // r2 = s0 + s1 + 2*s2 + 3*s3
            let t0 = self.gf_mul_simd(two, s2);
            let t1 = self.gf_mul_simd(three, s3);
            result[i + 2] = s0 ^ s1 ^ t0 ^ t1;

            // r3 = 3*s0 + s1 + s2 + 2*s3
            let t0 = self.gf_mul_simd(three, s0);
            let t1 = self.gf_mul_simd(two, s3);
            result[i + 3] = t0 ^ s1 ^ s2 ^ t1;

            // Record result bits
            for j in 0..4 {
                self.append_byte_bits(result[i + j]);
            }
        }

        result
    }

    /// AddRoundKey with trace recording.
    fn add_round_key_trace(
        &mut self,
        state: &[Simd<u8, 16>; 16],
        round_key: &[Simd<u8, 16>; 16],
    ) -> [Simd<u8, 16>; 16] {
        let mut result = [Simd::splat(0u8); 16];
        for i in 0..16 {
            result[i] = state[i] ^ round_key[i];
            self.append_byte_bits(result[i]);
        }
        result
    }

    /// Convert trace to CircleEvaluations.
    fn into_trace(self) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let domain = CanonicCoset::new(self.log_size).circle_domain();

        self.trace
            .into_iter()
            .map(|col| {
                let mut base_col = BaseColumn::zeros(1 << self.log_size);
                for (i, val) in col.into_iter().enumerate() {
                    base_col.data[i] = val;
                }
                CircleEvaluation::new(domain, base_col)
            })
            .collect()
    }
}

/// Generate trace for bitwise AES.
pub fn generate_trace(
    log_size: u32,
    inputs: &[AESBitwiseInput],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let mut gen = TraceGenerator::new(log_size);

    for input in inputs {
        gen.process_block(input);
    }

    gen.into_trace()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::gf_mul;

    #[test]
    fn test_sbox_simd() {
        let gen = TraceGenerator::new(4);

        // Test S-box on all values 0-255
        for i in 0..=255u8 {
            let input = Simd::splat(i);
            let output = gen.sbox_simd(input);
            assert_eq!(output[0], SBOX[i as usize]);
        }
    }

    #[test]
    fn test_gf_mul_simd() {
        let gen = TraceGenerator::new(4);

        // Test known GF multiplication values
        let a = Simd::splat(0x57u8);
        let b = Simd::splat(0x83u8);
        let result = gen.gf_mul_simd(a, b);

        // 0x57 * 0x83 in GF(2^8) = 0xc1
        assert_eq!(result[0], gf_mul(0x57, 0x83));
    }
}
