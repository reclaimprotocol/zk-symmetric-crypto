//! Bit-based ChaCha20 component (no lookup tables).
//!
//! This implementation represents u32s as 32 individual bits and uses
//! algebraic constraints for XOR instead of lookup tables. This eliminates
//! the fixed table overhead, making it efficient for small batch sizes.

pub mod air;
pub mod air_stream;
pub mod constraints;
mod constraints_stream;
mod gen;
pub mod gen_stream;

pub use constraints::ChaChabitwiseEvalAtRow;
pub use constraints_stream::ChaChaStreamEvalAtRow;
pub use gen::{generate_trace, ChaChabitwiseInput};
pub use gen_stream::{generate_stream_trace, ChaChaStreamInput};

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, InfoEvaluator};

/// Component type for bitwise ChaCha block.
pub type ChaChabitwiseComponent = FrameworkComponent<ChaChabitwiseEval>;

/// Evaluator for bitwise ChaCha block constraints.
pub struct ChaChabitwiseEval {
    pub log_size: u32,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for ChaChabitwiseEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        ChaChabitwiseEvalAtRow { eval }.eval()
    }
}

/// Get component info for bitwise ChaCha block.
pub fn chacha_bitwise_info() -> InfoEvaluator {
    let component = ChaChabitwiseEval {
        log_size: 10,
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

/// Component type for ChaCha20 stream encryption.
pub type ChaChaStreamComponent = FrameworkComponent<ChaChaStreamEval>;

/// Evaluator for ChaCha20 stream encryption constraints.
pub struct ChaChaStreamEval {
    pub log_size: u32,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for ChaChaStreamEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        ChaChaStreamEvalAtRow { eval }.eval()
    }
}

/// Get component info for ChaCha20 stream encryption.
pub fn chacha_stream_info() -> InfoEvaluator {
    let component = ChaChaStreamEval {
        log_size: 10,
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::simd::Simd;

    use stwo::core::pcs::TreeVec;
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::prover::backend::simd::m31::LOG_N_LANES;
    use stwo_constraint_framework::assert_constraints_on_polys;

    use crate::chacha::block::build_state;

    #[test]
    fn test_bitwise_info() {
        let info = chacha_bitwise_info();
        let n_cols = info.mask_offsets[1].len();
        println!("Bitwise component trace columns: {}", n_cols);
        println!("Bitwise component n_constraints: {}", info.n_constraints);
    }

    #[test]
    fn test_stream_info() {
        let info = chacha_stream_info();
        let n_cols = info.mask_offsets[1].len();
        println!("Stream component trace columns: {}", n_cols);
        println!("Stream component n_constraints: {}", info.n_constraints);
    }

    #[test]
    fn test_bitwise_constraints() {
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

        // No interaction trace needed (no lookups)
        let trace = TreeVec::new(vec![vec![], trace, vec![]]);
        let trace_polys = trace.map_cols(|c| c.interpolate());

        let component = ChaChabitwiseEval {
            log_size: LOG_SIZE,
            claimed_sum: SecureField::zero(),
        };

        assert_constraints_on_polys(
            &trace_polys,
            CanonicCoset::new(LOG_SIZE),
            |eval| {
                component.evaluate(eval);
            },
            SecureField::zero(),
        );
    }

    #[test]
    fn test_stream_constraints() {
        use std::simd::u32x16;
        use super::gen_stream::chacha20_encrypt;

        const LOG_SIZE: u32 = 6;

        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];

        let inputs: Vec<ChaChaStreamInput> = (0..(1 << (LOG_SIZE - LOG_N_LANES)))
            .map(|i| {
                let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane + 1) as u32));
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
        assert!(valid, "Ciphertext should be valid");

        let trace = TreeVec::new(vec![vec![], trace, vec![]]);
        let trace_polys = trace.map_cols(|c| c.interpolate());

        let component = ChaChaStreamEval {
            log_size: LOG_SIZE,
            claimed_sum: SecureField::zero(),
        };

        assert_constraints_on_polys(
            &trace_polys,
            CanonicCoset::new(LOG_SIZE),
            |eval| {
                component.evaluate(eval);
            },
            SecureField::zero(),
        );
    }
}

#[test]
fn debug_info() {
    let info = chacha_bitwise_info();
    println!("Tree 0 (preprocessed) columns: {}", info.mask_offsets[0].len());
    println!("Tree 1 (main trace) columns: {}", info.mask_offsets[1].len());
    if info.mask_offsets.len() > 2 {
        println!("Tree 2 (interaction) columns: {}", info.mask_offsets[2].len());
    }
}
