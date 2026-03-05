//! ChaCha20 full block component.
//!
//! This component proves a full ChaCha20 block:
//! - 10 double-rounds (20 quarter-rounds total)
//! - Final addition of initial state

mod constraints;
mod gen;

pub use constraints::ChaChaBlockEvalAtRow;
pub use gen::{generate_interaction_trace, generate_trace, ChaChaBlockInput, ChaChaBlockLookupData};

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, InfoEvaluator};

use super::constraints::ChaChaXorElements;

/// Component type for ChaCha full block.
pub type ChaChaBlockComponent = FrameworkComponent<ChaChaBlockEval>;

/// Evaluator for ChaCha block constraints.
pub struct ChaChaBlockEval {
    pub log_size: u32,
    pub xor_lookup_elements: ChaChaXorElements,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for ChaChaBlockEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        ChaChaBlockEvalAtRow {
            eval,
            xor_lookup_elements: &self.xor_lookup_elements,
        }
        .eval()
    }
}

/// Get component info (mask offsets, etc.) for ChaCha block.
pub fn chacha_block_info() -> InfoEvaluator {
    let component = ChaChaBlockEval {
        log_size: 10, // Arbitrary, just for info
        xor_lookup_elements: ChaChaXorElements::dummy(),
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

    use crate::chacha::xor_table::XorAccums;
    use crate::chacha::block::build_state;

    #[test]
    fn test_block_info() {
        let info = chacha_block_info();
        println!("Block component mask offsets: {:?}", info.mask_offsets);
        println!("Block component n_constraints: {:?}", info.n_constraints);
    }

    #[test]
    fn test_block_constraints() {
        const LOG_SIZE: u32 = 8; // Small for fast tests

        // Create test inputs - use RFC test vector
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

        // Generate main trace
        let (trace, lookup_data) = generate_trace(LOG_SIZE, &inputs, &mut xor_accum);

        // Generate interaction trace
        let xor_lookup_elements = ChaChaXorElements::dummy();
        let (interaction_trace, claimed_sum) = generate_interaction_trace(
            LOG_SIZE,
            lookup_data,
            &xor_lookup_elements,
        );

        // Assemble TreeVec (preprocessed empty, main trace, interaction trace)
        let trace = TreeVec::new(vec![vec![], trace, interaction_trace]);

        // Interpolate to polynomials
        let trace_polys = trace.map_cols(|c| c.interpolate());

        // Create component and validate constraints
        let component = ChaChaBlockEval {
            log_size: LOG_SIZE,
            xor_lookup_elements,
            claimed_sum,
        };

        assert_constraints_on_polys(
            &trace_polys,
            CanonicCoset::new(LOG_SIZE),
            |eval| {
                component.evaluate(eval);
            },
            claimed_sum,
        );
    }
}
