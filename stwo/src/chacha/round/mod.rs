//! ChaCha20 round component.
//!
//! This component proves one double-round of ChaCha20.
//! A double-round consists of 4 column quarter-rounds + 4 diagonal quarter-rounds.

mod constraints;
mod gen;

pub use constraints::ChaChaRoundEvalAtRow;
pub use gen::{generate_interaction_trace, generate_trace, ChaChaRoundInput, ChaChaRoundLookupData};

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, InfoEvaluator};

use super::constraints::ChaChaXorElements;

/// Component type for ChaCha round.
pub type ChaChaRoundComponent = FrameworkComponent<ChaChaRoundEval>;

/// Evaluator for ChaCha round constraints.
pub struct ChaChaRoundEval {
    pub log_size: u32,
    pub xor_lookup_elements: ChaChaXorElements,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for ChaChaRoundEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        ChaChaRoundEvalAtRow {
            eval,
            xor_lookup_elements: &self.xor_lookup_elements,
        }
        .eval()
    }
}

/// Get component info (mask offsets, etc.) for ChaCha round.
pub fn chacha_round_info() -> InfoEvaluator {
    let component = ChaChaRoundEval {
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
    use stwo_constraint_framework::assert_constraints_on_polys;

    use crate::chacha::xor_table::XorAccums;

    #[test]
    fn test_round_info() {
        let info = chacha_round_info();
        // Verify we can get constraint info without panicking
        println!("Round component mask offsets: {:?}", info.mask_offsets);
    }

    #[test]
    fn test_round_constraints() {
        use stwo::prover::backend::simd::m31::LOG_N_LANES;

        const LOG_SIZE: u32 = 8; // Small for fast tests

        // Create test inputs
        let mut xor_accum = XorAccums::new();
        let inputs: Vec<ChaChaRoundInput> = (0..(1 << (LOG_SIZE - LOG_N_LANES)))
            .map(|i| ChaChaRoundInput {
                v: std::array::from_fn(|j| Simd::splat((i * 16 + j) as u32)),
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
        let component = ChaChaRoundEval {
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
