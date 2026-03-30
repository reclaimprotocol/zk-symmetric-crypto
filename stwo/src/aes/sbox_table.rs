//! AES S-box lookup table for Stwo.
//!
//! The S-box is a 256-entry table mapping 8-bit input to 8-bit output.
//! We use LogUp lookup argument to verify S-box applications.

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{relation, FrameworkComponent, FrameworkEval, EvalAtRow, RelationEntry};

use super::SBOX;

/// S-box table has 256 entries (8 bits).
pub const SBOX_BITS: u32 = 8;
pub const SBOX_SIZE: usize = 256;

// Define S-box lookup relation: (input, output) pair
relation!(SboxElements, 2);

/// Preprocessed column ID for S-box table.
pub fn sbox_column_id(col: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("preprocessed_aes_sbox_{}", col),
    }
}

/// Generate the preprocessed (constant) trace for S-box table.
/// Returns two columns: input (0-255) and output (SBOX[input]).
pub fn generate_sbox_trace() -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
{
    let input_col: BaseColumn = (0..SBOX_SIZE)
        .map(|i| BaseField::from_u32_unchecked(i as u32))
        .collect();

    let output_col: BaseColumn = (0..SBOX_SIZE)
        .map(|i| BaseField::from_u32_unchecked(SBOX[i] as u32))
        .collect();

    [input_col, output_col]
        .map(|x| CircleEvaluation::new(CanonicCoset::new(SBOX_BITS).circle_domain(), x))
        .to_vec()
}

/// Accumulator that tracks S-box lookup multiplicities.
#[derive(Clone)]
pub struct SboxAccumulator {
    /// Multiplicity for each of the 256 S-box entries.
    pub mults: Vec<u32>,
}

impl SboxAccumulator {
    pub fn new() -> Self {
        Self {
            mults: vec![0u32; SBOX_SIZE],
        }
    }

    /// Record an S-box lookup (input -> output).
    pub fn add_input(&mut self, input: u8) {
        self.mults[input as usize] += 1;
    }

    /// Convert to BaseColumn for trace generation.
    pub fn into_base_column(self) -> BaseColumn {
        self.mults
            .into_iter()
            .map(|m| BaseField::from_u32_unchecked(m))
            .collect()
    }
}

impl Default for SboxAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// S-box table component for proving the lookup argument.
pub type SboxTableComponent = FrameworkComponent<SboxTableEval>;

/// Evaluator for S-box table constraints.
#[derive(Clone)]
pub struct SboxTableEval {
    pub lookup_elements: SboxElements,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for SboxTableEval {
    fn log_size(&self) -> u32 {
        SBOX_BITS
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        SBOX_BITS + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Get preprocessed columns (input, output)
        let input = eval.get_preprocessed_column(sbox_column_id(0));
        let output = eval.get_preprocessed_column(sbox_column_id(1));

        // Get multiplicity column
        let multiplicity = eval.next_trace_mask();

        // Add logup constraint for table side (yield with negative multiplicity)
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            -E::EF::from(multiplicity),
            &[input, output],
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::prover::backend::Column;

    #[test]
    fn test_sbox_trace_generation() {
        let trace = generate_sbox_trace();
        assert_eq!(trace.len(), 2);

        // Verify a few entries
        let input_col = &trace[0];
        let output_col = &trace[1];

        // Check entry 0: SBOX[0] = 0x63
        assert_eq!(input_col.values.at(0), BaseField::from_u32_unchecked(0));
        assert_eq!(output_col.values.at(0), BaseField::from_u32_unchecked(0x63));

        // Check entry 1: SBOX[1] = 0x7c
        assert_eq!(input_col.values.at(1), BaseField::from_u32_unchecked(1));
        assert_eq!(output_col.values.at(1), BaseField::from_u32_unchecked(0x7c));
    }

    #[test]
    fn test_sbox_accumulator() {
        let mut accum = SboxAccumulator::new();

        accum.add_input(0);
        accum.add_input(0);
        accum.add_input(1);
        accum.add_input(255);

        assert_eq!(accum.mults[0], 2);
        assert_eq!(accum.mults[1], 1);
        assert_eq!(accum.mults[255], 1);
        assert_eq!(accum.mults[2], 0);
    }
}
