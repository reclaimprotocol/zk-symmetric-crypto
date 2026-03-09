//! AIR and proving/verification for TOPRF component.

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, InfoEvaluator};

use super::constraints::TOPRFEvalAtRow;
use super::TOPRFInputs;

/// Component type for TOPRF verification.
pub type TOPRFComponent = FrameworkComponent<TOPRFEval>;

/// Evaluator for TOPRF verification constraints.
pub struct TOPRFEval {
    pub log_size: u32,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for TOPRFEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Constraint degree is at most 5 (from Poseidon2 x^5)
        self.log_size + 3
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, mut eval: E) -> E {
        let mut toprf_eval = TOPRFEvalAtRow { eval: &mut eval };
        toprf_eval.eval_toprf();
        eval
    }
}

/// Get component info for TOPRF.
pub fn toprf_info() -> InfoEvaluator {
    let component = TOPRFEval {
        log_size: 10,
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

/// Benchmark native TOPRF operations (no proof generation).
/// Returns the output hash value.
pub fn bench_native_toprf(inputs: &TOPRFInputs) -> Result<u32, String> {
    use super::gen::verify_toprf_native;

    let result = verify_toprf_native(inputs).map_err(|e| e.to_string())?;
    Ok(result.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toprf_info() {
        let info = toprf_info();
        println!("TOPRF columns: {}", info.mask_offsets[1].len());
        println!("TOPRF constraints: {}", info.n_constraints);
    }
}
