//! Bitwise AES component (no lookup tables).
//!
//! This implementation represents bytes as 8 individual bits and uses
//! algebraic constraints for GF(2^8) arithmetic.
//!
//! ## Complexity Analysis
//!
//! The main cost is the S-box, which requires computing x^254 in GF(2^8).
//!
//! **GF(2^8) multiplication cost:**
//! - 8 iterations of: conditional XOR (8 AND + 8 XOR) + xtime (3 XOR)
//! - Per multiplication: ~8 * (8 + 8 + 3) = 152 bit operations
//! - Each XOR needs 1 constraint, each AND needs 1 constraint
//!
//! **S-box inverse (x^254) cost:**
//! - 11 GF multiplications via addition chain
//! - ~11 * 152 = 1,672 bit operations per S-box
//!
//! **Per AES round:**
//! - SubBytes: 16 S-boxes = 16 * 1,672 = 26,752 constraints
//! - MixColumns: 4 columns * (8 GF muls + 12 XOR bytes) = ~5,000 constraints
//! - AddRoundKey: 16 XOR bytes = 128 constraints
//! - Total per round: ~32,000 constraints
//!
//! **Full AES-128 (10 rounds):**
//! - ~320,000 constraints for SubBytes+MixColumns+AddRoundKey
//! - Plus trace columns for all intermediate values
//!
//! This is about 10x more expensive than ChaCha20 bitwise.

pub mod constraints;
pub mod gen;

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, InfoEvaluator};

/// Component type for bitwise AES block.
pub type AESBitwiseComponent = FrameworkComponent<AESBitwiseEval>;

/// Evaluator for bitwise AES block constraints.
pub struct AESBitwiseEval {
    pub log_size: u32,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for AESBitwiseEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        constraints::AESBitwiseEvalAtRow { eval }.aes128_block()
    }
}

/// Get component info for bitwise AES block.
pub fn aes_bitwise_info() -> InfoEvaluator {
    let component = AESBitwiseEval {
        log_size: 10,
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_bitwise_info() {
        let info = aes_bitwise_info();
        let n_cols = info.mask_offsets[1].len();
        println!("AES Bitwise component trace columns: {}", n_cols);
        println!("AES Bitwise component n_constraints: {}", info.n_constraints);
    }
}
