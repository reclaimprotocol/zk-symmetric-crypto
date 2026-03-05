//! Lookup-based AES component.
//!
//! Uses S-box lookup tables instead of algebraic GF(2^8) inverse.
//! Much more efficient than bitwise for larger batches.
//!
//! Supports:
//! - AES-128 (10 rounds)
//! - AES-256 (14 rounds)
//! - CTR mode for both

pub mod air;
pub mod air_ctr;
pub mod constraints;
pub mod constraints256;
pub mod ctr;
pub mod gen;
pub mod gen_ctr;

use num_traits::Zero;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, InfoEvaluator};

use super::sbox_table::SboxElements;
use super::AesKeySize;

/// Component type for lookup-based AES-128 block.
pub type AESLookupComponent = FrameworkComponent<AESLookupEval>;

/// Evaluator for lookup-based AES-128 block constraints.
pub struct AESLookupEval {
    pub log_size: u32,
    pub sbox_lookup_elements: SboxElements,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for AESLookupEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        constraints::AESLookupEvalAtRow {
            eval,
            sbox_elements: &self.sbox_lookup_elements,
        }
        .aes128_block()
    }
}

/// Get component info for lookup-based AES-128 block.
pub fn aes_lookup_info() -> InfoEvaluator {
    let component = AESLookupEval {
        log_size: 10,
        sbox_lookup_elements: SboxElements::dummy(),
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

/// Component type for lookup-based AES-256 block.
pub type AES256LookupComponent = FrameworkComponent<AES256LookupEval>;

/// Evaluator for lookup-based AES-256 block constraints.
pub struct AES256LookupEval {
    pub log_size: u32,
    pub sbox_lookup_elements: SboxElements,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for AES256LookupEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        constraints256::AES256LookupEvalAtRow {
            eval,
            sbox_elements: &self.sbox_lookup_elements,
        }
        .aes256_block()
    }
}

/// Get component info for lookup-based AES-256 block.
pub fn aes256_lookup_info() -> InfoEvaluator {
    let component = AES256LookupEval {
        log_size: 10,
        sbox_lookup_elements: SboxElements::dummy(),
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

/// Component type for AES-CTR mode.
pub type AESCtrComponent = FrameworkComponent<AESCtrEval>;

/// Evaluator for AES-CTR mode constraints.
pub struct AESCtrEval {
    pub log_size: u32,
    pub key_size: AesKeySize,
    pub sbox_lookup_elements: SboxElements,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for AESCtrEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        ctr::AESCtrEvalAtRow {
            eval,
            sbox_elements: &self.sbox_lookup_elements,
            key_size: self.key_size,
        }
        .ctr_block()
    }
}

/// Get component info for AES-128-CTR.
pub fn aes128_ctr_info() -> InfoEvaluator {
    let component = AESCtrEval {
        log_size: 10,
        key_size: AesKeySize::Aes128,
        sbox_lookup_elements: SboxElements::dummy(),
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

/// Get component info for AES-256-CTR.
pub fn aes256_ctr_info() -> InfoEvaluator {
    let component = AESCtrEval {
        log_size: 10,
        key_size: AesKeySize::Aes256,
        sbox_lookup_elements: SboxElements::dummy(),
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_lookup_info() {
        let info = aes_lookup_info();
        let n_cols = info.mask_offsets[1].len();
        println!("AES-128 Lookup component trace columns: {}", n_cols);
        println!("AES-128 Lookup component n_constraints: {}", info.n_constraints);
    }

    #[test]
    fn test_aes256_lookup_info() {
        let info = aes256_lookup_info();
        let n_cols = info.mask_offsets[1].len();
        println!("AES-256 Lookup component trace columns: {}", n_cols);
        println!("AES-256 Lookup component n_constraints: {}", info.n_constraints);
    }

    #[test]
    fn test_aes_ctr_info() {
        let info128 = aes128_ctr_info();
        println!("AES-128-CTR component trace columns: {}", info128.mask_offsets[1].len());
        println!("AES-128-CTR component n_constraints: {}", info128.n_constraints);

        let info256 = aes256_ctr_info();
        println!("AES-256-CTR component trace columns: {}", info256.mask_offsets[1].len());
        println!("AES-256-CTR component n_constraints: {}", info256.n_constraints);
    }
}
