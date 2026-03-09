//! Hash component for TOPRF.
//!
//! Uses Poseidon2 over M31 field for efficient hashing in stwo.
//! The input (Baby Jubjub point coordinates) are provided as M31 limbs
//! and hashed using the native M31 Poseidon2 permutation.
//!
//! This differs from gnark's MiMC implementation but is more efficient
//! for stwo's native field operations.

pub mod constraints;
pub mod gen;

use std::ops::{Add, AddAssign, Mul, Sub};

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::FieldExpOps;

/// Poseidon2 state size (width 16 for M31).
pub const STATE_SIZE: usize = 16;

/// Number of partial rounds.
pub const N_PARTIAL_ROUNDS: usize = 14;

/// Number of full rounds (half before, half after partial rounds).
pub const N_HALF_FULL_ROUNDS: usize = 4;

/// Total full rounds.
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;

/// External round constants (full rounds).
/// Using placeholder values - should be properly generated.
pub const EXTERNAL_ROUND_CONSTS: [[u32; STATE_SIZE]; FULL_ROUNDS] =
    [[1234; STATE_SIZE]; FULL_ROUNDS];

/// Internal round constants (partial rounds).
pub const INTERNAL_ROUND_CONSTS: [u32; N_PARTIAL_ROUNDS] = [1234; N_PARTIAL_ROUNDS];

/// Apply the M4 MDS matrix.
/// See https://eprint.iacr.org/2023/323.pdf Section 5.1
#[inline(always)]
pub fn apply_m4<F>(x: [F; 4]) -> [F; 4]
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1.clone();
    let t3 = x[3].clone() + x[3].clone() + t0.clone();
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3.clone() + t5.clone();
    let t7 = t2.clone() + t4.clone();
    [t6, t5, t7, t4]
}

/// Apply external round matrix.
/// Applies circ(2M4, M4, M4, M4).
pub fn apply_external_round_matrix<F>(state: &mut [F; STATE_SIZE])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    for i in 0..4 {
        [
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s =
            state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

/// Apply internal round matrix.
/// mu_i = 2^{i+1} + 1.
/// See https://eprint.iacr.org/2023/323.pdf Section 5.2
pub fn apply_internal_round_matrix<F>(state: &mut [F; STATE_SIZE])
where
    F: Clone + AddAssign<F> + Add<F, Output = F> + Sub<F, Output = F> + Mul<BaseField, Output = F>,
{
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = s.clone() * BaseField::from_u32_unchecked(1 << (i + 1)) + sum.clone();
    });
}

/// Compute x^5 (the S-box for Poseidon2).
#[inline(always)]
pub fn pow5<F: FieldExpOps + Clone>(x: F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x
}

/// Hash input using Poseidon2.
///
/// Takes up to 16 M31 field elements and produces a single M31 output.
/// For TOPRF, the input is the limbs of the unmasked point coordinates
/// plus secret data.
pub fn poseidon2_hash(input: &[BaseField]) -> BaseField {
    assert!(input.len() <= STATE_SIZE, "Input too large for Poseidon2");

    // Initialize state with input (padded with zeros)
    let mut state: [BaseField; STATE_SIZE] =
        std::array::from_fn(|i| input.get(i).copied().unwrap_or(BaseField::from_u32_unchecked(0)));

    // First half of full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..STATE_SIZE {
            state[i] += BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]);
        }
        apply_external_round_matrix(&mut state);
        state = std::array::from_fn(|i| pow5(state[i]));
    }

    // Partial rounds
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += BaseField::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]);
        apply_internal_round_matrix(&mut state);
        state[0] = pow5(state[0]);
    }

    // Second half of full rounds
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..STATE_SIZE {
            state[i] +=
                BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
        }
        apply_external_round_matrix(&mut state);
        state = std::array::from_fn(|i| pow5(state[i]));
    }

    // Return first element as hash output
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_basic() {
        let input = [
            BaseField::from_u32_unchecked(1),
            BaseField::from_u32_unchecked(2),
            BaseField::from_u32_unchecked(3),
        ];

        let hash = poseidon2_hash(&input);

        // Just verify it runs and produces non-zero output
        assert!(hash.0 != 0);
    }

    #[test]
    fn test_poseidon2_deterministic() {
        let input = [
            BaseField::from_u32_unchecked(42),
            BaseField::from_u32_unchecked(123),
        ];

        let hash1 = poseidon2_hash(&input);
        let hash2 = poseidon2_hash(&input);

        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_poseidon2_different_inputs() {
        let input1 = [BaseField::from_u32_unchecked(1)];
        let input2 = [BaseField::from_u32_unchecked(2)];

        let hash1 = poseidon2_hash(&input1);
        let hash2 = poseidon2_hash(&input2);

        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_pow5() {
        let x = BaseField::from_u32_unchecked(3);
        let result = pow5(x);
        assert_eq!(result, BaseField::from_u32_unchecked(243)); // 3^5 = 243
    }
}
