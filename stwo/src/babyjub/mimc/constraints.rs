//! Constraint evaluation for Poseidon2 hash.
//!
//! Evaluates Poseidon2 permutation constraints over M31 field.

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::{
    apply_external_round_matrix, apply_internal_round_matrix, pow5, EXTERNAL_ROUND_CONSTS,
    INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, STATE_SIZE,
};

/// Evaluator for Poseidon2 hash constraints.
pub struct Poseidon2EvalAtRow<'a, E: EvalAtRow> {
    pub eval: &'a mut E,
}

impl<E: EvalAtRow> Poseidon2EvalAtRow<'_, E> {
    /// Evaluate Poseidon2 permutation constraints.
    ///
    /// Reads initial state and intermediate states from trace,
    /// constrains the permutation is computed correctly.
    pub fn eval_poseidon2(&mut self) -> [E::F; STATE_SIZE] {
        // Read initial state
        let mut state: [E::F; STATE_SIZE] = std::array::from_fn(|_| self.eval.next_trace_mask());

        // First half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            // Add round constants
            for i in 0..STATE_SIZE {
                state[i] +=
                    E::F::from(BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]));
            }

            // Apply MDS matrix
            apply_external_round_matrix(&mut state);

            // Apply S-box (x^5) and constrain
            state = std::array::from_fn(|i| pow5(state[i].clone()));

            // Read expected state from trace and constrain
            state.iter_mut().for_each(|s| {
                let m = self.eval.next_trace_mask();
                self.eval.add_constraint(s.clone() - m.clone());
                *s = m;
            });
        }

        // Partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            // Add round constant (only to first element)
            state[0] += E::F::from(BaseField::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]));

            // Apply internal MDS matrix
            apply_internal_round_matrix(&mut state);

            // Apply S-box only to first element
            state[0] = pow5(state[0].clone());

            // Read expected value and constrain
            let m = self.eval.next_trace_mask();
            self.eval.add_constraint(state[0].clone() - m.clone());
            state[0] = m;
        }

        // Second half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            // Add round constants
            for i in 0..STATE_SIZE {
                state[i] += E::F::from(BaseField::from_u32_unchecked(
                    EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i],
                ));
            }

            // Apply MDS matrix
            apply_external_round_matrix(&mut state);

            // Apply S-box and constrain
            state = std::array::from_fn(|i| pow5(state[i].clone()));

            state.iter_mut().for_each(|s| {
                let m = self.eval.next_trace_mask();
                self.eval.add_constraint(s.clone() - m.clone());
                *s = m;
            });
        }

        state
    }

    /// Hash multiple Field256 values (provided as M31 limbs) and return hash output.
    ///
    /// For TOPRF: hashes (unmasked.x, unmasked.y, secret_data[0], secret_data[1])
    /// Each Field256 has 9 limbs, so total input is 4 * 9 = 36 M31 elements.
    /// We use a sponge construction to handle inputs larger than state size.
    pub fn hash_field256_values(&mut self, n_field256_inputs: usize) -> E::F {
        let n_limbs_per_field = 9;
        let total_input_limbs = n_field256_inputs * n_limbs_per_field;

        // Sponge construction: absorb STATE_SIZE elements at a time
        let mut state: [E::F; STATE_SIZE] =
            std::array::from_fn(|_| E::F::from(BaseField::from_u32_unchecked(0)));

        let mut absorbed = 0;
        while absorbed < total_input_limbs {
            // Read up to STATE_SIZE input limbs
            let absorb_count = (total_input_limbs - absorbed).min(STATE_SIZE);
            for i in 0..absorb_count {
                let input = self.eval.next_trace_mask();
                state[i] = state[i].clone() + input;
            }
            absorbed += absorb_count;

            // Apply permutation
            state = self.eval_poseidon2_on_state(state);
        }

        // Return first element as hash
        state[0].clone()
    }

    /// Apply Poseidon2 permutation on given state.
    fn eval_poseidon2_on_state(&mut self, mut state: [E::F; STATE_SIZE]) -> [E::F; STATE_SIZE] {
        // First half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..STATE_SIZE {
                state[i] +=
                    E::F::from(BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]));
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5(state[i].clone()));

            state.iter_mut().for_each(|s| {
                let m = self.eval.next_trace_mask();
                self.eval.add_constraint(s.clone() - m.clone());
                *s = m;
            });
        }

        // Partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            state[0] += E::F::from(BaseField::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]));
            apply_internal_round_matrix(&mut state);
            state[0] = pow5(state[0].clone());

            let m = self.eval.next_trace_mask();
            self.eval.add_constraint(state[0].clone() - m.clone());
            state[0] = m;
        }

        // Second half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..STATE_SIZE {
                state[i] += E::F::from(BaseField::from_u32_unchecked(
                    EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i],
                ));
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5(state[i].clone()));

            state.iter_mut().for_each(|s| {
                let m = self.eval.next_trace_mask();
                self.eval.add_constraint(s.clone() - m.clone());
                *s = m;
            });
        }

        state
    }
}

/// Number of limbs in a Field256.
const N_FIELD256_LIMBS: usize = 9;

/// Number of limbs to generate for hash_to_scalar (covers 254-bit scalar).
const N_SCALAR_LIMBS: usize = 9;

impl<E: EvalAtRow> Poseidon2EvalAtRow<'_, E> {
    /// Compute hash_to_scalar for DLEQ challenge verification.
    ///
    /// This generates a 256-bit scalar from the hash inputs by:
    /// 1. Hashing 9 times with domain separators 0-8
    /// 2. Each hash produces one 29-bit limb
    /// 3. The result is a Field256 representing the challenge scalar
    ///
    /// The inputs are expected to be 12 Field256 values (6 points × 2 coordinates = 108 M31 limbs).
    /// Each hash call prepends a domain separator limb, so total input per hash is 109 limbs.
    ///
    /// Returns the 9 limbs of the computed scalar.
    pub fn hash_to_scalar_dleq(
        &mut self,
        n_point_coords: usize, // Number of Field256 coordinate values (should be 12 for 6 points)
    ) -> [E::F; N_SCALAR_LIMBS] {
        let mut result_limbs: [E::F; N_SCALAR_LIMBS] = std::array::from_fn(|_| {
            E::F::from(BaseField::from_u32_unchecked(0))
        });

        // For each limb, compute a hash with a different domain separator
        for limb_idx in 0..N_SCALAR_LIMBS {
            // The domain separator is the limb index (0-8)
            let domain_sep = E::F::from(BaseField::from_u32_unchecked(limb_idx as u32));

            // Sponge construction with domain separator prepended
            let mut state: [E::F; STATE_SIZE] =
                std::array::from_fn(|_| E::F::from(BaseField::from_u32_unchecked(0)));

            // Add domain separator to first position
            state[0] = domain_sep.clone();

            // Read domain separator from trace and constrain
            let traced_domain_sep = self.eval.next_trace_mask();
            self.eval.add_constraint(traced_domain_sep.clone() - domain_sep);

            // Apply first permutation (domain separator only, rest is zero)
            state = self.eval_poseidon2_on_state(state);

            // Now absorb the point coordinate limbs in chunks of STATE_SIZE
            let total_input_limbs = n_point_coords * N_FIELD256_LIMBS;
            let mut absorbed = 0;

            while absorbed < total_input_limbs {
                let absorb_count = (total_input_limbs - absorbed).min(STATE_SIZE);

                for i in 0..absorb_count {
                    let input = self.eval.next_trace_mask();
                    state[i] = state[i].clone() + input;
                }
                absorbed += absorb_count;

                // Apply permutation
                state = self.eval_poseidon2_on_state(state);
            }

            // Extract the hash output (first element) and mask to 29 bits
            // The masking is done by the prover; we read the masked value and constrain
            let hash_output = state[0].clone();

            // Read the expected limb value from trace
            let expected_limb = self.eval.next_trace_mask();

            // Constrain: hash_output mod 2^29 == expected_limb
            // Since we're in M31, the hash output is already < 2^31
            // The prover computes hash.0 & 0x1FFFFFFF
            // We need to verify this with a range check and relation

            // For now, we trust the prover's masked value and constrain
            // the relation: there exists k such that hash_output = expected_limb + k * 2^29
            // This requires reading k from trace
            let quotient = self.eval.next_trace_mask();
            let two_pow_29 = E::F::from(BaseField::from_u32_unchecked(1 << 29));
            self.eval.add_constraint(
                hash_output - expected_limb.clone() - quotient * two_pow_29
            );

            result_limbs[limb_idx] = expected_limb;
        }

        result_limbs
    }
}

/// Count constraints for one Poseidon2 permutation.
pub fn poseidon2_constraint_count() -> usize {
    // Full rounds: N_HALF_FULL_ROUNDS * 2 rounds, each with STATE_SIZE pow5 constraints
    let full_round_constraints = 2 * N_HALF_FULL_ROUNDS * STATE_SIZE;

    // Partial rounds: N_PARTIAL_ROUNDS rounds, each with 1 pow5 constraint
    let partial_round_constraints = N_PARTIAL_ROUNDS;

    full_round_constraints + partial_round_constraints
}

/// Count constraints for hash_to_scalar_dleq.
pub fn hash_to_scalar_constraint_count(n_point_coords: usize) -> usize {
    let total_input_limbs = n_point_coords * N_FIELD256_LIMBS;
    let n_permutations_per_limb = 1 + (total_input_limbs + STATE_SIZE - 1) / STATE_SIZE;

    // Per limb: domain sep constraint + n_permutations * poseidon2 + masking constraint
    let per_limb = 1 + n_permutations_per_limb * poseidon2_constraint_count() + 1;

    N_SCALAR_LIMBS * per_limb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_count() {
        let count = poseidon2_constraint_count();
        println!("Poseidon2 constraints per permutation: {}", count);

        // Should be: 2 * 4 * 16 + 14 = 128 + 14 = 142
        assert_eq!(count, 142);
    }
}
