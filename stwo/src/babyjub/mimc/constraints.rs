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

/// Count constraints for one Poseidon2 permutation.
pub fn poseidon2_constraint_count() -> usize {
    // Full rounds: N_HALF_FULL_ROUNDS * 2 rounds, each with STATE_SIZE pow5 constraints
    let full_round_constraints = 2 * N_HALF_FULL_ROUNDS * STATE_SIZE;

    // Partial rounds: N_PARTIAL_ROUNDS rounds, each with 1 pow5 constraint
    let partial_round_constraints = N_PARTIAL_ROUNDS;

    full_round_constraints + partial_round_constraints
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
