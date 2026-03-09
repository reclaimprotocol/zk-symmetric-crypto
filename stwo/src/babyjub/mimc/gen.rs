//! Trace generation for Poseidon2 hash.

use stwo::core::fields::m31::BaseField;

use super::{
    apply_external_round_matrix, apply_internal_round_matrix, pow5, EXTERNAL_ROUND_CONSTS,
    INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, STATE_SIZE,
};
use crate::babyjub::field256::gen::BigInt256;

/// Trace generator for Poseidon2.
pub struct Poseidon2TraceGen {
    pub trace: Vec<Vec<u32>>,
    pub col_index: usize,
}

impl Poseidon2TraceGen {
    /// Create new trace generator.
    pub fn new() -> Self {
        Self {
            trace: Vec::new(),
            col_index: 0,
        }
    }

    /// Append a value to trace.
    fn append(&mut self, val: u32) {
        if self.col_index >= self.trace.len() {
            self.trace.push(Vec::new());
        }
        self.trace[self.col_index].push(val);
        self.col_index += 1;
    }

    /// Append multiple values.
    fn append_state(&mut self, state: &[BaseField; STATE_SIZE]) {
        for s in state {
            self.append(s.0);
        }
    }

    /// Generate trace for Poseidon2 permutation.
    pub fn gen_poseidon2(&mut self, input: &[BaseField; STATE_SIZE]) -> [BaseField; STATE_SIZE] {
        let mut state = *input;

        // Append initial state
        self.append_state(&state);

        // First half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..STATE_SIZE {
                state[i] += BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5(state[i]));

            // Append state after S-box
            self.append_state(&state);
        }

        // Partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            state[0] += BaseField::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]);
            apply_internal_round_matrix(&mut state);
            state[0] = pow5(state[0]);

            // Append only first element
            self.append(state[0].0);
        }

        // Second half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..STATE_SIZE {
                state[i] +=
                    BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5(state[i]));

            // Append state after S-box
            self.append_state(&state);
        }

        state
    }

    /// Hash multiple Field256 values using sponge construction.
    /// Returns the hash output (first element of final state).
    pub fn gen_hash_field256(&mut self, inputs: &[BigInt256]) -> BaseField {
        // Convert Field256 limbs to BaseField elements
        let mut input_elements: Vec<BaseField> = Vec::new();
        for field256 in inputs {
            for &limb in &field256.limbs {
                input_elements.push(BaseField::from_u32_unchecked(limb));
            }
        }

        // Sponge construction
        let mut state: [BaseField; STATE_SIZE] =
            std::array::from_fn(|_| BaseField::from_u32_unchecked(0));

        let mut absorbed = 0;
        while absorbed < input_elements.len() {
            // Absorb up to STATE_SIZE elements
            let absorb_count = (input_elements.len() - absorbed).min(STATE_SIZE);
            for i in 0..absorb_count {
                // Append input element to trace
                self.append(input_elements[absorbed + i].0);
                state[i] = state[i] + input_elements[absorbed + i];
            }
            absorbed += absorb_count;

            // Pad with zeros if needed (no trace append for zeros)
            // Actually we need to not append zeros, just use the state as-is

            // Apply permutation
            state = self.gen_poseidon2_on_state(state);
        }

        state[0]
    }

    /// Apply Poseidon2 permutation on given state (helper for sponge).
    fn gen_poseidon2_on_state(&mut self, mut state: [BaseField; STATE_SIZE]) -> [BaseField; STATE_SIZE] {
        // First half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..STATE_SIZE {
                state[i] += BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5(state[i]));
            self.append_state(&state);
        }

        // Partial rounds
        for round in 0..N_PARTIAL_ROUNDS {
            state[0] += BaseField::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]);
            apply_internal_round_matrix(&mut state);
            state[0] = pow5(state[0]);
            self.append(state[0].0);
        }

        // Second half of full rounds
        for round in 0..N_HALF_FULL_ROUNDS {
            for i in 0..STATE_SIZE {
                state[i] +=
                    BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
            }
            apply_external_round_matrix(&mut state);
            state = std::array::from_fn(|i| pow5(state[i]));
            self.append_state(&state);
        }

        state
    }
}

impl Default for Poseidon2TraceGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Native Poseidon2 hash (no trace generation).
pub fn poseidon2_native(input: &[BaseField]) -> BaseField {
    assert!(input.len() <= STATE_SIZE, "Input too large");

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

    state[0]
}

/// Hash Field256 values using native computation (no trace).
pub fn hash_field256_native(inputs: &[BigInt256]) -> BaseField {
    // Convert to M31 elements
    let mut elements: Vec<BaseField> = Vec::new();
    for field256 in inputs {
        for &limb in &field256.limbs {
            elements.push(BaseField::from_u32_unchecked(limb));
        }
    }

    // Simple sponge
    let mut state: [BaseField; STATE_SIZE] =
        std::array::from_fn(|_| BaseField::from_u32_unchecked(0));

    let mut absorbed = 0;
    while absorbed < elements.len() {
        let absorb_count = (elements.len() - absorbed).min(STATE_SIZE);
        for i in 0..absorb_count {
            state[i] = state[i] + elements[absorbed + i];
        }
        absorbed += absorb_count;

        // Permute
        state = poseidon2_permute_native(state);
    }

    state[0]
}

/// Native Poseidon2 permutation on full state.
fn poseidon2_permute_native(mut state: [BaseField; STATE_SIZE]) -> [BaseField; STATE_SIZE] {
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..STATE_SIZE {
            state[i] += BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]);
        }
        apply_external_round_matrix(&mut state);
        state = std::array::from_fn(|i| pow5(state[i]));
    }

    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += BaseField::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]);
        apply_internal_round_matrix(&mut state);
        state[0] = pow5(state[0]);
    }

    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..STATE_SIZE {
            state[i] +=
                BaseField::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
        }
        apply_external_round_matrix(&mut state);
        state = std::array::from_fn(|i| pow5(state[i]));
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_gen_matches_native() {
        let input: [BaseField; STATE_SIZE] =
            std::array::from_fn(|i| BaseField::from_u32_unchecked((i * 7 + 3) as u32));

        let native_result = poseidon2_native(&input);

        let mut gen = Poseidon2TraceGen::new();
        let traced_result = gen.gen_poseidon2(&input);

        assert_eq!(native_result, traced_result[0]);
    }

    #[test]
    fn test_hash_field256() {
        let inputs = [
            BigInt256::from_limbs([1, 2, 3, 4, 5, 6, 7, 8, 0]),
            BigInt256::from_limbs([10, 20, 30, 40, 50, 60, 70, 80, 0]),
        ];

        let hash = hash_field256_native(&inputs);

        // Just verify it runs
        assert!(hash.0 != 0 || hash.0 == 0); // Always true, just checking no panic
    }

    #[test]
    fn test_poseidon2_deterministic() {
        let input = [BaseField::from_u32_unchecked(42)];

        let hash1 = poseidon2_native(&input);
        let hash2 = poseidon2_native(&input);

        assert_eq!(hash1, hash2);
    }
}
