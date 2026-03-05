//! Bitwise ChaCha20 constraint evaluation.
//!
//! Uses bit-level representation: each u32 is 32 field elements (one per bit).
//! XOR is computed algebraically: a XOR b = a + b - 2*a*b
//! No lookup tables needed.

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use crate::chacha::STATE_SIZE;

/// A u32 represented as 32 individual bits.
#[derive(Clone)]
pub struct BitU32<F: Clone> {
    /// Bits from LSB to MSB: bits[0] is bit 0, bits[31] is bit 31
    pub bits: [F; 32],
}

impl<F: Clone> BitU32<F> {
    pub fn new(bits: [F; 32]) -> Self {
        Self { bits }
    }
}

/// Constraint evaluator for bitwise ChaCha full block.
pub struct ChaChabitwiseEvalAtRow<E: EvalAtRow> {
    pub eval: E,
}

impl<E: EvalAtRow> ChaChabitwiseEvalAtRow<E> {
    /// Evaluate constraints for a full ChaCha20 block.
    pub fn eval(mut self) -> E {
        // Read initial state (16 u32s × 32 bits = 512 field elements)
        let initial: [BitU32<E::F>; STATE_SIZE] = std::array::from_fn(|_| self.next_u32());
        let mut v = initial.clone();

        // 10 double-rounds
        for _ in 0..10 {
            // Column quarter-rounds
            self.quarter_round(&mut v, 0, 4, 8, 12);
            self.quarter_round(&mut v, 1, 5, 9, 13);
            self.quarter_round(&mut v, 2, 6, 10, 14);
            self.quarter_round(&mut v, 3, 7, 11, 15);

            // Diagonal quarter-rounds
            self.quarter_round(&mut v, 0, 5, 10, 15);
            self.quarter_round(&mut v, 1, 6, 11, 12);
            self.quarter_round(&mut v, 2, 7, 8, 13);
            self.quarter_round(&mut v, 3, 4, 9, 14);
        }

        // Final addition: output[i] = v[i] + initial[i]
        for i in 0..STATE_SIZE {
            let _output = self.add_u32(v[i].clone(), initial[i].clone());
        }

        self.eval
    }

    /// Read next u32 from trace (32 bits).
    fn next_u32(&mut self) -> BitU32<E::F> {
        BitU32::new(std::array::from_fn(|_| self.eval.next_trace_mask()))
    }

    /// ChaCha quarter-round on indices a, b, c, d.
    fn quarter_round(&mut self, v: &mut [BitU32<E::F>; STATE_SIZE], a: usize, b: usize, c: usize, d: usize) {
        // a += b; d ^= a; d <<<= 16
        v[a] = self.add_u32(v[a].clone(), v[b].clone());
        v[d] = self.xor_rotl_u32(v[a].clone(), v[d].clone(), 16);

        // c += d; b ^= c; b <<<= 12
        v[c] = self.add_u32(v[c].clone(), v[d].clone());
        v[b] = self.xor_rotl_u32(v[c].clone(), v[b].clone(), 12);

        // a += b; d ^= a; d <<<= 8
        v[a] = self.add_u32(v[a].clone(), v[b].clone());
        v[d] = self.xor_rotl_u32(v[a].clone(), v[d].clone(), 8);

        // c += d; b ^= c; b <<<= 7
        v[c] = self.add_u32(v[c].clone(), v[d].clone());
        v[b] = self.xor_rotl_u32(v[c].clone(), v[b].clone(), 7);
    }

    /// Add two u32s with ripple-carry adder.
    /// Returns sum and constrains carry bits.
    fn add_u32(&mut self, a: BitU32<E::F>, b: BitU32<E::F>) -> BitU32<E::F> {
        // Read result bits from trace
        let result = self.next_u32();

        // Read carry bits from trace (32 carries, last one is overflow/discarded)
        let carries: [E::F; 32] = std::array::from_fn(|_| self.eval.next_trace_mask());

        // Constrain: for each bit position i:
        //   sum_i = a_i + b_i + carry_{i-1}
        //   result_i = sum_i mod 2
        //   carry_i = sum_i / 2 (i.e., sum_i >= 2)
        //
        // Constraints:
        //   1. carry_i ∈ {0, 1}: carry_i * (1 - carry_i) = 0
        //   2. result_i + 2*carry_i = a_i + b_i + carry_{i-1}

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        for i in 0..32 {
            let carry_in = if i == 0 {
                E::F::from(BaseField::from_u32_unchecked(0))
            } else {
                carries[i - 1].clone()
            };

            // Constrain carry ∈ {0, 1}
            self.eval.add_constraint(
                carries[i].clone() * (one.clone() - carries[i].clone())
            );

            // Constrain addition: result + 2*carry_out = a + b + carry_in
            self.eval.add_constraint(
                result.bits[i].clone() + two.clone() * carries[i].clone()
                    - a.bits[i].clone() - b.bits[i].clone() - carry_in
            );
        }

        result
    }

    /// XOR two u32s and left-rotate by r bits.
    fn xor_rotl_u32(&mut self, a: BitU32<E::F>, b: BitU32<E::F>, r: u32) -> BitU32<E::F> {
        // Read result bits from trace
        let result = self.next_u32();

        let two = E::F::from(BaseField::from_u32_unchecked(2));

        // For each output bit position i:
        //   source position = (i - r) mod 32 (left rotation)
        //   result[i] = a[src] XOR b[src]
        //
        // XOR constraint: c = a + b - 2*a*b
        // So: result[i] = a[src] + b[src] - 2*a[src]*b[src]

        for i in 0..32 {
            let src = ((i + 32 - r) % 32) as usize;

            // XOR: result = a + b - 2ab
            // Constraint: result - a - b + 2ab = 0
            self.eval.add_constraint(
                result.bits[i as usize].clone()
                    - a.bits[src].clone()
                    - b.bits[src].clone()
                    + two.clone() * a.bits[src].clone() * b.bits[src].clone()
            );
        }

        result
    }
}
