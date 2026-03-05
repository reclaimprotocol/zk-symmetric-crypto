//! ChaCha20 stream encryption constraint evaluation.
//!
//! Extends bitwise constraints with plaintext XOR to produce ciphertext.

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use super::constraints::BitU32;
use crate::chacha::STATE_SIZE;

/// Constraint evaluator for ChaCha20 stream encryption.
pub struct ChaChaStreamEvalAtRow<E: EvalAtRow> {
    pub eval: E,
}

impl<E: EvalAtRow> ChaChaStreamEvalAtRow<E> {
    /// Evaluate constraints for ChaCha20 stream encryption.
    /// Inputs: initial state (key/counter/nonce encoded)
    /// Outputs: ciphertext = keystream XOR plaintext
    pub fn eval(mut self) -> E {
        // Read initial state (16 u32s x 32 bits = 512 field elements)
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

        // Final addition: keystream[i] = v[i] + initial[i]
        let mut keystream: [BitU32<E::F>; STATE_SIZE] = std::array::from_fn(|_| BitU32::new(std::array::from_fn(|_| {
            E::F::from(BaseField::from_u32_unchecked(0))
        })));
        for i in 0..STATE_SIZE {
            keystream[i] = self.add_u32(v[i].clone(), initial[i].clone());
        }

        // Read plaintext (16 u32s x 32 bits = 512 field elements)
        let plaintext: [BitU32<E::F>; STATE_SIZE] = std::array::from_fn(|_| self.next_u32());

        // Constrain plaintext bits to be binary
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        for pt in &plaintext {
            for bit in &pt.bits {
                self.eval.add_constraint(bit.clone() * (one.clone() - bit.clone()));
            }
        }

        // XOR keystream with plaintext to get ciphertext
        // Read ciphertext from trace and constrain
        for i in 0..STATE_SIZE {
            let _ciphertext = self.xor_u32(keystream[i].clone(), plaintext[i].clone());
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
    fn add_u32(&mut self, a: BitU32<E::F>, b: BitU32<E::F>) -> BitU32<E::F> {
        let result = self.next_u32();
        let carries: [E::F; 32] = std::array::from_fn(|_| self.eval.next_trace_mask());

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        for i in 0..32 {
            let carry_in = if i == 0 {
                E::F::from(BaseField::from_u32_unchecked(0))
            } else {
                carries[i - 1].clone()
            };

            // Constrain carry in {0, 1}
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
        let result = self.next_u32();

        let two = E::F::from(BaseField::from_u32_unchecked(2));

        for i in 0..32 {
            let src = ((i + 32 - r) % 32) as usize;

            // XOR constraint: result = a + b - 2ab
            self.eval.add_constraint(
                result.bits[i as usize].clone()
                    - a.bits[src].clone()
                    - b.bits[src].clone()
                    + two.clone() * a.bits[src].clone() * b.bits[src].clone()
            );
        }

        result
    }

    /// XOR two u32s (no rotation).
    fn xor_u32(&mut self, a: BitU32<E::F>, b: BitU32<E::F>) -> BitU32<E::F> {
        let result = self.next_u32();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        for i in 0..32 {
            // Constrain result bit to be binary
            self.eval.add_constraint(
                result.bits[i].clone() * (one.clone() - result.bits[i].clone())
            );

            // XOR constraint: result = a + b - 2ab
            self.eval.add_constraint(
                result.bits[i].clone()
                    - a.bits[i].clone()
                    - b.bits[i].clone()
                    + two.clone() * a.bits[i].clone() * b.bits[i].clone()
            );
        }

        result
    }
}
